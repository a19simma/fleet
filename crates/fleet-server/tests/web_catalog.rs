//! The `/catalog` pages and the `/users/{id}/capabilities` page behind `admin_gate`: GET and
//! POST against no session, a non-admin, an admin, an admin demoted after login, and a
//! missing or wrong CSRF token on every route; then add, edit, enable and disable as an admin
//! with one hostile value per field. The tests need a Postgres superuser URL in `DATABASE_URL` for
//! `#[sqlx::test]` and live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use fleet_core::capability::Capability;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const GET_ROUTES: [&str; 3] = ["/catalog", "/catalog/greet", "/users/1/capabilities"];
const POST_ROUTES: [&str; 5] = [
    "/catalog",
    "/catalog/greet",
    "/catalog/greet/enable",
    "/catalog/greet/disable",
    "/users/1/capabilities",
];
const HOSTILE: &str = "<script>alert('x')</script>\"'&\r\n\u{2028}";

struct Session {
    cookie: String,
    csrf: String,
    user_id: i64,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    users: Users,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

type Snapshot = (
    Vec<(i64, bool)>,
    i64,
    i64,
    Vec<(String, String, String, String, bool)>,
    Vec<(i64, String, i64)>,
);

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let bearer = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let web = Web::with_console(auth, None, store.clone());
        let task = tokio::spawn(async move {
            serve_with_web(&store, &bearer, web, TcpIncoming::from(listener), async {
                let _ = rx.await;
            })
            .await
        });
        Self {
            addr,
            pool,
            users,
            stop: Some(stop),
            task,
        }
    }

    async fn session(&self, name: &str, seed: char, admin: bool) -> Session {
        let user_id: i64 =
            sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
                .bind(name)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        if admin {
            self.users.set_admin(user_id, true).await.unwrap();
        }
        let id = seed.to_string().repeat(64);
        let csrf = format!("csrf-{name}-token");
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, $3, now() + interval '1 hour')",
        )
        .bind(id.as_bytes())
        .bind(user_id)
        .bind(&csrf)
        .execute(&self.pool)
        .await
        .unwrap();
        Session {
            cookie: format!("{SESSION_COOKIE}={id}"),
            csrf,
            user_id,
        }
    }

    async fn snapshot(&self) -> Snapshot {
        let flags = sqlx::query_as("SELECT id, is_admin FROM users ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .unwrap();
        let audit = sqlx::query_scalar("SELECT count(*) FROM admin_audit")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        let sessions = sqlx::query_scalar("SELECT count(*) FROM web_sessions")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        let items = sqlx::query_as(
            "SELECT id, kind, name, content, admin_enabled FROM catalog_items ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        let grants = sqlx::query_as(
            "SELECT user_id, capability, granted_by FROM user_capabilities ORDER BY user_id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        (flags, audit, sessions, items, grants)
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
        let (status, location, _) = self.fetch(method, path, cookie, body).await;
        (status, location)
    }

    async fn fetch(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String, String) {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let body = body.unwrap_or_default();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\nContent-Length: {}\r\n",
            body.len()
        );
        if method == "POST" {
            let _ = write!(request, "{}: {}\r\n", FORM.0, FORM.1);
        }
        if let Some(cookie) = cookie {
            let _ = write!(request, "Cookie: {cookie}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let _ = stream.write_all(body.as_bytes()).await;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, page) = raw.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        let location = head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default();
        (status, location, page.to_owned())
    }

    async fn expect(
        &self,
        method: &str,
        who: Option<&Session>,
        body: Option<&str>,
        want: (u16, &str),
    ) {
        let paths: &[&str] = if method == "GET" {
            &GET_ROUTES
        } else {
            &POST_ROUTES
        };
        self.expect_on(paths, method, who, body, want).await;
    }

    async fn expect_on(
        &self,
        paths: &[&str],
        method: &str,
        who: Option<&Session>,
        body: Option<&str>,
        want: (u16, &str),
    ) {
        let before = self.snapshot().await;
        for path in paths {
            let (status, location) = self
                .send(method, path, who.map(|s| s.cookie.as_str()), body)
                .await;
            assert_eq!((status, location.as_str()), want, "{method} {path}");
        }
        assert_eq!(self.snapshot().await, before);
    }

    async fn post(&self, who: &Session, path: &str, fields: &[(&str, &str)]) -> (u16, String) {
        let mut body = format!("csrf={}", who.csrf);
        for (key, value) in fields {
            let _ = write!(body, "&{key}={}", encode(value));
        }
        self.send("POST", path, Some(&who.cookie), Some(&body))
            .await
    }

    async fn item(&self, id: &str) -> Option<(String, String, String, bool)> {
        sqlx::query_as("SELECT kind, name, content, admin_enabled FROM catalog_items WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .unwrap()
    }

    async fn add(&self, who: &Session, id: &str, kind: &str, content: &str) -> (u16, String) {
        self.post(
            who,
            "/catalog",
            &[
                ("id", id),
                ("kind", kind),
                ("name", id),
                ("content", content),
            ],
        )
        .await
    }

    async fn finish(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn encode(value: &str) -> String {
    value.bytes().fold(String::new(), |mut out, byte| {
        if byte.is_ascii_alphanumeric() {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
        out
    })
}

fn caps_path(user_id: i64) -> String {
    format!("/users/{user_id}/capabilities")
}

fn toggle_body(session: &Session, action: &str) -> String {
    toggle_body_for(session, action, "profile:tools")
}

fn toggle_body_for(session: &Session, action: &str, capability: &str) -> String {
    format!(
        "csrf={}&action={}&capability={}",
        session.csrf,
        encode(action),
        encode(capability)
    )
}

fn csrf_body(session: &Session) -> String {
    format!("csrf={}", session.csrf)
}

#[sqlx::test]
async fn get_without_a_session_redirects_to_login(pool: PgPool) {
    let h = Harness::start(pool).await;
    h.expect("GET", None, None, (303, "/login")).await;
    h.finish().await;
}

#[sqlx::test]
async fn get_as_a_non_admin_is_forbidden(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false).await;
    h.expect("GET", Some(&alice), None, (403, "")).await;
    h.finish().await;
}

#[sqlx::test]
async fn get_as_an_admin_reaches_the_capability_page(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let path = caps_path(root.user_id);
    h.expect_on(&[path.as_str()], "GET", Some(&root), None, (200, ""))
        .await;
    let (status, _) = h
        .send("GET", "/users/1/nope", Some(&root.cookie), None)
        .await;
    assert_eq!(status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn get_after_demotion_is_forbidden_on_the_same_session(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let path = caps_path(root.user_id);
    h.expect_on(&[path.as_str()], "GET", Some(&root), None, (200, ""))
        .await;
    h.users.set_admin(root.user_id, false).await.unwrap();
    h.expect("GET", Some(&root), None, (403, "")).await;
    h.finish().await;
}

#[sqlx::test]
async fn post_without_a_session_redirects_to_login(pool: PgPool) {
    let h = Harness::start(pool).await;
    h.expect("POST", None, Some("csrf=anything"), (303, "/login"))
        .await;
    h.finish().await;
}

#[sqlx::test]
async fn post_as_a_non_admin_with_a_valid_csrf_is_forbidden(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false).await;
    let body = csrf_body(&alice);
    h.expect("POST", Some(&alice), Some(&body), (403, "")).await;
    h.finish().await;
}

#[sqlx::test]
async fn post_as_an_admin_with_a_valid_csrf_and_no_action_is_a_bad_request(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let body = csrf_body(&root);
    let path = caps_path(root.user_id);
    h.expect_on(
        &[path.as_str()],
        "POST",
        Some(&root),
        Some(&body),
        (400, ""),
    )
    .await;
    h.finish().await;
}

#[sqlx::test]
async fn post_after_demotion_with_a_valid_csrf_is_forbidden(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let body = csrf_body(&root);
    let path = caps_path(root.user_id);
    h.expect_on(
        &[path.as_str()],
        "POST",
        Some(&root),
        Some(&body),
        (400, ""),
    )
    .await;
    h.users.set_admin(root.user_id, false).await.unwrap();
    h.expect("POST", Some(&root), Some(&body), (403, "")).await;
    h.finish().await;
}

#[sqlx::test]
async fn post_as_an_admin_without_a_csrf_is_forbidden(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.expect("POST", Some(&root), Some("other=1"), (403, ""))
        .await;
    h.finish().await;
}

#[sqlx::test]
async fn post_as_an_admin_with_a_wrong_csrf_is_forbidden(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.expect("POST", Some(&root), Some("csrf=wrong"), (403, ""))
        .await;
    h.finish().await;
}

#[sqlx::test]
async fn admin_adds_an_item_and_the_list_shows_it(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let (status, location) = h.add(&root, "greet", "skill", "say hello").await;
    assert_eq!((status, location.as_str()), (303, "/catalog"));
    let item = h.item("greet").await.unwrap();
    assert_eq!(
        item,
        ("skill".into(), "greet".into(), "say hello".into(), false)
    );
    let (status, _, page) = h.fetch("GET", "/catalog", Some(&root.cookie), None).await;
    assert_eq!(status, 200);
    assert!(page.contains("greet") && page.contains("disabled") && page.contains("Enable"));
    assert!(page.contains("/catalog/greet/enable"));
    assert_eq!(page.matches("name=\"csrf\"").count(), 3);
    assert!(page.contains(&format!("value=\"{}\"", root.csrf)));
    h.finish().await;
}

#[sqlx::test]
async fn admin_edits_content_only(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let (status, location) = h
        .post(
            &root,
            "/catalog/greet",
            &[
                ("content", "say goodbye"),
                ("kind", "context"),
                ("name", "other"),
                ("id", "other"),
            ],
        )
        .await;
    assert_eq!((status, location.as_str()), (303, "/catalog/greet"));
    assert_eq!(
        h.item("greet").await.unwrap(),
        ("skill".into(), "greet".into(), "say goodbye".into(), false)
    );
    assert!(h.item("other").await.is_none());
    let (status, _, page) = h
        .fetch("GET", "/catalog/greet", Some(&root.cookie), None)
        .await;
    assert_eq!(status, 200);
    assert!(page.contains("say goodbye"));
    assert_eq!(page.matches("name=\"csrf\"").count(), 2);
    h.finish().await;
}

#[sqlx::test]
async fn admin_enables_and_disables_an_item(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let (status, location) = h.post(&root, "/catalog/greet/enable", &[]).await;
    assert_eq!((status, location.as_str()), (303, "/catalog"));
    assert!(h.item("greet").await.unwrap().3);
    let (_, _, page) = h.fetch("GET", "/catalog", Some(&root.cookie), None).await;
    assert!(page.contains("Disable"));
    assert!(page.contains("/catalog/greet/disable"));
    let (status, _) = h.post(&root, "/catalog/greet/disable", &[]).await;
    assert_eq!(status, 303);
    assert!(!h.item("greet").await.unwrap().3);
    let (status, _) = h.post(&root, "/catalog/missing/enable", &[]).await;
    assert_eq!(status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn every_post_route_refuses_a_missing_csrf_and_writes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let before = h.snapshot().await;
    for path in &POST_ROUTES[..4] {
        let body = "id=other&kind=skill&name=other&content=x";
        let (status, _) = h.send("POST", path, Some(&root.cookie), Some(body)).await;
        assert_eq!(status, 403, "{path}");
    }
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn a_hostile_value_in_each_field_is_refused_and_writes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let before = h.snapshot().await;
    let cases: [(&str, &str, &str, &str, &str); 7] = [
        (HOSTILE, "skill", "ok", "body", "id"),
        ("ok", "skill", HOSTILE, "body", "name"),
        ("ok", HOSTILE, "ok", "body", "kind"),
        ("ok", "skill", "ok", "", "empty content"),
        ("ok", "tool", "not-a-tool", "1.0.0", "unknown tool"),
        ("Ok", "skill", "ok", "body", "uppercase id"),
        ("ok\u{85}", "skill", "ok", "body", "nel id"),
    ];
    for (id, kind, name, content, label) in cases {
        let (status, _) = h
            .post(
                &root,
                "/catalog",
                &[
                    ("id", id),
                    ("kind", kind),
                    ("name", name),
                    ("content", content),
                ],
            )
            .await;
        assert_eq!(status, 400, "{label}");
    }
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn hostile_content_is_stored_and_rendered_escaped(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let (status, _) = h.add(&root, "greet", "skill", HOSTILE).await;
    assert_eq!(status, 303);
    assert_eq!(h.item("greet").await.unwrap().2, HOSTILE);
    let (_, _, page) = h
        .fetch("GET", "/catalog/greet", Some(&root.cookie), None)
        .await;
    assert!(!page.contains("<script>alert"));
    assert!(page.contains("&lt;script&gt;"));
    h.finish().await;
}

#[sqlx::test]
async fn a_hostile_edit_content_and_item_path_are_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let before = h.snapshot().await;
    let (status, _) = h.post(&root, "/catalog/greet", &[("content", "")]).await;
    assert_eq!(status, 400);
    let (status, _) = h.post(&root, "/catalog/nope", &[("content", "x")]).await;
    assert_eq!(status, 404);
    for path in ["/catalog/%3Cscript%3E", "/catalog/UPPER", "/catalog/a%0Ab"] {
        let (status, _, _) = h.fetch("GET", path, Some(&root.cookie), None).await;
        assert_eq!(status, 404, "{path}");
        let (status, _) = h.post(&root, &format!("{path}/enable"), &[]).await;
        assert_eq!(status, 404, "{path}");
    }
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn adding_an_existing_id_is_refused_and_keeps_the_content(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let before = h.snapshot().await;
    let (status, _) = h.add(&root, "greet", "skill", "replaced").await;
    assert_eq!(status, 400);
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn a_demoted_admin_cannot_write_on_the_same_session(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    h.users.set_admin(root.user_id, false).await.unwrap();
    let before = h.snapshot().await;
    let (status, _) = h.add(&root, "other", "skill", "x").await;
    assert_eq!(status, 403);
    let (status, _) = h.post(&root, "/catalog/greet", &[("content", "y")]).await;
    assert_eq!(status, 403);
    let (status, _) = h.post(&root, "/catalog/greet/enable", &[]).await;
    assert_eq!(status, 403);
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn a_non_admin_with_a_valid_csrf_writes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let alice = h.session("alice", 'a', false).await;
    let before = h.snapshot().await;
    let (status, _) = h.add(&alice, "other", "skill", "x").await;
    assert_eq!(status, 403);
    let (status, _) = h.post(&alice, "/catalog/greet/enable", &[]).await;
    assert_eq!(status, 403);
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn every_kind_is_stored_as_chosen(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    for (id, kind, content) in [
        ("s1", "skill", "body"),
        ("a1", "subagent", "body"),
        ("c1", "context", "body"),
    ] {
        let (status, _) = h.add(&root, id, kind, content).await;
        assert_eq!(status, 303, "{kind}");
        assert_eq!(h.item(id).await.unwrap().0, kind);
    }
    h.finish().await;
}

const SEED_ITEMS: &str = "INSERT INTO catalog_items (id, kind, name, content, digest) \
     SELECT 'i' || lpad(n::text, 3, '0'), 'skill', 'i' || lpad(n::text, 3, '0'), 'x', sha256('x'::bytea) \
     FROM generate_series(0, $1) n";

#[sqlx::test]
async fn the_list_pages_past_the_limit_and_the_rest_is_reachable(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    sqlx::query(SEED_ITEMS)
        .bind(500_i32)
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, _, first) = h.fetch("GET", "/catalog", Some(&root.cookie), None).await;
    assert_eq!(status, 200);
    assert!(first.contains("/catalog/i499\"") && !first.contains("/catalog/i500\""));
    assert!(first.contains("href=\"/catalog?after=i499\""));
    let (status, _, second) = h
        .fetch("GET", "/catalog?after=i499", Some(&root.cookie), None)
        .await;
    assert_eq!(status, 200);
    assert!(second.contains("/catalog/i500\"") && !second.contains("/catalog/i499\""));
    assert!(!second.contains("after="));
    let (status, location) = h.post(&root, "/catalog/i500/enable", &[]).await;
    assert_eq!((status, location.as_str()), (303, "/catalog"));
    assert!(h.item("i500").await.unwrap().3);
    h.finish().await;
}

#[sqlx::test]
async fn a_list_of_exactly_the_limit_has_no_next_link(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    sqlx::query(SEED_ITEMS)
        .bind(499_i32)
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, _, page) = h.fetch("GET", "/catalog", Some(&root.cookie), None).await;
    assert_eq!(status, 200);
    assert!(page.contains("/catalog/i499\"") && !page.contains("after="));
    h.finish().await;
}

#[sqlx::test]
async fn an_illegal_list_cursor_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    for cursor in ["BAD", "-x", "a%00b", "a.b"] {
        let path = format!("/catalog?after={cursor}");
        let (status, _, _) = h.fetch("GET", &path, Some(&root.cookie), None).await;
        assert_eq!(status, 400, "{cursor}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn adding_the_same_kind_and_name_under_a_new_id_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    let before = h.snapshot().await;
    let (status, _) = h
        .post(
            &root,
            "/catalog",
            &[
                ("id", "other"),
                ("kind", "skill"),
                ("name", "greet"),
                ("content", "x"),
            ],
        )
        .await;
    assert_eq!(status, 400);
    assert!(h.item("other").await.is_none());
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

const LINK: &str = "href=\"/catalog\"";
const LINK_CURRENT: &str =
    "<a class=\"menu-active\" href=\"/catalog\" aria-current=\"page\">Catalog</a>";
const LINK_PLAIN: &str = "<a href=\"/catalog\">Catalog</a>";

#[sqlx::test]
async fn an_admin_sees_the_catalog_link_on_other_pages_unmarked(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    for path in ["/account", "/jobs", "/tokens"] {
        let (status, _, page) = h.fetch("GET", path, Some(&root.cookie), None).await;
        assert_eq!(status, 200, "{path}");
        assert!(page.contains(LINK_PLAIN), "{path}");
        assert!(!page.contains(LINK_CURRENT), "{path}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_non_admin_sees_no_catalog_link(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false).await;
    for path in ["/account", "/jobs", "/tokens"] {
        let (status, _, page) = h.fetch("GET", path, Some(&alice.cookie), None).await;
        assert_eq!(status, 200, "{path}");
        assert!(!page.contains(LINK), "{path}");
        assert!(page.contains("href=\"/account\""), "{path}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_demoted_admin_loses_the_catalog_link_on_the_next_request(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let (_, _, page) = h.fetch("GET", "/account", Some(&root.cookie), None).await;
    assert!(page.contains(LINK_PLAIN));
    h.users.set_admin(root.user_id, false).await.unwrap();
    let (status, _, page) = h.fetch("GET", "/account", Some(&root.cookie), None).await;
    assert_eq!(status, 200);
    assert!(!page.contains(LINK));
    h.finish().await;
}

#[sqlx::test]
async fn the_catalog_pages_mark_the_link_current(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.add(&root, "greet", "skill", "say hello").await;
    for path in ["/catalog", "/catalog/greet"] {
        let (status, _, page) = h.fetch("GET", path, Some(&root.cookie), None).await;
        assert_eq!(status, 200, "{path}");
        assert!(page.contains(LINK_CURRENT), "{path}");
        assert!(!page.contains(LINK_PLAIN), "{path}");
        assert_eq!(page.matches("aria-current=\"page\"").count(), 1, "{path}");
    }
    h.finish().await;
}

impl Harness {
    async fn grants(&self) -> Vec<(i64, String, i64)> {
        sqlx::query_as(
            "SELECT user_id, capability, granted_by FROM user_capabilities ORDER BY user_id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }
}

#[sqlx::test]
async fn the_page_shows_the_user_and_a_csrf_protected_grant_form(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    let (status, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
    assert_eq!(status, 200);
    assert!(
        page.contains("bob") && page.contains("not granted"),
        "{page}"
    );
    assert!(page.contains("value=\"grant\""), "{page}");
    assert!(page.contains(&format!("action=\"{path}\"")), "{page}");
    assert!(page.contains(&format!("name=\"csrf\" value=\"{}\"", root.csrf)));
    assert!(!page.contains("Granted by"));
    h.finish().await;
}

#[sqlx::test]
async fn grant_stores_the_row_and_the_page_shows_who_and_when(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("gina", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    let (status, location) = h
        .send(
            "POST",
            &path,
            Some(&root.cookie),
            Some(&toggle_body(&root, "grant")),
        )
        .await;
    assert_eq!((status, location.as_str()), (303, path.as_str()));
    assert_eq!(
        h.grants().await,
        [(bob.user_id, "profile:tools".to_owned(), root.user_id)]
    );
    let stamp: String = sqlx::query_scalar(
        "SELECT to_char(granted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') \
         FROM user_capabilities",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    let (_, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
    assert!(page.contains(">granted<"), "{page}");
    assert!(page.contains("<dd>gina</dd>"), "{page}");
    assert!(page.contains(&stamp), "{page}");
    assert!(page.contains("value=\"revoke\""), "{page}");
    h.finish().await;
}

#[sqlx::test]
async fn a_second_grant_keeps_the_first_audit_columns(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let other = h.session("other", 'd', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    h.send(
        "POST",
        &path,
        Some(&root.cookie),
        Some(&toggle_body(&root, "grant")),
    )
    .await;
    let (status, _) = h
        .send(
            "POST",
            &path,
            Some(&other.cookie),
            Some(&toggle_body(&other, "grant")),
        )
        .await;
    assert_eq!(status, 303);
    assert_eq!(h.grants().await.len(), 1);
    assert_eq!(h.grants().await[0].2, root.user_id);
    h.finish().await;
}

#[sqlx::test]
async fn revoke_removes_the_row(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    h.send(
        "POST",
        &path,
        Some(&root.cookie),
        Some(&toggle_body(&root, "grant")),
    )
    .await;
    let (status, location) = h
        .send(
            "POST",
            &path,
            Some(&root.cookie),
            Some(&toggle_body(&root, "revoke")),
        )
        .await;
    assert_eq!((status, location.as_str()), (303, path.as_str()));
    assert_eq!(h.grants().await.len(), 0);
    let (status, _) = h
        .send(
            "POST",
            &path,
            Some(&root.cookie),
            Some(&toggle_body(&root, "revoke")),
        )
        .await;
    assert_eq!(status, 303);
    h.finish().await;
}

#[sqlx::test]
async fn an_unknown_or_missing_capability_is_refused_and_writes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    let bodies = [
        toggle_body_for(&root, "grant", "admin:everything"),
        toggle_body_for(&root, "grant", "profile:tools "),
        toggle_body_for(&root, "grant", "PROFILE:TOOLS"),
        toggle_body_for(&root, "grant", ""),
        toggle_body_for(&root, "revoke", "admin:everything"),
        format!("csrf={}&action=grant", root.csrf),
    ];
    for body in &bodies {
        let (status, _) = h.send("POST", &path, Some(&root.cookie), Some(body)).await;
        assert_eq!(status, 400, "{body}");
    }
    assert_eq!(h.grants().await.len(), 0);
    h.finish().await;
}

#[sqlx::test]
async fn every_capability_can_be_granted_and_revoked_from_the_page(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    let (_, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
    for cap in Capability::ALL {
        assert!(
            page.contains(&format!("name=\"capability\" value=\"{}\"", cap.as_str())),
            "{cap:?} {page}"
        );
    }
    for only in Capability::ALL {
        let (status, _) = h
            .send(
                "POST",
                &path,
                Some(&root.cookie),
                Some(&toggle_body_for(&root, "grant", only.as_str())),
            )
            .await;
        assert_eq!(status, 303);
        let (_, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
        for cap in Capability::ALL {
            let (shown, hidden) = if cap == only {
                ("Revoke", "Grant")
            } else {
                ("Grant", "Revoke")
            };
            assert!(
                page.contains(&format!("{shown} {}", cap.as_str())),
                "{only:?} {cap:?}"
            );
            assert!(
                !page.contains(&format!("{hidden} {}", cap.as_str())),
                "{only:?} {cap:?}"
            );
        }
        h.send(
            "POST",
            &path,
            Some(&root.cookie),
            Some(&toggle_body_for(&root, "revoke", only.as_str())),
        )
        .await;
    }
    assert_eq!(h.grants().await.len(), 0);
    for cap in Capability::ALL {
        let name = cap.as_str();
        let (status, location) = h
            .send(
                "POST",
                &path,
                Some(&root.cookie),
                Some(&toggle_body_for(&root, "grant", name)),
            )
            .await;
        assert_eq!((status, location.as_str()), (303, path.as_str()), "{name}");
        let held: Vec<String> = h.grants().await.into_iter().map(|g| g.1).collect();
        assert!(held.iter().any(|g| g == name), "{name} {held:?}");
        let (_, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
        assert!(page.contains(&format!("Revoke {name}")), "{name} {page}");
        assert!(!page.contains(&format!("Grant {name}")), "{name} {page}");
    }
    assert_eq!(h.grants().await.len(), Capability::ALL.len());
    for cap in Capability::ALL {
        let name = cap.as_str();
        let (status, _) = h
            .send(
                "POST",
                &path,
                Some(&root.cookie),
                Some(&toggle_body_for(&root, "revoke", name)),
            )
            .await;
        assert_eq!(status, 303, "{name}");
        let held: Vec<String> = h.grants().await.into_iter().map(|g| g.1).collect();
        assert!(!held.iter().any(|g| g == name), "{name} {held:?}");
        let (_, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
        assert!(page.contains(&format!("Grant {name}")), "{name} {page}");
    }
    assert_eq!(h.grants().await.len(), 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_grant_post_is_refused_for_a_non_admin_and_a_demoted_admin(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let alice = h.session("alice", 'a', false).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    let before = h.snapshot().await;
    let (status, _) = h
        .send(
            "POST",
            &path,
            Some(&alice.cookie),
            Some(&toggle_body(&alice, "grant")),
        )
        .await;
    assert_eq!(status, 403);
    h.users.set_admin(root.user_id, false).await.unwrap();
    let before_demoted = h.snapshot().await;
    assert_eq!(before.4, before_demoted.4);
    let (status, _) = h
        .send(
            "POST",
            &path,
            Some(&root.cookie),
            Some(&toggle_body(&root, "grant")),
        )
        .await;
    assert_eq!(status, 403);
    assert_eq!(h.snapshot().await, before_demoted);
    let (status, _) = h.send("GET", &path, Some(&alice.cookie), None).await;
    assert_eq!(status, 403);
    assert_eq!(h.grants().await.len(), 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_grant_post_without_or_with_a_wrong_csrf_changes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    for body in [
        "action=grant",
        "csrf=wrong&action=grant",
        "csrf=&action=grant",
    ] {
        let (status, _) = h.send("POST", &path, Some(&root.cookie), Some(body)).await;
        assert_eq!(status, 403, "{body}");
    }
    assert_eq!(h.grants().await.len(), 0);
    h.send(
        "POST",
        &path,
        Some(&root.cookie),
        Some(&toggle_body(&root, "grant")),
    )
    .await;
    for body in ["action=revoke", "csrf=wrong&action=revoke"] {
        let (status, _) = h.send("POST", &path, Some(&root.cookie), Some(body)).await;
        assert_eq!(status, 403, "{body}");
    }
    assert_eq!(h.grants().await.len(), 1);
    h.finish().await;
}

#[sqlx::test]
async fn a_hostile_action_is_a_bad_request_and_changes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let path = caps_path(bob.user_id);
    let long = "grant".repeat(5000);
    let hostile = [
        "",
        "GRANT",
        " grant",
        "grant ",
        "grant\r",
        "grant\r\n",
        "grant\u{85}",
        "grant\u{2028}",
        "grant\\",
        "\\grant",
        "gr\u{430}nt",
        "\u{ff47}rant",
        "grant%00",
        "%67rant",
        "grant,revoke",
        "<script>",
        long.as_str(),
    ];
    for action in hostile {
        let before = h.snapshot().await;
        let (status, _) = h
            .send(
                "POST",
                &path,
                Some(&root.cookie),
                Some(&toggle_body(&root, action)),
            )
            .await;
        assert_eq!(status, 400, "{action:?}");
        assert_eq!(h.snapshot().await, before, "{action:?}");
    }
    let (status, _) = h
        .send("POST", &path, Some(&root.cookie), Some(&csrf_body(&root)))
        .await;
    assert_eq!(status, 400);
    assert_eq!(h.grants().await.len(), 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_hostile_path_id_is_not_found_and_changes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let bob = h.session("bob", 'c', false).await;
    let ids = [
        "abc".to_owned(),
        "0".to_owned(),
        "-1".to_owned(),
        "+1".to_owned(),
        "1.0".to_owned(),
        "1e1".to_owned(),
        "%20".to_owned(),
        format!("{}%20", bob.user_id),
        format!("{}%0D", bob.user_id),
        format!("{}%0D%0A", bob.user_id),
        format!("{}%C2%85", bob.user_id),
        format!("{}%E2%80%A8", bob.user_id),
        format!("{}%5C", bob.user_id),
        format!("{}%00", bob.user_id),
        "%D9%A1".to_owned(),
        "%EF%BC%91".to_owned(),
        "99999999999999999999".to_owned(),
        "9223372036854775808".to_owned(),
        "9".repeat(5000),
        "1;2".to_owned(),
        "%2F".to_owned(),
        "..".to_owned(),
    ];
    let (_, _, reference) = h
        .fetch(
            "GET",
            "/users/999999/capabilities",
            Some(&root.cookie),
            None,
        )
        .await;
    let before = h.snapshot().await;
    for id in &ids {
        let path = format!("/users/{id}/capabilities");
        let (status, _, page) = h.fetch("GET", &path, Some(&root.cookie), None).await;
        assert_eq!(status, 404, "GET {id}");
        assert_eq!(page, reference, "GET {id}");
        let (status, _, page) = h
            .fetch(
                "POST",
                &path,
                Some(&root.cookie),
                Some(&toggle_body(&root, "grant")),
            )
            .await;
        assert_eq!(status, 404, "POST {id}");
        assert_eq!(page, reference, "POST {id}");
    }
    assert_eq!(h.snapshot().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn an_absent_user_is_not_found_with_the_shared_text(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let (status, _, missing_route) = h
        .fetch("GET", "/users/1/nope", Some(&root.cookie), None)
        .await;
    assert_eq!(status, 404);
    for (method, action) in [("GET", "grant"), ("POST", "grant"), ("POST", "revoke")] {
        let body = toggle_body(&root, action);
        let (status, _, page) = h
            .fetch(
                method,
                "/users/987654/capabilities",
                Some(&root.cookie),
                (method == "POST").then_some(body.as_str()),
            )
            .await;
        assert_eq!(status, 404, "{method}");
        assert_eq!(page, missing_route, "{method}");
    }
    assert_eq!(h.grants().await.len(), 0);
    h.finish().await;
}
