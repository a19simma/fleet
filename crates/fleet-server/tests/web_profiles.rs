//! The profile pages over HTTP: session and CSRF gates, owner-only share buttons, read-only
//! views for others, escaping and refusals that leave the profile unchanged. The tests need
//! a Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]` and live in their own
//! binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use fleet_core::model_allowlist::ModelAllowlist;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::profiles::{self, ProfileContent};
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
const HOSTILE: &str = "<script>alert('x')</script>\"'&\r\n\u{2028}";

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    }
}

struct Session {
    cookie: String,
    csrf: String,
    user_id: i64,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        Self::start_with(pool, true).await
    }

    async fn start_allowing(pool: PgPool, models: &str) -> Self {
        Self::launch(pool, true, Some(models)).await
    }

    async fn start_with(pool: PgPool, configured: bool) -> Self {
        Self::launch(pool, configured, None).await
    }

    async fn launch(pool: PgPool, configured: bool, models: Option<&str>) -> Self {
        let allowlist = models.map(|raw| ModelAllowlist::parse(raw).unwrap());
        let store = Store::new(pool.clone()).with_model_allowlist(allowlist);
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = if configured {
            Web::with_console(auth, None, store.clone())
        } else {
            Web::with_auth(auth)
        };
        let bearer = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve_with_web(&store, &bearer, web, TcpIncoming::from(listener), async {
                let _ = rx.await;
            })
            .await
        });
        Self {
            addr,
            pool,
            stop: Some(stop),
            task,
        }
    }

    async fn session(&self, name: &str, seed: char) -> Session {
        let user_id: i64 =
            sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
                .bind(name)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let id = seed.to_string().repeat(64);
        let csrf = format!("csrf-{seed}-token");
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

    async fn profile(&self, owner: &Session, name: &str, json: &str, shared: bool) -> i64 {
        profiles::create_owned(
            &self.pool,
            Some(owner.user_id),
            None,
            name,
            ProfileContent::Json(json),
        )
        .await
        .unwrap();
        sqlx::query_scalar(
            "UPDATE profile SET visibility = $3 WHERE owner_user_id = $1 AND name = $2 RETURNING id",
        )
        .bind(owner.user_id)
        .bind(name)
        .bind(if shared { "shared" } else { "private" })
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn item(&self, id: &str, kind: &str, enabled: bool) {
        sqlx::query(
            "INSERT INTO catalog_items (id, kind, name, content, digest, admin_enabled) \
             VALUES ($1, $2, $1, 'body', sha256('x'::bytea), $3)",
        )
        .bind(id)
        .bind(kind)
        .bind(enabled)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn latest(&self, id: i64) -> (i32, serde_json::Value) {
        let (version, content): (i32, Vec<u8>) = sqlx::query_as(
            "SELECT v.version, b.content FROM profile p \
             JOIN profile_version v ON v.profile_id = p.id AND v.version = p.latest_version \
             JOIN profile_blob b ON b.hash = v.hash WHERE p.id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        (version, serde_json::from_slice(&content).unwrap())
    }

    async fn visibility(&self, id: i64) -> String {
        sqlx::query_scalar("SELECT visibility FROM profile WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn send(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\nOrigin: {ORIGIN}\r\n",
            body.len()
        );
        for (key, value) in extra {
            let _ = write!(request, "{key}: {value}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let _ = stream.write_all(body).await;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        Reply {
            status,
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    async fn get(&self, who: &Session, path: &str) -> Reply {
        self.send("GET", path, &[("Cookie", &who.cookie)], b"")
            .await
    }

    async fn post(&self, who: &Session, path: &str, body: &str) -> Reply {
        self.send(
            "POST",
            path,
            &[("Cookie", &who.cookie), FORM],
            body.as_bytes(),
        )
        .await
    }

    async fn post_csrf(&self, who: &Session, path: &str) -> Reply {
        self.post(who, path, &format!("csrf={}", who.csrf)).await
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

#[sqlx::test]
async fn the_pages_need_a_session_and_the_console(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    for path in ["/profiles", "/profiles/1"] {
        let reply = h.send("GET", path, &[], b"").await;
        assert_eq!(
            (reply.status, reply.location().as_str()),
            (303, "/login"),
            "{path}"
        );
    }
    for path in ["/profiles/1/share", "/profiles/1/unshare"] {
        let reply = h.send("POST", path, &[FORM], b"csrf=x").await;
        assert_eq!(reply.status, 403, "{path}");
    }
    h.finish().await;
    let h = Harness::start_with(pool, false).await;
    let alice = h.session("alice", 'a').await;
    for path in ["/profiles", "/profiles/1"] {
        assert_eq!(h.get(&alice, path).await.status, 404, "{path}");
    }
    assert_eq!(h.post_csrf(&alice, "/profiles/1/share").await.status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn the_list_shows_own_and_shared_profiles_only(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    h.profile(&alice, "alice-private", "{}", false).await;
    h.profile(&alice, "alice-shared", "{}", true).await;
    h.profile(&bob, "aaa-shared", "{}", true).await;
    h.profile(&bob, "bob-private", "{}", false).await;
    let page = h.get(&alice, "/profiles").await;
    assert_eq!(page.status, 200);
    for shown in ["alice-private", "alice-shared", "aaa-shared"] {
        assert!(page.body.contains(shown), "{shown}");
    }
    assert!(!page.body.contains("bob-private"));
    assert!(page.body.contains("read-only"));
    assert!(page.body.contains("owner"));
    assert!(page.body.find("alice-shared").unwrap() < page.body.find("aaa-shared").unwrap());
    h.finish().await;
}

#[sqlx::test]
async fn buttons_show_for_the_owner_and_a_read_only_view_for_others(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let private = h.profile(&alice, "mine", "{}", false).await;
    let shared = h.profile(&alice, "open", "{}", true).await;
    let page = h.get(&alice, &format!("/profiles/{private}")).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("id=\"share\""));
    assert!(!page.body.contains("id=\"unshare\""));
    assert!(page.body.contains(&format!("/profiles/{private}/share")));
    assert!(page.body.contains("name=\"csrf\" value=\"csrf-a-token\""));
    let page = h.get(&alice, &format!("/profiles/{shared}")).await;
    assert!(page.body.contains("id=\"unshare\""));
    assert!(!page.body.contains("id=\"share\""));
    let page = h.get(&bob, &format!("/profiles/{shared}")).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("id=\"read-only\""));
    assert!(
        !page
            .body
            .contains("<form method=\"post\" action=\"/profiles")
    );
    assert_eq!(
        h.get(&bob, &format!("/profiles/{private}")).await.status,
        404
    );
    for path in [
        "/profiles/nope",
        "/profiles/0",
        "/profiles/99999999",
        "/profiles/nope/nope",
    ] {
        assert_eq!(h.get(&alice, path).await.status, 404, "{path}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_owner_shares_and_unshares(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.profile(&alice, "mine", "{}", false).await;
    let reply = h.post_csrf(&alice, &format!("/profiles/{id}/share")).await;
    assert_eq!(
        (reply.status, reply.location()),
        (303, format!("/profiles/{id}"))
    );
    assert_eq!(h.visibility(id).await, "shared");
    let reply = h
        .post_csrf(&alice, &format!("/profiles/{id}/unshare"))
        .await;
    assert_eq!(reply.status, 303);
    assert_eq!(h.visibility(id).await, "private");
    h.finish().await;
}

#[sqlx::test]
async fn a_non_owner_post_is_refused_and_the_profile_is_unchanged(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let open = h.profile(&alice, "open", "{}", true).await;
    let closed = h.profile(&alice, "closed", "{}", false).await;
    let own_twin = h.profile(&bob, "open", "{}", false).await;
    let reply = h
        .post_csrf(&bob, &format!("/profiles/{open}/unshare"))
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(h.visibility(open).await, "shared");
    assert_eq!(h.visibility(own_twin).await, "private");
    let reply = h.post_csrf(&bob, &format!("/profiles/{open}/share")).await;
    assert_eq!(reply.status, 403);
    assert_eq!(h.visibility(own_twin).await, "private");
    let reply = h
        .post_csrf(&bob, &format!("/profiles/{closed}/share"))
        .await;
    assert_eq!(reply.status, 404);
    assert_eq!(h.visibility(closed).await, "private");
    let forged = format!(
        "csrf={}&owner={}&owner_user_id={}",
        bob.csrf, alice.user_id, alice.user_id
    );
    let reply = h
        .post(&bob, &format!("/profiles/{closed}/share"), &forged)
        .await;
    assert_eq!(reply.status, 404);
    assert_eq!(h.visibility(closed).await, "private");
    h.finish().await;
}

#[sqlx::test]
async fn a_post_without_the_csrf_token_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.profile(&alice, "mine", "{}", false).await;
    let path = format!("/profiles/{id}/share");
    for body in ["", "csrf=", "csrf=wrong", "other=csrf-a-token"] {
        let reply = h.post(&alice, &path, body).await;
        assert_eq!(reply.status, 403, "{body}");
        assert_eq!(h.visibility(id).await, "private", "{body}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn every_rendered_value_is_escaped(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let hostile = h.session(HOSTILE, 'b').await;
    let prefix = format!("content-marker <b onclick=\"y\">{HOSTILE}");
    let json = serde_json::json!({ "prompt_prefix": prefix }).to_string();
    let id = h.profile(&hostile, "evil", &json, true).await;
    let list = h.get(&alice, "/profiles").await;
    let detail = h.get(&alice, &format!("/profiles/{id}")).await;
    for page in [&list, &detail] {
        assert_eq!(page.status, 200);
        assert!(!page.body.contains("<script>alert"));
        assert!(!page.body.contains("'&\r\n"));
        assert!(page.body.contains("&lt;script&gt;alert"));
    }
    assert!(detail.body.contains("content-marker"));
    assert!(!detail.body.contains("<b onclick"));
    h.finish().await;
}

fn checkbox<'a>(body: &'a str, name: &str) -> &'a str {
    let key = format!("name=\"{name}\"");
    let at = body.find(&key).unwrap();
    let start = body[..at].rfind("<input").unwrap();
    let end = at + body[at..].find('>').unwrap();
    &body[start..end]
}

#[sqlx::test]
async fn the_editor_lists_catalog_items_per_kind_with_toggles(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.item("sk-on", "skill", true).await;
    h.item("sk-off", "skill", true).await;
    h.item("sk-admin", "skill", false).await;
    h.item("ag-one", "subagent", true).await;
    h.item("cx-one", "context", true).await;
    h.item("tl-one", "tool", true).await;
    let json = r#"{"selection":[{"item_id":"sk-off","enabled":false}]}"#;
    let id = h.profile(&alice, "mine", json, false).await;
    let page = h.get(&alice, &format!("/profiles/{id}")).await;
    assert_eq!(page.status, 200);
    for kind in ["skill", "subagent", "tool", "context"] {
        assert!(page.body.contains(&format!("id=\"kind-{kind}\"")), "{kind}");
    }
    assert!(page.body.contains(&format!("/profiles/{id}/selection")));
    let on = checkbox(&page.body, "on_sk-on");
    assert!(on.contains("checked") && !on.contains("disabled"));
    let off = checkbox(&page.body, "on_sk-off");
    assert!(!off.contains("checked") && !off.contains("disabled"));
    let admin = checkbox(&page.body, "on_sk-admin");
    assert!(admin.contains("disabled") && !admin.contains("checked"));
    assert!(page.body.contains("disabled by admin"));
    assert!(page.body.contains("id=\"note-ag-one\""));
    assert!(page.body.contains("Kimi"));
    assert!(!page.body.contains("id=\"note-sk-on\""));
    assert!(page.body.contains("<textarea"));
    h.finish().await;
}

#[sqlx::test]
async fn a_non_owner_sees_no_editor(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    h.item("sk-on", "skill", true).await;
    let id = h.profile(&alice, "open", "{}", true).await;
    let page = h.get(&bob, &format!("/profiles/{id}")).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("<textarea"));
    assert!(!page.body.contains("/selection"));
    assert!(!page.body.contains("on_sk-on"));
    h.finish().await;
}

#[sqlx::test]
async fn the_prompt_is_escaped_in_the_textarea(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let hostile = "</textarea><script>alert(1)</script><b onclick=\"y\">'&amp;";
    let json = serde_json::json!({ "authored_prompt": hostile }).to_string();
    let id = h.profile(&alice, "mine", &json, false).await;
    let page = h.get(&alice, &format!("/profiles/{id}")).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("<script>alert"));
    assert!(!page.body.contains("</textarea><script"));
    assert!(!page.body.contains("<b onclick"));
    assert!(page.body.contains("&lt;/textarea&gt;&lt;script&gt;"));
    assert!(page.body.contains("&amp;amp;"));
    h.finish().await;
}

#[sqlx::test]
async fn saving_stores_the_switched_off_items_and_the_prompt(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.item("sk-on", "skill", true).await;
    h.item("sk-off", "skill", true).await;
    h.item("sk-admin", "skill", false).await;
    let id = h.profile(&alice, "mine", "{}", false).await;
    let body = format!(
        "csrf={}&on_sk-on=1&on_sk-admin=1&on_nope=1&prompt=be%20brief%0D%0Aplease",
        alice.csrf
    );
    let reply = h
        .post(&alice, &format!("/profiles/{id}/selection"), &body)
        .await;
    assert_eq!(
        (reply.status, reply.location()),
        (303, format!("/profiles/{id}"))
    );
    let (version, json) = h.latest(id).await;
    assert_eq!(version, 2);
    assert_eq!(json["authored_prompt"], "be brief\nplease");
    assert_eq!(
        json["selection"],
        serde_json::json!([{"item_id": "sk-off", "enabled": false}])
    );
    let body = format!("csrf={}&on_sk-on=1&prompt=", alice.csrf);
    let reply = h
        .post(&alice, &format!("/profiles/{id}/selection"), &body)
        .await;
    assert_eq!(reply.status, 303);
    let (version, json) = h.latest(id).await;
    assert_eq!(version, 3);
    assert!(json.get("authored_prompt").is_none());
    assert_eq!(
        json["selection"],
        serde_json::json!([{"item_id": "sk-off", "enabled": false}])
    );
    let body = format!("csrf={}&on_sk-off=1&prompt=", alice.csrf);
    let reply = h
        .post(&alice, &format!("/profiles/{id}/selection"), &body)
        .await;
    assert_eq!(reply.status, 303);
    let (version, json) = h.latest(id).await;
    assert_eq!(version, 4);
    assert_eq!(
        json["selection"],
        serde_json::json!([{"item_id": "sk-on", "enabled": false}])
    );
    assert!(json.get("authored_prompt").is_none());
    h.finish().await;
}

#[sqlx::test]
async fn switching_an_item_off_then_on_returns_to_the_first_version(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let alice = h.session("alice", 'a').await;
    h.item("sk-on", "skill", true).await;
    let id = h.profile(&alice, "mine", "{}", false).await;
    let path = format!("/profiles/{id}/selection");
    let off = format!("csrf={}&prompt=", alice.csrf);
    assert_eq!(h.post(&alice, &path, &off).await.status, 303);
    let page = h.get(&alice, &format!("/profiles/{id}")).await;
    assert!(page.body.contains("<dd>2</dd>"), "{}", page.body);
    assert!(!checkbox(&page.body, "on_sk-on").contains("checked"));
    let on = format!("csrf={}&on_sk-on=1&prompt=", alice.csrf);
    assert_eq!(h.post(&alice, &path, &on).await.status, 303);
    let page = h.get(&alice, &format!("/profiles/{id}")).await;
    assert!(page.body.contains("<dd>1</dd>"), "{}", page.body);
    assert!(checkbox(&page.body, "on_sk-on").contains("checked"));
    let listing = h.get(&alice, "/profiles").await;
    assert!(listing.body.contains("<td>1</td>"), "{}", listing.body);
    assert!(!listing.body.contains("<td>2</td>"), "{}", listing.body);
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM profile_version WHERE profile_id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 2);
    h.finish().await;
}

#[sqlx::test]
async fn a_refused_save_writes_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    h.item("sk-on", "skill", true).await;
    let mine = h.profile(&alice, "mine", "{}", false).await;
    let open = h.profile(&alice, "open", "{}", true).await;
    let path = format!("/profiles/{mine}/selection");
    for body in ["", "csrf=", "csrf=wrong", "prompt=x"] {
        assert_eq!(h.post(&alice, &path, body).await.status, 403, "{body}");
    }
    let forbidden = format!("csrf={}&prompt=a%0Db", alice.csrf);
    assert_eq!(h.post(&alice, &path, &forbidden).await.status, 400);
    let over = format!("csrf={}&prompt={}", alice.csrf, "x".repeat(70_000));
    assert_eq!(h.post(&alice, &path, &over).await.status, 413);
    let body = format!("csrf={}&prompt=hi", bob.csrf);
    assert_eq!(h.post(&bob, &path, &body).await.status, 404);
    let shared = format!("/profiles/{open}/selection");
    assert_eq!(h.post(&bob, &shared, &body).await.status, 403);
    assert_eq!(h.latest(mine).await.0, 1);
    assert_eq!(h.latest(open).await.0, 1);
    h.finish().await;
}

#[sqlx::test]
async fn a_save_for_a_tool_item_needs_the_grant(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.item("tl-one", "tool", true).await;
    let id = h.profile(&alice, "mine", "{}", false).await;
    let body = format!("csrf={}&prompt=", alice.csrf);
    let reply = h
        .post(&alice, &format!("/profiles/{id}/selection"), &body)
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(h.latest(id).await.0, 1);
    h.finish().await;
}

#[sqlx::test]
async fn a_save_obeys_the_model_allowlist(pool: PgPool) {
    let h = Harness::start_allowing(pool, "opus").await;
    let alice = h.session("alice", 'a').await;
    let id = h
        .profile(&alice, "mine", r#"{"model":"sonnet"}"#, false)
        .await;
    let body = format!("csrf={}&prompt=hi", alice.csrf);
    let reply = h
        .post(&alice, &format!("/profiles/{id}/selection"), &body)
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(h.latest(id).await.0, 1);
    h.finish().await;
}

#[sqlx::test]
async fn empty_kinds_are_not_rendered(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.item("sk-on", "skill", true).await;
    let id = h.profile(&alice, "mine", "{}", false).await;
    let page = h.get(&alice, &format!("/profiles/{id}")).await;
    assert!(page.body.contains("id=\"kind-skill\""));
    assert!(!page.body.contains("id=\"kind-tool\""));
    h.finish().await;
}
