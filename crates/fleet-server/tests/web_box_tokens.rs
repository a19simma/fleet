//! The per-Box token page over HTTP: session and CSRF gates, the token shown once in the POST
//! response, owner-scoped listing and revoke, and hostile input refused. The tests need a
//! Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]` and live in their own binary
//! because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

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
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    users: Users,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        Self::start_with(pool, true).await
    }

    async fn start_with(pool: PgPool, configured: bool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
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
        let serving = store.clone();
        let task = tokio::spawn(async move {
            serve_with_web(&serving, &bearer, web, TcpIncoming::from(listener), async {
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

    async fn session(&self, name: &str, seed: char) -> Session {
        let user_id: i64 =
            sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
                .bind(name)
                .fetch_one(&self.pool)
                .await
                .unwrap();
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
        }
    }

    async fn send(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        if !extra
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("origin"))
        {
            let _ = write!(request, "Origin: {ORIGIN}\r\n");
        }
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

    async fn finish(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn token_in(body: &str) -> Option<String> {
    let start = body.find("fbx_")?;
    let token: String = body[start..].chars().take(68).collect();
    fleet_core::box_token::is_token(&token).then_some(token)
}

async fn count(h: &Harness, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&h.pool).await.unwrap()
}

fn bx(n: u32) -> String {
    format!("box-{n}")
}

fn issue_body(s: &Session, name: &str, label: &str) -> String {
    format!("csrf={}&box_name={name}&label={label}", s.csrf)
}

#[sqlx::test]
async fn the_pages_need_a_session_and_follow_the_console_switch(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let reply = h.send("GET", "/box-tokens", &[], b"").await;
    assert_eq!(reply.status, 303);
    assert_eq!(reply.location(), "/login");
    for path in ["/box-tokens/issue", "/box-tokens/revoke"] {
        let reply = h.send("POST", path, &[FORM], b"box_name=x").await;
        assert_eq!(reply.status, 403, "{path}");
    }
    h.finish().await;
    let off = Harness::start_with(pool, false).await;
    let alice = off.session("alice", 'a').await;
    assert_eq!(off.get(&alice, "/box-tokens").await.status, 404);
    off.finish().await;
}

#[sqlx::test]
async fn the_token_is_shown_once_in_the_post_response_only(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let made = h
        .post(
            &alice,
            "/box-tokens/issue",
            &issue_body(&alice, &bx(1), "laptop"),
        )
        .await;
    assert_eq!(made.status, 200, "{}", made.head);
    assert_eq!(made.location(), "");
    assert!(made.head.to_ascii_lowercase().contains("no-store"));
    let token = token_in(&made.body).unwrap();
    assert!(!made.head.contains(&token));
    let page = h.get(&alice, "/box-tokens").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains(&token));
    assert!(!page.body.contains("fbx_"));
    assert!(page.body.contains("laptop"));
    assert!(page.body.contains(&bx(1)));
    let resolved = h.users.resolve_box_token(token.as_bytes()).await.unwrap();
    assert!(resolved.is_some());
    h.finish().await;
}

#[sqlx::test]
async fn issuing_needs_the_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bad = h
        .post(
            &alice,
            "/box-tokens/issue",
            &format!("csrf=wrong&box_name={}&label=x", bx(1)),
        )
        .await;
    assert_eq!(bad.status, 403);
    let none = h
        .post(
            &alice,
            "/box-tokens/issue",
            &format!("box_name={}&label=x", bx(1)),
        )
        .await;
    assert_eq!(none.status, 403);
    assert_eq!(count(&h, "SELECT count(*) FROM box_tokens").await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn revoking_needs_the_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.post(
        &alice,
        "/box-tokens/issue",
        &issue_body(&alice, &bx(1), "x"),
    )
    .await;
    let id = count(&h, "SELECT id FROM box_tokens").await;
    let bad = h
        .post(&alice, "/box-tokens/revoke", &format!("csrf=wrong&id={id}"))
        .await;
    assert_eq!(bad.status, 403);
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM box_tokens WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    h.finish().await;
}

#[sqlx::test]
async fn hostile_box_names_and_labels_are_refused_and_nothing_is_made(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let long_label = "x".repeat(65);
    let long_name = "n".repeat(300);
    let ok = bx(7);
    let cases: [(&str, &str); 12] = [
        ("", "ok"),
        ("a%20b", "ok"),
        ("a%2Fb", "ok"),
        ("a%0Ab", "ok"),
        ("a%0D%0Ab", "ok"),
        ("%E2%80%A8", "ok"),
        ("..", "ok"),
        ("a%5Cb", "ok"),
        ("%C3%A9", "ok"),
        (long_name.as_str(), "ok"),
        (ok.as_str(), "a%0Ab"),
        (ok.as_str(), long_label.as_str()),
    ];
    for (name, label) in cases {
        let made = h
            .post(
                &alice,
                "/box-tokens/issue",
                &issue_body(&alice, name, label),
            )
            .await;
        assert_eq!(made.status, 303, "{name} {label}");
        assert_eq!(
            made.location(),
            "/box-tokens?notice=invalid",
            "{name} {label}"
        );
    }
    let nul = h
        .post(
            &alice,
            "/box-tokens/issue",
            &issue_body(&alice, &bx(7), "a%00b"),
        )
        .await;
    assert_eq!(nul.location(), "/box-tokens?notice=invalid");
    assert_eq!(count(&h, "SELECT count(*) FROM box_tokens").await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_missing_box_name_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let made = h
        .post(
            &alice,
            "/box-tokens/issue",
            &format!("csrf={}&label=x", alice.csrf),
        )
        .await;
    assert_eq!(made.location(), "/box-tokens?notice=invalid");
    assert_eq!(count(&h, "SELECT count(*) FROM box_tokens").await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_taken_name_and_the_cap_show_fixed_notices(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let first = h
        .post(&alice, "/box-tokens/issue", &issue_body(&alice, &bx(1), ""))
        .await;
    assert_eq!(first.status, 200);
    let again = h
        .post(&alice, "/box-tokens/issue", &issue_body(&alice, &bx(1), ""))
        .await;
    assert_eq!(again.location(), "/box-tokens?notice=taken");
    for n in 0..19_u32 {
        let name = bx(n + 100);
        let made = h
            .post(&alice, "/box-tokens/issue", &issue_body(&alice, &name, ""))
            .await;
        assert_eq!(made.status, 200, "{name}");
    }
    let capped = h
        .post(
            &alice,
            "/box-tokens/issue",
            &issue_body(&alice, &bx(900), ""),
        )
        .await;
    assert_eq!(capped.location(), "/box-tokens?notice=limit");
    let page = h.get(&alice, "/box-tokens?notice=taken").await;
    assert!(page.body.contains("id=\"notice\""));
    let unknown = h.get(&alice, "/box-tokens?notice=%3Cb%3E").await;
    assert!(!unknown.body.contains("id=\"notice\""));
    h.finish().await;
}

#[sqlx::test]
async fn the_list_is_the_users_own_and_escaped(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    h.post(
        &alice,
        "/box-tokens/issue",
        &issue_body(&alice, &bx(11), "%3Cscript%3Ex%3C%2Fscript%3E"),
    )
    .await;
    h.post(&bob, "/box-tokens/issue", &issue_body(&bob, &bx(22), "bl"))
        .await;
    let page = h.get(&alice, "/box-tokens").await;
    assert!(page.body.contains(&bx(11)));
    assert!(!page.body.contains(&bx(22)));
    assert!(!page.body.contains("<script>x"));
    assert!(page.body.contains("&lt;script&gt;"));
    h.finish().await;
}

#[sqlx::test]
async fn revoke_is_owner_scoped_and_marks_the_row(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let made = h
        .post(&alice, "/box-tokens/issue", &issue_body(&alice, &bx(1), ""))
        .await;
    let token = token_in(&made.body).unwrap();
    let id = count(&h, "SELECT id FROM box_tokens").await;
    let theirs = h
        .post(
            &bob,
            "/box-tokens/revoke",
            &format!("csrf={}&id={id}", bob.csrf),
        )
        .await;
    assert_eq!(theirs.location(), "/box-tokens?notice=not_found");
    assert!(
        h.users
            .resolve_box_token(token.as_bytes())
            .await
            .unwrap()
            .is_some()
    );
    for junk in ["", "abc", "-1", "99999999999999999999", "1%0A"] {
        let bad = h
            .post(
                &alice,
                "/box-tokens/revoke",
                &format!("csrf={}&id={junk}", alice.csrf),
            )
            .await;
        assert_eq!(bad.location(), "/box-tokens?notice=not_found", "{junk}");
    }
    let mine = h
        .post(
            &alice,
            "/box-tokens/revoke",
            &format!("csrf={}&id={id}", alice.csrf),
        )
        .await;
    assert_eq!(mine.status, 303);
    assert_eq!(mine.location(), "/box-tokens?notice=revoked");
    assert!(
        h.users
            .resolve_box_token(token.as_bytes())
            .await
            .unwrap()
            .is_none()
    );
    let page = h.get(&alice, "/box-tokens").await;
    assert!(page.body.contains("revoked"));
    h.finish().await;
}

#[sqlx::test]
async fn the_page_has_the_enroll_hint_and_a_nav_entry(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let page = h.get(&alice, "/box-tokens").await;
    assert!(page.body.contains("mise run tofu:enroll"));
    assert!(page.body.contains("href=\"/box-tokens\""));
    let tokens = h.get(&alice, "/tokens").await;
    assert!(tokens.body.contains("href=\"/box-tokens\""));
    h.finish().await;
}

#[sqlx::test]
async fn the_lifetime_field_is_range_checked_and_defaults(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let hostile = [
        "abc",
        "-1",
        "366",
        "1.5",
        "99999999999",
        "1%0A2",
        "%2B5",
        "%EF%BC%91",
    ];
    for days in hostile {
        let body = format!("{}&days={days}", issue_body(&alice, &bx(1), ""));
        let made = h.post(&alice, "/box-tokens/issue", &body).await;
        assert_eq!(made.location(), "/box-tokens?notice=invalid", "{days}");
    }
    assert_eq!(count(&h, "SELECT count(*) FROM box_tokens").await, 0);
    for (n, days) in [(1, ""), (2, "1"), (3, "365"), (4, "0")] {
        let body = format!("{}&days={days}", issue_body(&alice, &bx(n), ""));
        let made = h.post(&alice, "/box-tokens/issue", &body).await;
        assert_eq!(made.status, 200, "{days}");
    }
    let spans: Vec<i64> = sqlx::query_scalar(
        "SELECT round(extract(epoch FROM expires_at - created_at) / 86400)::bigint \
         FROM box_tokens ORDER BY id",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();
    assert_eq!(spans, [90, 1, 365, 90]);
    h.finish().await;
}

#[sqlx::test]
async fn names_are_trimmed_and_the_status_column_tracks_time_and_use(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let padded = format!("csrf={}&box_name=%20{}%20&label=", alice.csrf, bx(5));
    let made = h.post(&alice, "/box-tokens/issue", &padded).await;
    assert_eq!(made.status, 200);
    let stored: String = sqlx::query_scalar("SELECT box_name FROM box_tokens")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(stored, bx(5));
    let fresh = h.get(&alice, "/box-tokens").await;
    assert!(fresh.body.contains("never"));
    assert!(fresh.body.contains("active"));
    assert!(fresh.body.contains("action=\"/box-tokens/revoke\""));
    sqlx::query("UPDATE box_tokens SET expires_at = now() - interval '1 hour', created_at = now() - interval '2 hours'")
        .execute(&h.pool)
        .await
        .unwrap();
    let old = h.get(&alice, "/box-tokens").await;
    assert!(old.body.contains("expired"));
    assert!(!old.body.contains("action=\"/box-tokens/revoke\""));
    h.finish().await;
}
