//! `/catalog` and `/users/{id}/capabilities` stubs behind `admin_gate`: GET and POST against
//! no session, a non-admin, an admin, an admin demoted after login, and a missing or wrong
//! CSRF token. The tests need a Postgres superuser URL in `DATABASE_URL` for
//! `#[sqlx::test]` and live in their own binary because each one binds a socket.

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
const PATHS: [&str; 2] = ["/catalog", "/users/1/capabilities"];

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

type Snapshot = (Vec<(i64, bool)>, i64, i64);

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
        let web = Web::with_auth(auth);
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
        (flags, audit, sessions)
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
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
        let (head, _) = raw.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        let location = head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default();
        (status, location)
    }

    async fn expect(
        &self,
        method: &str,
        who: Option<&Session>,
        body: Option<&str>,
        want: (u16, &str),
    ) {
        let before = self.snapshot().await;
        for path in PATHS {
            let (status, location) = self
                .send(method, path, who.map(|s| s.cookie.as_str()), body)
                .await;
            assert_eq!((status, location.as_str()), want, "{method} {path}");
        }
        assert_eq!(self.snapshot().await, before);
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
async fn get_as_an_admin_renders_the_stub(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    h.expect("GET", Some(&root), None, (501, "")).await;
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
    h.expect("GET", Some(&root), None, (501, "")).await;
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
async fn post_as_an_admin_with_a_valid_csrf_reaches_the_stub(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let body = csrf_body(&root);
    h.expect("POST", Some(&root), Some(&body), (501, "")).await;
    h.finish().await;
}

#[sqlx::test]
async fn post_after_demotion_with_a_valid_csrf_is_forbidden(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'b', true).await;
    let body = csrf_body(&root);
    h.expect("POST", Some(&root), Some(&body), (501, "")).await;
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
