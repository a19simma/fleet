//! Admin-issued setup code enrollment over HTTP with a software authenticator. They need a
//! Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]`.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code asserts by panicking"
)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::Url;

const WAIT: Duration = Duration::from_secs(20);
const SETTLE: Duration = Duration::from_millis(700);
const ORIGIN: &str = "https://fleet.example.com";
const EVIL: &str = "https://evil.example.com";
const START: &str = "/passkey/enroll/start";
const FINISH: &str = "/passkey/enroll/finish";

type Authenticator = WebauthnAuthenticator<SoftPasskey>;

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }

    fn cookie(&self) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("set-cookie")
                .then(|| value.trim().to_owned())
        })
    }
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_auth(auth);
        let store = Store::new(pool.clone());
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

    async fn send(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        send_to(self.addr, method, path, extra, body).await
    }

    async fn post(&self, path: &str, extra: &[(&str, &str)], body: &Value) -> Reply {
        post_to(self.addr, path, extra, body).await
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

async fn send_to(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut stream = TcpStream::connect(addr).await.unwrap();
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

async fn post_to(addr: SocketAddr, path: &str, extra: &[(&str, &str)], body: &Value) -> Reply {
    let mut headers = vec![("Content-Type", "application/json")];
    headers.extend_from_slice(extra);
    send_to(addr, "POST", path, &headers, body.to_string().as_bytes()).await
}

struct Prepared {
    ceremony: Value,
    credential: Value,
}

impl Prepared {
    fn body(&self) -> Value {
        json!({ "ceremony": self.ceremony, "credential": self.credential })
    }
}

async fn prepare(h: &Harness, authn: &mut Authenticator, code: &str) -> Prepared {
    let start = h.post(START, &[], &json!({ "code": code })).await;
    assert_eq!(start.status, 200, "{}", start.body);
    let start = start.json();
    let options = serde_json::from_value(start["options"].clone()).unwrap();
    let credential = authn
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    Prepared {
        ceremony: start["ceremony"].clone(),
        credential: serde_json::to_value(credential).unwrap(),
    }
}

fn authenticator() -> Authenticator {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

async fn issue(pool: &PgPool, cmd: &AdminCommand) -> (i64, String) {
    let outcome = run(pool, cmd, "test").await.unwrap();
    let code = String::from_utf8(outcome.setup_code.expose().to_vec()).unwrap();
    (outcome.user_id, code)
}

async fn create(pool: &PgPool, name: &str) -> (i64, String) {
    issue(pool, &AdminCommand::CreateUser(name.to_owned())).await
}

async fn reset(pool: &PgPool, name: &str) -> (i64, String) {
    issue(pool, &AdminCommand::ResetPasskeys(name.to_owned())).await
}

async fn keys_of(pool: &PgPool, user: i64) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM passkeys WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn all_keys(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM passkeys")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn an_issued_code_registers_a_passkey_for_its_user_and_signs_them_in(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let (bob, _) = create(&h.pool, "bob").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &code).await;
    let done = h.post(FINISH, &[], &prepared.body()).await;
    assert_eq!(done.status, 200, "{}", done.body);
    let cookie = done.cookie().unwrap();
    assert!(
        cookie.starts_with(&format!("{SESSION_COOKIE}=")),
        "{cookie}"
    );
    for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(flag), "{cookie}");
    }
    assert_eq!(keys_of(&h.pool, alice).await, 1);
    assert_eq!(keys_of(&h.pool, bob).await, 0);
    let session_user: i64 = sqlx::query_scalar("SELECT user_id FROM web_sessions")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(session_user, alice);
    let spent: bool =
        sqlx::query_scalar("SELECT used_at IS NOT NULL FROM setup_codes WHERE user_id = $1")
            .bind(alice)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(spent);
    h.finish().await;
}

#[sqlx::test]
async fn a_reset_code_registers_a_new_passkey_after_a_reset(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, first) = create(&h.pool, "alice").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &first).await;
    assert_eq!(h.post(FINISH, &[], &prepared.body()).await.status, 200);
    let (_, second) = reset(&h.pool, "alice").await;
    assert_eq!(keys_of(&h.pool, alice).await, 0);
    let mut fresh = authenticator();
    let prepared = prepare(&h, &mut fresh, &second).await;
    assert_eq!(h.post(FINISH, &[], &prepared.body()).await.status, 200);
    assert_eq!(keys_of(&h.pool, alice).await, 1);
    h.finish().await;
}

#[sqlx::test]
async fn a_used_code_is_refused_at_start_and_at_a_second_finish(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let mut one = authenticator();
    let mut two = authenticator();
    let first = prepare(&h, &mut one, &code).await;
    let second = prepare(&h, &mut two, &code).await;
    assert_eq!(h.post(FINISH, &[], &first.body()).await.status, 200);
    assert_eq!(h.post(FINISH, &[], &second.body()).await.status, 400);
    assert_eq!(keys_of(&h.pool, alice).await, 1);
    let again = h.post(START, &[], &json!({ "code": code })).await;
    assert_eq!(again.status, 400);
    h.finish().await;
}

#[sqlx::test]
async fn an_expired_code_is_refused_at_start_and_at_finish(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &code).await;
    sqlx::query("UPDATE setup_codes SET expires_at = now() - interval '1 minute'")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.post(FINISH, &[], &prepared.body()).await.status, 400);
    assert_eq!(keys_of(&h.pool, alice).await, 0);
    let start = h.post(START, &[], &json!({ "code": code })).await;
    assert_eq!(start.status, 400);
    h.finish().await;
}

#[sqlx::test]
async fn bad_codes_all_get_the_same_answer(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (_, used) = create(&h.pool, "used").await;
    let (_, expired) = create(&h.pool, "expired").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &used).await;
    assert_eq!(h.post(FINISH, &[], &prepared.body()).await.status, 200);
    sqlx::query(
        "UPDATE setup_codes SET expires_at = now() - interval '1 minute' WHERE used_at IS NULL",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let unknown = "0".repeat(64);
    let mut seen = Vec::new();
    for code in [
        used.as_str(),
        expired.as_str(),
        unknown.as_str(),
        "",
        "short",
    ] {
        let reply = h.post(START, &[], &json!({ "code": code })).await;
        assert_eq!(reply.status, 400);
        seen.push(reply.body);
    }
    assert!(seen.windows(2).all(|pair| pair[0] == pair[1]), "{seen:?}");
    assert_eq!(
        h.post(START, &[], &json!({})).await.status,
        400,
        "missing field"
    );
    h.finish().await;
}

#[sqlx::test]
async fn a_code_cannot_register_a_passkey_for_another_user(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let (bob, _) = create(&h.pool, "bob").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &code).await;
    sqlx::query("UPDATE setup_codes SET user_id = $1 WHERE user_id = $2")
        .bind(bob)
        .bind(alice)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.post(FINISH, &[], &prepared.body()).await.status, 400);
    assert_eq!(all_keys(&h.pool).await, 0);
    let spent: i64 =
        sqlx::query_scalar("SELECT count(*) FROM setup_codes WHERE used_at IS NOT NULL")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(spent, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_reset_after_start_leaves_no_passkey(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &code).await;
    reset(&h.pool, "alice").await;
    assert_eq!(h.post(FINISH, &[], &prepared.body()).await.status, 400);
    assert_eq!(keys_of(&h.pool, alice).await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_finish_waits_for_the_user_lock_and_loses_to_a_reset(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &code).await;
    let mut tx = h.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(alice)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let addr = h.addr;
    let body = prepared.body();
    let racer = tokio::spawn(async move { post_to(addr, FINISH, &[], &body).await });
    tokio::time::sleep(SETTLE).await;
    assert!(!racer.is_finished(), "finish ran without the user lock");
    sqlx::query("DELETE FROM passkeys WHERE user_id = $1")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM setup_codes WHERE user_id = $1 AND used_at IS NULL")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let reply = tokio::time::timeout(WAIT, racer).await.unwrap().unwrap();
    assert_eq!(reply.status, 400);
    assert_eq!(keys_of(&h.pool, alice).await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn racing_resets_never_leave_a_passkey(pool: PgPool) {
    let h = Harness::start(pool).await;
    for round in 0..8 {
        let name = format!("racer{round}");
        let (user, code) = create(&h.pool, &name).await;
        let mut authn = authenticator();
        let prepared = prepare(&h, &mut authn, &code).await;
        let addr = h.addr;
        let body = prepared.body();
        let finish = tokio::spawn(async move { post_to(addr, FINISH, &[], &body).await });
        let pool = h.pool.clone();
        let resetting = tokio::spawn(async move { reset(&pool, &name).await });
        tokio::time::timeout(WAIT, finish).await.unwrap().unwrap();
        tokio::time::timeout(WAIT, resetting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(keys_of(&h.pool, user).await, 0, "round {round}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn enroll_routes_refuse_a_foreign_origin(pool: PgPool) {
    let h = Harness::start(pool).await;
    for path in [START, FINISH] {
        let reply = h.post(path, &[("Origin", EVIL)], &json!({})).await;
        assert_eq!(reply.status, 403, "{path}: {}", reply.head);
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_enroll_page_renders_without_spending_the_code(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (_, code) = create(&h.pool, "alice").await;
    let page = h.send("GET", &format!("/enroll/{code}"), &[], b"").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("data-mode=\"enroll\""), "{}", page.body);
    assert!(!page.body.contains(&code));
    let spent: i64 =
        sqlx::query_scalar("SELECT count(*) FROM setup_codes WHERE used_at IS NOT NULL")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(spent, 0);
    h.finish().await;
}

async fn held_lock(h: &Harness, user: i64) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = h.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx
}

#[sqlx::test]
async fn two_finishes_of_one_code_register_exactly_one_passkey(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let mut one = authenticator();
    let mut two = authenticator();
    let first = prepare(&h, &mut one, &code).await;
    let second = prepare(&h, &mut two, &code).await;
    let tx = held_lock(&h, alice).await;
    let addr = h.addr;
    let (a, b) = (first.body(), second.body());
    let left = tokio::spawn(async move { post_to(addr, FINISH, &[], &a).await });
    let right = tokio::spawn(async move { post_to(addr, FINISH, &[], &b).await });
    tokio::time::sleep(SETTLE).await;
    tx.commit().await.unwrap();
    let left = tokio::time::timeout(WAIT, left).await.unwrap().unwrap();
    let right = tokio::time::timeout(WAIT, right).await.unwrap().unwrap();
    let mut statuses = [left.status, right.status];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 400]);
    assert_eq!(keys_of(&h.pool, alice).await, 1);
    h.finish().await;
}

#[sqlx::test]
async fn a_code_that_expires_while_finish_waits_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let (alice, code) = create(&h.pool, "alice").await;
    let mut authn = authenticator();
    let prepared = prepare(&h, &mut authn, &code).await;
    let mut tx = held_lock(&h, alice).await;
    let addr = h.addr;
    let body = prepared.body();
    let racer = tokio::spawn(async move { post_to(addr, FINISH, &[], &body).await });
    tokio::time::sleep(SETTLE).await;
    sqlx::query("UPDATE setup_codes SET expires_at = now() - interval '1 minute'")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let reply = tokio::time::timeout(WAIT, racer).await.unwrap().unwrap();
    assert_eq!(reply.status, 400);
    assert_eq!(keys_of(&h.pool, alice).await, 0);
    h.finish().await;
}
