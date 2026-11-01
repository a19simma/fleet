//! Passkey setup, login, sessions and the web POST limits, driven over HTTP with a software
//! authenticator. They need a Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]`.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code asserts by panicking"
)]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{AuthError, MAX_BODY_BYTES, SESSION_COOKIE, Web, WebAuth};
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
const ORIGIN: &str = "https://fleet.example.com";
const EVIL: &str = "https://evil.example.com";

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
    users: Users,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn webauth(pool: &PgPool, users: &Users, origin: &str, rp_id: Option<&str>) -> WebAuth {
    WebAuth::new(pool.clone(), users.clone(), origin, rp_id).unwrap()
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let users = Users::new(pool.clone());
        let web = Web::with_auth(webauth(&pool, &users, ORIGIN, Some("example.com")));
        let store = Store::new(pool.clone());
        let auth = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve_with_web(&store, &auth, web, TcpIncoming::from(listener), async {
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

    async fn post(&self, path: &str, extra: &[(&str, &str)], body: &Value) -> Reply {
        let mut headers = vec![("Content-Type", "application/json")];
        headers.extend_from_slice(extra);
        self.send("POST", path, &headers, body.to_string().as_bytes())
            .await
    }

    async fn get(&self, path: &str, extra: &[(&str, &str)]) -> Reply {
        self.send("GET", path, extra, b"").await
    }

    async fn setup(&self, authn: &mut Authenticator, name: &str) -> Reply {
        let code = self.users.issue_setup_code().await.unwrap().unwrap();
        let code = String::from_utf8(code.expose().to_vec()).unwrap();
        self.setup_with(authn, &code, name, ORIGIN).await
    }

    async fn setup_with(
        &self,
        authn: &mut Authenticator,
        code: &str,
        name: &str,
        origin: &str,
    ) -> Reply {
        let start = self
            .post(
                "/passkey/setup/start",
                &[],
                &json!({ "code": code, "username": name }),
            )
            .await;
        assert_eq!(start.status, 200, "{}", start.body);
        let start = start.json();
        let options = serde_json::from_value(start["options"].clone()).unwrap();
        let credential = authn
            .do_registration(Url::parse(origin).unwrap(), options)
            .unwrap();
        self.post(
            "/passkey/setup/finish",
            &[],
            &json!({ "ceremony": start["ceremony"], "credential": credential }),
        )
        .await
    }

    async fn login_start(&self, name: &str) -> (Value, Value) {
        let start = self
            .post("/passkey/login/start", &[], &json!({ "username": name }))
            .await;
        assert_eq!(start.status, 200, "{}", start.body);
        let start = start.json();
        (start["ceremony"].clone(), start["options"].clone())
    }

    async fn login_at(&self, authn: &mut Authenticator, name: &str, origin: &str) -> Reply {
        let (ceremony, options) = self.login_start(name).await;
        let credential = authn
            .do_authentication(
                Url::parse(origin).unwrap(),
                serde_json::from_value(options).unwrap(),
            )
            .unwrap();
        self.post(
            "/passkey/login/finish",
            &[],
            &json!({ "ceremony": ceremony, "credential": credential }),
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

fn authenticator() -> Authenticator {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

fn cookie_header(reply: &Reply) -> String {
    let set = reply.cookie().unwrap();
    set.split(';').next().unwrap().to_owned()
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[sqlx::test]
async fn setup_creates_admin_and_first_passkey_then_stops_working(pool: PgPool) {
    let h = Harness::start(pool).await;
    let bootstrap = h.users.bootstrap_user().await.unwrap();
    assert!(bootstrap > 0);
    let mut authn = authenticator();
    let code = h.users.issue_setup_code().await.unwrap().unwrap();
    let code = String::from_utf8(code.expose().to_vec()).unwrap();

    let done = h.setup_with(&mut authn, &code, "Admin", ORIGIN).await;
    assert_eq!(done.status, 200, "{}", done.body);
    let cookie = done.cookie().unwrap();
    assert!(
        cookie.starts_with(&format!("{SESSION_COOKIE}=")),
        "{cookie}"
    );
    for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(flag), "{cookie}");
    }
    let name: String =
        sqlx::query_scalar("SELECT username FROM users WHERE lower(username) <> 'bootstrap'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(name, "admin");
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 1);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);

    let mut second = authenticator();
    let again = h
        .post(
            "/passkey/setup/start",
            &[],
            &json!({ "code": code, "username": "other" }),
        )
        .await;
    assert_eq!(again.status, 400);
    let spent = h.setup_with_unchecked(&mut second, &code).await;
    assert_ne!(spent, 200);
    assert_eq!(
        count(
            &h.pool,
            "SELECT count(*) FROM users WHERE lower(username) <> 'bootstrap'"
        )
        .await,
        1
    );
    h.finish().await;
}

impl Harness {
    async fn setup_with_unchecked(&self, authn: &mut Authenticator, code: &str) -> u16 {
        let start = self
            .post(
                "/passkey/setup/start",
                &[],
                &json!({ "code": code, "username": "late" }),
            )
            .await;
        if start.status != 200 {
            return start.status;
        }
        let start = start.json();
        let options = serde_json::from_value(start["options"].clone()).unwrap();
        let credential = authn
            .do_registration(Url::parse(ORIGIN).unwrap(), options)
            .unwrap();
        self.post(
            "/passkey/setup/finish",
            &[],
            &json!({ "ceremony": start["ceremony"], "credential": credential }),
        )
        .await
        .status
    }
}

#[sqlx::test]
async fn a_wrong_setup_code_creates_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let _real = h.users.issue_setup_code().await.unwrap().unwrap();
    let start = h
        .post(
            "/passkey/setup/start",
            &[],
            &json!({ "code": "0".repeat(64), "username": "admin" }),
        )
        .await;
    assert_eq!(start.status, 400);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 0);
    assert_eq!(
        count(
            &h.pool,
            "SELECT count(*) FROM users WHERE lower(username) <> 'bootstrap'"
        )
        .await,
        0
    );
    h.finish().await;
}

#[sqlx::test]
async fn the_username_bootstrap_is_reserved_in_any_case(pool: PgPool) {
    let h = Harness::start(pool).await;
    let code = h.users.issue_setup_code().await.unwrap().unwrap();
    let code = String::from_utf8(code.expose().to_vec()).unwrap();
    for name in ["bootstrap", "Bootstrap", "BOOTSTRAP"] {
        let start = h
            .post(
                "/passkey/setup/start",
                &[],
                &json!({ "code": code, "username": name }),
            )
            .await;
        assert_eq!(start.status, 400, "{name}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn login_succeeds_and_usernames_are_case_folded(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "Alice").await.status, 200);

    let logged = h.login_at(&mut authn, "ALICE", ORIGIN).await;
    assert_eq!(logged.status, 200, "{}", logged.body);
    let cookie = cookie_header(&logged);
    let account = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(account.status, 200);
    assert!(account.body.contains("alice"), "{}", account.body);
    let anonymous = h.get("/account", &[]).await;
    assert_eq!(anonymous.status, 303);
    h.finish().await;
}

#[sqlx::test]
async fn a_wrong_origin_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);
    let refused = h.login_at(&mut authn, "alice", EVIL).await;
    assert_eq!(refused.status, 400);
    assert!(refused.cookie().is_none());
    h.finish().await;
}

#[sqlx::test]
async fn a_wrong_rp_id_is_refused(pool: PgPool) {
    let h = Harness::start(pool.clone()).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);

    let (ceremony, _) = h.login_start("alice").await;
    let foreign = webauth(&pool, &h.users, ORIGIN, Some("fleet.example.com"));
    let (_, foreign_options) = foreign.login_start("alice").await.unwrap();
    let credential = authn
        .do_authentication(Url::parse(ORIGIN).unwrap(), foreign_options)
        .unwrap();
    let refused = h
        .post(
            "/passkey/login/finish",
            &[],
            &json!({ "ceremony": ceremony, "credential": credential }),
        )
        .await;
    assert_eq!(refused.status, 400);
    assert!(refused.cookie().is_none());
    h.finish().await;
}

#[sqlx::test]
async fn a_replayed_challenge_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);

    let (ceremony, options) = h.login_start("alice").await;
    let credential = authn
        .do_authentication(
            Url::parse(ORIGIN).unwrap(),
            serde_json::from_value(options).unwrap(),
        )
        .unwrap();
    let body = json!({ "ceremony": ceremony, "credential": credential });
    assert_eq!(
        h.post("/passkey/login/finish", &[], &body).await.status,
        200
    );
    assert_eq!(
        h.post("/passkey/login/finish", &[], &body).await.status,
        400
    );
    h.finish().await;
}

#[sqlx::test]
async fn a_cloned_counter_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);
    assert_eq!(h.login_at(&mut authn, "alice", ORIGIN).await.status, 200);

    let changed = sqlx::query(
        "UPDATE passkeys SET public_key = convert_to(jsonb_set(convert_from(public_key, 'UTF8')::jsonb, '{cred,counter}', '1000')::text, 'UTF8') \
         WHERE convert_from(public_key, 'UTF8')::jsonb #> '{cred,counter}' IS NOT NULL",
    )
    .execute(&h.pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(changed, 1);

    let refused = h.login_at(&mut authn, "alice", ORIGIN).await;
    assert_eq!(refused.status, 400);
    assert!(refused.cookie().is_none());
    h.finish().await;
}

#[sqlx::test]
async fn adding_a_passkey_needs_the_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let done = h.setup(&mut authn, "alice").await;
    let cookie = cookie_header(&done);
    let csrf: String = sqlx::query_scalar("SELECT csrf FROM web_sessions")
        .fetch_one(&h.pool)
        .await
        .unwrap();

    let none = h
        .post("/passkey/add/start", &[("Cookie", &cookie)], &json!({}))
        .await;
    assert_eq!(none.status, 403);
    let wrong = h
        .post(
            "/passkey/add/start",
            &[("Cookie", &cookie), ("X-CSRF-Token", "nope")],
            &json!({}),
        )
        .await;
    assert_eq!(wrong.status, 403);
    let no_session = h
        .post("/passkey/add/start", &[("X-CSRF-Token", &csrf)], &json!({}))
        .await;
    assert_eq!(no_session.status, 403);
    let ok = h
        .post(
            "/passkey/add/start",
            &[("Cookie", &cookie), ("X-CSRF-Token", &csrf)],
            &json!({}),
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.body);

    let logout = h
        .send(
            "POST",
            "/logout",
            &[
                ("Cookie", &cookie),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            b"csrf=nope",
        )
        .await;
    assert_eq!(logout.status, 403);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    let body = format!("csrf={csrf}");
    let logout = h
        .send(
            "POST",
            "/logout",
            &[
                ("Cookie", &cookie),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            body.as_bytes(),
        )
        .await;
    assert_eq!(logout.status, 303, "{}", logout.head);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn an_oversized_post_body_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let big = "a".repeat(MAX_BODY_BYTES + 1);
    let reply = h
        .post("/passkey/login/start", &[], &json!({ "username": big }))
        .await;
    assert_eq!(reply.status, 413, "{}", reply.head);
    h.finish().await;
}

#[sqlx::test]
async fn adding_an_already_registered_credential_is_refused_not_a_500(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let done = h.setup(&mut authn, "alice").await;
    let cookie = cookie_header(&done);
    let csrf: String = sqlx::query_scalar("SELECT csrf FROM web_sessions")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let headers = [("Cookie", cookie.as_str()), ("X-CSRF-Token", csrf.as_str())];

    let start = h.post("/passkey/add/start", &headers, &json!({})).await;
    assert_eq!(start.status, 200, "{}", start.body);
    let start = start.json();
    let mut second = authenticator();
    let credential = second
        .do_registration(
            Url::parse(ORIGIN).unwrap(),
            serde_json::from_value(start["options"].clone()).unwrap(),
        )
        .unwrap();

    let bob: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('bob') RETURNING id")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)")
        .bind(bob)
        .bind(credential.raw_id.as_ref())
        .bind(b"x".as_slice())
        .execute(&h.pool)
        .await
        .unwrap();

    let finish = h
        .post(
            "/passkey/add/finish",
            &headers,
            &json!({ "ceremony": start["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, 400, "{}", finish.body);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 2);
    h.finish().await;
}

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

async fn session_csrf(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT csrf FROM web_sessions")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn an_idle_session_expires_and_activity_keeps_one_alive(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);

    sqlx::query("UPDATE web_sessions SET last_seen = now() - interval '20 minutes'")
        .execute(&h.pool)
        .await
        .unwrap();
    let active = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(active.status, 200, "{}", active.head);

    sqlx::query("UPDATE web_sessions SET last_seen = now() - interval '31 minutes'")
        .execute(&h.pool)
        .await
        .unwrap();
    let idle = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(idle.status, 303, "{}", idle.head);
    assert!(idle.head.to_lowercase().contains("location: /login"));
    h.finish().await;
}

#[sqlx::test]
async fn an_expired_session_redirects_to_login(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let ok = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(ok.status, 200);

    sqlx::query("UPDATE web_sessions SET expires_at = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    let expired = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(expired.status, 303, "{}", expired.head);
    assert!(expired.head.to_lowercase().contains("location: /login"));
    let none = h.get("/account", &[]).await;
    assert_eq!(none.status, 303);
    h.finish().await;
}

#[sqlx::test]
async fn login_rotates_the_session_id_and_revokes_the_old_one(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let first = cookie_header(&h.setup(&mut authn, "alice").await);
    let first_csrf = session_csrf(&h.pool).await;

    let second_reply = h
        .login_at_with(&mut authn, "alice", &[("Cookie", &first)])
        .await;
    assert_eq!(second_reply.status, 200, "{}", second_reply.body);
    let second = cookie_header(&second_reply);
    assert_ne!(first, second);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    assert_ne!(session_csrf(&h.pool).await, first_csrf);

    let old = h.get("/account", &[("Cookie", &first)]).await;
    assert_eq!(old.status, 303);
    let new = h.get("/account", &[("Cookie", &second)]).await;
    assert_eq!(new.status, 200);

    let third = cookie_header(&h.login_at(&mut authn, "alice", ORIGIN).await);
    assert_ne!(second, third);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 2);
    h.finish().await;
}

impl Harness {
    async fn login_at_with(
        &self,
        authn: &mut Authenticator,
        name: &str,
        extra: &[(&str, &str)],
    ) -> Reply {
        let (ceremony, options) = self.login_start(name).await;
        let credential = authn
            .do_authentication(
                Url::parse(ORIGIN).unwrap(),
                serde_json::from_value(options).unwrap(),
            )
            .unwrap();
        self.post(
            "/passkey/login/finish",
            extra,
            &json!({ "ceremony": ceremony, "credential": credential }),
        )
        .await
    }
}

#[sqlx::test]
async fn logout_revokes_the_session_on_the_server(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;

    let body = format!("csrf={csrf}");
    let out = h
        .send(
            "POST",
            "/logout",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    assert_eq!(out.status, 303, "{}", out.head);
    let cleared = out.cookie().unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 0);

    let replay = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(replay.status, 303);
    let add = h
        .post(
            "/passkey/add/start",
            &[("Cookie", &cookie), ("X-CSRF-Token", &csrf)],
            &json!({}),
        )
        .await;
    assert_eq!(add.status, 403);
    h.finish().await;
}

#[sqlx::test]
async fn every_state_changing_route_refuses_a_foreign_origin(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let evil = ("Origin", EVIL);
    let session = [
        ("Cookie", cookie.as_str()),
        ("X-CSRF-Token", csrf.as_str()),
        evil,
    ];
    let cases: [(&str, &[(&str, &str)]); 8] = [
        ("/account/passkeys/delete", &session),
        ("/account/device-code", &session),
        ("/passkey/setup/start", &[evil]),
        ("/passkey/setup/finish", &[evil]),
        ("/passkey/login/start", &[evil]),
        ("/passkey/login/finish", &[evil]),
        ("/passkey/add/start", &session),
        ("/passkey/add/finish", &session),
    ];
    for (path, extra) in cases {
        let reply = h.post(path, extra, &json!({})).await;
        assert_eq!(reply.status, 403, "{path}: {}", reply.head);
    }

    let body = format!("csrf={csrf}");
    let logout = h
        .send(
            "POST",
            "/logout",
            &[("Cookie", &cookie), FORM, evil],
            body.as_bytes(),
        )
        .await;
    assert_eq!(logout.status, 403, "{}", logout.head);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    h.finish().await;
}

#[sqlx::test]
async fn every_session_route_refuses_a_missing_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;

    for path in ["/passkey/add/start", "/passkey/add/finish"] {
        let none = h.post(path, &[("Cookie", &cookie)], &json!({})).await;
        assert_eq!(none.status, 403, "{path}");
        let wrong = h
            .post(
                path,
                &[("Cookie", &cookie), ("X-CSRF-Token", "nope")],
                &json!({}),
            )
            .await;
        assert_eq!(wrong.status, 403, "{path}");
    }
    for path in ["/account/passkeys/delete", "/account/device-code"] {
        for body in [&b""[..], &b"csrf=nope&id=1"[..]] {
            let refused = h
                .send("POST", path, &[("Cookie", &cookie), FORM], body)
                .await;
            assert_eq!(refused.status, 403, "{path}: {}", refused.head);
        }
    }
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 1);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM setup_codes").await, 0);
    let empty = h
        .send("POST", "/logout", &[("Cookie", &cookie), FORM], b"")
        .await;
    assert_eq!(empty.status, 403, "{}", empty.head);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    let wrong = h
        .send(
            "POST",
            "/logout",
            &[("Cookie", &cookie), FORM],
            b"csrf=nope",
        )
        .await;
    assert_eq!(wrong.status, 403, "{}", wrong.head);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    let ok = h
        .post(
            "/passkey/add/start",
            &[("Cookie", &cookie), ("X-CSRF-Token", &csrf)],
            &json!({}),
        )
        .await;
    assert_eq!(ok.status, 200);
    h.finish().await;
}

#[sqlx::test]
async fn a_counter_that_moved_during_the_ceremony_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);
    assert_eq!(h.login_at(&mut authn, "alice", ORIGIN).await.status, 200);

    let (ceremony, options) = h.login_start("alice").await;
    let credential = authn
        .do_authentication(
            Url::parse(ORIGIN).unwrap(),
            serde_json::from_value(options).unwrap(),
        )
        .unwrap();
    sqlx::query(
        "UPDATE passkeys SET public_key = convert_to(jsonb_set(convert_from(public_key, 'UTF8')::jsonb, '{cred,counter}', '1000')::text, 'UTF8')",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let before = count(&h.pool, "SELECT count(*) FROM web_sessions").await;
    let refused = h
        .post(
            "/passkey/login/finish",
            &[],
            &json!({ "ceremony": ceremony, "credential": credential }),
        )
        .await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(refused.cookie().is_none());
    assert_eq!(
        count(&h.pool, "SELECT count(*) FROM web_sessions").await,
        before
    );
    h.finish().await;
}

#[sqlx::test]
async fn an_equal_non_zero_counter_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);
    assert_eq!(h.login_at(&mut authn, "alice", ORIGIN).await.status, 200);

    let (ceremony, options) = h.login_start("alice").await;
    let credential = authn
        .do_authentication(
            Url::parse(ORIGIN).unwrap(),
            serde_json::from_value(options).unwrap(),
        )
        .unwrap();
    let presented: i64 = {
        let stored: i64 = sqlx::query_scalar(
            "SELECT (convert_from(public_key, 'UTF8')::jsonb #>> '{cred,counter}')::bigint FROM passkeys",
        )
        .fetch_one(&h.pool)
        .await
        .unwrap();
        stored + 1
    };
    sqlx::query(
        "UPDATE passkeys SET public_key = convert_to(jsonb_set(convert_from(public_key, 'UTF8')::jsonb, '{cred,counter}', to_jsonb($1::bigint))::text, 'UTF8')",
    )
    .bind(presented)
    .execute(&h.pool)
    .await
    .unwrap();
    assert!(presented > 0);
    let refused = h
        .post(
            "/passkey/login/finish",
            &[],
            &json!({ "ceremony": ceremony, "credential": credential }),
        )
        .await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(refused.cookie().is_none());
    h.finish().await;
}

#[sqlx::test]
async fn a_login_keeps_sessions_inside_both_windows(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);
    sqlx::query(
        "UPDATE web_sessions SET last_seen = now() - interval '29 minutes', expires_at = now() + interval '1 minute'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    assert_eq!(h.login_at(&mut authn, "alice", ORIGIN).await.status, 200);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 2);
    h.finish().await;
}

#[sqlx::test]
async fn a_login_purges_expired_and_idle_sessions(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    assert_eq!(h.setup(&mut authn, "alice").await.status, 200);
    sqlx::query("UPDATE web_sessions SET last_seen = now() - interval '31 minutes'")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.login_at(&mut authn, "alice", ORIGIN).await.status, 200);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    sqlx::query("UPDATE web_sessions SET expires_at = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.login_at(&mut authn, "alice", ORIGIN).await.status, 200);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM web_sessions").await, 1);
    h.finish().await;
}

const SETTLE: Duration = Duration::from_millis(400);

async fn direct_admin(
    pool: &PgPool,
    authn: &mut Authenticator,
) -> (WebAuth, Users, i64, fleet_server::web::NewSession) {
    let users = Users::new(pool.clone());
    let auth = webauth(pool, &users, ORIGIN, Some("example.com"));
    let code = users.issue_setup_code().await.unwrap().unwrap();
    let code = String::from_utf8(code.expose().to_vec()).unwrap();
    let (ceremony, options) = auth.setup_start(&code, "alice").await.unwrap();
    let credential = authn
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let session = auth
        .setup_finish(&ceremony, &credential, Ipv4Addr::LOCALHOST.into())
        .await
        .unwrap();
    let alice: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(pool)
        .await
        .unwrap();
    (auth, users, alice, session)
}

async fn add_ceremony(
    auth: &WebAuth,
    alice: i64,
) -> (String, webauthn_rs::prelude::RegisterPublicKeyCredential) {
    let (ceremony, options) = auth.add_start(alice).await.unwrap();
    let mut second = authenticator();
    let credential = second
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    (ceremony, credential)
}

#[sqlx::test]
async fn a_reset_between_add_start_and_add_finish_leaves_no_passkey(pool: PgPool) {
    let mut authn = authenticator();
    let (auth, _users, alice, session) = direct_admin(&pool, &mut authn).await;
    let (ceremony, credential) = add_ceremony(&auth, alice).await;
    run(
        &pool,
        &AdminCommand::ResetPasskeys("alice".to_owned()),
        "op",
    )
    .await
    .unwrap();
    let outcome = auth
        .add_finish(alice, session.id.expose(), &ceremony, &credential)
        .await;
    assert!(matches!(outcome, Err(AuthError::Refused)));
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 0);
}

#[sqlx::test]
async fn add_finish_waits_for_the_user_lock_and_loses_to_a_reset(pool: PgPool) {
    let mut authn = authenticator();
    let (auth, _users, alice, session) = direct_admin(&pool, &mut authn).await;
    let (ceremony, credential) = add_ceremony(&auth, alice).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(alice)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let cookie = session.id.expose().to_vec();
    let racer = tokio::spawn(async move {
        auth.add_finish(alice, &cookie, &ceremony, &credential)
            .await
    });
    tokio::time::sleep(SETTLE).await;
    assert!(!racer.is_finished(), "add_finish ran without the user lock");
    sqlx::query("DELETE FROM passkeys WHERE user_id = $1")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM web_sessions WHERE user_id = $1")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let outcome = tokio::time::timeout(WAIT, racer).await.unwrap().unwrap();
    assert!(matches!(outcome, Err(AuthError::Refused)));
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 0);
}

#[sqlx::test]
async fn add_finish_with_a_live_session_stores_the_passkey(pool: PgPool) {
    let mut authn = authenticator();
    let (auth, _users, alice, session) = direct_admin(&pool, &mut authn).await;
    let (ceremony, credential) = add_ceremony(&auth, alice).await;
    auth.add_finish(alice, session.id.expose(), &ceremony, &credential)
        .await
        .unwrap();
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 2);
}

#[sqlx::test]
async fn a_failing_passkey_insert_during_setup_leaves_no_admin_and_no_delete(pool: PgPool) {
    let users = Users::new(pool.clone());
    let auth = webauth(&pool, &users, ORIGIN, Some("example.com"));
    let mut authn = authenticator();
    let code = users.issue_setup_code().await.unwrap().unwrap();
    let code = String::from_utf8(code.expose().to_vec()).unwrap();
    let (ceremony, options) = auth.setup_start(&code, "alice").await.unwrap();
    let credential = authn
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let bootstrap = users.bootstrap_user().await.unwrap();
    sqlx::query("INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)")
        .bind(bootstrap)
        .bind(credential.raw_id.as_ref())
        .bind(b"x".as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION refuse_user_delete() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'user delete'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER refuse_user_delete BEFORE DELETE ON users \
         FOR EACH ROW EXECUTE FUNCTION refuse_user_delete()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let outcome = auth
        .setup_finish(&ceremony, &credential, Ipv4Addr::LOCALHOST.into())
        .await;
    assert!(outcome.is_err());
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM users WHERE lower(username) <> 'bootstrap'"
        )
        .await,
        0
    );
    assert!(!users.has_real_users().await.unwrap());
}

async fn extra_passkey(pool: &PgPool, user_id: i64, tag: u8) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user_id)
    .bind(vec![tag; 16])
    .bind(b"x".as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn user_id(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn form_body(csrf: &str, id: i64) -> String {
    format!("csrf={csrf}&id={id}")
}

#[sqlx::test]
async fn the_account_page_lists_numbered_passkeys_and_a_create_button(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    h.setup(&mut authn, "alice").await;
    let alice = user_id(&h.pool, "alice").await;
    let login = h.login_at(&mut authn, "alice", ORIGIN).await;
    assert_eq!(login.status, 200, "{}", login.body);
    let used: i64 = count(
        &h.pool,
        "SELECT count(*) FROM passkeys WHERE last_used_at IS NOT NULL",
    )
    .await;
    assert_eq!(used, 1);
    let cookie = cookie_header(&login);
    extra_passkey(&h.pool, alice, 7).await;
    let page = h.get("/account", &[("Cookie", &cookie)]).await;
    assert_eq!(page.status, 200);
    for text in [
        "Passkey 1",
        "Passkey 2",
        "never",
        "Create a passkey",
        "Delete",
        "Created",
        "Last used",
        "Create a code for a new device",
    ] {
        assert!(page.body.contains(text), "{text}: {}", page.body);
    }
    assert!(!page.body.contains("Add a passkey"));
    let page = h.get("/account", &[("Cookie", &cookie)]).await;
    assert!(page.body.contains(" UTC"), "{}", page.body);
    h.finish().await;
}

#[sqlx::test]
async fn deleting_the_last_passkey_is_refused_and_another_is_deleted(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let alice = user_id(&h.pool, "alice").await;
    let only: i64 = sqlx::query_scalar("SELECT id FROM passkeys WHERE user_id = $1")
        .bind(alice)
        .fetch_one(&h.pool)
        .await
        .unwrap();

    let body = form_body(&csrf, only);
    let refused = h
        .send(
            "POST",
            "/account/passkeys/delete",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    assert_eq!(refused.status, 400, "{}", refused.head);
    assert!(refused.body.contains("request refused"));
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 1);

    let second = extra_passkey(&h.pool, alice, 9).await;
    let body = form_body(&csrf, second);
    let done = h
        .send(
            "POST",
            "/account/passkeys/delete",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    assert_eq!(done.status, 303, "{}", done.head);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 1);
    let again = h
        .send(
            "POST",
            "/account/passkeys/delete",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    assert_eq!(again.status, 400);
    h.finish().await;
}

#[sqlx::test]
async fn a_user_cannot_delete_another_users_passkey(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let alice = user_id(&h.pool, "alice").await;
    extra_passkey(&h.pool, alice, 3).await;
    let bob: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('bob') RETURNING id")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let theirs = extra_passkey(&h.pool, bob, 4).await;
    let body = form_body(&csrf, theirs);
    let refused = h
        .send(
            "POST",
            "/account/passkeys/delete",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    assert_eq!(refused.status, 400, "{}", refused.head);
    assert_eq!(
        count(&h.pool, "SELECT count(*) FROM passkeys WHERE user_id = (SELECT id FROM users WHERE username = 'bob')").await,
        1
    );
    h.finish().await;
}

fn enroll_code(reply: &Reply) -> String {
    let marker = format!("{ORIGIN}/enroll/");
    let start = reply.body.find(&marker).unwrap() + marker.len();
    reply.body[start..start + 64].to_owned()
}

#[sqlx::test]
async fn a_new_device_code_is_self_service_short_lived_and_single_use(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let body = format!("csrf={csrf}");
    let made = h
        .send(
            "POST",
            "/account/device-code",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    assert_eq!(made.status, 200, "{}", made.body);
    let code = enroll_code(&made);
    assert!(code.bytes().all(|b| b.is_ascii_hexdigit()));

    let minutes: f64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM expires_at - now()) / 60)::float8 FROM setup_codes",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(minutes > 9.0 && minutes <= 10.0, "{minutes}");

    let mut phone = authenticator();
    let first = h.enroll_with(&mut phone, &code).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 2);
    let mut spare = authenticator();
    let second = h.enroll_with(&mut spare, &code).await;
    assert_ne!(second.status, 200);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 2);
    h.finish().await;
}

#[sqlx::test]
async fn an_expired_new_device_code_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let body = format!("csrf={csrf}");
    let made = h
        .send(
            "POST",
            "/account/device-code",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    let code = enroll_code(&made);
    sqlx::query("UPDATE setup_codes SET expires_at = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    let mut phone = authenticator();
    let refused = h.enroll_with(&mut phone, &code).await;
    assert_eq!(refused.status, 400);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 1);
    h.finish().await;
}

#[sqlx::test]
async fn a_new_code_replaces_the_previous_open_code(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let body = format!("csrf={csrf}");
    let mut codes = Vec::new();
    for _ in 0..2 {
        let made = h
            .send(
                "POST",
                "/account/device-code",
                &[("Cookie", &cookie), FORM],
                body.as_bytes(),
            )
            .await;
        codes.push(enroll_code(&made));
    }
    assert_eq!(
        count(
            &h.pool,
            "SELECT count(*) FROM setup_codes WHERE used_at IS NULL"
        )
        .await,
        1
    );
    let mut phone = authenticator();
    assert_eq!(h.enroll_with(&mut phone, &codes[0]).await.status, 400);
    assert_eq!(h.enroll_with(&mut phone, &codes[1]).await.status, 200);
    h.finish().await;
}

#[sqlx::test]
async fn a_code_moved_to_another_user_cannot_finish_the_ceremony(pool: PgPool) {
    let h = Harness::start(pool).await;
    let mut authn = authenticator();
    let cookie = cookie_header(&h.setup(&mut authn, "alice").await);
    let csrf = session_csrf(&h.pool).await;
    let body = format!("csrf={csrf}");
    let made = h
        .send(
            "POST",
            "/account/device-code",
            &[("Cookie", &cookie), FORM],
            body.as_bytes(),
        )
        .await;
    let code = enroll_code(&made);
    let start = h
        .post("/passkey/enroll/start", &[], &json!({ "code": code }))
        .await;
    assert_eq!(start.status, 200, "{}", start.body);
    let start = start.json();
    let bob: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('bob') RETURNING id")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE setup_codes SET user_id = $1")
        .bind(bob)
        .execute(&h.pool)
        .await
        .unwrap();
    let options = serde_json::from_value(start["options"].clone()).unwrap();
    let credential = authenticator()
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let finish = h
        .post(
            "/passkey/enroll/finish",
            &[],
            &json!({ "ceremony": start["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, 400, "{}", finish.body);
    assert_eq!(count(&h.pool, "SELECT count(*) FROM passkeys").await, 1);
    assert_eq!(
        count(
            &h.pool,
            "SELECT count(*) FROM setup_codes WHERE used_at IS NOT NULL"
        )
        .await,
        0
    );
    h.finish().await;
}

impl Harness {
    async fn enroll_with(&self, authn: &mut Authenticator, code: &str) -> Reply {
        let start = self
            .post("/passkey/enroll/start", &[], &json!({ "code": code }))
            .await;
        if start.status != 200 {
            return start;
        }
        let start = start.json();
        let options = serde_json::from_value(start["options"].clone()).unwrap();
        let credential = authn
            .do_registration(Url::parse(ORIGIN).unwrap(), options)
            .unwrap();
        self.post(
            "/passkey/enroll/finish",
            &[],
            &json!({ "ceremony": start["ceremony"], "credential": credential }),
        )
        .await
    }
}
