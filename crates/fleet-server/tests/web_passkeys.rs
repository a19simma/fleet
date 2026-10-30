//! Passkey setup, login, sessions and the web POST limits, driven over HTTP with a software
//! authenticator. They need a Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]`.

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
use fleet_server::cred::users::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{MAX_BODY_BYTES, SESSION_COOKIE, Web, WebAuth};
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
    let cases: [(&str, &[(&str, &str)]); 6] = [
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
    let empty = h
        .send("POST", "/logout", &[("Cookie", &cookie), FORM], b"")
        .await;
    assert!(empty.status == 403 || empty.status == 400, "{}", empty.head);
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
