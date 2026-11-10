//! The `/environments` pages and the `/submit` form (ADR-0067): session and CSRF gates on every
//! route, owner scope with a byte-identical 404 for a foreign or unknown name, a write-only
//! secret field, fingerprints, the submit select with scripts disabled without `env:scripts`,
//! hostile text at the render edge and the admin capability page. The tests need a Postgres
//! superuser URL in `DATABASE_URL` for `#[sqlx::test]` and live in their own binary because
//! each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_core::environment::{
    Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec, SecretSpec,
    SecretValue,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{EnvironmentService, EnvironmentStore};
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
const REPO: &str = "https://example.com/org/repo.git";
const SHEBANG: &str = "#!/bin/sh\necho a\n";
const MARKER: &str = "zq-secret-marker-7731-value";
const GET_ROUTES: [&str; 3] = ["/environments", "/environments/alpha", "/submit"];
const POST_ROUTES: [&str; 5] = [
    "/environments/create",
    "/environments/alpha/secrets/put",
    "/environments/alpha/secrets/delete",
    "/environments/alpha/delete",
    "/submit",
];

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-web-env-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "cd".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

struct Session {
    cookie: String,
    csrf: String,
    user_id: i64,
}

struct Page {
    status: u16,
    location: String,
    body: String,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    envs: EnvironmentStore,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let bearer = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let sealer = Arc::new(sealer());
        let service = EnvironmentService::new(EnvironmentStore::new(pool.clone(), sealer.clone()));
        let envs = EnvironmentStore::new(pool.clone(), sealer);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let web = Web::with_environments(auth, None, Some(service), store.clone());
        let task = tokio::spawn(async move {
            serve_with_web(&store, &bearer, web, TcpIncoming::from(listener), async {
                let _ = rx.await;
            })
            .await
        });
        Self {
            addr,
            pool,
            envs,
            stop: Some(stop),
            task,
        }
    }

    async fn session(&self, name: &str, seed: char, admin: bool, scripts: bool) -> Session {
        let user_id: i64 = sqlx::query_scalar(
            "INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id",
        )
        .bind(name)
        .bind(admin)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        if scripts {
            sqlx::query(
                "INSERT INTO user_capabilities (user_id, capability, granted_by) \
                 VALUES ($1, 'env:scripts', $1)",
            )
            .bind(user_id)
            .execute(&self.pool)
            .await
            .unwrap();
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

    async fn environment(&self, owner: i64, name: &str, entries: Vec<Entry>) -> i64 {
        let id = self
            .envs
            .create_environment(owner, &EnvironmentName::new(name).unwrap())
            .await
            .unwrap();
        let inserted = sqlx::query(
            "INSERT INTO user_capabilities (user_id, capability, granted_by) \
             VALUES ($1, 'env:scripts', $1) ON CONFLICT DO NOTHING",
        )
        .bind(owner)
        .execute(&self.pool)
        .await
        .unwrap()
        .rows_affected();
        self.envs
            .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
            .await
            .unwrap();
        if inserted == 1 {
            sqlx::query(
                "DELETE FROM user_capabilities WHERE user_id = $1 AND capability = 'env:scripts'",
            )
            .bind(owner)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        id
    }

    async fn counts(&self) -> (i64, i64, i64, i64) {
        let one = |sql: &'static str| {
            let pool = self.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(sql)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        (
            one("SELECT count(*) FROM environment").await,
            one("SELECT count(*) FROM environment_secret").await,
            one("SELECT count(*) FROM environment_version").await,
            one("SELECT count(*) FROM jobs").await,
        )
    }

    async fn fetch(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> Page {
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
        Page {
            status,
            location,
            body: page.to_owned(),
        }
    }

    async fn get(&self, who: &Session, path: &str) -> Page {
        self.fetch("GET", path, Some(&who.cookie), None).await
    }

    async fn post(&self, who: &Session, path: &str, fields: &[(&str, &str)]) -> Page {
        let mut body = format!("csrf={}", who.csrf);
        for (key, value) in fields {
            let _ = write!(body, "&{key}={}", encode(value));
        }
        self.fetch("POST", path, Some(&who.cookie), Some(&body))
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

async fn submit(h: &Harness, who: &Session, fields: Vec<(&'static str, String)>) -> Page {
    let borrowed: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    h.post(who, "/submit", &borrowed).await
}

fn secret(name: &str, agent_visible: bool) -> Entry {
    Entry::Secret(
        SecretSpec::new(
            EntryName::new(name).unwrap(),
            agent_visible,
            fleet_core::environment::Delivery::File,
        )
        .unwrap(),
    )
}

fn script(name: &str, body: &str) -> Entry {
    Entry::Script(ScriptSpec::with_defaults(
        EntryName::new(name).unwrap(),
        ScriptBody::new(body).unwrap(),
    ))
}

#[sqlx::test]
async fn every_route_needs_a_session_and_every_post_a_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    h.environment(alice.user_id, "alpha", vec![secret("TOKEN", true)])
        .await;
    let before = h.counts().await;
    for path in GET_ROUTES {
        let page = h.fetch("GET", path, None, None).await;
        assert_eq!(
            (page.status, page.location.as_str()),
            (303, "/login"),
            "{path}"
        );
    }
    for path in POST_ROUTES {
        let none = h.fetch("POST", path, None, Some("csrf=x")).await;
        assert_eq!(none.status, 403, "no session {path}");
        let missing = h
            .fetch("POST", path, Some(&alice.cookie), Some("name=alpha"))
            .await;
        assert_eq!(missing.status, 403, "no csrf {path}");
        let wrong = h
            .fetch(
                "POST",
                path,
                Some(&alice.cookie),
                Some("csrf=wrong&name=alpha"),
            )
            .await;
        assert_eq!(wrong.status, 403, "wrong csrf {path}");
    }
    assert_eq!(h.counts().await, before);
    for path in GET_ROUTES {
        let page = h.get(&alice, path).await;
        assert_eq!(page.status, 200, "{path}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn pages_list_only_the_session_users_environments(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let bob = h.session("bob", 'b', false, false).await;
    h.environment(alice.user_id, "alpha", vec![secret("TOKEN", true)])
        .await;
    h.environment(bob.user_id, "bravo", vec![secret("TOKEN", true)])
        .await;
    let list = h.get(&alice, "/environments").await;
    assert!(list.body.contains("/environments/alpha"));
    assert!(!list.body.contains("bravo"));
    let submit = h.get(&alice, "/submit").await;
    assert!(submit.body.contains("alpha (v1)"));
    assert!(!submit.body.contains("bravo"));
    h.finish().await;
}

#[sqlx::test]
async fn a_foreign_name_is_byte_identical_to_an_unknown_name(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let bob = h.session("bob", 'b', false, false).await;
    h.environment(bob.user_id, "bravo", vec![secret("TOKEN", true)])
        .await;
    let foreign = h.get(&alice, "/environments/bravo").await;
    let unknown = h.get(&alice, "/environments/nowhere").await;
    let hostile = h.get(&alice, "/environments/%3Cscript%3E").await;
    assert_eq!(foreign.status, 404);
    assert_eq!(foreign.body, unknown.body);
    assert_eq!(foreign.body, hostile.body);
    let before = h.counts().await;
    for (path, fields) in [
        (
            "/environments/{}/secrets/put",
            vec![("name", "TOKEN"), ("value", MARKER)],
        ),
        ("/environments/{}/delete", vec![]),
    ] {
        let foreign = h.post(&alice, &path.replace("{}", "bravo"), &fields).await;
        let unknown = h
            .post(&alice, &path.replace("{}", "nowhere"), &fields)
            .await;
        assert_eq!(foreign.status, 404, "{path}");
        assert_eq!(foreign.body, unknown.body, "{path}");
        assert_eq!(foreign.location, unknown.location, "{path}");
    }
    assert_eq!(h.counts().await, before);
    h.finish().await;
}

#[sqlx::test]
async fn the_secret_field_is_write_only_and_the_fingerprint_shows(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let id = h
        .environment(alice.user_id, "alpha", vec![secret("TOKEN", true)])
        .await;
    assert!(
        h.get(&alice, "/environments/alpha")
            .await
            .body
            .contains("not set")
    );
    let put = h
        .post(
            &alice,
            "/environments/alpha/secrets/put",
            &[("name", "TOKEN"), ("value", MARKER)],
        )
        .await;
    assert_eq!(put.status, 303);
    assert_eq!(put.location, "/environments/alpha?notice=secret_saved");
    assert!(!put.location.contains(MARKER));
    assert!(!put.body.contains(MARKER));
    let (cipher, fingerprint): (Vec<u8>, String) = sqlx::query_as(
        "SELECT ciphertext, fingerprint FROM environment_secret WHERE environment_id = $1",
    )
    .bind(id)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    let page = h
        .get(&alice, "/environments/alpha?notice=secret_saved")
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&fingerprint), "fingerprint is shown");
    assert!(page.body.contains("Secret saved."));
    assert!(page.body.contains("type=\"password\""));
    assert!(!page.body.contains(MARKER));
    assert!(!page.body.contains(&hex(&cipher)));
    assert!(!page.body.contains(&hex(&cipher[..8])));
    let sealed = String::from_utf8_lossy(&cipher).into_owned();
    assert!(!page.body.contains(&sealed));
    let positive = format!("<td>{fingerprint}</td> {MARKER} {}", hex(&cipher));
    assert!(positive.contains(MARKER) && positive.contains(&hex(&cipher[..8])));
    let value = SecretValue::new(MARKER.to_owned()).unwrap();
    assert_eq!(value.expose(), MARKER.as_bytes());
    let list = h.get(&alice, "/environments").await;
    assert!(!list.body.contains(MARKER));
    h.finish().await;
}

#[sqlx::test]
async fn create_delete_and_secret_removal_use_fixed_notices(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let made = h
        .post(&alice, "/environments/create", &[("name", "alpha")])
        .await;
    assert_eq!(made.location, "/environments?notice=created");
    let again = h
        .post(&alice, "/environments/create", &[("name", "alpha")])
        .await;
    assert_eq!(again.location, "/environments?notice=exists");
    let bad = h
        .post(&alice, "/environments/create", &[("name", "<b>x")])
        .await;
    assert_eq!(bad.location, "/environments?notice=invalid");
    let notice = h.get(&alice, "/environments?notice=%3Cscript%3E").await;
    assert!(!notice.body.contains("<script>"));
    assert!(!notice.body.contains("id=\"notice\""));
    h.post(
        &alice,
        "/environments/alpha/secrets/put",
        &[("name", "TOKEN"), ("value", MARKER)],
    )
    .await;
    let gone = h
        .post(
            &alice,
            "/environments/alpha/secrets/delete",
            &[("name", "TOKEN")],
        )
        .await;
    assert_eq!(gone.location, "/environments/alpha?notice=secret_deleted");
    assert_eq!(h.counts().await.1, 0);
    let deleted = h.post(&alice, "/environments/alpha/delete", &[]).await;
    assert_eq!(deleted.location, "/environments?notice=deleted");
    assert_eq!(h.counts().await.0, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_hostile_script_body_is_escaped_and_warnings_show(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let body = "#!/bin/sh\necho '<script>alert(1)</script>' \"&\" \"'\"\n";
    h.environment(
        alice.user_id,
        "alpha",
        vec![secret("TOKEN", false), script("setup", body)],
    )
    .await;
    let page = h.get(&alice, "/environments/alpha").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("<script>alert(1)"));
    assert!(page.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(page.body.contains("no (setup only)"));
    assert!(
        page.body
            .contains("Warning: secret TOKEN is not agent-visible")
    );
    assert!(page.body.contains("You do not hold env:scripts"));
    h.finish().await;
}

#[sqlx::test]
async fn the_submit_select_disables_scripts_without_the_capability(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let carol = h.session("carol", 'c', false, true).await;
    for user in [&alice, &carol] {
        h.environment(user.user_id, "plain", vec![secret("TOKEN", true)])
            .await;
        h.environment(user.user_id, "setup", vec![script("run", SHEBANG)])
            .await;
    }
    let page = h.get(&alice, "/submit").await;
    assert!(
        page.body
            .contains("<option value=\"plain\">plain (v1)</option>")
    );
    assert!(
        page.body.contains(
            "<option value=\"setup\" disabled=\"\">setup (v1) - needs env:scripts</option>"
        )
    );
    assert!(page.body.contains("job-environment-hint"));
    let page = h.get(&carol, "/submit").await;
    assert!(
        page.body
            .contains("<option value=\"setup\">setup (v1)</option>")
    );
    assert!(!page.body.contains("disabled"));
    h.finish().await;
}

#[sqlx::test]
async fn submit_pins_an_owned_environment_and_refuses_the_rest(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a', false, false).await;
    let bob = h.session("bob", 'b', false, false).await;
    h.environment(alice.user_id, "plain", vec![secret("TOKEN", true)])
        .await;
    h.environment(alice.user_id, "setup", vec![script("run", SHEBANG)])
        .await;
    h.environment(bob.user_id, "bravo", vec![secret("TOKEN", true)])
        .await;
    let form = |key: &str, environment: &str| {
        vec![
            ("key", key.to_owned()),
            ("prompt", "add hello.txt".to_owned()),
            ("repo", REPO.to_owned()),
            ("base_ref", "main".to_owned()),
            ("environment", environment.to_owned()),
        ]
    };
    let scripts = submit(&h, &alice, form("k-scripts", "setup")).await;
    assert_eq!(scripts.location, "/submit?notice=env_scripts");
    let foreign = submit(&h, &alice, form("k-foreign", "bravo")).await;
    let unknown = submit(&h, &alice, form("k-unknown", "nowhere")).await;
    assert_eq!(foreign.location, "/submit?notice=env_missing");
    assert_eq!(foreign.location, unknown.location);
    assert_eq!(h.counts().await.3, 0);
    let ok = submit(&h, &alice, form("k-plain", "plain")).await;
    assert_eq!(ok.status, 303);
    assert!(ok.location.starts_with("/jobs/"), "{}", ok.location);
    let pinned: Option<i64> =
        sqlx::query_scalar("SELECT environment_id FROM jobs WHERE idempotency_key = 'k-plain'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(pinned.is_some());
    assert_eq!(h.counts().await.3, 1);
    h.finish().await;
}

#[sqlx::test]
async fn the_admin_capability_page_lists_env_scripts(pool: PgPool) {
    let h = Harness::start(pool).await;
    let root = h.session("root", 'e', true, false).await;
    let page = h
        .get(&root, &format!("/users/{}/capabilities", root.user_id))
        .await;
    assert_eq!((page.status, page.location.as_str()), (200, ""));
    for name in ["profile:tools", "forge:github_app", "env:scripts"] {
        assert!(page.body.contains(name), "{name}");
    }
    h.finish().await;
}
