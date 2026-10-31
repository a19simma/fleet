//! The credentials page over HTTP: session and CSRF gates, owner scoping, the write-only
//! value and the fixed rejection of classic GitHub tokens. The tests need a Postgres
//! superuser URL in `DATABASE_URL` for `#[sqlx::test]` and live in their own binary because
//! each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::credential::Secret;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, Users};
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
const EVIL: &str = "https://evil.example.com";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const PAT_B: &str = "github_pat_22ZYXWVUT9zyxwvutsrqponmlk";
const CLASSIC: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const EXPIRY_MS: i64 = 1_900_000_000_000;
static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct FakeGithub {
    answer: Arc<Mutex<Result<GithubUser, GithubError>>>,
    calls: Arc<AtomicUsize>,
}

impl FakeGithub {
    fn ok() -> Self {
        Self {
            answer: Arc::new(Mutex::new(Ok(GithubUser {
                login: "octo".to_owned(),
                expires_at_ms: Some(EXPIRY_MS),
            }))),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn set(&self, answer: Result<GithubUser, GithubError>) {
        *self.answer.lock().unwrap() = answer;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl GithubApi for FakeGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer.lock().unwrap().clone()
    }
}

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
    github: FakeGithub,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-web-cred-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    sealer.unwrap()
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        Self::start_with(pool, true).await
    }

    async fn start_with(pool: PgPool, configured: bool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let github = FakeGithub::ok();
        let service = CredentialService::new(
            CredentialStore::new(pool.clone(), Arc::new(sealer())),
            Arc::new(github.clone()),
        );
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = if configured {
            Web::with_credentials(auth, service)
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
            github,
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
            user_id,
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

    async fn page(&self, who: &Session, query: &str) -> Reply {
        self.send(
            "GET",
            &format!("/credentials{query}"),
            &[("Cookie", &who.cookie)],
            b"",
        )
        .await
    }

    async fn act(&self, who: &Session, action: &str, body: &str) -> Reply {
        self.send(
            "POST",
            &format!("/credentials/{action}"),
            &[("Cookie", &who.cookie), FORM],
            body.as_bytes(),
        )
        .await
    }

    async fn put(&self, who: &Session, kind: &str, value: &str) -> Reply {
        let body = format!("csrf={}&kind={kind}&value={value}", who.csrf);
        self.act(who, "put", &body).await
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

async fn stored(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn id_of(pool: &PgPool, user_id: i64, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM credentials WHERE user_id = $1 AND kind = $2")
        .bind(user_id)
        .bind(kind)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn the_page_needs_a_session(pool: PgPool) {
    let h = Harness::start(pool).await;
    let reply = h.send("GET", "/credentials", &[], b"").await;
    assert_eq!(reply.status, 303);
    assert_eq!(reply.location(), "/login");
    let forged = Session {
        cookie: format!("{SESSION_COOKIE}={}", "e".repeat(64)),
        csrf: String::new(),
        user_id: 0,
    };
    let reply = h.page(&forged, "").await;
    assert_eq!(reply.status, 303);
    h.finish().await;
}

#[sqlx::test]
async fn the_page_is_off_when_credentials_are_not_configured(pool: PgPool) {
    let h = Harness::start_with(pool, false).await;
    let alice = h.session("alice", 'a').await;
    assert_eq!(h.page(&alice, "").await.status, 404);
    assert_eq!(h.put(&alice, "github_pat", PAT).await.status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn the_page_lists_every_kind_and_no_refreshing_file_option(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let page = h.page(&alice, "").await;
    assert_eq!(page.status, 200);
    for kind in [
        "anthropic_api_key",
        "claude_subscription_token",
        "github_pat",
        "kimi_membership_key",
        "kimi_platform_key",
        "codex_api_key",
    ] {
        assert!(page.body.contains(kind), "{kind}");
    }
    assert!(!page.body.contains("refreshing_file"));
    assert!(page.body.contains("not set"));
    assert!(page.body.contains(&alice.csrf));
    h.finish().await;
}

#[sqlx::test]
async fn put_shows_login_fingerprint_and_expiry_and_never_the_value(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let put = h.put(&alice, "github_pat", PAT).await;
    assert_eq!(put.status, 303, "{}", put.head);
    assert!(!put.head.contains(PAT) && !put.body.contains(PAT));
    assert_eq!(put.location(), "/credentials?notice=saved");
    let page = h.page(&alice, "?notice=saved").await;
    assert!(!page.body.contains(PAT));
    assert!(page.body.contains("octo"));
    assert!(page.body.contains("2030-03-17"));
    assert!(page.body.contains("Saved"));
    assert_eq!(page.body.matches("/credentials/verify").count(), 1);
    let fingerprint: String = sqlx::query_scalar("SELECT fingerprint FROM credentials")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert!(page.body.contains(&fingerprint));
    assert_eq!(h.github.calls(), 1);
    let ant = h.put(&alice, "anthropic_api_key", ANT).await;
    assert_eq!(ant.status, 303);
    let page = h.page(&alice, "").await;
    assert!(!page.body.contains(ANT) && !page.body.contains(PAT));
    assert!(page.body.contains("never"));
    assert_eq!(page.body.matches("/credentials/verify").count(), 1);
    assert_eq!(page.body.matches("/credentials/delete").count(), 2);
    assert!(page.body.contains(">none<"));
    h.finish().await;
}

#[sqlx::test]
async fn last_used_shows_the_latest_use(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.put(&alice, "anthropic_api_key", ANT).await;
    let id = id_of(&h.pool, alice.user_id, "anthropic_api_key").await;
    sqlx::query(
        "INSERT INTO credential_use (credential_id, job_id, used_at) VALUES \
         ($1, 'j1', '2031-01-02 03:04:05+00'), ($1, 'j2', '2032-05-06 07:08:09+00')",
    )
    .bind(id)
    .execute(&h.pool)
    .await
    .unwrap();
    let page = h.page(&alice, "").await;
    assert!(page.body.contains("2032-05-06 07:08 UTC"));
    assert!(!page.body.contains("2031-01-02"));
    h.finish().await;
}

#[sqlx::test]
async fn a_classic_github_token_gets_the_fixed_rejection(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let put = h.put(&alice, "github_pat", CLASSIC).await;
    assert_eq!(put.status, 303);
    assert!(!put.head.contains(CLASSIC));
    assert_eq!(put.location(), "/credentials?notice=github_classic");
    let page = h.page(&alice, "?notice=github_classic").await;
    assert!(
        page.body
            .contains("fine-grained token starting with github_pat_")
    );
    assert!(!page.body.contains(CLASSIC));
    assert_eq!(stored(&h.pool).await, 0);
    assert_eq!(h.github.calls(), 0);
    h.finish().await;
}

#[sqlx::test]
async fn an_unknown_notice_renders_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let page = h.page(&alice, "?notice=%3Cscript%3E").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("script>"));
    h.finish().await;
}

#[sqlx::test]
async fn a_github_refusal_and_an_outage_store_nothing(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.github.set(Err(GithubError::Rejected));
    let put = h.put(&alice, "github_pat", PAT).await;
    assert_eq!(put.location(), "/credentials?notice=github_refused");
    h.github.set(Err(GithubError::Unavailable));
    let put = h.put(&alice, "github_pat", PAT).await;
    assert_eq!(put.location(), "/credentials?notice=unavailable");
    assert_eq!(stored(&h.pool).await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn invalid_and_unknown_input_is_refused_with_a_fixed_notice(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let put = h.put(&alice, "anthropic_api_key", "short").await;
    assert_eq!(put.location(), "/credentials?notice=invalid");
    let put = h.put(&alice, "gitlab_pat", ANT).await;
    assert_eq!(put.location(), "/credentials?notice=invalid");
    let body = format!("csrf={}&kind=anthropic_api_key", alice.csrf);
    let put = h.act(&alice, "put", &body).await;
    assert_eq!(put.location(), "/credentials?notice=invalid");
    assert_eq!(stored(&h.pool).await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_shape_field_cannot_select_refreshing_file(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let body = format!(
        "csrf={}&kind=anthropic_api_key&shape=refreshing_file&value={ANT}",
        alice.csrf
    );
    let put = h.act(&alice, "put", &body).await;
    assert_eq!(put.location(), "/credentials?notice=saved");
    let shape: String = sqlx::query_scalar("SELECT shape FROM credentials")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(shape, "static_secret");
    h.finish().await;
}

#[sqlx::test]
async fn every_post_needs_a_session_and_the_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.put(&alice, "anthropic_api_key", ANT).await;
    let id = id_of(&h.pool, alice.user_id, "anthropic_api_key").await;
    let bodies = [
        ("put", format!("kind=github_pat&value={PAT}")),
        ("put", format!("csrf=wrong&kind=github_pat&value={PAT}")),
        ("delete", format!("id={id}")),
        ("delete", format!("csrf=wrong&id={id}")),
        ("verify", format!("id={id}")),
        ("verify", format!("csrf=wrong&id={id}")),
    ];
    for (action, body) in &bodies {
        let reply = h.act(&alice, action, body).await;
        assert_eq!(reply.status, 403, "{action} {body}");
        let anonymous = h
            .send(
                "POST",
                &format!("/credentials/{action}"),
                &[FORM],
                format!("csrf={}&id={id}&kind=github_pat&value={PAT}", alice.csrf).as_bytes(),
            )
            .await;
        assert_eq!(anonymous.status, 403, "{action} anonymous");
    }
    assert_eq!(stored(&h.pool).await, 1);
    assert_eq!(h.github.calls(), 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_foreign_origin_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let body = format!("csrf={}&kind=anthropic_api_key&value={ANT}", alice.csrf);
    let reply = h
        .send(
            "POST",
            "/credentials/put",
            &[("Cookie", &alice.cookie), FORM, ("Origin", EVIL)],
            body.as_bytes(),
        )
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(stored(&h.pool).await, 0);
    h.finish().await;
}

#[sqlx::test]
async fn delete_removes_the_row_and_is_final(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.put(&alice, "anthropic_api_key", ANT).await;
    let id = id_of(&h.pool, alice.user_id, "anthropic_api_key").await;
    let body = format!("csrf={}&id={id}", alice.csrf);
    let gone = h.act(&alice, "delete", &body).await;
    assert_eq!(gone.location(), "/credentials?notice=deleted");
    assert_eq!(stored(&h.pool).await, 0);
    let again = h.act(&alice, "delete", &body).await;
    assert_eq!(again.location(), "/credentials?notice=not_found");
    let junk = h
        .act(&alice, "delete", &format!("csrf={}&id=abc", alice.csrf))
        .await;
    assert_eq!(junk.location(), "/credentials?notice=not_found");
    h.finish().await;
}

#[sqlx::test]
async fn user_b_cannot_see_delete_or_verify_user_a_rows(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    h.put(&alice, "github_pat", PAT).await;
    let id = id_of(&h.pool, alice.user_id, "github_pat").await;
    let fingerprint: String = sqlx::query_scalar("SELECT fingerprint FROM credentials")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let page = h.page(&bob, "").await;
    assert!(!page.body.contains("octo"));
    assert!(!page.body.contains(&fingerprint));
    let del = h
        .act(&bob, "delete", &format!("csrf={}&id={id}", bob.csrf))
        .await;
    assert_eq!(del.location(), "/credentials?notice=not_found");
    let calls = h.github.calls();
    let verify = h
        .act(&bob, "verify", &format!("csrf={}&id={id}", bob.csrf))
        .await;
    assert_eq!(verify.location(), "/credentials?notice=not_found");
    assert_eq!(h.github.calls(), calls);
    assert_eq!(stored(&h.pool).await, 1);
    h.put(&bob, "github_pat", PAT_B).await;
    assert_eq!(stored(&h.pool).await, 2);
    let alice_page = h.page(&alice, "").await;
    assert!(alice_page.body.contains(&fingerprint));
    h.finish().await;
}

#[sqlx::test]
async fn verify_reports_valid_and_invalid_and_refuses_kinds_without_a_verifier(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    h.put(&alice, "github_pat", PAT).await;
    h.put(&alice, "anthropic_api_key", ANT).await;
    let gh = id_of(&h.pool, alice.user_id, "github_pat").await;
    let ant = id_of(&h.pool, alice.user_id, "anthropic_api_key").await;
    let body = format!("csrf={}&id={gh}", alice.csrf);
    let ok = h.act(&alice, "verify", &body).await;
    assert_eq!(ok.location(), "/credentials?notice=verified");
    h.github.set(Err(GithubError::Rejected));
    let bad = h.act(&alice, "verify", &body).await;
    assert_eq!(bad.location(), "/credentials?notice=invalid_token");
    h.github.set(Err(GithubError::Unavailable));
    let down = h.act(&alice, "verify", &body).await;
    assert_eq!(down.location(), "/credentials?notice=unavailable");
    let none = h
        .act(&alice, "verify", &format!("csrf={}&id={ant}", alice.csrf))
        .await;
    assert_eq!(none.location(), "/credentials?notice=no_verifier");
    let page = h.page(&alice, "?notice=invalid_token").await;
    assert!(page.body.contains("GitHub refused the stored token"));
    h.finish().await;
}
