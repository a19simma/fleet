//! The console wiring the way `main` builds it: credentials, jobs and tokens pages answer
//! with a session and redirect to the login page without one, and the home and account
//! pages link to them. The tests need a Postgres superuser URL in `DATABASE_URL` for
//! `#[sqlx::test]` and live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
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
const PAGES: [&str; 3] = ["/credentials", "/jobs", "/tokens"];

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Rejected)
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

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn sealer() -> FileSealer {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "fleet-web-console-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    sealer.unwrap()
}

impl Harness {
    async fn start(pool: PgPool, credentials: bool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let service = credentials.then(|| {
            CredentialService::new(
                CredentialStore::new(pool.clone(), Arc::new(sealer())),
                Arc::new(NoGithub),
            )
        });
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_console(auth, service, store.clone());
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

    async fn cookie(&self) -> String {
        let user_id: i64 =
            sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let id = "a".repeat(64);
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, 'csrf-alice-token', now() + interval '1 hour')",
        )
        .bind(id.as_bytes())
        .bind(user_id)
        .execute(&self.pool)
        .await
        .unwrap();
        format!("{SESSION_COOKIE}={id}")
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(cookie) = cookie {
            let _ = write!(request, "Cookie: {cookie}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
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
async fn each_page_answers_with_a_session_and_redirects_without_one(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let cookie = h.cookie().await;
    for path in PAGES {
        assert_eq!(h.get(path, Some(&cookie)).await.status, 200, "{path}");
        let bare = h.get(path, None).await;
        assert_eq!(bare.status, 303, "{path}");
        assert_eq!(bare.location(), "/login", "{path}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn jobs_and_tokens_stay_up_when_credentials_are_unconfigured(pool: PgPool) {
    let h = Harness::start(pool, false).await;
    let cookie = h.cookie().await;
    assert_eq!(h.get("/credentials", Some(&cookie)).await.status, 404);
    assert_eq!(h.get("/jobs", Some(&cookie)).await.status, 200);
    assert_eq!(h.get("/tokens", Some(&cookie)).await.status, 200);
    h.finish().await;
}

#[sqlx::test]
async fn the_home_and_account_pages_link_to_each_page(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let cookie = h.cookie().await;
    let home = h.get("/", None).await;
    let account = h.get("/account", Some(&cookie)).await;
    for path in PAGES {
        let link = format!("href=\"{path}\"");
        assert!(home.body.contains(&link), "home {path}");
        assert!(account.body.contains(&link), "account {path}");
    }
    h.finish().await;
}
