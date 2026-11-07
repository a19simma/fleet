//! `FleetRepos` handlers and store (ADR-0059). They need a Postgres superuser URL in
//! `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_core::repo::{RepoRef, RepoVerdict};
use fleet_proto::v1::fleet_repos_client::FleetReposClient;
use fleet_proto::v1::{AddRepoRequest, ListReposRequest, RemoveRepoRequest, RepoInfo};
use fleet_server::auth::BearerAuth;
use fleet_server::config::{Forge, HostConfig, RepoHosts, Token};
use fleet_server::cred::https::{FetchError, ForgeGet, ForgeReply, ForgeTransport};
use fleet_server::cred::limiter::Clock;
use fleet_server::cred::repo_fake::{FakeState, FakeVerifier};
use fleet_server::cred::repo_limit::CheckLimiter;
use fleet_server::cred::repo_store::RepoStore;
use fleet_server::cred::repo_verify::{
    GithubVerifier, RepoCredential, RepoRefusal, RepoVerifier, RepoVerifiers,
};
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, RepoService, Users};
use fleet_server::service::router_with;
use fleet_server::store::Store;
use hyper::StatusCode;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const HOSTS: &str = "host=github.com,forge=github,api=https://api.github.com;host=git.example.org,forge=forgejo,api=https://git.example.org/api/v1";

static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

struct Echo {
    calls: AtomicUsize,
    kinds: Mutex<Vec<&'static str>>,
}

impl Echo {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            kinds: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl RepoVerifier for Echo {
    async fn verify(
        &self,
        _host: &HostConfig,
        credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let kind = match credential {
            None => return Err(RepoRefusal::NoCredential),
            Some(RepoCredential::Pat(_)) => "pat",
            Some(RepoCredential::App { .. }) => "app",
        };
        self.kinds.lock().unwrap().push(kind);
        Ok(RepoVerdict {
            canonical_path: repo.path().to_owned(),
            read: true,
            push: Some(true),
            login: None,
        })
    }
}

struct Vanishing {
    pool: PgPool,
}

#[tonic::async_trait]
impl RepoVerifier for Vanishing {
    async fn verify(
        &self,
        _host: &HostConfig,
        _credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        sqlx::query("DELETE FROM credentials")
            .execute(&self.pool)
            .await
            .unwrap();
        Ok(RepoVerdict {
            canonical_path: repo.path().to_owned(),
            read: true,
            push: None,
            login: None,
        })
    }
}

struct Gated {
    entered: tokio::sync::Notify,
    gate: tokio::sync::Semaphore,
}

#[tonic::async_trait]
impl RepoVerifier for Gated {
    async fn verify(
        &self,
        _host: &HostConfig,
        _credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        self.entered.notify_one();
        self.gate.acquire().await.unwrap().forget();
        Ok(RepoVerdict {
            canonical_path: repo.path().to_owned(),
            read: true,
            push: None,
            login: None,
        })
    }
}

struct Script {
    reply: ForgeReply,
}

#[tonic::async_trait]
impl ForgeTransport for Script {
    async fn get(&self, _request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        Ok(self.reply.clone())
    }
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn logs() -> &'static LogBuffer {
    static BUFFER: std::sync::OnceLock<LogBuffer> = std::sync::OnceLock::new();
    static INIT: Once = Once::new();
    let buffer = BUFFER.get_or_init(LogBuffer::default);
    INIT.call_once(|| {
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(buffer.clone())
                .with_max_level(tracing::Level::TRACE)
                .finish(),
        )
        .unwrap();
    });
    buffer
}

struct Setup {
    verifier: Arc<dyn RepoVerifier>,
    max_repos: usize,
    limiter: Option<CheckLimiter>,
    concurrency: Option<usize>,
    budget: Option<Duration>,
    configured: bool,
    users: bool,
    hosts: &'static str,
}

impl Setup {
    fn new(verifier: Arc<dyn RepoVerifier>) -> Self {
        Self {
            verifier,
            max_repos: fleet_proto::MAX_REPOS_PER_USER,
            limiter: None,
            concurrency: None,
            budget: None,
            configured: true,
            users: true,
            hosts: HOSTS,
        }
    }

    fn fake(fake: FakeVerifier) -> Self {
        Self::new(Arc::new(fake))
    }
}

struct Harness {
    client: FleetReposClient<Channel>,
    alice: String,
    bob: String,
    admin: String,
    pool: PgPool,
    alice_id: i64,
    bob_id: i64,
    creds: CredentialStore,
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn give_pat(creds: &CredentialStore, user_id: i64) {
    creds
        .put(
            user_id,
            CredentialKind::GithubPat,
            CredentialShape::StaticSecret,
            Secret::new(PAT.to_owned()),
            Some("octo".to_owned()),
            None,
        )
        .await
        .unwrap();
}

async fn token(users: &Users, id: i64) -> String {
    let made = users.create_api_token(id, "t").await.unwrap();
    String::from_utf8(made.token.expose().to_vec()).unwrap()
}

async fn harness(pool: PgPool, setup: Setup) -> Harness {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice_id = user(&pool, "alice").await;
    let bob_id = user(&pool, "bob").await;
    let admin_id = user(&pool, "root").await;
    sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .unwrap();
    let users = Users::new(pool.clone());
    let (alice, bob, admin) = (
        token(&users, alice_id).await,
        token(&users, bob_id).await,
        token(&users, admin_id).await,
    );
    let path = std::env::temp_dir().join(format!(
        "fleet-repo-rpc-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
    give_pat(&creds, alice_id).await;
    give_pat(&creds, bob_id).await;
    let mut verifiers = RepoVerifiers::new(RepoHosts::parse(setup.hosts).unwrap())
        .with(Forge::Github, Arc::clone(&setup.verifier))
        .with(Forge::Forgejo, Arc::clone(&setup.verifier));
    if let Some(budget) = setup.budget {
        verifiers = verifiers.with_budget(budget);
    }
    let mut repos = RepoService::new(
        RepoStore::new(pool.clone(), creds.clone()).with_max_repos(setup.max_repos),
        Arc::new(verifiers),
    );
    if let Some(limiter) = setup.limiter {
        repos = repos.with_limiter(limiter);
    }
    if let Some(permits) = setup.concurrency {
        repos = repos.with_concurrency(permits);
    }
    let service = CredentialService::new(creds.clone(), Arc::new(NoGithub)).with_repos(repos);
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let auth = if setup.users {
        auth.with_users(users)
    } else {
        auth
    };
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with(&store, &auth, setup.configured.then_some(service))
            .serve_with_incoming(incoming),
    );
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    Harness {
        client: FleetReposClient::new(channel),
        alice,
        bob,
        admin,
        pool,
        alice_id,
        bob_id,
        creds,
    }
}

struct NoGithub;

#[tonic::async_trait]
impl fleet_server::cred::github::GithubApi for NoGithub {
    async fn user(
        &self,
        _token: &Secret,
    ) -> Result<fleet_server::cred::github::GithubUser, fleet_server::cred::github::GithubError>
    {
        Err(fleet_server::cred::github::GithubError::Unavailable)
    }
}

fn as_token<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

fn add(repo: &str) -> AddRepoRequest {
    AddRepoRequest {
        repo: repo.to_owned(),
    }
}

fn remove(host: &str, path: &str) -> RemoveRepoRequest {
    RemoveRepoRequest {
        host: host.to_owned(),
        path: path.to_owned(),
    }
}

async fn add_as(h: &mut Harness, token: &str, repo: &str) -> Result<RepoInfo, tonic::Status> {
    h.client
        .add_repo(as_token(token, add(repo)))
        .await
        .map(tonic::Response::into_inner)
}

async fn rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM user_repos")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn ok_add(h: &mut Harness, repo: &str) -> RepoInfo {
    let alice = h.alice.clone();
    add_as(h, &alice, repo).await.unwrap()
}

async fn push_is_recorded(pool: PgPool, push: Option<bool>) {
    let mut h = harness(pool, Setup::fake(FakeVerifier::ok("octo/hello", push))).await;
    let info = ok_add(&mut h, "https://github.com/octo/hello").await;
    assert_eq!(info.host, "github.com");
    assert_eq!(info.path, "octo/hello");
    assert_eq!(info.forge_kind, "github");
    assert_eq!(info.push, push);
    assert!(info.runnable);
    assert!(info.verified_at_ms > 1_700_000_000_000);
    let stored: Option<bool> = sqlx::query_scalar("SELECT push FROM user_repos")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(stored, push);
    let alice = h.alice.clone();
    let listed = h
        .client
        .list_repos(as_token(&alice, ListReposRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.repos, vec![info]);
}

#[sqlx::test]
async fn add_with_push_true(pool: PgPool) {
    push_is_recorded(pool, Some(true)).await;
}

#[sqlx::test]
async fn add_with_push_false(pool: PgPool) {
    push_is_recorded(pool, Some(false)).await;
}

#[sqlx::test]
async fn add_with_push_unreported(pool: PgPool) {
    push_is_recorded(pool, None).await;
}

async fn refusal_is_exact(pool: PgPool, fake: FakeVerifier, reason: &str) {
    let mut h = harness(pool, Setup::fake(fake)).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), reason);
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn refusal_not_allowed_host(pool: PgPool) {
    refusal_is_exact(
        pool,
        FakeVerifier::not_allowed_host(),
        fleet_proto::PRECONDITION_REPO_NOT_ALLOWED_HOST,
    )
    .await;
}

#[sqlx::test]
async fn refusal_no_credential(pool: PgPool) {
    refusal_is_exact(
        pool,
        FakeVerifier::no_credential(),
        fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL,
    )
    .await;
}

#[sqlx::test]
async fn refusal_not_found_or_no_access(pool: PgPool) {
    refusal_is_exact(
        pool,
        FakeVerifier::not_found_or_no_access(),
        fleet_proto::PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
    )
    .await;
}

#[sqlx::test]
async fn refusal_upstream_unavailable(pool: PgPool) {
    refusal_is_exact(
        pool,
        FakeVerifier::upstream_unavailable(),
        fleet_proto::PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
    )
    .await;
}

#[sqlx::test]
async fn refusal_timeout_from_the_forge(pool: PgPool) {
    refusal_is_exact(
        pool,
        FakeVerifier::timed_out(),
        fleet_proto::PRECONDITION_REPO_TIMEOUT,
    )
    .await;
}

#[sqlx::test]
async fn a_hanging_forge_times_out_at_the_budget(pool: PgPool) {
    let mut setup = Setup::fake(FakeVerifier::hanging());
    setup.budget = Some(Duration::from_millis(100));
    let mut h = harness(pool, setup).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_TIMEOUT);
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn a_user_without_a_credential_is_refused_and_stores_nothing(pool: PgPool) {
    let mut h = harness(pool, Setup::fake(FakeVerifier::ok("octo/hello", None))).await;
    sqlx::query("DELETE FROM credentials WHERE user_id = $1")
        .bind(h.alice_id)
        .execute(&h.pool)
        .await
        .unwrap();
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn a_host_off_the_operator_list_is_refused_before_any_check(pool: PgPool) {
    let echo = Echo::new();
    let mut h = harness(pool, Setup::new(echo.clone())).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "https://evil.example/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        err.message(),
        fleet_proto::PRECONDITION_REPO_NOT_ALLOWED_HOST
    );
    assert_eq!(echo.calls(), 0);
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn a_forgejo_host_has_no_credential_until_repo_8(pool: PgPool) {
    let echo = Echo::new();
    let mut h = harness(pool, Setup::new(echo)).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "https://git.example.org/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
}

#[sqlx::test]
async fn a_non_github_row_lists_as_not_runnable(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    sqlx::query(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, 'git.example.org', 'o/n', 'forgejo')",
    )
    .bind(h.alice_id)
    .execute(&h.pool)
    .await
    .unwrap();
    ok_add(&mut h, "github.com/octo/hello").await;
    let alice = h.alice.clone();
    let listed = h
        .client
        .list_repos(as_token(&alice, ListReposRequest {}))
        .await
        .unwrap()
        .into_inner();
    let flags: Vec<(String, bool)> = listed
        .repos
        .iter()
        .map(|r| (r.host.clone(), r.runnable))
        .collect();
    assert_eq!(
        flags,
        vec![
            ("git.example.org".to_owned(), false),
            ("github.com".to_owned(), true)
        ]
    );
}

#[sqlx::test]
async fn the_path_comes_from_the_verdict_and_the_host_is_lowercase(pool: PgPool) {
    let mut h = harness(pool, Setup::fake(FakeVerifier::moved("new/home"))).await;
    let info = ok_add(&mut h, "GitHub.com/Old/Name.git").await;
    assert_eq!(
        (info.host.as_str(), info.path.as_str()),
        ("github.com", "new/home")
    );
}

#[sqlx::test]
async fn a_verdict_outside_the_forge_grammar_is_upstream_unavailable(pool: PgPool) {
    let mut h = harness(pool, Setup::fake(FakeVerifier::moved("a/b/c"))).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        err.message(),
        fleet_proto::PRECONDITION_REPO_UPSTREAM_UNAVAILABLE
    );
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn an_unreadable_verdict_is_not_found_or_no_access(pool: PgPool) {
    let verdict = RepoVerdict {
        canonical_path: "octo/hello".to_owned(),
        read: false,
        push: Some(true),
        login: None,
    };
    let mut h = harness(
        pool,
        Setup::fake(FakeVerifier::new(FakeState::Verdict(verdict))),
    )
    .await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(
        err.message(),
        fleet_proto::PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS
    );
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn hostile_references_are_refused_before_any_check(pool: PgPool) {
    let echo = Echo::new();
    let mut h = harness(pool, Setup::new(echo.clone())).await;
    let alice = h.alice.clone();
    let long = format!("github.com/octo/{}", "n".repeat(5000));
    let cases = [
        "",
        "github.com/octo",
        "http://github.com/octo/hello",
        "https://user@github.com/octo/hello",
        "https://github.com:443/octo/hello",
        "github.com/octo/hello?x=1",
        "github.com/octo/he%6clo",
        "github.com/octo/hello\r\n",
        "https://127.0.0.1/octo/hello",
        long.as_str(),
    ];
    for case in cases {
        let err = add_as(&mut h, &alice, case).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{case:?}");
        assert!(!err.message().contains("octo"), "{case:?}");
    }
    assert_eq!(echo.calls(), 0);
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn re_adding_refreshes_push_and_verified_at(pool: PgPool) {
    let mut h = harness(
        pool,
        Setup::fake(FakeVerifier::ok("octo/hello", Some(true))),
    )
    .await;
    ok_add(&mut h, "github.com/octo/hello").await;
    sqlx::query(
        "UPDATE user_repos SET push = false, verified_at = to_timestamp(1000), forge_kind = 'forgejo'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let again = ok_add(&mut h, "github.com/OCTO/hello").await;
    assert_eq!(again.push, Some(true));
    assert_eq!(again.forge_kind, "github");
    assert!(again.verified_at_ms > 1_700_000_000_000);
    assert_eq!(rows(&h.pool).await, 1);
    let (push, kind): (Option<bool>, String) =
        sqlx::query_as("SELECT push, forge_kind FROM user_repos")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!((push, kind.as_str()), (Some(true), "github"));
}

#[sqlx::test]
async fn user_b_cannot_list_or_remove_user_a_rows(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    ok_add(&mut h, "github.com/octo/hello").await;
    let bob = h.bob.clone();
    let listed = h
        .client
        .list_repos(as_token(&bob, ListReposRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.repos, Vec::<RepoInfo>::new());
    let foreign = h
        .client
        .remove_repo(as_token(&bob, remove("github.com", "octo/hello")))
        .await
        .unwrap_err();
    let missing = h
        .client
        .remove_repo(as_token(&bob, remove("github.com", "octo/nothing")))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(foreign.code(), missing.code());
    assert_eq!(foreign.message(), missing.message());
    assert_eq!(foreign.message(), fleet_proto::ERR_REPO_NOT_FOUND);
    assert_eq!(rows(&h.pool).await, 1);
    let alice = h.alice.clone();
    h.client
        .remove_repo(as_token(&alice, remove("GitHub.com", "Octo/Hello")))
        .await
        .unwrap();
    assert_eq!(rows(&h.pool).await, 0);
    let gone = h
        .client
        .remove_repo(as_token(&alice, remove("github.com", "octo/hello")))
        .await
        .unwrap_err();
    assert_eq!(gone.message(), foreign.message());
}

#[sqlx::test]
async fn two_users_hold_the_same_repository_independently(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    let (alice, bob) = (h.alice.clone(), h.bob.clone());
    add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap();
    add_as(&mut h, &bob, "github.com/octo/hello").await.unwrap();
    assert_eq!(rows(&h.pool).await, 2);
    h.client
        .remove_repo(as_token(&bob, remove("github.com", "octo/hello")))
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT user_id FROM user_repos")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(left, h.alice_id);
    assert_ne!(left, h.bob_id);
}

#[sqlx::test]
async fn box_and_unknown_tokens_are_refused_on_every_rpc(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    for (token, code) in [
        (BOX, Code::PermissionDenied),
        (
            "job-token-0123456789abcdef0123456789",
            Code::Unauthenticated,
        ),
    ] {
        let a = h
            .client
            .add_repo(as_token(token, add("github.com/o/n")))
            .await;
        let l = h
            .client
            .list_repos(as_token(token, ListReposRequest {}))
            .await;
        let r = h
            .client
            .remove_repo(as_token(token, remove("github.com", "o/n")))
            .await;
        for err in [a.unwrap_err(), l.unwrap_err(), r.unwrap_err()] {
            assert_eq!(err.code(), code, "{token}");
            if code == Code::PermissionDenied {
                assert_eq!(err.message(), "bearer token not valid for this service");
            }
        }
    }
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn a_request_without_a_token_is_unauthenticated(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    let a = h.client.add_repo(Request::new(add("github.com/o/n"))).await;
    let l = h.client.list_repos(Request::new(ListReposRequest {})).await;
    let r = h
        .client
        .remove_repo(Request::new(remove("github.com", "o/n")))
        .await;
    for code in [
        a.unwrap_err().code(),
        l.unwrap_err().code(),
        r.unwrap_err().code(),
    ] {
        assert_eq!(code, Code::Unauthenticated);
    }
}

#[sqlx::test]
async fn an_admin_and_the_bootstrap_user_add_their_own_repos(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    let admin = h.admin.clone();
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'root'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    give_pat(&h.creds, admin_id).await;
    add_as(&mut h, &admin, "github.com/octo/hello")
        .await
        .unwrap();
    let rows_of_admin: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_repos WHERE user_id = $1")
            .bind(admin_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows_of_admin, 1);
    let bootstrap = add_as(&mut h, CLIENT, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(bootstrap.code(), Code::FailedPrecondition);
    assert_eq!(
        bootstrap.message(),
        fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL
    );
    let listed = h
        .client
        .list_repos(as_token(CLIENT, ListReposRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.repos, Vec::<RepoInfo>::new());
}

#[sqlx::test]
async fn an_unconfigured_server_is_a_failed_precondition(pool: PgPool) {
    let mut setup = Setup::new(Echo::new());
    setup.configured = false;
    let mut h = harness(pool, setup).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/o/n").await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_NOT_CONFIGURED);
}

#[sqlx::test]
async fn the_row_cap_refuses_one_over_and_still_refreshes_a_held_row(pool: PgPool) {
    let mut setup = Setup::new(Echo::new());
    setup.max_repos = 2;
    let mut h = harness(pool, setup).await;
    ok_add(&mut h, "github.com/octo/one").await;
    ok_add(&mut h, "github.com/octo/two").await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/three")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(err.message(), fleet_proto::ERR_REPO_LIMIT);
    assert_eq!(rows(&h.pool).await, 2);
    ok_add(&mut h, "github.com/octo/two").await;
    assert_eq!(rows(&h.pool).await, 2);
    let bob = h.bob.clone();
    add_as(&mut h, &bob, "github.com/octo/three").await.unwrap();
    h.client
        .remove_repo(as_token(&alice, remove("github.com", "octo/one")))
        .await
        .unwrap();
    ok_add(&mut h, "github.com/octo/three").await;
    assert_eq!(rows(&h.pool).await, 3);
}

#[sqlx::test]
async fn the_production_cap_is_the_shared_constant(pool: PgPool) {
    let mut h = harness(pool, Setup::new(Echo::new())).await;
    for n in 0..fleet_proto::MAX_REPOS_PER_USER {
        sqlx::query(
            "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, 'github.com', $2, 'github')",
        )
        .bind(h.alice_id)
        .bind(format!("o/r{n}"))
        .execute(&h.pool)
        .await
        .unwrap();
    }
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/extra")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    let listed = h
        .client
        .list_repos(as_token(&alice, ListReposRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.repos.len(), fleet_proto::MAX_REPOS_PER_USER);
}

#[sqlx::test]
async fn the_per_user_check_limit_follows_the_injected_clock(pool: PgPool) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let seen = Arc::clone(&now);
    let clock: Clock = Arc::new(move || *seen.lock().unwrap());
    let echo = Echo::new();
    let mut setup = Setup::new(echo.clone());
    setup.limiter = Some(CheckLimiter::new(clock, 2, Duration::from_secs(60)));
    let mut h = harness(pool, setup).await;
    let (alice, bob) = (h.alice.clone(), h.bob.clone());
    add_as(&mut h, &alice, "github.com/octo/one").await.unwrap();
    add_as(&mut h, &alice, "github.com/octo/two").await.unwrap();
    let err = add_as(&mut h, &alice, "github.com/octo/three")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(err.message(), fleet_proto::ERR_REPO_RATE_LIMITED);
    assert_eq!(echo.calls(), 2);
    add_as(&mut h, &bob, "github.com/octo/one").await.unwrap();
    *now.lock().unwrap() += Duration::from_secs(60);
    add_as(&mut h, &alice, "github.com/octo/three")
        .await
        .unwrap();
    assert_eq!(echo.calls(), 4);
}

#[sqlx::test]
async fn a_user_over_the_limit_is_rate_limited_while_the_global_cap_is_full(pool: PgPool) {
    let gated = Arc::new(Gated {
        entered: tokio::sync::Notify::new(),
        gate: tokio::sync::Semaphore::new(1),
    });
    let clock: Clock = Arc::new(Instant::now);
    let mut setup = Setup::new(gated.clone());
    setup.concurrency = Some(1);
    setup.limiter = Some(CheckLimiter::new(clock, 1, Duration::from_secs(600)));
    let mut h = harness(pool, setup).await;
    let (alice, bob) = (h.alice.clone(), h.bob.clone());
    add_as(&mut h, &alice, "github.com/octo/one").await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), gated.entered.notified())
        .await
        .unwrap();
    let mut holder = h.client.clone();
    let held = tokio::spawn(async move {
        holder
            .add_repo(as_token(&bob, add("github.com/octo/two")))
            .await
    });
    tokio::time::timeout(Duration::from_secs(30), gated.entered.notified())
        .await
        .unwrap();
    let err = add_as(&mut h, &alice, "github.com/octo/three")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(err.message(), fleet_proto::ERR_REPO_RATE_LIMITED);
    gated.gate.add_permits(1);
    held.await.unwrap().unwrap();
    assert_eq!(rows(&h.pool).await, 2);
}

#[sqlx::test]
async fn an_unhosted_github_credential_is_never_sent_to_another_github_host(pool: PgPool) {
    let echo = Echo::new();
    let mut setup = Setup::new(echo.clone());
    setup.hosts = "host=github.com,forge=github,api=https://api.github.com;host=ghe.example,forge=github,api=https://ghe.example/api/v3";
    let mut h = harness(pool, setup).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "ghe.example/octo/one")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
    assert!(echo.kinds.lock().unwrap().is_empty());
    assert_eq!(rows(&h.pool).await, 0);
    ok_add(&mut h, "github.com/octo/one").await;
    assert_eq!(*echo.kinds.lock().unwrap(), vec!["pat"]);
}

#[sqlx::test]
async fn the_global_semaphore_bounds_concurrent_checks(pool: PgPool) {
    let gated = Arc::new(Gated {
        entered: tokio::sync::Notify::new(),
        gate: tokio::sync::Semaphore::new(0),
    });
    let mut setup = Setup::new(gated.clone());
    setup.concurrency = Some(1);
    let mut h = harness(pool, setup).await;
    let (alice, bob) = (h.alice.clone(), h.bob.clone());
    let mut first_client = h.client.clone();
    let first = tokio::spawn(async move {
        first_client
            .add_repo(as_token(&alice, add("github.com/octo/one")))
            .await
    });
    tokio::time::timeout(Duration::from_secs(30), gated.entered.notified())
        .await
        .unwrap();
    let err = add_as(&mut h, &bob, "github.com/octo/two")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(err.message(), fleet_proto::ERR_REPO_BUSY);
    gated.gate.add_permits(2);
    first.await.unwrap().unwrap();
    add_as(&mut h, &bob, "github.com/octo/two").await.unwrap();
    assert_eq!(rows(&h.pool).await, 2);
}

#[sqlx::test]
async fn a_credential_removed_between_verify_and_insert_inserts_nothing(pool: PgPool) {
    let mut h = harness(pool.clone(), Setup::new(Arc::new(Vanishing { pool }))).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
    assert_eq!(rows(&h.pool).await, 0);
}

#[sqlx::test]
async fn a_tombstoned_credential_between_verify_and_insert_inserts_nothing(pool: PgPool) {
    struct Tombstone {
        pool: PgPool,
    }

    #[tonic::async_trait]
    impl RepoVerifier for Tombstone {
        async fn verify(
            &self,
            _host: &HostConfig,
            _credential: Option<&RepoCredential>,
            repo: &RepoRef,
        ) -> Result<RepoVerdict, RepoRefusal> {
            sqlx::query("UPDATE credentials SET tombstoned_at = now()")
                .execute(&self.pool)
                .await
                .unwrap();
            Ok(RepoVerdict {
                canonical_path: repo.path().to_owned(),
                read: true,
                push: None,
                login: None,
            })
        }
    }

    let mut h = harness(pool.clone(), Setup::new(Arc::new(Tombstone { pool }))).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
    assert_eq!(rows(&h.pool).await, 0);
}

async fn blocked_until_released(h: &Harness, lock: &'static str, id: i64) {
    let mut tx = h.pool.begin().await.unwrap();
    sqlx::query(lock)
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    let alice = h.alice.clone();
    let mut client = h.client.clone();
    let call = tokio::spawn(async move {
        client
            .add_repo(as_token(&alice, add("github.com/octo/hello")))
            .await
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!call.is_finished(), "the insert did not wait for {lock}");
    tx.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[sqlx::test]
async fn an_insert_waits_on_the_user_row_lock(pool: PgPool) {
    let h = harness(pool, Setup::new(Echo::new())).await;
    let id = h.alice_id;
    blocked_until_released(&h, "SELECT id FROM users WHERE id = $1 FOR SHARE", id).await;
}

#[sqlx::test]
async fn an_insert_waits_on_a_credential_delete_in_flight(pool: PgPool) {
    let h = harness(pool, Setup::new(Echo::new())).await;
    let id = h.alice_id;
    blocked_until_released(
        &h,
        "SELECT id FROM credentials WHERE user_id = $1 FOR UPDATE",
        id,
    )
    .await;
}

struct LockingVerifier {
    pool: PgPool,
    locked: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl RepoVerifier for LockingVerifier {
    async fn verify(
        &self,
        _host: &HostConfig,
        _credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        let mut tx = self.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM credentials FOR UPDATE")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        let release = self.release.clone();
        let locked = self.locked.clone();
        tokio::spawn(async move {
            locked.notify_one();
            release.notified().await;
            tx.commit().await.unwrap();
        });
        self.locked.notified().await;
        Ok(RepoVerdict {
            canonical_path: repo.path().to_owned(),
            read: true,
            push: None,
            login: None,
        })
    }
}

#[sqlx::test]
async fn the_recheck_waits_on_a_credential_locked_after_the_check(pool: PgPool) {
    let locked = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let verifier = Arc::new(LockingVerifier {
        pool: pool.clone(),
        locked: locked.clone(),
        release: release.clone(),
    });
    let h = harness(pool, Setup::new(verifier)).await;
    let alice = h.alice.clone();
    let mut client = h.client.clone();
    let call = tokio::spawn(async move {
        client
            .add_repo(as_token(&alice, add("github.com/octo/hello")))
            .await
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!call.is_finished(), "the recheck did not wait for the lock");
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(30), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(rows(&h.pool).await, 1);
}

#[sqlx::test]
async fn concurrent_adds_never_pass_the_cap(pool: PgPool) {
    let mut setup = Setup::new(Echo::new());
    setup.max_repos = 3;
    let h = harness(pool, setup).await;
    let mut calls = Vec::new();
    for n in 0..8 {
        let mut client = h.client.clone();
        let alice = h.alice.clone();
        calls.push(tokio::spawn(async move {
            client
                .add_repo(as_token(&alice, add(&format!("github.com/octo/r{n}"))))
                .await
        }));
    }
    let mut ok = 0;
    for call in calls {
        if call.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 3);
    assert_eq!(rows(&h.pool).await, 3);
}

#[sqlx::test]
async fn no_secret_or_upstream_body_reaches_logs_or_replies(pool: PgPool) {
    let buffer = logs();
    let body = "UPSTREAM-BODY-SENTINEL-d41d8cd9";
    let transport = Script {
        reply: ForgeReply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: body.as_bytes().to_vec(),
            location: None,
        },
    };
    let verifier = GithubVerifier::new(Arc::new(transport), None);
    let mut h = harness(pool, Setup::new(Arc::new(verifier))).await;
    let alice = h.alice.clone();
    let err = add_as(&mut h, &alice, "github.com/octo/hello")
        .await
        .unwrap_err();
    assert_eq!(
        err.message(),
        fleet_proto::PRECONDITION_REPO_UPSTREAM_UNAVAILABLE
    );
    let reply = format!("{err:?}");
    let captured = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(captured.contains("repository lookup refused"), "{captured}");
    for needle in [PAT, body, &alice] {
        assert!(!reply.contains(needle));
        assert!(!captured.contains(needle), "{needle} reached the logs");
    }
}

#[sqlx::test]
async fn a_real_github_reply_is_parsed_for_path_and_push(pool: PgPool) {
    let transport = Script {
        reply: ForgeReply {
            status: StatusCode::OK,
            body: br#"{"full_name":"Octo/Hello","permissions":{"pull":true,"push":false}}"#
                .to_vec(),
            location: None,
        },
    };
    let verifier = GithubVerifier::new(Arc::new(transport), None);
    let mut h = harness(pool, Setup::new(Arc::new(verifier))).await;
    let info = ok_add(&mut h, "github.com/octo/hello").await;
    assert_eq!(info.path, "octo/hello");
    assert_eq!(info.push, Some(false));
}

#[sqlx::test]
async fn the_github_app_wins_over_the_pat(pool: PgPool) {
    let echo = Echo::new();
    let mut h = harness(pool, Setup::new(echo.clone())).await;
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'root'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    fleet_server::cred::capability::Capabilities::new(h.pool.clone())
        .grant(admin_id, h.alice_id, "forge:github_app")
        .await
        .unwrap();
    ok_add(&mut h, "github.com/octo/one").await;
    h.creds
        .put(
            h.alice_id,
            CredentialKind::GithubApp,
            CredentialShape::StaticSecret,
            Secret::new("12345678".to_owned()),
            None,
            None,
        )
        .await
        .unwrap();
    ok_add(&mut h, "github.com/octo/two").await;
    assert_eq!(*echo.kinds.lock().unwrap(), vec!["pat", "app"]);
}

#[sqlx::test]
async fn the_client_token_without_a_user_store_has_no_caller(pool: PgPool) {
    let mut setup = Setup::new(Echo::new());
    setup.users = false;
    let mut h = harness(pool, setup).await;
    let err = h
        .client
        .list_repos(as_token(CLIENT, ListReposRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), fleet_proto::ERR_NEEDS_USER_TOKEN);
}
