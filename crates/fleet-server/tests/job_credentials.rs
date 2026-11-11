//! `FleetWorker.GetJobCredentials` over a real tonic server on a loopback port. The tests need a
//! Postgres superuser URL in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database
//! per test. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_proto::v1::SubmitJobRequest;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{ClaimJobRequest, GetJobCredentialsReply, GetJobCredentialsRequest, Job};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer};
use fleet_server::service::router_with;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const BOX: &str = "box-token-0123456789abcdef0123456789";

fn box_a() -> String {
    format!("box-{}", 1)
}

fn box_b() -> String {
    format!("box-{}", 2)
}
const CLIENT: &str = "client-token-0123456789abcdef012345";
const REPO: &str = "https://github.com/org/repo.git";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const OAT: &str = "sk-ant-oat01-abcdefghijklmnopqrstuv";
const CODEX: &str = "sk-abcdefghijklmnopqrstuvwxyz0123";
const BOB_PAT: &str = "github_pat_22ZYXWVUT9zyxwvutsrqponmlk";
const DENIED: &str = fleet_proto::ERR_LEASE_MISMATCH;
const STATIC: CredentialShape = CredentialShape::StaticSecret;

static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Worker = FleetWorkerClient<InterceptedService<Channel, Interceptor>>;

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Unavailable)
    }
}

fn as_box(mut request: Request<()>) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {BOX}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

struct World {
    pool: PgPool,
    store: Store,
    creds: CredentialStore,
    worker: Worker,
    alice: i64,
    bob: i64,
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world_with(pool: PgPool, configured: bool) -> World {
    world_opts(pool, configured, false).await
}

async fn world_opts(pool: PgPool, configured: bool, file_repos: bool) -> World {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let path = std::env::temp_dir().join(format!(
        "fleet-job-cred-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let mut creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
    if file_repos {
        creds = creds.with_file_repos();
    }
    let service = CredentialService::new(creds.clone(), Arc::new(NoGithub));
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with(&store, &auth, configured.then_some(service)).serve_with_incoming(incoming),
    );
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    World {
        pool,
        store,
        creds,
        worker: FleetWorkerClient::with_interceptor(channel, as_box),
        alice,
        bob,
    }
}

async fn world(pool: PgPool) -> World {
    world_with(pool, true).await
}

impl World {
    async fn put(&self, user_id: i64, kind: CredentialKind, value: &str, expires: Option<i64>) {
        self.creds
            .put(
                user_id,
                kind,
                STATIC,
                Secret::new(value.into()),
                None,
                expires,
            )
            .await
            .unwrap();
    }

    async fn running(&mut self, owner: i64, agent: &str, key: &str) -> Job {
        self.running_at(owner, agent, key, REPO).await
    }

    async fn running_at(&mut self, owner: i64, agent: &str, key: &str, repo: &str) -> Job {
        self.store
            .submit_job_for(
                Some(owner),
                &SubmitJobRequest {
                    idempotency_key: key.to_owned(),
                    prompt: "add hello.txt".to_owned(),
                    repo: repo.to_owned(),
                    base_ref: "main".to_owned(),
                    open_pr: false,
                    agent: String::new(),
                    profile: String::new(),
                    environment: String::new(),
                },
            )
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET agent = $1 WHERE idempotency_key = $2")
            .bind(agent)
            .bind(key)
            .execute(&self.pool)
            .await
            .unwrap();
        self.worker
            .claim_job(ClaimJobRequest { r#box: box_a() })
            .await
            .unwrap()
            .into_inner()
            .job
            .unwrap()
    }

    async fn fetch(
        &mut self,
        job: &Job,
        attempt: u32,
        box_name: &str,
    ) -> Result<GetJobCredentialsReply, Status> {
        self.worker
            .get_job_credentials(GetJobCredentialsRequest {
                job_id: job.job_id.clone(),
                attempt,
                r#box: box_name.to_owned(),
            })
            .await
            .map(tonic::Response::into_inner)
    }

    async fn uses(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM credential_use")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn pairs(reply: &GetJobCredentialsReply) -> Vec<(String, String, String)> {
    let mut out: Vec<_> = reply
        .credentials
        .iter()
        .map(|c| (c.kind.clone(), c.shape.clone(), c.value.clone()))
        .collect();
    out.sort();
    out
}

fn entry(kind: &str, value: &str) -> (String, String, String) {
    (
        kind.to_owned(),
        "static_secret".to_owned(),
        value.to_owned(),
    )
}

#[sqlx::test]
async fn the_lease_holder_gets_the_owner_agent_and_github_credentials(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::ClaudeSubscriptionToken, OAT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    w.put(w.alice, CredentialKind::CodexApiKey, CODEX, None)
        .await;
    w.put(w.bob, CredentialKind::GithubPat, BOB_PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![
            entry("anthropic_api_key", ANT),
            entry("claude_subscription_token", OAT),
            entry("github_pat", PAT),
        ]
    );
    assert_eq!(w.uses().await, 3);
    let used: Vec<String> = sqlx::query_scalar("SELECT DISTINCT job_id FROM credential_use")
        .fetch_all(&w.pool)
        .await
        .unwrap();
    assert_eq!(used, vec![job.job_id.clone()]);
}

async fn tombstone_then_fetch(pool: PgPool, kind: &str) -> (Status, i64) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE kind = $1")
        .bind(kind)
        .execute(&w.pool)
        .await
        .unwrap();
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    (err, w.uses().await)
}

#[sqlx::test]
async fn a_tombstoned_github_credential_is_not_released(pool: PgPool) {
    let (err, uses) = tombstone_then_fetch(pool, "github_pat").await;
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_NO_GITHUB);
    assert_eq!(uses, 0);
}

#[sqlx::test]
async fn a_tombstoned_agent_credential_is_not_released(pool: PgPool) {
    let (err, uses) = tombstone_then_fetch(pool, "anthropic_api_key").await;
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), fleet_proto::PRECONDITION_NO_AGENT);
    assert_eq!(uses, 0);
}

#[sqlx::test]
async fn a_codex_job_gets_only_codex_and_github(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::CodexApiKey, CODEX, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "codex", "k1").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![entry("codex_api_key", CODEX), entry("github_pat", PAT)]
    );
    assert_eq!(w.uses().await, 2);
}

#[sqlx::test]
async fn every_lease_mismatch_gets_the_same_denial(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let attempt = job.attempt;

    let wrong_box = w.fetch(&job, attempt, &box_b()).await.unwrap_err();
    let wrong_attempt = w.fetch(&job, attempt + 1, &box_a()).await.unwrap_err();
    let mut missing = job.clone();
    missing.job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned();
    let unknown = w.fetch(&missing, attempt, &box_a()).await.unwrap_err();
    let mut malformed = job.clone();
    malformed.job_id = "not a job".to_owned();
    let bad_id = w.fetch(&malformed, attempt, &box_a()).await.unwrap_err();
    let huge_attempt = w.fetch(&job, u32::MAX, &box_a()).await.unwrap_err();

    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 second'")
        .execute(&w.pool)
        .await
        .unwrap();
    let expired = w.fetch(&job, attempt, &box_a()).await.unwrap_err();

    sqlx::query(
        "UPDATE jobs SET lease_expires_at = now() + interval '1 hour', state = 'SUCCEEDED'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    let finished = w.fetch(&job, attempt, &box_a()).await.unwrap_err();

    for status in [
        wrong_box,
        wrong_attempt,
        unknown,
        bad_id,
        huge_attempt,
        expired,
        finished,
    ] {
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
        assert_eq!(status.message(), DENIED);
    }
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_queued_job_has_no_lease(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    sqlx::query("UPDATE jobs SET state = 'QUEUED'")
        .execute(&w.pool)
        .await
        .unwrap();
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(status.message(), DENIED);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn an_owner_without_github_fails_with_a_fixed_error(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.bob, CredentialKind::GithubPat, BOB_PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_NO_GITHUB);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn an_owner_without_an_agent_credential_fails_with_a_fixed_error(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    w.put(w.alice, CredentialKind::CodexApiKey, CODEX, None)
        .await;
    let job = w.running(w.alice, "claude", "k1").await;
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_NO_AGENT);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn an_expired_credential_is_refused_with_a_fixed_error(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(
        w.alice,
        CredentialKind::GithubPat,
        PAT,
        Some(1_900_000_000_000),
    )
    .await;
    let job = w.running(w.alice, "claude", "k1").await;
    sqlx::query(
        "UPDATE credentials SET expires_at = now() - interval '1 second' WHERE kind = 'github_pat'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_EXPIRED);
    assert!(!status.message().contains(PAT));
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_server_without_credentials_configured_refuses(pool: PgPool) {
    let mut w = world_with(pool, false).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_NOT_CONFIGURED);
}

#[sqlx::test]
async fn released_credentials_never_print_their_value(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let released = w
        .creds
        .release_for_job(&job.job_id, job.attempt, &box_a())
        .await
        .unwrap()
        .credentials;
    assert_eq!(released.len(), 2);
    for text in [format!("{released:?}"), format!("{released:#?}")] {
        assert!(!text.contains(ANT) && !text.contains(PAT), "{text}");
        assert!(text.contains("ReleasedCredential"), "{text}");
    }
}

const KIMI_M: &str = "sk-kimi-membership-abcdefghijklmnop";
const KIMI_P: &str = "sk-kimi-platform-abcdefghijklmnopqr";

async fn expire(w: &World, kind: &str) {
    sqlx::query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE kind = $1")
        .bind(kind)
        .execute(&w.pool)
        .await
        .unwrap();
}

async fn with_future_expiry(w: &World, kind: CredentialKind, value: &str) {
    w.put(w.alice, kind, value, Some(1_900_000_000_000)).await;
}

#[sqlx::test]
async fn only_an_expired_agent_credential_is_refused(pool: PgPool) {
    let mut w = world(pool).await;
    with_future_expiry(&w, CredentialKind::AnthropicApiKey, ANT).await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    expire(&w, "anthropic_api_key").await;
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_EXPIRED);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn an_expired_unneeded_claude_credential_is_skipped(pool: PgPool) {
    let mut w = world(pool).await;
    with_future_expiry(&w, CredentialKind::AnthropicApiKey, ANT).await;
    w.put(w.alice, CredentialKind::ClaudeSubscriptionToken, OAT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    expire(&w, "anthropic_api_key").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![
            entry("claude_subscription_token", OAT),
            entry("github_pat", PAT)
        ]
    );
    assert_eq!(w.uses().await, 2);
    let expired_used: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_use u JOIN credentials c ON c.id = u.credential_id \
         WHERE c.kind = 'anthropic_api_key'",
    )
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(expired_used, 0);
}

#[sqlx::test]
async fn a_kimi_job_gets_both_kimi_kinds(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::KimiMembershipKey, KIMI_M, None)
        .await;
    w.put(w.alice, CredentialKind::KimiPlatformKey, KIMI_P, None)
        .await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "kimi", "k1").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![
            entry("github_pat", PAT),
            entry("kimi_membership_key", KIMI_M),
            entry("kimi_platform_key", KIMI_P),
        ]
    );
    assert_eq!(w.uses().await, 3);
}

#[sqlx::test]
async fn an_unknown_agent_has_no_agent_credential(pool: PgPool) {
    let mut w = world(pool).await;
    sqlx::query("ALTER TABLE jobs DROP CONSTRAINT jobs_agent_check")
        .execute(&w.pool)
        .await
        .unwrap();
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "mystery", "k1").await;
    let status = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_NO_AGENT);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn job_writers_wait_while_a_release_is_open(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;

    let mut hold = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM credentials WHERE kind = 'anthropic_api_key' FOR UPDATE")
        .fetch_all(&mut *hold)
        .await
        .unwrap();

    let creds = w.creds.clone();
    let (job_id, attempt) = (job.job_id.clone(), job.attempt);
    let release =
        tokio::spawn(async move { creds.release_for_job(&job_id, attempt, &box_a()).await });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!release.is_finished());

    let mut writer = w.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '300ms'")
        .execute(&mut *writer)
        .await
        .unwrap();
    let blocked = sqlx::query("UPDATE jobs SET state = 'QUEUED' WHERE job_id = $1")
        .bind(&job.job_id)
        .execute(&mut *writer)
        .await;
    assert!(blocked.is_err(), "job write did not wait for the release");
    drop(writer);

    hold.rollback().await.unwrap();
    let released = tokio::time::timeout(std::time::Duration::from_secs(20), release)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .credentials;
    assert_eq!(released.len(), 2);
}

const FGJ: &str = "0123456789abcdef0123456789abcdef01234567";
const FGJ_HOST: &str = "git.example.com";

async fn forgejo_host(pool: &PgPool) {
    sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
        .bind(FGJ_HOST)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_forgejo_pat_is_never_released_to_a_github_job(pool: PgPool) {
    let mut w = world(pool).await;
    forgejo_host(&w.pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    w.creds
        .put_for_host(
            w.alice,
            FGJ_HOST,
            CredentialKind::ForgejoPat,
            STATIC,
            Secret::new(FGJ.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let job = w.running(w.alice, "claude", "k1").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![entry("anthropic_api_key", ANT), entry("github_pat", PAT)]
    );
    assert!(reply.credentials.iter().all(|c| c.value != FGJ));
}

#[sqlx::test]
async fn a_github_credential_stored_for_another_host_is_not_released(pool: PgPool) {
    let mut w = world(pool).await;
    forgejo_host(&w.pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    sqlx::query("UPDATE credentials SET host = $1 WHERE kind = 'github_pat'")
        .bind(FGJ_HOST)
        .execute(&w.pool)
        .await
        .unwrap();
    let job = w.running(w.alice, "claude", "k1").await;
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), "no github credential");
    assert_eq!(w.uses().await, 0);
}

const FGJ_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
const FGJ_HOST_B: &str = "code.example.net";
const FGJ_REPO: &str = "https://git.example.com/org/repo.git";
const FGJ_REPO_B: &str = "https://code.example.net/org/repo.git";
const NO_HOST_CREDENTIAL: &str = fleet_proto::PRECONDITION_HOST_NO_CREDENTIAL;

impl World {
    async fn put_forgejo(&self, user_id: i64, host: &str, value: &str, expires: Option<i64>) {
        self.creds
            .put_for_host(
                user_id,
                host,
                CredentialKind::ForgejoPat,
                STATIC,
                Secret::new(value.into()),
                None,
                expires,
            )
            .await
            .unwrap();
    }

    async fn grant(&self, host: &str, ips: &[&str]) {
        sqlx::query(
            "UPDATE git_hosts SET allow_private = true, \
             approved_ips = ARRAY(SELECT unnest($2::text[])::inet) WHERE host = $1",
        )
        .bind(host)
        .bind(ips)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn register(&self, user_id: i64, host: &str, verified: &str) {
        sqlx::query(
            "INSERT INTO user_repos (user_id, host, path, forge_kind, verified_at) \
             VALUES ($1, $2, 'org/repo', 'forgejo', $3::timestamptz)",
        )
        .bind(user_id)
        .bind(host)
        .bind(verified)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn forgejo_job(&mut self, repo: &str) -> Job {
        forgejo_host(&self.pool).await;
        self.put(self.alice, CredentialKind::AnthropicApiKey, ANT, None)
            .await;
        self.running_at(self.alice, "claude", "k1", repo).await
    }
}

async fn other_host(pool: &PgPool) {
    sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
        .bind(FGJ_HOST_B)
        .execute(pool)
        .await
        .unwrap();
}

fn host_entry(reply: &GetJobCredentialsReply) -> &fleet_proto::v1::JobHostCredential {
    assert_eq!(reply.hosts.len(), 1);
    reply.hosts.first().unwrap()
}

fn assert_refused(err: &Status, message: &str) {
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), message);
}

#[sqlx::test]
async fn a_github_job_reply_names_the_github_host(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    let host = host_entry(&reply);
    assert_eq!(host.host, "github.com");
    assert_eq!(host.host_kind, "github");
    assert!(!host.allow_private);
    assert_eq!(host.approved_ips, Vec::<String>::new());
    let credential = host.credential.as_ref().unwrap();
    assert_eq!(
        (credential.kind.as_str(), credential.value.as_str()),
        ("github_pat", PAT)
    );
    assert_eq!(
        pairs(&reply),
        vec![entry("anthropic_api_key", ANT), entry("github_pat", PAT)]
    );
}

#[sqlx::test]
async fn a_bare_owner_name_job_is_a_github_job(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    sqlx::query("UPDATE jobs SET repo = 'org/repo'")
        .execute(&w.pool)
        .await
        .unwrap();
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(host_entry(&reply).host, "github.com");
}

#[sqlx::test]
async fn a_forgejo_job_gets_its_pat_in_the_host_entry_only(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    w.grant(FGJ_HOST, &["192.168.3.1", "10.0.0.7"]).await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(pairs(&reply), vec![entry("anthropic_api_key", ANT)]);
    let host = host_entry(&reply);
    assert_eq!(host.host, FGJ_HOST);
    assert_eq!(host.host_kind, "forgejo");
    assert!(host.allow_private);
    assert_eq!(host.approved_ips, vec!["192.168.3.1", "10.0.0.7"]);
    let credential = host.credential.as_ref().unwrap();
    assert_eq!(
        (credential.kind.as_str(), credential.value.as_str()),
        ("forgejo_pat", FGJ)
    );
    assert_eq!(w.uses().await, 2);
}

#[sqlx::test]
async fn a_forgejo_job_without_a_private_grant_carries_no_addresses(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    let host = host_entry(&reply);
    assert!(!host.allow_private);
    assert_eq!(host.approved_ips, Vec::<String>::new());
}

#[sqlx::test]
async fn a_forgejo_job_without_its_pat_fails_with_the_fixed_error(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    other_host(&w.pool).await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    w.put_forgejo(w.alice, FGJ_HOST_B, FGJ_B, None).await;
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, NO_HOST_CREDENTIAL);
    assert!(!err.message().contains(PAT) && !err.message().contains(FGJ_B));
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn only_the_job_hosts_token_is_released(pool: PgPool) {
    let mut w = world(pool).await;
    other_host(&w.pool).await;
    let job = w.forgejo_job(FGJ_REPO_B).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    w.put_forgejo(w.alice, FGJ_HOST_B, FGJ_B, None).await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    let host = host_entry(&reply);
    assert_eq!(host.host, FGJ_HOST_B);
    assert_eq!(host.credential.as_ref().unwrap().value, FGJ_B);
    let text = format!("{reply:?}");
    assert!(!text.contains(FGJ) && !text.contains(PAT), "{text}");
}

#[sqlx::test]
async fn a_forgejo_job_of_another_owner_never_sees_the_owners_token(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.bob, FGJ_HOST, FGJ_B, None).await;
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, NO_HOST_CREDENTIAL);
}

#[sqlx::test]
async fn an_expired_forgejo_pat_is_refused(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, Some(1_700_000_000_000))
        .await;
    sqlx::query(
        "UPDATE credentials SET expires_at = now() - interval '1 hour' WHERE kind = 'forgejo_pat'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, "credential expired");
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_forgejo_job_with_no_agent_credential_is_refused(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    sqlx::query("DELETE FROM credentials WHERE kind = 'anthropic_api_key'")
        .execute(&w.pool)
        .await
        .unwrap();
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, "no agent credential");
}

#[sqlx::test]
async fn a_host_row_removed_before_the_fetch_releases_nothing(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    sqlx::query("DELETE FROM git_hosts WHERE host = $1")
        .bind(FGJ_HOST)
        .execute(&w.pool)
        .await
        .unwrap();
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, NO_HOST_CREDENTIAL);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_github_row_on_another_host_releases_no_github_token(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ('ghe.example.com', 'github')")
        .execute(&w.pool)
        .await
        .unwrap();
    let job = w
        .running_at(
            w.alice,
            "claude",
            "k1",
            "https://ghe.example.com/org/repo.git",
        )
        .await;
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, NO_HOST_CREDENTIAL);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn an_unreadable_job_repository_releases_nothing(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    sqlx::query("UPDATE jobs SET repo = 'not a repository'")
        .execute(&w.pool)
        .await
        .unwrap();
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, NO_HOST_CREDENTIAL);
}

#[sqlx::test]
async fn a_revoked_private_host_is_refused_before_claim(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    w.grant(FGJ_HOST, &["192.168.3.1"]).await;
    w.register(w.alice, FGJ_HOST, "now()").await;
    let admin = user(&w.pool, "admin").await;
    let host = fleet_core::host::HostName::normalise(FGJ_HOST).unwrap();
    fleet_server::hosts::HostStore::new(w.pool.clone())
        .revoke(admin, &host)
        .await
        .unwrap();
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, NO_HOST_CREDENTIAL);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_revoke_without_a_registered_repository_clears_the_reply_addresses(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    w.grant(FGJ_HOST, &["192.168.3.1"]).await;
    sqlx::query("UPDATE git_hosts SET allow_private = false, approved_ips = '{}'")
        .execute(&w.pool)
        .await
        .unwrap();
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    let host = host_entry(&reply);
    assert!(!host.allow_private);
    assert_eq!(host.approved_ips, Vec::<String>::new());
}

#[sqlx::test]
async fn a_verified_repository_without_a_grant_still_gets_its_token(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    w.register(w.alice, FGJ_HOST, "now()").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(host_entry(&reply).credential.as_ref().unwrap().value, FGJ);
}

#[sqlx::test]
async fn a_stale_repository_on_a_granted_host_still_gets_its_token(pool: PgPool) {
    let mut w = world(pool).await;
    let job = w.forgejo_job(FGJ_REPO).await;
    w.put_forgejo(w.alice, FGJ_HOST, FGJ, None).await;
    w.grant(FGJ_HOST, &["192.168.3.1"]).await;
    w.register(w.alice, FGJ_HOST, "1970-01-01T00:00:00Z").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert!(host_entry(&reply).allow_private);
}

async fn file_repo_world(file_repos: bool, pool: PgPool, repo: &str) -> (World, Job) {
    let mut w = world_opts(pool, true, file_repos).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "claude", "k1").await;
    sqlx::query("UPDATE jobs SET repo = $1")
        .bind(repo)
        .execute(&w.pool)
        .await
        .unwrap();
    (w, job)
}

#[sqlx::test]
async fn a_file_url_job_releases_the_github_credential_when_file_repos_are_on(pool: PgPool) {
    let (mut w, job) = file_repo_world(true, pool, "file:///srv/origin.git").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![entry("anthropic_api_key", ANT), entry("github_pat", PAT)]
    );
    let host = host_entry(&reply);
    assert_eq!(host.host, "");
    assert_eq!(host.host_kind, "github");
    assert!(!host.allow_private);
    assert_eq!(host.approved_ips, Vec::<String>::new());
    assert_eq!(w.uses().await, 2);
}

#[sqlx::test]
async fn an_absolute_path_job_releases_the_github_credential_when_file_repos_are_on(pool: PgPool) {
    let (mut w, job) = file_repo_world(true, pool, "/srv/origin.git").await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(host_entry(&reply).host, "");
    assert_eq!(pairs(&reply).len(), 2);
}

async fn assert_repo_refused(file_repos: bool, pool: PgPool, repo: &str) {
    let (mut w, job) = file_repo_world(file_repos, pool, repo).await;
    let err = w.fetch(&job, job.attempt, &box_a()).await.unwrap_err();
    assert_refused(&err, fleet_proto::PRECONDITION_HOST_NO_CREDENTIAL);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_file_url_job_is_refused_when_file_repos_are_off(pool: PgPool) {
    assert_repo_refused(false, pool, "file:///srv/origin.git").await;
}

#[sqlx::test]
async fn an_absolute_path_job_is_refused_when_file_repos_are_off(pool: PgPool) {
    assert_repo_refused(false, pool, "/srv/origin.git").await;
}

#[sqlx::test]
async fn file_repos_on_do_not_relax_an_unregistered_real_host(pool: PgPool) {
    assert_repo_refused(true, pool, "https://git.unregistered.example/org/repo.git").await;
}

#[sqlx::test]
async fn file_repos_on_do_not_relax_junk_text(pool: PgPool) {
    assert_repo_refused(true, pool, "not a repo").await;
}

#[sqlx::test]
async fn file_repos_on_do_not_relax_a_relative_path(pool: PgPool) {
    assert_repo_refused(true, pool, "relative/dir/origin.git").await;
}

async fn assert_hostless_release(pool: PgPool, repo: &str) {
    let (mut w, job) = file_repo_world(true, pool, repo).await;
    let reply = w.fetch(&job, job.attempt, &box_a()).await.unwrap();
    assert_eq!(
        pairs(&reply),
        vec![entry("anthropic_api_key", ANT), entry("github_pat", PAT)]
    );
    let host = host_entry(&reply);
    assert_eq!(host.host, "");
    assert_eq!(host.host_kind, "github");
    assert!(!host.allow_private);
    assert_eq!(host.approved_ips, Vec::<String>::new());
    assert_eq!(w.uses().await, 2);
}

#[sqlx::test]
async fn file_repos_on_release_hostless_for_a_file_url_naming_a_host(pool: PgPool) {
    assert_hostless_release(pool, "file://evil.example/x").await;
}

#[sqlx::test]
async fn file_repos_on_release_hostless_for_a_double_slash_path(pool: PgPool) {
    assert_hostless_release(pool, "//evil.example/a/b").await;
}

#[sqlx::test]
async fn file_repos_on_refuse_an_uppercase_file_scheme(pool: PgPool) {
    assert_repo_refused(true, pool, "FILE://x").await;
}

#[sqlx::test]
async fn file_repos_on_refuse_a_mixed_case_file_scheme(pool: PgPool) {
    assert_repo_refused(true, pool, "File:///srv/origin.git").await;
}

#[sqlx::test]
async fn file_repos_on_refuse_a_backslash_path(pool: PgPool) {
    assert_repo_refused(true, pool, "\\srv\\origin.git").await;
}

#[sqlx::test]
async fn file_repos_on_refuse_a_leading_space_path(pool: PgPool) {
    assert_repo_refused(true, pool, " /srv/origin.git").await;
}

#[sqlx::test]
async fn file_repos_on_refuse_a_leading_space_file_url(pool: PgPool) {
    assert_repo_refused(true, pool, " file:///srv/origin.git").await;
}
