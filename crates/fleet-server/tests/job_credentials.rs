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
const CLIENT: &str = "client-token-0123456789abcdef012345";
const REPO: &str = "https://example.com/org/repo.git";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const OAT: &str = "sk-ant-oat01-abcdefghijklmnopqrstuv";
const CODEX: &str = "sk-abcdefghijklmnopqrstuvwxyz0123";
const BOB_PAT: &str = "github_pat_22ZYXWVUT9zyxwvutsrqponmlk";
const DENIED: &str = "lease does not match";
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
    let creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
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
        self.store
            .submit_job_for(
                Some(owner),
                &SubmitJobRequest {
                    idempotency_key: key.to_owned(),
                    prompt: "add hello.txt".to_owned(),
                    repo: REPO.to_owned(),
                    base_ref: "main".to_owned(),
                    open_pr: false,
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
            .claim_job(ClaimJobRequest {
                r#box: "box-1".to_owned(),
            })
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
    let reply = w.fetch(&job, job.attempt, "box-1").await.unwrap();
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

#[sqlx::test]
async fn a_codex_job_gets_only_codex_and_github(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::AnthropicApiKey, ANT, None)
        .await;
    w.put(w.alice, CredentialKind::CodexApiKey, CODEX, None)
        .await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    let job = w.running(w.alice, "codex", "k1").await;
    let reply = w.fetch(&job, job.attempt, "box-1").await.unwrap();
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

    let wrong_box = w.fetch(&job, attempt, "box-2").await.unwrap_err();
    let wrong_attempt = w.fetch(&job, attempt + 1, "box-1").await.unwrap_err();
    let mut missing = job.clone();
    missing.job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned();
    let unknown = w.fetch(&missing, attempt, "box-1").await.unwrap_err();
    let mut malformed = job.clone();
    malformed.job_id = "not a job".to_owned();
    let bad_id = w.fetch(&malformed, attempt, "box-1").await.unwrap_err();
    let huge_attempt = w.fetch(&job, u32::MAX, "box-1").await.unwrap_err();

    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 second'")
        .execute(&w.pool)
        .await
        .unwrap();
    let expired = w.fetch(&job, attempt, "box-1").await.unwrap_err();

    sqlx::query(
        "UPDATE jobs SET lease_expires_at = now() + interval '1 hour', state = 'SUCCEEDED'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    let finished = w.fetch(&job, attempt, "box-1").await.unwrap_err();

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
    let status = w.fetch(&job, job.attempt, "box-1").await.unwrap_err();
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
    let status = w.fetch(&job, job.attempt, "box-1").await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "no github credential");
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn an_owner_without_an_agent_credential_fails_with_a_fixed_error(pool: PgPool) {
    let mut w = world(pool).await;
    w.put(w.alice, CredentialKind::GithubPat, PAT, None).await;
    w.put(w.alice, CredentialKind::CodexApiKey, CODEX, None)
        .await;
    let job = w.running(w.alice, "claude", "k1").await;
    let status = w.fetch(&job, job.attempt, "box-1").await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "no agent credential");
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
    let status = w.fetch(&job, job.attempt, "box-1").await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "credential expired");
    assert!(!status.message().contains(PAT));
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_server_without_credentials_configured_refuses(pool: PgPool) {
    let mut w = world_with(pool, false).await;
    let job = w.running(w.alice, "claude", "k1").await;
    let status = w.fetch(&job, job.attempt, "box-1").await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "credentials are not configured");
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
        .release_for_job(&job.job_id, job.attempt, "box-1")
        .await
        .unwrap();
    assert_eq!(released.len(), 2);
    for text in [format!("{released:?}"), format!("{released:#?}")] {
        assert!(!text.contains(ANT) && !text.contains(PAT), "{text}");
        assert!(text.contains("ReleasedCredential"), "{text}");
    }
}
