//! A credential kind that needs a capability is refused at put and at release without the grant,
//! and a revoke refuses a release that follows. The tests inject the gate because the
//! API refuses `github_app` at put before the store runs: they gate `github_pat` (and in one
//! test `anthropic_api_key`) on `forge:github_app` instead. They need a Postgres superuser URL
//! in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;

use fleet_core::capability::Capability;
use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_proto::v1::PutCredentialRequest;
use fleet_server::cred::CredentialService;
use fleet_server::cred::FileSealer;
use fleet_server::cred::capability::Capabilities;
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::{CredentialStore, StoreError, required_capability};
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::Code;

const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const STATIC: CredentialShape = CredentialShape::StaticSecret;
const CAP: &str = "forge:github_app";

fn gate(kind: CredentialKind) -> Option<Capability> {
    (kind == CredentialKind::GithubPat).then_some(Capability::ForgeGithubApp)
}

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Unavailable)
    }
}

struct World {
    pool: PgPool,
    creds: CredentialStore,
    caps: Capabilities,
    alice: i64,
    admin: i64,
}

async fn user(pool: &PgPool, name: &str, admin: bool) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(admin)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world(pool: PgPool, tag: &str) -> World {
    Store::new(pool.clone()).migrate().await.unwrap();
    let path =
        std::env::temp_dir().join(format!("fleet-cred-gate-{}-{tag}.keys", std::process::id()));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let creds =
        CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap())).with_capability_gate(gate);
    World {
        caps: Capabilities::new(pool.clone()),
        alice: user(&pool, "alice", false).await,
        admin: user(&pool, "root", true).await,
        creds,
        pool,
    }
}

impl World {
    async fn put(&self, kind: CredentialKind, value: &str) -> Result<(), StoreError> {
        self.creds
            .put(
                self.alice,
                kind,
                STATIC,
                Secret::new(value.into()),
                None,
                None,
            )
            .await
            .map(|_| ())
    }

    async fn running_job(&self) -> (String, u32) {
        let job = "01JJOBGATE0000000000000000";
        sqlx::query(
            "INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr, state, attempt, box, \
             lease_expires_at, user_id, agent) \
             VALUES ($1, 'k', 'p', 'o/r', 'main', 'b', false, 'RUNNING', 1, 'alpha', now() + interval '1 hour', $2, 'claude')",
        )
        .bind(job)
        .bind(self.alice)
        .execute(&self.pool)
        .await
        .unwrap();
        (job.to_owned(), 1_u32)
    }

    async fn count(&self, table: &'static str) -> i64 {
        let sql = match table {
            "credentials" => "SELECT count(*) FROM credentials",
            _ => "SELECT count(*) FROM credential_use",
        };
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }
}

#[sqlx::test]
async fn put_without_the_grant_is_refused_and_writes_no_row(pool: PgPool) {
    let w = world(pool, "put").await;
    let err = w.put(CredentialKind::GithubPat, PAT).await.unwrap_err();
    assert!(matches!(err, StoreError::CapabilityDenied), "{err:?}");
    assert_eq!(w.count("credentials").await, 0);
}

#[sqlx::test]
async fn put_with_the_grant_succeeds(pool: PgPool) {
    let w = world(pool, "put-ok").await;
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    w.put(CredentialKind::GithubPat, PAT).await.unwrap();
    assert_eq!(w.count("credentials").await, 1);
}

#[sqlx::test]
async fn an_ungated_kind_needs_no_grant(pool: PgPool) {
    let w = world(pool, "ungated").await;
    w.put(CredentialKind::AnthropicApiKey, ANT).await.unwrap();
    assert_eq!(w.count("credentials").await, 1);
}

#[sqlx::test]
async fn release_without_the_grant_is_refused_and_writes_no_use_row(pool: PgPool) {
    let w = world(pool, "rel").await;
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    w.put(CredentialKind::GithubPat, PAT).await.unwrap();
    w.put(CredentialKind::AnthropicApiKey, ANT).await.unwrap();
    w.caps.revoke(w.admin, w.alice, CAP).await.unwrap();
    let (job, attempt) = w.running_job().await;
    let err = w
        .creds
        .release_for_job(&job, attempt, "alpha")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::CapabilityDenied), "{err:?}");
    assert_eq!(w.count("credential_use").await, 0);
}

#[sqlx::test]
async fn release_with_the_grant_succeeds_and_revoke_then_refuses(pool: PgPool) {
    let w = world(pool, "rel-ok").await;
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    w.put(CredentialKind::GithubPat, PAT).await.unwrap();
    w.put(CredentialKind::AnthropicApiKey, ANT).await.unwrap();
    let (job, attempt) = w.running_job().await;
    let released = w
        .creds
        .release_for_job(&job, attempt, "alpha")
        .await
        .unwrap();
    assert_eq!(released.len(), 2);
    assert_eq!(w.count("credential_use").await, 2);
    w.caps.revoke(w.admin, w.alice, CAP).await.unwrap();
    let err = w
        .creds
        .release_for_job(&job, attempt, "alpha")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::CapabilityDenied), "{err:?}");
    assert_eq!(w.count("credential_use").await, 2);
}

fn gate_anthropic(kind: CredentialKind) -> Option<Capability> {
    (kind == CredentialKind::AnthropicApiKey).then_some(Capability::ForgeGithubApp)
}

#[sqlx::test]
async fn the_service_maps_a_denied_put_and_release_to_permission_denied(pool: PgPool) {
    let w = world(pool, "svc").await;
    let put_service = CredentialService::new(
        w.creds.clone().with_capability_gate(gate_anthropic),
        Arc::new(NoGithub),
    );
    let err = put_service
        .put(
            w.alice,
            PutCredentialRequest {
                kind: CredentialKind::AnthropicApiKey.wire_name().to_owned(),
                shape: STATIC.wire_name().to_owned(),
                value: ANT.to_owned(),
                expires_at_ms: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(w.count("credentials").await, 0);
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    w.put(CredentialKind::GithubPat, PAT).await.unwrap();
    w.put(CredentialKind::AnthropicApiKey, ANT).await.unwrap();
    w.caps.revoke(w.admin, w.alice, CAP).await.unwrap();
    let service = CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let (job, attempt) = w.running_job().await;
    let err = service
        .job_credentials(&job, attempt, "alpha")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.message(),
        fleet_server::cred::capability::ERR_CAPABILITY_NOT_GRANTED
    );
}

#[test]
fn the_production_gate_requires_the_capability_for_github_app_only() {
    for kind in CredentialKind::ALL {
        let expected = (kind == CredentialKind::GithubApp).then_some(Capability::ForgeGithubApp);
        assert_eq!(required_capability(kind), expected, "{kind:?}");
    }
}
