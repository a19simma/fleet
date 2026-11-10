//! `submit_job` environment pin (ADR-0067 decisions 4, 10 and 11): the pin taken at submit,
//! the unknown-name reply, the `env:scripts` recheck, idempotency and the hostile-name table.
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because they bind sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fleet_core::environment::{
    Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec, SecretSpec,
};
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::{Job, SubmitJobRequest};
use fleet_proto::{ERR_ENV_NOT_FOUND, ERR_ENV_SCRIPTS_NOT_GRANTED};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{EnvironmentService, EnvironmentStore};
use fleet_server::profiles::{self, ProfileContent};
use fleet_server::service::router_with_environments;
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const REPO: &str = "https://example.com/org/repo.git";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-env-submit-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

fn envs(pool: &PgPool) -> EnvironmentStore {
    EnvironmentStore::new(pool.clone(), Arc::new(sealer()))
}

async fn user(pool: &PgPool, name: &str, scripts: bool) -> i64 {
    let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
    if scripts {
        sqlx::query(
            "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, 'env:scripts', $1)",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }
    id
}

fn secret(name: &str) -> Entry {
    Entry::Secret(SecretSpec::with_defaults(EntryName::new(name).unwrap()))
}

fn script(name: &str) -> Entry {
    Entry::Script(ScriptSpec::with_defaults(
        EntryName::new(name).unwrap(),
        ScriptBody::new(SHEBANG).unwrap(),
    ))
}

async fn environment(pool: &PgPool, owner: i64, name: &str, entries: Vec<Entry>) -> (i64, i32) {
    let store = envs(pool);
    let id = store
        .create_environment(owner, &EnvironmentName::new(name).unwrap())
        .await
        .unwrap();
    let saved = store
        .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
        .await
        .unwrap();
    (id, saved.version)
}

fn request(key: &str, environment: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
        agent: String::new(),
        profile: String::new(),
        environment: environment.to_owned(),
    }
}

async fn core(pool: &PgPool) -> Store {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    store
}

async fn pin_of(pool: &PgPool, key: &str) -> (Option<i64>, Option<i32>) {
    sqlx::query_as(
        "SELECT environment_id, environment_version FROM jobs WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn job_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn save(pool: &PgPool, owner: i64, id: i64, entries: Vec<Entry>) -> i32 {
    envs(pool)
        .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
        .await
        .unwrap()
        .version
}

#[sqlx::test]
async fn a_submit_pins_the_latest_version_and_a_later_version_does_not_move_it(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, one) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let job = store
        .submit_job_for(Some(alice), &request("k1", "prod"))
        .await
        .unwrap();
    assert!(job.has_environment);
    assert_eq!(pin_of(&pool, "k1").await, (Some(id), Some(one)));
    let two = save(&pool, alice, id, vec![secret("TOKEN"), secret("OTHER")]).await;
    assert_eq!(two, one + 1);
    assert_eq!(pin_of(&pool, "k1").await, (Some(id), Some(one)));
    store
        .submit_job_for(Some(alice), &request("k2", "PROD"))
        .await
        .unwrap();
    assert_eq!(pin_of(&pool, "k2").await, (Some(id), Some(two)));
}

#[sqlx::test]
async fn a_profile_and_an_environment_pin_together(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, version) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    profiles::create_owned(
        &pool,
        Some(alice),
        None,
        "alpha",
        ProfileContent::Json(r#"{"claude_md":"x"}"#),
    )
    .await
    .unwrap();
    let job = store
        .submit_job_for(
            Some(alice),
            &SubmitJobRequest {
                profile: "alpha".to_owned(),
                ..request("both", "prod")
            },
        )
        .await
        .unwrap();
    assert!(job.has_environment);
    assert_eq!(job.profile.map(|p| p.name), Some("alpha".to_owned()));
    assert_eq!(pin_of(&pool, "both").await, (Some(id), Some(version)));
}

#[sqlx::test]
async fn no_environment_and_the_dash_pin_nothing(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    for (key, name) in [("plain", ""), ("dash", "-")] {
        let job = store
            .submit_job_for(Some(alice), &request(key, name))
            .await
            .unwrap();
        assert!(!job.has_environment, "{key}");
        assert_eq!(pin_of(&pool, key).await, (None, None), "{key}");
    }
}

#[sqlx::test]
async fn a_secrets_only_environment_passes_without_the_capability(pool: PgPool) {
    let store = core(&pool).await;
    let bob = user(&pool, "bob", false).await;
    let (id, version) = environment(&pool, bob, "plain", vec![secret("TOKEN")]).await;
    store
        .submit_job_for(Some(bob), &request("k", "plain"))
        .await
        .unwrap();
    assert_eq!(pin_of(&pool, "k").await, (Some(id), Some(version)));
}

#[sqlx::test]
async fn scripts_with_the_capability_revoked_refuse_and_leave_no_job_row(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", true).await;
    environment(&pool, alice, "scripted", vec![script("setup")]).await;
    store
        .submit_job_for(Some(alice), &request("granted", "scripted"))
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let before = job_rows(&pool).await;
    let err = store
        .submit_job_for(Some(alice), &request("revoked", "scripted"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::EnvironmentScriptsNotGranted),
        "{err}"
    );
    assert_eq!(job_rows(&pool).await, before);
}

#[sqlx::test]
async fn a_submit_waits_for_a_revoke_in_flight_and_then_refuses(pool: PgPool) {
    let store = Arc::new(core(&pool).await);
    let alice = user(&pool, "alice", true).await;
    environment(&pool, alice, "scripted", vec![script("setup")]).await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1 AND capability = 'env:scripts'")
        .bind(alice)
        .execute(&mut *holder)
        .await
        .unwrap();
    let submitter = store.clone();
    let task = tokio::spawn(async move {
        submitter
            .submit_job_for(Some(alice), &request("race", "scripted"))
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query LIKE '%FROM user_capabilities%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the submit never waited on the grant row"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(job_rows(&pool).await, 0);
    holder.commit().await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(got, Err(StoreError::EnvironmentScriptsNotGranted)),
        "{got:?}"
    );
    assert_eq!(job_rows(&pool).await, 0);
}

#[sqlx::test]
async fn a_resubmit_of_the_same_environment_is_equal_and_another_one_conflicts(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, _) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    environment(&pool, alice, "stage", vec![secret("TOKEN")]).await;
    let first = store
        .submit_job_for(Some(alice), &request("k", "prod"))
        .await
        .unwrap();
    let again = store
        .submit_job_for(Some(alice), &request("k", "Prod"))
        .await
        .unwrap();
    assert_eq!(first, again);
    for other in ["stage", "-", "", "ghost"] {
        let err = store
            .submit_job_for(Some(alice), &request("k", other))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::KeyConflict), "{other}: {err}");
    }
    store
        .submit_job_for(Some(alice), &request("plain", ""))
        .await
        .unwrap();
    let err = store
        .submit_job_for(Some(alice), &request("plain", "prod"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict), "{err}");
    save(&pool, alice, id, vec![secret("TOKEN"), secret("OTHER")]).await;
    let err = store
        .submit_job_for(Some(alice), &request("k", "prod"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict), "{err}");
}

#[sqlx::test]
async fn a_judge_job_never_carries_a_pin(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let target = store
        .submit_job_for(Some(alice), &request("t", "prod"))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&target.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let judge = store
        .submit_judge_for(
            Some(alice),
            &fleet_proto::v1::SubmitJudgeRequest {
                idempotency_key: "j".to_owned(),
                prompt: "grade it".to_owned(),
                target_job_id: target.job_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(!judge.has_environment);
    assert_eq!(pin_of(&pool, "j").await, (None, None));
}

#[sqlx::test]
async fn the_legacy_owner_cannot_name_an_environment(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let err = store.submit_job(&request("k", "prod")).await.unwrap_err();
    assert!(matches!(err, StoreError::UnknownEnvironment), "{err}");
    assert_eq!(job_rows(&pool).await, 0);
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    users: Users,
}

async fn rig(pool: PgPool) -> Rig {
    let core = core(&pool).await;
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let service = EnvironmentService::new(envs(&pool));
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with_environments(&core, &auth, None, Some(service)).serve_with_incoming(incoming),
    );
    Rig { addr, pool, users }
}

impl Rig {
    async fn submit(&self, owner: i64, key: &str, environment: &str) -> Result<Job, Status> {
        let made = self.users.create_api_token(owner, "t").await.unwrap();
        let token = String::from_utf8(made.token.expose().to_vec()).unwrap();
        let channel: Channel = Endpoint::from_shared(format!("http://{}", self.addr))
            .unwrap()
            .connect_lazy();
        let mut call = Request::new(request(key, environment));
        call.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
        );
        FleetJobsClient::new(channel)
            .submit_job(call)
            .await
            .map(tonic::Response::into_inner)
    }
}

fn same_status(left: &Status, right: &Status, cause: &str) {
    assert_eq!(left.code(), right.code(), "{cause}");
    assert_eq!(left.message(), right.message(), "{cause}");
    assert_eq!(left.details(), right.details(), "{cause}");
    assert_eq!(
        left.metadata().clone().into_headers(),
        right.metadata().clone().into_headers(),
        "{cause}"
    );
}

#[sqlx::test]
async fn unknown_and_foreign_names_get_one_byte_identical_reply(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    let bob = user(&rig.pool, "bob", false).await;
    environment(&rig.pool, alice, "alice-env", vec![secret("TOKEN")]).await;
    let foreign = rig.submit(bob, "f", "alice-env").await.unwrap_err();
    let unknown = rig.submit(bob, "u", "ghost").await.unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(foreign.message(), ERR_ENV_NOT_FOUND);
    same_status(&foreign, &unknown, "foreign against unknown");
    assert_eq!(job_rows(&rig.pool).await, 0);
}

#[sqlx::test]
async fn a_revoked_scripts_submit_gets_the_fixed_refusal_over_rpc(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", true).await;
    environment(&rig.pool, alice, "scripted", vec![script("setup")]).await;
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&rig.pool)
        .await
        .unwrap();
    let refused = rig.submit(alice, "k", "scripted").await.unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied);
    assert_eq!(refused.message(), ERR_ENV_SCRIPTS_NOT_GRANTED);
    assert_eq!(job_rows(&rig.pool).await, 0);
}

#[sqlx::test]
async fn hostile_environment_names_are_refused_before_any_write(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    environment(&rig.pool, alice, "prod", vec![secret("TOKEN")]).await;
    let long = "a".repeat(65);
    let table: Vec<(&str, String)> = vec![
        ("cr", "prod\r".to_owned()),
        ("crlf", "prod\r\n".to_owned()),
        ("lf", "prod\n".to_owned()),
        ("nel", "prod\u{85}".to_owned()),
        ("line separator", "prod\u{2028}".to_owned()),
        ("paragraph separator", "prod\u{2029}".to_owned()),
        ("bidi override", "pr\u{202e}od".to_owned()),
        ("bidi isolate", "\u{2066}prod".to_owned()),
        ("nul", "prod\0".to_owned()),
        ("space", "prod ".to_owned()),
        ("leading space", " prod".to_owned()),
        ("tab", "pr\tod".to_owned()),
        ("non-ascii", "prod\u{e9}".to_owned()),
        ("fullwidth", "\u{ff50}rod".to_owned()),
        ("kelvin", "\u{212a}".to_owned()),
        ("dot start", ".prod".to_owned()),
        ("dash start", "-prod".to_owned()),
        ("slash", "a/b".to_owned()),
        ("backslash", "a\\b".to_owned()),
        ("dot dot", "..".to_owned()),
        ("over long", long),
        ("percent", "pr%6fd".to_owned()),
    ];
    for (label, name) in table {
        let status = rig.submit(alice, "k", &name).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{label}");
        assert_eq!(status.message(), "invalid job request", "{label}");
        assert_eq!(job_rows(&rig.pool).await, 0, "{label}");
    }
    rig.submit(alice, "ok", &"a".repeat(64)).await.unwrap_err();
    rig.submit(alice, "ok2", "prod").await.unwrap();
}
