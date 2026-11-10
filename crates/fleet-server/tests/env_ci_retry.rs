//! The Environment pin on a CI retry Job (ADR-0067 decision 11): the fix Job inherits the pin of
//! the Job it fixes, never the latest version, and the server refuses the retry with the fixed
//! `env_unavailable` outcome when the pinned scripts lost `env:scripts` or the Environment is
//! gone. The tests need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fleet_core::BoxName;
use fleet_core::environment::{
    Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec, SecretSpec,
};
use fleet_proto::v1::{CiRetry, CiState, Job, JobCi, JobState, ReportJobRequest, SubmitJobRequest};
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::EnvironmentStore;
use fleet_server::store::Store;
use sqlx::PgPool;

const REPO: &str = "https://example.com/org/repo.git";
const PR: &str = "https://example.com/org/repo/pull/7";
const LOG: &str = "step one\nerror: it broke\n";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn boxed() -> BoxName {
    BoxName::new(&format!("box-{}", 1)).unwrap()
}

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-env-retry-{}-{}.keys",
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

async fn store(pool: &PgPool) -> Store {
    let store = Store::new(pool.clone()).with_max_ci_retries(3);
    store.migrate().await.unwrap();
    store
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

async fn save(pool: &PgPool, owner: i64, id: i64, entries: Vec<Entry>) -> i32 {
    envs(pool)
        .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
        .await
        .unwrap()
        .version
}

fn submit(key: &str, environment: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "do it".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: true,
        agent: String::new(),
        profile: String::new(),
        environment: environment.to_owned(),
    }
}

fn failing(job: &Job) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job.job_id.clone(),
        attempt: job.attempt,
        r#box: boxed().as_str().to_owned(),
        terminal_state: Some(JobState::Succeeded as i32),
        pr_url: Some(PR.to_owned()),
        branch: job.branch.clone(),
        ci: Some(JobCi {
            state: CiState::Failure as i32,
            url: None,
            failure_log: Some(LOG.to_owned()),
        }),
        ..ReportJobRequest::default()
    }
}

async fn running(store: &Store, owner: i64, key: &str, environment: &str) -> Job {
    store
        .submit_job_for(Some(owner), &submit(key, environment))
        .await
        .unwrap();
    store.claim_job(&boxed()).await.unwrap().unwrap()
}

async fn pin_of_job(pool: &PgPool, job_id: &str) -> (Option<i64>, Option<i32>) {
    sqlx::query_as("SELECT environment_id, environment_version FROM jobs WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn child_of(pool: &PgPool, parent: &str) -> Option<String> {
    sqlx::query_scalar("SELECT job_id FROM jobs WHERE parent_job_id = $1")
        .bind(parent)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn total(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn outcome(store: &Store, job: &Job) -> Option<CiRetry> {
    store
        .get_job(&job.job_id)
        .await
        .unwrap()
        .ci_retry
        .map(|raw| CiRetry::try_from(raw).unwrap())
}

async fn revoke(pool: &PgPool, user_id: i64) {
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_retry_inherits_the_parent_pin_and_a_later_version_does_not_move_it(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, one) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let parent = running(&store, alice, "root", "prod").await;
    let two = save(&pool, alice, id, vec![secret("TOKEN"), secret("OTHER")]).await;
    assert_eq!(two, one + 1);
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    assert_eq!(outcome(&store, &parent).await, Some(CiRetry::Submitted));
    let child = child_of(&pool, &parent.job_id).await.unwrap();
    assert_eq!(pin_of_job(&pool, &child).await, (Some(id), Some(one)));
    let fix = store.get_job(&child).await.unwrap();
    assert!(fix.has_environment);
}

#[sqlx::test]
async fn a_second_retry_inherits_the_same_pin(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, one) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let parent = running(&store, alice, "root", "prod").await;
    save(&pool, alice, id, vec![secret("TOKEN"), secret("OTHER")]).await;
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    let first = store.claim_job(&boxed()).await.unwrap().unwrap();
    store.report_job(&boxed(), &failing(&first)).await.unwrap();
    let second = child_of(&pool, &first.job_id).await.unwrap();
    assert_eq!(pin_of_job(&pool, &second).await, (Some(id), Some(one)));
}

#[sqlx::test]
async fn a_parent_without_a_pin_gives_a_retry_without_one(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", false).await;
    environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let parent = running(&store, alice, "root", "-").await;
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    assert_eq!(outcome(&store, &parent).await, Some(CiRetry::Submitted));
    let child = child_of(&pool, &parent.job_id).await.unwrap();
    assert_eq!(pin_of_job(&pool, &child).await, (None, None));
}

#[sqlx::test]
async fn a_secrets_only_pin_retries_without_the_capability(pool: PgPool) {
    let store = store(&pool).await;
    let bob = user(&pool, "bob", false).await;
    let (id, version) = environment(&pool, bob, "plain", vec![secret("TOKEN")]).await;
    let parent = running(&store, bob, "root", "plain").await;
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    let child = child_of(&pool, &parent.job_id).await.unwrap();
    assert_eq!(pin_of_job(&pool, &child).await, (Some(id), Some(version)));
}

#[sqlx::test]
async fn a_scripted_pin_with_the_capability_kept_retries(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", true).await;
    let (id, version) = environment(&pool, alice, "scripted", vec![script("setup")]).await;
    let parent = running(&store, alice, "root", "scripted").await;
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    assert_eq!(outcome(&store, &parent).await, Some(CiRetry::Submitted));
    let child = child_of(&pool, &parent.job_id).await.unwrap();
    assert_eq!(pin_of_job(&pool, &child).await, (Some(id), Some(version)));
}

#[sqlx::test]
async fn a_revoked_capability_refuses_the_retry_and_writes_no_job_row(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", true).await;
    environment(&pool, alice, "scripted", vec![script("setup")]).await;
    let parent = running(&store, alice, "root", "scripted").await;
    revoke(&pool, alice).await;
    let before = total(&pool).await;
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    assert_eq!(
        outcome(&store, &parent).await,
        Some(CiRetry::EnvUnavailable)
    );
    assert_eq!(child_of(&pool, &parent.job_id).await, None);
    assert_eq!(total(&pool).await, before);
}

#[sqlx::test]
async fn a_deleted_environment_refuses_the_retry_and_writes_no_job_row(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, _) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let parent = running(&store, alice, "root", "prod").await;
    envs(&pool).delete_environment(alice, id).await.unwrap();
    let before = total(&pool).await;
    store.report_job(&boxed(), &failing(&parent)).await.unwrap();
    assert_eq!(
        outcome(&store, &parent).await,
        Some(CiRetry::EnvUnavailable)
    );
    assert_eq!(child_of(&pool, &parent.job_id).await, None);
    assert_eq!(total(&pool).await, before);
}

#[sqlx::test]
async fn a_retry_waits_for_a_revoke_in_flight_and_then_refuses(pool: PgPool) {
    let store = Arc::new(store(&pool).await);
    let alice = user(&pool, "alice", true).await;
    environment(&pool, alice, "scripted", vec![script("setup")]).await;
    let parent = running(&store, alice, "root", "scripted").await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1 AND capability = 'env:scripts'")
        .bind(alice)
        .execute(&mut *holder)
        .await
        .unwrap();
    let reporter = store.clone();
    let report = failing(&parent);
    let task = tokio::spawn(async move { reporter.report_job(&boxed(), &report).await });
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
            "the retry never waited on the grant row"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(child_of(&pool, &parent.job_id).await, None);
    holder.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        outcome(&store, &parent).await,
        Some(CiRetry::EnvUnavailable)
    );
    assert_eq!(child_of(&pool, &parent.job_id).await, None);
}

#[sqlx::test]
async fn a_judge_of_a_pinned_job_carries_no_pin(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice", false).await;
    environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let parent = running(&store, alice, "root", "prod").await;
    store
        .report_job(
            &boxed(),
            &ReportJobRequest {
                ci: None,
                ..failing(&parent)
            },
        )
        .await
        .unwrap();
    let judge = store
        .submit_judge_for(
            Some(alice),
            &fleet_proto::v1::SubmitJudgeRequest {
                idempotency_key: "j".to_owned(),
                prompt: "grade it".to_owned(),
                target_job_id: parent.job_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(!judge.has_environment);
    assert_eq!(pin_of_job(&pool, &judge.job_id).await, (None, None));
}
