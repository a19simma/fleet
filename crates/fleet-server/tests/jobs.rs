//! Job store tests. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_proto::v1::{JobState, SubmitJobRequest};
use fleet_server::jobs::{MAX_BASE_REF_BYTES, MAX_KEY_BYTES, MAX_PROMPT_BYTES, MAX_REPO_BYTES};
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(30);

fn request(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: "https://example.com/org/repo.git".to_owned(),
        base_ref: "main".to_owned(),
        open_pr: true,
    }
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

async fn job_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn submit_is_idempotent(pool: PgPool) {
    let store = store(pool.clone()).await;
    let first = timeout(WAIT, store.submit_job(&request("k1")))
        .await
        .unwrap()
        .unwrap();
    let again = timeout(WAIT, store.submit_job(&request("k1")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(first.prompt, "add hello.txt");
    assert_eq!(first.job_id.len(), 26);
    assert!(first.job_id.parse::<fleet_core::EventId>().is_ok());
    assert_eq!(first.state, i32::from(JobState::Queued));
    assert_eq!(
        first.branch.as_deref(),
        Some(format!("swarm/{}", first.job_id).as_str())
    );
    assert_eq!(job_rows(&pool).await, 1);
    let other = store.submit_job(&request("k2")).await.unwrap();
    assert_ne!(other.job_id, first.job_id);
    assert_eq!(job_rows(&pool).await, 2);
}

#[sqlx::test]
async fn different_prompt_is_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let first = store.submit_job(&request("k1")).await.unwrap();
    let mut changed = request("k1");
    "other secret".clone_into(&mut changed.prompt);
    let err = timeout(WAIT, store.submit_job(&changed))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict));
    assert!(!format!("{err} {err:?}").contains("secret"));
    let stored = store.submit_job(&request("k1")).await.unwrap();
    assert_eq!(stored, first);
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn each_other_field_mismatch_is_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    store.submit_job(&request("k1")).await.unwrap();
    let edits: [fn(&mut SubmitJobRequest); 3] = [
        |r| "https://example.com/org/other.git".clone_into(&mut r.repo),
        |r| "dev".clone_into(&mut r.base_ref),
        |r| r.open_pr = !r.open_pr,
    ];
    for edit in edits {
        let mut changed = request("k1");
        edit(&mut changed);
        let err = store.submit_job(&changed).await.unwrap_err();
        assert!(matches!(err, StoreError::KeyConflict));
    }
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn concurrent_submits_with_other_params_yield_one_winner(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut tasks = Vec::new();
    for i in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let mut r = request("race");
            r.prompt = format!("prompt {i}");
            store.submit_job(&r).await
        }));
    }
    let mut won = 0;
    let mut conflicts = 0;
    for task in tasks {
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Ok(_) => won += 1,
            Err(StoreError::KeyConflict) => conflicts += 1,
            Err(other) => panic!("unexpected {other}"),
        }
    }
    assert_eq!(won, 1);
    assert_eq!(conflicts, 15);
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn concurrent_submits_create_one_job(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.submit_job(&request("same")).await
        }));
    }
    let mut ids = Vec::new();
    for task in tasks {
        let job = timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        ids.push(job.job_id);
    }
    ids.dedup();
    assert_eq!(ids.len(), 1);
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn missing_key_is_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let err = store.submit_job(&request("")).await.unwrap_err();
    assert!(matches!(err, StoreError::InvalidJob(_)));
    assert_eq!(err.to_string(), "invalid idempotency key");
    assert_eq!(job_rows(&pool).await, 0);
}

#[sqlx::test]
async fn invalid_input_is_rejected_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let secret = "s3cret-token";
    let long = |n: usize| "a".repeat(n + 1);
    let mut cases = Vec::new();
    let mut with = |label: &str, edit: &dyn Fn(&mut SubmitJobRequest)| {
        let mut r = request("k");
        edit(&mut r);
        cases.push((label.to_owned(), r));
    };
    with("key long", &|r| r.idempotency_key = long(MAX_KEY_BYTES));
    with("key space", &|r| r.idempotency_key = format!("a {secret}"));
    with("key nul", &|r| r.idempotency_key = format!("a\0{secret}"));
    with("prompt empty", &|r| r.prompt = "  ".into());
    with("prompt long", &|r| r.prompt = long(MAX_PROMPT_BYTES));
    with("prompt nul", &|r| r.prompt = format!("a\0{secret}"));
    with("repo http", &|r| r.repo = format!("http://x/{secret}"));
    with("repo bare scheme", &|r| r.repo = "https://".into());
    with("repo userinfo", &|r| {
        r.repo = format!("https://user:{secret}@example.com/org/repo.git");
    });
    with("repo token userinfo", &|r| {
        r.repo = format!("https://{secret}@example.com/org/repo.git");
    });
    with("repo space", &|r| r.repo = format!("https://x/a {secret}"));
    with("repo long", &|r| {
        r.repo = format!("https://{}", long(MAX_REPO_BYTES));
    });
    with("ref empty", &|r| r.base_ref = String::new());
    with("ref long", &|r| r.base_ref = long(MAX_BASE_REF_BYTES));
    with("ref newline", &|r| r.base_ref = format!("a\n{secret}"));
    for (label, case) in cases {
        let err = store.submit_job(&case).await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidJob(_)), "{label}");
        let text = format!("{err} {err:?}");
        assert!(!text.contains(secret), "{label} echoed input");
    }
    assert_eq!(job_rows(&pool).await, 0);
}

#[sqlx::test]
async fn boundary_sizes_are_accepted(pool: PgPool) {
    let store = store(pool).await;
    let mut r = request(&"k".repeat(MAX_KEY_BYTES));
    r.prompt = "p".repeat(MAX_PROMPT_BYTES);
    r.base_ref = "b".repeat(MAX_BASE_REF_BYTES);
    r.open_pr = false;
    let job = store.submit_job(&r).await.unwrap();
    assert!(!job.open_pr);
    assert_eq!(job.prompt.len(), MAX_PROMPT_BYTES);
}

fn claimer(n: u32) -> String {
    format!("box-{n}")
}

async fn submit_n(store: &Store, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..n {
        let job = store.submit_job(&request(&format!("k{i}"))).await.unwrap();
        ids.push(job.job_id);
    }
    ids
}

#[sqlx::test]
async fn concurrent_claims_are_exclusive(pool: PgPool) {
    let store = store(pool).await;
    let jobs = 12;
    let mut expected = submit_n(&store, jobs).await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.claim_job(&claimer(i % 4 + 1)).await
        }));
    }
    let mut claimed = Vec::new();
    let mut empty = 0;
    for task in tasks {
        match timeout(WAIT, task).await.unwrap().unwrap().unwrap() {
            Some(job) => {
                assert_eq!(job.state, i32::from(JobState::Running));
                assert_eq!(job.attempt, 1);
                claimed.push(job.job_id);
            }
            None => empty += 1,
        }
    }
    claimed.sort();
    expected.sort();
    assert_eq!(claimed, expected);
    assert_eq!(empty, 12);
}

#[sqlx::test]
async fn claim_is_fifo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let ids = submit_n(&store, 3).await;
    let cancelled = store.submit_job(&request("late")).await.unwrap();
    sqlx::query("UPDATE jobs SET state = 'CANCELLED' WHERE job_id = $1")
        .bind(&cancelled.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut order = Vec::new();
    for _ in 0..=ids.len() {
        let claimed = timeout(WAIT, store.claim_job(&claimer(1)))
            .await
            .unwrap()
            .unwrap();
        order.extend(claimed.map(|job| job.job_id));
    }
    assert_eq!(order, ids);
    let left: String = sqlx::query_scalar("SELECT state FROM jobs WHERE job_id = $1")
        .bind(&cancelled.job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, "CANCELLED");
}

#[sqlx::test]
async fn claim_sets_lease_and_attempt(pool: PgPool) {
    let lease = Duration::from_secs(45);
    let store = store(pool.clone()).await.with_lease(lease);
    let queued = store.submit_job(&request("k")).await.unwrap();
    assert_eq!(queued.attempt, 0);
    assert_eq!(queued.lease_expires_at_ms, None);
    let job = timeout(WAIT, store.claim_job(&claimer(2)))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(job.job_id, queued.job_id);
    assert_eq!(job.state, i32::from(JobState::Running));
    assert_eq!(job.r#box, claimer(2));
    assert_eq!(job.attempt, 1);
    let claimed = job.claimed_at_ms.unwrap();
    let expires = job.lease_expires_at_ms.unwrap();
    assert_eq!(expires - claimed, 45_000);
    assert!(claimed >= job.created_at_ms);
    let default = Store::new(pool.clone());
    default.submit_job(&request("k2")).await.unwrap();
    let second = default.claim_job(&claimer(2)).await.unwrap().unwrap();
    assert_eq!(
        second.lease_expires_at_ms.unwrap() - second.claimed_at_ms.unwrap(),
        120_000
    );
}

#[sqlx::test]
async fn empty_queue_returns_none(pool: PgPool) {
    let store = store(pool.clone()).await;
    let first = timeout(WAIT, store.claim_job(&claimer(1)))
        .await
        .unwrap()
        .unwrap();
    assert!(first.is_none());
    submit_n(&store, 1).await;
    assert!(store.claim_job(&claimer(1)).await.unwrap().is_some());
    assert!(store.claim_job(&claimer(1)).await.unwrap().is_none());
}

#[sqlx::test]
async fn invalid_box_rejected_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    submit_n(&store, 1).await;
    let secret = "s3cret-token";
    for raw in [
        secret.to_owned(),
        String::new(),
        format!("{}\n{secret}", claimer(1)),
    ] {
        let err = store.claim_job(&raw).await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidBox));
        assert!(!format!("{err} {err:?}").contains(secret));
    }
    let state: String = sqlx::query_scalar("SELECT state FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "QUEUED");
}

async fn claimed(store: &Store, box_name: &str) -> fleet_proto::v1::Job {
    store.submit_job(&request("rk")).await.unwrap();
    store.claim_job(box_name).await.unwrap().unwrap()
}

async fn set_lease_in_past(pool: &PgPool) {
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 hour'")
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test]
async fn report_renews_lease(pool: PgPool) {
    let store = store(pool.clone())
        .await
        .with_lease(Duration::from_secs(45));
    let job = claimed(&store, &claimer(1)).await;
    set_lease_in_past(&pool).await;
    let reply = timeout(
        WAIT,
        store.report_job(&job.job_id, job.attempt, &claimer(1), "running", "step 2"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!reply.cancel_requested);
    let now: i64 = sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM now()) * 1000)::bigint")
        .fetch_one(&pool)
        .await
        .unwrap();
    let delta = i64::try_from(reply.lease_expires_at_ms).unwrap() - now;
    assert!((40_000..=45_000).contains(&delta), "delta {delta}");
    let (phase, progress, lease): (String, String, i64) = sqlx::query_as(
        "SELECT phase, progress, (EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint FROM jobs",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(phase, "running");
    assert_eq!(progress, "step 2");
    assert_eq!(lease, i64::try_from(reply.lease_expires_at_ms).unwrap());
    sqlx::query("UPDATE jobs SET cancel_requested = true")
        .execute(&pool)
        .await
        .unwrap();
    let again = store
        .report_job(&job.job_id, job.attempt, &claimer(1), "running", "step 3")
        .await
        .unwrap();
    assert!(again.cancel_requested);
}

#[sqlx::test]
async fn stale_attempt_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let secret = "s3cret-job";
    let cases = [
        (job.job_id.clone(), job.attempt + 1, claimer(1)),
        (job.job_id.clone(), job.attempt - 1, claimer(1)),
        (job.job_id.clone(), job.attempt, claimer(2)),
        (secret.to_owned(), job.attempt, claimer(1)),
    ];
    for (id, attempt, box_name) in cases {
        let err = store
            .report_job(&id, attempt, &box_name, "hijack", "hijack")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::StaleReport));
        assert!(!format!("{err} {err:?}").contains(secret));
    }
    let err = store
        .report_job(&job.job_id, job.attempt, secret, "x", "x")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidBox));
    for state in ["QUEUED", "SUCCEEDED", "LOST", "CANCELLED", "FAILED"] {
        sqlx::query("UPDATE jobs SET state = $1")
            .bind(state)
            .execute(&pool)
            .await
            .unwrap();
        let err = store
            .report_job(&job.job_id, job.attempt, &claimer(1), "late", "late")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::StaleReport), "{state}");
    }
    let (phase, progress): (String, String) = sqlx::query_as("SELECT phase, progress FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((phase.as_str(), progress.as_str()), ("", ""));
}
