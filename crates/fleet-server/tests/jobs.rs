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
