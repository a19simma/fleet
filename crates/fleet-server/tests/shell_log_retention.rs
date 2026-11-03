//! The retention sweep prunes `job_shell_log_chunks` at the summary age, per table. The tests
//! need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_server::retention::{Policy, run_retention_once};
use fleet_server::store::Store;
use sqlx::PgPool;

const DAY: i64 = 24;
const TERMINAL: [&str; 4] = ["SUCCEEDED", "FAILED", "CANCELLED", "LOST"];

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

async fn job(
    pool: &PgPool,
    id: &str,
    state: &str,
    finished_hours_ago: Option<i64>,
    created_hours_ago: i64,
) {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, created_at, \
         finished_at) VALUES ($1, 'p', 'r', 'main', 'b', false, $2, \
         now() - make_interval(hours => $4), now() - make_interval(hours => $3))",
    )
    .bind(id)
    .bind(state)
    .bind(finished_hours_ago.map(|h| i32::try_from(h).unwrap()))
    .bind(i32::try_from(created_hours_ago).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn chunks(pool: &PgPool, id: &str) {
    sqlx::query(
        "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
         SELECT $1, c, s, 'x'::bytea, 'running' FROM unnest(ARRAY['c1', 'c2']) c, \
         generate_series(0, 2) s",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
}

async fn chunks_of(pool: &PgPool, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM job_shell_log_chunks WHERE job_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn aged_terminal_chunks_are_pruned_and_young_ones_kept(pool: PgPool) {
    let store = store(pool.clone()).await;
    for state in TERMINAL {
        let old = format!("old-{state}");
        let young = format!("young-{state}");
        job(&pool, &old, state, Some(365 * DAY + 1), 500 * DAY).await;
        job(&pool, &young, state, Some(365 * DAY - 1), 500 * DAY).await;
        chunks(&pool, &old).await;
        chunks(&pool, &young).await;
    }
    job(&pool, "null-old", "LOST", None, 400 * DAY).await;
    job(&pool, "null-young", "LOST", None, 300 * DAY).await;
    chunks(&pool, "null-old").await;
    chunks(&pool, "null-young").await;
    run_retention_once(&store, &Policy::default()).await;
    for state in TERMINAL {
        assert_eq!(
            chunks_of(&pool, &format!("old-{state}")).await,
            0,
            "{state}"
        );
        assert_eq!(
            chunks_of(&pool, &format!("young-{state}")).await,
            6,
            "{state}"
        );
    }
    assert_eq!(chunks_of(&pool, "null-old").await, 0);
    assert_eq!(chunks_of(&pool, "null-young").await, 6);
}

#[sqlx::test]
async fn running_and_queued_chunks_are_never_pruned(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "run", "RUNNING", None, 1000 * DAY).await;
    job(&pool, "runf", "RUNNING", Some(1000 * DAY), 1000 * DAY).await;
    job(&pool, "queue", "QUEUED", None, 1000 * DAY).await;
    for id in ["run", "runf", "queue"] {
        chunks(&pool, id).await;
    }
    run_retention_once(&store, &Policy::default()).await;
    for id in ["run", "runf", "queue"] {
        assert_eq!(chunks_of(&pool, id).await, 6, "{id}");
    }
}

#[sqlx::test]
async fn chunks_are_pruned_without_a_summary_row(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "gone", "SUCCEEDED", Some(400 * DAY), 400 * DAY).await;
    chunks(&pool, "gone").await;
    let summaries: i64 = sqlx::query_scalar("SELECT count(*) FROM job_summary")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(summaries, 0);
    let stats = run_retention_once(&store, &Policy::default()).await;
    assert_eq!(stats.summaries_deleted, 0);
    assert_eq!(chunks_of(&pool, "gone").await, 0);
}
