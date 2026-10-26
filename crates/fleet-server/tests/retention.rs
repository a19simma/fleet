//! Retention sweep. The tests need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_server::retention::{Policy, run_retention, run_retention_once};
use fleet_server::store::Store;
use sqlx::PgPool;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
const TERMINAL: [&str; 4] = ["SUCCEEDED", "FAILED", "CANCELLED", "LOST"];
const DAY: i64 = 24;

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
         now() - make_interval(hours => $4), \
         now() - make_interval(hours => $3))",
    )
    .bind(id)
    .bind(state)
    .bind(finished_hours_ago.map(|h| i32::try_from(h).unwrap()))
    .bind(i32::try_from(created_hours_ago).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn rows(pool: &PgPool, id: &str, events: i32, summary: bool) {
    for seq in 0..events {
        sqlx::query("INSERT INTO job_event (job_id, seq, ts_ms, kind) VALUES ($1, $2, 0, 'tool')")
            .bind(id)
            .bind(seq)
            .execute(pool)
            .await
            .unwrap();
    }
    if summary {
        sqlx::query("INSERT INTO job_summary (job_id, complete, missing) VALUES ($1, true, '{}')")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn events_of(pool: &PgPool, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM job_event WHERE job_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn has_summary(pool: &PgPool, id: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM job_summary WHERE job_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        == 1
}

async fn total_events(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM job_event")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn policy() -> Policy {
    Policy::default()
}

#[sqlx::test]
async fn events_are_pruned_at_the_ninety_day_boundary(pool: PgPool) {
    let store = store(pool.clone()).await;
    for state in TERMINAL {
        let inside = format!("in-{state}");
        let outside = format!("out-{state}");
        job(&pool, &inside, state, Some(90 * DAY - 1), 200 * DAY).await;
        job(&pool, &outside, state, Some(90 * DAY + 1), 200 * DAY).await;
        rows(&pool, &inside, 2, false).await;
        rows(&pool, &outside, 3, false).await;
    }
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.events_deleted, 12);
    assert_eq!(stats.error, None);
    for state in TERMINAL {
        assert_eq!(events_of(&pool, &format!("in-{state}")).await, 2);
        assert_eq!(events_of(&pool, &format!("out-{state}")).await, 0);
    }
}

#[sqlx::test]
async fn summaries_survive_events_and_go_after_a_year(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "mid", "SUCCEEDED", Some(200 * DAY), 300 * DAY).await;
    job(&pool, "kept", "FAILED", Some(365 * DAY - 1), 400 * DAY).await;
    job(&pool, "gone", "FAILED", Some(365 * DAY + 1), 400 * DAY).await;
    for id in ["mid", "kept", "gone"] {
        rows(&pool, id, 1, true).await;
    }
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.summaries_deleted, 1);
    assert_eq!(stats.events_deleted, 3);
    assert!(has_summary(&pool, "mid").await);
    assert!(has_summary(&pool, "kept").await);
    assert!(!has_summary(&pool, "gone").await);
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(jobs, 3);
}

#[sqlx::test]
async fn summaries_follow_the_same_state_and_fallback_rules(pool: PgPool) {
    let store = store(pool.clone()).await;
    for state in TERMINAL {
        let inside = format!("in-{state}");
        let outside = format!("out-{state}");
        job(&pool, &inside, state, Some(365 * DAY - 1), 500 * DAY).await;
        job(&pool, &outside, state, Some(365 * DAY + 1), 500 * DAY).await;
        rows(&pool, &inside, 0, true).await;
        rows(&pool, &outside, 0, true).await;
    }
    job(&pool, "null-old", "LOST", None, 400 * DAY).await;
    job(&pool, "null-young", "LOST", None, 300 * DAY).await;
    job(&pool, "fin-young", "LOST", Some(10 * DAY), 900 * DAY).await;
    for id in ["null-old", "null-young", "fin-young"] {
        rows(&pool, id, 0, true).await;
    }
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.summaries_deleted, 5);
    for state in TERMINAL {
        assert!(has_summary(&pool, &format!("in-{state}")).await);
        assert!(!has_summary(&pool, &format!("out-{state}")).await);
    }
    assert!(!has_summary(&pool, "null-old").await);
    assert!(has_summary(&pool, "null-young").await);
    assert!(has_summary(&pool, "fin-young").await);
}

#[sqlx::test]
async fn a_summary_table_error_keeps_the_event_counts(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "old", "SUCCEEDED", Some(100 * DAY), 100 * DAY).await;
    rows(&pool, "old", 2, false).await;
    sqlx::query("ALTER TABLE job_summary RENAME TO job_summary_gone")
        .execute(&pool)
        .await
        .unwrap();
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.error, Some("database"));
    assert_eq!(stats.events_deleted, 2);
    assert_eq!(stats.summary_batches, 1);
}

#[sqlx::test]
async fn an_event_table_error_ends_the_sweep_before_summaries(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "old", "SUCCEEDED", Some(400 * DAY), 400 * DAY).await;
    rows(&pool, "old", 0, true).await;
    sqlx::query("ALTER TABLE job_event RENAME TO job_event_gone")
        .execute(&pool)
        .await
        .unwrap();
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.error, Some("database"));
    assert_eq!(stats.summary_batches, 0);
    assert!(has_summary(&pool, "old").await);
}

#[sqlx::test]
async fn running_and_queued_jobs_are_never_pruned(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "run", "RUNNING", None, 1000 * DAY).await;
    job(&pool, "runf", "RUNNING", Some(1000 * DAY), 1000 * DAY).await;
    job(&pool, "queue", "QUEUED", None, 1000 * DAY).await;
    job(&pool, "queuef", "QUEUED", Some(1000 * DAY), 1000 * DAY).await;
    for id in ["run", "runf", "queue", "queuef"] {
        rows(&pool, id, 2, true).await;
    }
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.events_deleted, 0);
    assert_eq!(stats.summaries_deleted, 0);
    for id in ["run", "runf", "queue", "queuef"] {
        assert_eq!(events_of(&pool, id).await, 2);
        assert!(has_summary(&pool, id).await);
    }
}

#[sqlx::test]
async fn a_null_finish_time_falls_back_to_created_at(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "old", "LOST", None, 100 * DAY).await;
    job(&pool, "young", "LOST", None, 80 * DAY).await;
    job(&pool, "finished", "LOST", Some(10 * DAY), 300 * DAY).await;
    for id in ["old", "young", "finished"] {
        rows(&pool, id, 1, false).await;
    }
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.events_deleted, 1);
    assert_eq!(events_of(&pool, "old").await, 0);
    assert_eq!(events_of(&pool, "young").await, 1);
    assert_eq!(events_of(&pool, "finished").await, 1);
}

#[sqlx::test]
async fn deletes_run_in_bounded_batches(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "big", "SUCCEEDED", Some(100 * DAY), 100 * DAY).await;
    rows(&pool, "big", 25, false).await;
    let small = policy().with_batches(10, 10);
    let stats = run_retention_once(&store, &small).await;
    assert_eq!(stats.events_deleted, 25);
    assert_eq!(stats.event_batches, 3);
    assert_eq!(stats.summary_batches, 1);
    assert!(!stats.capped);
    assert_eq!(total_events(&pool).await, 0);
}

#[sqlx::test]
async fn a_sweep_stops_at_max_batches_and_the_next_one_finishes(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "big", "SUCCEEDED", Some(100 * DAY), 100 * DAY).await;
    rows(&pool, "big", 25, false).await;
    let capped = policy().with_batches(10, 2);
    let first = run_retention_once(&store, &capped).await;
    assert_eq!(first.events_deleted, 20);
    assert_eq!(first.event_batches, 2);
    assert!(first.capped);
    assert_eq!(total_events(&pool).await, 5);
    let second = run_retention_once(&store, &capped).await;
    assert_eq!(second.events_deleted, 5);
    assert!(!second.capped);
    assert_eq!(total_events(&pool).await, 0);
}

#[sqlx::test]
async fn summaries_are_batched_too(pool: PgPool) {
    let store = store(pool.clone()).await;
    for n in 0..7 {
        let id = format!("s{n}");
        job(&pool, &id, "FAILED", Some(400 * DAY), 400 * DAY).await;
        rows(&pool, &id, 0, true).await;
    }
    let small = policy().with_batches(3, 2);
    let stats = run_retention_once(&store, &small).await;
    assert_eq!(stats.summaries_deleted, 6);
    assert_eq!(stats.summary_batches, 2);
    assert!(stats.capped);
}

#[sqlx::test]
async fn locked_rows_are_skipped_instead_of_waited_on(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "held", "SUCCEEDED", Some(400 * DAY), 400 * DAY).await;
    job(&pool, "free", "SUCCEEDED", Some(400 * DAY), 400 * DAY).await;
    rows(&pool, "held", 2, true).await;
    rows(&pool, "free", 2, true).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM job_event WHERE job_id = 'held' FOR UPDATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT 1 FROM job_summary WHERE job_id = 'held' FOR UPDATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    let stats = timeout(WAIT, run_retention_once(&store, &policy()))
        .await
        .unwrap();
    assert_eq!(stats.error, None);
    assert_eq!(events_of(&pool, "held").await, 2);
    assert_eq!(events_of(&pool, "free").await, 0);
    assert!(has_summary(&pool, "held").await);
    assert!(!has_summary(&pool, "free").await);
    tx.rollback().await.unwrap();
    run_retention_once(&store, &policy()).await;
    assert_eq!(events_of(&pool, "held").await, 0);
    assert!(!has_summary(&pool, "held").await);
}

#[sqlx::test]
async fn pruned_jobs_still_read(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "old", "SUCCEEDED", Some(400 * DAY), 400 * DAY).await;
    rows(&pool, "old", 3, true).await;
    run_retention_once(&store, &policy()).await;
    let page = store.read_job_events("old", None, 10).await.unwrap();
    assert_eq!(page.events.len(), 0);
    let got = store.get_job_with_summary("old").await.unwrap();
    assert_eq!(got.job_id, "old");
    assert!(got.summary.is_none());
}

#[sqlx::test]
async fn a_failed_sweep_reports_a_label_and_nothing_else(pool: PgPool) {
    let store = store(pool.clone()).await;
    pool.close().await;
    let stats = run_retention_once(&store, &policy()).await;
    assert_eq!(stats.error, Some("pool_closed"));
    assert_eq!(stats.events_deleted, 0);
}

#[sqlx::test]
async fn the_loop_sweeps_survives_errors_and_stops_on_cancel(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "old", "SUCCEEDED", Some(100 * DAY), 100 * DAY).await;
    rows(&pool, "old", 2, false).await;
    let (tx, rx) = watch::channel(false);
    let swept = std::sync::Arc::new(Notify::new());
    let signal = std::sync::Arc::clone(&swept);
    let task = tokio::spawn(async move {
        run_retention(
            store,
            policy(),
            Duration::from_millis(20),
            rx,
            Some(&signal),
        )
        .await;
    });
    timeout(WAIT, swept.notified()).await.unwrap();
    assert_eq!(total_events(&pool).await, 0);
    pool.close().await;
    timeout(WAIT, swept.notified()).await.unwrap();
    timeout(WAIT, swept.notified()).await.unwrap();
    assert!(!task.is_finished());
    tx.send_replace(true);
    timeout(WAIT, task).await.unwrap().unwrap();
}

#[sqlx::test]
async fn cancellation_stops_a_loop_waiting_on_a_long_interval(pool: PgPool) {
    let store = store(pool).await;
    let (tx, rx) = watch::channel(false);
    let swept = std::sync::Arc::new(Notify::new());
    let signal = std::sync::Arc::clone(&swept);
    let task = tokio::spawn(async move {
        run_retention(
            store,
            policy(),
            Duration::from_secs(3600),
            rx,
            Some(&signal),
        )
        .await;
    });
    timeout(WAIT, swept.notified()).await.unwrap();
    tx.send_replace(true);
    timeout(WAIT, task).await.unwrap().unwrap();
}

#[sqlx::test]
async fn cancellation_stops_a_sweep_blocked_on_a_lock(pool: PgPool) {
    let store = store(pool.clone()).await;
    job(&pool, "old", "SUCCEEDED", Some(100 * DAY), 100 * DAY).await;
    rows(&pool, "old", 1, false).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE job_event IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        run_retention(store, policy(), Duration::from_secs(3600), rx, None).await;
    });
    timeout(WAIT, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    stop.send_replace(true);
    timeout(WAIT, task).await.unwrap().unwrap();
    tx.rollback().await.unwrap();
}

#[sqlx::test]
async fn retention_indexes_exist(pool: PgPool) {
    let _store = store(pool.clone()).await;
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE tablename = 'jobs' ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(names.contains(&"jobs_created_idx".to_owned()));
    assert!(names.contains(&"jobs_terminal_finished_idx".to_owned()));
    let def: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'jobs_terminal_finished_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(def.contains("= ANY"), "{def}");
    assert!(def.contains("COALESCE(finished_at, created_at)"), "{def}");
}
