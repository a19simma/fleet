//! Schema tests for the timing tables. They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::{
    MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SPANS, MAX_TIMING_NAME_BYTES,
};
use sqlx::PgPool;

async fn job(pool: &PgPool, id: &str) {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr) \
         VALUES ($1, 't', 'r', 'main', 'b', false)",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
}

async fn span(pool: &PgPool, id: &str, seq: i32, kind: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO job_timing_spans (job_id, seq, kind, start_ms, end_ms, name) \
         VALUES ($1, $2, $3, 0, 1, 'n')",
    )
    .bind(id)
    .bind(seq)
    .bind(kind)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn shell(
    pool: &PgPool,
    id: &str,
    seq: i32,
    command: &str,
    log: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO job_shell_commands \
         (job_id, seq, id, command, background, started_ms, duration_ms, log, log_truncated) \
         VALUES ($1, $2, 'c', $3, false, 0, 1, $4, false)",
    )
    .bind(id)
    .bind(seq)
    .bind(command)
    .bind(log)
    .execute(pool)
    .await
    .map(|_| ())
}

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

fn cap(value: usize) -> i32 {
    i32::try_from(value).unwrap()
}

#[sqlx::test]
async fn span_seq_just_under_and_just_over_the_cap(pool: PgPool) {
    job(&pool, "j1").await;
    span(&pool, "j1", cap(MAX_SPANS) - 1, "api").await.unwrap();
    let err = span(&pool, "j1", cap(MAX_SPANS), "api").await.unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn shell_seq_just_under_and_just_over_the_cap(pool: PgPool) {
    job(&pool, "j1").await;
    shell(&pool, "j1", cap(MAX_SHELL_COMMANDS) - 1, "ls", "")
        .await
        .unwrap();
    let err = shell(&pool, "j1", cap(MAX_SHELL_COMMANDS), "ls", "")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn command_just_under_and_just_over_the_cap(pool: PgPool) {
    job(&pool, "j1").await;
    shell(&pool, "j1", 0, &"a".repeat(MAX_COMMAND_BYTES), "")
        .await
        .unwrap();
    let err = shell(&pool, "j1", 1, &"a".repeat(MAX_COMMAND_BYTES + 1), "")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
    let err = shell(&pool, "j1", 2, "", "").await.unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn log_just_under_and_just_over_the_cap(pool: PgPool) {
    job(&pool, "j1").await;
    shell(&pool, "j1", 0, "ls", &"a".repeat(MAX_SHELL_LOG_BYTES))
        .await
        .unwrap();
    let err = shell(&pool, "j1", 1, "ls", &"a".repeat(MAX_SHELL_LOG_BYTES + 1))
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn span_name_just_under_and_just_over_the_cap(pool: PgPool) {
    job(&pool, "j1").await;
    let insert = |seq: i32, len: usize| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO job_timing_spans (job_id, seq, kind, start_ms, end_ms, name) \
                 VALUES ('j1', $1, 'tool', 0, 1, $2)",
            )
            .bind(seq)
            .bind("a".repeat(len))
            .execute(&pool)
            .await
        }
    };
    insert(0, MAX_TIMING_NAME_BYTES).await.unwrap();
    let err = insert(1, MAX_TIMING_NAME_BYTES + 1).await.unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn an_unknown_span_kind_is_rejected(pool: PgPool) {
    job(&pool, "j1").await;
    for (seq, kind) in ["api", "tool", "shell", "bg_shell"].iter().enumerate() {
        span(&pool, "j1", i32::try_from(seq).unwrap(), kind)
            .await
            .unwrap();
    }
    let err = span(&pool, "j1", 9, "other").await.unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn deleting_the_job_cascades_to_all_three_tables(pool: PgPool) {
    job(&pool, "j1").await;
    sqlx::query(
        "INSERT INTO job_timing (job_id, wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, overhead_ms) \
         VALUES ('j1', 1, 1, 1, 1, 1, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    span(&pool, "j1", 0, "api").await.unwrap();
    shell(&pool, "j1", 0, "ls", "").await.unwrap();
    sqlx::query("DELETE FROM jobs WHERE job_id = 'j1'")
        .execute(&pool)
        .await
        .unwrap();
    for query in [
        "SELECT count(*) FROM job_timing",
        "SELECT count(*) FROM job_timing_spans",
        "SELECT count(*) FROM job_shell_commands",
    ] {
        let count: i64 = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
        assert_eq!(count, 0, "{query}");
    }
}

#[sqlx::test]
async fn a_span_for_a_missing_job_is_rejected(pool: PgPool) {
    let err = span(&pool, "missing", 0, "api").await.unwrap_err();
    assert_eq!(code(&err), "23503");
}
