//! Schema tests for migration 0025: live shell log chunks. They need a Postgres superuser URL in
//! `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::{MAX_COMMAND_ID_BYTES, MAX_SHELL_LOG_CHUNK_BYTES, MAX_SHELL_LOG_CHUNKS};
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

async fn chunk(
    pool: &PgPool,
    job_id: &str,
    command_id: &str,
    seq: i32,
    bytes: &[u8],
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(job_id)
    .bind(command_id)
    .bind(seq)
    .bind(bytes)
    .bind(status)
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

async fn count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM job_shell_log_chunks")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn every_status_and_the_bounds_are_accepted(pool: PgPool) {
    job(&pool, "j").await;
    for (seq, status) in ["queued", "running", "done", "failed"].iter().enumerate() {
        chunk(&pool, "j", "c", i32::try_from(seq).unwrap(), b"x", status)
            .await
            .unwrap();
    }
    let last = i32::try_from(MAX_SHELL_LOG_CHUNKS - 1).unwrap();
    chunk(&pool, "j", "d", last, &[], "running").await.unwrap();
    let full = vec![0xff; MAX_SHELL_LOG_CHUNK_BYTES];
    chunk(&pool, "j", "e", 0, &full, "running").await.unwrap();
    let longest = "a".repeat(MAX_COMMAND_ID_BYTES);
    chunk(&pool, "j", &longest, 0, b"x", "done").await.unwrap();
    assert_eq!(count(&pool).await, 7);
}

#[sqlx::test]
async fn an_oversize_chunk_is_refused(pool: PgPool) {
    job(&pool, "j").await;
    let over = vec![b'x'; MAX_SHELL_LOG_CHUNK_BYTES + 1];
    let err = chunk(&pool, "j", "c", 0, &over, "running")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn an_unknown_or_unspecified_status_is_refused(pool: PgPool) {
    job(&pool, "j").await;
    for status in ["unspecified", "Queued", "", "cancelled"] {
        let err = chunk(&pool, "j", "c", 0, b"x", status).await.unwrap_err();
        assert_eq!(code(&err), "23514", "{status}");
    }
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn seq_outside_the_range_is_refused(pool: PgPool) {
    job(&pool, "j").await;
    let past = i32::try_from(MAX_SHELL_LOG_CHUNKS).unwrap();
    for seq in [-1, past, i32::MAX] {
        let err = chunk(&pool, "j", "c", seq, b"x", "running")
            .await
            .unwrap_err();
        assert_eq!(code(&err), "23514", "{seq}");
    }
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn hostile_command_ids_are_refused(pool: PgPool) {
    job(&pool, "j").await;
    let long = "a".repeat(MAX_COMMAND_ID_BYTES + 1);
    for id in [
        "",
        "a\n",
        "\na",
        "a\r\n",
        "a b",
        "a/b",
        "a\\b",
        "a@b",
        "\u{e9}",
        "a\u{2028}",
        "a\0b",
        &long,
    ] {
        let err = chunk(&pool, "j", id, 0, b"x", "running").await.unwrap_err();
        let expected = if id.contains('\0') { "22021" } else { "23514" };
        assert_eq!(code(&err), expected, "{id:?}");
    }
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn job_command_and_seq_are_unique_but_each_part_may_repeat(pool: PgPool) {
    job(&pool, "j").await;
    job(&pool, "k").await;
    chunk(&pool, "j", "c", 0, b"x", "running").await.unwrap();
    let err = chunk(&pool, "j", "c", 0, b"y", "running")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23505");
    chunk(&pool, "j", "c", 1, b"x", "running").await.unwrap();
    chunk(&pool, "j", "d", 0, b"x", "running").await.unwrap();
    chunk(&pool, "k", "c", 0, b"x", "running").await.unwrap();
    assert_eq!(count(&pool).await, 4);
}

#[sqlx::test]
async fn a_chunk_needs_its_job(pool: PgPool) {
    let err = chunk(&pool, "missing", "c", 0, b"x", "running")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23503");
}

#[sqlx::test]
async fn deleting_the_job_cascades_to_its_chunks(pool: PgPool) {
    job(&pool, "j").await;
    job(&pool, "k").await;
    chunk(&pool, "j", "c", 0, b"x", "running").await.unwrap();
    chunk(&pool, "k", "c", 0, b"x", "running").await.unwrap();
    sqlx::query("DELETE FROM jobs WHERE job_id = 'j'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool).await, 1);
}
