//! Schema tests for migration 0018: job ownership, job agent, passkeys and web
//! sessions. They need a Postgres superuser URL in `DATABASE_URL`.

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;

const BACKFILL_VERSION: i64 = 18;

async fn migrate_before_backfill(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < BACKFILL_VERSION)
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(pool).await
}

async fn migrate_rest(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

async fn old_job(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr) \
         VALUES ($1, 'p', 'r', 'main', 'b', false)",
    )
    .bind(id)
    .execute(pool)
    .await
    .map(drop)
}

async fn user(pool: &PgPool, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
}

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
        .unwrap_or_default()
}

#[sqlx::test(migrations = false)]
async fn existing_jobs_are_backfilled_to_the_bootstrap_user(pool: PgPool) {
    migrate_before_backfill(&pool).await.unwrap();
    old_job(&pool, "job-a").await.unwrap();
    old_job(&pool, "job-b").await.unwrap();
    migrate_rest(&pool).await.unwrap();
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT j.job_id, u.username, j.agent FROM jobs j JOIN users u ON u.id = j.user_id \
         ORDER BY j.job_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let expected = |id: &str| (id.to_owned(), "bootstrap".to_owned(), "claude".to_owned());
    assert_eq!(rows, vec![expected("job-a"), expected("job-b")]);
}

#[sqlx::test(migrations = false)]
async fn backfill_reuses_a_bootstrap_user_that_already_exists(pool: PgPool) {
    migrate_before_backfill(&pool).await.unwrap();
    let existing = user(&pool, "Bootstrap").await.unwrap();
    old_job(&pool, "job-a").await.unwrap();
    migrate_rest(&pool).await.unwrap();
    let owner: i64 = sqlx::query_scalar("SELECT user_id FROM jobs WHERE job_id = 'job-a'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(owner, existing);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

#[sqlx::test]
async fn a_job_inserted_without_owner_or_agent_gets_the_defaults(pool: PgPool) {
    old_job(&pool, "job-a").await.unwrap();
    let (username, agent): (String, String) =
        sqlx::query_as("SELECT u.username, j.agent FROM jobs j JOIN users u ON u.id = j.user_id")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((username.as_str(), agent.as_str()), ("bootstrap", "claude"));
}

#[sqlx::test]
async fn an_empty_database_has_no_users(pool: PgPool) {
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[sqlx::test]
async fn job_user_id_is_not_null(pool: PgPool) {
    old_job(&pool, "job-a").await.unwrap();
    let err = sqlx::query("UPDATE jobs SET user_id = NULL")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23502");
}

#[sqlx::test]
async fn job_user_id_must_name_a_user(pool: PgPool) {
    old_job(&pool, "job-a").await.unwrap();
    let err = sqlx::query("UPDATE jobs SET user_id = 999999")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23503");
}

#[sqlx::test]
async fn every_agent_is_accepted_and_an_unknown_one_is_rejected(pool: PgPool) {
    old_job(&pool, "job-a").await.unwrap();
    for agent in ["claude", "codex", "kimi"] {
        sqlx::query("UPDATE jobs SET agent = $1")
            .bind(agent)
            .execute(&pool)
            .await
            .unwrap();
    }
    let err = sqlx::query("UPDATE jobs SET agent = 'gemini'")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn passkey_credential_id_is_unique_and_owned_by_a_user(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let insert = "INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)";
    sqlx::query(insert)
        .bind(id)
        .bind(vec![1_u8; 16])
        .bind(vec![2_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    let dup = sqlx::query(insert)
        .bind(id)
        .bind(vec![1_u8; 16])
        .bind(vec![3_u8; 32])
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "23505");
    let orphan = sqlx::query(insert)
        .bind(999_999_i64)
        .bind(vec![9_u8; 16])
        .bind(vec![2_u8; 32])
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&orphan), "23503");
}

#[sqlx::test]
async fn web_session_hash_is_unique_32_bytes_and_owned_by_a_user(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let insert = "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
                  VALUES ($1, $2, 'token', now() + interval '1 day')";
    sqlx::query(insert)
        .bind(vec![5_u8; 32])
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let dup = sqlx::query(insert)
        .bind(vec![5_u8; 32])
        .bind(id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "23505");
    let short = sqlx::query(insert)
        .bind(vec![5_u8; 31])
        .bind(id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&short), "23514");
    let orphan = sqlx::query(insert)
        .bind(vec![6_u8; 32])
        .bind(999_999_i64)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&orphan), "23503");
    let seen: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM web_sessions WHERE last_seen <= now() AND last_seen > now() - interval '1 minute'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(seen, 1);
}
