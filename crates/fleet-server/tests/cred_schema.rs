//! Schema tests for the credential tables. They need a Postgres superuser URL in
//! `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

use sqlx::PgPool;

async fn user(pool: &PgPool, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
}

async fn credential(
    pool: &PgPool,
    user_id: i64,
    kind: &str,
    shape: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint) \
         VALUES ($1, $2, $3, '\\x00', 'k1', 'fp') RETURNING id",
    )
    .bind(user_id)
    .bind(kind)
    .bind(shape)
    .fetch_one(pool)
    .await
}

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

#[sqlx::test]
async fn migration_applies_on_an_empty_database(pool: PgPool) {
    for table in [
        "SELECT count(*) FROM users",
        "SELECT count(*) FROM api_tokens",
        "SELECT count(*) FROM credentials",
        "SELECT count(*) FROM credential_use",
    ] {
        let count: i64 = sqlx::query_scalar(table).fetch_one(&pool).await.unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[sqlx::test]
async fn duplicate_username_is_rejected(pool: PgPool) {
    user(&pool, "alice").await.unwrap();
    let err = user(&pool, "alice").await.unwrap_err();
    assert_eq!(code(&err), "23505");
}

#[sqlx::test]
async fn duplicate_username_differing_in_case_is_rejected(pool: PgPool) {
    user(&pool, "alice").await.unwrap();
    let err = user(&pool, "ALICE").await.unwrap_err();
    assert_eq!(code(&err), "23505");
}

#[sqlx::test]
async fn every_known_kind_and_shape_is_accepted(pool: PgPool) {
    let kinds = [
        "anthropic_api_key",
        "claude_subscription_token",
        "github_pat",
        "kimi_membership_key",
        "kimi_platform_key",
        "codex_api_key",
    ];
    let id = user(&pool, "alice").await.unwrap();
    for (index, kind) in kinds.iter().enumerate() {
        let shape = if index % 2 == 0 {
            "static_secret"
        } else {
            "refreshing_file"
        };
        credential(&pool, id, kind, shape).await.unwrap();
    }
}

#[sqlx::test]
async fn unknown_kind_is_rejected(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let err = credential(&pool, id, "mystery_key", "static_secret")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn unknown_shape_is_rejected(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let err = credential(&pool, id, "github_pat", "mystery")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn second_credential_of_one_kind_for_a_user_is_rejected(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    credential(&pool, id, "github_pat", "static_secret")
        .await
        .unwrap();
    let err = credential(&pool, id, "github_pat", "static_secret")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23505");
}

#[sqlx::test]
async fn duplicate_token_hash_is_rejected(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let insert = "INSERT INTO api_tokens (user_id, hash) VALUES ($1, $2)";
    let hash = vec![7_u8; 32];
    sqlx::query(insert)
        .bind(id)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let err = sqlx::query(insert)
        .bind(id)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23505");
}

#[sqlx::test]
async fn credential_use_update_delete_and_truncate_are_rejected(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_pat", "static_secret")
        .await
        .unwrap();
    sqlx::query("INSERT INTO credential_use (credential_id, job_id) VALUES ($1, 'job')")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    for statement in [
        "UPDATE credential_use SET job_id = 'other'",
        "DELETE FROM credential_use",
        "TRUNCATE credential_use",
    ] {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("insert-only"), "{statement}: {message}");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn deleting_a_user_with_credentials_is_refused(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    credential(&pool, id, "github_pat", "static_secret")
        .await
        .unwrap();
    let err = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23503");
}

#[sqlx::test]
async fn deleting_a_credential_with_use_rows_succeeds_and_keeps_the_rows(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_pat", "static_secret")
        .await
        .unwrap();
    sqlx::query("INSERT INTO credential_use (credential_id, job_id) VALUES ($1, 'job')")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM credentials WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    let kept: i64 =
        sqlx::query_scalar("SELECT count(*) FROM credential_use WHERE credential_id = $1")
            .bind(cred)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(kept, 1);
    for statement in [
        "UPDATE credential_use SET job_id = 'other'",
        "DELETE FROM credential_use",
        "TRUNCATE credential_use",
    ] {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert!(err.to_string().contains("insert-only"), "{statement}");
    }
}
