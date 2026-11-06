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
        "github_app",
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

async fn mint(
    pool: &PgPool,
    cred: i64,
    attempt: &str,
    outcome: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
         installation_id, requested_permissions, outcome) \
         VALUES (gen_random_uuid(), $1::uuid, $2, 'job', 'o/r', '42', 'contents:read', $3)",
    )
    .bind(attempt)
    .bind(cred)
    .bind(outcome)
    .execute(pool)
    .await
}

const ATTEMPT: &str = "11111111-1111-1111-1111-111111111111";

#[sqlx::test]
async fn github_app_mint_accepts_every_outcome(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    for outcome in [
        "attempt",
        "minted",
        "failed",
        "denied",
        "revoked",
        "revoke_failed",
    ] {
        mint(&pool, cred, ATTEMPT, outcome).await.unwrap();
    }
    let err = mint(&pool, cred, ATTEMPT, "bogus").await.unwrap_err();
    assert_eq!(code(&err), "23514");
}

async fn mint_with(
    pool: &PgPool,
    cred: i64,
    column: &str,
    value: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let mut row = [
        ("job_id", "job"),
        ("repo", "o/r"),
        ("installation_id", "42"),
        ("requested_permissions", "contents:read"),
        ("reason", "ok"),
    ];
    for (name, slot) in &mut row {
        if *name == column {
            *slot = value;
        }
    }
    sqlx::query(
        "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
         installation_id, requested_permissions, outcome, reason) \
         VALUES (gen_random_uuid(), gen_random_uuid(), $1, $2, $3, $4, $5, 'attempt', $6)",
    )
    .bind(cred)
    .bind(row[0].1)
    .bind(row[1].1)
    .bind(row[2].1)
    .bind(row[3].1)
    .bind(row[4].1)
    .execute(pool)
    .await
}

#[sqlx::test]
async fn github_app_mint_text_columns_are_bounded(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    for (column, max) in [
        ("job_id", 64),
        ("repo", 140),
        ("requested_permissions", 512),
        ("reason", 200),
    ] {
        mint_with(&pool, cred, column, &"a".repeat(max))
            .await
            .unwrap();
        let err = mint_with(&pool, cred, column, &"a".repeat(max + 1))
            .await
            .unwrap_err();
        assert_eq!(code(&err), "23514", "{column}");
    }
    for column in ["job_id", "repo", "requested_permissions"] {
        let err = mint_with(&pool, cred, column, "").await.unwrap_err();
        assert_eq!(code(&err), "23514", "{column} empty");
    }
}

#[sqlx::test]
async fn github_app_mint_installation_id_is_bounded_to_u64(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    mint_with(&pool, cred, "installation_id", "18446744073709551615")
        .await
        .unwrap();
    for bad in ["18446744073709551616", "99999999999999999999"] {
        let err = mint_with(&pool, cred, "installation_id", bad)
            .await
            .unwrap_err();
        assert_eq!(code(&err), "23514", "{bad}");
    }
}

#[sqlx::test]
async fn a_tombstoned_credential_cannot_be_untombstoned(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET tombstoned_at = NULL WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    let err = sqlx::query("UPDATE credentials SET tombstoned_at = NULL WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23001");
    assert!(err.to_string().contains("tombstone"), "{err}");
    sqlx::query("UPDATE credentials SET shape = 'static_secret' WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    let still: bool =
        sqlx::query_scalar("SELECT tombstoned_at IS NOT NULL FROM credentials WHERE id = $1")
            .bind(cred)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(still);
}

#[sqlx::test]
async fn github_app_mint_rejects_update_delete_and_truncate(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    mint(&pool, cred, ATTEMPT, "attempt").await.unwrap();
    for statement in [
        "UPDATE github_app_mint SET reason = 'x'",
        "DELETE FROM github_app_mint",
        "TRUNCATE github_app_mint",
    ] {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("insert-only"), "{statement}: {message}");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM github_app_mint")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn github_app_mint_attempt_and_outcome_pair_is_unique(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    mint(&pool, cred, ATTEMPT, "attempt").await.unwrap();
    let err = mint(&pool, cred, ATTEMPT, "attempt").await.unwrap_err();
    assert_eq!(code(&err), "23505");
    mint(
        &pool,
        cred,
        "22222222-2222-2222-2222-222222222222",
        "attempt",
    )
    .await
    .unwrap();
}

#[sqlx::test]
async fn github_app_mint_expires_at_only_on_minted_rows(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    let insert = |outcome: &'static str| {
        sqlx::query(
            "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
             installation_id, requested_permissions, outcome, expires_at) \
             VALUES (gen_random_uuid(), gen_random_uuid(), $1, 'j', 'o/r', '42', 'p', $2, now())",
        )
        .bind(cred)
        .bind(outcome)
        .execute(&pool)
    };
    insert("minted").await.unwrap();
    assert_eq!(code(&insert("failed").await.unwrap_err()), "23514");
}

#[sqlx::test]
async fn github_app_mint_rejects_bad_installation_ids(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    for bad in ["0", "01", "", "1 ", "+1", "123456789012345678901"] {
        let err = sqlx::query(
            "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
             installation_id, requested_permissions, outcome) \
             VALUES (gen_random_uuid(), gen_random_uuid(), $1, 'j', 'o/r', $2, 'p', 'attempt')",
        )
        .bind(cred)
        .bind(bad)
        .execute(&pool)
        .await
        .unwrap_err();
        assert_eq!(code(&err), "23514", "{bad:?}");
    }
}

#[sqlx::test]
async fn credential_with_mint_history_cannot_be_deleted_but_can_be_tombstoned(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    mint(&pool, cred, ATTEMPT, "attempt").await.unwrap();
    let err = sqlx::query("DELETE FROM credentials WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("mint history"), "{err}");
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
    let tombstoned: bool =
        sqlx::query_scalar("SELECT tombstoned_at IS NOT NULL FROM credentials WHERE id = $1")
            .bind(cred)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(tombstoned);
}

#[sqlx::test]
async fn mint_credential_foreign_key_is_no_action(pool: PgPool) {
    let action: String = sqlx::query_scalar(
        "SELECT confdeltype::text FROM pg_constraint \
         WHERE conrelid = 'github_app_mint'::regclass AND contype = 'f'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(action, "a");
}

#[sqlx::test]
async fn credential_without_mint_history_can_be_deleted(pool: PgPool) {
    let id = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, id, "github_app", "static_secret")
        .await
        .unwrap();
    sqlx::query("DELETE FROM credentials WHERE id = $1")
        .bind(cred)
        .execute(&pool)
        .await
        .unwrap();
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
