//! Schema tests for migration 0023: Profile ownership and visibility. They need a Postgres
//! superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;

const OWNERSHIP_VERSION: i64 = 23;

async fn migrate_before(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < OWNERSHIP_VERSION)
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(pool).await.unwrap();
}

async fn migrate_rest(pool: &PgPool) {
    sqlx::migrate!("./migrations").run(pool).await.unwrap();
}

async fn legacy_version(pool: &PgPool, name: &str, version: i32, hash_byte: u8) {
    let hash = vec![hash_byte; 32];
    sqlx::query(
        "INSERT INTO profile_blob (hash, content, size) VALUES ($1, 'x', 1) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&hash)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO profile_version (name, version, hash) VALUES ($1, $2, $3)")
        .bind(name)
        .bind(version)
        .bind(&hash)
        .execute(pool)
        .await
        .unwrap();
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
        .unwrap_or_default()
}

#[sqlx::test(migrations = false)]
async fn legacy_profiles_go_to_the_system_user_as_shared(pool: PgPool) {
    migrate_before(&pool).await;
    legacy_version(&pool, "alpha", 1, 1).await;
    legacy_version(&pool, "alpha", 2, 2).await;
    legacy_version(&pool, "beta", 1, 3).await;
    migrate_rest(&pool).await;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT p.name, u.username, p.visibility FROM profile p \
         JOIN users u ON u.id = p.owner_user_id ORDER BY p.name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let expected = |name: &str| (name.to_owned(), "system".to_owned(), "shared".to_owned());
    assert_eq!(rows, vec![expected("alpha"), expected("beta")]);
}

#[sqlx::test(migrations = false)]
async fn the_system_user_holds_no_credentials(pool: PgPool) {
    migrate_before(&pool).await;
    legacy_version(&pool, "alpha", 1, 1).await;
    migrate_rest(&pool).await;
    let held: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM api_tokens) + (SELECT count(*) FROM passkeys) \
         + (SELECT count(*) FROM web_sessions)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(held, 0);
}

#[sqlx::test(migrations = false)]
async fn no_legacy_rows_means_no_system_user(pool: PgPool) {
    migrate_before(&pool).await;
    migrate_rest(&pool).await;
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[sqlx::test]
async fn a_new_profile_is_private_and_names_are_unique_per_owner(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let insert = "INSERT INTO profile (owner_user_id, name) VALUES ($1, 'p')";
    sqlx::query(insert)
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(insert).bind(bob).execute(&pool).await.unwrap();
    let again = sqlx::query(insert)
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&again), "23505");
    let visibility: String =
        sqlx::query_scalar("SELECT visibility FROM profile WHERE owner_user_id = $1")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(visibility, "private");
}

#[sqlx::test]
async fn an_unknown_visibility_is_refused(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let err = sqlx::query(
        "INSERT INTO profile (owner_user_id, name, visibility) VALUES ($1, 'p', 'public')",
    )
    .bind(alice)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&err), "23514");
}
