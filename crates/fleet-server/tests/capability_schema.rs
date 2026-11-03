//! Schema tests for migration 0026: per-user capabilities. They need a Postgres superuser URL in
//! `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::SubmitJobRequest;
use fleet_server::store::Store;
use sqlx::PgPool;
use std::borrow::Cow;

const GRANT: &str = "INSERT INTO user_capabilities (user_id, capability, granted_by) \
                     VALUES ($1, $2, $3) ON CONFLICT (user_id, capability) DO NOTHING";

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
        .unwrap_or_default()
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn grant(pool: &PgPool, user: i64, cap: &str, by: i64) -> Result<u64, sqlx::Error> {
    sqlx::query(GRANT)
        .bind(user)
        .bind(cap)
        .bind(by)
        .execute(pool)
        .await
        .map(|done| done.rows_affected())
}

async fn count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM user_capabilities")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn the_one_capability_is_accepted_and_stamped(pool: PgPool) {
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    assert_eq!(
        grant(&pool, alice, "profile:tools", admin).await.unwrap(),
        1
    );
    let stamped: bool = sqlx::query_scalar(
        "SELECT granted_at <= now() AND granted_by = $2 FROM user_capabilities WHERE user_id = $1",
    )
    .bind(alice)
    .bind(admin)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stamped);
}

#[sqlx::test]
async fn a_second_grant_is_a_no_op_and_keeps_the_first_row(pool: PgPool) {
    let (alice, admin, other) = (
        user(&pool, "alice").await,
        user(&pool, "admin").await,
        user(&pool, "other").await,
    );
    assert_eq!(
        grant(&pool, alice, "profile:tools", admin).await.unwrap(),
        1
    );
    assert_eq!(
        grant(&pool, alice, "profile:tools", other).await.unwrap(),
        0
    );
    assert_eq!(count(&pool).await, 1);
    let by: i64 = sqlx::query_scalar("SELECT granted_by FROM user_capabilities")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(by, admin);
}

#[sqlx::test]
async fn a_plain_duplicate_insert_violates_the_key(pool: PgPool) {
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    grant(&pool, alice, "profile:tools", admin).await.unwrap();
    let err = sqlx::query(
        "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, $2, $3)",
    )
    .bind(alice)
    .bind("profile:tools")
    .bind(admin)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&err), "23505");
}

#[sqlx::test]
async fn any_other_capability_text_is_refused(pool: PgPool) {
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    for cap in [
        "",
        "Profile:Tools",
        "profile:tools ",
        "profile:tools\n",
        "profile:tool",
        "admin",
        "profile:*",
    ] {
        let err = grant(&pool, alice, cap, admin).await.unwrap_err();
        assert_eq!(code(&err), "23514", "{cap:?}");
    }
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn the_user_and_the_granter_must_exist(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let err = grant(&pool, alice, "profile:tools", i64::MAX)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23503");
    let err = grant(&pool, i64::MAX, "profile:tools", alice)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23503");
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn deleting_the_user_drops_the_grant_and_a_granter_is_protected(pool: PgPool) {
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    grant(&pool, alice, "profile:tools", admin).await.unwrap();
    let err = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23503");
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test]
async fn a_stored_job_is_never_stamped_even_when_the_owner_holds_the_capability(pool: PgPool) {
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    grant(&pool, alice, "profile:tools", admin).await.unwrap();
    let store = Store::new(pool.clone());
    let request = SubmitJobRequest {
        idempotency_key: "k".into(),
        prompt: "p".into(),
        repo: "https://example.com/org/repo.git".into(),
        base_ref: "main".into(),
        ..SubmitJobRequest::default()
    };
    let job = store.submit_job_for(Some(alice), &request).await.unwrap();
    assert_eq!(job.user_id, u64::try_from(alice).unwrap());
    assert!(!job.profile_tools_granted);
    let fetched = store.get_job(&job.job_id).await.unwrap();
    assert!(!fetched.profile_tools_granted);
}
