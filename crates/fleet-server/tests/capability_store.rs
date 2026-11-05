//! Capability store tests. They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_server::cred::capability::{
    Capabilities, CapabilityError, PROFILE_TOOLS, REASON_NO_SUCH_ACTOR, REASON_NO_SUCH_USER,
    REASON_UNKNOWN_CAPABILITY,
};
use sqlx::PgPool;

const BAND: Duration = Duration::from_millis(400);
const OUTER: Duration = Duration::from_secs(20);

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM user_capabilities")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn grant_has_revoke_has_regrant_cycle(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    assert!(!caps.has(alice, PROFILE_TOOLS).await.unwrap());
    assert!(caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap());
    assert!(caps.has(alice, PROFILE_TOOLS).await.unwrap());
    assert!(caps.revoke(admin, alice, PROFILE_TOOLS).await.unwrap());
    assert!(!caps.has(alice, PROFILE_TOOLS).await.unwrap());
    assert!(caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap());
    assert!(caps.has(alice, PROFILE_TOOLS).await.unwrap());
}

#[sqlx::test]
async fn a_second_grant_changes_nothing_and_keeps_the_first_audit(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, a1, a2) = (
        user(&pool, "alice").await,
        user(&pool, "admin1").await,
        user(&pool, "admin2").await,
    );
    assert!(caps.grant(a1, alice, PROFILE_TOOLS).await.unwrap());
    assert!(!caps.grant(a2, alice, PROFILE_TOOLS).await.unwrap());
    let by: i64 = sqlx::query_scalar("SELECT granted_by FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(by, a1);
}

#[sqlx::test]
async fn revoke_of_an_absent_grant_is_a_noop(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, bob, admin) = (
        user(&pool, "alice").await,
        user(&pool, "bob").await,
        user(&pool, "admin").await,
    );
    assert!(!caps.revoke(admin, alice, PROFILE_TOOLS).await.unwrap());
    caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap();
    assert!(!caps.revoke(admin, bob, PROFILE_TOOLS).await.unwrap());
    assert!(caps.revoke(admin, alice, PROFILE_TOOLS).await.unwrap());
    assert!(!caps.revoke(admin, alice, PROFILE_TOOLS).await.unwrap());
    assert_eq!(rows(&pool).await, 0);
    assert!(!caps.revoke(admin, 9_999, PROFILE_TOOLS).await.unwrap());
}

#[sqlx::test]
async fn grant_stamps_the_acting_admin(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap();
    let ok: bool = sqlx::query_scalar(
        "SELECT granted_by = $2 AND granted_by <> user_id AND granted_at IS NOT NULL \
         AND granted_at <= now() FROM user_capabilities WHERE user_id = $1 AND capability = $3",
    )
    .bind(alice)
    .bind(admin)
    .bind(PROFILE_TOOLS)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(ok);
}

#[sqlx::test]
async fn grant_to_an_absent_or_deleted_user_fails_closed(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    let err = caps.grant(admin, 9_999, PROFILE_TOOLS).await.unwrap_err();
    assert!(matches!(err, CapabilityError::NoSuchUser));
    assert_eq!(err.to_string(), REASON_NO_SUCH_USER);
    caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!caps.has(alice, PROFILE_TOOLS).await.unwrap());
    let err = caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap_err();
    assert!(matches!(err, CapabilityError::NoSuchUser));
    assert_eq!(rows(&pool).await, 0);
}

#[sqlx::test]
async fn grant_by_an_absent_actor_fails_closed(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let err = caps.grant(9_999, alice, PROFILE_TOOLS).await.unwrap_err();
    assert!(matches!(err, CapabilityError::NoSuchActor));
    assert_eq!(err.to_string(), REASON_NO_SUCH_ACTOR);
    assert_eq!(rows(&pool).await, 0);
}

#[sqlx::test]
async fn revoke_by_an_absent_actor_fails_closed_and_keeps_the_grant(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap();
    let err = caps.revoke(9_999, alice, PROFILE_TOOLS).await.unwrap_err();
    assert!(matches!(err, CapabilityError::NoSuchActor));
    assert!(caps.has(alice, PROFILE_TOOLS).await.unwrap());
}

#[sqlx::test]
async fn an_unknown_capability_is_refused_before_sql_and_never_held(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    for name in [
        "",
        "profile:Tools",
        "profile:tools ",
        "profile:tools\n",
        "admin",
        "profile:%",
    ] {
        let err = caps.grant(admin, alice, name).await.unwrap_err();
        assert!(
            matches!(err, CapabilityError::UnknownCapability),
            "{name:?}"
        );
        assert_eq!(err.to_string(), REASON_UNKNOWN_CAPABILITY);
        assert!(matches!(
            caps.revoke(admin, alice, name).await,
            Err(CapabilityError::UnknownCapability)
        ));
        assert!(!caps.has(alice, name).await.unwrap());
    }
    assert!(!caps.has(9_999, PROFILE_TOOLS).await.unwrap());
    assert_eq!(rows(&pool).await, 0);
}

#[sqlx::test]
async fn has_waits_for_an_open_revoke_and_then_sees_it(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    let reader = Capabilities::new(pool.clone());
    let mut task = tokio::spawn(async move { reader.has(alice, PROFILE_TOOLS).await });
    assert!(tokio::time::timeout(BAND, &mut task).await.is_err());
    tx.commit().await.unwrap();
    let held = tokio::time::timeout(OUTER, task).await.unwrap().unwrap();
    assert!(!held.unwrap());
}

#[sqlx::test]
async fn revoke_waits_for_a_reader_holding_the_grant(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    caps.grant(admin, alice, PROFILE_TOOLS).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM user_capabilities WHERE user_id = $1 FOR SHARE")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    let writer = Capabilities::new(pool.clone());
    let mut task = tokio::spawn(async move { writer.revoke(admin, alice, PROFILE_TOOLS).await });
    assert!(tokio::time::timeout(BAND, &mut task).await.is_err());
    tx.commit().await.unwrap();
    let revoked = tokio::time::timeout(OUTER, task).await.unwrap().unwrap();
    assert!(revoked.unwrap());
}

#[sqlx::test]
async fn grant_waits_for_the_actor_row_and_fails_when_it_is_deleted(pool: PgPool) {
    let caps = Capabilities::new(pool.clone());
    let (alice, admin) = (user(&pool, "alice").await, user(&pool, "admin").await);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(admin)
        .execute(&mut *tx)
        .await
        .unwrap();
    let mut task = tokio::spawn(async move { caps.grant(admin, alice, PROFILE_TOOLS).await });
    assert!(tokio::time::timeout(BAND, &mut task).await.is_err());
    tx.commit().await.unwrap();
    let out = tokio::time::timeout(OUTER, task).await.unwrap().unwrap();
    assert!(matches!(out, Err(CapabilityError::NoSuchActor)));
    assert_eq!(rows(&pool).await, 0);
}
