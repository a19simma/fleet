//! Admin flag in the users store (ADR-0056): one test per insert path into `users`, plus
//! `set_admin` and `is_admin`. They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::{UserError, Users};
use sqlx::PgPool;

async fn flag(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT is_admin FROM users WHERE username = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn created(pool: &PgPool, name: &str) -> i64 {
    let outcome = run(pool, &AdminCommand::CreateUser(name.into()), "op")
        .await
        .unwrap();
    outcome.user_id
}

#[expect(
    clippy::significant_drop_tightening,
    reason = "commit consumes the redemption; the lint cannot see the move"
)]
async fn redeem_password(users: &Users, name: &str) -> i64 {
    let redemption = users.begin_redeem_password(name).await.unwrap();
    let id = redemption.user_id();
    redemption.commit().await.unwrap();
    id
}

#[sqlx::test]
async fn insert_path_setup_redemption_is_admin_and_second_user_is_not(pool: PgPool) {
    let users = Users::new(pool.clone());
    let code = users.issue_setup_code().await.unwrap().unwrap();
    let first = users.redeem_setup(code.expose(), "first").await.unwrap();
    assert!(users.is_admin(first).await.unwrap());
    assert!(flag(&pool, "first").await);
    assert!(users.issue_setup_code().await.unwrap().is_none());
    assert!(matches!(
        users.redeem_setup(code.expose(), "second").await,
        Err(UserError::BadSetupCode)
    ));
    let second = created(&pool, "second").await;
    assert!(!users.is_admin(second).await.unwrap());
    assert!(users.is_admin(first).await.unwrap());
}

#[sqlx::test]
async fn insert_path_password_redemption_is_admin(pool: PgPool) {
    let users = Users::new(pool.clone());
    let id = redeem_password(&users, "pw-first").await;
    assert!(users.is_admin(id).await.unwrap());
    assert!(flag(&pool, "pw-first").await);
}

#[sqlx::test]
async fn insert_path_admin_create_user_is_not_admin(pool: PgPool) {
    let users = Users::new(pool.clone());
    let id = created(&pool, "made").await;
    assert!(!users.is_admin(id).await.unwrap());
    assert!(!flag(&pool, "made").await);
}

#[sqlx::test]
async fn insert_path_enroll_inserts_no_row_and_keeps_the_flag(pool: PgPool) {
    let users = Users::new(pool.clone());
    let outcome = run(&pool, &AdminCommand::CreateUser("invitee".into()), "op")
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    let id = users
        .redeem_user_setup(outcome.setup_code.expose())
        .await
        .unwrap();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    assert!(!users.is_admin(id).await.unwrap());
}

#[sqlx::test]
async fn insert_path_bootstrap_user_is_not_admin(pool: PgPool) {
    let users = Users::new(pool.clone());
    let boot = users.bootstrap_user().await.unwrap();
    assert!(!users.is_admin(boot).await.unwrap());
}

#[sqlx::test]
async fn set_admin_grants_and_revokes_and_is_read_live(pool: PgPool) {
    let users = Users::new(pool.clone());
    let id = created(&pool, "alice").await;
    users.set_admin(id, true).await.unwrap();
    assert!(users.is_admin(id).await.unwrap());
    sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!users.is_admin(id).await.unwrap());
    users.set_admin(id, true).await.unwrap();
    users.set_admin(id, false).await.unwrap();
    assert!(!users.is_admin(id).await.unwrap());
}

#[sqlx::test]
async fn set_admin_refuses_bootstrap_before_sql_and_unknown_user(pool: PgPool) {
    let users = Users::new(pool.clone());
    let boot = users.bootstrap_user().await.unwrap();
    let result = users.set_admin(boot, true).await;
    assert!(matches!(result, Err(UserError::BootstrapNotAdmin)));
    assert!(!users.is_admin(boot).await.unwrap());
    users.set_admin(boot, false).await.unwrap();
    assert!(matches!(
        users.set_admin(i64::MAX, true).await,
        Err(UserError::NoSuchUser)
    ));
    assert!(!users.is_admin(i64::MAX).await.unwrap());
}

#[sqlx::test]
async fn set_admin_typed_refusal_holds_when_the_check_constraint_is_absent(pool: PgPool) {
    sqlx::query("ALTER TABLE users DROP CONSTRAINT users_bootstrap_not_admin")
        .execute(&pool)
        .await
        .unwrap();
    let users = Users::new(pool.clone());
    let boot = users.bootstrap_user().await.unwrap();
    assert!(matches!(
        users.set_admin(boot, true).await,
        Err(UserError::BootstrapNotAdmin)
    ));
    assert!(!users.is_admin(boot).await.unwrap());
}

#[sqlx::test]
async fn set_admin_waits_for_a_writer_holding_the_target_row(pool: PgPool) {
    let users = Users::new(pool.clone());
    let id = created(&pool, "locked").await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let racer = users.clone();
    let task = tokio::spawn(async move { racer.set_admin(id, true).await });
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(!task.is_finished());
    tx.commit().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(users.is_admin(id).await.unwrap());
}
