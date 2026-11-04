//! Schema tests for migration 0028: `users.is_admin` and the widened `admin_audit` actions.
//! They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_server::cred::admin::{AdminCommand, run};
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;

const ADMIN_VERSION: i64 = 28;

async fn migrate_before(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < ADMIN_VERSION)
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

fn code(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
}

fn constraint(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        .map(str::to_owned)
}

async fn audit(pool: &PgPool, action: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_audit (action, user_id, username, operator) VALUES ($1, 1, 'u', 'op')",
    )
    .bind(action)
    .execute(pool)
    .await
    .map(drop)
}

#[sqlx::test(migrations = false)]
async fn rows_written_by_the_previous_release_survive_with_no_admin(pool: PgPool) {
    migrate_before(&pool).await;
    run(&pool, &AdminCommand::CreateUser("alice".into()), "op")
        .await
        .unwrap();
    run(&pool, &AdminCommand::CreateUser("bob".into()), "op")
        .await
        .unwrap();
    run(&pool, &AdminCommand::ResetPasskeys("alice".into()), "op")
        .await
        .unwrap();
    sqlx::query_scalar::<_, i64>("SELECT bootstrap_user_id()")
        .fetch_one(&pool)
        .await
        .unwrap();
    migrate_rest(&pool).await;
    let users: Vec<(String, bool)> =
        sqlx::query_as("SELECT username, is_admin FROM users ORDER BY username")
            .fetch_all(&pool)
            .await
            .unwrap();
    let expected = |n: &str| (n.to_owned(), false);
    assert_eq!(
        users,
        vec![expected("alice"), expected("bob"), expected("bootstrap")]
    );
    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM admin_audit ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(actions, vec!["user_create", "user_create", "passkey_reset"]);
}

#[sqlx::test]
async fn a_new_user_is_not_admin(pool: PgPool) {
    let admin: bool =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('carol') RETURNING is_admin")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!admin);
}

#[sqlx::test]
async fn is_admin_is_not_null(pool: PgPool) {
    sqlx::query("INSERT INTO users (username) VALUES ('carol')")
        .execute(&pool)
        .await
        .unwrap();
    let err = sqlx::query("UPDATE users SET is_admin = NULL")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err).as_deref(), Some("23502"));
}

#[sqlx::test]
async fn an_ordinary_user_can_be_made_admin(pool: PgPool) {
    sqlx::query("INSERT INTO users (username) VALUES ('carol')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_admin = true WHERE username = 'carol'")
        .execute(&pool)
        .await
        .unwrap();
}

#[sqlx::test]
async fn bootstrap_cannot_be_inserted_as_admin_in_any_letter_case(pool: PgPool) {
    for name in ["bootstrap", "Bootstrap", "BOOTSTRAP"] {
        let err = sqlx::query("INSERT INTO users (username, is_admin) VALUES ($1, true)")
            .bind(name)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(code(&err).as_deref(), Some("23514"));
        assert_eq!(
            constraint(&err).as_deref(),
            Some("users_bootstrap_not_admin")
        );
    }
}

#[sqlx::test]
async fn the_bootstrap_user_cannot_be_promoted(pool: PgPool) {
    sqlx::query_scalar::<_, i64>("SELECT bootstrap_user_id()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let err = sqlx::query("UPDATE users SET is_admin = true WHERE lower(username) = 'bootstrap'")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        constraint(&err).as_deref(),
        Some("users_bootstrap_not_admin")
    );
    let admins: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE is_admin")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(admins, 0);
}

#[sqlx::test]
async fn admin_audit_accepts_every_action(pool: PgPool) {
    for action in [
        "user_create",
        "passkey_reset",
        "bootstrap_password_revoked",
        "admin_grant",
        "admin_revoke",
    ] {
        audit(&pool, action).await.unwrap();
    }
}

#[sqlx::test]
async fn admin_audit_still_rejects_an_unknown_action(pool: PgPool) {
    for action in ["admin_promote", "ADMIN_GRANT", ""] {
        let err = audit(&pool, action).await.unwrap_err();
        assert_eq!(code(&err).as_deref(), Some("23514"));
        assert_eq!(
            constraint(&err).as_deref(),
            Some("admin_audit_action_check")
        );
    }
}
