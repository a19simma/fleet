//! Per-Box token storage (ADR-0069). They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_core::BoxName;
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::{
    BoxTokenLabel, BoxTokenTtl, MAX_ACTIVE_BOX_TOKENS, UserError, Users,
};
use sqlx::PgPool;

async fn user(pool: &PgPool, name: &str) -> i64 {
    run(pool, &AdminCommand::CreateUser(name.into()), "op")
        .await
        .unwrap()
        .user_id
}

fn name(n: u32) -> BoxName {
    BoxName::new(&format!("box-{n}")).unwrap()
}

fn label() -> BoxTokenLabel {
    BoxTokenLabel::new("laptop").unwrap()
}

fn ttl() -> BoxTokenTtl {
    BoxTokenTtl::default()
}

#[sqlx::test]
async fn issued_token_has_prefix_and_resolves_to_user_and_box(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let issued = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    let plain = String::from_utf8(issued.token.expose().to_vec()).unwrap();
    assert!(plain.starts_with("fbx_"));
    assert_eq!(plain.len(), 4 + 64);
    assert!(
        plain[4..]
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    );
    let owner = users
        .resolve_box_token(plain.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.token_id, issued.id);
    assert_eq!(owner.user_id, alice);
    assert_eq!(owner.box_name, name(1).as_str());
    let stored: Vec<u8> = sqlx::query_scalar("SELECT hash FROM box_tokens WHERE id = $1")
        .bind(issued.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, plain.as_bytes());
    assert_eq!(stored.len(), 32);
}

#[sqlx::test]
async fn default_ttl_is_90_days_and_max_is_365(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let issued = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    let days: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - created_at)::float8 / 86400 FROM box_tokens WHERE id = $1",
    )
    .bind(issued.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!((days - 90.0).abs() < 0.01, "{days}");
    assert!(BoxTokenTtl::new(365).is_ok());
    assert!(matches!(BoxTokenTtl::new(0), Err(UserError::InvalidTtl)));
    assert!(matches!(BoxTokenTtl::new(366), Err(UserError::InvalidTtl)));
    assert!(matches!(
        BoxTokenTtl::new(u32::MAX),
        Err(UserError::InvalidTtl)
    ));
}

#[sqlx::test]
async fn expired_revoked_and_unknown_tokens_do_not_resolve(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let expired = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    sqlx::query("UPDATE box_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(expired.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        users
            .resolve_box_token(expired.token.expose())
            .await
            .unwrap()
            .is_none()
    );
    let revoked = users
        .issue_box_token(alice, &name(2), &label(), ttl())
        .await
        .unwrap();
    users.revoke_box_token(alice, revoked.id).await.unwrap();
    assert!(
        users
            .resolve_box_token(revoked.token.expose())
            .await
            .unwrap()
            .is_none()
    );
    for hostile in [&b""[..], b"fbx_", b"fbx_00", b"flt_abc", b"\xff\xfe"] {
        assert!(users.resolve_box_token(hostile).await.unwrap().is_none());
    }
}

#[sqlx::test]
async fn an_active_box_name_is_unique_across_users(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    for who in [alice, bob] {
        assert!(matches!(
            users.issue_box_token(who, &name(1), &label(), ttl()).await,
            Err(UserError::BoxNameTaken)
        ));
    }
}

#[sqlx::test]
async fn revoked_and_expired_tokens_free_the_name(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let first = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    users.revoke_box_token(alice, first.id).await.unwrap();
    let second = users
        .issue_box_token(bob, &name(1), &label(), ttl())
        .await
        .unwrap();
    sqlx::query("UPDATE box_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(second.id)
        .execute(&pool)
        .await
        .unwrap();
    users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_user_holds_at_most_the_cap_of_active_tokens(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let mut first = 0;
    for n in 0..MAX_ACTIVE_BOX_TOKENS {
        let id = users
            .issue_box_token(alice, &name(u32::try_from(n).unwrap() + 1), &label(), ttl())
            .await
            .unwrap()
            .id;
        if n == 0 {
            first = id;
        }
    }
    let over = name(u32::try_from(MAX_ACTIVE_BOX_TOKENS).unwrap() + 1);
    assert!(matches!(
        users.issue_box_token(alice, &over, &label(), ttl()).await,
        Err(UserError::TooManyBoxTokens)
    ));
    users
        .issue_box_token(bob, &over, &label(), ttl())
        .await
        .unwrap();
    users.revoke_box_token(alice, first).await.unwrap();
    users
        .issue_box_token(alice, &name(999), &label(), ttl())
        .await
        .unwrap();
}

#[sqlx::test]
async fn revoke_is_owner_scoped(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let issued = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    assert!(matches!(
        users.revoke_box_token(bob, issued.id).await,
        Err(UserError::NotFound)
    ));
    assert!(
        users
            .resolve_box_token(issued.token.expose())
            .await
            .unwrap()
            .is_some()
    );
    users.revoke_box_token(alice, issued.id).await.unwrap();
    assert!(matches!(
        users.revoke_box_token(alice, issued.id).await,
        Err(UserError::NotFound)
    ));
}

#[sqlx::test]
async fn list_shows_only_the_users_tokens_without_secrets(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    users
        .issue_box_token(bob, &name(2), &label(), ttl())
        .await
        .unwrap();
    let rows = users.list_box_tokens(alice).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].box_name, name(1).as_str());
    assert_eq!(rows[0].label, "laptop");
}

#[sqlx::test]
async fn last_used_is_written_once_a_minute(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let issued = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    let read = || async {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT last_used_at::text FROM box_tokens WHERE id = $1",
        )
        .bind(issued.id)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    assert!(read().await.is_none());
    users
        .resolve_box_token(issued.token.expose())
        .await
        .unwrap();
    let first = read().await.unwrap();
    users
        .resolve_box_token(issued.token.expose())
        .await
        .unwrap();
    assert_eq!(read().await.unwrap(), first);
    sqlx::query("UPDATE box_tokens SET last_used_at = now() - interval '2 minutes' WHERE id = $1")
        .bind(issued.id)
        .execute(&pool)
        .await
        .unwrap();
    users
        .resolve_box_token(issued.token.expose())
        .await
        .unwrap();
    let later: bool = sqlx::query_scalar(
        "SELECT last_used_at > now() - interval '1 minute' FROM box_tokens WHERE id = $1",
    )
    .bind(issued.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(later);
}

#[sqlx::test]
async fn issue_and_revoke_write_audit_rows_and_audit_is_insert_only(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let issued = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    users.revoke_box_token(alice, issued.id).await.unwrap();
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM box_token_audit WHERE user_id = $1 ORDER BY id")
            .bind(alice)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(actions, ["issue", "revoke"]);
    for sql in [
        "UPDATE box_token_audit SET action = 'issue'",
        "DELETE FROM box_token_audit",
        "TRUNCATE box_token_audit",
    ] {
        assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{sql}");
    }
}

#[sqlx::test]
async fn reset_passkeys_revokes_box_tokens_and_audits(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let mine = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    let theirs = users
        .issue_box_token(bob, &name(2), &label(), ttl())
        .await
        .unwrap();
    run(&pool, &AdminCommand::ResetPasskeys("alice".into()), "op")
        .await
        .unwrap();
    assert!(
        users
            .resolve_box_token(mine.token.expose())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        users
            .resolve_box_token(theirs.token.expose())
            .await
            .unwrap()
            .is_some()
    );
    let resets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM box_token_audit WHERE user_id = $1 AND action = 'reset'",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(resets, 1);
}

#[test]
fn labels_are_validated() {
    for ok in ["", "laptop", &"x".repeat(64), "caf\u{e9}"] {
        assert!(BoxTokenLabel::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        &"x".repeat(65),
        "a\nb",
        "a\rb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\0b",
        "a\u{202e}b",
        "a\u{200b}b",
    ] {
        assert!(
            matches!(BoxTokenLabel::new(bad), Err(UserError::InvalidLabel)),
            "{bad:?}"
        );
    }
}

#[sqlx::test]
async fn closing_an_expired_token_audits_expired_and_lists_it_unrevoked(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let old = users
        .issue_box_token(alice, &name(1), &label(), ttl())
        .await
        .unwrap();
    sqlx::query("UPDATE box_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(old.id)
        .execute(&pool)
        .await
        .unwrap();
    users
        .issue_box_token(bob, &name(1), &label(), ttl())
        .await
        .unwrap();
    let audit: Vec<(i64, i64, String, String)> = sqlx::query_as(
        "SELECT token_id, user_id, box_name, action FROM box_token_audit \
         WHERE action = 'expired' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit,
        [(
            old.id,
            alice,
            name(1).as_str().to_owned(),
            "expired".to_owned()
        )]
    );
    let rows = users.list_box_tokens(alice).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].revoked_at, None);
    users.revoke_box_token(alice, rows[0].id).await.unwrap_err();
    let revoked = users
        .issue_box_token(alice, &name(2), &label(), ttl())
        .await
        .unwrap();
    users.revoke_box_token(alice, revoked.id).await.unwrap();
    let rows = users.list_box_tokens(alice).await.unwrap();
    assert!(
        rows.iter()
            .find(|r| r.id == revoked.id)
            .unwrap()
            .revoked_at
            .is_some()
    );
}
