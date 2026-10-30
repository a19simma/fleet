//! Credential store tests. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

use std::sync::Arc;

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_server::cred::FileSealer;
use fleet_server::cred::github::MAX_EXPIRY_MS;
use fleet_server::cred::store::{CredentialStore, StoreError};
use fleet_server::cred::users::{UserError, Users};
use sqlx::PgPool;

const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const PAT2: &str = "github_pat_22ZYXWVUT9zyxwvutsrqponmlk";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const STATIC: CredentialShape = CredentialShape::StaticSecret;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn store(pool: &PgPool, tag: &str) -> Res<CredentialStore> {
    let path = std::env::temp_dir().join(format!(
        "fleet-cred-store-{}-{tag}.keys",
        std::process::id()
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32)))?;
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path)?;
    Ok(CredentialStore::new(pool.clone(), Arc::new(sealer?)))
}

async fn user(pool: &PgPool, name: &str) -> Res<i64> {
    Ok(
        sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(pool)
            .await?,
    )
}

#[sqlx::test]
async fn list_returns_fingerprint_login_and_expiry_only(pool: PgPool) {
    let store = store(&pool, "list").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            Some("octo".into()),
            Some(1_900_000_000_000),
        )
        .await
        .unwrap();
    let listed = store.list(alice).await.unwrap();
    assert_eq!(listed, vec![put.clone()]);
    assert_eq!(put.kind, CredentialKind::GithubPat);
    assert_eq!(put.login.as_deref(), Some("octo"));
    assert_eq!(put.expires_at_ms, Some(1_900_000_000_000));
    assert_eq!(put.fingerprint.len(), 12);
    assert!(!format!("{put:?}").contains(PAT));
}

#[sqlx::test]
async fn put_replaces_the_credential_of_one_kind(pool: PgPool) {
    let store = store(&pool, "upsert").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let first = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let second = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT2.into()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_ne!(first.fingerprint, second.fingerprint);
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
    let opened = store.open_for_use(alice, second.id, "job-1").await.unwrap();
    assert_eq!(opened.expose(), PAT2.as_bytes());
}

#[sqlx::test]
async fn put_rejects_an_invalid_value(pool: PgPool) {
    let store = store(&pool, "invalid").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let err = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new("short".into()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Invalid(_)));
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
}

#[sqlx::test]
async fn put_rejects_an_expiry_outside_the_range(pool: PgPool) {
    let store = store(&pool, "expiry").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    for ms in [-1, MAX_EXPIRY_MS + 1, i64::MAX, i64::MIN] {
        let err = store
            .put(
                alice,
                CredentialKind::AnthropicApiKey,
                STATIC,
                Secret::new(ANT.into()),
                None,
                Some(ms),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidExpiry), "{ms}");
    }
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
    for ms in [0, MAX_EXPIRY_MS] {
        store
            .put(
                alice,
                CredentialKind::AnthropicApiKey,
                STATIC,
                Secret::new(ANT.into()),
                None,
                Some(ms),
            )
            .await
            .unwrap();
    }
}

#[sqlx::test]
async fn open_for_use_writes_one_credential_use_row(pool: PgPool) {
    let store = store(&pool, "use").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::AnthropicApiKey,
            STATIC,
            Secret::new(ANT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let opened = store.open_for_use(alice, put.id, "job-7").await.unwrap();
    assert_eq!(opened.expose(), ANT.as_bytes());
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT credential_id, job_id FROM credential_use")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![(put.id, "job-7".to_owned())]);
}

#[sqlx::test]
async fn a_user_cannot_read_or_delete_another_users_credential(pool: PgPool) {
    let store = store(&pool, "owner").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let read = store.open_for_use(bob, put.id, "job-1").await.unwrap_err();
    let del = store.delete(bob, put.id).await.unwrap_err();
    let missing = store
        .open_for_use(bob, put.id + 1000, "job-1")
        .await
        .unwrap_err();
    assert!(matches!(read, StoreError::NotFound));
    assert!(matches!(del, StoreError::NotFound));
    assert_eq!(read.to_string(), missing.to_string());
    assert_eq!(store.list(bob).await.unwrap().len(), 0);
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
    let uses: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(uses, 0);
}

#[sqlx::test]
async fn delete_is_final_and_keeps_use_rows(pool: PgPool) {
    let store = store(&pool, "delete").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    store.open_for_use(alice, put.id, "job-1").await.unwrap();
    store.delete(alice, put.id).await.unwrap();
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
    assert!(matches!(
        store
            .open_for_use(alice, put.id, "job-2")
            .await
            .unwrap_err(),
        StoreError::NotFound
    ));
    assert!(matches!(
        store.delete(alice, put.id).await.unwrap_err(),
        StoreError::NotFound
    ));
    let uses: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(uses, 1);
}

#[sqlx::test]
async fn database_holds_no_plaintext(pool: PgPool) {
    let store = store(&pool, "dump").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            Some("octo".into()),
            None,
        )
        .await
        .unwrap();
    store.open_for_use(alice, put.id, "job-1").await.unwrap();
    let dumps = [
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM users t",
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM credentials t",
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM credential_use t",
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM jobs t",
    ];
    for query in dumps {
        let dump: String = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
        assert!(!dump.contains(PAT), "{query}");
        assert!(!dump.contains("11ABCDEFG0"), "{query}");
    }
    let blob: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!blob.windows(PAT.len()).any(|w| w == PAT.as_bytes()));
}

#[sqlx::test]
async fn api_token_is_stored_as_hash_and_shown_once(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    let made = users.create_api_token(alice, "cli").await.unwrap();
    let plain = made.token.expose().to_vec();
    assert!(!format!("{made:?}").contains(std::str::from_utf8(&plain).unwrap()));
    let hashed: bool = sqlx::query_scalar(
        "SELECT hash = sha256($1::bytea) AND position($1::bytea IN hash) = 0 \
         FROM api_tokens WHERE id = $2",
    )
    .bind(&plain)
    .bind(made.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(hashed);
    assert_eq!(users.authenticate(&plain).await.unwrap(), Some(alice));
    assert_eq!(users.authenticate(b"flt_wrong").await.unwrap(), None);
    assert!(matches!(
        users.revoke_api_token(bob, made.id).await,
        Err(UserError::NotFound)
    ));
    assert_eq!(users.authenticate(&plain).await.unwrap(), Some(alice));
    users.revoke_api_token(alice, made.id).await.unwrap();
    assert_eq!(users.authenticate(&plain).await.unwrap(), None);
    assert!(matches!(
        users.revoke_api_token(alice, made.id).await,
        Err(UserError::NotFound)
    ));
}

#[sqlx::test]
async fn setup_code_is_single_use_and_ignores_the_bootstrap_user(pool: PgPool) {
    let users = Users::new(pool.clone());
    let boot = users.bootstrap_user().await.unwrap();
    assert_eq!(users.bootstrap_user().await.unwrap(), boot);
    assert!(!users.has_real_users().await.unwrap());
    let code = users.issue_setup_code().await.unwrap().unwrap();
    let code = code.expose().to_vec();
    assert!(matches!(
        users.redeem_setup(b"wrong", "admin").await,
        Err(UserError::BadSetupCode)
    ));
    assert!(matches!(
        users.redeem_setup(&code, "Bootstrap").await,
        Err(UserError::ReservedUsername)
    ));
    assert!(matches!(
        users.redeem_setup(&code, "bad name").await,
        Err(UserError::InvalidUsername)
    ));
    let admin = users.redeem_setup(&code, "admin").await.unwrap();
    assert_ne!(admin, boot);
    assert!(users.has_real_users().await.unwrap());
    assert!(matches!(
        users.redeem_setup(&code, "other").await,
        Err(UserError::BadSetupCode)
    ));
    assert!(users.issue_setup_code().await.unwrap().is_none());
}

#[sqlx::test]
async fn setup_is_inert_once_any_user_exists(pool: PgPool) {
    let users = Users::new(pool.clone());
    let code = users.issue_setup_code().await.unwrap().unwrap();
    user(&pool, "alice").await.unwrap();
    assert!(matches!(
        users.redeem_setup(code.expose(), "admin").await,
        Err(UserError::SetupClosed)
    ));
    assert!(matches!(
        users.redeem_setup(code.expose(), "admin").await,
        Err(UserError::BadSetupCode)
    ));
    let fresh = Users::new(pool);
    assert!(fresh.issue_setup_code().await.unwrap().is_none());
}
