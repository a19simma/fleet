//! Audit rows for credential puts and deletes (ADR-0068). They need a Postgres superuser URL in
//! `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_server::cred::FileSealer;
use fleet_server::cred::store::{CredentialStore, StoreError};
use sqlx::PgPool;

const FGJ: &str = "0123456789abcdef0123456789abcdef01234567";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const HOST: &str = "git.example.com";
const STATIC: CredentialShape = CredentialShape::StaticSecret;

static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

fn key_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn key_paths_are_distinct_per_call() {
    assert_ne!(key_path("fleet-x"), key_path("fleet-x"));
}

fn store(pool: &PgPool) -> CredentialStore {
    let path = key_path("fleet-cred-audit");
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()))
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn host(pool: &PgPool) {
    sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
        .bind(HOST)
        .execute(pool)
        .await
        .unwrap();
}

async fn rows(pool: &PgPool) -> Vec<(i64, String, String, String, String)> {
    sqlx::query_as("SELECT user_id, host, kind, action, outcome FROM credential_audit ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

fn row(
    user: i64,
    host: &str,
    kind: &str,
    action: &str,
    outcome: &str,
) -> (i64, String, String, String, String) {
    (
        user,
        host.to_owned(),
        kind.to_owned(),
        action.to_owned(),
        outcome.to_owned(),
    )
}

async fn put_forgejo(store: &CredentialStore, user: i64) -> i64 {
    store
        .put_for_host(
            user,
            HOST,
            CredentialKind::ForgejoPat,
            STATIC,
            Secret::new(FGJ.into()),
            None,
            None,
        )
        .await
        .unwrap()
        .id
}

#[sqlx::test]
async fn a_put_writes_one_row_with_user_host_and_kind(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    host(&pool).await;
    put_forgejo(&store, alice).await;
    assert_eq!(
        rows(&pool).await,
        vec![row(alice, HOST, "forgejo_pat", "put", "stored")]
    );
    put_forgejo(&store, alice).await;
    assert_eq!(rows(&pool).await.len(), 2);
}

#[sqlx::test]
async fn a_github_put_is_audited_under_github_com(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    store
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
    assert_eq!(
        rows(&pool).await,
        vec![row(alice, "github.com", "github_pat", "put", "stored")]
    );
}

#[sqlx::test]
async fn a_refused_put_writes_no_row(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    let err = store
        .put_for_host(
            alice,
            HOST,
            CredentialKind::ForgejoPat,
            STATIC,
            Secret::new(FGJ.into()),
            None,
            None,
        )
        .await;
    assert!(matches!(err, Err(StoreError::HostUnknown)));
    assert_eq!(rows(&pool).await.len(), 0);
}

#[sqlx::test]
async fn a_delete_writes_one_removed_row(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    host(&pool).await;
    let id = put_forgejo(&store, alice).await;
    store.delete_for_host(alice, id, HOST).await.unwrap();
    assert_eq!(
        rows(&pool).await,
        vec![
            row(alice, HOST, "forgejo_pat", "put", "stored"),
            row(alice, HOST, "forgejo_pat", "delete", "removed"),
        ]
    );
}

#[sqlx::test]
async fn a_refused_delete_writes_no_row(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    host(&pool).await;
    let id = put_forgejo(&store, alice).await;
    let err = store.delete_for_host(alice, id, "").await;
    assert!(matches!(err, Err(StoreError::HostInvalid(_))));
    let err = store.delete_for_host(alice, id + 1, HOST).await;
    assert!(matches!(err, Err(StoreError::NotFound)));
    assert_eq!(rows(&pool).await.len(), 1);
}

#[sqlx::test]
async fn deleting_a_credential_with_mint_history_audits_a_tombstone(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    let id = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap()
        .id;
    sqlx::query(
        "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
         installation_id, requested_permissions, outcome) \
         VALUES (gen_random_uuid(), gen_random_uuid(), $1, 'job', 'o/r', '42', 'contents:read', 'attempt')",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    store.delete(alice, id).await.unwrap();
    assert_eq!(
        rows(&pool).await.last().cloned(),
        Some(row(
            alice,
            "github.com",
            "github_pat",
            "delete",
            "tombstoned"
        ))
    );
}

#[sqlx::test]
async fn audit_rows_never_hold_the_value(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    host(&pool).await;
    let id = put_forgejo(&store, alice).await;
    store.delete_for_host(alice, id, HOST).await.unwrap();
    let dump: String =
        sqlx::query_scalar("SELECT string_agg(t::text, ' ') FROM credential_audit t")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!dump.contains(FGJ));
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code().map(std::borrow::Cow::into_owned))
        .unwrap_or_default()
}

#[sqlx::test]
async fn the_table_is_insert_only(pool: PgPool) {
    let store = store(&pool);
    let alice = user(&pool, "alice").await;
    host(&pool).await;
    put_forgejo(&store, alice).await;
    let update = sqlx::query("UPDATE credential_audit SET outcome = 'removed'")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&update), "23001");
    let delete = sqlx::query("DELETE FROM credential_audit")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&delete), "23001");
    let truncate = sqlx::query("TRUNCATE credential_audit")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&truncate), "23001");
    assert_eq!(rows(&pool).await.len(), 1);
}

#[sqlx::test]
async fn each_column_rejects_a_bad_value_by_constraint_name(pool: PgPool) {
    let insert = |host: String, action: &'static str, outcome: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO credential_audit (user_id, host, kind, action, outcome) \
                 VALUES (1, $1, 'forgejo_pat', $2, $3)",
            )
            .bind(host)
            .bind(action)
            .bind(outcome)
            .execute(&pool)
            .await
        }
    };
    insert(HOST.to_owned(), "put", "stored").await.unwrap();
    for (host, action, outcome, name) in [
        (
            String::new(),
            "put",
            "stored",
            "credential_audit_host_check",
        ),
        (
            "a".repeat(254),
            "put",
            "stored",
            "credential_audit_host_check",
        ),
        (
            HOST.to_owned(),
            "read",
            "stored",
            "credential_audit_action_check",
        ),
        (
            HOST.to_owned(),
            "put",
            "refused",
            "credential_audit_outcome_check",
        ),
    ] {
        let err = insert(host, action, outcome).await.unwrap_err();
        assert_eq!(
            err.as_database_error().and_then(|e| e.constraint()),
            Some(name)
        );
    }
}
