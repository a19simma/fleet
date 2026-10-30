//! The per-user credential cap holds under concurrent puts. The tests need a Postgres superuser
//! URL in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_server::cred::FileSealer;
use fleet_server::cred::store::{CredentialStore, StoreError};
use fleet_server::store::Store;
use sqlx::PgPool;

const KEYS: [(CredentialKind, &str); 4] = [
    (
        CredentialKind::AnthropicApiKey,
        "sk-ant-api03-abcdefghijklmnopqrstuv",
    ),
    (
        CredentialKind::ClaudeSubscriptionToken,
        "sk-ant-oat01-abcdefghijklmnopqrstuv",
    ),
    (
        CredentialKind::GithubPat,
        "github_pat_11ABCDEFG0abcdefghijklmnop",
    ),
    (
        CredentialKind::CodexApiKey,
        "sk-abcdefghijklmnopqrstuvwxyz0123",
    ),
];

static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

async fn store(pool: &PgPool, cap: usize) -> CredentialStore {
    Store::new(pool.clone()).migrate().await.unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-cred-cap-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    CredentialStore::with_limit(pool.clone(), Arc::new(sealer.unwrap()), cap)
}

async fn user(pool: &PgPool) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn concurrent_puts_never_pass_the_cap(pool: PgPool) {
    let store = store(&pool, 2).await;
    let uid = user(&pool).await;
    let mut tasks = Vec::new();
    for (kind, value) in KEYS {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put(
                    uid,
                    kind,
                    CredentialShape::StaticSecret,
                    Secret::new(value.to_owned()),
                    None,
                    None,
                )
                .await
        }));
    }
    let mut refused = 0;
    for task in tasks {
        if matches!(task.await.unwrap(), Err(StoreError::TooMany)) {
            refused += 1;
        }
    }
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 2);
    assert_eq!(refused, 2);
}

#[sqlx::test]
async fn replacing_a_kind_at_the_cap_is_allowed(pool: PgPool) {
    let store = store(&pool, 1).await;
    let uid = user(&pool).await;
    let (kind, value) = KEYS[0];
    for _ in 0..2 {
        store
            .put(
                uid,
                kind,
                CredentialShape::StaticSecret,
                Secret::new(value.to_owned()),
                None,
                None,
            )
            .await
            .unwrap();
    }
    let (other, other_value) = KEYS[1];
    let err = store
        .put(
            uid,
            other,
            CredentialShape::StaticSecret,
            Secret::new(other_value.to_owned()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::TooMany));
}
