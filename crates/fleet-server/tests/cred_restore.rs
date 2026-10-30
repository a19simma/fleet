//! Restore tests for the credential store (ADR-0040): a database restored without the master
//! key cannot read credentials, and one restored with the key can. They need a Postgres
//! superuser URL in `DATABASE_URL` (port 55606 in the Ralph lane), which `#[sqlx::test]` reads.
//! The restore is a row copy of `users` and `credentials` into a second migrated database, not a
//! `pg_dump` and `pg_restore`. Each run names its database by process id, tag and counter, and a
//! guard drops it with `DROP DATABASE ... WITH (FORCE)` even when an assertion panics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_server::config::{CredentialsStartError, CredentialsState};
use fleet_server::cred::store::{CredentialStore, StoreError};
use fleet_server::cred::{FileSealer, KeyRingError, SealError};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn ring(tag: &str, text: &str) -> Res<FileSealer> {
    let path = std::env::temp_dir().join(format!(
        "fleet-cred-restore-{}-{tag}.keys",
        std::process::id()
    ));
    std::fs::write(&path, text)?;
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path)?;
    Ok(sealer?)
}

fn key_line(id: &str, byte: &str) -> String {
    format!("{id}:{}\n", byte.repeat(32))
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A restored database that is dropped, with its connections, when the guard goes out of scope.
struct Restored {
    pool: PgPool,
    name: String,
    admin: PgConnectOptions,
}

impl Drop for Restored {
    fn drop(&mut self) {
        let name = self.name.clone();
        let admin = self.admin.clone();
        let cleanup = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                let Ok(pool) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect_with(admin)
                    .await
                else {
                    return;
                };
                let drop_sql = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
                let _ = sqlx::query(sqlx::AssertSqlSafe(drop_sql))
                    .execute(&pool)
                    .await;
                pool.close().await;
            });
        });
        let _ = cleanup.join();
    }
}

async fn restore_into_new_database(source: &PgPool, tag: &str) -> Res<Restored> {
    let name = format!(
        "fleet_restore_{}_{tag}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let name = name.as_str();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(source)
        .await?;
    let admin = source.connect_options().as_ref().clone();
    let options = admin.clone().database(name);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await?;
    let restored = Restored {
        pool,
        name: name.to_owned(),
        admin,
    };
    let target = restored.pool.clone();
    sqlx::migrate!("./migrations").run(&target).await?;
    let users = sqlx::query("SELECT id, username FROM users")
        .fetch_all(source)
        .await?;
    for row in users {
        sqlx::query("INSERT INTO users (id, username) OVERRIDING SYSTEM VALUE VALUES ($1, $2)")
            .bind(row.try_get::<i64, _>("id")?)
            .bind(row.try_get::<String, _>("username")?)
            .execute(&target)
            .await?;
    }
    let creds = sqlx::query(
        "SELECT id, user_id, kind, shape, ciphertext, key_id, fingerprint FROM credentials",
    )
    .fetch_all(source)
    .await?;
    for row in creds {
        sqlx::query(
            "INSERT INTO credentials (id, user_id, kind, shape, ciphertext, key_id, fingerprint) \
             OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(row.try_get::<i64, _>("id")?)
        .bind(row.try_get::<i64, _>("user_id")?)
        .bind(row.try_get::<String, _>("kind")?)
        .bind(row.try_get::<String, _>("shape")?)
        .bind(row.try_get::<Vec<u8>, _>("ciphertext")?)
        .bind(row.try_get::<String, _>("key_id")?)
        .bind(row.try_get::<String, _>("fingerprint")?)
        .execute(&target)
        .await?;
    }
    Ok(restored)
}

async fn seeded(pool: &PgPool, sealer: FileSealer) -> Res<(i64, i64)> {
    let user: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(pool)
            .await?;
    let store = CredentialStore::new(pool.clone(), Arc::new(sealer));
    let put = store
        .put(
            user,
            CredentialKind::GithubPat,
            CredentialShape::StaticSecret,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await?;
    Ok((user, put.id))
}

#[sqlx::test]
async fn dump_with_the_key_reads_the_credential(pool: PgPool) {
    let key = key_line("k1", "ab");
    let (user, id) = seeded(&pool, ring("a1", &key).unwrap()).await.unwrap();
    let restored = restore_into_new_database(&pool, "with_key").await.unwrap();
    let store = CredentialStore::new(restored.pool.clone(), Arc::new(ring("a2", &key).unwrap()));
    let secret = store.open_for_use(user, id, "job-1").await.unwrap();
    assert_eq!(secret.expose(), PAT.as_bytes());
}

#[sqlx::test]
async fn dump_with_a_different_key_cannot_read_the_credential(pool: PgPool) {
    let (user, id) = seeded(&pool, ring("b1", &key_line("k1", "ab")).unwrap())
        .await
        .unwrap();
    let restored = restore_into_new_database(&pool, "wrong_key").await.unwrap();
    let other = ring("b2", &key_line("k1", "cd")).unwrap();
    let store = CredentialStore::new(restored.pool.clone(), Arc::new(other));
    let err = store.open_for_use(user, id, "job-1").await.unwrap_err();
    assert!(matches!(err, StoreError::Seal(SealError::Open)));
    let unknown = ring("b3", &key_line("k9", "ef")).unwrap();
    let store = CredentialStore::new(restored.pool.clone(), Arc::new(unknown));
    let err = store.open_for_use(user, id, "job-1").await.unwrap_err();
    assert!(matches!(err, StoreError::Seal(SealError::UnknownKey)));
    let uses: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&restored.pool)
        .await
        .unwrap();
    assert_eq!(uses, 0);
}

#[sqlx::test]
async fn dump_with_no_key_file_stops_startup(pool: PgPool) {
    seeded(&pool, ring("c1", &key_line("k1", "ab")).unwrap())
        .await
        .unwrap();
    let restored = restore_into_new_database(&pool, "no_key").await.unwrap();
    let rows_exist: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM credentials)")
        .fetch_one(&restored.pool)
        .await
        .unwrap();
    assert!(rows_exist);
    assert!(matches!(
        CredentialsState::resolve(None, rows_exist),
        Err(CredentialsStartError::RowsWithoutKey)
    ));
    let missing = std::env::temp_dir().join("fleet-cred-restore-no-such-key");
    assert!(matches!(
        CredentialsState::resolve(Some(&missing), rows_exist),
        Err(CredentialsStartError::KeyRing(KeyRingError::Missing))
    ));
}
