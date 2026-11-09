//! Environment secret sealing tests (ADR-0067). They need a Postgres superuser URL in
//! `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::{Arc, Mutex};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret, fingerprint};
use fleet_core::environment::{EntryName, EnvironmentName, SecretValue};
use fleet_server::cred::seal::{Aad, FileSealer, SealError, Sealed, Sealer};
use fleet_server::cred::store::CredentialStore;
use fleet_server::environments::{EnvError, EnvironmentStore};
use sqlx::PgPool;
use zeroize::Zeroizing;

const VALUE: &str = "pve-token-Zk93abQ7xw";
const OTHER: &str = "pve-token-Mm41cdR8yz";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";

fn key_line(id: &str, byte: &str) -> String {
    format!("{id}:{}\n", byte.repeat(32))
}

fn sealer(tag: &str, lines: &[(&str, &str)]) -> FileSealer {
    let path =
        std::env::temp_dir().join(format!("fleet-env-store-{}-{tag}.keys", std::process::id()));
    let text: String = lines.iter().map(|(id, b)| key_line(id, b)).collect();
    std::fs::write(&path, text).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

fn store(pool: &PgPool, tag: &str) -> EnvironmentStore {
    EnvironmentStore::new(pool.clone(), Arc::new(sealer(tag, &[("k1", "ab")])))
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn env_name(raw: &str) -> EnvironmentName {
    EnvironmentName::new(raw).unwrap()
}

fn entry(raw: &str) -> EntryName {
    EntryName::new(raw).unwrap()
}

fn value(raw: &str) -> SecretValue {
    SecretValue::new(raw.to_owned()).unwrap()
}

async fn ciphertext_row(pool: &PgPool, env: i64, name: &str) -> Option<(Vec<u8>, String, String)> {
    sqlx::query_as(
        "SELECT ciphertext, key_id, fingerprint FROM environment_secret \
         WHERE environment_id = $1 AND name = $2",
    )
    .bind(env)
    .bind(name)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[sqlx::test]
async fn a_secret_round_trips_and_only_its_fingerprint_is_readable(pool: PgPool) {
    let store = store(&pool, "round");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let put = store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    let opened = store
        .open_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap();
    assert_eq!(opened.as_slice(), VALUE.as_bytes());
    let (cipher, key_id, stored_fp) = ciphertext_row(&pool, env, "TOKEN").await.unwrap();
    assert_eq!(key_id, "k1");
    assert_eq!(stored_fp, put);
    assert_eq!(put, fingerprint(&Secret::new(VALUE.to_owned())));
    assert!(!cipher.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
}

#[sqlx::test]
async fn a_second_put_replaces_the_value_and_the_fingerprint(pool: PgPool) {
    let store = store(&pool, "replace");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let first = store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    let second = store
        .put_secret(alice, env, &entry("TOKEN"), &value(OTHER))
        .await
        .unwrap();
    assert_ne!(first, second);
    let opened = store
        .open_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap();
    assert_eq!(opened.as_slice(), OTHER.as_bytes());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM environment_secret")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

#[sqlx::test]
async fn an_unknown_or_foreign_environment_and_a_wrong_name_are_not_found(pool: PgPool) {
    let store = store(&pool, "scope");
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    for (who, id, name) in [
        (bob, env, "TOKEN"),
        (alice, env + 100, "TOKEN"),
        (alice, env, "OTHER"),
        (alice, env, "token"),
    ] {
        let err = store.open_secret(who, id, &entry(name)).await.unwrap_err();
        assert_eq!(err, EnvError::NotFound, "{who} {id} {name}");
    }
    let put = store
        .put_secret(bob, env, &entry("TOKEN"), &value(OTHER))
        .await;
    assert_eq!(put.unwrap_err(), EnvError::NotFound);
    let opened = store
        .open_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap();
    assert_eq!(opened.as_slice(), VALUE.as_bytes());
}

#[sqlx::test]
async fn a_ciphertext_moved_to_another_user_env_or_name_does_not_open(pool: PgPool) {
    let store = store(&pool, "moved");
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let other_env = store
        .create_environment(alice, &env_name("dev"))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    let (cipher, key_id, fp) = ciphertext_row(&pool, env, "TOKEN").await.unwrap();
    for (target_env, name) in [(other_env, "TOKEN"), (env, "RENAMED")] {
        sqlx::query(
            "INSERT INTO environment_secret (environment_id, name, ciphertext, key_id, fingerprint) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(target_env)
        .bind(name)
        .bind(&cipher)
        .bind(&key_id)
        .bind(&fp)
        .execute(&pool)
        .await
        .unwrap();
        let err = store
            .open_secret(alice, target_env, &entry(name))
            .await
            .unwrap_err();
        assert_eq!(err, EnvError::Open, "{target_env} {name}");
    }
    sqlx::query("UPDATE environment SET user_id = $1 WHERE id = $2")
        .bind(bob)
        .bind(env)
        .execute(&pool)
        .await
        .unwrap();
    let err = store
        .open_secret(bob, env, &entry("TOKEN"))
        .await
        .unwrap_err();
    assert_eq!(err, EnvError::Open);
}

#[sqlx::test]
async fn a_credential_ciphertext_does_not_open_as_an_environment_secret(pool: PgPool) {
    let ring = Arc::new(sealer("cross", &[("k1", "ab")]));
    let creds = CredentialStore::new(pool.clone(), ring.clone());
    let envs = EnvironmentStore::new(pool.clone(), ring);
    let alice = user(&pool, "alice").await;
    creds
        .put(
            alice,
            CredentialKind::GithubPat,
            CredentialShape::StaticSecret,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let env = envs
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO environment_secret (environment_id, name, ciphertext, key_id, fingerprint) \
         SELECT $1, 'TOKEN', ciphertext, key_id, fingerprint FROM credentials WHERE user_id = $2",
    )
    .bind(env)
    .bind(alice)
    .execute(&pool)
    .await
    .unwrap();
    let err = envs
        .open_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap_err();
    assert_eq!(err, EnvError::Open);
}

#[sqlx::test]
async fn rows_sealed_under_an_old_key_open_after_rotation(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let old = EnvironmentStore::new(pool.clone(), Arc::new(sealer("old", &[("k1", "ab")])));
    let env = old
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    old.put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    let rotated = EnvironmentStore::new(
        pool.clone(),
        Arc::new(sealer("new", &[("k2", "cd"), ("k1", "ab")])),
    );
    let opened = rotated
        .open_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap();
    assert_eq!(opened.as_slice(), VALUE.as_bytes());
    rotated
        .put_secret(alice, env, &entry("FRESH"), &value(OTHER))
        .await
        .unwrap();
    assert_eq!(ciphertext_row(&pool, env, "TOKEN").await.unwrap().1, "k1");
    assert_eq!(ciphertext_row(&pool, env, "FRESH").await.unwrap().1, "k2");
}

struct FailingSeal(FileSealer);

impl Sealer for FailingSeal {
    fn seal(&self, _aad: &Aad, _plaintext: &[u8]) -> Result<Sealed, SealError> {
        Err(SealError::Seal)
    }

    fn open(
        &self,
        aad: &Aad,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        self.0.open(aad, key_id, ciphertext)
    }
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[sqlx::test]
async fn a_failed_seal_leaves_no_row_and_no_value_in_errors_or_logs(pool: PgPool) {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let alice = user(&pool, "alice").await;
    let good = store(&pool, "fail-good");
    let env = good
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    good.put_secret(alice, env, &entry("KEPT"), &value(VALUE))
        .await
        .unwrap();
    let failing = EnvironmentStore::new(
        pool.clone(),
        Arc::new(FailingSeal(sealer("fail", &[("k1", "ab")]))),
    );
    let new_err = failing
        .put_secret(alice, env, &entry("FRESH"), &value(OTHER))
        .await
        .unwrap_err();
    let old_err = failing
        .put_secret(alice, env, &entry("KEPT"), &value(OTHER))
        .await
        .unwrap_err();
    assert_eq!(new_err, EnvError::Seal);
    assert_eq!(old_err, EnvError::Seal);
    assert!(ciphertext_row(&pool, env, "FRESH").await.is_none());
    let kept = good.open_secret(alice, env, &entry("KEPT")).await.unwrap();
    assert_eq!(kept.as_slice(), VALUE.as_bytes());
    let shown = format!("{new_err} {new_err:?} {old_err} {old_err:?}");
    let captured = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(captured.contains(" WARN "), "{captured}");
    assert!(
        captured.contains("environment secret seal failed"),
        "{captured}"
    );
    for needle in [VALUE, OTHER] {
        assert!(!shown.contains(needle));
        assert!(!captured.contains(needle), "{needle} reached the logs");
    }
}
