//! Environment secret sealing tests (ADR-0067). They need a Postgres superuser URL in
//! `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::{Arc, Mutex};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret, fingerprint};
use fleet_core::environment::{
    EgressHost, Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec,
    SecretSpec, SecretValue,
};
use fleet_server::cred::seal::{Aad, FileSealer, SealError, Sealed, Sealer};
use fleet_server::cred::store::CredentialStore;
use fleet_server::environments::{
    EnvError, EnvironmentStore, Limits, ReleasedSecret, record_environment_use,
};
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

const TABLES: [&str; 5] = [
    "environment",
    "environment_version",
    "environment_entry",
    "environment_secret",
    "environment_use",
];

async fn counts(pool: &PgPool) -> Vec<i64> {
    let mut out = Vec::new();
    for table in TABLES {
        let n: i64 = match table {
            "environment" => sqlx::query_scalar("SELECT count(*) FROM environment"),
            "environment_version" => sqlx::query_scalar("SELECT count(*) FROM environment_version"),
            "environment_entry" => sqlx::query_scalar("SELECT count(*) FROM environment_entry"),
            "environment_secret" => sqlx::query_scalar("SELECT count(*) FROM environment_secret"),
            _ => sqlx::query_scalar("SELECT count(*) FROM environment_use"),
        }
        .fetch_one(pool)
        .await
        .unwrap();
        out.push(n);
    }
    out
}

fn script(name: &str, body: &str) -> Entry {
    Entry::Script(ScriptSpec::with_defaults(
        entry(name),
        ScriptBody::new(body).unwrap(),
    ))
}

fn secret_entry(name: &str) -> Entry {
    Entry::Secret(SecretSpec::with_defaults(entry(name)))
}

fn spec(entries: Vec<Entry>) -> EnvironmentSpec {
    EnvironmentSpec::new(entries, vec![]).unwrap()
}

fn spec_with_host(entries: Vec<Entry>, host: &str) -> EnvironmentSpec {
    EnvironmentSpec::new(entries, vec![EgressHost::new(host).unwrap()]).unwrap()
}

#[sqlx::test]
async fn an_owner_creates_lists_gets_and_deletes_environments(pool: PgPool) {
    let store = store(&pool, "crud");
    let alice = user(&pool, "alice").await;
    let a = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let b = store
        .create_environment(alice, &env_name("dev"))
        .await
        .unwrap();
    let listed = store.list_environments(alice).await.unwrap();
    let names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["dev", "prod"]);
    let got = store.get_environment(alice, a).await.unwrap();
    assert_eq!(
        (got.id, got.name.as_str(), got.latest_version),
        (a, "prod", None)
    );
    store
        .save_version(alice, a, &spec(vec![secret_entry("TOKEN")]))
        .await
        .unwrap();
    assert_eq!(
        store
            .get_environment(alice, a)
            .await
            .unwrap()
            .latest_version,
        Some(1)
    );
    store.delete_environment(alice, b).await.unwrap();
    assert_eq!(
        store.get_environment(alice, b).await,
        Err(EnvError::NotFound)
    );
    assert_eq!(store.list_environments(alice).await.unwrap().len(), 1);
}

#[sqlx::test]
async fn a_second_user_gets_the_unknown_id_answer_and_changes_no_row(pool: PgPool) {
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
    store
        .save_version(alice, env, &spec(vec![secret_entry("TOKEN")]))
        .await
        .unwrap();
    let before = counts(&pool).await;
    let unknown = env + 1000;
    let s = spec(vec![secret_entry("OTHER")]);
    for id in [env, unknown] {
        assert_eq!(
            store.get_environment(bob, id).await,
            Err(EnvError::NotFound)
        );
        assert_eq!(
            store
                .put_secret(bob, id, &entry("TOKEN"), &value(OTHER))
                .await,
            Err(EnvError::NotFound)
        );
        assert_eq!(
            store.delete_secret(bob, id, &entry("TOKEN")).await,
            Err(EnvError::NotFound)
        );
        assert_eq!(
            store.save_version(bob, id, &s).await,
            Err(EnvError::NotFound)
        );
        assert_eq!(
            store.delete_environment(bob, id).await,
            Err(EnvError::NotFound)
        );
    }
    assert_eq!(store.list_environments(bob).await.unwrap().len(), 0);
    assert_eq!(counts(&pool).await, before);
    let kept = store
        .open_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap();
    assert_eq!(kept.as_slice(), VALUE.as_bytes());
}

#[sqlx::test]
async fn deleting_a_secret_removes_only_that_secret(pool: PgPool) {
    let store = store(&pool, "delsecret");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("OTHER"), &value(OTHER))
        .await
        .unwrap();
    store
        .delete_secret(alice, env, &entry("TOKEN"))
        .await
        .unwrap();
    assert_eq!(
        store.delete_secret(alice, env, &entry("TOKEN")).await,
        Err(EnvError::NotFound)
    );
    assert!(ciphertext_row(&pool, env, "TOKEN").await.is_none());
    assert!(ciphertext_row(&pool, env, "OTHER").await.is_some());
}

#[sqlx::test]
async fn two_equal_structural_writes_make_one_version(pool: PgPool) {
    let store = store(&pool, "dedupe");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let s = spec(vec![
        secret_entry("TOKEN"),
        script("setup", "#!/bin/sh\necho a\n"),
    ]);
    let first = store.save_version(alice, env, &s).await.unwrap();
    let again = store.save_version(alice, env, &s).await.unwrap();
    assert_eq!((first.version, first.created), (1, true));
    assert_eq!((again.version, again.created), (1, false));
    assert_eq!(counts(&pool).await, [1, 1, 2, 0, 0]);
    let changed = spec(vec![
        secret_entry("TOKEN"),
        script("setup", "#!/bin/sh\necho b\n"),
    ]);
    let next = store.save_version(alice, env, &changed).await.unwrap();
    assert_eq!((next.version, next.created), (2, true));
    let back = store.save_version(alice, env, &s).await.unwrap();
    assert_eq!((back.version, back.created), (3, true));
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT hash FROM environment_version WHERE environment_id = $1 AND version = 1",
    )
    .bind(env)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.as_slice(), s.version_hash().as_bytes());
}

#[sqlx::test]
async fn a_host_change_makes_a_new_version(pool: PgPool) {
    let store = store(&pool, "hosts");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let a = spec_with_host(vec![secret_entry("TOKEN")], "a.example.com");
    let b = spec_with_host(vec![secret_entry("TOKEN")], "b.example.com");
    assert!(store.save_version(alice, env, &a).await.unwrap().created);
    assert!(store.save_version(alice, env, &b).await.unwrap().created);
    let hosts: Vec<String> = sqlx::query_scalar(
        "SELECT egress_hosts[1] FROM environment_version WHERE environment_id = $1 ORDER BY version",
    )
    .bind(env)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(hosts, ["a.example.com", "b.example.com"]);
}

#[sqlx::test]
async fn a_value_only_secret_update_makes_no_version(pool: PgPool) {
    let store = store(&pool, "valueonly");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let s = spec(vec![secret_entry("TOKEN")]);
    store.save_version(alice, env, &s).await.unwrap();
    store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    let before = counts(&pool).await;
    store
        .put_secret(alice, env, &entry("TOKEN"), &value(OTHER))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, before);
    let again = store.save_version(alice, env, &s).await.unwrap();
    assert_eq!((again.version, again.created), (1, false));
}

#[sqlx::test]
async fn a_save_waits_for_the_environment_lock_and_then_dedupes(pool: PgPool) {
    let store = Arc::new(store(&pool, "race"));
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let s = spec(vec![secret_entry("TOKEN")]);
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM environment WHERE id = $1 FOR UPDATE")
        .bind(env)
        .execute(&mut *holder)
        .await
        .unwrap();
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let s = s.clone();
            tokio::spawn(async move { store.save_version(alice, env, &s).await })
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query LIKE '%FROM environment WHERE%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting >= 2 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "savers never blocked");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(counts(&pool).await[1], 0);
    holder.commit().await.unwrap();
    let mut created = 0;
    for task in tasks {
        if task.await.unwrap().unwrap().created {
            created += 1;
        }
    }
    assert_eq!(created, 1);
    assert_eq!(counts(&pool).await[1], 1);
}

#[sqlx::test]
async fn an_environment_delete_drops_secrets_and_keeps_versions_and_use_rows(pool: PgPool) {
    let store = store(&pool, "survive");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let fp = store
        .put_secret(alice, env, &entry("TOKEN"), &value(VALUE))
        .await
        .unwrap();
    store
        .save_version(alice, env, &spec(vec![secret_entry("TOKEN")]))
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let released = [ReleasedSecret {
        name: "TOKEN".to_owned(),
        fingerprint: fp,
    }];
    record_environment_use(&mut conn, env, 1, "job-1", &released)
        .await
        .unwrap();
    drop(conn);
    store.delete_environment(alice, env).await.unwrap();
    assert_eq!(counts(&pool).await, [0, 1, 1, 0, 1]);
}

#[sqlx::test]
async fn use_rows_are_one_per_secret_released_and_one_for_none(pool: PgPool) {
    let alice_env = 7_i64;
    let mut conn = pool.acquire().await.unwrap();
    let released: Vec<ReleasedSecret> = ["A", "B", "C"]
        .iter()
        .map(|n| ReleasedSecret {
            name: (*n).to_owned(),
            fingerprint: format!("fp-{n}"),
        })
        .collect();
    let n = record_environment_use(&mut conn, alice_env, 2, "job-a", &released)
        .await
        .unwrap();
    assert_eq!(n, 3);
    let none = record_environment_use(&mut conn, alice_env, 2, "job-b", &[])
        .await
        .unwrap();
    assert_eq!(none, 1);
    drop(conn);
    let rows: Vec<(String, i32, String, String, String)> = sqlx::query_as(
        "SELECT job_id, version, name, fingerprint, job_id FROM environment_use \
         WHERE environment_id = $1 ORDER BY id",
    )
    .bind(alice_env)
    .fetch_all(&pool)
    .await
    .unwrap();
    let shape: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.2.as_str(), r.3.as_str()))
        .collect();
    assert_eq!(
        shape,
        [
            ("job-a", "A", "fp-A"),
            ("job-a", "B", "fp-B"),
            ("job-a", "C", "fp-C"),
            ("job-b", "", ""),
        ]
    );
    assert!(rows.iter().all(|r| r.1 == 2));
}

#[sqlx::test]
async fn environments_per_user_are_capped_per_user(pool: PgPool) {
    let limits = Limits {
        max_environments: 2,
        ..Limits::default()
    };
    let store = store(&pool, "capenv").with_limits(limits);
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let a = store
        .create_environment(alice, &env_name("one"))
        .await
        .unwrap();
    store
        .create_environment(alice, &env_name("two"))
        .await
        .unwrap();
    assert_eq!(
        store.create_environment(alice, &env_name("three")).await,
        Err(EnvError::TooManyEnvironments)
    );
    assert_eq!(counts(&pool).await[0], 2);
    store
        .create_environment(bob, &env_name("one"))
        .await
        .unwrap();
    store.delete_environment(alice, a).await.unwrap();
    store
        .create_environment(alice, &env_name("three"))
        .await
        .unwrap();
}

#[sqlx::test]
async fn the_default_environment_cap_is_the_named_constant(pool: PgPool) {
    assert_eq!(
        Limits::default().max_environments,
        fleet_server::environments::MAX_ENVIRONMENTS_PER_USER
    );
    assert_eq!(
        Limits::default().max_entries,
        fleet_core::environment::MAX_ENTRIES
    );
    assert_eq!(
        Limits::default().max_total_bytes,
        fleet_core::environment::MAX_TOTAL_BYTES
    );
    drop(pool);
}

#[sqlx::test]
async fn entries_per_version_are_capped(pool: PgPool) {
    let limits = Limits {
        max_entries: 2,
        ..Limits::default()
    };
    let store = store(&pool, "capent").with_limits(limits);
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let over = spec(vec![
        secret_entry("A"),
        secret_entry("B"),
        secret_entry("C"),
    ]);
    assert_eq!(
        store.save_version(alice, env, &over).await,
        Err(EnvError::TooManyEntries)
    );
    assert_eq!(counts(&pool).await[1], 0);
    let at = spec(vec![secret_entry("A"), secret_entry("B")]);
    assert!(store.save_version(alice, env, &at).await.unwrap().created);
    store
        .put_secret(alice, env, &entry("A"), &value(VALUE))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("B"), &value(OTHER))
        .await
        .unwrap();
    assert_eq!(
        store
            .put_secret(alice, env, &entry("C"), &value(VALUE))
            .await,
        Err(EnvError::TooManyEntries)
    );
    assert!(ciphertext_row(&pool, env, "C").await.is_none());
    store
        .put_secret(alice, env, &entry("A"), &value(OTHER))
        .await
        .unwrap();
}

#[sqlx::test]
async fn script_bodies_plus_secret_values_are_capped(pool: PgPool) {
    let body = "#!/bin/sh\n";
    let limits = Limits {
        max_total_bytes: body.len() + VALUE.len() + OTHER.len(),
        ..Limits::default()
    };
    let store = store(&pool, "captotal").with_limits(limits);
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    store
        .save_version(alice, env, &spec(vec![script("setup", body)]))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("A"), &value(VALUE))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("B"), &value(OTHER))
        .await
        .unwrap();
    let longer = format!("{OTHER}x");
    assert_eq!(
        store
            .put_secret(alice, env, &entry("B"), &value(&longer))
            .await,
        Err(EnvError::TooLarge)
    );
    let kept = store.open_secret(alice, env, &entry("B")).await.unwrap();
    assert_eq!(kept.as_slice(), OTHER.as_bytes());
    let bigger = spec(vec![script("setup", "#!/bin/sh\n#\n")]);
    assert_eq!(
        store.save_version(alice, env, &bigger).await,
        Err(EnvError::TooLarge)
    );
    assert_eq!(counts(&pool).await[1], 1);
}

fn capture() -> (LogBuffer, tracing::subscriber::DefaultGuard) {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (buffer, guard)
}

fn assert_clean(buffer: &LogBuffer, err: EnvError, marker: &str, expected: EnvError) {
    assert_eq!(err, expected);
    tracing::warn!("capture control line");
    let captured = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(captured.contains("capture control line"), "{captured}");
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(marker));
    assert!(!captured.contains(marker), "{marker} reached the logs");
}

const MARK: &str = "MARKER-zq81-secret-value";

#[sqlx::test]
async fn marker_not_found_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let store = store(&pool, "mnf");
    let alice = user(&pool, "alice").await;
    let err = store
        .put_secret(alice, 99, &entry("TOKEN"), &value(MARK))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::NotFound);
}

#[sqlx::test]
async fn marker_exists_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let store = store(&pool, "mex");
    let alice = user(&pool, "alice").await;
    store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let err = store
        .create_environment(alice, &env_name("Prod"))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::Exists);
}

#[sqlx::test]
async fn marker_seal_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let alice = user(&pool, "alice").await;
    let good = store(&pool, "msealg");
    let env = good
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let failing = EnvironmentStore::new(
        pool.clone(),
        Arc::new(FailingSeal(sealer("mseal", &[("k1", "ab")]))),
    );
    let err = failing
        .put_secret(alice, env, &entry("TOKEN"), &value(MARK))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::Seal);
}

#[sqlx::test]
async fn marker_open_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let store = store(&pool, "mopen");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("A"), &value(MARK))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("B"), &value(VALUE))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE environment_secret SET ciphertext = \
         (SELECT ciphertext FROM environment_secret WHERE name = 'B' AND environment_id = $1) \
         WHERE name = 'A' AND environment_id = $1",
    )
    .bind(env)
    .execute(&pool)
    .await
    .unwrap();
    let err = store
        .open_secret(alice, env, &entry("A"))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::Open);
}

#[sqlx::test]
async fn marker_unknown_key_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let alice = user(&pool, "alice").await;
    let old = store(&pool, "mkeyold");
    let env = old
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    old.put_secret(alice, env, &entry("A"), &value(MARK))
        .await
        .unwrap();
    let rotated = EnvironmentStore::new(pool.clone(), Arc::new(sealer("mkeynew", &[("k2", "cd")])));
    let err = rotated
        .open_secret(alice, env, &entry("A"))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::UnknownKey);
}

#[sqlx::test]
async fn marker_database_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let store = store(&pool, "mdb");
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    pool.close().await;
    let err = store
        .put_secret(alice, env, &entry("A"), &value(MARK))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::Database);
}

#[sqlx::test]
async fn marker_too_many_environments_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let limits = Limits {
        max_environments: 1,
        ..Limits::default()
    };
    let store = store(&pool, "mtme").with_limits(limits);
    let alice = user(&pool, "alice").await;
    store
        .create_environment(alice, &env_name("one"))
        .await
        .unwrap();
    let err = store
        .create_environment(alice, &env_name(MARK.to_ascii_lowercase().as_str()))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::TooManyEnvironments);
}

#[sqlx::test]
async fn marker_too_many_entries_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let limits = Limits {
        max_entries: 1,
        ..Limits::default()
    };
    let store = store(&pool, "mtmen").with_limits(limits);
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    store
        .put_secret(alice, env, &entry("A"), &value(VALUE))
        .await
        .unwrap();
    let err = store
        .put_secret(alice, env, &entry("B"), &value(MARK))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::TooManyEntries);
}

#[sqlx::test]
async fn marker_too_large_carries_no_value(pool: PgPool) {
    let (buffer, _guard) = capture();
    let limits = Limits {
        max_total_bytes: MARK.len() - 1,
        ..Limits::default()
    };
    let store = store(&pool, "mtl").with_limits(limits);
    let alice = user(&pool, "alice").await;
    let env = store
        .create_environment(alice, &env_name("prod"))
        .await
        .unwrap();
    let err = store
        .put_secret(alice, env, &entry("A"), &value(MARK))
        .await
        .unwrap_err();
    assert_clean(&buffer, err, MARK, EnvError::TooLarge);
}
