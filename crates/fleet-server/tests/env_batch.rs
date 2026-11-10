//! `submit_batch` Environment pin (ADR-0067 decisions 10 and 11): one resolution pins every
//! child, the refusals write nothing, and the idempotency comparison includes the Environment.
//! The tests need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::environment::{
    Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec, SecretSpec,
};
use fleet_proto::v1::SubmitBatchRequest;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::EnvironmentStore;
use fleet_server::jobs::JobInvalid;
use fleet_server::profiles::{self, ProfileContent};
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REPO: &str = "https://example.com/org/repo.git";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-env-batch-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

fn envs(pool: &PgPool) -> EnvironmentStore {
    EnvironmentStore::new(pool.clone(), Arc::new(sealer()))
}

async fn core(pool: &PgPool) -> Store {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    store
}

async fn user(pool: &PgPool, name: &str, scripts: bool) -> i64 {
    let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
    if scripts {
        sqlx::query(
            "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, 'env:scripts', $1)",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }
    for name in ["alpha", "beta"] {
        profiles::create_owned(
            pool,
            Some(id),
            None,
            name,
            ProfileContent::Json(r#"{"claude_md":"x"}"#),
        )
        .await
        .unwrap();
    }
    id
}

fn secret(name: &str) -> Entry {
    Entry::Secret(SecretSpec::with_defaults(EntryName::new(name).unwrap()))
}

fn script(name: &str) -> Entry {
    Entry::Script(ScriptSpec::with_defaults(
        EntryName::new(name).unwrap(),
        ScriptBody::new(SHEBANG).unwrap(),
    ))
}

async fn environment(pool: &PgPool, owner: i64, name: &str, entries: Vec<Entry>) -> (i64, i32) {
    let store = envs(pool);
    let id = store
        .create_environment(owner, &EnvironmentName::new(name).unwrap())
        .await
        .unwrap();
    let saved = store
        .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
        .await
        .unwrap();
    (id, saved.version)
}

async fn save(pool: &PgPool, owner: i64, id: i64, entries: Vec<Entry>) -> i32 {
    envs(pool)
        .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
        .await
        .unwrap()
        .version
}

fn request(key: &str, environment: &str) -> SubmitBatchRequest {
    SubmitBatchRequest {
        idempotency_key: key.to_owned(),
        prompt: "do it".to_owned(),
        repo: REPO.to_owned(),
        base_sha: SHA.to_owned(),
        repeats: 0,
        profiles: vec!["alpha".to_owned(), "beta".to_owned()],
        agent: String::new(),
        environment: environment.to_owned(),
    }
}

async fn pins(pool: &PgPool, batch_id: &str) -> Vec<(Option<i64>, Option<i32>)> {
    sqlx::query_as(
        "SELECT environment_id, environment_version FROM jobs WHERE batch_id = $1 ORDER BY batch_pos",
    )
    .bind(batch_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn rows(pool: &PgPool) -> (i64, i64) {
    let batches = sqlx::query_scalar("SELECT count(*) FROM batch")
        .fetch_one(pool)
        .await
        .unwrap();
    let jobs = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap();
    (batches, jobs)
}

#[sqlx::test]
async fn every_child_pins_the_version_resolved_once(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, one) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let reply = store
        .submit_batch_for(Some(alice), &request("k1", "prod"))
        .await
        .unwrap();
    assert!(reply.created);
    assert_eq!(
        pins(&pool, &reply.batch_id).await,
        vec![(Some(id), Some(one)); 2]
    );
    let two = save(&pool, alice, id, vec![secret("TOKEN"), secret("OTHER")]).await;
    assert_eq!(
        pins(&pool, &reply.batch_id).await,
        vec![(Some(id), Some(one)); 2]
    );
    let later = store
        .submit_batch_for(Some(alice), &request("k2", "PROD"))
        .await
        .unwrap();
    assert_eq!(
        pins(&pool, &later.batch_id).await,
        vec![(Some(id), Some(two)); 2]
    );
}

#[sqlx::test]
async fn batches_with_mixed_names_pin_each_as_asked(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (prod, one) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let (stage, two) = environment(&pool, alice, "stage", vec![secret("TOKEN")]).await;
    let cases = [
        ("a", "prod", Some((prod, one))),
        ("b", "stage", Some((stage, two))),
        ("c", "-", None),
        ("d", "", None),
    ];
    for (key, name, want) in cases {
        let reply = store
            .submit_batch_for(Some(alice), &request(key, name))
            .await
            .unwrap();
        let want = want.map_or((None, None), |(id, version)| (Some(id), Some(version)));
        assert_eq!(
            pins(&pool, &reply.batch_id).await,
            vec![want; 2],
            "{name:?}"
        );
    }
}

#[sqlx::test]
async fn an_unknown_name_refuses_the_whole_batch(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let bob = user(&pool, "bob", false).await;
    environment(&pool, bob, "theirs", vec![secret("TOKEN")]).await;
    let before = rows(&pool).await;
    for name in ["ghost", "theirs"] {
        let err = store
            .submit_batch_for(Some(alice), &request("k", name))
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::UnknownEnvironment),
            "{name}: {err}"
        );
    }
    assert_eq!(rows(&pool).await, before);
}

#[sqlx::test]
async fn an_environment_without_a_version_refuses_the_whole_batch(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    envs(&pool)
        .create_environment(alice, &EnvironmentName::new("empty").unwrap())
        .await
        .unwrap();
    let before = rows(&pool).await;
    let err = store
        .submit_batch_for(Some(alice), &request("k", "empty"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::EnvironmentWithoutVersion),
        "{err}"
    );
    assert_eq!(rows(&pool).await, before);
}

#[sqlx::test]
async fn scripts_with_the_capability_revoked_refuse_the_whole_batch(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", true).await;
    environment(&pool, alice, "scripted", vec![script("setup")]).await;
    store
        .submit_batch_for(Some(alice), &request("granted", "scripted"))
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let before = rows(&pool).await;
    let err = store
        .submit_batch_for(Some(alice), &request("revoked", "scripted"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::EnvironmentScriptsNotGranted),
        "{err}"
    );
    assert_eq!(rows(&pool).await, before);
}

#[sqlx::test]
async fn the_legacy_owner_cannot_name_an_environment(pool: PgPool) {
    let store = core(&pool).await;
    let before = rows(&pool).await;
    let err = store
        .submit_batch_for(None, &request("k", "prod"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::UnknownEnvironment), "{err}");
    assert_eq!(rows(&pool).await, before);
}

#[sqlx::test]
async fn a_hostile_name_is_refused_before_any_write(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let before = rows(&pool).await;
    for name in ["a b", "../x", "x\r\ny", &"n".repeat(300)] {
        let err = store
            .submit_batch_for(Some(alice), &request("k", name))
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidJob(JobInvalid::Environment)),
            "{err}"
        );
    }
    assert_eq!(rows(&pool).await, before);
}

#[sqlx::test]
async fn a_resubmit_of_the_same_environment_is_equal_and_another_one_conflicts(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (id, _) = environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    environment(&pool, alice, "stage", vec![secret("TOKEN")]).await;
    let first = store
        .submit_batch_for(Some(alice), &request("k", "prod"))
        .await
        .unwrap();
    let again = store
        .submit_batch_for(Some(alice), &request("k", "Prod"))
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.batch_id, first.batch_id);
    assert_eq!(again.job_ids, first.job_ids);
    for other in ["stage", "-", "", "ghost"] {
        let err = store
            .submit_batch_for(Some(alice), &request("k", other))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::KeyConflict), "{other}: {err}");
    }
    store
        .submit_batch_for(Some(alice), &request("plain", ""))
        .await
        .unwrap();
    let err = store
        .submit_batch_for(Some(alice), &request("plain", "prod"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict), "{err}");
    save(&pool, alice, id, vec![secret("TOKEN"), secret("OTHER")]).await;
    let err = store
        .submit_batch_for(Some(alice), &request("k", "prod"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict), "{err}");
}

#[sqlx::test]
async fn a_replay_conflicts_when_the_children_do_not_share_one_pin(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    environment(&pool, alice, "prod", vec![secret("TOKEN")]).await;
    let first = store
        .submit_batch_for(Some(alice), &request("k", "prod"))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE jobs SET environment_id = NULL, environment_version = NULL \
         WHERE batch_id = $1 AND batch_pos = 1",
    )
    .bind(&first.batch_id)
    .execute(&pool)
    .await
    .unwrap();
    let err = store
        .submit_batch_for(Some(alice), &request("k", "prod"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict), "{err}");
}
