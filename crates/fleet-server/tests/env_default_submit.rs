//! Default Environment bindings at submit and batch (ADR-0067 decision 10): the repo then
//! profile order, `-` over both, the refusals, the Profile blob refusal and the per-user scope.
//! The tests need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::environment::{
    Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec, SecretSpec,
};
use fleet_proto::v1::{SubmitBatchRequest, SubmitJobRequest};
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{BindingKey, EnvironmentStore};
use fleet_server::profiles::{self, ProfileContent, ProfileFault, Viewer};
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;

const REPO: &str = "https://example.com/org/repo.git";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn envs(pool: &PgPool) -> EnvironmentStore {
    let path = std::env::temp_dir().join(format!(
        "fleet-env-default-submit-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    EnvironmentStore::new(pool.clone(), Arc::new(loaded.unwrap()))
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

async fn register_repo(pool: &PgPool, owner: i64) {
    sqlx::query(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, 'example.com', 'org/repo', 'github')",
    )
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
}

async fn bind_repo(pool: &PgPool, owner: i64, environment: i64) {
    envs(pool)
        .set_default(
            owner,
            environment,
            &BindingKey::Repo {
                host: "example.com".to_owned(),
                path: "org/repo".to_owned(),
            },
        )
        .await
        .unwrap();
}

async fn bind_profile(pool: &PgPool, owner: i64, environment: i64, name: &str) {
    envs(pool)
        .set_default(owner, environment, &BindingKey::Profile(name.to_owned()))
        .await
        .unwrap();
}

async fn profile(pool: &PgPool, owner: i64, name: &str) {
    profiles::create_owned(
        pool,
        Some(owner),
        None,
        name,
        ProfileContent::Json(r#"{"claude_md":"x"}"#),
    )
    .await
    .unwrap();
}

fn job(key: &str, profile: &str, environment: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
        agent: String::new(),
        profile: profile.to_owned(),
        environment: environment.to_owned(),
    }
}

fn batch(key: &str, profiles: &[&str], environment: &str) -> SubmitBatchRequest {
    SubmitBatchRequest {
        idempotency_key: key.to_owned(),
        prompt: "do it".to_owned(),
        repo: REPO.to_owned(),
        base_sha: SHA.to_owned(),
        repeats: 0,
        profiles: profiles.iter().map(|name| (*name).to_owned()).collect(),
        agent: String::new(),
        environment: environment.to_owned(),
    }
}

async fn pin_of(pool: &PgPool, key: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT environment_id FROM jobs WHERE idempotency_key = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn batch_pins(pool: &PgPool, batch_id: &str) -> Vec<Option<i64>> {
    sqlx::query_scalar("SELECT environment_id FROM jobs WHERE batch_id = $1 ORDER BY batch_pos")
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
async fn the_repo_then_the_profile_then_nothing_decide_and_dash_beats_both(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (repo_env, _) = environment(&pool, alice, "repo-env", vec![secret("T")]).await;
    let (profile_env, _) = environment(&pool, alice, "profile-env", vec![secret("T")]).await;
    let (named, _) = environment(&pool, alice, "named", vec![secret("T")]).await;
    profile(&pool, alice, "alpha").await;
    register_repo(&pool, alice).await;
    let submit = |key: &'static str, profile: &'static str, environment: &'static str| {
        let store = store.clone();
        async move {
            store
                .submit_job_for(Some(alice), &job(key, profile, environment))
                .await
                .unwrap();
        }
    };
    submit("none", "alpha", "").await;
    assert_eq!(pin_of(&pool, "none").await, None);
    bind_profile(&pool, alice, profile_env, "alpha").await;
    submit("profile", "alpha", "").await;
    assert_eq!(pin_of(&pool, "profile").await, Some(profile_env));
    submit("profile-less", "", "").await;
    assert_eq!(pin_of(&pool, "profile-less").await, None);
    bind_repo(&pool, alice, repo_env).await;
    submit("repo", "alpha", "").await;
    assert_eq!(pin_of(&pool, "repo").await, Some(repo_env));
    submit("repo-no-profile", "", "").await;
    assert_eq!(pin_of(&pool, "repo-no-profile").await, Some(repo_env));
    submit("dash", "alpha", "-").await;
    assert_eq!(pin_of(&pool, "dash").await, None);
    submit("explicit", "alpha", "named").await;
    assert_eq!(pin_of(&pool, "explicit").await, Some(named));
}

#[sqlx::test]
async fn a_binding_to_scripts_after_a_revoke_refuses_submit_and_batch_and_writes_nothing(
    pool: PgPool,
) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", true).await;
    let (scripted, _) = environment(&pool, alice, "scripted", vec![script("setup")]).await;
    profile(&pool, alice, "alpha").await;
    register_repo(&pool, alice).await;
    bind_repo(&pool, alice, scripted).await;
    let granted = store
        .submit_job_for(Some(alice), &job("granted", "", ""))
        .await
        .unwrap();
    assert!(granted.has_environment);
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let replay = store
        .submit_job_for(Some(alice), &job("granted", "", ""))
        .await
        .unwrap_err();
    assert!(matches!(replay, StoreError::KeyConflict), "{replay}");
    let before = rows(&pool).await;
    let single = store
        .submit_job_for(Some(alice), &job("revoked", "alpha", ""))
        .await
        .unwrap_err();
    assert!(
        matches!(single, StoreError::EnvironmentScriptsNotGranted),
        "{single}"
    );
    let many = store
        .submit_batch_for(Some(alice), &batch("revoked", &["alpha"], ""))
        .await
        .unwrap_err();
    assert!(
        matches!(many, StoreError::EnvironmentScriptsNotGranted),
        "{many}"
    );
    assert_eq!(rows(&pool).await, before);
    let dash = store
        .submit_job_for(Some(alice), &job("dash", "alpha", "-"))
        .await
        .unwrap();
    assert!(!dash.has_environment);
}

#[sqlx::test]
async fn a_binding_changes_no_profile_hash_and_a_replay_of_a_bound_submit_is_not_a_conflict(
    pool: PgPool,
) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (env, _) = environment(&pool, alice, "prod", vec![secret("T")]).await;
    profile(&pool, alice, "alpha").await;
    profile(&pool, alice, "beta").await;
    let hashes = || async {
        sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT profile_id, hash FROM profile_version ORDER BY profile_id, version",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let before = hashes().await;
    bind_profile(&pool, alice, env, "alpha").await;
    assert_eq!(hashes().await, before);
    let first = store
        .submit_job_for(Some(alice), &job("k", "alpha", ""))
        .await
        .unwrap();
    assert_eq!(pin_of(&pool, "k").await, Some(env));
    let again = store
        .submit_job_for(Some(alice), &job("k", "alpha", ""))
        .await
        .unwrap();
    assert_eq!(again.job_id, first.job_id);
    let (other, _) = environment(&pool, alice, "other", vec![secret("T")]).await;
    bind_profile(&pool, alice, other, "alpha").await;
    let moved = store
        .submit_job_for(Some(alice), &job("k", "alpha", ""))
        .await
        .unwrap_err();
    assert!(matches!(moved, StoreError::KeyConflict), "{moved}");
    bind_profile(&pool, alice, env, "alpha").await;
    let bare = store
        .submit_job_for(Some(alice), &job("k", "alpha", "-"))
        .await
        .unwrap_err();
    assert!(matches!(bare, StoreError::KeyConflict), "{bare}");
    let made = store
        .submit_batch_for(Some(alice), &batch("b", &["alpha", "beta"], ""))
        .await
        .unwrap();
    assert_eq!(
        batch_pins(&pool, &made.batch_id).await,
        vec![Some(env), None]
    );
    let replay = store
        .submit_batch_for(Some(alice), &batch("b", &["alpha", "beta"], ""))
        .await
        .unwrap();
    assert!(!replay.created);
    assert_eq!(replay.batch_id, made.batch_id);
}

#[sqlx::test]
async fn a_batch_resolves_the_repo_for_every_child_and_the_profile_per_child(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let (a_env, _) = environment(&pool, alice, "a-env", vec![secret("T")]).await;
    let (b_env, _) = environment(&pool, alice, "b-env", vec![secret("T")]).await;
    let (r_env, _) = environment(&pool, alice, "r-env", vec![secret("T")]).await;
    profile(&pool, alice, "alpha").await;
    profile(&pool, alice, "beta").await;
    bind_profile(&pool, alice, a_env, "alpha").await;
    bind_profile(&pool, alice, b_env, "beta").await;
    let split = store
        .submit_batch_for(Some(alice), &batch("split", &["alpha", "beta"], ""))
        .await
        .unwrap();
    assert_eq!(
        batch_pins(&pool, &split.batch_id).await,
        vec![Some(a_env), Some(b_env)]
    );
    register_repo(&pool, alice).await;
    bind_repo(&pool, alice, r_env).await;
    let repo = store
        .submit_batch_for(Some(alice), &batch("repo", &["alpha", "beta"], ""))
        .await
        .unwrap();
    assert_eq!(
        batch_pins(&pool, &repo.batch_id).await,
        vec![Some(r_env), Some(r_env)]
    );
    let dash = store
        .submit_batch_for(Some(alice), &batch("dash", &["alpha", "beta"], "-"))
        .await
        .unwrap();
    assert_eq!(batch_pins(&pool, &dash.batch_id).await, vec![None, None]);
}

#[sqlx::test]
async fn two_users_bound_to_one_shared_profile_each_resolve_their_own_binding(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let bob = user(&pool, "bob", false).await;
    let (a_env, _) = environment(&pool, alice, "a-env", vec![secret("T")]).await;
    let (b_env, _) = environment(&pool, bob, "b-env", vec![secret("T")]).await;
    profile(&pool, alice, "shared-one").await;
    profiles::share_owned(&pool, Some(alice), "shared-one")
        .await
        .unwrap();
    bind_profile(&pool, alice, a_env, "shared-one").await;
    bind_profile(&pool, bob, b_env, "shared-one").await;
    store
        .submit_job_for(Some(bob), &job("bob", "shared-one", ""))
        .await
        .unwrap();
    store
        .submit_job_for(Some(alice), &job("alice", "shared-one", ""))
        .await
        .unwrap();
    assert_eq!(pin_of(&pool, "bob").await, Some(b_env));
    assert_eq!(pin_of(&pool, "alice").await, Some(a_env));
    let carol = user(&pool, "carol", false).await;
    store
        .submit_job_for(Some(carol), &job("carol", "shared-one", ""))
        .await
        .unwrap();
    assert_eq!(pin_of(&pool, "carol").await, None);
}

async fn plant_environment_key(pool: &PgPool, name: &str) {
    let hash: Vec<u8> = sqlx::query_scalar(
        "SELECT v.hash FROM profile p JOIN profile_version v \
         ON v.profile_id = p.id AND v.version = p.latest_version WHERE p.name = $1",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    let content = br#"{"claude_md":"x","environment":"prod"}"#.to_vec();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE profile_blob SET content = $1, size = octet_length($1) WHERE hash = $2")
        .bind(content)
        .bind(hash)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn is_environment_refusal(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::InvalidProfile(ProfileFault::Malformed(
            fleet_core::ProfileError::EnvironmentNotAllowed
        ))
    )
}

#[sqlx::test]
async fn a_stored_blob_with_an_environment_key_is_refused_distinctly_not_as_corrupt(pool: PgPool) {
    let store = core(&pool).await;
    let alice = user(&pool, "alice", false).await;
    profile(&pool, alice, "alpha").await;
    plant_environment_key(&pool, "alpha").await;
    let before = rows(&pool).await;
    let single = store
        .submit_job_for(Some(alice), &job("s", "alpha", ""))
        .await
        .unwrap_err();
    assert!(is_environment_refusal(&single), "{single}");
    let many = store
        .submit_batch_for(Some(alice), &batch("b", &["alpha"], ""))
        .await
        .unwrap_err();
    assert!(is_environment_refusal(&many), "{many}");
    let read = store
        .get_profile(Viewer::User(alice), "alpha", None)
        .await
        .unwrap_err();
    assert!(is_environment_refusal(&read), "{read}");
    assert_eq!(rows(&pool).await, before);
}
