//! Work project repository binding (WRK-13, ADR-0064 decision 10): migration 0041 and the
//! `set_work_project_repo` store call. The tests need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_proto::v1::CreateWorkProjectRequest;
use fleet_server::cred::FileSealer;
use fleet_server::cred::repo_store::RepoStore;
use fleet_server::cred::store::CredentialStore;
use fleet_server::store::{Store, StoreError, WorkFault};
use sqlx::PgPool;
use sqlx::migrate::Migrator;

const FOREIGN_KEY: &str = "23503";
const REPO_VERSION: i64 = 41;
static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
        .unwrap_or_default()
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn registry(pool: &PgPool, owner: i64, path: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) \
         VALUES ($1, 'github.com', $2, 'github') RETURNING id",
    )
    .bind(owner)
    .bind(path)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn raw_project(pool: &PgPool, owner: i64, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO work_project (user_id, name) VALUES ($1, $2) RETURNING id")
        .bind(owner)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn bound(pool: &PgPool, project: i64) -> Option<i64> {
    sqlx::query_scalar("SELECT repo_id FROM work_project WHERE id = $1")
        .bind(project)
        .fetch_one(pool)
        .await
        .unwrap()
}

struct World {
    store: Store,
    repos: RepoStore,
    pool: PgPool,
    alice: i64,
    bob: i64,
}

async fn world(pool: PgPool) -> World {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-work-repo-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    World {
        repos: RepoStore::new(pool.clone(), creds),
        store,
        pool,
        alice,
        bob,
    }
}

async fn blocked_backends(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
         AND datname = current_database()",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn until_blocked(pool: &PgPool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while blocked_backends(pool).await == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

fn refusal<T: std::fmt::Debug>(result: Result<T, StoreError>) -> String {
    match result.unwrap_err() {
        StoreError::Work(fault) => fault.to_string(),
        other => format!("not a work fault: {other:?}"),
    }
}

async fn migrate_before(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < REPO_VERSION)
        .cloned()
        .collect();
    Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    }
    .run(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn migration_nulls_a_binding_to_another_owners_row_and_keeps_the_rest(pool: PgPool) {
    migrate_before(&pool).await;
    let (alice, bob) = (user(&pool, "alice").await, user(&pool, "bob").await);
    let (mine, theirs) = (
        registry(&pool, alice, "a/mine").await,
        registry(&pool, bob, "b/theirs").await,
    );
    let (ok, crossed, unbound) = (
        raw_project(&pool, alice, "ok").await,
        raw_project(&pool, alice, "crossed").await,
        raw_project(&pool, alice, "unbound").await,
    );
    for (project, repo) in [(ok, mine), (crossed, theirs)] {
        sqlx::query("UPDATE work_project SET repo_id = $1 WHERE id = $2")
            .bind(repo)
            .bind(project)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    assert_eq!(bound(&pool, ok).await, Some(mine));
    assert_eq!(bound(&pool, crossed).await, None);
    assert_eq!(bound(&pool, unbound).await, None);
    let names: i64 = sqlx::query_scalar("SELECT count(*) FROM work_project")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(names, 3);
}

#[sqlx::test]
async fn the_schema_refuses_a_binding_to_another_owners_row(pool: PgPool) {
    let w = world(pool).await;
    let theirs = registry(&w.pool, w.bob, "b/theirs").await;
    let project = raw_project(&w.pool, w.alice, "p").await;
    let err = sqlx::query("UPDATE work_project SET repo_id = $1 WHERE id = $2")
        .bind(theirs)
        .bind(project)
        .execute(&w.pool)
        .await
        .unwrap_err();
    assert_eq!(code(&err), FOREIGN_KEY);
    assert_eq!(bound(&w.pool, project).await, None);
}

#[sqlx::test]
async fn a_registry_delete_clears_the_binding_through_the_real_remove_path(pool: PgPool) {
    let w = world(pool).await;
    let repo = registry(&w.pool, w.alice, "a/mine").await;
    let project = raw_project(&w.pool, w.alice, "p").await;
    w.store
        .set_work_project_repo(w.alice, "p", Some("github.com/a/mine"))
        .await
        .unwrap();
    assert_eq!(bound(&w.pool, project).await, Some(repo));
    w.repos
        .remove(w.alice, "github.com", "a/mine")
        .await
        .unwrap();
    assert_eq!(bound(&w.pool, project).await, None);
}

#[sqlx::test]
async fn set_binds_a_registered_repo_and_replies_with_it(pool: PgPool) {
    let w = world(pool).await;
    let (one, two) = (
        registry(&w.pool, w.alice, "a/one").await,
        registry(&w.pool, w.alice, "a/two").await,
    );
    let project = raw_project(&w.pool, w.alice, "p").await;
    let reply = w
        .store
        .set_work_project_repo(w.alice, "p", Some("github.com/a/one"))
        .await
        .unwrap();
    assert_eq!(reply.repo.as_deref(), Some("github.com/a/one"));
    assert_eq!(bound(&w.pool, project).await, Some(one));
    let reply = w
        .store
        .set_work_project_repo(w.alice, "p", Some("github.com/a/two"))
        .await
        .unwrap();
    assert_eq!(reply.repo.as_deref(), Some("github.com/a/two"));
    assert_eq!(bound(&w.pool, project).await, Some(two));
}

#[sqlx::test]
async fn set_clears_the_binding_and_a_project_without_a_repo_still_works(pool: PgPool) {
    let w = world(pool).await;
    registry(&w.pool, w.alice, "a/one").await;
    let created = w
        .store
        .create_work_project(
            w.alice,
            &CreateWorkProjectRequest {
                key: "k".to_owned(),
                name: "p".to_owned(),
                repo: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.repo, None);
    w.store
        .set_work_project_repo(w.alice, "p", Some("github.com/a/one"))
        .await
        .unwrap();
    let cleared = w
        .store
        .set_work_project_repo(w.alice, "p", None)
        .await
        .unwrap();
    assert_eq!(cleared.repo, None);
    let listed = w.store.list_work_projects(w.alice).await.unwrap().projects;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].repo, None);
}

#[sqlx::test]
async fn an_unknown_and_a_foreign_registry_row_get_one_refusal(pool: PgPool) {
    let w = world(pool).await;
    registry(&w.pool, w.bob, "b/theirs").await;
    let project = raw_project(&w.pool, w.alice, "p").await;
    let unknown = refusal(
        w.store
            .set_work_project_repo(w.alice, "p", Some("github.com/a/none"))
            .await,
    );
    let foreign = refusal(
        w.store
            .set_work_project_repo(w.alice, "p", Some("github.com/b/theirs"))
            .await,
    );
    assert_eq!(unknown, foreign);
    assert_eq!(unknown, WorkFault::RepoNotRegistered.to_string());
    assert_eq!(bound(&w.pool, project).await, None);
}

#[sqlx::test]
async fn set_refuses_a_bad_repo_text_and_an_unknown_or_foreign_project(pool: PgPool) {
    let w = world(pool).await;
    registry(&w.pool, w.alice, "a/one").await;
    raw_project(&w.pool, w.bob, "theirs").await;
    let bad = refusal(
        w.store
            .set_work_project_repo(w.alice, "p", Some("not a repo"))
            .await,
    );
    assert_eq!(bad, WorkFault::Invalid("invalid repository").to_string());
    let missing = refusal(
        w.store
            .set_work_project_repo(w.alice, "nope", Some("github.com/a/one"))
            .await,
    );
    let foreign = refusal(
        w.store
            .set_work_project_repo(w.alice, "theirs", Some("github.com/a/one"))
            .await,
    );
    assert_eq!(missing, foreign);
    assert_eq!(missing, WorkFault::ProjectNotFound.to_string());
}

#[sqlx::test]
async fn set_waits_for_the_project_row_lock_before_it_reads(pool: PgPool) {
    let w = world(pool).await;
    registry(&w.pool, w.alice, "a/one").await;
    let project = raw_project(&w.pool, w.alice, "p").await;
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM work_project WHERE id = $1 FOR UPDATE")
        .bind(project)
        .execute(&mut *holder)
        .await
        .unwrap();
    let (store, alice) = (w.store.clone(), w.alice);
    let task = tokio::spawn(async move {
        store
            .set_work_project_repo(alice, "p", Some("github.com/a/one"))
            .await
    });
    until_blocked(&w.pool).await;
    assert!(!task.is_finished());
    sqlx::query("DELETE FROM work_project WHERE id = $1")
        .bind(project)
        .execute(&mut *holder)
        .await
        .unwrap();
    holder.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refusal(result), WorkFault::ProjectNotFound.to_string());
}

#[sqlx::test]
async fn a_registry_delete_in_flight_makes_set_refuse_and_leaves_no_orphan(pool: PgPool) {
    let w = world(pool).await;
    let repo = registry(&w.pool, w.alice, "a/one").await;
    let project = raw_project(&w.pool, w.alice, "p").await;
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_repos WHERE id = $1")
        .bind(repo)
        .execute(&mut *holder)
        .await
        .unwrap();
    let (store, alice) = (w.store.clone(), w.alice);
    let task = tokio::spawn(async move {
        store
            .set_work_project_repo(alice, "p", Some("github.com/a/one"))
            .await
    });
    until_blocked(&w.pool).await;
    assert!(!task.is_finished());
    holder.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refusal(result), WorkFault::RepoNotRegistered.to_string());
    assert_eq!(bound(&w.pool, project).await, None);
}

#[sqlx::test]
async fn a_registry_delete_in_flight_makes_create_refuse_with_the_same_reason(pool: PgPool) {
    let w = world(pool).await;
    let repo = registry(&w.pool, w.alice, "a/one").await;
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_repos WHERE id = $1")
        .bind(repo)
        .execute(&mut *holder)
        .await
        .unwrap();
    let (store, alice) = (w.store.clone(), w.alice);
    let task = tokio::spawn(async move {
        store
            .create_work_project(
                alice,
                &CreateWorkProjectRequest {
                    key: "k".to_owned(),
                    name: "p".to_owned(),
                    repo: Some("github.com/a/one".to_owned()),
                },
            )
            .await
    });
    until_blocked(&w.pool).await;
    holder.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refusal(result), WorkFault::RepoNotRegistered.to_string());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM work_project")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
