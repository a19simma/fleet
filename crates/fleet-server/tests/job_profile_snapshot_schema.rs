//! Schema tests for migration 0029: the job snapshot columns. They need a Postgres superuser
//! URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::borrow::Cow;

use fleet_proto::MAX_BLOB_CATALOG_ITEMS;
use fleet_proto::v1::SubmitJobRequest;
use fleet_server::store::Store;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::migrate::Migrator;

const SNAPSHOT_VERSION: i64 = 29;

/// Migration 0031 adds `jobs.profile_tools_granted`, a plain column the store reads on every job
/// select, so the pre-snapshot schema keeps it.
const TOOLS_GRANTED_VERSION: i64 = 31;

/// Migration 0042 adds `jobs.environment_id`, which the store reads on every job select as
/// `has_environment`, so the pre-snapshot schema keeps it.
const ENVIRONMENTS_VERSION: i64 = 42;

async fn migrate_before(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| {
            m.version < SNAPSHOT_VERSION
                || m.version == TOOLS_GRANTED_VERSION
                || m.version == ENVIRONMENTS_VERSION
        })
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(pool).await.unwrap();
}

async fn migrate_rest(pool: &PgPool) {
    sqlx::migrate!("./migrations").run(pool).await.unwrap();
}

fn request(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.into(),
        prompt: "do it".into(),
        repo: "https://example.com/r.git".into(),
        base_ref: "main".into(),
        open_pr: true,
        ..SubmitJobRequest::default()
    }
}

fn constraint(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        .map(str::to_owned)
}

async fn set_snapshot(
    pool: &PgPool,
    job_id: &str,
    catalog: Option<Value>,
    notes: Option<Value>,
    hash: Option<Vec<u8>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE jobs SET snapshot_catalog = $2, snapshot_notes = $3, snapshot_hash = $4 \
         WHERE job_id = $1",
    )
    .bind(job_id)
    .bind(catalog)
    .bind(notes)
    .bind(hash)
    .execute(pool)
    .await
    .map(drop)
}

async fn snapshot_nulls(pool: &PgPool, job_id: &str) -> (bool, bool, bool) {
    sqlx::query_as(
        "SELECT snapshot_catalog IS NULL, snapshot_notes IS NULL, snapshot_hash IS NULL \
         FROM jobs WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn jobs_built_by_the_previous_release_survive_with_empty_snapshots(pool: PgPool) {
    migrate_before(&pool).await;
    let store = Store::new(pool.clone());
    let first = store.submit_job(&request("k1")).await.unwrap();
    let owner: i64 = sqlx::query_scalar("SELECT bootstrap_user_id()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let second = store
        .submit_job_for(Some(owner), &request("k2"))
        .await
        .unwrap();
    migrate_rest(&pool).await;
    for before in [first, second] {
        let after = store.get_job(&before.job_id).await.unwrap();
        assert_eq!(format!("{after:?}"), format!("{before:?}"));
        assert_eq!(
            snapshot_nulls(&pool, &before.job_id).await,
            (true, true, true)
        );
    }
}

#[sqlx::test(migrations = false)]
async fn a_client_that_omits_the_profile_field_still_submits(pool: PgPool) {
    migrate_before(&pool).await;
    migrate_rest(&pool).await;
    let store = Store::new(pool.clone());
    let job = store.submit_job(&request("k1")).await.unwrap();
    assert_eq!(snapshot_nulls(&pool, &job.job_id).await, (true, true, true));
    let again = store.submit_job(&request("k1")).await.unwrap();
    assert_eq!(again.job_id, job.job_id);
}

#[sqlx::test(migrations = false)]
async fn a_full_snapshot_is_accepted_and_the_job_stays_readable(pool: PgPool) {
    migrate_before(&pool).await;
    migrate_rest(&pool).await;
    let store = Store::new(pool.clone());
    let job = store.submit_job(&request("k1")).await.unwrap();
    let item = json!({"id": "a", "kind": "skill", "name": "a", "content": "body"});
    set_snapshot(
        &pool,
        &job.job_id,
        Some(json!([item])),
        Some(json!([])),
        Some(vec![7; 32]),
    )
    .await
    .unwrap();
    assert_eq!(
        snapshot_nulls(&pool, &job.job_id).await,
        (false, false, false)
    );
    store.get_job(&job.job_id).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn a_partial_snapshot_is_refused_for_each_missing_column(pool: PgPool) {
    migrate_before(&pool).await;
    migrate_rest(&pool).await;
    let store = Store::new(pool.clone());
    let job = store.submit_job(&request("k1")).await.unwrap();
    let catalog = Some(json!([]));
    let notes = Some(json!([]));
    let hash = Some(vec![7; 32]);
    let cases = [
        (None, notes.clone(), hash.clone()),
        (catalog.clone(), None, hash),
        (catalog, notes, None),
    ];
    for (c, n, h) in cases {
        let err = set_snapshot(&pool, &job.job_id, c, n, h).await.unwrap_err();
        assert_eq!(
            constraint(&err).as_deref(),
            Some("jobs_snapshot_columns_together")
        );
    }
    assert_eq!(snapshot_nulls(&pool, &job.job_id).await, (true, true, true));
}

#[sqlx::test(migrations = false)]
async fn the_snapshot_shape_is_checked(pool: PgPool) {
    migrate_before(&pool).await;
    migrate_rest(&pool).await;
    let store = Store::new(pool.clone());
    let job = store.submit_job(&request("k1")).await.unwrap();
    let at_cap = Value::Array(vec![json!({}); MAX_BLOB_CATALOG_ITEMS]);
    let over_cap = Value::Array(vec![json!({}); MAX_BLOB_CATALOG_ITEMS + 1]);
    set_snapshot(
        &pool,
        &job.job_id,
        Some(at_cap),
        Some(json!([])),
        Some(vec![0; 32]),
    )
    .await
    .unwrap();
    let bad = [
        (
            over_cap,
            json!([]),
            vec![0; 32],
            "jobs_snapshot_catalog_shape",
        ),
        (
            json!({}),
            json!([]),
            vec![0; 32],
            "jobs_snapshot_catalog_shape",
        ),
        (
            json!([]),
            json!({}),
            vec![0; 32],
            "jobs_snapshot_notes_shape",
        ),
        (json!([]), json!([]), vec![0; 31], "jobs_snapshot_hash_len"),
        (json!([]), json!([]), vec![0; 33], "jobs_snapshot_hash_len"),
    ];
    for (c, n, h, name) in bad {
        let err = set_snapshot(&pool, &job.job_id, Some(c), Some(n), Some(h))
            .await
            .unwrap_err();
        assert_eq!(constraint(&err).as_deref(), Some(name));
    }
}
