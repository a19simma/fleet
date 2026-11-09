//! Schema tests for migration 0042: environment tables, their triggers and the job pin columns
//! (ADR-0067). They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::borrow::Cow;

use sqlx::PgPool;
use sqlx::migrate::Migrator;

const ENV_VERSION: i64 = 42;
const RESTRICT: &str = "23001";
const CHECK: &str = "23514";

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
        .unwrap_or_default()
}

fn message(err: &sqlx::Error) -> String {
    err.as_database_error()
        .map(|e| e.message().to_owned())
        .unwrap_or_default()
}

async fn seed(pool: &PgPool) {
    sqlx::query("INSERT INTO users (username) VALUES ('alice')")
        .execute(pool)
        .await
        .unwrap();
    for stmt in [
        "INSERT INTO environment (id, user_id, name) OVERRIDING SYSTEM VALUE VALUES (7, 1, 'prod')",
        "INSERT INTO environment_version (environment_id, user_id, version, hash, egress_hosts) \
         VALUES (7, 1, 1, decode(repeat('ab', 32), 'hex'), ARRAY['example.com'])",
        "INSERT INTO environment_entry (environment_id, version, position, name, kind, \
         agent_visible, delivery) VALUES (7, 1, 0, 'TOKEN', 'secret', false, 'file')",
        "INSERT INTO environment_use (environment_id, version, job_id, name, fingerprint) \
         VALUES (7, 1, 'job-a', 'TOKEN', 'abcdef123456')",
    ] {
        sqlx::query(stmt).execute(pool).await.unwrap();
    }
}

async fn insert_job(
    pool: &PgPool,
    id: &str,
    env: Option<i64>,
    version: Option<i32>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, environment_id, \
         environment_version) VALUES ($1, 'p', 'r', 'main', 'b', false, $2, $3)",
    )
    .bind(id)
    .bind(env)
    .bind(version)
    .execute(pool)
    .await
    .map(drop)
}

const SNAPSHOT_VERSION: &str = "SELECT to_jsonb(t)::text FROM environment_version t";
const SNAPSHOT_ENTRY: &str = "SELECT to_jsonb(t)::text FROM environment_entry t";
const SNAPSHOT_USE: &str = "SELECT to_jsonb(t)::text FROM environment_use t";

struct Guarded {
    snapshot: &'static str,
    update: &'static str,
    delete: &'static str,
    truncate: &'static str,
    text: &'static str,
}

const GUARDED: [Guarded; 3] = [
    Guarded {
        snapshot: SNAPSHOT_VERSION,
        update: "UPDATE environment_version SET egress_hosts = ARRAY['evil.example']",
        delete: "DELETE FROM environment_version",
        truncate: "TRUNCATE environment_version CASCADE",
        text: "environment_version is immutable",
    },
    Guarded {
        snapshot: SNAPSHOT_ENTRY,
        update: "UPDATE environment_entry SET name = 'OTHER'",
        delete: "DELETE FROM environment_entry",
        truncate: "TRUNCATE environment_entry",
        text: "environment_entry is immutable",
    },
    Guarded {
        snapshot: SNAPSHOT_USE,
        update: "UPDATE environment_use SET fingerprint = 'ffffffffffff'",
        delete: "DELETE FROM environment_use",
        truncate: "TRUNCATE environment_use",
        text: "environment_use is insert-only",
    },
];

#[sqlx::test]
async fn version_entry_and_use_rows_refuse_update_delete_and_truncate(pool: PgPool) {
    seed(&pool).await;
    for g in GUARDED {
        let before: String = sqlx::query_scalar(g.snapshot)
            .fetch_one(&pool)
            .await
            .unwrap();
        for stmt in [g.update, g.delete, g.truncate] {
            let err = sqlx::query(stmt).execute(&pool).await.unwrap_err();
            assert_eq!(code(&err), RESTRICT, "{stmt}");
            assert_eq!(message(&err), g.text, "{stmt}");
        }
        let after: String = sqlx::query_scalar(g.snapshot)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, after, "{}", g.text);
    }
}

#[sqlx::test]
async fn deleting_the_environment_keeps_its_versions_entries_and_uses(pool: PgPool) {
    seed(&pool).await;
    sqlx::query("DELETE FROM environment WHERE id = 7")
        .execute(&pool)
        .await
        .unwrap();
    for g in GUARDED {
        let rows: Vec<String> = sqlx::query_scalar(g.snapshot)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{}", g.text);
    }
}

async fn job_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn job_pins_all_set_and_none_set_are_accepted(pool: PgPool) {
    insert_job(&pool, "none", None, None).await.unwrap();
    insert_job(&pool, "both", Some(7), Some(1)).await.unwrap();
    assert_eq!(job_count(&pool).await, 2);
}

#[sqlx::test]
async fn a_job_with_only_the_environment_id_is_refused(pool: PgPool) {
    let err = insert_job(&pool, "id-only", Some(7), None)
        .await
        .unwrap_err();
    assert_eq!(code(&err), CHECK);
    assert_eq!(job_count(&pool).await, 0);
}

#[sqlx::test]
async fn a_job_with_only_the_environment_version_is_refused(pool: PgPool) {
    let err = insert_job(&pool, "version-only", None, Some(1))
        .await
        .unwrap_err();
    assert_eq!(code(&err), CHECK);
    assert_eq!(job_count(&pool).await, 0);
}

#[sqlx::test(migrations = false)]
async fn jobs_from_before_the_migration_keep_null_pins(pool: PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < ENV_VERSION)
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr) \
         VALUES ('old', 'p', 'r', 'main', 'b', false)",
    )
    .execute(&pool)
    .await
    .unwrap();
    all.run(&pool).await.unwrap();
    let pins: (Option<i64>, Option<i32>) =
        sqlx::query_as("SELECT environment_id, environment_version FROM jobs WHERE job_id = 'old'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pins, (None, None));
}
