//! Schema tests for migration 0038: retro, improvement, occurrence, pitfall and suggested edit
//! tables (ADR-0065, ADR-0066). They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use sqlx::PgPool;

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

const UNIQUE: &str = "23505";
const FOREIGN_KEY: &str = "23503";
const CHECK: &str = "23514";

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn project(pool: &PgPool, user_id: i64, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO work_project (user_id, name) VALUES ($1, $2) RETURNING id")
        .bind(user_id)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn item(pool: &PgPool, project_id: i64, key: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO work_item (project_id, key, title) VALUES ($1, $2, 't') RETURNING id",
    )
    .bind(project_id)
    .bind(key)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn attempt(pool: &PgPool, project_id: i64, item_id: i64) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO work_attempt (project_id, item_id, holder, expires_at) \
         VALUES ($1, $2, 'w', now() + interval '10 minutes') RETURNING id",
    )
    .bind(project_id)
    .bind(item_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn retro(pool: &PgPool, project_id: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO retro (project_id, title) VALUES ($1, 'r') RETURNING id")
        .bind(project_id)
        .fetch_one(pool)
        .await
}

async fn improvement(pool: &PgPool, project_id: i64, title: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO improvement (project_id, vertical, title, kind) \
         VALUES ($1, 'core', $2, 'process') RETURNING id",
    )
    .bind(project_id)
    .bind(title)
    .fetch_one(pool)
    .await
}

async fn run(pool: &PgPool, sql: &'static str) -> sqlx::Error {
    sqlx::query(sql).execute(pool).await.unwrap_err()
}

#[sqlx::test]
async fn retro_state_and_span_are_checked(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let q = project(&pool, owner, "other").await;
    let id = retro(&pool, p).await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM retro WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "open");
    let closed_without_time = sqlx::query("UPDATE retro SET state = 'closed' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&closed_without_time), CHECK);
    let foreign_item = item(&pool, q, "X").await;
    let cross = sqlx::query("UPDATE retro SET span_from_item_id = $2 WHERE id = $1")
        .bind(id)
        .bind(foreign_item)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&cross), FOREIGN_KEY);
}

#[sqlx::test]
async fn deleting_a_span_item_clears_only_the_span_column(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let a = item(&pool, p, "A").await;
    let id = retro(&pool, p).await.unwrap();
    sqlx::query("UPDATE retro SET span_from_item_id = $2 WHERE id = $1")
        .bind(id)
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM work_item WHERE id = $1")
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();
    let row: (i64, Option<i64>) =
        sqlx::query_as("SELECT project_id, span_from_item_id FROM retro WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (p, None));
}

#[sqlx::test]
async fn improvement_title_is_unique_per_project_and_kind_is_closed(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let q = project(&pool, owner, "other").await;
    improvement(&pool, p, "same").await.unwrap();
    assert_eq!(
        code(&improvement(&pool, p, "same").await.unwrap_err()),
        UNIQUE
    );
    improvement(&pool, q, "same").await.unwrap();
    let bad_kind = sqlx::query(
        "INSERT INTO improvement (project_id, vertical, title, kind) \
         VALUES ($1, 'core', 'k', 'magic')",
    )
    .bind(p)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&bad_kind), CHECK);
    let zero = sqlx::query("UPDATE improvement SET occurrences = 0 WHERE project_id = $1")
        .bind(p)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&zero), CHECK);
}

#[sqlx::test]
async fn disposition_and_reason_are_both_or_neither(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let id = improvement(&pool, p, "t").await.unwrap();
    let only_disposition =
        sqlx::query("UPDATE improvement SET disposition = 'accepted' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(code(&only_disposition), CHECK);
    let only_reason =
        sqlx::query("UPDATE improvement SET disposition_reason = 'why' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(code(&only_reason), CHECK);
    let bad = sqlx::query(
        "UPDATE improvement SET disposition = 'maybe', disposition_reason = 'why' WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&bad), CHECK);
    sqlx::query(
        "UPDATE improvement SET disposition = 'deferred', disposition_reason = 'later' \
         WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
}

#[sqlx::test]
async fn improvement_links_cannot_cross_projects(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let q = project(&pool, owner, "other").await;
    let foreign_retro = retro(&pool, q).await.unwrap();
    let foreign_item = item(&pool, q, "X").await;
    let by_retro = sqlx::query(
        "INSERT INTO improvement (project_id, retro_id, vertical, title, kind) \
         VALUES ($1, $2, 'core', 't', 'docs')",
    )
    .bind(p)
    .bind(foreign_retro)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&by_retro), FOREIGN_KEY);
    let by_item = sqlx::query(
        "INSERT INTO improvement (project_id, item_id, vertical, title, kind) \
         VALUES ($1, $2, 'core', 't', 'docs')",
    )
    .bind(p)
    .bind(foreign_item)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&by_item), FOREIGN_KEY);
}

#[sqlx::test]
async fn occurrences_cascade_and_their_links_cannot_cross_projects(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let q = project(&pool, owner, "other").await;
    let imp = improvement(&pool, p, "t").await.unwrap();
    let foreign_attempt = {
        let i = item(&pool, q, "X").await;
        attempt(&pool, q, i).await
    };
    let cross = sqlx::query(
        "INSERT INTO improvement_occurrence (project_id, improvement_id, attempt_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(p)
    .bind(imp)
    .bind(foreign_attempt)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&cross), FOREIGN_KEY);
    let foreign_parent = sqlx::query(
        "INSERT INTO improvement_occurrence (project_id, improvement_id) VALUES ($1, $2)",
    )
    .bind(q)
    .bind(imp)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&foreign_parent), FOREIGN_KEY);
    sqlx::query("INSERT INTO improvement_occurrence (project_id, improvement_id) VALUES ($1, $2)")
        .bind(p)
        .bind(imp)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM improvement WHERE id = $1")
        .bind(imp)
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM improvement_occurrence")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[sqlx::test]
async fn pitfalls_are_user_level_or_project_level_of_the_same_user(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let p = project(&pool, alice, "fleet").await;
    let add = |user_id: i64, project_id: Option<i64>, symptom: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO pitfall (user_id, project_id, symptom, cause, fix) \
                 VALUES ($1, $2, $3, 'c', 'f')",
            )
            .bind(user_id)
            .bind(project_id)
            .bind(symptom)
            .execute(&pool)
            .await
        }
    };
    add(alice, None, "s").await.unwrap();
    assert_eq!(code(&add(alice, None, "s").await.unwrap_err()), UNIQUE);
    add(bob, None, "s").await.unwrap();
    add(alice, Some(p), "s").await.unwrap();
    assert_eq!(code(&add(alice, Some(p), "s").await.unwrap_err()), UNIQUE);
    assert_eq!(
        code(&add(bob, Some(p), "other").await.unwrap_err()),
        FOREIGN_KEY
    );
    let empty =
        sqlx::query("INSERT INTO pitfall (user_id, symptom, cause, fix) VALUES ($1, '', 'c', 'f')")
            .bind(alice)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(code(&empty), CHECK);
}

#[sqlx::test]
async fn suggested_edit_kind_state_decision_and_payload_are_checked(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let q = project(&pool, owner, "other").await;
    let add = |kind: &'static str, payload: usize| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO suggested_edit (project_id, kind, target, base_hash, payload, filed_by) \
                 VALUES ($1, $2, 't', 'h', repeat('x', $3), 'w')",
            )
            .bind(p)
            .bind(kind)
            .bind(i32::try_from(payload).unwrap())
            .execute(&pool)
            .await
        }
    };
    add("slice_op", 65536).await.unwrap();
    add("pitfall", 1).await.unwrap();
    add("file_patch", 1).await.unwrap();
    assert_eq!(code(&add("rewrite", 1).await.unwrap_err()), CHECK);
    assert_eq!(code(&add("slice_op", 65537).await.unwrap_err()), CHECK);
    let decided_pending = run(
        &pool,
        "UPDATE suggested_edit SET decided_at = now() WHERE kind = 'pitfall'",
    )
    .await;
    assert_eq!(code(&decided_pending), CHECK);
    let accepted_undecided = run(
        &pool,
        "UPDATE suggested_edit SET state = 'accepted' WHERE kind = 'pitfall'",
    )
    .await;
    assert_eq!(code(&accepted_undecided), CHECK);
    let unknown_state = run(
        &pool,
        "UPDATE suggested_edit SET state = 'maybe' WHERE kind = 'pitfall'",
    )
    .await;
    assert_eq!(code(&unknown_state), CHECK);
    sqlx::query("UPDATE suggested_edit SET state = 'stale' WHERE kind = 'pitfall'")
        .execute(&pool)
        .await
        .unwrap();
    let foreign_attempt = {
        let i = item(&pool, q, "X").await;
        attempt(&pool, q, i).await
    };
    let cross = sqlx::query(
        "INSERT INTO suggested_edit (project_id, attempt_id, kind, target, base_hash, payload, filed_by) \
         VALUES ($1, $2, 'pitfall', 't', 'h', 'p', 'w')",
    )
    .bind(p)
    .bind(foreign_attempt)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&cross), FOREIGN_KEY);
}

#[sqlx::test]
async fn deleting_a_project_removes_every_retro_row(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await;
    let r = retro(&pool, p).await.unwrap();
    let imp = improvement(&pool, p, "t").await.unwrap();
    sqlx::query("INSERT INTO improvement_occurrence (project_id, improvement_id) VALUES ($1, $2)")
        .bind(p)
        .bind(imp)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pitfall (user_id, project_id, symptom, cause, fix) \
         VALUES ($1, $2, 's', 'c', 'f')",
    )
    .bind(owner)
    .bind(p)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO suggested_edit (project_id, retro_id, kind, target, base_hash, payload, filed_by) \
         VALUES ($1, $2, 'pitfall', 't', 'h', 'p', 'w')",
    )
    .bind(p)
    .bind(r)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM work_project WHERE id = $1")
        .bind(p)
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM retro) + (SELECT count(*) FROM improvement) \
         + (SELECT count(*) FROM improvement_occurrence) + (SELECT count(*) FROM pitfall) \
         + (SELECT count(*) FROM suggested_edit)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}
