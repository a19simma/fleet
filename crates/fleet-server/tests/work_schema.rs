//! Schema tests for migration 0037: the work tracker tables (ADR-0064). They need a Postgres
//! superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use sqlx::PgPool;

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

const UNIQUE: &str = "23505";
const NOT_NULL: &str = "23502";
const FOREIGN_KEY: &str = "23503";
const CHECK: &str = "23514";

async fn one(pool: &PgPool, sql: &'static str, id: i64) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn project(pool: &PgPool, user_id: i64, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO work_project (user_id, name) VALUES ($1, $2) RETURNING id")
        .bind(user_id)
        .bind(name)
        .fetch_one(pool)
        .await
}

async fn slice(pool: &PgPool, project_id: i64, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO work_slice (project_id, name) VALUES ($1, $2) RETURNING id")
        .bind(project_id)
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

async fn attempt(pool: &PgPool, project_id: i64, item_id: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO work_attempt (project_id, item_id, holder, expires_at) \
         VALUES ($1, $2, 'w', now() + interval '10 minutes') RETURNING id",
    )
    .bind(project_id)
    .bind(item_id)
    .fetch_one(pool)
    .await
}

async fn lease(
    pool: &PgPool,
    project_id: i64,
    slice_id: i64,
    attempt_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO work_slice_lease (slice_id, project_id, attempt_id) VALUES ($1, $2, $3)",
    )
    .bind(slice_id)
    .bind(project_id)
    .bind(attempt_id)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn dep(
    pool: &PgPool,
    project_id: i64,
    from: i64,
    to: i64,
    why: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO work_dep (project_id, item_id, depends_on_id, why) VALUES ($1, $2, $3, $4)",
    )
    .bind(project_id)
    .bind(from)
    .bind(to)
    .bind(why)
    .execute(pool)
    .await
    .map(|_| ())
}

#[sqlx::test]
async fn every_work_table_stores_a_row_and_a_project_delete_removes_them_all(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let repo: i64 = sqlx::query_scalar(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) \
         VALUES ($1, 'github.com', 'o/n', 'github') RETURNING id",
    )
    .bind(owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    let p = project(&pool, owner, "fleet").await.unwrap();
    sqlx::query("UPDATE work_project SET repo_id = $1 WHERE id = $2")
        .bind(repo)
        .bind(p)
        .execute(&pool)
        .await
        .unwrap();
    let s = slice(&pool, p, "contract").await;
    sqlx::query("INSERT INTO work_slice_path (slice_id, path) VALUES ($1, 'crates/fleet-proto')")
        .bind(s)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO work_mergeable_path (project_id, path) VALUES ($1, 'docs/adr')")
        .bind(p)
        .execute(&pool)
        .await
        .unwrap();
    let a = item(&pool, p, "A").await;
    let b = item(&pool, p, "B").await;
    sqlx::query("INSERT INTO work_item_slice (project_id, item_id, slice_id) VALUES ($1, $2, $3)")
        .bind(p)
        .bind(b)
        .bind(s)
        .execute(&pool)
        .await
        .unwrap();
    dep(&pool, p, b, a, Some("B reads what A writes"))
        .await
        .unwrap();
    let at = attempt(&pool, p, b).await.unwrap();
    lease(&pool, p, s, at).await.unwrap();
    sqlx::query(
        "INSERT INTO work_event (project_id, item_id, attempt_id, kind, actor) \
         VALUES ($1, $2, $3, 'claimed', 'w')",
    )
    .bind(p)
    .bind(b)
    .bind(at)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO work_defer (project_id, item_id, attempt_id, title, reason, vertical) \
         VALUES ($1, $2, $3, 't', 'r', 'core')",
    )
    .bind(p)
    .bind(b)
    .bind(at)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO work_request_key (project_id, key, rpc, request_digest, response) \
         VALUES ($1, 'k', 'ClaimWork', decode(repeat('00', 32), 'hex'), '\\x')",
    )
    .bind(p)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    for table in [
        "work_project",
        "work_slice",
        "work_slice_path",
        "work_mergeable_path",
        "work_item",
        "work_item_slice",
        "work_dep",
        "work_attempt",
        "work_slice_lease",
        "work_event",
        "work_defer",
        "work_request_key",
    ] {
        let sql = format!("SELECT count(*) FROM {table}");
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
}

#[sqlx::test]
async fn deleting_a_registry_repo_clears_the_project_binding_and_keeps_the_project(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let repo: i64 = sqlx::query_scalar(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) \
         VALUES ($1, 'github.com', 'o/n', 'github') RETURNING id",
    )
    .bind(owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    let p = project(&pool, owner, "fleet").await.unwrap();
    sqlx::query("UPDATE work_project SET repo_id = $1 WHERE id = $2")
        .bind(repo)
        .bind(p)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_repos WHERE id = $1")
        .bind(repo)
        .execute(&pool)
        .await
        .unwrap();
    let bound: Option<i64> = sqlx::query_scalar("SELECT repo_id FROM work_project WHERE id = $1")
        .bind(p)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bound, None);
}

#[sqlx::test]
async fn a_project_name_is_unique_per_user_and_a_slice_or_item_key_per_project(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let p = project(&pool, alice, "fleet").await.unwrap();
    assert_eq!(
        code(&project(&pool, alice, "fleet").await.unwrap_err()),
        UNIQUE
    );
    let other = project(&pool, bob, "fleet").await.unwrap();
    slice(&pool, p, "s").await;
    slice(&pool, other, "s").await;
    let dup = sqlx::query("INSERT INTO work_slice (project_id, name) VALUES ($1, 's')")
        .bind(p)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&dup), UNIQUE);
    item(&pool, p, "A").await;
    item(&pool, other, "A").await;
    let dup = sqlx::query("INSERT INTO work_item (project_id, key, title) VALUES ($1, 'A', 't')")
        .bind(p)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&dup), UNIQUE);
}

#[sqlx::test]
async fn slice_and_mergeable_paths_refuse_hostile_text(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await.unwrap();
    let s = slice(&pool, p, "s").await;
    let long = "a".repeat(513);
    let hostile = [
        "",
        "/abs",
        "dir/",
        "a//b",
        ".",
        "..",
        "a/../b",
        "a/./b",
        "a\\b",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "caf\u{e9}",
        long.as_str(),
    ];
    for path in hostile {
        let slice_err = sqlx::query("INSERT INTO work_slice_path (slice_id, path) VALUES ($1, $2)")
            .bind(s)
            .bind(path)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(code(&slice_err), CHECK, "slice {path:?}");
        let merge_err =
            sqlx::query("INSERT INTO work_mergeable_path (project_id, path) VALUES ($1, $2)")
                .bind(p)
                .bind(path)
                .execute(&pool)
                .await
                .unwrap_err();
        assert_eq!(code(&merge_err), CHECK, "mergeable {path:?}");
    }
    for path in [
        ".gitignore",
        "a/.b",
        "dir with space/f..txt",
        &"a".repeat(512),
    ] {
        sqlx::query("INSERT INTO work_slice_path (slice_id, path) VALUES ($1, $2)")
            .bind(s)
            .bind(path)
            .execute(&pool)
            .await
            .unwrap();
    }
}

#[sqlx::test]
async fn a_slice_has_at_most_one_lease(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await.unwrap();
    let s = slice(&pool, p, "s").await;
    let a = item(&pool, p, "A").await;
    let b = item(&pool, p, "B").await;
    let first = attempt(&pool, p, a).await.unwrap();
    let second = attempt(&pool, p, b).await.unwrap();
    lease(&pool, p, s, first).await.unwrap();
    assert_eq!(code(&lease(&pool, p, s, second).await.unwrap_err()), UNIQUE);
    assert_eq!(
        one(
            &pool,
            "SELECT count(*) FROM work_slice_lease WHERE slice_id = $1",
            s
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn deleting_an_attempt_frees_its_leases_and_a_leased_slice_cannot_be_dropped_while_a_member(
    pool: PgPool,
) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await.unwrap();
    let s = slice(&pool, p, "s").await;
    let a = item(&pool, p, "A").await;
    sqlx::query("INSERT INTO work_item_slice (project_id, item_id, slice_id) VALUES ($1, $2, $3)")
        .bind(p)
        .bind(a)
        .bind(s)
        .execute(&pool)
        .await
        .unwrap();
    let drop_slice = sqlx::query("DELETE FROM work_slice WHERE id = $1")
        .bind(s)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&drop_slice), FOREIGN_KEY);
    let at = attempt(&pool, p, a).await.unwrap();
    lease(&pool, p, s, at).await.unwrap();
    sqlx::query("DELETE FROM work_attempt WHERE id = $1")
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        one(
            &pool,
            "SELECT count(*) FROM work_slice_lease WHERE slice_id = $1",
            s
        )
        .await,
        0
    );
}

#[sqlx::test]
async fn a_dependency_needs_a_why_and_stays_inside_one_project(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await.unwrap();
    let q = project(&pool, owner, "other").await.unwrap();
    let a = item(&pool, p, "A").await;
    let b = item(&pool, p, "B").await;
    let foreign = item(&pool, q, "A").await;
    assert_eq!(
        code(&dep(&pool, p, b, a, None).await.unwrap_err()),
        NOT_NULL
    );
    assert_eq!(
        code(&dep(&pool, p, b, a, Some("")).await.unwrap_err()),
        CHECK
    );
    assert_eq!(
        code(
            &dep(&pool, p, b, a, Some(&"w".repeat(501)))
                .await
                .unwrap_err()
        ),
        CHECK
    );
    assert_eq!(
        code(&dep(&pool, p, a, a, Some("self")).await.unwrap_err()),
        CHECK
    );
    assert_eq!(
        code(&dep(&pool, p, b, foreign, Some("cross")).await.unwrap_err()),
        FOREIGN_KEY
    );
    dep(&pool, p, b, a, Some("reads A")).await.unwrap();
    assert_eq!(
        code(&dep(&pool, p, b, a, Some("again")).await.unwrap_err()),
        UNIQUE
    );
    let wrong_project = sqlx::query(
        "INSERT INTO work_item_slice (project_id, item_id, slice_id) VALUES ($1, $2, $3)",
    )
    .bind(q)
    .bind(foreign)
    .bind(slice(&pool, p, "s").await)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&wrong_project), FOREIGN_KEY);
}

#[sqlx::test]
async fn an_item_has_one_open_attempt_and_the_verdict_fields_agree(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await.unwrap();
    let a = item(&pool, p, "A").await;
    let first = attempt(&pool, p, a).await.unwrap();
    assert_eq!(code(&attempt(&pool, p, a).await.unwrap_err()), UNIQUE);
    let half_closed = sqlx::query("UPDATE work_attempt SET verdict = 'pass' WHERE id = $1")
        .bind(first)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&half_closed), CHECK);
    let bad_verdict =
        sqlx::query("UPDATE work_attempt SET verdict = 'maybe', closed_at = now() WHERE id = $1")
            .bind(first)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(code(&bad_verdict), CHECK);
    let lost_with_evidence = sqlx::query(
        "UPDATE work_attempt SET verdict = 'lost', closed_at = now(), evidence = 'x' WHERE id = $1",
    )
    .bind(first)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&lost_with_evidence), CHECK);
    sqlx::query(
        "UPDATE work_attempt SET verdict = 'fail', closed_at = now(), evidence = repeat('e', 8192) \
         WHERE id = $1",
    )
    .bind(first)
    .execute(&pool)
    .await
    .unwrap();
    attempt(&pool, p, a).await.unwrap();
    let over = sqlx::query("UPDATE work_attempt SET evidence = repeat('e', 8193) WHERE id = $1")
        .bind(first)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&over), CHECK);
}

#[sqlx::test]
async fn event_kinds_and_defer_states_are_closed_sets(pool: PgPool) {
    let owner = user(&pool, "alice").await;
    let p = project(&pool, owner, "fleet").await.unwrap();
    let bad_kind = sqlx::query(
        "INSERT INTO work_event (project_id, kind, actor) VALUES ($1, 'exploded', 'w')",
    )
    .bind(p)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&bad_kind), CHECK);
    let bad_state = sqlx::query(
        "INSERT INTO work_defer (project_id, title, reason, vertical, state) \
         VALUES ($1, 't', 'r', 'v', 'lingering')",
    )
    .bind(p)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&bad_state), CHECK);
    let promoted_without_state = sqlx::query(
        "INSERT INTO work_defer (project_id, title, reason, vertical, promoted_item_id) \
         VALUES ($1, 't', 'r', 'v', $2)",
    )
    .bind(p)
    .bind(item(&pool, p, "A").await)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(code(&promoted_without_state), CHECK);
}
