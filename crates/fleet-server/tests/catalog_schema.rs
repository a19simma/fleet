//! Schema tests for migration 0024: the catalog table. They need a Postgres superuser URL in
//! `DATABASE_URL`.

use fleet_proto::MAX_CATALOG_CONTENT_BYTES;
use sqlx::PgPool;
use std::borrow::Cow;

const INSERT: &str = "INSERT INTO catalog_items (id, kind, name, content, digest) \
                      VALUES ($1, $2, $3, $4, $5)";

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
        .unwrap_or_default()
}

async fn insert(
    pool: &PgPool,
    id: &str,
    kind: &str,
    name: &str,
    content: &str,
    digest: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(INSERT)
        .bind(id)
        .bind(kind)
        .bind(name)
        .bind(content)
        .bind(digest)
        .execute(pool)
        .await
        .map(|_| ())
}

#[sqlx::test]
async fn each_core_kind_is_accepted_and_new_items_are_disabled(pool: PgPool) {
    for kind in ["skill", "subagent", "tool", "context"] {
        insert(&pool, kind, kind, kind, "body", &[0; 32])
            .await
            .unwrap();
    }
    let enabled: i64 = sqlx::query_scalar("SELECT count(*) FROM catalog_items WHERE admin_enabled")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(enabled, 0);
}

#[sqlx::test]
async fn an_unknown_kind_is_refused(pool: PgPool) {
    let err = insert(&pool, "a", "plugin", "a", "body", &[0; 32])
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
}

#[sqlx::test]
async fn kind_and_name_are_unique_but_names_repeat_across_kinds(pool: PgPool) {
    insert(&pool, "a", "skill", "same", "body", &[0; 32])
        .await
        .unwrap();
    insert(&pool, "b", "tool", "same", "body", &[0; 32])
        .await
        .unwrap();
    let dup = insert(&pool, "c", "skill", "same", "body", &[0; 32])
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "23505");
}

#[sqlx::test]
async fn content_is_bounded_by_the_shared_const_in_bytes(pool: PgPool) {
    let at = "a".repeat(MAX_CATALOG_CONTENT_BYTES);
    insert(&pool, "at", "skill", "at", &at, &[0; 32])
        .await
        .unwrap();
    let over = format!("{at}a");
    let err = insert(&pool, "over", "skill", "over", &over, &[0; 32])
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
    let wide = "\u{e9}".repeat(MAX_CATALOG_CONTENT_BYTES / 2 + 1);
    let err = insert(&pool, "wide", "skill", "wide", &wide, &[0; 32])
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
    let empty = insert(&pool, "empty", "skill", "empty", "", &[0; 32])
        .await
        .unwrap_err();
    assert_eq!(code(&empty), "23514");
}

#[sqlx::test]
async fn id_name_and_digest_shapes_are_checked(pool: PgPool) {
    for (id, name, digest) in [
        ("Upper", "ok", vec![0; 32]),
        ("-lead", "ok", vec![0; 32]),
        ("ok", "Bad Name", vec![0; 32]),
        ("ok", "ok", vec![0; 31]),
    ] {
        let err = insert(&pool, id, "skill", name, "body", &digest)
            .await
            .unwrap_err();
        assert_eq!(code(&err), "23514", "{id} {name} {}", digest.len());
    }
}
