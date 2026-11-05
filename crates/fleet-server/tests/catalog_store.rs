//! The catalog admin store: upsert and enable against a real database. They need a Postgres
//! superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_core::catalog::{
    CatalogItem as CoreItem, CatalogKind as CoreKind, MAX_BODY_BYTES, MAX_NAME_BYTES,
};
use fleet_proto::v1::{CatalogKind, SetCatalogItemEnabledRequest, UpsertCatalogItemRequest};
use fleet_server::catalog::{
    DEFAULT_CATALOG_PAGE, MAX_CATALOG_CURSOR_BYTES, MAX_CATALOG_PAGE, REASON_ADMIN_REQUIRED,
    REASON_CURSOR_INVALID, REASON_IDENTITY_CHANGE, REASON_KIND_UNKNOWN, REASON_NAME_TAKEN,
    REASON_NOT_FOUND, list_enabled, list_enabled_capped, set_enabled, upsert_item,
};
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::Users;
use sqlx::PgPool;
use tonic::Code;

fn upsert(id: &str, kind: CatalogKind, name: &str, content: &str) -> UpsertCatalogItemRequest {
    UpsertCatalogItemRequest {
        id: id.to_owned(),
        kind: kind as i32,
        name: name.to_owned(),
        content: content.to_owned(),
    }
}

fn enable(id: &str, enabled: bool) -> SetCatalogItemEnabledRequest {
    SetCatalogItemEnabledRequest {
        id: id.to_owned(),
        enabled,
    }
}

async fn snapshot(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id), '[]')::text FROM catalog_items t",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn migrated(pool: &PgPool) {
    sqlx::migrate!("./migrations").run(pool).await.unwrap();
}

async fn user(pool: &PgPool, name: &str, admin: bool) -> i64 {
    let id = run(pool, &AdminCommand::CreateUser(name.into()), "op")
        .await
        .unwrap()
        .user_id;
    if admin {
        Users::new(pool.clone()).set_admin(id, true).await.unwrap();
    }
    id
}

async fn admin(pool: &PgPool) -> i64 {
    match sqlx::query_scalar("SELECT id FROM users WHERE username = 'root'")
        .fetch_optional(pool)
        .await
        .unwrap()
    {
        Some(id) => id,
        None => user(pool, "root", true).await,
    }
}

async fn plain(pool: &PgPool) -> i64 {
    match sqlx::query_scalar("SELECT id FROM users WHERE username = 'plain'")
        .fetch_optional(pool)
        .await
        .unwrap()
    {
        Some(id) => id,
        None => user(pool, "plain", false).await,
    }
}

#[sqlx::test(migrations = false)]
async fn a_non_admin_is_refused_and_no_row_changes(pool: PgPool) {
    migrated(&pool).await;
    upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "body"),
    )
    .await
    .unwrap();
    let before = snapshot(&pool).await;

    let err = upsert_item(
        &pool,
        plain(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "other"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::PermissionDenied, REASON_ADMIN_REQUIRED)
    );
    let err = upsert_item(
        &pool,
        plain(&pool).await,
        &upsert("b", CatalogKind::Skill, "b", "body"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::PermissionDenied, REASON_ADMIN_REQUIRED)
    );
    let err = set_enabled(&pool, plain(&pool).await, &enable("a", true))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::PermissionDenied, REASON_ADMIN_REQUIRED)
    );

    assert_eq!(snapshot(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn an_admin_upsert_stores_the_recomputed_digest_and_stays_disabled(pool: PgPool) {
    migrated(&pool).await;
    let item = upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "body"),
    )
    .await
    .unwrap();
    let expected = CoreItem::new(CoreKind::Skill, "a", "a", "body")
        .unwrap()
        .digest();
    assert_eq!(item.digest, expected);
    assert!(!item.admin_enabled);
    assert_eq!(item.kind, CatalogKind::Skill as i32);

    let stored: Vec<u8> = sqlx::query_scalar("SELECT digest FROM catalog_items WHERE id = 'a'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, expected);
}

#[sqlx::test(migrations = false)]
async fn a_forged_stored_digest_is_replaced_and_enabled_survives_an_upsert(pool: PgPool) {
    migrated(&pool).await;
    sqlx::query(
        "INSERT INTO catalog_items (id, kind, name, content, digest, admin_enabled) \
         VALUES ('a', 'skill', 'a', 'old', $1, true)",
    )
    .bind([7_u8; 32].as_slice())
    .execute(&pool)
    .await
    .unwrap();
    let item = upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "new"),
    )
    .await
    .unwrap();
    assert_eq!(
        item.digest,
        CoreItem::new(CoreKind::Skill, "a", "a", "new")
            .unwrap()
            .digest()
    );
    assert_eq!(item.content, "new");
    assert!(item.admin_enabled);
}

#[sqlx::test(migrations = false)]
async fn a_kind_or_name_change_on_an_existing_id_is_refused(pool: PgPool) {
    migrated(&pool).await;
    upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "body"),
    )
    .await
    .unwrap();
    let before = snapshot(&pool).await;
    for request in [
        upsert("a", CatalogKind::Subagent, "a", "changed"),
        upsert("a", CatalogKind::Skill, "renamed", "changed"),
    ] {
        let err = upsert_item(&pool, admin(&pool).await, &request)
            .await
            .unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::FailedPrecondition, REASON_IDENTITY_CHANGE)
        );
    }
    assert_eq!(snapshot(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn a_kind_and_name_held_by_another_id_is_refused(pool: PgPool) {
    migrated(&pool).await;
    upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "body"),
    )
    .await
    .unwrap();
    let before = snapshot(&pool).await;
    let err = upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("b", CatalogKind::Skill, "a", "body"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::AlreadyExists, REASON_NAME_TAKEN)
    );
    assert_eq!(snapshot(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn an_item_the_core_refuses_never_reaches_sql(pool: PgPool) {
    migrated(&pool).await;
    let cases = [
        upsert("a", CatalogKind::Tool, "not-a-registry-tool", "1.0.0"),
        upsert("a", CatalogKind::Unspecified, "a", "body"),
        upsert("Bad Id", CatalogKind::Skill, "a", "body"),
    ];
    for request in cases {
        let err = upsert_item(&pool, admin(&pool).await, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
    assert_eq!(snapshot(&pool).await, "[]");
}

#[sqlx::test(migrations = false)]
async fn an_admin_flips_enabled_both_ways_and_an_unknown_id_is_not_found(pool: PgPool) {
    migrated(&pool).await;
    upsert_item(
        &pool,
        admin(&pool).await,
        &upsert("a", CatalogKind::Skill, "a", "body"),
    )
    .await
    .unwrap();
    let on = set_enabled(&pool, admin(&pool).await, &enable("a", true))
        .await
        .unwrap();
    assert!(on.admin_enabled);
    let off = set_enabled(&pool, admin(&pool).await, &enable("a", false))
        .await
        .unwrap();
    assert!(!off.admin_enabled);
    assert_eq!(
        off.digest,
        CoreItem::new(CoreKind::Skill, "a", "a", "body")
            .unwrap()
            .digest()
    );
    let err = set_enabled(&pool, admin(&pool).await, &enable("zz", true))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::NotFound, REASON_NOT_FOUND)
    );
}

#[sqlx::test(migrations = false)]
async fn every_hostile_string_field_is_refused_before_sql(pool: PgPool) {
    migrated(&pool).await;
    let long_id = "a".repeat(MAX_NAME_BYTES * 4);
    let long_name = "a".repeat(MAX_NAME_BYTES + 1);
    let long_body = "x".repeat(MAX_BODY_BYTES + 1);
    let hostile_ids = [
        "",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a b",
        "a\\b",
        "a/../b",
        "a@b",
        "[::1]",
        "\u{e9}",
        "A",
        long_id.as_str(),
    ];
    let hostile_names = [
        "",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a b",
        "a\\b",
        "user@host",
        "\u{e9}",
        long_name.as_str(),
    ];
    let mut cases = Vec::new();
    for id in hostile_ids {
        cases.push(upsert(id, CatalogKind::Skill, "a", "body"));
    }
    for name in hostile_names {
        cases.push(upsert("a", CatalogKind::Skill, name, "body"));
    }
    cases.push(upsert("a", CatalogKind::Skill, "a", ""));
    cases.push(upsert("a", CatalogKind::Skill, "a", &long_body));
    cases.push(upsert("a", CatalogKind::Tool, "a", "not a version"));
    for request in cases {
        let err = upsert_item(&pool, admin(&pool).await, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{request:?}");
    }
    assert_eq!(snapshot(&pool).await, "[]");
}

#[sqlx::test(migrations = false)]
async fn concurrent_upserts_of_one_id_cannot_flip_kind_or_name(pool: PgPool) {
    migrated(&pool).await;
    for round in 0..20 {
        let id = format!("race-{round}");
        let (first, second, third) = (
            format!("first-{round}"),
            format!("second-{round}"),
            format!("third-{round}"),
        );
        let requests = [
            upsert(&id, CatalogKind::Skill, &first, "one"),
            upsert(&id, CatalogKind::Subagent, &first, "two"),
            upsert(&id, CatalogKind::Skill, &second, "three"),
            upsert(&id, CatalogKind::Context, &third, "four"),
        ];
        let results: [Result<_, tonic::Status>; 4] = tokio::join!(
            upsert_item(&pool, admin(&pool).await, &requests[0]),
            upsert_item(&pool, admin(&pool).await, &requests[1]),
            upsert_item(&pool, admin(&pool).await, &requests[2]),
            upsert_item(&pool, admin(&pool).await, &requests[3]),
        )
        .into();
        let winners: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}");
        for err in results.iter().filter_map(|r| r.as_ref().err()) {
            assert_eq!(
                (err.code(), err.message()),
                (Code::FailedPrecondition, REASON_IDENTITY_CHANGE)
            );
        }
        let (kind, name): (String, String) =
            sqlx::query_as("SELECT kind, name FROM catalog_items WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let wire = CatalogKind::try_from(winners[0].kind)
            .unwrap()
            .as_str_name();
        assert!(wire.ends_with(&kind.to_uppercase()), "{wire} {kind}");
        assert_eq!(winners[0].name, name);
    }
}

async fn seed(pool: &PgPool, id: &str, kind: CatalogKind, enabled: bool) {
    let (name, content) = if kind == CatalogKind::Tool {
        ("node", "22.1.0")
    } else {
        (id, "body")
    };
    upsert_item(pool, admin(pool).await, &upsert(id, kind, name, content))
        .await
        .unwrap();
    if enabled {
        set_enabled(pool, admin(pool).await, &enable(id, true))
            .await
            .unwrap();
    }
}

fn ids(page: &fleet_server::catalog::CatalogPage) -> Vec<&str> {
    page.items.iter().map(|i| i.id.as_str()).collect()
}

#[sqlx::test(migrations = false)]
async fn list_returns_only_enabled_items_in_id_order(pool: PgPool) {
    migrated(&pool).await;
    seed(&pool, "c", CatalogKind::Skill, true).await;
    seed(&pool, "a", CatalogKind::Tool, true).await;
    seed(&pool, "b", CatalogKind::Skill, false).await;

    let page = list_enabled(&pool, 0, "", 0).await.unwrap();
    assert_eq!(ids(&page), ["a", "c"]);
    assert_eq!(page.next_id, "c");
}

#[sqlx::test(migrations = false)]
async fn a_disabled_item_is_hidden_even_when_the_filter_names_its_kind(pool: PgPool) {
    migrated(&pool).await;
    seed(&pool, "a", CatalogKind::Skill, true).await;
    seed(&pool, "b", CatalogKind::Skill, false).await;
    seed(&pool, "c", CatalogKind::Tool, false).await;

    let page = list_enabled(&pool, CatalogKind::Skill as i32, "", 0)
        .await
        .unwrap();
    assert_eq!(ids(&page), ["a"]);
    let page = list_enabled(&pool, CatalogKind::Tool as i32, "", 0)
        .await
        .unwrap();
    assert_eq!(ids(&page), Vec::<&str>::new());
}

#[sqlx::test(migrations = false)]
async fn the_kind_filter_matches_one_kind(pool: PgPool) {
    migrated(&pool).await;
    seed(&pool, "a", CatalogKind::Skill, true).await;
    seed(&pool, "b", CatalogKind::Tool, true).await;
    seed(&pool, "c", CatalogKind::Context, true).await;

    let page = list_enabled(&pool, CatalogKind::Tool as i32, "", 0)
        .await
        .unwrap();
    assert_eq!(ids(&page), ["b"]);
}

#[sqlx::test(migrations = false)]
async fn an_unknown_kind_fails_closed(pool: PgPool) {
    migrated(&pool).await;
    seed(&pool, "a", CatalogKind::Skill, true).await;

    for kind in [5, 99, -1, i32::MAX, i32::MIN] {
        let err = list_enabled(&pool, kind, "", 0).await.unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::InvalidArgument, REASON_KIND_UNKNOWN)
        );
    }
}

#[sqlx::test(migrations = false)]
async fn the_cursor_resumes_after_the_last_id(pool: PgPool) {
    migrated(&pool).await;
    for id in ["a", "b", "c"] {
        seed(&pool, id, CatalogKind::Skill, true).await;
    }

    let first = list_enabled_capped(&pool, 0, "", 2, 2).await.unwrap();
    assert_eq!(ids(&first), ["a", "b"]);
    let second = list_enabled_capped(&pool, 0, &first.next_id, 2, 2)
        .await
        .unwrap();
    assert_eq!(ids(&second), ["c"]);
    let third = list_enabled_capped(&pool, 0, &second.next_id, 2, 2)
        .await
        .unwrap();
    assert_eq!(ids(&third), Vec::<&str>::new());
    assert_eq!(third.next_id, "c");
}

#[sqlx::test(migrations = false)]
async fn a_shrunk_cap_cuts_a_page_just_over_it(pool: PgPool) {
    migrated(&pool).await;
    for id in ["a", "b", "c", "d"] {
        seed(&pool, id, CatalogKind::Skill, true).await;
    }

    let at = list_enabled_capped(&pool, 0, "", 3, 3).await.unwrap();
    assert_eq!(at.items.len(), 3);
    let over = list_enabled_capped(&pool, 0, "", 4, 3).await.unwrap();
    assert_eq!(over.items.len(), 3);
    let default = list_enabled_capped(&pool, 0, "", 0, 3).await.unwrap();
    assert_eq!(default.items.len(), 3);
}

#[sqlx::test(migrations = false)]
async fn the_real_cap_holds_at_and_just_over(pool: PgPool) {
    migrated(&pool).await;
    sqlx::query(
        "INSERT INTO catalog_items (id, kind, name, content, digest, admin_enabled) \
         SELECT 'i' || lpad(g::text, 4, '0'), 'skill', 'i' || lpad(g::text, 4, '0'), 'body', \
         decode(repeat('00', 32), 'hex'), true FROM generate_series(1, $1) g",
    )
    .bind(i32::try_from(MAX_CATALOG_PAGE).unwrap() + 1)
    .execute(&pool)
    .await
    .unwrap();

    let at = list_enabled(&pool, 0, "", MAX_CATALOG_PAGE).await.unwrap();
    assert_eq!(at.items.len(), MAX_CATALOG_PAGE as usize);
    let over = list_enabled(&pool, 0, "", MAX_CATALOG_PAGE + 1)
        .await
        .unwrap();
    assert_eq!(over.items.len(), MAX_CATALOG_PAGE as usize);
    let max = list_enabled(&pool, 0, "", u32::MAX).await.unwrap();
    assert_eq!(max.items.len(), MAX_CATALOG_PAGE as usize);
    let default = list_enabled(&pool, 0, "", 0).await.unwrap();
    assert_eq!(default.items.len(), DEFAULT_CATALOG_PAGE as usize);
}

#[sqlx::test(migrations = false)]
async fn a_demoted_or_unknown_actor_is_refused_and_no_row_changes(pool: PgPool) {
    migrated(&pool).await;
    let root = admin(&pool).await;
    upsert_item(&pool, root, &upsert("a", CatalogKind::Skill, "a", "body"))
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    Users::new(pool.clone())
        .set_admin(root, false)
        .await
        .unwrap();

    for actor in [root, i64::MAX] {
        let err = upsert_item(&pool, actor, &upsert("a", CatalogKind::Skill, "a", "other"))
            .await
            .unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::PermissionDenied, REASON_ADMIN_REQUIRED)
        );
        let err = set_enabled(&pool, actor, &enable("a", true))
            .await
            .unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::PermissionDenied, REASON_ADMIN_REQUIRED)
        );
    }
    assert_eq!(snapshot(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn a_write_waits_for_a_demotion_in_flight_then_is_refused(pool: PgPool) {
    migrated(&pool).await;
    let root = admin(&pool).await;
    let mut demotion = pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
        .bind(root)
        .execute(&mut *demotion)
        .await
        .unwrap();

    let writer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            upsert_item(&pool, root, &upsert("a", CatalogKind::Skill, "a", "body")).await
        })
    };
    let waiting = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        while !writer.is_finished() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(waiting.is_err(), "the write did not wait on the actor row");

    demotion.commit().await.unwrap();
    let err = tokio::time::timeout(std::time::Duration::from_secs(10), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::PermissionDenied, REASON_ADMIN_REQUIRED)
    );
    assert_eq!(snapshot(&pool).await, "[]");
}

fn hostile_cursors() -> Vec<(&'static str, String)> {
    vec![
        ("nul", "a\0b".to_owned()),
        ("lone nul", "\0".to_owned()),
        ("over the cap", "a".repeat(MAX_CATALOG_CURSOR_BYTES + 1)),
        ("leading dash", "-a".to_owned()),
        ("leading underscore", "_a".to_owned()),
        ("uppercase", "A".to_owned()),
        ("space", "a b".to_owned()),
        ("leading space", " a".to_owned()),
        ("lf", "a\n".to_owned()),
        ("crlf", "a\r\n".to_owned()),
        ("nel", "a\u{85}".to_owned()),
        ("line separator", "a\u{2028}".to_owned()),
        ("slash", "a/b".to_owned()),
        ("backslash", "a\\b".to_owned()),
        ("percent", "a%41".to_owned()),
        ("non ascii", "\u{e9}".to_owned()),
        ("wildcard", "a%".to_owned()),
    ]
}

#[sqlx::test(migrations = false)]
async fn a_hostile_after_id_is_refused_with_the_fixed_reason(pool: PgPool) {
    migrated(&pool).await;
    seed(&pool, "a", CatalogKind::Skill, true).await;
    for (label, cursor) in hostile_cursors() {
        let err = list_enabled(&pool, 0, &cursor, 0).await.unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::InvalidArgument, REASON_CURSOR_INVALID),
            "{label}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn a_legal_after_id_passes_including_the_cap_exactly(pool: PgPool) {
    migrated(&pool).await;
    seed(&pool, "b", CatalogKind::Skill, true).await;
    let at_cap = "a".repeat(MAX_CATALOG_CURSOR_BYTES);
    for cursor in ["", "a", "a-b_c9", "0", at_cap.as_str()] {
        list_enabled(&pool, 0, cursor, 0).await.unwrap();
    }
}
