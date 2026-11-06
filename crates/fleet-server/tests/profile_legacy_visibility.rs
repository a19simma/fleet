//! A profile written by the release before ownership (0023) and carried through the
//! migrations is system-owned, shared and readable by every viewer. They need a Postgres
//! superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_server::profiles::{self, Viewer};
use fleet_server::store::StoreError;
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;

const OWNERSHIP_VERSION: i64 = 23;
const LEGACY_CONTENT: &str = r#"{"claude_md":"legacy"}"#;

async fn migrate_before(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < OWNERSHIP_VERSION)
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(pool).await.unwrap();
}

async fn legacy_create(pool: &PgPool, name: &str, version: i32, hash_byte: u8) {
    let hash = vec![hash_byte; 32];
    let content = LEGACY_CONTENT.as_bytes();
    sqlx::query(
        "INSERT INTO profile_blob (hash, content, size) VALUES ($1, $2, $3) \
         ON CONFLICT (hash) DO NOTHING",
    )
    .bind(&hash)
    .bind(content)
    .bind(i32::try_from(content.len()).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO profile_version (name, version, hash) VALUES ($1, $2, $3)")
        .bind(name)
        .bind(version)
        .bind(&hash)
        .execute(pool)
        .await
        .unwrap();
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn a_legacy_profile_is_system_owned_shared_and_readable_by_every_viewer(pool: PgPool) {
    migrate_before(&pool).await;
    legacy_create(&pool, "alpha", 1, 1).await;
    legacy_create(&pool, "alpha", 2, 2).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let viewers = [Viewer::User(alice), Viewer::User(bob), Viewer::Shared];
    for viewer in viewers {
        let latest = profiles::get_for(&pool, viewer, "alpha", None)
            .await
            .unwrap();
        assert_eq!(latest.version, 2);
        assert_eq!(latest.owner, "system");
        assert_eq!(
            latest.visibility,
            fleet_proto::v1::ProfileVisibility::Shared as i32
        );
        let first = profiles::get_for(&pool, viewer, "alpha", Some(1))
            .await
            .unwrap();
        assert_eq!(first.version, 1);
        let listed = profiles::list_for(&pool, viewer, 0, None).await.unwrap();
        assert_eq!(listed.profiles.len(), 1);
        assert_eq!(listed.profiles[0].name, "alpha");
        assert_eq!(listed.profiles[0].owner, "system");
    }
    assert!(matches!(
        profiles::get_for(&pool, Viewer::User(bob), "ghost", None).await,
        Err(StoreError::NotFound)
    ));
}
