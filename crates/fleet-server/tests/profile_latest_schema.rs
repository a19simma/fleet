//! Schema test for migration 0032: `profile.latest_version` is backfilled with the highest
//! version. It needs a Postgres superuser URL in `DATABASE_URL`.

use std::borrow::Cow;

use sqlx::PgPool;
use sqlx::migrate::Migrator;

const LATEST_VERSION: i64 = 32;

#[sqlx::test(migrations = false)]
async fn the_backfill_points_latest_at_the_highest_version(pool: PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < LATEST_VERSION)
        .cloned()
        .collect();
    Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    }
    .run(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO profile (owner_user_id, name, visibility) \
         VALUES (system_user_id(), 'alpha', 'shared')",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (version, byte) in [(1_i32, 1_u8), (2, 2), (3, 3)] {
        sqlx::query("INSERT INTO profile_blob (hash, content, size) VALUES ($1, 'x', 1)")
            .bind(vec![byte; 32])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO profile_version (profile_id, version, hash) \
             SELECT id, $1, $2 FROM profile WHERE name = 'alpha'",
        )
        .bind(version)
        .bind(vec![byte; 32])
        .execute(&pool)
        .await
        .unwrap();
    }
    all.run(&pool).await.unwrap();
    let latest: Option<i32> =
        sqlx::query_scalar("SELECT latest_version FROM profile WHERE name = 'alpha'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(latest, Some(3));
}
