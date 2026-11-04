//! Schema tests for migration 0027: profile versions and job pins keyed by profile id. They
//! need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;

const BY_ID_VERSION: i64 = 27;

async fn migrate_before(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations");
    let older: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| m.version < BY_ID_VERSION)
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(pool).await.unwrap();
}

fn code(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(Cow::into_owned)
}

async fn migrate_rest(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

async fn legacy_create(pool: &PgPool, name: &str, hash_byte: u8) {
    let hash = vec![hash_byte; 32];
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO profile_blob (hash, content, size) VALUES ($1, 'x', 1) \
         ON CONFLICT (hash) DO NOTHING",
    )
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(name)
        .execute(&mut *tx)
        .await
        .unwrap();
    let existing = sqlx::query("SELECT version FROM profile_version WHERE name = $1 AND hash = $2")
        .bind(name)
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await
        .unwrap();
    if existing.is_none() {
        sqlx::query(
            "INSERT INTO profile_version (name, version, hash) \
             SELECT $1, COALESCE(MAX(version), 0) + 1, $2 FROM profile_version WHERE name = $1 \
             RETURNING version",
        )
        .bind(name)
        .bind(&hash)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

async fn legacy_submit(pool: &PgPool, key: &str, name: &str) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO batch (batch_id, idempotency_key, prompt, repo, base_sha, repeats) \
         VALUES ($1, $1, 'p', 'r', repeat('a', 40), 1) ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(key)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(name)
        .execute(&mut *tx)
        .await
        .unwrap();
    let (version, hash): (i32, Vec<u8>) = sqlx::query_as(
        "SELECT version, hash FROM profile_version WHERE name = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let user: i64 = sqlx::query_scalar("SELECT bootstrap_user_id()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, \
         batch_id, repeat_idx, batch_pos, profile_name, profile_version, profile_hash, user_id, agent) \
         VALUES ($1, 'p', 'r', 'main', 'swarm/' || $1, false, $1, 0, 0, $2, $3, $4, $5, 'claude')",
    )
    .bind(key)
    .bind(name)
    .bind(version)
    .bind(hash)
    .bind(user)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn system_profile(pool: &PgPool, name: &str) {
    sqlx::query(
        "INSERT INTO profile (owner_user_id, name, visibility) \
         VALUES (system_user_id(), $1, 'shared')",
    )
    .bind(name)
    .execute(pool)
    .await
    .unwrap();
}

async fn skip_profile_inserts_named(pool: &PgPool, name: &str) {
    sqlx::query("CREATE TABLE skipped_name (name text NOT NULL)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO skipped_name (name) VALUES ($1)")
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION skip_named_profile() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF EXISTS (SELECT 1 FROM skipped_name WHERE name = NEW.name) THEN RETURN NULL; END IF; \
         RETURN NEW; END; $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER skip_named_profile BEFORE INSERT ON profile \
         FOR EACH ROW EXECUTE FUNCTION skip_named_profile()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn seed(pool: &PgPool) {
    legacy_create(pool, "alpha", 1).await;
    legacy_create(pool, "alpha", 2).await;
    legacy_create(pool, "beta", 3).await;
    legacy_submit(pool, "j1", "alpha").await;
    legacy_submit(pool, "j2", "beta").await;
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr) \
         VALUES ('j0', 'p', 'r', 'main', 'swarm/j0', false)",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn versions_pins_and_hashes_survive(pool: PgPool) {
    migrate_before(&pool).await;
    seed(&pool).await;
    migrate_rest(&pool).await.unwrap();
    let versions: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT p.name, v.version, encode(v.hash, 'hex') FROM profile_version v \
         JOIN profile p ON p.id = v.profile_id ORDER BY p.name, v.version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let hex = |b: u8| format!("{b:02x}").repeat(32);
    assert_eq!(
        versions,
        vec![
            ("alpha".to_owned(), 1, hex(1)),
            ("alpha".to_owned(), 2, hex(2)),
            ("beta".to_owned(), 1, hex(3)),
        ]
    );
    let pins: Vec<(String, String, i32, String)> = sqlx::query_as(
        "SELECT j.job_id, p.name, j.profile_version, encode(j.profile_hash, 'hex') \
         FROM jobs j JOIN profile p ON p.id = j.profile_id ORDER BY j.job_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        pins,
        vec![
            ("j1".to_owned(), "alpha".to_owned(), 2, hex(2)),
            ("j2".to_owned(), "beta".to_owned(), 1, hex(3)),
        ]
    );
    let name: String = sqlx::query_scalar("SELECT profile_name FROM jobs WHERE job_id = 'j1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(name, "alpha");
}

#[sqlx::test(migrations = false)]
async fn the_job_pin_foreign_keys_follow_the_profile_id(pool: PgPool) {
    migrate_before(&pool).await;
    seed(&pool).await;
    migrate_rest(&pool).await.unwrap();
    let defs: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid = 'jobs'::regclass AND conname LIKE 'jobs_profile_%_fk' ORDER BY conname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(defs.len(), 2);
    assert!(
        defs[0]
            .1
            .starts_with("FOREIGN KEY (profile_id, profile_hash)")
    );
    assert!(
        defs[1]
            .1
            .starts_with("FOREIGN KEY (profile_id, profile_version)")
    );
    let bad = sqlx::query("UPDATE jobs SET profile_version = 9 WHERE job_id = 'j1'")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&bad), Some("23503".to_owned()));
    let partial = sqlx::query("UPDATE jobs SET profile_id = NULL WHERE job_id = 'j1'")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code(&partial), Some("23514".to_owned()));
}

#[sqlx::test(migrations = false)]
async fn the_triggers_are_recreated(pool: PgPool) {
    migrate_before(&pool).await;
    seed(&pool).await;
    migrate_rest(&pool).await.unwrap();
    for stmt in [
        "UPDATE profile_version SET version = 9",
        "DELETE FROM profile_version",
        "TRUNCATE profile_version CASCADE",
    ] {
        let err = sqlx::query(stmt).execute(&pool).await.unwrap_err();
        assert_eq!(
            err.as_database_error().map(|e| e.message().to_owned()),
            Some("profile tables are insert-only".to_owned()),
            "{stmt}"
        );
    }
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, 3);
}

#[sqlx::test(migrations = false)]
async fn names_first_created_after_the_ownership_backfill_go_to_a_shared_system_profile(
    pool: PgPool,
) {
    migrate_before(&pool).await;
    seed(&pool).await;
    legacy_create(&pool, "gamma", 4).await;
    legacy_submit(&pool, "j3", "gamma").await;
    system_profile(&pool, "beta").await;
    migrate_rest(&pool).await.unwrap();
    let profiles: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT u.username, p.name, p.visibility FROM profile p \
         JOIN users u ON u.id = p.owner_user_id ORDER BY p.name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let shared = |name: &str| ("system".to_owned(), name.to_owned(), "shared".to_owned());
    assert_eq!(
        profiles,
        vec![shared("alpha"), shared("beta"), shared("gamma")]
    );
    let pins: Vec<(String, String)> = sqlx::query_as(
        "SELECT j.job_id, u.username FROM jobs j JOIN profile p ON p.id = j.profile_id \
         JOIN users u ON u.id = p.owner_user_id ORDER BY j.job_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        pins,
        vec![
            ("j1".to_owned(), "system".to_owned()),
            ("j2".to_owned(), "system".to_owned()),
            ("j3".to_owned(), "system".to_owned()),
        ]
    );
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, 4);
}

#[sqlx::test(migrations = false)]
async fn a_users_private_profile_keeps_an_empty_stream_and_the_legacy_stream_goes_to_system(
    pool: PgPool,
) {
    migrate_before(&pool).await;
    seed(&pool).await;
    let alice: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO profile (owner_user_id, name) VALUES ($1, 'gamma')")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    legacy_create(&pool, "gamma", 5).await;
    legacy_submit(&pool, "j3", "gamma").await;
    migrate_rest(&pool).await.unwrap();
    let streams: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT u.username, p.visibility, count(v.version) FROM profile p \
         JOIN users u ON u.id = p.owner_user_id \
         LEFT JOIN profile_version v ON v.profile_id = p.id \
         WHERE p.name = 'gamma' GROUP BY u.username, p.visibility ORDER BY u.username",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        streams,
        vec![
            ("alice".to_owned(), "private".to_owned(), 0),
            ("system".to_owned(), "shared".to_owned(), 1),
        ]
    );
    let owner: String = sqlx::query_scalar(
        "SELECT u.username FROM jobs j JOIN profile p ON p.id = j.profile_id \
         JOIN users u ON u.id = p.owner_user_id WHERE j.job_id = 'j3'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner, "system");
}

#[sqlx::test(migrations = false)]
async fn a_job_name_without_any_version_is_refused_by_the_pin_foreign_key(pool: PgPool) {
    migrate_before(&pool).await;
    seed(&pool).await;
    sqlx::query("ALTER TABLE jobs DROP CONSTRAINT jobs_profile_version_fk, DROP CONSTRAINT jobs_profile_hash_fk")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET profile_name = 'ghost' WHERE job_id = 'j1'")
        .execute(&pool)
        .await
        .unwrap();
    let err = migrate_rest(&pool).await.unwrap_err();
    assert!(err.to_string().contains("jobs_profile_version_fk"), "{err}");
    let ghosts: i64 = sqlx::query_scalar("SELECT count(*) FROM profile WHERE name = 'ghost'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ghosts, 0);
}

#[sqlx::test(migrations = false)]
async fn a_version_row_lost_after_the_profile_insert_aborts_the_migration(pool: PgPool) {
    migrate_before(&pool).await;
    seed(&pool).await;
    legacy_create(&pool, "gamma", 9).await;
    skip_profile_inserts_named(&pool, "gamma").await;
    let err = migrate_rest(&pool).await.unwrap_err();
    assert!(
        err.to_string().contains(
            "profile_version backfill kept 3 of 4 rows: a name has no system-owned profile"
        ),
        "{err}"
    );
    let old_shape: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_name = 'profile_version' AND column_name = 'name'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_shape, 1);
    let no_v2: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE tablename = 'profile_version_v2'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(no_v2, 0);
}

#[sqlx::test(migrations = false)]
async fn a_pinned_job_left_without_a_profile_aborts_the_migration(pool: PgPool) {
    migrate_before(&pool).await;
    seed(&pool).await;
    sqlx::query("ALTER TABLE jobs DROP CONSTRAINT jobs_profile_version_fk, DROP CONSTRAINT jobs_profile_hash_fk")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET profile_name = 'ghost' WHERE job_id = 'j1'")
        .execute(&pool)
        .await
        .unwrap();
    skip_profile_inserts_named(&pool, "ghost").await;
    let err = migrate_rest(&pool).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("jobs backfill left 1 pinned jobs without profile_id"),
        "{err}"
    );
}

#[sqlx::test(migrations = false)]
async fn an_empty_database_migrates_and_accepts_a_new_version(pool: PgPool) {
    migrate_before(&pool).await;
    migrate_rest(&pool).await.unwrap();
    system_profile(&pool, "alpha").await;
    sqlx::query("INSERT INTO profile_blob (hash, content, size) VALUES ($1, 'x', 1)")
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO profile_version (profile_id, version, hash) \
         SELECT id, 1, $1 FROM profile WHERE name = 'alpha'",
    )
    .bind(vec![7_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
}
