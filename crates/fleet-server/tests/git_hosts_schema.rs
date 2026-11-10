//! Schema tests for migration 0045: `git_hosts`, `credentials.host`, `forgejo_pat`, `git_host_requests`.
//! They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;

const GIT_HOSTS_VERSION: i64 = 45;

async fn migrate_before(pool: &PgPool) {
    let older: Vec<_> = sqlx::migrate!("./migrations")
        .migrations
        .iter()
        .filter(|m| m.version < GIT_HOSTS_VERSION)
        .cloned()
        .collect();
    let partial = Migrator {
        migrations: Cow::Owned(older),
        ..Migrator::DEFAULT
    };
    partial.run(pool).await.unwrap();
}

async fn migrate_all(pool: &PgPool) {
    sqlx::migrate!("./migrations").run(pool).await.unwrap();
}

fn constraint(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        .map(str::to_owned)
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn credential(
    pool: &PgPool,
    user_id: i64,
    kind: &str,
    host: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint, host) \
         VALUES ($1, $2, 'static_secret', '\\x00', 'k', 'f', $3)",
    )
    .bind(user_id)
    .bind(kind)
    .bind(host)
    .execute(pool)
    .await
    .map(drop)
}

async fn host(
    pool: &PgPool,
    name: &str,
    kind: &str,
    allow: bool,
    ips: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO git_hosts (host, kind, allow_private, approved_ips) \
         VALUES ($1, $2, $3, $4::inet[])",
    )
    .bind(name)
    .bind(kind)
    .bind(allow)
    .bind(ips)
    .execute(pool)
    .await
    .map(drop)
}

#[sqlx::test(migrations = false)]
async fn existing_credentials_survive_with_host_github_com(pool: PgPool) {
    migrate_before(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    for (u, kind) in [
        (alice, "github_pat"),
        (alice, "anthropic_api_key"),
        (bob, "github_pat"),
    ] {
        sqlx::query(
            "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint) \
             VALUES ($1, $2, 'static_secret', '\\x01', 'k', 'f')",
        )
        .bind(u)
        .bind(kind)
        .execute(&pool)
        .await
        .unwrap();
    }
    migrate_all(&pool).await;
    let hosts: Vec<String> = sqlx::query_scalar("SELECT host FROM credentials")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(hosts, ["github.com"; 3]);
    let seeded: (String, bool, i64) = sqlx::query_as(
        "SELECT kind, allow_private, cardinality(approved_ips)::bigint FROM git_hosts WHERE host = 'github.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(seeded, ("github".to_owned(), false, 0));
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM git_hosts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 1);
}

#[sqlx::test(migrations = false)]
async fn forgejo_pat_is_accepted_and_unknown_kind_refused(pool: PgPool) {
    migrate_all(&pool).await;
    let alice = user(&pool, "alice").await;
    host(&pool, "git.example.org", "forgejo", false, "{}")
        .await
        .unwrap();
    credential(&pool, alice, "forgejo_pat", "git.example.org")
        .await
        .unwrap();
    let err = credential(&pool, alice, "gitlab_pat", "git.example.org")
        .await
        .unwrap_err();
    assert_eq!(constraint(&err).as_deref(), Some("credentials_kind_check"));
}

#[sqlx::test(migrations = false)]
async fn duplicate_user_kind_host_is_refused_but_another_host_is_not(pool: PgPool) {
    migrate_all(&pool).await;
    let alice = user(&pool, "alice").await;
    credential(&pool, alice, "github_pat", "github.com")
        .await
        .unwrap();
    let err = credential(&pool, alice, "github_pat", "github.com")
        .await
        .unwrap_err();
    assert_eq!(
        constraint(&err).as_deref(),
        Some("credentials_user_kind_host_key")
    );
    credential(&pool, alice, "forgejo_pat", "git.example.org")
        .await
        .unwrap();
    credential(&pool, alice, "forgejo_pat", "git2.example.org")
        .await
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn git_host_kind_check_refuses_other_kinds(pool: PgPool) {
    migrate_all(&pool).await;
    let err = host(&pool, "git.example.org", "gitlab", false, "{}")
        .await
        .unwrap_err();
    assert_eq!(constraint(&err).as_deref(), Some("git_hosts_kind_check"));
}

#[sqlx::test(migrations = false)]
async fn approved_ips_need_allow_private(pool: PgPool) {
    migrate_all(&pool).await;
    let err = host(&pool, "git.example.org", "forgejo", false, "{192.168.3.1}")
        .await
        .unwrap_err();
    assert_eq!(
        constraint(&err).as_deref(),
        Some("git_hosts_approved_ips_need_allow_private")
    );
    host(&pool, "git.example.org", "forgejo", true, "{192.168.3.1}")
        .await
        .unwrap();
    host(&pool, "git2.example.org", "forgejo", true, "{}")
        .await
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn host_requests_default_to_pending_and_refuse_other_status(pool: PgPool) {
    migrate_all(&pool).await;
    let alice = user(&pool, "alice").await;
    sqlx::query("INSERT INTO git_host_requests (host, user_id, resolved) VALUES ('h.example.org', $1, '{192.168.3.1}')")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM git_host_requests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "pending");
    let err = sqlx::query("INSERT INTO git_host_requests (host, user_id, resolved, status) VALUES ('h.example.org', $1, '{}', 'bogus')")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        constraint(&err).as_deref(),
        Some("git_host_requests_status_check")
    );
}
