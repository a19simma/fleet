//! Schema tests for migration 0036: the user repository registry and the nullable mint job id.
//! They need a Postgres superuser URL in `DATABASE_URL`.

use sqlx::PgPool;

async fn user(pool: &PgPool, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
}

async fn credential(pool: &PgPool, user_id: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint) \
         VALUES ($1, 'github_app', 'static_secret', '\\x00', 'k1', 'fp') RETURNING id",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

fn code(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

async fn add_repo(
    pool: &PgPool,
    user_id: i64,
    host: &str,
    path: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, $2, $3, $4)")
        .bind(user_id)
        .bind(host)
        .bind(path)
        .bind(kind)
        .execute(pool)
        .await
        .map(|_| ())
}

async fn mint(
    pool: &PgPool,
    cred: i64,
    job_id: Option<&str>,
    scope: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
         installation_id, requested_permissions, outcome, scope) \
         VALUES (gen_random_uuid(), gen_random_uuid(), $1, $2, 'o/r', '1', 'metadata:read', \
         'attempt', $3)",
    )
    .bind(cred)
    .bind(job_id)
    .bind(scope)
    .execute(pool)
    .await
    .map(|_| ())
}

#[sqlx::test]
async fn a_user_repo_is_unique_per_user_host_and_path(pool: PgPool) {
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    add_repo(&pool, alice, "github.com", "o/r", "github")
        .await
        .unwrap();
    let err = add_repo(&pool, alice, "github.com", "o/r", "github")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23505");
    add_repo(&pool, alice, "git.example.org", "o/r", "forgejo")
        .await
        .unwrap();
    add_repo(&pool, bob, "github.com", "o/r", "github")
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_user_repo_refuses_an_unknown_kind_and_out_of_range_text(pool: PgPool) {
    let alice = user(&pool, "alice").await.unwrap();
    let err = add_repo(&pool, alice, "github.com", "o/r", "gitlab")
        .await
        .unwrap_err();
    assert_eq!(code(&err), "23514");
    for (host, path, ok) in [
        ("h".repeat(253), "o/r".to_owned(), true),
        ("h".repeat(254), "o/r".to_owned(), false),
        ("h".to_owned(), "p".to_owned(), true),
        (String::new(), "o/r".to_owned(), false),
        ("github.com".to_owned(), "p".repeat(141), true),
        ("github.com".to_owned(), "p".repeat(142), false),
        ("github.com".to_owned(), String::new(), false),
    ] {
        let got = add_repo(&pool, alice, &host, &path, "github").await;
        assert_eq!(got.is_ok(), ok, "{} {}", host.len(), path.len());
        if let Err(err) = got {
            assert_eq!(code(&err), "23514");
        }
    }
}

#[sqlx::test]
async fn push_is_nullable_and_verified_at_defaults(pool: PgPool) {
    let alice = user(&pool, "alice").await.unwrap();
    add_repo(&pool, alice, "github.com", "o/r", "github")
        .await
        .unwrap();
    let (push, stamped): (Option<bool>, bool) =
        sqlx::query_as("SELECT push, verified_at IS NOT NULL FROM user_repos")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(push, None);
    assert!(stamped);
}

#[sqlx::test]
async fn deleting_a_user_removes_its_repos(pool: PgPool) {
    let alice = user(&pool, "alice").await.unwrap();
    add_repo(&pool, alice, "github.com", "o/r", "github")
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM user_repos")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[sqlx::test]
async fn a_probe_mint_may_have_no_job_and_a_job_mint_may_not(pool: PgPool) {
    let alice = user(&pool, "alice").await.unwrap();
    let cred = credential(&pool, alice).await.unwrap();
    mint(&pool, cred, None, "probe").await.unwrap();
    mint(&pool, cred, Some("job-1"), "probe").await.unwrap();
    mint(&pool, cred, Some("job-1"), "job").await.unwrap();
    let err = mint(&pool, cred, None, "job").await.unwrap_err();
    assert_eq!(code(&err), "23514");
    let err = mint(&pool, cred, None, "other").await.unwrap_err();
    assert_eq!(code(&err), "23514");
}
