//! Admin subcommand tests: user create and passkey reset by direct database access. They need
//! a Postgres superuser URL in `DATABASE_URL`, which `#[sqlx::test]` reads.

use std::process::{Command, Output};

use fleet_server::cred::admin::{AdminCommand, AdminError, SETUP_CODE_TTL_HOURS, parse_args, run};
use fleet_server::cred::users::{UserError, Users};
use sqlx::{ConnectOptions, PgPool};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn run_bin(url: &str, cmd: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fleet-server"))
        .arg("admin")
        .args(cmd)
        .env_clear()
        .env("FLEET_DATABASE_URL", url)
        .output()
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

async fn count(pool: &PgPool, sql: &'static str) -> Res<i64> {
    Ok(sqlx::query_scalar(sql).fetch_one(pool).await?)
}

async fn user_with_passkey(pool: &PgPool, name: &str) -> Res<i64> {
    let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await?;
    sqlx::query("INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("cred-{name}").into_bytes())
        .bind(vec![1_u8])
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
         VALUES (sha256($1::bytea), $2, 'c', now() + interval '1 hour')",
    )
    .bind(name.as_bytes())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn add_tokens(pool: &PgPool, user: i64, active: usize, revoked: usize) -> Res<()> {
    for n in 0..active + revoked {
        sqlx::query(
            "INSERT INTO api_tokens (user_id, hash, revoked_at) \
             VALUES ($1, sha256($2::bytea), CASE WHEN $3 THEN now() - interval '1 day' END)",
        )
        .bind(user)
        .bind(format!("tok-{user}-{n}").into_bytes())
        .bind(n >= active)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn active_tokens(pool: &PgPool, user: i64) -> Res<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(pool)
    .await?)
}

#[sqlx::test]
async fn reset_revokes_active_tokens_of_that_user_only_and_counts_them(pool: PgPool) {
    let alice = user_with_passkey(&pool, "alice").await.unwrap();
    let bob = user_with_passkey(&pool, "bob").await.unwrap();
    add_tokens(&pool, alice, 2, 1).await.unwrap();
    add_tokens(&pool, bob, 2, 0).await.unwrap();
    let old: String = sqlx::query_scalar(
        "SELECT revoked_at::text FROM api_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .unwrap();
    let done = run(&pool, &AdminCommand::ResetPasskeys("alice".into()), "op")
        .await
        .unwrap();
    assert_eq!(done.tokens_revoked, 2);
    assert_eq!(active_tokens(&pool, alice).await.unwrap(), 0);
    assert_eq!(active_tokens(&pool, bob).await.unwrap(), 2);
    let after: String = sqlx::query_scalar(
        "SELECT min(revoked_at)::text FROM api_tokens WHERE user_id = $1 \
         AND revoked_at < now() - interval '12 hours'",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old, after);
    let audited: i32 =
        sqlx::query_scalar("SELECT tokens_revoked FROM admin_audit WHERE user_id = $1")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audited, 2);
}

#[sqlx::test]
async fn create_user_audits_zero_tokens_revoked(pool: PgPool) {
    let done = run(&pool, &AdminCommand::CreateUser("alice".into()), "op")
        .await
        .unwrap();
    assert_eq!(done.tokens_revoked, 0);
    let audited: i32 = sqlx::query_scalar("SELECT tokens_revoked FROM admin_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audited, 0);
}

#[sqlx::test]
async fn a_rolled_back_reset_leaves_tokens_valid(pool: PgPool) {
    let alice = user_with_passkey(&pool, "alice").await.unwrap();
    add_tokens(&pool, alice, 2, 0).await.unwrap();
    sqlx::query("DROP TABLE admin_audit")
        .execute(&pool)
        .await
        .unwrap();
    run(&pool, &AdminCommand::ResetPasskeys("alice".into()), "op")
        .await
        .unwrap_err();
    assert_eq!(active_tokens(&pool, alice).await.unwrap(), 2);
    assert_eq!(
        count(&pool, "SELECT count(*) FROM passkeys").await.unwrap(),
        1
    );
}

#[sqlx::test]
async fn the_binary_reports_tokens_ttl_and_a_blank_operator(pool: PgPool) {
    let url = pool.connect_options().to_url_lossy().to_string();
    let alice = user_with_passkey(&pool, "alice").await.unwrap();
    add_tokens(&pool, alice, 3, 0).await.unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_fleet-server"))
        .args(["admin", "reset-passkeys", "alice"])
        .env_clear()
        .env("FLEET_DATABASE_URL", &url)
        .env("USER", "")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("api tokens revoked: 3\n"), "{stdout}");
    assert!(
        stdout.contains(&format!("expires in {SETUP_CODE_TTL_HOURS} hours")),
        "{stdout}"
    );
    let operator: String = sqlx::query_scalar("SELECT operator FROM admin_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(operator, "unknown");
}

#[test]
fn database_failure_prints_the_migration_hint() {
    let err = AdminError::from(sqlx::Error::PoolTimedOut);
    assert_eq!(err.to_string(), "database error: is the database migrated?");
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn parse_accepts_the_two_commands() {
    assert_eq!(
        parse_args(&args(&["create-user", "alice"])).unwrap(),
        AdminCommand::CreateUser("alice".into())
    );
    assert_eq!(
        parse_args(&args(&["reset-passkeys", "alice"])).unwrap(),
        AdminCommand::ResetPasskeys("alice".into())
    );
}

#[test]
fn parse_rejects_bad_usage_with_exit_code_2() {
    for bad in [
        args(&[]),
        args(&["create-user"]),
        args(&["create-user", "a", "b"]),
        args(&["reset-passkeys"]),
        args(&["frobnicate", "a"]),
    ] {
        let err = parse_args(&bad).unwrap_err();
        assert!(matches!(err, AdminError::Usage), "{bad:?}");
        assert_eq!(err.exit_code(), 2);
    }
}

#[test]
fn exit_codes_are_fixed() {
    assert_eq!(AdminError::Usage.exit_code(), 2);
    assert_eq!(AdminError::NoSuchUser.exit_code(), 3);
    assert_eq!(AdminError::User(UserError::Taken).exit_code(), 4);
    assert_eq!(AdminError::User(UserError::InvalidUsername).exit_code(), 5);
    assert_eq!(AdminError::User(UserError::ReservedUsername).exit_code(), 5);
    assert_eq!(AdminError::User(UserError::NotFound).exit_code(), 1);
}

#[sqlx::test]
async fn create_user_makes_a_user_a_hashed_code_and_an_audit_row(pool: PgPool) {
    let done = run(&pool, &AdminCommand::CreateUser("alice".into()), "op")
        .await
        .unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(done.user_id, id);
    let code = String::from_utf8(done.setup_code.expose().to_vec()).unwrap();
    assert!(code.len() >= 32);
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM setup_codes WHERE user_id = $1 AND hash = sha256($2::bytea) \
         AND used_at IS NULL AND expires_at > now() AND expires_at < now() + interval '2 days'",
    )
    .bind(id)
    .bind(code.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, 1);
    let plain: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM setup_codes WHERE position($1::bytea in hash) > 0",
    )
    .bind(code.as_bytes())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(plain, 0);
    let audit: (String, i64, String, String, i32, i32) = sqlx::query_as(
        "SELECT action, user_id, username, operator, passkeys_removed, sessions_revoked \
         FROM admin_audit",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit,
        ("user_create".into(), id, "alice".into(), "op".into(), 0, 0)
    );
}

#[sqlx::test]
async fn create_user_rejects_taken_invalid_and_reserved_names_without_an_audit_row(pool: PgPool) {
    run(&pool, &AdminCommand::CreateUser("alice".into()), "op")
        .await
        .unwrap();
    for (name, code) in [("ALICE", 4), ("a b", 5), ("bootstrap", 5)] {
        let err = run(&pool, &AdminCommand::CreateUser(name.into()), "op")
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), code, "{name}");
    }
    assert_eq!(
        count(&pool, "SELECT count(*) FROM admin_audit")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM setup_codes")
            .await
            .unwrap(),
        1
    );
}

#[sqlx::test]
async fn reset_removes_passkeys_and_sessions_of_that_user_only(pool: PgPool) {
    let alice = user_with_passkey(&pool, "alice").await.unwrap();
    user_with_passkey(&pool, "bob").await.unwrap();
    let done = run(&pool, &AdminCommand::ResetPasskeys("Alice".into()), "op")
        .await
        .unwrap();
    assert_eq!(done.user_id, alice);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM passkeys WHERE user_id = $1")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM web_sessions WHERE user_id = $1")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM passkeys").await.unwrap(),
        1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM web_sessions")
            .await
            .unwrap(),
        1
    );
    let audit: (String, i32, i32) = sqlx::query_as(
        "SELECT action, passkeys_removed, sessions_revoked FROM admin_audit WHERE user_id = $1",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit, ("passkey_reset".into(), 1, 1));
}

#[sqlx::test]
async fn reset_replaces_older_unused_codes_with_one_fresh_code(pool: PgPool) {
    let first = run(&pool, &AdminCommand::CreateUser("alice".into()), "op")
        .await
        .unwrap();
    let second = run(&pool, &AdminCommand::ResetPasskeys("alice".into()), "op")
        .await
        .unwrap();
    assert_ne!(first.setup_code.expose(), second.setup_code.expose());
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM setup_codes WHERE used_at IS NULL"
        )
        .await
        .unwrap(),
        1
    );
    let users = Users::new(pool.clone());
    assert!(matches!(
        users.redeem_user_setup(first.setup_code.expose()).await,
        Err(UserError::BadSetupCode)
    ));
    assert_eq!(
        users
            .redeem_user_setup(second.setup_code.expose())
            .await
            .unwrap(),
        second.user_id
    );
}

#[sqlx::test]
async fn a_setup_code_works_once_and_not_after_expiry(pool: PgPool) {
    let users = Users::new(pool.clone());
    let done = run(&pool, &AdminCommand::CreateUser("alice".into()), "op")
        .await
        .unwrap();
    assert_eq!(
        users
            .redeem_user_setup(done.setup_code.expose())
            .await
            .unwrap(),
        done.user_id
    );
    assert!(matches!(
        users.redeem_user_setup(done.setup_code.expose()).await,
        Err(UserError::BadSetupCode)
    ));
    let again = run(&pool, &AdminCommand::ResetPasskeys("alice".into()), "op")
        .await
        .unwrap();
    sqlx::query("UPDATE setup_codes SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        users.redeem_user_setup(again.setup_code.expose()).await,
        Err(UserError::BadSetupCode)
    ));
}

#[sqlx::test]
async fn reset_of_unknown_or_bootstrap_user_fails_with_exit_code_3(pool: PgPool) {
    sqlx::query("SELECT bootstrap_user_id()")
        .execute(&pool)
        .await
        .unwrap();
    for name in ["ghost", "bootstrap"] {
        let err = run(&pool, &AdminCommand::ResetPasskeys(name.into()), "op")
            .await
            .unwrap_err();
        assert!(matches!(err, AdminError::NoSuchUser), "{name}");
        assert_eq!(err.exit_code(), 3);
    }
    assert_eq!(
        count(&pool, "SELECT count(*) FROM admin_audit")
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test]
async fn the_binary_prints_the_code_once_and_keeps_it_out_of_stderr(pool: PgPool) {
    let url = pool.connect_options().to_url_lossy().to_string();
    let out = run_bin(&url, &["create-user", "carol"]).unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let code = stdout
        .lines()
        .find_map(|l| l.strip_prefix("setup code: "))
        .unwrap()
        .to_owned();
    assert!(code.len() >= 32);
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&code));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM admin_audit")
            .await
            .unwrap(),
        1
    );

    let dup = run_bin(&url, &["create-user", "carol"]).unwrap();
    assert_eq!(dup.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&dup.stderr).contains("username is taken"));
    assert!(!String::from_utf8_lossy(&dup.stderr).contains(&url));

    let missing = run_bin(&url, &["reset-passkeys", "nobody"]).unwrap();
    assert_eq!(missing.status.code(), Some(3));
    let usage = run_bin(&url, &["create-user"]).unwrap();
    assert_eq!(usage.status.code(), Some(2));
    let no_url = Command::new(env!("CARGO_BIN_EXE_fleet-server"))
        .args(["admin", "create-user", "dave"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(no_url.status.code(), Some(6));
}
