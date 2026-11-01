//! The bootstrap password for the first admin, driven straight through `WebAuth` with a
//! software authenticator. They need a Postgres superuser URL in `DATABASE_URL` for
//! `#[sqlx::test]`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::limiter::{Clock, Limiter};
use fleet_server::cred::password::BootstrapPassword;
use fleet_server::cred::users::Users;
use fleet_server::web::{AuthError, NewSession, WebAuth};
use sqlx::PgPool;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::Url;

const ORIGIN: &str = "https://fleet.example.com";
const PASSWORD: &str = "Zx9-correct-horse-battery";
const WRONG: &str = "Zx9-correct-horse-batterz";
const WINDOW: Duration = Duration::from_secs(60);
const IP_LIMIT: usize = 3;
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));

type Authenticator = WebauthnAuthenticator<SoftPasskey>;

fn authenticator() -> Authenticator {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

fn clock() -> (Clock, Arc<Mutex<Instant>>) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&now);
    let read: Clock = Arc::new(move || *handle.lock().unwrap());
    (read, now)
}

fn web(pool: &PgPool, password: BootstrapPassword, clock: Clock) -> (WebAuth, Users) {
    let users = Users::new(pool.clone());
    let limiter = Limiter::with_limits(clock, 100, IP_LIMIT, WINDOW);
    let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com"))
        .unwrap()
        .with_bootstrap(password, Arc::new(limiter), 0);
    (auth, users)
}

async fn armed_web(pool: &PgPool) -> (WebAuth, Users) {
    let (read, _) = clock();
    let password = BootstrapPassword::from_plaintext(PASSWORD.to_owned())
        .await
        .unwrap();
    web(pool, password, read)
}

async fn redeem(
    auth: &WebAuth,
    password: &str,
    name: &str,
    ip: IpAddr,
) -> Result<NewSession, AuthError> {
    let (ceremony, options) = auth.setup_password_start(password, name, ip).await?;
    let credential = authenticator()
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    auth.setup_finish(&ceremony, &credential, ip).await
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

fn is_refused<T>(outcome: &Result<T, AuthError>) -> bool {
    matches!(outcome, Err(AuthError::Refused))
}

#[sqlx::test]
async fn the_password_creates_the_first_admin_and_revokes_itself_in_one_transaction(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    assert!(users.bootstrap_password_armed().await.unwrap());
    redeem(&auth, PASSWORD, "alice", LOCAL).await.unwrap();

    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 1);
    assert_eq!(count(&pool, "SELECT count(*) FROM web_sessions").await, 1);
    let row: (String, bool) =
        sqlx::query_as("SELECT hash, revoked_at IS NOT NULL FROM bootstrap_password")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (String::new(), true));
    let audit: (String, String, String) = sqlx::query_as(
        "SELECT action, username, operator FROM admin_audit WHERE action = 'bootstrap_password_revoked'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit,
        (
            "bootstrap_password_revoked".to_owned(),
            "alice".to_owned(),
            "server".to_owned()
        )
    );
    assert!(!users.bootstrap_password_armed().await.unwrap());
    assert!(is_refused(&redeem(&auth, PASSWORD, "bob", LOCAL).await));
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM users WHERE lower(username) <> 'bootstrap'"
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn wrong_revoked_unconfigured_and_rate_limited_all_refuse_alike(pool: PgPool) {
    let (auth, _) = armed_web(&pool).await;
    let wrong = auth.setup_password_start(WRONG, "alice", LOCAL).await;
    assert!(is_refused(&wrong));

    let (read, _) = clock();
    let (none, _) = web(&pool, BootstrapPassword::disarmed(), read);
    let unconfigured = none.setup_password_start(PASSWORD, "alice", LOCAL).await;
    assert!(is_refused(&unconfigured));

    let (limited_auth, _) = armed_web(&pool).await;
    for _ in 0..IP_LIMIT {
        let _ = limited_auth
            .setup_password_start(WRONG, "alice", OTHER)
            .await;
    }
    let limited = limited_auth
        .setup_password_start(PASSWORD, "alice", OTHER)
        .await;
    assert!(is_refused(&limited));

    redeem(&auth, PASSWORD, "alice", LOCAL).await.unwrap();
    let revoked = auth.setup_password_start(PASSWORD, "bob", LOCAL).await;
    assert!(is_refused(&revoked));

    let texts: Vec<String> = [wrong, unconfigured, limited, revoked]
        .into_iter()
        .map(|outcome| outcome.map(|_| ()).unwrap_err().to_string())
        .collect();
    assert!(
        texts.iter().all(|text| text == "request refused"),
        "{texts:?}"
    );
}

#[sqlx::test]
async fn the_reserved_bootstrap_user_never_gets_a_password_and_nothing_is_revoked(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    for name in ["bootstrap", "Bootstrap", "BOOTSTRAP"] {
        assert!(is_refused(
            &auth.setup_password_start(PASSWORD, name, LOCAL).await
        ));
    }
    assert!(users.begin_redeem_password("bootstrap").await.is_err());
    assert_eq!(
        count(&pool, "SELECT count(*) FROM bootstrap_password").await,
        0
    );
    assert!(users.bootstrap_password_armed().await.unwrap());
}

#[sqlx::test]
async fn a_failing_passkey_insert_leaves_the_password_unrevoked(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    let (ceremony, options) = auth
        .setup_password_start(PASSWORD, "alice", LOCAL)
        .await
        .unwrap();
    let credential = authenticator()
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let bootstrap = users.bootstrap_user().await.unwrap();
    sqlx::query("INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)")
        .bind(bootstrap)
        .bind(credential.raw_id.as_ref())
        .bind(b"x".as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let outcome = auth.setup_finish(&ceremony, &credential, LOCAL).await;
    assert!(outcome.is_err());
    assert_eq!(
        count(&pool, "SELECT count(*) FROM bootstrap_password").await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM admin_audit WHERE action = 'bootstrap_password_revoked'"
        )
        .await,
        0
    );
    assert!(!users.has_real_users().await.unwrap());
    assert!(users.bootstrap_password_armed().await.unwrap());
    redeem(&auth, PASSWORD, "alice", LOCAL).await.unwrap();
}

#[sqlx::test]
async fn two_concurrent_redeems_let_exactly_one_win(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    let auth = Arc::new(auth);
    let first = {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move { redeem(&auth, PASSWORD, "alice", LOCAL).await.is_ok() })
    };
    let second = {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move { redeem(&auth, PASSWORD, "bob", OTHER).await.is_ok() })
    };
    let wins = [first.await.unwrap(), second.await.unwrap()]
        .into_iter()
        .filter(|won| *won)
        .count();
    assert_eq!(wins, 1);
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 1);
    assert_eq!(
        count(&pool, "SELECT count(*) FROM bootstrap_password").await,
        1
    );
    assert!(!users.bootstrap_password_armed().await.unwrap());
}

#[sqlx::test]
async fn a_reset_never_re_arms_the_password(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    redeem(&auth, PASSWORD, "alice", LOCAL).await.unwrap();
    let reset = run(
        &pool,
        &AdminCommand::ResetPasskeys("alice".to_owned()),
        "operator",
    )
    .await
    .unwrap();
    assert_eq!(reset.passkeys_removed, 1);
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 0);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NOT NULL FROM bootstrap_password")
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    assert!(!users.bootstrap_password_armed().await.unwrap());
    assert!(is_refused(&redeem(&auth, PASSWORD, "alice", LOCAL).await));
    assert!(is_refused(&redeem(&auth, PASSWORD, "carol", LOCAL).await));
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 0);
}

#[sqlx::test]
async fn a_concurrent_reset_and_redeem_leave_the_password_revoked(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    redeem(&auth, PASSWORD, "alice", LOCAL).await.unwrap();
    let auth = Arc::new(auth);
    let again = {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move { redeem(&auth, PASSWORD, "alice", LOCAL).await.is_ok() })
    };
    let reset = {
        let pool = pool.clone();
        tokio::spawn(async move {
            run(
                &pool,
                &AdminCommand::ResetPasskeys("alice".to_owned()),
                "operator",
            )
            .await
            .is_ok()
        })
    };
    assert!(!again.await.unwrap());
    assert!(reset.await.unwrap());
    assert!(!users.bootstrap_password_armed().await.unwrap());
    assert_eq!(count(&pool, "SELECT count(*) FROM passkeys").await, 0);
}

#[sqlx::test]
async fn one_client_is_limited_while_another_is_not_and_the_window_slides(pool: PgPool) {
    let (read, now) = clock();
    let password = BootstrapPassword::from_plaintext(PASSWORD.to_owned())
        .await
        .unwrap();
    let (auth, _) = web(&pool, password, read);
    for _ in 0..IP_LIMIT - 1 {
        assert!(is_refused(
            &auth.setup_password_start(WRONG, "alice", OTHER).await
        ));
    }
    let (ceremony, _) = auth
        .setup_password_start(PASSWORD, "alice", OTHER)
        .await
        .unwrap();
    assert_ne!(ceremony.len(), 0);
    assert!(is_refused(
        &auth.setup_password_start(WRONG, "alice", OTHER).await
    ));
    assert!(is_refused(
        &auth.setup_password_start(PASSWORD, "alice", OTHER).await
    ));
    auth.setup_password_start(PASSWORD, "alice", LOCAL)
        .await
        .unwrap();
    *now.lock().unwrap() += WINDOW;
    auth.setup_password_start(PASSWORD, "alice", OTHER)
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_parallel_burst_from_one_client_reaches_at_most_the_limit_in_hashes(pool: PgPool) {
    let (read, _) = clock();
    let password = BootstrapPassword::from_plaintext(PASSWORD.to_owned())
        .await
        .unwrap();
    let users = Users::new(pool.clone());
    let limiter = Limiter::with_limits(read, 100, 1, WINDOW);
    let auth = Arc::new(
        WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com"))
            .unwrap()
            .with_bootstrap(password.clone(), Arc::new(limiter), 0),
    );
    let before = password.hash_runs();
    let burst: Vec<_> = (0..12)
        .map(|_| {
            let auth = Arc::clone(&auth);
            tokio::spawn(async move { auth.setup_password_start(WRONG, "alice", LOCAL).await })
        })
        .collect();
    for task in burst {
        assert!(is_refused(&task.await.unwrap()));
    }
    assert_eq!(password.hash_runs() - before, 1);
}

#[sqlx::test]
async fn a_parallel_burst_over_the_global_limit_reaches_at_most_it_in_hashes(pool: PgPool) {
    let (read, _) = clock();
    let password = BootstrapPassword::from_plaintext(PASSWORD.to_owned())
        .await
        .unwrap();
    let users = Users::new(pool.clone());
    let limiter = Limiter::with_limits(read, 1, 100, WINDOW);
    let auth = Arc::new(
        WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com"))
            .unwrap()
            .with_bootstrap(password.clone(), Arc::new(limiter), 0),
    );
    let burst: Vec<_> = (0..12u8)
        .map(|n| {
            let auth = Arc::clone(&auth);
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100 + n));
            tokio::spawn(async move { auth.setup_password_start(WRONG, "alice", ip).await })
        })
        .collect();
    for task in burst {
        assert!(is_refused(&task.await.unwrap()));
    }
    assert_eq!(password.hash_runs(), 1);
}

#[sqlx::test]
async fn successful_verifies_do_not_consume_the_budget(pool: PgPool) {
    let (auth, _) = armed_web(&pool).await;
    for _ in 0..IP_LIMIT * 3 {
        auth.setup_password_start(PASSWORD, "alice", OTHER)
            .await
            .unwrap();
    }
    for _ in 0..IP_LIMIT {
        assert!(is_refused(
            &auth.setup_password_start(WRONG, "alice", OTHER).await
        ));
    }
    assert!(is_refused(
        &auth.setup_password_start(PASSWORD, "alice", OTHER).await
    ));
}

#[sqlx::test]
async fn a_database_failure_releases_the_reservation(pool: PgPool) {
    let (auth, _) = armed_web(&pool).await;
    pool.close().await;
    for _ in 0..IP_LIMIT * 3 {
        let outcome = auth.setup_password_start(PASSWORD, "alice", OTHER).await;
        assert!(matches!(outcome, Err(AuthError::Internal)), "{outcome:?}");
    }
}

#[sqlx::test]
async fn a_correct_password_with_a_hostile_username_is_refused_and_leaves_state(pool: PgPool) {
    let (auth, users) = armed_web(&pool).await;
    for name in ["", "a b", "caf\u{e9}", "al\nice", &"x".repeat(65)] {
        assert!(is_refused(
            &auth.setup_password_start(PASSWORD, name, LOCAL).await
        ));
    }
    assert!(users.bootstrap_password_armed().await.unwrap());
    assert_eq!(
        count(&pool, "SELECT count(*) FROM bootstrap_password").await,
        0
    );
}
