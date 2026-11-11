//! Credential store tests. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_core::host::HostError;
use fleet_server::cred::FileSealer;
use fleet_server::cred::github::MAX_EXPIRY_MS;
use fleet_server::cred::store::{CredentialStore, StoreError};
use fleet_server::cred::users::{UserError, Users};
use sqlx::PgPool;

const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const PAT2: &str = "github_pat_22ZYXWVUT9zyxwvutsrqponmlk";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const STATIC: CredentialShape = CredentialShape::StaticSecret;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

fn key_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn key_paths_are_distinct_per_call() {
    assert_ne!(key_path("fleet-x"), key_path("fleet-x"));
}

fn store(pool: &PgPool, tag: &str) -> Res<CredentialStore> {
    let path = key_path(&format!("fleet-cred-store-{tag}"));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32)))?;
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path)?;
    Ok(CredentialStore::new(pool.clone(), Arc::new(sealer?)))
}

async fn user(pool: &PgPool, name: &str) -> Res<i64> {
    Ok(
        sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(pool)
            .await?,
    )
}

#[sqlx::test]
async fn list_returns_fingerprint_login_and_expiry_only(pool: PgPool) {
    let store = store(&pool, "list").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            Some("octo".into()),
            Some(1_900_000_000_000),
        )
        .await
        .unwrap();
    let listed = store.list(alice).await.unwrap();
    assert_eq!(listed, vec![put.clone()]);
    assert_eq!(put.kind, CredentialKind::GithubPat);
    assert_eq!(put.login.as_deref(), Some("octo"));
    assert_eq!(put.expires_at_ms, Some(1_900_000_000_000));
    assert_eq!(put.fingerprint.len(), 12);
    assert!(!format!("{put:?}").contains(PAT));
}

#[sqlx::test]
async fn put_replaces_the_credential_of_one_kind(pool: PgPool) {
    let store = store(&pool, "upsert").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let first = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let second = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT2.into()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_ne!(first.fingerprint, second.fingerprint);
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
    let opened = store.open_for_use(alice, second.id, "job-1").await.unwrap();
    assert_eq!(opened.expose(), PAT2.as_bytes());
}

#[sqlx::test]
async fn put_rejects_an_invalid_value(pool: PgPool) {
    let store = store(&pool, "invalid").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let err = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new("short".into()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Invalid(_)));
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
}

#[sqlx::test]
async fn put_validates_a_github_app_installation_id(pool: PgPool) {
    let store = store(&pool, "app-id").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    sqlx::query(
        "INSERT INTO user_capabilities (user_id, capability, granted_by) \
         VALUES ($1, 'forge:github_app', $1)",
    )
    .bind(alice)
    .execute(&pool)
    .await
    .unwrap();
    for bad in ["0", "12a", "99999999999999999999", "1/.."] {
        let err = store
            .put(
                alice,
                CredentialKind::GithubApp,
                STATIC,
                Secret::new(bad.into()),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{bad}");
    }
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
    store
        .put(
            alice,
            CredentialKind::GithubApp,
            STATIC,
            Secret::new("12345678".into()),
            None,
            None,
        )
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_tombstoned_credential_is_not_listed_or_opened(pool: PgPool) {
    let store = store(&pool, "tomb").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let kept = store
        .put(
            alice,
            CredentialKind::AnthropicApiKey,
            STATIC,
            Secret::new(ANT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let gone = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE id = $1")
        .bind(gone.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(store.list(alice).await.unwrap(), vec![kept]);
    let err = store
        .open_for_use(alice, gone.id, "job-1")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
    let err = store.open_for_verify(alice, gone.id).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
}

#[sqlx::test]
async fn put_rejects_an_expiry_outside_the_range(pool: PgPool) {
    let store = store(&pool, "expiry").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    for ms in [-1, MAX_EXPIRY_MS + 1, i64::MAX, i64::MIN] {
        let err = store
            .put(
                alice,
                CredentialKind::AnthropicApiKey,
                STATIC,
                Secret::new(ANT.into()),
                None,
                Some(ms),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidExpiry), "{ms}");
    }
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
    for ms in [0, MAX_EXPIRY_MS] {
        store
            .put(
                alice,
                CredentialKind::AnthropicApiKey,
                STATIC,
                Secret::new(ANT.into()),
                None,
                Some(ms),
            )
            .await
            .unwrap();
    }
}

#[sqlx::test]
async fn open_for_use_writes_one_credential_use_row(pool: PgPool) {
    let store = store(&pool, "use").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::AnthropicApiKey,
            STATIC,
            Secret::new(ANT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let opened = store.open_for_use(alice, put.id, "job-7").await.unwrap();
    assert_eq!(opened.expose(), ANT.as_bytes());
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT credential_id, job_id FROM credential_use")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![(put.id, "job-7".to_owned())]);
}

#[sqlx::test]
async fn a_user_cannot_read_or_delete_another_users_credential(pool: PgPool) {
    let store = store(&pool, "owner").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let read = store.open_for_use(bob, put.id, "job-1").await.unwrap_err();
    let del = store.delete(bob, put.id).await.unwrap_err();
    let missing = store
        .open_for_use(bob, put.id + 1000, "job-1")
        .await
        .unwrap_err();
    assert!(matches!(read, StoreError::NotFound));
    assert!(matches!(del, StoreError::NotFound));
    assert_eq!(read.to_string(), missing.to_string());
    assert_eq!(store.list(bob).await.unwrap().len(), 0);
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
    let uses: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(uses, 0);
}

#[sqlx::test]
async fn delete_is_final_and_keeps_use_rows(pool: PgPool) {
    let store = store(&pool, "delete").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    store.open_for_use(alice, put.id, "job-1").await.unwrap();
    store.delete(alice, put.id).await.unwrap();
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
    assert!(matches!(
        store
            .open_for_use(alice, put.id, "job-2")
            .await
            .unwrap_err(),
        StoreError::NotFound
    ));
    assert!(matches!(
        store.delete(alice, put.id).await.unwrap_err(),
        StoreError::NotFound
    ));
    let uses: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(uses, 1);
}

#[sqlx::test]
async fn database_holds_no_plaintext(pool: PgPool) {
    let store = store(&pool, "dump").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            Some("octo".into()),
            None,
        )
        .await
        .unwrap();
    store.open_for_use(alice, put.id, "job-1").await.unwrap();
    let dumps = [
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM users t",
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM credentials t",
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM credential_use t",
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM jobs t",
    ];
    for query in dumps {
        let dump: String = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
        assert!(!dump.contains(PAT), "{query}");
        assert!(!dump.contains("11ABCDEFG0"), "{query}");
    }
    let blob: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!blob.windows(PAT.len()).any(|w| w == PAT.as_bytes()));
}

#[sqlx::test]
async fn api_token_is_stored_as_hash_and_shown_once(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    let made = users.create_api_token(alice, "cli").await.unwrap();
    let plain = made.token.expose().to_vec();
    assert!(!format!("{made:?}").contains(std::str::from_utf8(&plain).unwrap()));
    let hashed: bool = sqlx::query_scalar(
        "SELECT hash = sha256($1::bytea) AND position($1::bytea IN hash) = 0 \
         FROM api_tokens WHERE id = $2",
    )
    .bind(&plain)
    .bind(made.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(hashed);
    assert_eq!(users.authenticate(&plain).await.unwrap(), Some(alice));
    assert_eq!(users.authenticate(b"flt_wrong").await.unwrap(), None);
    assert!(matches!(
        users.revoke_api_token(bob, made.id).await,
        Err(UserError::NotFound)
    ));
    assert_eq!(users.authenticate(&plain).await.unwrap(), Some(alice));
    users.revoke_api_token(alice, made.id).await.unwrap();
    assert_eq!(users.authenticate(&plain).await.unwrap(), None);
    assert!(matches!(
        users.revoke_api_token(alice, made.id).await,
        Err(UserError::NotFound)
    ));
}

#[sqlx::test]
async fn setup_code_is_single_use_and_ignores_the_bootstrap_user(pool: PgPool) {
    let users = Users::new(pool.clone());
    let boot = users.bootstrap_user().await.unwrap();
    assert_eq!(users.bootstrap_user().await.unwrap(), boot);
    assert!(!users.has_real_users().await.unwrap());
    let code = users.issue_setup_code().await.unwrap().unwrap();
    let code = code.expose().to_vec();
    assert!(matches!(
        users.redeem_setup(b"wrong", "admin").await,
        Err(UserError::BadSetupCode)
    ));
    assert!(matches!(
        users.redeem_setup(&code, "Bootstrap").await,
        Err(UserError::ReservedUsername)
    ));
    assert!(matches!(
        users.redeem_setup(&code, "bad name").await,
        Err(UserError::InvalidUsername)
    ));
    let admin = users.redeem_setup(&code, "admin").await.unwrap();
    assert_ne!(admin, boot);
    assert!(users.has_real_users().await.unwrap());
    assert!(matches!(
        users.redeem_setup(&code, "other").await,
        Err(UserError::BadSetupCode)
    ));
    assert!(users.issue_setup_code().await.unwrap().is_none());
}

#[sqlx::test]
async fn setup_is_inert_once_any_user_exists(pool: PgPool) {
    let users = Users::new(pool.clone());
    let code = users.issue_setup_code().await.unwrap().unwrap();
    user(&pool, "alice").await.unwrap();
    assert!(matches!(
        users.redeem_setup(code.expose(), "admin").await,
        Err(UserError::SetupClosed)
    ));
    assert!(matches!(
        users.redeem_setup(code.expose(), "admin").await,
        Err(UserError::BadSetupCode)
    ));
    let fresh = Users::new(pool);
    assert!(fresh.issue_setup_code().await.unwrap().is_none());
}

const FGJ_A: &str = "0123456789abcdef0123456789abcdef01234567";
const FGJ_B: &str = "fedcba9876543210fedcba9876543210fedcba98";
const HOST_A: &str = "git.example.com";
const HOST_B: &str = "code.example.org";

async fn add_host(pool: &PgPool, host: &str) {
    sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
        .bind(host)
        .execute(pool)
        .await
        .unwrap();
}

async fn put_forgejo(
    store: &CredentialStore,
    user: i64,
    host: &str,
    value: &str,
) -> Result<fleet_server::cred::store::CredentialSummary, StoreError> {
    store
        .put_for_host(
            user,
            host,
            CredentialKind::ForgejoPat,
            STATIC,
            Secret::new(value.into()),
            None,
            None,
        )
        .await
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    let sql = match table {
        "credentials" => "SELECT count(*) FROM credentials",
        _ => "SELECT count(*) FROM credential_audit",
    };
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

fn hostile_hosts() -> Vec<String> {
    let long_label = format!("{}.example.com", "a".repeat(64));
    let long_name = format!("{}.example.com", "a.".repeat(130));
    let raw_long = "a".repeat(1025);
    [
        "",
        "a b.example.com",
        "a\tb.example.com",
        "a\r\nb.example.com",
        "a\u{85}b.example.com",
        "a\u{2028}b.example.com",
        "a\0b.example.com",
        "https://git.example.com",
        "git.example.com/path",
        "git.example.com?q=1",
        "git.example.com#f",
        "//git.example.com",
        "user@git.example.com",
        "git.example.com:443",
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "[::1]",
        "*.example.com",
        "a\\b.example.com",
        "-a.example.com",
        "a-.example.com",
        "a..example.com",
        "localhost",
        "printer.local",
        "svc.internal",
        "a\u{200b}b.example.com",
        long_label.as_str(),
        long_name.as_str(),
        raw_long.as_str(),
    ]
    .iter()
    .map(|h| (*h).to_owned())
    .filter(|h| !h.is_empty())
    .collect()
}

#[sqlx::test]
async fn forgejo_pat_is_stored_for_its_host_and_listed_with_it(pool: PgPool) {
    let store = store(&pool, "fgj-put").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let put = put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap();
    assert_eq!(put.host, HOST_A);
    assert_eq!(put.kind, CredentialKind::ForgejoPat);
    assert_eq!(store.list(alice).await.unwrap(), vec![put]);
}

#[sqlx::test]
async fn a_github_kind_keeps_github_com_by_default_and_explicitly(pool: PgPool) {
    let store = store(&pool, "fgj-gh").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let bare = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(bare.host, "github.com");
    let explicit = store
        .put_for_host(
            alice,
            "GitHub.COM",
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT2.into()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(explicit.host, "github.com");
    assert_eq!(explicit.id, bare.id);
    let agent = store
        .put(
            alice,
            CredentialKind::AnthropicApiKey,
            STATIC,
            Secret::new(ANT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(agent.host, "github.com");
}

#[sqlx::test]
async fn a_forgejo_pat_needs_a_host(pool: PgPool) {
    let store = store(&pool, "fgj-empty").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let err = put_forgejo(&store, alice, "", FGJ_A).await.unwrap_err();
    assert!(matches!(err, StoreError::HostInvalid(HostError::Empty)));
    assert_eq!(count(&pool, "credentials").await, 0);
    assert_eq!(count(&pool, "audit").await, 0);
}

#[sqlx::test]
async fn a_host_missing_from_git_hosts_is_refused(pool: PgPool) {
    let store = store(&pool, "fgj-unknown").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let err = put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap_err();
    assert!(matches!(err, StoreError::HostUnknown));
    assert_eq!(count(&pool, "credentials").await, 0);
    assert_eq!(count(&pool, "audit").await, 0);
}

#[sqlx::test]
async fn kind_and_host_kind_must_agree(pool: PgPool) {
    let store = store(&pool, "fgj-mismatch").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let err = put_forgejo(&store, alice, "github.com", FGJ_A)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::HostKindMismatch));
    let err = store
        .put_for_host(
            alice,
            HOST_A,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::HostKindMismatch));
    let err = store
        .put_for_host(
            alice,
            HOST_A,
            CredentialKind::AnthropicApiKey,
            STATIC,
            Secret::new(ANT.into()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::HostKindMismatch));
    assert_eq!(count(&pool, "credentials").await, 0);
    assert_eq!(count(&pool, "audit").await, 0);
}

#[sqlx::test]
async fn a_github_row_whose_host_row_is_gone_is_refused(pool: PgPool) {
    let store = store(&pool, "fgj-gone").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    sqlx::query("DELETE FROM git_hosts WHERE host = 'github.com'")
        .execute(&pool)
        .await
        .unwrap();
    let err = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::HostUnknown));
}

#[sqlx::test]
async fn hostile_hosts_are_refused_on_every_call(pool: PgPool) {
    let store = store(&pool, "fgj-hostile").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let kept = put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap();
    for host in hostile_hosts() {
        let put = put_forgejo(&store, alice, &host, FGJ_B).await;
        assert!(
            matches!(put, Err(StoreError::HostInvalid(_))),
            "put {host:?}"
        );
        let list = store.list_for_host(alice, &host).await;
        assert!(
            matches!(list, Err(StoreError::HostInvalid(_))),
            "list {host:?}"
        );
        let delete = store.delete_for_host(alice, kept.id, &host).await;
        assert!(
            matches!(delete, Err(StoreError::HostInvalid(_))),
            "delete {host:?}"
        );
        let open = store
            .open_for_host(alice, CredentialKind::ForgejoPat, &host)
            .await;
        assert!(
            matches!(open, Err(StoreError::HostInvalid(_))),
            "open {host:?}"
        );
    }
    assert_eq!(store.list(alice).await.unwrap(), vec![kept]);
    assert_eq!(count(&pool, "audit").await, 1);
}

#[sqlx::test]
async fn host_case_and_trailing_dot_normalise_to_one_row(pool: PgPool) {
    let store = store(&pool, "fgj-case").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let first = put_forgejo(&store, alice, "GIT.Example.COM", FGJ_A)
        .await
        .unwrap();
    let second = put_forgejo(&store, alice, "git.example.com.", FGJ_B)
        .await
        .unwrap();
    assert_eq!(first.host, HOST_A);
    assert_eq!(second.id, first.id);
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
}

#[sqlx::test]
async fn one_user_holds_one_forgejo_pat_per_host(pool: PgPool) {
    let store = store(&pool, "fgj-two").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    add_host(&pool, HOST_B).await;
    let a = put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap();
    let b = put_forgejo(&store, alice, HOST_B, FGJ_B).await.unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(store.list(alice).await.unwrap(), vec![a.clone(), b.clone()]);
    assert_eq!(store.list_for_host(alice, HOST_A).await.unwrap(), vec![a]);
    assert_eq!(store.list_for_host(alice, HOST_B).await.unwrap(), vec![b]);
    assert_eq!(store.list_for_host(alice, "").await.unwrap().len(), 2);
    let err = store.list_for_host(alice, "other.example.com").await;
    assert!(matches!(err, Err(StoreError::HostUnknown)));
}

#[sqlx::test]
async fn a_token_is_opened_only_for_the_host_it_was_stored_for(pool: PgPool) {
    let store = store(&pool, "fgj-iso").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    add_host(&pool, HOST_A).await;
    add_host(&pool, HOST_B).await;
    add_host(&pool, "empty.example.net").await;
    put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap();
    put_forgejo(&store, alice, HOST_B, FGJ_B).await.unwrap();
    put_forgejo(&store, bob, HOST_B, FGJ_A).await.unwrap();
    let (summary, secret) = store
        .open_for_host(alice, CredentialKind::ForgejoPat, HOST_B)
        .await
        .unwrap();
    assert_eq!(summary.host, HOST_B);
    assert_eq!(secret.expose(), FGJ_B.as_bytes());
    let (_, secret) = store
        .open_for_host(alice, CredentialKind::ForgejoPat, "Git.Example.com")
        .await
        .unwrap();
    assert_eq!(secret.expose(), FGJ_A.as_bytes());
    let none = store
        .open_for_host(alice, CredentialKind::ForgejoPat, "empty.example.net")
        .await;
    assert!(matches!(none, Err(StoreError::NotFound)));
    let (_, secret) = store
        .open_for_host(bob, CredentialKind::ForgejoPat, HOST_B)
        .await
        .unwrap();
    assert_eq!(secret.expose(), FGJ_A.as_bytes());
    let none = store
        .open_for_host(bob, CredentialKind::ForgejoPat, HOST_A)
        .await;
    assert!(matches!(none, Err(StoreError::NotFound)));
    let bare = store
        .open_for_host(alice, CredentialKind::ForgejoPat, "")
        .await;
    assert!(matches!(
        bare,
        Err(StoreError::HostInvalid(HostError::Empty))
    ));
    let other_kind = store
        .open_for_host(alice, CredentialKind::GithubPat, HOST_A)
        .await;
    assert!(matches!(other_kind, Err(StoreError::HostKindMismatch)));
}

#[sqlx::test]
async fn delete_needs_the_host_the_row_is_stored_for(pool: PgPool) {
    let store = store(&pool, "fgj-del").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    add_host(&pool, HOST_B).await;
    let a = put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap();
    let wrong = store.delete_for_host(alice, a.id, HOST_B).await;
    assert!(matches!(wrong, Err(StoreError::NotFound)));
    let unknown = store
        .delete_for_host(alice, a.id, "other.example.net")
        .await;
    assert!(matches!(unknown, Err(StoreError::HostUnknown)));
    let bare = store.delete_for_host(alice, a.id, "").await;
    assert!(matches!(
        bare,
        Err(StoreError::HostInvalid(HostError::Empty))
    ));
    let github = store.delete_for_host(alice, a.id, "github.com").await;
    assert!(matches!(github, Err(StoreError::HostKindMismatch)));
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
    assert_eq!(count(&pool, "audit").await, 1);
    store
        .delete_for_host(alice, a.id, "GIT.example.com")
        .await
        .unwrap();
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
}

#[sqlx::test]
async fn a_github_row_is_deleted_with_an_empty_or_github_host_only(pool: PgPool) {
    let store = store(&pool, "fgj-delgh").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let put = store
        .put(
            alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.into()),
            None,
            None,
        )
        .await
        .unwrap();
    let other = store.delete_for_host(alice, put.id, HOST_A).await;
    assert!(matches!(other, Err(StoreError::HostKindMismatch)));
    store
        .delete_for_host(alice, put.id, "github.com")
        .await
        .unwrap();
    assert_eq!(store.list(alice).await.unwrap().len(), 0);
}

#[sqlx::test]
async fn another_users_row_is_not_found_whatever_the_host(pool: PgPool) {
    let store = store(&pool, "fgj-foreign").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    let bob = user(&pool, "bob").await.unwrap();
    add_host(&pool, HOST_A).await;
    let a = put_forgejo(&store, alice, HOST_A, FGJ_A).await.unwrap();
    let err = store.delete_for_host(bob, a.id, HOST_A).await;
    assert!(matches!(err, Err(StoreError::NotFound)));
    assert_eq!(store.list(alice).await.unwrap().len(), 1);
}

#[sqlx::test]
async fn the_cap_counts_a_second_host_as_another_credential(pool: PgPool) {
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    add_host(&pool, HOST_B).await;
    let limited = CredentialStore::with_limit(pool.clone(), cap_sealer(), 1);
    put_forgejo(&limited, alice, HOST_A, FGJ_A).await.unwrap();
    put_forgejo(&limited, alice, HOST_A, FGJ_B).await.unwrap();
    let err = put_forgejo(&limited, alice, HOST_B, FGJ_B).await;
    assert!(matches!(err, Err(StoreError::TooMany)));
}

fn cap_sealer() -> Arc<FileSealer> {
    let path = key_path("fleet-cred-store-cap");
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    Arc::new(sealer.unwrap())
}

#[sqlx::test]
async fn a_put_waits_on_a_lock_held_on_the_host_row(pool: PgPool) {
    let store = store(&pool, "fgj-lock").unwrap();
    let alice = user(&pool, "alice").await.unwrap();
    add_host(&pool, HOST_A).await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT host FROM git_hosts WHERE host = $1 FOR UPDATE")
        .bind(HOST_A)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    let writer = store.clone();
    let task = tokio::spawn(async move { put_forgejo(&writer, alice, HOST_A, FGJ_A).await });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!task.is_finished());
    assert_eq!(count(&pool, "credentials").await, 0);
    holder.rollback().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(count(&pool, "credentials").await, 1);
}
