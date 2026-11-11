//! `FleetCredentials` over a real tonic server on a loopback port with a fake GitHub seam.
//! The tests need a Postgres superuser URL in `DATABASE_URL`, which `#[sqlx::test]` reads to
//! create one database per test. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fleet_core::credential::{CredentialKind, Secret};
use fleet_proto::v1::fleet_credentials_client::FleetCredentialsClient;
use fleet_proto::v1::{
    DeleteCredentialRequest, ListCredentialsRequest, PutCredentialRequest, VerifyCredentialRequest,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::capability::{Capabilities, ERR_CAPABILITY_NOT_GRANTED};
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, Users};
use fleet_server::service::{MAX_CREDENTIAL_MESSAGE_BYTES, router_with};
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request};

const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const CLASSIC: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
static KEY_FILES: AtomicUsize = AtomicUsize::new(0);
const CLIENT: &str = "client-token-0123456789abcdef012345";
const STATIC: &str = "static_secret";
const FGJ: &str = "0123456789abcdef0123456789abcdef01234567";
const FGJ2: &str = "fedcba9876543210fedcba9876543210fedcba98";
const FGJ_HOST: &str = "git.example.com";
const FGJ_HOST_B: &str = "code.example.org";
const EXPIRY_MS: i64 = 1_900_000_000_000;

#[derive(Clone)]
struct FakeGithub {
    answer: Arc<Mutex<Result<GithubUser, GithubError>>>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl FakeGithub {
    fn answering(answer: Result<GithubUser, GithubError>) -> Self {
        Self {
            answer: Arc::new(Mutex::new(answer)),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn ok() -> Self {
        Self::answering(Ok(GithubUser {
            login: "octo".to_owned(),
            expires_at_ms: Some(EXPIRY_MS),
        }))
    }

    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

#[tonic::async_trait]
impl GithubApi for FakeGithub {
    async fn user(&self, token: &Secret) -> Result<GithubUser, GithubError> {
        self.seen
            .lock()
            .unwrap()
            .push(String::from_utf8(token.expose().to_vec()).unwrap());
        self.answer.lock().unwrap().clone()
    }
}

struct Harness {
    client: FleetCredentialsClient<Channel>,
    github: FakeGithub,
    alice: String,
    bob: String,
    pool: PgPool,
    alice_id: i64,
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn harness(pool: PgPool, github: FakeGithub) -> Harness {
    harness_with(pool, github, true).await
}

async fn harness_with(pool: PgPool, github: FakeGithub, configured: bool) -> Harness {
    build(pool, github, configured, true).await
}

async fn build(pool: PgPool, github: FakeGithub, configured: bool, with_users: bool) -> Harness {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice_id = user(&pool, "alice").await;
    let bob_id = user(&pool, "bob").await;
    let users = Users::new(pool.clone());
    let alice = users.create_api_token(alice_id, "t").await.unwrap();
    let bob = users.create_api_token(bob_id, "t").await.unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-cred-rpc-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let service = CredentialService::new(
        CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap())),
        Arc::new(github.clone()),
    );
    let auth = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let auth = if with_users {
        auth.with_users(users)
    } else {
        auth
    };
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with(&store, &auth, configured.then_some(service)).serve_with_incoming(incoming),
    );
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    Harness {
        client: FleetCredentialsClient::new(channel),
        github,
        alice: String::from_utf8(alice.token.expose().to_vec()).unwrap(),
        bob: String::from_utf8(bob.token.expose().to_vec()).unwrap(),
        pool,
        alice_id,
    }
}

fn as_user<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

fn put(kind: &str, value: &str) -> PutCredentialRequest {
    PutCredentialRequest {
        kind: kind.to_owned(),
        shape: STATIC.to_owned(),
        value: value.to_owned(),
        expires_at_ms: None,
        host: String::new(),
    }
}

async fn add_host(pool: &PgPool, host: &str) {
    sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
        .bind(host)
        .execute(pool)
        .await
        .unwrap();
}

fn put_on(host: &str, kind: &str, value: &str) -> PutCredentialRequest {
    let mut request = put(kind, value);
    host.clone_into(&mut request.host);
    request
}

async fn stored(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn put_rejects_classic_github_token_before_any_network_call(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", CLASSIC)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(!err.message().contains(CLASSIC));
    assert_eq!(h.github.calls(), 0);
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn put_rejects_unknown_kind_and_refreshing_file(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("gitlab_pat", PAT)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let mut file = put("anthropic_api_key", ANT);
    file.shape = "refreshing_file".to_owned();
    let err = h
        .client
        .put_credential(as_user(&h.alice, file))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn put_github_pat_stores_login_and_expiry_from_the_response(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let mut request = put("github_pat", PAT);
    request.expires_at_ms = Some(5);
    let info = h
        .client
        .put_credential(as_user(&h.alice, request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.kind, "github_pat");
    assert_eq!(info.login.as_deref(), Some("octo"));
    assert_eq!(info.expires_at_ms, Some(EXPIRY_MS.unsigned_abs()));
    assert_eq!(*h.github.seen.lock().unwrap(), vec![PAT.to_owned()]);
    let listed = h
        .client
        .list_credentials(as_user(&h.alice, ListCredentialsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials, vec![info]);
    let (owner,): (i64,) = sqlx::query_as("SELECT user_id FROM credentials")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(owner, h.alice_id);
}

#[sqlx::test]
async fn failed_verification_stores_nothing_and_leaks_nothing(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::answering(Err(GithubError::Rejected))).await;
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", PAT)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(!format!("{err:?}").contains(PAT));
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn unreachable_github_is_unavailable_and_stores_nothing(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::answering(Err(GithubError::Unavailable))).await;
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", PAT)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert!(!format!("{err:?}").contains(PAT));
    assert_eq!(stored(&h.pool).await, 0);
}

async fn grant_app(h: &Harness) {
    let admin: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, is_admin) VALUES ('root', true) RETURNING id",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    Capabilities::new(h.pool.clone())
        .grant(admin, h.alice_id, "forge:github_app")
        .await
        .unwrap();
}

#[sqlx::test]
async fn put_github_app_without_the_capability_is_refused_and_stores_nothing(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("github_app", "12345678")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), ERR_CAPABILITY_NOT_GRANTED);
    assert_eq!(h.github.calls(), 0);
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn put_github_app_with_the_capability_stores_the_installation_id(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    grant_app(&h).await;
    let mut request = put("github_app", "12345678");
    request.expires_at_ms = Some(1);
    let info = h
        .client
        .put_credential(as_user(&h.alice, request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.kind, "github_app");
    assert_eq!(info.shape, STATIC);
    assert_eq!(info.login, None);
    assert_eq!(info.expires_at_ms, None);
    assert_eq!(h.github.calls(), 0);
    assert_eq!(stored(&h.pool).await, 1);
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM credentials")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert!(!sealed.windows(8).any(|w| w == b"12345678"));
}

#[sqlx::test]
async fn put_github_app_refuses_hostile_installation_ids_even_with_the_capability(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    grant_app(&h).await;
    let long = "9".repeat(21);
    for value in [
        "",
        " ",
        " 1",
        "1 ",
        "1 2",
        "1\r",
        "1\r\n",
        "1\n",
        "\u{85}1",
        "1\u{2028}",
        "1\u{2029}",
        "0",
        "0123",
        "007",
        "+1",
        "-1",
        "1.0",
        "\u{661}",
        "\u{ff11}\u{ff12}",
        "12a",
        "1/2",
        "..",
        "1%2f",
        "1?x",
        "1#x",
        "1\\2",
        "18446744073709551616",
        long.as_str(),
        PAT,
    ] {
        let err = h
            .client
            .put_credential(as_user(&h.alice, put("github_app", value)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{value:?}");
        if value.len() > 4 {
            assert!(!err.message().contains(value), "{value:?}");
        }
    }
    assert_eq!(h.github.calls(), 0);
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn put_github_app_accepts_the_u64_edges(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    grant_app(&h).await;
    for value in ["1", "18446744073709551615"] {
        h.client
            .put_credential(as_user(&h.alice, put("github_app", value)))
            .await
            .unwrap();
    }
    assert_eq!(stored(&h.pool).await, 1);
}

#[sqlx::test]
async fn other_kinds_store_without_a_network_call(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let mut request = put("anthropic_api_key", ANT);
    request.expires_at_ms = Some(EXPIRY_MS.unsigned_abs());
    let info = h
        .client
        .put_credential(as_user(&h.alice, request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.login, None);
    assert_eq!(info.expires_at_ms, Some(EXPIRY_MS.unsigned_abs()));
    assert_eq!(h.github.calls(), 0);
}

#[sqlx::test]
async fn credentials_belong_to_the_caller_only(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let info = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", PAT)))
        .await
        .unwrap()
        .into_inner();
    let listed = h
        .client
        .list_credentials(as_user(&h.bob, ListCredentialsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials.len(), 0);
    let err = h
        .client
        .delete_credential(as_user(
            &h.bob,
            DeleteCredentialRequest {
                id: info.id,
                host: String::new(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let calls = h.github.calls();
    let err = h
        .client
        .verify_credential(as_user(&h.bob, VerifyCredentialRequest { id: info.id }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(h.github.calls(), calls);
    assert_eq!(stored(&h.pool).await, 1);
    h.client
        .delete_credential(as_user(
            &h.alice,
            DeleteCredentialRequest {
                id: info.id,
                host: String::new(),
            },
        ))
        .await
        .unwrap();
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn verify_reports_validity_login_and_expiry(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let info = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", PAT)))
        .await
        .unwrap()
        .into_inner();
    let reply = h
        .client
        .verify_credential(as_user(&h.alice, VerifyCredentialRequest { id: info.id }))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.valid);
    assert_eq!(reply.login.as_deref(), Some("octo"));
    assert_eq!(reply.expires_at_ms, Some(EXPIRY_MS.unsigned_abs()));
    *h.github.answer.lock().unwrap() = Err(GithubError::Rejected);
    let reply = h
        .client
        .verify_credential(as_user(&h.alice, VerifyCredentialRequest { id: info.id }))
        .await
        .unwrap()
        .into_inner();
    assert!(!reply.valid);
    let uses: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_use")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(uses, 0);
}

#[sqlx::test]
async fn verify_of_a_kind_without_a_verifier_is_a_failed_precondition(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let info = h
        .client
        .put_credential(as_user(&h.alice, put("anthropic_api_key", ANT)))
        .await
        .unwrap()
        .into_inner();
    let err = h
        .client
        .verify_credential(as_user(&h.alice, VerifyCredentialRequest { id: info.id }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn oversize_value_is_rejected(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let long = format!("github_pat_{}", "a".repeat(600));
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", &long)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(h.github.calls(), 0);
}

#[sqlx::test]
async fn message_over_the_decode_limit_is_refused(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let huge = "a".repeat(MAX_CREDENTIAL_MESSAGE_BYTES + 1);
    let err = h
        .client
        .put_credential(as_user(&h.alice, put("anthropic_api_key", &huge)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::OutOfRange);
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn box_token_is_denied(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let err = h
        .client
        .list_credentials(as_user(
            "box-token-0123456789abcdef0123456789",
            ListCredentialsRequest {},
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[sqlx::test]
async fn out_of_range_expiry_is_invalid_argument_for_every_kind(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    grant_app(&h).await;
    add_host(&h.pool, FGJ_HOST).await;
    for kind in CredentialKind::ALL {
        let value = match kind {
            CredentialKind::GithubPat => PAT,
            CredentialKind::GithubApp => "12345678",
            CredentialKind::ForgejoPat => FGJ,
            _ => ANT,
        };
        let host = if kind == CredentialKind::ForgejoPat {
            FGJ_HOST
        } else {
            ""
        };
        for ms in [
            253_402_300_800_000,
            u64::MAX,
            u64::try_from(i64::MAX).unwrap() + 1,
        ] {
            let mut request = put(kind.wire_name(), value);
            request.host = host.to_owned();
            request.expires_at_ms = Some(ms);
            let err = h
                .client
                .put_credential(as_user(&h.alice, request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "{kind:?} {ms}");
        }
        assert_eq!(stored(&h.pool).await, 0, "{kind:?}");
        let mut request = put(kind.wire_name(), value);
        request.host = host.to_owned();
        request.expires_at_ms = Some(253_402_300_799_000);
        h.client
            .put_credential(as_user(&h.alice, request))
            .await
            .unwrap();
        sqlx::query("DELETE FROM credentials")
            .execute(&h.pool)
            .await
            .unwrap();
    }
}

#[sqlx::test]
async fn a_rejected_re_put_leaves_the_stored_credential_intact(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let first = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", PAT)))
        .await
        .unwrap()
        .into_inner();
    let before: (Vec<u8>, String) =
        sqlx::query_as("SELECT ciphertext, fingerprint FROM credentials")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    *h.github.answer.lock().unwrap() = Err(GithubError::Rejected);
    let err = h
        .client
        .put_credential(as_user(
            &h.alice,
            put("github_pat", "github_pat_22ZZZZZZZ9zzzzzzzzzzzzzzzz"),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let after: (Vec<u8>, String) =
        sqlx::query_as("SELECT ciphertext, fingerprint FROM credentials")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    let listed = h
        .client
        .list_credentials(as_user(&h.alice, ListCredentialsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials, vec![first]);
}

#[sqlx::test]
async fn the_caller_is_checked_before_the_unconfigured_state(pool: PgPool) {
    let mut h = build(pool, FakeGithub::ok(), false, false).await;
    let err = h
        .client
        .list_credentials(as_user(CLIENT, ListCredentialsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "credentials need a user token");
}

#[sqlx::test]
async fn a_user_token_on_an_unconfigured_server_is_failed_precondition(pool: PgPool) {
    let mut h = harness_with(pool, FakeGithub::ok(), false).await;
    let err = h
        .client
        .list_credentials(as_user(&h.alice, ListCredentialsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn forgejo_pat_is_stored_for_its_host_without_a_github_call(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    add_host(&h.pool, FGJ_HOST).await;
    let info = h
        .client
        .put_credential(as_user(
            &h.alice,
            put_on("Git.Example.COM", "forgejo_pat", FGJ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.host, FGJ_HOST);
    assert_eq!(info.kind, "forgejo_pat");
    assert_eq!(info.login, None);
    assert_eq!(h.github.calls(), 0);
    let listed = h
        .client
        .list_credentials(as_user(&h.alice, ListCredentialsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials, vec![info]);
}

#[sqlx::test]
async fn put_refuses_a_missing_unknown_or_mismatched_host(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    add_host(&h.pool, FGJ_HOST).await;
    for (request, code, message) in [
        (
            put_on("", "forgejo_pat", FGJ),
            Code::InvalidArgument,
            "host is empty",
        ),
        (
            put_on(FGJ_HOST_B, "forgejo_pat", FGJ),
            Code::FailedPrecondition,
            fleet_proto::PRECONDITION_HOST_UNKNOWN,
        ),
        (
            put_on("github.com", "forgejo_pat", FGJ),
            Code::InvalidArgument,
            "credential kind does not fit the host",
        ),
        (
            put_on(FGJ_HOST, "github_pat", PAT),
            Code::InvalidArgument,
            "credential kind does not fit the host",
        ),
        (
            put_on("https://git.example.com", "forgejo_pat", FGJ),
            Code::InvalidArgument,
            "host contains a scheme",
        ),
    ] {
        let err = h
            .client
            .put_credential(as_user(&h.alice, request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "{message}");
        assert_eq!(err.message(), message);
        assert!(!err.message().contains(FGJ));
    }
    assert_eq!(h.github.calls(), 0);
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn put_refuses_a_malformed_forgejo_token_before_the_host_lookup(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    add_host(&h.pool, FGJ_HOST).await;
    for bad in [FGJ.to_uppercase(), FGJ[..39].to_owned(), format!("{FGJ}0")] {
        let err = h
            .client
            .put_credential(as_user(&h.alice, put_on(FGJ_HOST, "forgejo_pat", &bad)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "forgejo_pat must be 40 lowercase hex characters"
        );
        assert!(!err.message().contains(&bad));
    }
    assert_eq!(stored(&h.pool).await, 0);
}

#[sqlx::test]
async fn delete_takes_the_host_and_refuses_another(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    add_host(&h.pool, FGJ_HOST).await;
    add_host(&h.pool, FGJ_HOST_B).await;
    let a = h
        .client
        .put_credential(as_user(&h.alice, put_on(FGJ_HOST, "forgejo_pat", FGJ)))
        .await
        .unwrap()
        .into_inner();
    h.client
        .put_credential(as_user(&h.alice, put_on(FGJ_HOST_B, "forgejo_pat", FGJ2)))
        .await
        .unwrap();
    for (host, code) in [
        (FGJ_HOST_B, Code::NotFound),
        ("", Code::InvalidArgument),
        ("unregistered.example.net", Code::FailedPrecondition),
        ("a\\b.example.com", Code::InvalidArgument),
    ] {
        let err = h
            .client
            .delete_credential(as_user(
                &h.alice,
                DeleteCredentialRequest {
                    id: a.id,
                    host: host.to_owned(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "{host:?}");
    }
    assert_eq!(stored(&h.pool).await, 2);
    h.client
        .delete_credential(as_user(
            &h.alice,
            DeleteCredentialRequest {
                id: a.id,
                host: FGJ_HOST.to_owned(),
            },
        ))
        .await
        .unwrap();
    assert_eq!(stored(&h.pool).await, 1);
}

#[sqlx::test]
async fn a_second_host_does_not_replace_the_first(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    add_host(&h.pool, FGJ_HOST).await;
    add_host(&h.pool, FGJ_HOST_B).await;
    for (host, value) in [(FGJ_HOST, FGJ), (FGJ_HOST_B, FGJ2)] {
        h.client
            .put_credential(as_user(&h.alice, put_on(host, "forgejo_pat", value)))
            .await
            .unwrap();
    }
    assert_eq!(stored(&h.pool).await, 2);
}

#[sqlx::test]
async fn a_forgejo_credential_cannot_be_verified(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    add_host(&h.pool, FGJ_HOST).await;
    let info = h
        .client
        .put_credential(as_user(&h.alice, put_on(FGJ_HOST, "forgejo_pat", FGJ)))
        .await
        .unwrap()
        .into_inner();
    let err = h
        .client
        .verify_credential(as_user(&h.alice, VerifyCredentialRequest { id: info.id }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(h.github.calls(), 0);
}

#[sqlx::test]
async fn the_cap_counts_each_host_and_lets_an_existing_pair_be_replaced(pool: PgPool) {
    let mut h = harness(pool, FakeGithub::ok()).await;
    let cap = fleet_proto::MAX_CREDENTIALS_PER_USER;
    sqlx::query(
        "INSERT INTO git_hosts (host, kind) SELECT 'h' || g || '.example.com', 'forgejo' \
         FROM generate_series(1, $1::int + 1) g",
    )
    .bind(i32::try_from(cap).unwrap())
    .execute(&h.pool)
    .await
    .unwrap();
    for n in 1..cap {
        h.client
            .put_credential(as_user(
                &h.alice,
                put_on(&format!("h{n}.example.com"), "forgejo_pat", FGJ),
            ))
            .await
            .unwrap();
    }
    h.client
        .put_credential(as_user(&h.alice, put("anthropic_api_key", ANT)))
        .await
        .unwrap();
    let extra = format!("h{}.example.com", cap + 1);
    let err = h
        .client
        .put_credential(as_user(&h.alice, put_on(&extra, "forgejo_pat", FGJ)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(stored(&h.pool).await, i64::try_from(cap).unwrap());
    h.client
        .put_credential(as_user(
            &h.alice,
            put_on("h1.example.com", "forgejo_pat", FGJ2),
        ))
        .await
        .unwrap();
    assert_eq!(stored(&h.pool).await, i64::try_from(cap).unwrap());
    let github = h
        .client
        .put_credential(as_user(&h.alice, put("github_pat", PAT)))
        .await
        .unwrap_err();
    assert_eq!(github.code(), Code::ResourceExhausted);
    assert_eq!(h.github.calls(), 0);
}
