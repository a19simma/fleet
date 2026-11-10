//! Default Environment bindings (ADR-0067 decision 10): the schema, the three RPCs through the
//! production auth layer, the resolve order and the refusals around it. The tests need a
//! Postgres superuser URL in `DATABASE_URL` and live in their own binary because they bind
//! sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fleet_core::environment::{
    Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody, ScriptSpec, SecretSpec,
};
use fleet_proto::v1::fleet_environments_client::FleetEnvironmentsClient;
use fleet_proto::v1::{
    ClearEnvironmentDefaultRequest, EnvironmentBindingKey, EnvironmentRepoKey,
    GetEnvironmentDefaultRequest, SetEnvironmentDefaultRequest, environment_binding_key::Key,
};
use fleet_proto::{ERR_ENV_KEY_INVALID, ERR_ENV_KEY_NOT_FOUND, ERR_ENV_NOT_FOUND};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{
    BindingKey, DefaultKeys, EnvRequest, EnvironmentService, EnvironmentStore, PinRefusal,
    PinResult, resolve_pin_with_defaults,
};
use fleet_server::profiles::{self, ProfileContent};
use fleet_server::service::router_with_environments;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-env-default-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

fn envs(pool: &PgPool) -> EnvironmentStore {
    EnvironmentStore::new(pool.clone(), Arc::new(sealer()))
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    users: Users,
}

async fn rig(pool: PgPool) -> Rig {
    let core = Store::new(pool.clone());
    core.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let service = Some(EnvironmentService::new(envs(&pool)));
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with_environments(&core, &auth, None, service).serve_with_incoming(incoming),
    );
    Rig { addr, pool, users }
}

async fn migrated(pool: &PgPool) {
    Store::new(pool.clone()).migrate().await.unwrap();
}

async fn user(pool: &PgPool, name: &str, scripts: bool) -> i64 {
    let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
    if scripts {
        sqlx::query(
            "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, 'env:scripts', $1)",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }
    id
}

async fn token_of(rig: &Rig, user: i64) -> String {
    let made = rig.users.create_api_token(user, "t").await.unwrap();
    String::from_utf8(made.token.expose().to_vec()).unwrap()
}

fn client(rig: &Rig) -> FleetEnvironmentsClient<Channel> {
    FleetEnvironmentsClient::new(
        Endpoint::from_shared(format!("http://{}", rig.addr))
            .unwrap()
            .connect_lazy(),
    )
}

fn authed<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

fn secret(name: &str) -> Entry {
    Entry::Secret(SecretSpec::with_defaults(EntryName::new(name).unwrap()))
}

fn script(name: &str) -> Entry {
    Entry::Script(ScriptSpec::with_defaults(
        EntryName::new(name).unwrap(),
        ScriptBody::new(SHEBANG).unwrap(),
    ))
}

async fn environment(pool: &PgPool, owner: i64, name: &str, entries: Vec<Entry>) -> i64 {
    let store = envs(pool);
    let id = store
        .create_environment(owner, &EnvironmentName::new(name).unwrap())
        .await
        .unwrap();
    store
        .save_version(owner, id, &EnvironmentSpec::new(entries, vec![]).unwrap())
        .await
        .unwrap();
    id
}

async fn repo(pool: &PgPool, owner: i64, host: &str, path: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, $2, $3, 'github') RETURNING id",
    )
    .bind(owner)
    .bind(host)
    .bind(path)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn profile(pool: &PgPool, owner: i64, name: &str) -> i64 {
    profiles::create_owned(
        pool,
        Some(owner),
        None,
        name,
        ProfileContent::Json(r#"{"claude_md":"x"}"#),
    )
    .await
    .unwrap();
    sqlx::query_scalar("SELECT id FROM profile WHERE owner_user_id = $1 AND name = $2")
        .bind(owner)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn repo_key(host: &str, path: &str) -> EnvironmentBindingKey {
    EnvironmentBindingKey {
        key: Some(Key::Repo(EnvironmentRepoKey {
            host: host.to_owned(),
            path: path.to_owned(),
        })),
    }
}

fn profile_key(name: &str) -> EnvironmentBindingKey {
    EnvironmentBindingKey {
        key: Some(Key::Profile(name.to_owned())),
    }
}

async fn bindings(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM environment_default")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn bind_repo(pool: &PgPool, owner: i64, environment: i64, repo_id: i64) {
    envs(pool)
        .set_default(
            owner,
            environment,
            &BindingKey::Repo {
                host: repo_host(pool, repo_id).await,
                path: repo_path(pool, repo_id).await,
            },
        )
        .await
        .unwrap();
}

async fn repo_host(pool: &PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT host FROM user_repos WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn repo_path(pool: &PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT path FROM user_repos WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn bind_profile(pool: &PgPool, owner: i64, environment: i64, name: &str) {
    envs(pool)
        .set_default(owner, environment, &BindingKey::Profile(name.to_owned()))
        .await
        .unwrap();
}

async fn resolve(pool: &PgPool, owner: i64, request: &EnvRequest, keys: DefaultKeys) -> PinResult {
    let mut tx = pool.begin().await.unwrap();
    let out = resolve_pin_with_defaults(&mut tx, owner, request, keys)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    out
}

fn named(name: &str) -> EnvRequest {
    EnvRequest::Named(EnvironmentName::new(name).unwrap())
}

fn pinned_to(result: PinResult) -> Option<i64> {
    result.into_pin().unwrap().map(|pin| pin.environment_id)
}

#[sqlx::test]
async fn the_schema_holds_one_binding_per_key_and_scopes_every_foreign_key_to_the_owner(
    pool: PgPool,
) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let bob = user(&pool, "bob", false).await;
    let a_env = environment(&pool, alice, "a-env", vec![secret("T")]).await;
    let b_env = environment(&pool, bob, "b-env", vec![secret("T")]).await;
    let a_repo = repo(&pool, alice, "github.com", "org/one").await;
    let b_repo = repo(&pool, bob, "github.com", "org/one").await;
    let a_profile = profile(&pool, alice, "alpha").await;

    let insert = |user_id: i64, env: i64, repo_id: Option<i64>, profile_id: Option<i64>| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO environment_default (user_id, environment_id, repo_id, profile_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(user_id)
            .bind(env)
            .bind(repo_id)
            .bind(profile_id)
            .execute(&pool)
            .await
        }
    };
    insert(alice, a_env, Some(a_repo), None).await.unwrap();
    insert(alice, a_env, None, Some(a_profile)).await.unwrap();
    assert!(insert(alice, a_env, Some(a_repo), None).await.is_err());
    assert!(insert(alice, a_env, None, Some(a_profile)).await.is_err());
    assert!(insert(alice, a_env, None, None).await.is_err());
    assert!(
        insert(alice, a_env, Some(a_repo), Some(a_profile))
            .await
            .is_err()
    );
    assert!(insert(alice, b_env, Some(a_repo), None).await.is_err());
    assert!(insert(bob, a_env, Some(b_repo), None).await.is_err());
    assert!(insert(bob, b_env, Some(a_repo), None).await.is_err());
    insert(bob, b_env, Some(b_repo), None).await.unwrap();
    assert_eq!(bindings(&pool).await, 3);
}

#[sqlx::test]
async fn deleting_an_environment_or_a_repository_removes_its_bindings(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let doomed = environment(&pool, alice, "doomed", vec![secret("T")]).await;
    let kept = environment(&pool, alice, "kept", vec![secret("T")]).await;
    let r1 = repo(&pool, alice, "github.com", "org/one").await;
    let r2 = repo(&pool, alice, "github.com", "org/two").await;
    profile(&pool, alice, "alpha").await;
    bind_repo(&pool, alice, doomed, r1).await;
    bind_profile(&pool, alice, doomed, "alpha").await;
    bind_repo(&pool, alice, kept, r2).await;
    assert_eq!(bindings(&pool).await, 3);
    envs(&pool).delete_environment(alice, doomed).await.unwrap();
    assert_eq!(bindings(&pool).await, 1);
    sqlx::query("DELETE FROM user_repos WHERE id = $1")
        .bind(r2)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(bindings(&pool).await, 0);
}

#[sqlx::test]
async fn the_explicit_name_then_no_env_then_the_repo_then_the_profile_decide(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let explicit = environment(&pool, alice, "explicit", vec![secret("T")]).await;
    let by_repo = environment(&pool, alice, "by-repo", vec![secret("T")]).await;
    let by_profile = environment(&pool, alice, "by-profile", vec![secret("T")]).await;
    let repo_id = repo(&pool, alice, "github.com", "org/one").await;
    profile(&pool, alice, "alpha").await;
    let profile_id: i64 = sqlx::query_scalar("SELECT id FROM profile WHERE name = 'alpha'")
        .fetch_one(&pool)
        .await
        .unwrap();
    bind_repo(&pool, alice, by_repo, repo_id).await;
    bind_profile(&pool, alice, by_profile, "alpha").await;

    let both = DefaultKeys {
        repo_id: Some(repo_id),
        profile_id: Some(profile_id),
    };
    let repo_only = DefaultKeys {
        repo_id: Some(repo_id),
        profile_id: None,
    };
    let profile_only = DefaultKeys {
        repo_id: None,
        profile_id: Some(profile_id),
    };
    let neither = DefaultKeys::default();
    let table: [(&str, EnvRequest, DefaultKeys, Option<i64>); 8] = [
        (
            "explicit beats both",
            named("explicit"),
            both,
            Some(explicit),
        ),
        ("no-env beats both", EnvRequest::Bare, both, None),
        (
            "repo over profile",
            EnvRequest::Default,
            both,
            Some(by_repo),
        ),
        ("repo alone", EnvRequest::Default, repo_only, Some(by_repo)),
        (
            "profile alone",
            EnvRequest::Default,
            profile_only,
            Some(by_profile),
        ),
        ("no key", EnvRequest::Default, neither, None),
        ("no-env without keys", EnvRequest::Bare, neither, None),
        (
            "explicit without keys",
            named("EXPLICIT"),
            neither,
            Some(explicit),
        ),
    ];
    for (label, request, keys, want) in table {
        assert_eq!(
            pinned_to(resolve(&pool, alice, &request, keys).await),
            want,
            "{label}"
        );
    }
}

#[sqlx::test]
async fn a_profile_binding_survives_a_rename_and_the_profile_hash_does_not_move(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let env = environment(&pool, alice, "prod", vec![secret("T")]).await;
    let profile_id = profile(&pool, alice, "alpha").await;
    let hashes = || async {
        sqlx::query_as::<_, (i32, Vec<u8>)>(
            "SELECT version, hash FROM profile_version WHERE profile_id = $1 ORDER BY version",
        )
        .bind(profile_id)
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let before = hashes().await;
    bind_profile(&pool, alice, env, "alpha").await;
    assert_eq!(hashes().await, before);
    sqlx::query("UPDATE profile SET name = 'beta' WHERE id = $1")
        .bind(profile_id)
        .execute(&pool)
        .await
        .unwrap();
    let keys = DefaultKeys {
        repo_id: None,
        profile_id: Some(profile_id),
    };
    assert_eq!(
        pinned_to(resolve(&pool, alice, &EnvRequest::Default, keys).await),
        Some(env)
    );
    let found = envs(&pool)
        .get_default(alice, &BindingKey::Profile("beta".to_owned()))
        .await
        .unwrap();
    assert_eq!(found.as_deref(), Some("prod"));
    assert!(
        envs(&pool)
            .get_default(alice, &BindingKey::Profile("alpha".to_owned()))
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn a_binding_to_scripts_after_a_revoke_refuses_and_never_falls_through(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", true).await;
    let scripted = environment(&pool, alice, "scripted", vec![script("setup")]).await;
    let plain = environment(&pool, alice, "plain", vec![secret("T")]).await;
    let repo_id = repo(&pool, alice, "github.com", "org/one").await;
    let profile_id = profile(&pool, alice, "alpha").await;
    bind_repo(&pool, alice, scripted, repo_id).await;
    bind_profile(&pool, alice, plain, "alpha").await;
    let keys = DefaultKeys {
        repo_id: Some(repo_id),
        profile_id: Some(profile_id),
    };
    assert_eq!(
        pinned_to(resolve(&pool, alice, &EnvRequest::Default, keys).await),
        Some(scripted)
    );
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        resolve(&pool, alice, &EnvRequest::Default, keys).await,
        PinResult::Refused(PinRefusal::ScriptsNotGranted)
    );
    assert_eq!(
        pinned_to(resolve(&pool, alice, &EnvRequest::Bare, keys).await),
        None
    );
}

#[sqlx::test]
async fn a_binding_to_an_environment_without_a_version_refuses(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let env = envs(&pool)
        .create_environment(alice, &EnvironmentName::new("empty").unwrap())
        .await
        .unwrap();
    let repo_id = repo(&pool, alice, "github.com", "org/one").await;
    bind_repo(&pool, alice, env, repo_id).await;
    let keys = DefaultKeys {
        repo_id: Some(repo_id),
        profile_id: None,
    };
    assert_eq!(
        resolve(&pool, alice, &EnvRequest::Default, keys).await,
        PinResult::Refused(PinRefusal::NoVersion)
    );
}

#[sqlx::test]
async fn a_profile_that_carries_an_environment_key_is_refused_at_create_and_edit(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    profile(&pool, alice, "alpha").await;
    let hostile = [
        r#"{"claude_md":"x","environment":"prod"}"#,
        r#"{"claude_md":"x","Environment":"prod"}"#,
        r#"{"claude_md":"x","environment":null}"#,
    ];
    for json in hostile {
        assert!(
            profiles::create_owned(&pool, Some(alice), None, "beta", ProfileContent::Json(json))
                .await
                .is_err(),
            "create {json}"
        );
        assert!(
            profiles::edit_owned(
                &pool,
                Some(alice),
                None,
                "alpha",
                ProfileContent::Json(json)
            )
            .await
            .is_err(),
            "edit {json}"
        );
    }
    let toml = "claude_md = \"x\"\nenvironment = \"prod\"\n";
    assert!(
        profiles::create_owned(&pool, Some(alice), None, "beta", ProfileContent::Toml(toml))
            .await
            .is_err()
    );
    let beta: i64 = sqlx::query_scalar("SELECT count(*) FROM profile WHERE name = 'beta'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(beta, 0);
}

#[derive(Clone, Copy, Debug)]
enum Rpc {
    Set,
    Get,
    Clear,
}

async fn call(
    rig: &Rig,
    rpc: Rpc,
    token: &str,
    key: impl Into<Option<EnvironmentBindingKey>>,
    environment: &str,
) -> Result<Option<String>, Status> {
    let key = key.into();
    let mut c = client(rig);
    match rpc {
        Rpc::Set => c
            .set_environment_default(authed(
                SetEnvironmentDefaultRequest {
                    key,
                    environment: environment.to_owned(),
                },
                token,
            ))
            .await
            .map(|_| None),
        Rpc::Get => c
            .get_environment_default(authed(GetEnvironmentDefaultRequest { key }, token))
            .await
            .map(|r| r.into_inner().environment),
        Rpc::Clear => c
            .clear_environment_default(authed(ClearEnvironmentDefaultRequest { key }, token))
            .await
            .map(|_| None),
    }
}

const RPCS: [Rpc; 3] = [Rpc::Set, Rpc::Get, Rpc::Clear];

#[sqlx::test]
async fn the_rpcs_set_read_replace_and_clear_a_binding(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    let token = token_of(&rig, alice).await;
    environment(&rig.pool, alice, "one", vec![secret("T")]).await;
    environment(&rig.pool, alice, "two", vec![secret("T")]).await;
    repo(&rig.pool, alice, "github.com", "org/one").await;
    profile(&rig.pool, alice, "alpha").await;
    for key in [repo_key("GitHub.com", "Org/One"), profile_key("alpha")] {
        let read = |k: EnvironmentBindingKey| call(&rig, Rpc::Get, &token, k, "");
        assert_eq!(read(key.clone()).await.unwrap(), None);
        call(&rig, Rpc::Set, &token, key.clone(), "ONE")
            .await
            .unwrap();
        assert_eq!(read(key.clone()).await.unwrap().as_deref(), Some("one"));
        call(&rig, Rpc::Set, &token, key.clone(), "two")
            .await
            .unwrap();
        assert_eq!(read(key.clone()).await.unwrap().as_deref(), Some("two"));
        call(&rig, Rpc::Clear, &token, key.clone(), "")
            .await
            .unwrap();
        assert_eq!(read(key.clone()).await.unwrap(), None);
        call(&rig, Rpc::Clear, &token, key.clone(), "")
            .await
            .unwrap();
    }
    assert_eq!(bindings(&rig.pool).await, 0);
}

#[sqlx::test]
async fn user_b_cannot_read_set_or_clear_user_a_binding(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    let bob = user(&rig.pool, "bob", false).await;
    let bob_token = token_of(&rig, bob).await;
    let a_env = environment(&rig.pool, alice, "alice-env", vec![secret("T")]).await;
    environment(&rig.pool, bob, "bob-env", vec![secret("T")]).await;
    repo(&rig.pool, alice, "github.com", "org/private").await;
    profile(&rig.pool, alice, "alice-profile").await;
    repo(&rig.pool, bob, "github.com", "org/mine").await;
    profile(&rig.pool, bob, "bob-profile").await;
    bind_repo(
        &rig.pool,
        alice,
        a_env,
        sqlx::query_scalar("SELECT id FROM user_repos")
            .fetch_one(&rig.pool)
            .await
            .unwrap(),
    )
    .await;
    bind_profile(&rig.pool, alice, a_env, "alice-profile").await;
    let before = bindings(&rig.pool).await;
    for rpc in RPCS {
        let pairs = [
            (
                repo_key("github.com", "org/private"),
                repo_key("github.com", "org/ghost"),
            ),
            (profile_key("alice-profile"), profile_key("ghost-profile")),
        ];
        for (foreign, unknown) in pairs {
            let a = call(&rig, rpc, &bob_token, foreign, "bob-env")
                .await
                .unwrap_err();
            let b = call(&rig, rpc, &bob_token, unknown, "bob-env")
                .await
                .unwrap_err();
            assert_eq!(a.code(), Code::NotFound, "{rpc:?}");
            assert_eq!(a.message(), ERR_ENV_KEY_NOT_FOUND, "{rpc:?}");
            assert_eq!((a.code(), a.message()), (b.code(), b.message()), "{rpc:?}");
        }
    }
    for key in [
        repo_key("github.com", "org/mine"),
        profile_key("bob-profile"),
    ] {
        let foreign = call(&rig, Rpc::Set, &bob_token, key.clone(), "alice-env")
            .await
            .unwrap_err();
        let unknown = call(&rig, Rpc::Set, &bob_token, key, "ghost")
            .await
            .unwrap_err();
        assert_eq!(foreign.code(), Code::NotFound);
        assert_eq!(foreign.message(), ERR_ENV_NOT_FOUND);
        assert_eq!(
            (foreign.code(), foreign.message()),
            (unknown.code(), unknown.message())
        );
    }
    assert_eq!(bindings(&rig.pool).await, before);
}

#[sqlx::test]
async fn every_binding_rpc_refuses_the_caller_classes_it_is_not_owed(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    environment(&rig.pool, alice, "one", vec![secret("T")]).await;
    repo(&rig.pool, alice, "github.com", "org/one").await;
    for rpc in RPCS {
        for (label, token, code) in [
            ("client", CLIENT, Code::PermissionDenied),
            ("box", BOX, Code::PermissionDenied),
            ("bogus", "d5cb2d7a5e1f4c0e9a3b", Code::Unauthenticated),
        ] {
            let status = call(&rig, rpc, token, repo_key("github.com", "org/one"), "one")
                .await
                .unwrap_err();
            assert_eq!(status.code(), code, "{label} {rpc:?}");
        }
    }
    assert_eq!(bindings(&rig.pool).await, 0);
}

#[sqlx::test]
async fn a_hostile_key_is_refused_before_any_lookup_and_writes_nothing(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    let token = token_of(&rig, alice).await;
    environment(&rig.pool, alice, "one", vec![secret("T")]).await;
    let long_host = "h".repeat(254);
    let long_path = "p".repeat(142);
    let hosts = [
        "",
        " ",
        "github.com\r\n",
        "github.com\n",
        "github.com\u{85}",
        "github.com\u{2028}",
        "user@github.com",
        "github.com\\evil",
        "[::1]",
        "a..b/c",
        "gith\u{fb}b.com",
        "github.com\0",
        &long_host,
    ];
    let paths = [
        "",
        " org/one",
        "org/one\r\n",
        "org\\one",
        "org/one\u{2028}",
        "org/\u{e9}",
        "org/one?x=1",
        "org/one#f",
        "org/one\0",
        &long_path,
    ];
    let mut keys: Vec<Option<EnvironmentBindingKey>> = vec![
        None,
        Some(EnvironmentBindingKey { key: None }),
        Some(profile_key("")),
        Some(profile_key("al pha")),
        Some(profile_key("alpha\n")),
        Some(profile_key("al\u{e9}")),
        Some(profile_key(&"a".repeat(65))),
    ];
    for host in hosts {
        keys.push(Some(repo_key(host, "org/one")));
    }
    for path in paths {
        keys.push(Some(repo_key("github.com", path)));
    }
    for rpc in RPCS {
        for key in &keys {
            let status = call(&rig, rpc, &token, key.clone(), "one")
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::InvalidArgument, "{rpc:?} {key:?}");
            assert_eq!(status.message(), ERR_ENV_KEY_INVALID, "{rpc:?} {key:?}");
        }
    }
    assert_eq!(bindings(&rig.pool).await, 0);
}

#[sqlx::test]
async fn a_hostile_environment_name_is_refused_on_set(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice", false).await;
    let token = token_of(&rig, alice).await;
    repo(&rig.pool, alice, "github.com", "org/one").await;
    for name in [
        "",
        "-",
        " ",
        "a b",
        "a\r\nb",
        "a\u{2028}b",
        "\u{e9}",
        &"a".repeat(65),
    ] {
        let status = call(
            &rig,
            Rpc::Set,
            &token,
            repo_key("github.com", "org/one"),
            name,
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{name:?}");
    }
    assert_eq!(bindings(&rig.pool).await, 0);
}

#[sqlx::test]
async fn a_set_waits_for_a_submit_that_holds_the_environment_row(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let env = environment(&pool, alice, "prod", vec![secret("T")]).await;
    repo(&pool, alice, "github.com", "org/one").await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM environment WHERE id = $1 FOR SHARE")
        .bind(env)
        .execute(&mut *holder)
        .await
        .unwrap();
    let store = Arc::new(envs(&pool));
    let setter = Arc::clone(&store);
    let task = tokio::spawn(async move {
        setter
            .set_default(
                alice,
                env,
                &BindingKey::Repo {
                    host: "github.com".to_owned(),
                    path: "org/one".to_owned(),
                },
            )
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query LIKE '%FROM environment WHERE id%FOR UPDATE%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the set never waited on the environment row"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(bindings(&pool).await, 0);
    holder.commit().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(bindings(&pool).await, 1);
}

#[sqlx::test]
async fn another_users_repo_or_profile_id_resolves_to_no_binding(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice", false).await;
    let bob = user(&pool, "bob", false).await;
    let b_env = environment(&pool, bob, "b-env", vec![secret("T")]).await;
    let b_repo = repo(&pool, bob, "github.com", "org/one").await;
    let b_profile = profile(&pool, bob, "beta").await;
    bind_repo(&pool, bob, b_env, b_repo).await;
    bind_profile(&pool, bob, b_env, "beta").await;
    let keys = DefaultKeys {
        repo_id: Some(b_repo),
        profile_id: Some(b_profile),
    };
    assert_eq!(
        resolve(&pool, alice, &EnvRequest::Default, keys).await,
        PinResult::None
    );
    assert_eq!(
        pinned_to(resolve(&pool, bob, &EnvRequest::Default, keys).await),
        Some(b_env)
    );
}
