//! `FleetProfiles` over a real tonic server on a loopback port, plus the insert-only
//! triggers. The tests need a Postgres superuser URL in `DATABASE_URL`. They live in their
//! own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::fleet_profiles_client::FleetProfilesClient;
use fleet_proto::v1::{CreateProfileRequest, GetProfileRequest, ListProfilesRequest};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::profiles::{self, ProfileContent, ProfileFault, Viewer};
use fleet_server::service::router;
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;
use tokio::time::timeout;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const WAIT: Duration = Duration::from_secs(30);

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Profiles = FleetProfilesClient<InterceptedService<Channel, Interceptor>>;

fn as_client(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, CLIENT)
}

fn as_box(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, BOX)
}

fn with_token(mut request: Request<()>, token: &str) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {token}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

fn serve(pool: &PgPool, store: &Store) -> SocketAddr {
    serve_as(store, Some(Users::new(pool.clone())))
}

fn serve_as(store: &Store, users: Option<Users>) -> SocketAddr {
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let auth = match users {
        Some(users) => auth.with_users(users),
        None => auth,
    };
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(store, &auth).serve_with_incoming(incoming));
    addr
}

fn client_for(addr: SocketAddr, interceptor: Interceptor) -> Profiles {
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    FleetProfilesClient::with_interceptor(channel, interceptor)
}

fn spawn(pool: &PgPool, store: &Store) -> Profiles {
    client_for(serve(pool, store), as_client)
}

fn create(name: &str, content: &str) -> CreateProfileRequest {
    CreateProfileRequest {
        name: name.to_owned(),
        content_json: content.to_owned(),
        content_toml: String::new(),
    }
}

fn create_toml(name: &str, content: &str) -> CreateProfileRequest {
    CreateProfileRequest {
        name: name.to_owned(),
        content_json: String::new(),
        content_toml: content.to_owned(),
    }
}

const TOOLS_TOML: &str = "[[tools]]\nname = \"node\"\nversion = \"20.11.1\"\n";
const PLAIN_TOML: &str = "claude_md = \"one\"\nmax_turns = 5\n";

async fn counts(pool: &PgPool) -> (i64, i64) {
    let blobs = sqlx::query_scalar("SELECT count(*) FROM profile_blob")
        .fetch_one(pool)
        .await
        .unwrap();
    let versions = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(pool)
        .await
        .unwrap();
    (blobs, versions)
}

#[sqlx::test]
async fn gate_off_refuses_tools_and_stores_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let err = profiles
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), fleet_proto::ERR_PROFILE_TOOLS_DISABLED);
    assert_eq!(counts(&pool).await, (0, 0));
    let json = r#"{"tools":[{"name":"node","version":"20.11.1"}]}"#;
    let err = profiles
        .create_profile(create("alpha", json))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_ne!(err.message(), fleet_proto::ERR_PROFILE_TOOLS_DISABLED);
    assert_eq!(counts(&pool).await, (0, 0));
}

#[sqlx::test]
async fn gate_on_accepts_tools_and_the_hash_round_trips(pool: PgPool) {
    let store = store(pool.clone()).await.with_profile_tools(true);
    let mut profiles = spawn(&pool, &store);
    let created = profiles
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap()
        .into_inner();
    assert!(created.created);
    let expected = fleet_core::Profile::from_toml(TOOLS_TOML).unwrap();
    assert_eq!(created.hash, expected.hash().to_string());
    assert_eq!(created.content_json.as_bytes(), expected.canonical_json());
    let fetched = profiles
        .get_profile(get("alpha", None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.hash, created.hash);
    assert_eq!(fetched.content_json, created.content_json);
    let again = profiles
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap()
        .into_inner();
    assert!(!again.created);
    assert_eq!(again.version, created.version);
}

#[sqlx::test]
async fn profiles_without_tools_ignore_the_gate(pool: PgPool) {
    let mut hashes = Vec::new();
    for allow in [false, true] {
        let store = store(pool.clone()).await.with_profile_tools(allow);
        let mut profiles = spawn(&pool, &store);
        for request in [create("alpha", ONE), create_toml("beta", PLAIN_TOML)] {
            let reply = profiles.create_profile(request).await.unwrap().into_inner();
            hashes.push(reply.hash);
        }
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[0], hashes[2]);
    assert_eq!(hashes[0], hashes[3]);
}

#[sqlx::test]
async fn exactly_one_content_field_must_be_set(pool: PgPool) {
    let store = store(pool.clone()).await.with_profile_tools(true);
    let mut profiles = spawn(&pool, &store);
    let both = CreateProfileRequest {
        name: "alpha".to_owned(),
        content_json: ONE.to_owned(),
        content_toml: PLAIN_TOML.to_owned(),
    };
    let neither = CreateProfileRequest {
        name: "alpha".to_owned(),
        content_json: String::new(),
        content_toml: String::new(),
    };
    for request in [both, neither] {
        let err = profiles.create_profile(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), fleet_proto::ERR_PROFILE_CONTENT_CHOICE);
    }
    assert_eq!(counts(&pool).await, (0, 0));
}

fn get(name: &str, version: Option<u32>) -> GetProfileRequest {
    GetProfileRequest {
        name: name.to_owned(),
        version,
    }
}

const ONE: &str = r#"{"claude_md":"one","max_turns":5}"#;
const ONE_REORDERED: &str = r#"{ "max_turns": 5, "claude_md": "one" }"#;
const TWO: &str = r#"{"claude_md":"two"}"#;

#[sqlx::test]
async fn same_content_same_version(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let first = timeout(WAIT, profiles.create_profile(create("alpha", ONE)))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(first.version, 1);
    assert!(first.created);
    assert_eq!(first.hash.len(), 64);
    let again = profiles
        .create_profile(create("alpha", ONE_REORDERED))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.version, 1);
    assert!(!again.created);
    assert_eq!(again.hash, first.hash);
    assert_eq!(again.content_json, first.content_json);
    assert_eq!(first.content_json, r#"{"claude_md":"one","max_turns":5}"#);
}

#[sqlx::test]
async fn different_content_gets_a_new_version(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let first = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap()
        .into_inner();
    let second = profiles
        .create_profile(create("alpha", TWO))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.version, 2);
    assert_ne!(second.hash, first.hash);
    let back = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(back.version, 1);
    assert!(!back.created);
}

#[sqlx::test]
async fn same_content_under_two_names_shares_one_blob(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let a = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap()
        .into_inner();
    let b = profiles
        .create_profile(create("beta", ONE))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(a.hash, b.hash);
    assert_eq!((a.version, b.version), (1, 1));
    let blobs: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_blob")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(blobs, 1);
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(versions, 2);
}

#[sqlx::test]
async fn concurrent_creates_of_one_content_make_one_version(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&pool, &store);
    let mut calls = Vec::new();
    for _ in 0..8 {
        let mut profiles = client_for(addr, as_client);
        calls.push(tokio::spawn(async move {
            profiles.create_profile(create("alpha", ONE)).await
        }));
    }
    for call in calls {
        let reply = call.await.unwrap().unwrap().into_inner();
        assert_eq!(reply.version, 1);
    }
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(versions, 1);
}

#[sqlx::test]
async fn get_by_name_and_by_version(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let one = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap()
        .into_inner();
    let two = profiles
        .create_profile(create("alpha", TWO))
        .await
        .unwrap()
        .into_inner();

    let latest = profiles
        .get_profile(get("alpha", None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.hash, two.hash);
    assert_eq!(latest.content_json, TWO);
    assert!(!latest.created);

    let pinned = profiles
        .get_profile(get("alpha", Some(1)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(pinned.version, 1);
    assert_eq!(pinned.hash, one.hash);
    assert_eq!(pinned.content_json, one.content_json);

    for request in [
        get("missing", None),
        get("alpha", Some(3)),
        get("alpha", Some(0)),
    ] {
        let err = profiles.get_profile(request).await.unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert_eq!(err.message(), "profile not found");
    }
    let err = profiles
        .get_profile(get("bad name", None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[sqlx::test]
async fn list_returns_latest_per_name(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    profiles.create_profile(create("beta", ONE)).await.unwrap();
    profiles.create_profile(create("alpha", ONE)).await.unwrap();
    let alpha2 = profiles
        .create_profile(create("alpha", TWO))
        .await
        .unwrap()
        .into_inner();
    let listed = profiles
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap()
        .into_inner()
        .profiles;
    let names: Vec<_> = listed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta"]);
    assert_eq!(listed[0].latest_version, 2);
    assert_eq!(listed[0].hash, alpha2.hash);
    assert_eq!(listed[1].latest_version, 1);

    let page = profiles
        .list_profiles(ListProfilesRequest {
            limit: 1,
            after_name: Some("alpha".to_owned()),
        })
        .await
        .unwrap()
        .into_inner()
        .profiles;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].name, "beta");
}

#[sqlx::test]
async fn invalid_input_is_invalid_argument_and_never_echoed(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let secret = "zzz-private-input";
    let cases = [
        create("alpha", &format!("{{\"{secret}\":1}}")),
        create("alpha", &format!("not json {secret}")),
        create("alpha", &format!("{{\"claude_md\":\"a\\u0000{secret}\"}}")),
        create(
            "alpha",
            &format!("{{\"model\":\"{secret}\",\"settings\":{{\"model\":\"x\"}}}}"),
        ),
        create("zzz private input", "{}"),
        create("", "{}"),
        create(&"a".repeat(65), "{}"),
    ];
    for request in cases {
        let err = profiles.create_profile(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{}", err.message());
        assert!(!err.message().contains("private"), "{}", err.message());
        assert!(!err.message().contains('{'), "{}", err.message());
    }
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_blob")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

#[sqlx::test]
async fn box_token_is_denied_on_every_profile_rpc(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = client_for(serve(&pool, &store), as_box);
    let denied = [
        profiles
            .create_profile(create("alpha", ONE))
            .await
            .unwrap_err()
            .code(),
        profiles
            .get_profile(get("alpha", None))
            .await
            .unwrap_err()
            .code(),
        profiles
            .list_profiles(ListProfilesRequest::default())
            .await
            .unwrap_err()
            .code(),
    ];
    assert_eq!(denied, [Code::PermissionDenied; 3]);
}

#[sqlx::test]
async fn missing_token_is_unauthenticated(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = client_for(serve(&pool, &store), Ok);
    let err = profiles
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[sqlx::test]
async fn update_delete_and_truncate_are_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    profiles.create_profile(create("alpha", ONE)).await.unwrap();
    let statements = [
        "UPDATE profile_blob SET size = size",
        "UPDATE profile_blob SET content = '\\x7b7d'",
        "UPDATE profile_version SET version = 9",
        "UPDATE profile_version SET profile_id = profile_id + 1",
        "DELETE FROM profile_blob",
        "DELETE FROM profile_version",
        "TRUNCATE profile_blob CASCADE",
        "TRUNCATE profile_version CASCADE",
    ];
    for statement in statements {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("insert-only"), "{statement}: {message}");
    }
    let blobs: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_blob")
        .fetch_one(&pool)
        .await
        .unwrap();
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((blobs, versions), (1, 1));
}

const OWNED: &str = r#"{"claude_md":"owned"}"#;

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn owners(pool: &PgPool) -> Vec<(i64, String)> {
    sqlx::query_as("SELECT owner_user_id, name FROM profile ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn owned(pool: &PgPool, caller: Option<i64>, name: &str, json: &str) -> Result<(), String> {
    profiles::create_owned(pool, caller, name, ProfileContent::Json(json), false)
        .await
        .map(|_| ())
        .map_err(|err| err.to_string())
}

#[sqlx::test]
async fn create_owned_sets_the_owner_from_the_caller(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    assert_eq!(owners(&pool).await, [(alice, "alpha".to_owned())]);
    owned(&pool, Some(bob), "alpha", r#"{"claude_md":"two"}"#)
        .await
        .unwrap();
    assert_eq!(
        owners(&pool).await,
        [(alice, "alpha".to_owned()), (bob, "alpha".to_owned())]
    );
}

#[sqlx::test]
async fn create_owned_refuses_without_a_user_and_writes_nothing(pool: PgPool) {
    store(pool.clone()).await;
    let ghost = i64::MAX;
    let refusal = "profile create needs a user token".to_owned();
    for caller in [None, Some(ghost), Some(-1)] {
        assert_eq!(
            owned(&pool, caller, "alpha", OWNED).await,
            Err(refusal.clone())
        );
    }
    assert_eq!(owned(&pool, None, "bad name", "{").await, Err(refusal));
    assert_eq!(counts(&pool).await, (0, 0));
    assert_eq!(owners(&pool).await, Vec::<(i64, String)>::new());
}

#[sqlx::test]
async fn forged_owner_in_the_content_does_not_stick(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let forged = format!(r#"{{"claude_md":"x","owner_user_id":{bob}}}"#);
    let err = owned(&pool, Some(alice), "alpha", &forged)
        .await
        .unwrap_err();
    assert!(!err.contains(&bob.to_string()));
    assert_eq!(counts(&pool).await, (0, 0));
    assert_eq!(owners(&pool).await, Vec::<(i64, String)>::new());
}

async fn put(pool: &PgPool, caller: i64, json: &str) -> fleet_proto::v1::ProfileVersion {
    profiles::create_owned(
        pool,
        Some(caller),
        "alpha",
        ProfileContent::Json(json),
        false,
    )
    .await
    .unwrap()
}

const SHARED_CONTENT: &str = r#"{"claude_md":"same"}"#;

#[sqlx::test]
async fn two_owners_of_one_name_keep_independent_version_streams(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let a1 = put(&pool, alice, r#"{"claude_md":"a1"}"#).await;
    let a2 = put(&pool, alice, SHARED_CONTENT).await;
    let b1 = put(&pool, bob, SHARED_CONTENT).await;
    let b2 = put(&pool, bob, SHARED_CONTENT).await;
    assert_eq!((a1.version, a1.created), (1, true));
    assert_eq!((a2.version, a2.created), (2, true));
    assert_eq!((b1.version, b1.created), (1, true));
    assert_eq!((b2.version, b2.created), (1, false));
    assert_eq!(a2.hash, b1.hash);
}

#[sqlx::test]
async fn a_private_profile_reads_as_not_found_for_another_user(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    let get = |viewer: Option<i64>, name: &'static str, version| {
        let viewer = Viewer::from(viewer);
        let pool = pool.clone();
        async move { profiles::get_for(&pool, viewer, name, version).await }
    };
    assert_eq!(get(Some(alice), "alpha", None).await.unwrap().version, 1);
    assert_eq!(get(Some(alice), "alpha", Some(1)).await.unwrap().version, 1);
    for version in [None, Some(1)] {
        let foreign = get(Some(bob), "alpha", version).await.unwrap_err();
        let absent = get(Some(bob), "ghost", version).await.unwrap_err();
        assert_eq!(foreign.to_string(), absent.to_string());
        assert!(matches!(foreign, StoreError::NotFound));
        assert!(matches!(
            get(None, "alpha", version).await,
            Err(StoreError::NotFound)
        ));
    }
    let listed = profiles::list_for(&pool, Viewer::User(bob), 0, None)
        .await
        .unwrap();
    assert_eq!(
        listed.profiles,
        Vec::<fleet_proto::v1::ProfileSummary>::new()
    );
    let own = profiles::list_for(&pool, Viewer::User(alice), 0, None)
        .await
        .unwrap();
    assert_eq!(own.profiles.len(), 1);
}

async fn profile_id(pool: &PgPool, owner: i64, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM profile WHERE owner_user_id = $1 AND name = $2")
        .bind(owner)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn share(pool: &PgPool, id: i64) {
    sqlx::query("UPDATE profile SET visibility = 'shared' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

async fn snapshot(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(\
         'profiles', (SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY id), '[]') FROM profile p),\
         'versions', (SELECT coalesce(jsonb_agg(to_jsonb(v) - 'created_at' ORDER BY profile_id, version), '[]') FROM profile_version v),\
         'blobs', (SELECT count(*) FROM profile_blob))::text",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn update(
    pool: &PgPool,
    caller: Option<i64>,
    id: i64,
    json: &str,
) -> Result<fleet_proto::v1::ProfileVersion, StoreError> {
    profiles::update_owned(pool, caller, id, ProfileContent::Json(json), false).await
}

const NEXT: &str = r#"{"claude_md":"next"}"#;

fn is_not_owner(err: &StoreError) -> bool {
    matches!(err, StoreError::InvalidProfile(ProfileFault::NotOwner))
}

#[sqlx::test]
async fn update_is_owner_only_and_refusals_write_nothing(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    let id = profile_id(&pool, alice, "alpha").await;
    let before = snapshot(&pool).await;

    let foreign = update(&pool, Some(bob), id, NEXT).await.unwrap_err();
    let absent = update(&pool, Some(bob), id + 1000, NEXT).await.unwrap_err();
    assert!(matches!(foreign, StoreError::NotFound));
    assert_eq!(foreign.to_string(), absent.to_string());
    assert!(matches!(
        update(&pool, None, id, NEXT).await,
        Err(StoreError::InvalidProfile(ProfileFault::Unowned))
    ));
    assert_eq!(snapshot(&pool).await, before);

    share(&pool, id).await;
    let before = snapshot(&pool).await;
    let reader = update(&pool, Some(bob), id, NEXT).await.unwrap_err();
    assert!(is_not_owner(&reader), "{reader}");
    assert_eq!(snapshot(&pool).await, before);

    let done = update(&pool, Some(alice), id, NEXT).await.unwrap();
    assert_eq!(
        (done.name.as_str(), done.version, done.created),
        ("alpha", 2, true)
    );
    let repeat = update(&pool, Some(alice), id, NEXT).await.unwrap();
    assert_eq!((repeat.version, repeat.created), (2, false));
    let versions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM profile_version WHERE profile_id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(versions, 2);
}

#[sqlx::test]
async fn update_validates_before_any_lookup(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    let id = profile_id(&pool, alice, "alpha").await;
    let before = snapshot(&pool).await;
    for caller in [alice, bob] {
        let err = update(&pool, Some(caller), id, "not json")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidProfile(ProfileFault::Malformed(_))
        ));
    }
    let err = update(&pool, Some(bob), id, "not json").await.unwrap_err();
    assert!(!err.to_string().contains("not json"));
    assert_eq!(snapshot(&pool).await, before);
}

#[sqlx::test]
async fn update_takes_the_profile_row_lock(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    let id = profile_id(&pool, alice, "alpha").await;
    let mut held = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM profile WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *held)
        .await
        .unwrap();
    let racing = pool.clone();
    let task = tokio::spawn(async move { update(&racing, Some(alice), id, NEXT).await });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!task.is_finished());
    held.commit().await.unwrap();
    let done = timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert_eq!(done.version, 2);
}

async fn bare_profile(pool: &PgPool, owner: i64, name: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO profile (owner_user_id, name, visibility) VALUES ($1, $2, 'private') RETURNING id",
    )
    .bind(owner)
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test]
async fn delete_is_owner_only_and_refusals_write_nothing(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let bare = bare_profile(&pool, alice, "bare").await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    let kept = profile_id(&pool, alice, "alpha").await;
    let before = snapshot(&pool).await;

    let foreign = profiles::delete_owned(&pool, Some(bob), bare)
        .await
        .unwrap_err();
    let absent = profiles::delete_owned(&pool, Some(bob), bare + 1000)
        .await
        .unwrap_err();
    assert!(matches!(foreign, StoreError::NotFound));
    assert_eq!(foreign.to_string(), absent.to_string());
    assert!(matches!(
        profiles::delete_owned(&pool, None, bare).await,
        Err(StoreError::InvalidProfile(ProfileFault::Unowned))
    ));
    assert_eq!(snapshot(&pool).await, before);

    share(&pool, bare).await;
    let before = snapshot(&pool).await;
    let reader = profiles::delete_owned(&pool, Some(bob), bare)
        .await
        .unwrap_err();
    assert!(is_not_owner(&reader), "{reader}");
    assert_eq!(snapshot(&pool).await, before);

    let versioned = profiles::delete_owned(&pool, Some(alice), kept)
        .await
        .unwrap_err();
    assert!(matches!(
        versioned,
        StoreError::InvalidProfile(ProfileFault::HasVersions)
    ));
    assert_eq!(snapshot(&pool).await, before);

    profiles::delete_owned(&pool, Some(alice), bare)
        .await
        .unwrap();
    let left: Vec<i64> = sqlx::query_scalar("SELECT id FROM profile ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, [kept]);
    assert!(matches!(
        profiles::delete_owned(&pool, Some(alice), bare).await,
        Err(StoreError::NotFound)
    ));
}

const UNOWNED: &str = "profile create needs a user token";

async fn api_token(pool: &PgPool, user_id: i64) -> String {
    let made = Users::new(pool.clone())
        .create_api_token(user_id, "test")
        .await
        .unwrap();
    String::from_utf8(made.token.expose().to_vec()).unwrap()
}

#[derive(Clone)]
struct Bearer(String);

impl tonic::service::Interceptor for Bearer {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        with_token(request, &self.0)
    }
}

fn bearer_client(
    addr: SocketAddr,
    token: String,
) -> FleetProfilesClient<InterceptedService<Channel, Bearer>> {
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    FleetProfilesClient::with_interceptor(channel, Bearer(token))
}

async fn nothing_written(pool: &PgPool) {
    assert_eq!(counts(pool).await, (0, 0));
    assert_eq!(owners(pool).await, Vec::<(i64, String)>::new());
}

#[sqlx::test]
async fn user_token_create_records_the_caller_as_owner(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let mut as_bob = bearer_client(addr, api_token(&pool, bob).await);
    let made = as_alice
        .create_profile(create("alpha", ONE))
        .await
        .unwrap()
        .into_inner();
    assert!(made.created);
    assert_eq!(owners(&pool).await, [(alice, "alpha".to_owned())]);
    as_bob.create_profile(create("alpha", ONE)).await.unwrap();
    assert_eq!(
        owners(&pool).await,
        [(alice, "alpha".to_owned()), (bob, "alpha".to_owned())]
    );
}

#[sqlx::test]
async fn client_token_create_records_the_bootstrap_user_as_owner(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    profiles.create_profile(create("alpha", ONE)).await.unwrap();
    let bootstrap = Users::new(pool.clone()).bootstrap_user().await.unwrap();
    assert_eq!(owners(&pool).await, [(bootstrap, "alpha".to_owned())]);
}

#[sqlx::test]
async fn box_token_create_is_refused_and_writes_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = client_for(serve(&pool, &store), as_box);
    let err = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn no_token_create_is_refused_and_writes_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = client_for(serve(&pool, &store), Ok);
    let err = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn no_caller_create_is_refused_with_one_reason_before_the_body_is_read(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = client_for(serve_as(&store, None), as_client);
    let both = CreateProfileRequest {
        name: "bad name".to_owned(),
        content_json: "{".to_owned(),
        content_toml: "x".to_owned(),
    };
    for request in [create("alpha", ONE), create("bad name", "{"), both] {
        let err = profiles.create_profile(request).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(err.message(), UNOWNED);
    }
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn a_deleted_users_token_is_refused_and_writes_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let token = api_token(&pool, alice).await;
    let mut profiles = bearer_client(serve(&pool, &store), token);
    sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let err = profiles
        .create_profile(create("beta", ONE))
        .await
        .unwrap_err();
    assert!(
        matches!(err.code(), Code::Unauthenticated | Code::PermissionDenied),
        "{err:?}"
    );
    assert_eq!(owners(&pool).await, Vec::<(i64, String)>::new());
}

#[sqlx::test]
async fn a_caller_that_is_no_stored_user_maps_to_permission_denied(pool: PgPool) {
    use fleet_proto::v1::fleet_profiles_server::FleetProfiles;
    use fleet_server::auth::Caller;
    use fleet_server::service::FleetService;

    let svc = FleetService::new(store(pool.clone()).await);
    let mut request = Request::new(create("alpha", ONE));
    request
        .extensions_mut()
        .insert(Caller { user_id: i64::MAX });
    let err = svc.create_profile(request).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), UNOWNED);
    assert_eq!(
        ProfileFault::Unowned.to_string(),
        profiles::ERR_PROFILE_UNOWNED
    );
    assert_eq!(UNOWNED, profiles::ERR_PROFILE_UNOWNED);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn an_owner_in_the_content_is_refused_and_a_clean_create_ignores_it(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let mut profiles = bearer_client(serve(&pool, &store), api_token(&pool, alice).await);
    let forged = format!(r#"{{"claude_md":"x","owner_user_id":{bob}}}"#);
    let err = profiles
        .create_profile(create("alpha", &forged))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(!err.message().contains(&bob.to_string()));
    nothing_written(&pool).await;
    profiles.create_profile(create("alpha", ONE)).await.unwrap();
    assert_eq!(owners(&pool).await, [(alice, "alpha".to_owned())]);
}

#[sqlx::test]
async fn create_waits_for_a_concurrent_user_delete_and_is_then_refused(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    let task = tokio::spawn({
        let pool = pool.clone();
        async move {
            profiles::create_owned(
                &pool,
                Some(alice),
                "alpha",
                ProfileContent::Json(ONE),
                false,
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!task.is_finished());
    tx.commit().await.unwrap();
    let result = timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            result,
            Err(StoreError::InvalidProfile(ProfileFault::Unowned))
        ),
        "{result:?}"
    );
    nothing_written(&pool).await;
}

#[test]
fn a_caller_id_is_never_the_shared_only_viewer() {
    assert_eq!(Viewer::from(Some(7)), Viewer::User(7));
    assert_eq!(Viewer::from(None), Viewer::Shared);
}

#[sqlx::test]
async fn an_authenticated_caller_reads_and_lists_their_private_profile(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let mut as_bob = bearer_client(addr, api_token(&pool, bob).await);
    let mut no_caller = client_for(serve_as(&store, None), as_client);
    as_alice.create_profile(create("alpha", ONE)).await.unwrap();
    let read = as_alice
        .get_profile(get("alpha", None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.version, 1);
    let listed = as_alice
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.profiles.len(), 1);
    let hidden = as_bob.get_profile(get("alpha", None)).await.unwrap_err();
    assert_eq!(hidden.code(), Code::NotFound);
    let shared_only = no_caller.get_profile(get("alpha", None)).await.unwrap_err();
    assert_eq!(shared_only.code(), Code::NotFound);
    let by_bob = as_bob
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        by_bob.profiles,
        Vec::<fleet_proto::v1::ProfileSummary>::new()
    );
    let by_none = no_caller
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        by_none.profiles,
        Vec::<fleet_proto::v1::ProfileSummary>::new()
    );
}
