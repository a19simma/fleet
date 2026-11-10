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
use fleet_server::cred::capability::{Capabilities, PROFILE_TOOLS};
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
        edit: false,
    }
}

fn create_toml(name: &str, content: &str) -> CreateProfileRequest {
    CreateProfileRequest {
        name: name.to_owned(),
        content_json: String::new(),
        content_toml: content.to_owned(),
        edit: false,
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
async fn a_granted_client_saves_tools_and_the_hash_round_trips(pool: PgPool) {
    let store = store(pool.clone()).await;
    let bootstrap = Users::new(pool.clone()).bootstrap_user().await.unwrap();
    grant_tools(&pool, bootstrap).await;
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
async fn exactly_one_content_field_must_be_set(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&pool, &store);
    let both = CreateProfileRequest {
        name: "alpha".to_owned(),
        content_json: ONE.to_owned(),
        content_toml: PLAIN_TOML.to_owned(),
        edit: false,
    };
    let neither = CreateProfileRequest {
        name: "alpha".to_owned(),
        content_json: String::new(),
        content_toml: String::new(),
        edit: false,
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
async fn a_re_save_equal_to_an_older_version_moves_latest_there(pool: PgPool) {
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
    let back = profiles
        .create_profile(create("alpha", ONE))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((back.version, back.created), (1, false));
    let latest = profiles
        .get_profile(get("alpha", None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(latest.version, 1);
    assert_eq!(latest.hash, first.hash);
    let listed = profiles
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap()
        .into_inner()
        .profiles;
    assert_eq!(listed[0].latest_version, 1);
    assert_eq!(listed[0].hash, first.hash);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM profile_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 2);
    let forward = profiles
        .create_profile(create("alpha", TWO))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((forward.version, forward.created), (2, false));
    let latest = profiles
        .get_profile(get("alpha", None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(latest.version, 2);
    let fresh = profiles
        .create_profile(create("alpha", r#"{"claude_md":"three"}"#))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((fresh.version, fresh.created), (3, true));
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
    profiles::create_owned(pool, caller, None, name, ProfileContent::Json(json))
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
        None,
        "alpha",
        ProfileContent::Json(json),
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
    profiles::update_owned(pool, caller, None, id, ProfileContent::Json(json)).await
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
        edit: false,
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
    request.extensions_mut().insert(Caller {
        user_id: i64::MAX,
        is_admin: false,
    });
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
            profiles::create_owned(&pool, Some(alice), None, "alpha", ProfileContent::Json(ONE))
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

struct Matrix {
    pool: PgPool,
    alice: i64,
    bob: i64,
}

fn body(owner: &str, name: &str) -> String {
    format!(r#"{{"claude_md":"{owner}-{name}"}}"#)
}

async fn matrix(pool: PgPool) -> Matrix {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    for (caller, owner, name, shared) in [
        (alice, "alice", "apple", false),
        (alice, "alice", "cherry", true),
        (alice, "alice", "dup", false),
        (bob, "bob", "alpha", true),
        (bob, "bob", "banana", false),
        (bob, "bob", "dup", true),
    ] {
        owned(&pool, Some(caller), name, &body(owner, name))
            .await
            .unwrap();
        if shared {
            share(&pool, profile_id(&pool, caller, name).await).await;
        }
    }
    Matrix { pool, alice, bob }
}

impl Matrix {
    async fn read(&self, viewer: Viewer, name: &str) -> Result<String, StoreError> {
        profiles::get_for(&self.pool, viewer, name, None)
            .await
            .map(|read| read.content_json)
    }

    async fn names(&self, viewer: Viewer) -> Vec<String> {
        profiles::list_for(&self.pool, viewer, 0, None)
            .await
            .unwrap()
            .profiles
            .into_iter()
            .map(|summary| summary.name)
            .collect()
    }

    async fn id(&self, owner: i64, name: &str) -> i64 {
        profile_id(&self.pool, owner, name).await
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

#[sqlx::test]
async fn matrix_get_owner_reads_own_private_and_own_shared(pool: PgPool) {
    let m = matrix(pool).await;
    let own = Viewer::User(m.alice);
    for name in ["apple", "cherry", "dup"] {
        let read = m.read(own, name).await.unwrap();
        assert!(read.contains(&format!("alice-{name}")), "{read}");
    }
}

#[sqlx::test]
async fn matrix_get_other_user_reads_shared_and_private_is_not_found(pool: PgPool) {
    let m = matrix(pool).await;
    let bob = Viewer::User(m.bob);
    assert!(
        m.read(bob, "cherry")
            .await
            .unwrap()
            .contains("alice-cherry")
    );
    assert!(m.read(bob, "dup").await.unwrap().contains("bob-dup"));
    let foreign = m.read(bob, "apple").await.unwrap_err();
    let absent = m.read(bob, "ghost").await.unwrap_err();
    assert!(matches!(foreign, StoreError::NotFound));
    assert_eq!(foreign.to_string(), absent.to_string());
}

#[sqlx::test]
async fn matrix_get_no_caller_reads_shared_only(pool: PgPool) {
    let m = matrix(pool).await;
    let none = Viewer::from(None);
    assert!(
        m.read(none, "cherry")
            .await
            .unwrap()
            .contains("alice-cherry")
    );
    assert!(m.read(none, "alpha").await.unwrap().contains("bob-alpha"));
    assert!(m.read(none, "dup").await.unwrap().contains("bob-dup"));
    for name in ["apple", "banana", "ghost"] {
        assert!(matches!(
            m.read(none, name).await,
            Err(StoreError::NotFound)
        ));
    }
}

#[sqlx::test]
async fn matrix_list_owner_gets_own_plus_shared_in_name_order(pool: PgPool) {
    let m = matrix(pool).await;
    assert_eq!(
        m.names(Viewer::User(m.alice)).await,
        names(&["alpha", "apple", "cherry", "dup"])
    );
    let listed = profiles::list_for(&m.pool, Viewer::User(m.alice), 0, None)
        .await
        .unwrap();
    let dup = listed.profiles.iter().find(|p| p.name == "dup").unwrap();
    let own = profiles::get_for(&m.pool, Viewer::User(m.alice), "dup", None)
        .await
        .unwrap();
    assert_eq!(dup.hash, own.hash);
}

#[sqlx::test]
async fn matrix_list_other_user_gets_own_plus_shared_without_foreign_private(pool: PgPool) {
    let m = matrix(pool).await;
    assert_eq!(
        m.names(Viewer::User(m.bob)).await,
        names(&["alpha", "banana", "cherry", "dup"])
    );
}

#[sqlx::test]
async fn matrix_list_no_caller_gets_shared_only(pool: PgPool) {
    let m = matrix(pool).await;
    assert_eq!(
        m.names(Viewer::from(None)).await,
        names(&["alpha", "cherry", "dup"])
    );
}

#[sqlx::test]
async fn matrix_update_owner_adds_a_version_to_private_and_shared(pool: PgPool) {
    let m = matrix(pool).await;
    for name in ["apple", "cherry"] {
        let id = m.id(m.alice, name).await;
        let done = update(&m.pool, Some(m.alice), id, NEXT).await.unwrap();
        assert_eq!((done.version, done.created), (2, true), "{name}");
    }
}

#[sqlx::test]
async fn matrix_update_other_user_is_not_found_private_and_permission_denied_shared(pool: PgPool) {
    let m = matrix(pool).await;
    let private = m.id(m.alice, "apple").await;
    let shared = m.id(m.alice, "cherry").await;
    let before = snapshot(&m.pool).await;
    let hidden = update(&m.pool, Some(m.bob), private, NEXT)
        .await
        .unwrap_err();
    let absent = update(&m.pool, Some(m.bob), private + 1000, NEXT)
        .await
        .unwrap_err();
    assert!(matches!(hidden, StoreError::NotFound));
    assert_eq!(hidden.to_string(), absent.to_string());
    let reader = update(&m.pool, Some(m.bob), shared, NEXT)
        .await
        .unwrap_err();
    assert!(is_not_owner(&reader), "{reader}");
    assert_eq!(snapshot(&m.pool).await, before);
}

#[sqlx::test]
async fn matrix_update_no_caller_is_unowned_and_writes_nothing(pool: PgPool) {
    let m = matrix(pool).await;
    let before = snapshot(&m.pool).await;
    for name in ["apple", "cherry"] {
        let id = m.id(m.alice, name).await;
        assert!(matches!(
            update(&m.pool, None, id, NEXT).await,
            Err(StoreError::InvalidProfile(ProfileFault::Unowned))
        ));
    }
    assert_eq!(snapshot(&m.pool).await, before);
}

#[sqlx::test]
async fn matrix_delete_owner_removes_private_and_shared(pool: PgPool) {
    let m = matrix(pool).await;
    let private = bare_profile(&m.pool, m.alice, "bare-private").await;
    let shared = bare_profile(&m.pool, m.alice, "bare-shared").await;
    share(&m.pool, shared).await;
    for id in [private, shared] {
        profiles::delete_owned(&m.pool, Some(m.alice), id)
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM profile WHERE id = $1")
            .bind(id)
            .fetch_one(&m.pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}

#[sqlx::test]
async fn matrix_delete_other_user_is_not_found_private_and_permission_denied_shared(pool: PgPool) {
    let m = matrix(pool).await;
    let private = bare_profile(&m.pool, m.alice, "bare-private").await;
    let shared = bare_profile(&m.pool, m.alice, "bare-shared").await;
    share(&m.pool, shared).await;
    let before = snapshot(&m.pool).await;
    let hidden = profiles::delete_owned(&m.pool, Some(m.bob), private)
        .await
        .unwrap_err();
    let absent = profiles::delete_owned(&m.pool, Some(m.bob), private + 1000)
        .await
        .unwrap_err();
    assert!(matches!(hidden, StoreError::NotFound));
    assert_eq!(hidden.to_string(), absent.to_string());
    let reader = profiles::delete_owned(&m.pool, Some(m.bob), shared)
        .await
        .unwrap_err();
    assert!(is_not_owner(&reader), "{reader}");
    assert_eq!(snapshot(&m.pool).await, before);
}

#[sqlx::test]
async fn matrix_delete_no_caller_is_unowned_and_writes_nothing(pool: PgPool) {
    let m = matrix(pool).await;
    let private = bare_profile(&m.pool, m.alice, "bare-private").await;
    let shared = bare_profile(&m.pool, m.alice, "bare-shared").await;
    share(&m.pool, shared).await;
    let before = snapshot(&m.pool).await;
    for id in [private, shared] {
        assert!(matches!(
            profiles::delete_owned(&m.pool, None, id).await,
            Err(StoreError::InvalidProfile(ProfileFault::Unowned))
        ));
    }
    assert_eq!(snapshot(&m.pool).await, before);
}

const BATCH_REPO: &str = "https://example.com/org/repo.git";
const BATCH_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

async fn visibility_of(pool: &PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT visibility FROM profile WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn share_and_unshare_flip_visibility_and_are_idempotent(pool: PgPool) {
    let m = matrix(pool).await;
    let id = m.id(m.alice, "apple").await;
    for _ in 0..2 {
        let reply = profiles::share_owned(&m.pool, Some(m.alice), "apple")
            .await
            .unwrap();
        assert_eq!(reply.name, "apple");
        assert_eq!(reply.owner_user_id, u64::try_from(m.alice).unwrap());
        assert_eq!(
            reply.visibility,
            fleet_proto::v1::ProfileVisibility::Shared as i32
        );
        assert_eq!(visibility_of(&m.pool, id).await, "shared");
    }
    for _ in 0..2 {
        let reply = profiles::unshare_owned(&m.pool, Some(m.alice), "apple")
            .await
            .unwrap();
        assert_eq!(
            reply.visibility,
            fleet_proto::v1::ProfileVisibility::Private as i32
        );
        assert_eq!(visibility_of(&m.pool, id).await, "private");
    }
}

#[sqlx::test]
async fn share_and_unshare_refusals_write_nothing(pool: PgPool) {
    let m = matrix(pool).await;
    let before = snapshot(&m.pool).await;
    for shared in [true, false] {
        let call = |caller: Option<i64>, name: &'static str| {
            let pool = m.pool.clone();
            async move {
                if shared {
                    profiles::share_owned(&pool, caller, name).await
                } else {
                    profiles::unshare_owned(&pool, caller, name).await
                }
            }
        };
        let hidden = call(Some(m.bob), "apple").await.unwrap_err();
        let absent = call(Some(m.bob), "nothing").await.unwrap_err();
        assert!(matches!(hidden, StoreError::NotFound));
        assert_eq!(hidden.to_string(), absent.to_string());
        let reader = call(Some(m.bob), "cherry").await.unwrap_err();
        assert!(is_not_owner(&reader), "{reader}");
        assert!(matches!(
            call(None, "apple").await,
            Err(StoreError::InvalidProfile(ProfileFault::Unowned))
        ));
        for bad in ["", "bad name", "a/b"] {
            assert!(matches!(
                call(Some(m.alice), bad).await,
                Err(StoreError::InvalidProfile(ProfileFault::Name))
            ));
        }
        let long = "n".repeat(profiles::MAX_NAME_BYTES + 1);
        assert!(matches!(
            profiles::share_owned(&m.pool, Some(m.alice), &long).await,
            Err(StoreError::InvalidProfile(ProfileFault::Name))
        ));
    }
    assert_eq!(snapshot(&m.pool).await, before);
}

#[sqlx::test]
async fn a_name_owned_by_both_users_resolves_to_the_callers_own(pool: PgPool) {
    let m = matrix(pool).await;
    let alice_dup = m.id(m.alice, "dup").await;
    let bob_dup = m.id(m.bob, "dup").await;
    profiles::share_owned(&m.pool, Some(m.alice), "dup")
        .await
        .unwrap();
    assert_eq!(visibility_of(&m.pool, alice_dup).await, "shared");
    assert_eq!(visibility_of(&m.pool, bob_dup).await, "shared");
    profiles::unshare_owned(&m.pool, Some(m.alice), "dup")
        .await
        .unwrap();
    assert_eq!(visibility_of(&m.pool, alice_dup).await, "private");
    assert_eq!(visibility_of(&m.pool, bob_dup).await, "shared");
}

#[sqlx::test]
async fn unshare_leaves_a_queued_jobs_snapshot_intact(pool: PgPool) {
    let m = matrix(pool).await;
    let store = Store::new(m.pool.clone());
    let reply = store
        .submit_batch_for(
            Some(m.bob),
            &fleet_proto::v1::SubmitBatchRequest {
                idempotency_key: "snapshot-key".to_owned(),
                prompt: "fix the bug".to_owned(),
                repo: BATCH_REPO.to_owned(),
                base_sha: BATCH_SHA.to_owned(),
                repeats: 0,
                profiles: vec!["cherry".to_owned()],
                agent: String::new(),
                environment: String::new(),
            },
        )
        .await
        .unwrap();
    let job_id = reply.job_ids[0].clone();
    let row = |pool: PgPool, job_id: String| async move {
        sqlx::query_scalar::<_, String>("SELECT to_jsonb(j)::text FROM jobs j WHERE job_id = $1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let before = row(m.pool.clone(), job_id.clone()).await;
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE job_id = $1")
        .bind(&job_id)
        .fetch_one(&m.pool)
        .await
        .unwrap();
    assert_eq!(state, "QUEUED");
    profiles::unshare_owned(&m.pool, Some(m.alice), "cherry")
        .await
        .unwrap();
    assert_eq!(row(m.pool.clone(), job_id).await, before);
    let hidden = store
        .get_profile(Viewer::User(m.bob), "cherry", None)
        .await
        .unwrap_err();
    assert!(matches!(hidden, StoreError::NotFound));
}

#[sqlx::test]
async fn share_waits_on_the_profile_row_lock(pool: PgPool) {
    let m = matrix(pool).await;
    let id = m.id(m.alice, "apple").await;
    let mut holder = m.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM profile WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    let pool = m.pool.clone();
    let alice = m.alice;
    let task =
        tokio::spawn(async move { profiles::share_owned(&pool, Some(alice), "apple").await });
    timeout(WAIT, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE wait_event_type = 'Lock' AND query LIKE '%FROM profile WHERE owner_user_id%'",
            )
            .fetch_one(&m.pool)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!task.is_finished());
    assert_eq!(visibility_of(&m.pool, id).await, "private");
    holder.commit().await.unwrap();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert_eq!(visibility_of(&m.pool, id).await, "shared");
}

#[sqlx::test]
async fn share_rpc_maps_owner_not_owner_and_missing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let mut as_bob = bearer_client(addr, api_token(&pool, bob).await);
    as_alice.create_profile(create("alpha", ONE)).await.unwrap();
    let shared = as_alice
        .share_profile(fleet_proto::v1::ShareProfileRequest {
            name: "alpha".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        shared.visibility,
        fleet_proto::v1::ProfileVisibility::Shared as i32
    );
    let denied = as_bob
        .unshare_profile(fleet_proto::v1::UnshareProfileRequest {
            name: "alpha".to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(denied.message(), "only the owner can change this profile");
    let missing = as_bob
        .share_profile(fleet_proto::v1::ShareProfileRequest {
            name: "nothing".to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);
    let unshared = as_alice
        .unshare_profile(fleet_proto::v1::UnshareProfileRequest {
            name: "alpha".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        unshared.visibility,
        fleet_proto::v1::ProfileVisibility::Private as i32
    );
    let id = profile_id(&pool, alice, "alpha").await;
    assert_eq!(visibility_of(&pool, id).await, "private");
}

const RICH: &str = r#"{"authored_prompt":"be brief","selection":[{"enabled":false,"item_id":"skill-b"},{"enabled":false,"item_id":"skill-a"}]}"#;

async fn seed_rich(pool: &PgPool) {
    catalog_item(pool, "skill-a", "skill", true).await;
    catalog_item(pool, "skill-b", "skill", true).await;
}

fn off(id: &str) -> fleet_proto::v1::SelectionEntry {
    fleet_proto::v1::SelectionEntry {
        item_id: id.to_owned(),
        enabled: false,
    }
}

async fn read(
    pool: &PgPool,
    viewer: Viewer,
    name: &str,
    version: Option<u32>,
) -> Result<fleet_proto::v1::ProfileVersion, StoreError> {
    profiles::get_for(pool, viewer, name, version).await
}

#[sqlx::test]
async fn get_returns_owner_visibility_selection_and_prompt(pool: PgPool) {
    use fleet_proto::v1::ProfileVisibility;
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    seed_rich(&pool).await;
    put(&pool, alice, RICH).await;
    let own = read(&pool, Viewer::User(alice), "alpha", None)
        .await
        .unwrap();
    assert_eq!(own.owner, "alice");
    assert_eq!(own.visibility, ProfileVisibility::Private as i32);
    assert_eq!(own.selection, vec![off("skill-a"), off("skill-b")]);
    assert_eq!(own.authored_prompt, "be brief");
    assert!(!own.created);
    assert!(read(&pool, Viewer::User(bob), "alpha", None).await.is_err());
    profiles::share_owned(&pool, Some(alice), "alpha")
        .await
        .unwrap();
    for viewer in [Viewer::User(bob), Viewer::Shared, Viewer::User(alice)] {
        let seen = read(&pool, viewer, "alpha", Some(1)).await.unwrap();
        assert_eq!(seen.owner, "alice");
        assert_eq!(seen.visibility, ProfileVisibility::Shared as i32);
        assert_eq!(seen.selection, own.selection);
        assert_eq!(seen.authored_prompt, "be brief");
    }
    assert_eq!(
        read(&pool, Viewer::User(bob), "alpha", None).await.unwrap(),
        read(&pool, Viewer::User(alice), "alpha", None)
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn get_fields_follow_the_requested_version(pool: PgPool) {
    store(pool.clone()).await;
    seed_rich(&pool).await;
    let alice = user(&pool, "alice").await;
    put(&pool, alice, RICH).await;
    put(&pool, alice, OWNED).await;
    let first = read(&pool, Viewer::User(alice), "alpha", Some(1))
        .await
        .unwrap();
    let latest = read(&pool, Viewer::User(alice), "alpha", None)
        .await
        .unwrap();
    assert_eq!(
        (first.version, first.authored_prompt.as_str()),
        (1, "be brief")
    );
    assert_eq!(first.selection.len(), 2);
    assert_eq!(latest.version, 2);
    assert_eq!(latest.authored_prompt, "");
    assert_eq!(
        latest.selection,
        Vec::<fleet_proto::v1::SelectionEntry>::new()
    );
}

#[sqlx::test]
async fn list_returns_owner_and_visibility_per_row(pool: PgPool) {
    use fleet_proto::v1::ProfileVisibility::{Private, Shared};
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    seed_rich(&pool).await;
    owned(&pool, Some(alice), "alpha", OWNED).await.unwrap();
    owned(&pool, Some(bob), "beta", OWNED).await.unwrap();
    owned(&pool, Some(bob), "gamma", OWNED).await.unwrap();
    owned(&pool, Some(alice), "gamma", RICH).await.unwrap();
    for (owner, name) in [(bob, "beta"), (bob, "gamma")] {
        profiles::share_owned(&pool, Some(owner), name)
            .await
            .unwrap();
    }
    let rows = |viewer| {
        let pool = pool.clone();
        async move {
            profiles::list_for(&pool, viewer, 0, None)
                .await
                .unwrap()
                .profiles
                .into_iter()
                .map(|p| (p.name, p.owner, p.visibility))
                .collect::<Vec<_>>()
        }
    };
    let row = |name: &str, owner: &str, vis: fleet_proto::v1::ProfileVisibility| {
        (name.to_owned(), owner.to_owned(), vis as i32)
    };
    assert_eq!(
        rows(Viewer::User(alice)).await,
        vec![
            row("alpha", "alice", Private),
            row("beta", "bob", Shared),
            row("gamma", "alice", Private),
        ]
    );
    assert_eq!(
        rows(Viewer::User(bob)).await,
        vec![row("beta", "bob", Shared), row("gamma", "bob", Shared)]
    );
    assert_eq!(
        rows(Viewer::Shared).await,
        vec![row("beta", "bob", Shared), row("gamma", "bob", Shared)]
    );
}

#[sqlx::test]
async fn a_hostile_owner_name_is_returned_verbatim(pool: PgPool) {
    store(pool.clone()).await;
    let hostile = "al\"\r\n\u{85}\u{2028}\u{202e}<b>\\\u{1f600}";
    let owner = user(&pool, hostile).await;
    put(&pool, owner, OWNED).await;
    profiles::share_owned(&pool, Some(owner), "alpha")
        .await
        .unwrap();
    let got = read(&pool, Viewer::Shared, "alpha", None).await.unwrap();
    assert_eq!(got.owner, hostile);
    let listed = profiles::list_for(&pool, Viewer::Shared, 0, None)
        .await
        .unwrap();
    assert_eq!(listed.profiles[0].owner, hostile);
}

#[sqlx::test]
async fn not_visible_and_absent_profiles_give_one_status_over_rpc(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    seed_rich(&pool).await;
    put(&pool, alice, RICH).await;
    let mut client = spawn(&pool, &store);
    let hidden = timeout(
        WAIT,
        client.get_profile(GetProfileRequest {
            name: "alpha".to_owned(),
            version: None,
        }),
    )
    .await
    .unwrap()
    .unwrap_err();
    let absent = timeout(
        WAIT,
        client.get_profile(GetProfileRequest {
            name: "ghost".to_owned(),
            version: None,
        }),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(hidden.code(), Code::NotFound);
    assert_eq!(hidden.code(), absent.code());
    assert_eq!(hidden.message(), absent.message());
    profiles::share_owned(&pool, Some(alice), "alpha")
        .await
        .unwrap();
    let seen = timeout(
        WAIT,
        client.get_profile(GetProfileRequest {
            name: "alpha".to_owned(),
            version: None,
        }),
    )
    .await
    .unwrap()
    .unwrap()
    .into_inner();
    assert_eq!(seen.owner, "alice");
    assert_eq!(seen.authored_prompt, "be brief");
    let listed = timeout(
        WAIT,
        client.list_profiles(ListProfilesRequest {
            limit: 0,
            after_name: None,
        }),
    )
    .await
    .unwrap()
    .unwrap()
    .into_inner();
    assert_eq!(listed.profiles[0].owner, "alice");
    assert_eq!(
        listed.profiles[0].visibility,
        fleet_proto::v1::ProfileVisibility::Shared as i32
    );
}

const TOOLS_TOML_TWO: &str = "[[tools]]\nname = \"node\"\nversion = \"20.11.2\"\n";

async fn root(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO users (username, is_admin) VALUES ('root', true) \
         ON CONFLICT (lower(username)) DO UPDATE SET is_admin = true RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn grant_tools(pool: &PgPool, user: i64) {
    let admin = root(pool).await;
    Capabilities::new(pool.clone())
        .grant(admin, user, PROFILE_TOOLS)
        .await
        .unwrap();
}

async fn revoke_tools(pool: &PgPool, user: i64) {
    let admin = root(pool).await;
    assert!(
        Capabilities::new(pool.clone())
            .revoke(admin, user, PROFILE_TOOLS)
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn saving_tools_without_the_capability_is_denied_and_stores_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let err = as_alice
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), profiles::ERR_PROFILE_TOOLS_NOT_GRANTED);
    assert!(!err.message().contains("node"));
    assert_eq!(counts(&pool).await, (0, 0));
    let json = r#"{"tools":[{"name":"node","version":"20.11.1"}]}"#;
    let err = as_alice
        .create_profile(create("alpha", json))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(counts(&pool).await, (0, 0));
    let mut as_client = client_for(addr, as_client);
    let err = as_client
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), profiles::ERR_PROFILE_TOOLS_NOT_GRANTED);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn a_grant_is_per_user_and_covers_only_tools(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    grant_tools(&pool, alice).await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let mut as_bob = bearer_client(addr, api_token(&pool, bob).await);
    let created = as_alice
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap()
        .into_inner();
    let expected = fleet_core::Profile::from_toml(TOOLS_TOML).unwrap();
    assert!(created.created);
    assert_eq!(created.hash, expected.hash().to_string());
    assert_eq!(created.content_json.as_bytes(), expected.canonical_json());
    let err = as_bob
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    as_bob
        .create_profile(create_toml("beta", PLAIN_TOML))
        .await
        .unwrap();
    assert_eq!(
        owners(&pool).await,
        [(alice, "alpha".to_owned()), (bob, "beta".to_owned())]
    );
}

#[sqlx::test]
async fn a_revoke_between_saves_refuses_the_second_save(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    grant_tools(&pool, alice).await;
    let mut as_alice = bearer_client(serve(&pool, &store), api_token(&pool, alice).await);
    as_alice
        .create_profile(create_toml("alpha", TOOLS_TOML))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 1));
    revoke_tools(&pool, alice).await;
    for content in [TOOLS_TOML_TWO, TOOLS_TOML] {
        let err = as_alice
            .create_profile(create_toml("alpha", content))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(err.message(), profiles::ERR_PROFILE_TOOLS_NOT_GRANTED);
    }
    assert_eq!(counts(&pool).await, (1, 1));
    as_alice.create_profile(create("alpha", ONE)).await.unwrap();
    assert_eq!(counts(&pool).await, (2, 2));
}

#[sqlx::test]
async fn updating_with_tools_needs_the_capability(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    owned(&pool, Some(alice), "alpha", ONE).await.unwrap();
    let id = profile_id(&pool, alice, "alpha").await;
    let before = counts(&pool).await;
    let err = profiles::update_owned(
        &pool,
        Some(alice),
        None,
        id,
        ProfileContent::Toml(TOOLS_TOML),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::ToolsNotGranted), "{err}");
    assert_eq!(counts(&pool).await, before);
    grant_tools(&pool, alice).await;
    profiles::update_owned(
        &pool,
        Some(alice),
        None,
        id,
        ProfileContent::Toml(TOOLS_TOML),
    )
    .await
    .unwrap();
}

const UNKNOWN_ITEM: &str = "profile selection names an item that is not in the catalog";
const DISABLED_ITEM: &str = "profile selection names an item an admin disabled";

async fn catalog_item(pool: &PgPool, id: &str, kind: &str, enabled: bool) {
    let body = if kind == "tool" { "1.2.3" } else { "body" };
    let name = if kind == "tool" { "node" } else { id };
    sqlx::query(
        "INSERT INTO catalog_items (id, kind, name, content, digest, admin_enabled) \
         VALUES ($1, $2, $3, $4, decode(repeat('00', 32), 'hex'), $5)",
    )
    .bind(id)
    .bind(kind)
    .bind(name)
    .bind(body)
    .bind(enabled)
    .execute(pool)
    .await
    .unwrap();
}

fn off_json(ids: &[&str]) -> String {
    let entries: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| serde_json::json!({ "item_id": id, "enabled": false }))
        .collect();
    serde_json::json!({ "claude_md": "x", "selection": entries }).to_string()
}

fn off_toml(ids: &[&str]) -> String {
    let mut out = String::from("claude_md = \"x\"\n");
    for id in ids {
        out.push_str("[[selection]]\nitem_id = \"");
        out.push_str(id);
        out.push_str("\"\nenabled = false\n");
    }
    out
}

async fn save(pool: &PgPool, caller: i64, name: &str, content: ProfileContent<'_>) -> StoreError {
    profiles::create_owned(pool, Some(caller), None, name, content)
        .await
        .unwrap_err()
}

#[sqlx::test]
async fn an_unknown_selection_id_is_refused_and_writes_nothing(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "known", "skill", true).await;
    for content in [off_json(&["known", "ghost"]), off_json(&["ghost"])] {
        let err = save(&pool, alice, "alpha", ProfileContent::Json(&content)).await;
        assert!(matches!(err, StoreError::InvalidProfile(_)), "{err}");
        assert_eq!(err.to_string(), UNKNOWN_ITEM);
        assert!(!err.to_string().contains("ghost"));
    }
    let toml = off_toml(&["ghost"]);
    let err = save(&pool, alice, "alpha", ProfileContent::Toml(&toml)).await;
    assert_eq!(err.to_string(), UNKNOWN_ITEM);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn an_admin_disabled_selection_id_is_refused_and_writes_nothing(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "known", "skill", true).await;
    catalog_item(&pool, "dis", "skill", false).await;
    let json = off_json(&["known", "dis"]);
    let err = save(&pool, alice, "alpha", ProfileContent::Json(&json)).await;
    assert!(matches!(err, StoreError::InvalidProfile(_)), "{err}");
    assert_eq!(err.to_string(), DISABLED_ITEM);
    assert!(!err.to_string().contains("dis\u{0}"));
    let toml = off_toml(&["dis"]);
    let err = save(&pool, alice, "alpha", ProfileContent::Toml(&toml)).await;
    assert_eq!(err.to_string(), DISABLED_ITEM);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn an_unknown_id_is_reported_before_a_disabled_one(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "dis", "skill", false).await;
    let json = off_json(&["dis", "ghost"]);
    let err = save(&pool, alice, "alpha", ProfileContent::Json(&json)).await;
    assert_eq!(err.to_string(), UNKNOWN_ITEM);
}

#[sqlx::test]
async fn known_enabled_and_empty_selections_are_accepted(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "a", "skill", true).await;
    catalog_item(&pool, "b", "context", true).await;
    catalog_item(&pool, "c", "subagent", true).await;
    for (name, content) in [("one", off_json(&["a", "b", "c"])), ("two", off_json(&[]))] {
        profiles::create_owned(
            &pool,
            Some(alice),
            None,
            name,
            ProfileContent::Json(&content),
        )
        .await
        .unwrap();
    }
    let toml = off_toml(&["a"]);
    profiles::create_owned(
        &pool,
        Some(alice),
        None,
        "three",
        ProfileContent::Toml(&toml),
    )
    .await
    .unwrap();
    assert_eq!(counts(&pool).await, (3, 3));
}

#[sqlx::test]
async fn a_tool_item_needs_the_owner_grant_to_save(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "tool1", "tool", true).await;
    let json = off_json(&["tool1"]);
    let toml = off_toml(&["tool1"]);
    for content in [ProfileContent::Json(&json), ProfileContent::Toml(&toml)] {
        let err = save(&pool, alice, "alpha", content).await;
        assert!(matches!(err, StoreError::ToolsNotGranted), "{err}");
        assert_eq!(err.to_string(), profiles::ERR_PROFILE_TOOLS_NOT_GRANTED);
    }
    nothing_written(&pool).await;
    grant_tools(&pool, alice).await;
    profiles::create_owned(
        &pool,
        Some(alice),
        None,
        "alpha",
        ProfileContent::Json(&json),
    )
    .await
    .unwrap();
    profiles::create_owned(
        &pool,
        Some(alice),
        None,
        "beta",
        ProfileContent::Toml(&toml),
    )
    .await
    .unwrap();
    revoke_tools(&pool, alice).await;
    let err = save(&pool, alice, "gamma", ProfileContent::Json(&json)).await;
    assert!(matches!(err, StoreError::ToolsNotGranted), "{err}");
    assert_eq!(counts(&pool).await, (1, 2));
}

#[sqlx::test]
async fn non_tool_kinds_need_no_grant(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    for (id, kind) in [("a", "skill"), ("b", "subagent"), ("c", "context")] {
        catalog_item(&pool, id, kind, true).await;
    }
    let json = off_json(&["a", "b", "c"]);
    profiles::create_owned(
        &pool,
        Some(alice),
        None,
        "alpha",
        ProfileContent::Json(&json),
    )
    .await
    .unwrap();
}

#[sqlx::test]
async fn a_disabled_tool_item_reports_disabled_before_the_grant(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "tool1", "tool", false).await;
    let json = off_json(&["tool1"]);
    let err = save(&pool, alice, "alpha", ProfileContent::Json(&json)).await;
    assert_eq!(err.to_string(), DISABLED_ITEM);
}

#[sqlx::test]
async fn update_applies_the_same_selection_rules(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "ok", "skill", true).await;
    catalog_item(&pool, "dis", "skill", false).await;
    catalog_item(&pool, "tool1", "tool", true).await;
    owned(&pool, Some(alice), "alpha", ONE).await.unwrap();
    let id = profile_id(&pool, alice, "alpha").await;
    let before = counts(&pool).await;
    for (ids, want) in [
        (vec!["ghost"], UNKNOWN_ITEM),
        (vec!["dis"], DISABLED_ITEM),
        (vec!["tool1"], profiles::ERR_PROFILE_TOOLS_NOT_GRANTED),
    ] {
        let json = off_json(&ids);
        let err = profiles::update_owned(&pool, Some(alice), None, id, ProfileContent::Json(&json))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), want);
        let toml = off_toml(&ids);
        let err = profiles::update_owned(&pool, Some(alice), None, id, ProfileContent::Toml(&toml))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), want);
    }
    assert_eq!(counts(&pool).await, before);
    let json = off_json(&["ok"]);
    profiles::update_owned(&pool, Some(alice), None, id, ProfileContent::Json(&json))
        .await
        .unwrap();
    grant_tools(&pool, alice).await;
    let json = off_json(&["tool1"]);
    profiles::update_owned(&pool, Some(alice), None, id, ProfileContent::Json(&json))
        .await
        .unwrap();
}

#[sqlx::test]
async fn hostile_selection_ids_are_refused_by_the_validator_without_an_echo(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "known", "skill", true).await;
    let long = "a".repeat(65);
    let hostile = [
        "",
        long.as_str(),
        "a\rb",
        "a\nb",
        "a\r\nb",
        "a\u{0}b",
        "a b",
        " known",
        "known ",
        "\u{e9}clair",
        "a%41",
        "a\\b",
        "a'; DROP TABLE catalog_items; --",
        "a\" OR \"1\"=\"1",
        "A",
        "-a",
        "a\u{85}b",
        "a\u{2028}b",
    ];
    for id in hostile {
        let json = off_json(&[id]);
        let err = save(&pool, alice, "alpha", ProfileContent::Json(&json)).await;
        assert!(
            matches!(err, StoreError::InvalidProfile(_)),
            "{id:?}: {err}"
        );
        let text = err.to_string();
        let sample = id.trim();
        assert!(
            sample.is_empty() || !text.contains(sample),
            "{id:?}: {text}"
        );
        assert_ne!(text, UNKNOWN_ITEM, "{id:?}");
        assert_ne!(text, DISABLED_ITEM, "{id:?}");
    }
    nothing_written(&pool).await;
    let items: i64 = sqlx::query_scalar("SELECT count(*) FROM catalog_items")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(items, 1);
}

#[sqlx::test]
async fn the_model_allowlist_still_runs_first(pool: PgPool) {
    let allow = fleet_core::model_allowlist::ModelAllowlist::parse("claude-opus-4-1").unwrap();
    let store = Store::new(pool.clone()).with_model_allowlist(Some(allow));
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let json = serde_json::json!({
        "model": "gpt-5",
        "selection": [{ "item_id": "ghost", "enabled": false }],
    })
    .to_string();
    let err = store
        .create_profile(Some(alice), "alpha", &json)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::ModelDenied(_)), "{err}");
    let ok = serde_json::json!({
        "model": "claude-opus-4-1",
        "selection": [{ "item_id": "ghost", "enabled": false }],
    })
    .to_string();
    let err = store
        .create_profile(Some(alice), "alpha", &ok)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), UNKNOWN_ITEM);
}

#[sqlx::test]
async fn a_save_over_rpc_maps_the_refusals_to_fixed_statuses(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "dis", "skill", false).await;
    catalog_item(&pool, "tool1", "tool", true).await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let err = as_alice
        .create_profile(create("alpha", &off_json(&["ghost"])))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), UNKNOWN_ITEM);
    let err = as_alice
        .create_profile(create("alpha", &off_json(&["dis"])))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), DISABLED_ITEM);
    let err = as_alice
        .create_profile(create("alpha", &off_json(&["tool1"])))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), profiles::ERR_PROFILE_TOOLS_NOT_GRANTED);
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn a_save_waits_for_a_tools_revoke_in_flight_and_is_then_refused(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "tool1", "tool", true).await;
    grant_tools(&pool, alice).await;
    let mut revoke = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&mut *revoke)
        .await
        .unwrap();
    let held = pool.clone();
    let json = off_json(&["tool1"]);
    let save = tokio::spawn(async move {
        profiles::create_owned(
            &held,
            Some(alice),
            None,
            "alpha",
            ProfileContent::Json(&json),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!save.is_finished());
    revoke.commit().await.unwrap();
    let err = timeout(WAIT, save).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(err, StoreError::ToolsNotGranted), "{err}");
    nothing_written(&pool).await;
}

#[sqlx::test]
async fn a_save_waits_for_an_admin_disable_in_flight_and_is_then_refused(pool: PgPool) {
    store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    catalog_item(&pool, "a", "skill", true).await;
    let mut edit = pool.begin().await.unwrap();
    sqlx::query("UPDATE catalog_items SET admin_enabled = false WHERE id = 'a'")
        .execute(&mut *edit)
        .await
        .unwrap();
    let held = pool.clone();
    let json = off_json(&["a"]);
    let save = tokio::spawn(async move {
        profiles::create_owned(
            &held,
            Some(alice),
            None,
            "alpha",
            ProfileContent::Json(&json),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!save.is_finished());
    edit.commit().await.unwrap();
    let err = timeout(WAIT, save).await.unwrap().unwrap().unwrap_err();
    assert_eq!(err.to_string(), DISABLED_ITEM);
    nothing_written(&pool).await;
}

fn edit_request(name: &str, content: &str) -> CreateProfileRequest {
    CreateProfileRequest {
        edit: true,
        ..create(name, content)
    }
}

#[sqlx::test]
async fn edit_saves_a_version_of_the_callers_own_profile(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    as_alice.create_profile(create("alpha", ONE)).await.unwrap();
    let saved = as_alice
        .create_profile(edit_request("alpha", TWO))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(saved.version, 2);
    assert_eq!(counts(&pool).await, (2, 2));
    assert_eq!(owners(&pool).await, vec![(alice, "alpha".to_owned())]);
}

#[sqlx::test]
async fn edit_of_a_shared_foreign_profile_is_denied_and_forks_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let mut as_bob = bearer_client(addr, api_token(&pool, bob).await);
    as_alice.create_profile(create("alpha", ONE)).await.unwrap();
    as_alice
        .share_profile(fleet_proto::v1::ShareProfileRequest {
            name: "alpha".to_owned(),
        })
        .await
        .unwrap();
    let before = counts(&pool).await;
    let denied = as_bob
        .create_profile(edit_request("alpha", TWO))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(denied.message(), "only the owner can change this profile");
    assert_eq!(counts(&pool).await, before);
    assert_eq!(owners(&pool).await, vec![(alice, "alpha".to_owned())]);
}

#[sqlx::test]
async fn edit_of_a_private_foreign_or_missing_profile_is_not_found(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let addr = serve(&pool, &store);
    let mut as_alice = bearer_client(addr, api_token(&pool, alice).await);
    let mut as_bob = bearer_client(addr, api_token(&pool, bob).await);
    as_alice.create_profile(create("alpha", ONE)).await.unwrap();
    let before = counts(&pool).await;
    for name in ["alpha", "nothing"] {
        let err = as_bob
            .create_profile(edit_request(name, TWO))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound, "{name}");
        assert_eq!(err.message(), "profile not found", "{name}");
    }
    assert_eq!(counts(&pool).await, before);
}
