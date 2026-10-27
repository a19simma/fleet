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
use fleet_server::service::router;
use fleet_server::store::Store;
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

fn serve(store: &Store) -> SocketAddr {
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
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

fn spawn(store: &Store) -> Profiles {
    client_for(serve(store), as_client)
}

fn create(name: &str, content: &str) -> CreateProfileRequest {
    CreateProfileRequest {
        name: name.to_owned(),
        content_json: content.to_owned(),
    }
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
    let store = store(pool).await;
    let mut profiles = spawn(&store);
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
    let store = store(pool).await;
    let mut profiles = spawn(&store);
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
    let mut profiles = spawn(&store);
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
    let addr = serve(&store);
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
    let store = store(pool).await;
    let mut profiles = spawn(&store);
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
    let store = store(pool).await;
    let mut profiles = spawn(&store);
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
    let mut profiles = spawn(&store);
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
    let store = store(pool).await;
    let mut profiles = client_for(serve(&store), as_box);
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
    let store = store(pool).await;
    let mut profiles = client_for(serve(&store), Ok);
    let err = profiles
        .list_profiles(ListProfilesRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[sqlx::test]
async fn update_delete_and_truncate_are_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut profiles = spawn(&store);
    profiles.create_profile(create("alpha", ONE)).await.unwrap();
    let statements = [
        "UPDATE profile_blob SET size = size",
        "UPDATE profile_blob SET content = '\\x7b7d'",
        "UPDATE profile_version SET version = 9",
        "UPDATE profile_version SET name = 'other'",
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
