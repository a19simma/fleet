//! The profile sharing, catalog and capability RPCs over a real tonic server on a loopback
//! port. The sharing handlers are stubs that answer `UNIMPLEMENTED` for the caller that reaches
//! them. The client token lists the
//! catalog and shares profiles, the box token reaches neither, and no static token reaches an
//! admin service. The tests need
//! a Postgres superuser URL in `DATABASE_URL` and live in their own binary because each one binds
//! a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::v1::fleet_capability_admin_client::FleetCapabilityAdminClient;
use fleet_proto::v1::fleet_catalog_admin_client::FleetCatalogAdminClient;
use fleet_proto::v1::fleet_catalog_client::FleetCatalogClient;
use fleet_proto::v1::fleet_profiles_client::FleetProfilesClient;
use fleet_proto::v1::{
    GrantCapabilityRequest, ListCapabilitiesRequest, ListCatalogRequest, RevokeCapabilityRequest,
    SetCatalogItemEnabledRequest, ShareProfileRequest, UnshareProfileRequest,
    UpsertCatalogItemRequest,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const DENIED: &str = "bearer token not valid for this service";

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;

fn as_box(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, BOX)
}

fn as_client(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, CLIENT)
}

fn with_token(mut request: Request<()>, token: &str) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {token}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

fn channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

async fn start(pool: PgPool) -> (SocketAddr, Store) {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    (addr, store)
}

fn catalog(
    addr: SocketAddr,
    i: Interceptor,
) -> FleetCatalogClient<InterceptedService<Channel, Interceptor>> {
    FleetCatalogClient::with_interceptor(channel(addr), i)
}

fn profiles(
    addr: SocketAddr,
    i: Interceptor,
) -> FleetProfilesClient<InterceptedService<Channel, Interceptor>> {
    FleetProfilesClient::with_interceptor(channel(addr), i)
}

fn catalog_admin(
    addr: SocketAddr,
    i: Interceptor,
) -> FleetCatalogAdminClient<InterceptedService<Channel, Interceptor>> {
    FleetCatalogAdminClient::with_interceptor(channel(addr), i)
}

fn capability_admin(
    addr: SocketAddr,
    i: Interceptor,
) -> FleetCapabilityAdminClient<InterceptedService<Channel, Interceptor>> {
    FleetCapabilityAdminClient::with_interceptor(channel(addr), i)
}

fn admin_denied(err: &Status) {
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "admin required");
}

fn denied(err: &Status) {
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), DENIED);
}

#[sqlx::test]
async fn list_catalog_answers_an_empty_page_for_the_client_token(pool: PgPool) {
    let (addr, _) = start(pool).await;
    let reply = catalog(addr, as_client)
        .list_catalog(ListCatalogRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.items.len(), 0);
    assert_eq!(reply.next_id, "");
}

#[sqlx::test]
async fn the_box_token_cannot_list_the_catalog(pool: PgPool) {
    let (addr, _) = start(pool).await;
    let err = catalog(addr, as_box)
        .list_catalog(ListCatalogRequest::default())
        .await
        .unwrap_err();
    denied(&err);
}

#[sqlx::test]
async fn share_and_unshare_need_a_user_token_for_the_static_client_token(pool: PgPool) {
    let (addr, _) = start(pool).await;
    let mut client = profiles(addr, as_client);
    let share = client
        .share_profile(ShareProfileRequest::default())
        .await
        .unwrap_err();
    let unshare = client
        .unshare_profile(UnshareProfileRequest::default())
        .await
        .unwrap_err();
    for err in [share, unshare] {
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(err.message(), fleet_server::profiles::ERR_PROFILE_UNOWNED);
    }
}

#[sqlx::test]
async fn the_box_token_cannot_share_a_profile(pool: PgPool) {
    let (addr, _) = start(pool).await;
    let mut client = profiles(addr, as_box);
    denied(
        &client
            .share_profile(ShareProfileRequest::default())
            .await
            .unwrap_err(),
    );
    denied(
        &client
            .unshare_profile(UnshareProfileRequest::default())
            .await
            .unwrap_err(),
    );
}

#[sqlx::test]
async fn no_token_reaches_an_admin_service(pool: PgPool) {
    let (addr, _) = start(pool).await;
    let tokens: [Interceptor; 2] = [as_box, as_client];
    for i in tokens {
        let mut catalog = catalog_admin(addr, i);
        admin_denied(
            &catalog
                .upsert_catalog_item(UpsertCatalogItemRequest::default())
                .await
                .unwrap_err(),
        );
        admin_denied(
            &catalog
                .set_catalog_item_enabled(SetCatalogItemEnabledRequest::default())
                .await
                .unwrap_err(),
        );
        let mut caps = capability_admin(addr, i);
        admin_denied(
            &caps
                .grant_capability(GrantCapabilityRequest::default())
                .await
                .unwrap_err(),
        );
        admin_denied(
            &caps
                .revoke_capability(RevokeCapabilityRequest::default())
                .await
                .unwrap_err(),
        );
        admin_denied(
            &caps
                .list_capabilities(ListCapabilitiesRequest::default())
                .await
                .unwrap_err(),
        );
    }
}
