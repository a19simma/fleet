//! The admin gate over a real tonic server built by the composition root: every admin RPC
//! against every credential class, one test per cell, plus the handler re-check, the unknown
//! admin path, the list kind check and the list cursor rules. The tests need a Postgres
//! superuser URL in `DATABASE_URL` and live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::v1::fleet_capability_admin_client::FleetCapabilityAdminClient;
use fleet_proto::v1::fleet_capability_admin_server::FleetCapabilityAdmin;
use fleet_proto::v1::fleet_catalog_admin_client::FleetCatalogAdminClient;
use fleet_proto::v1::fleet_catalog_admin_server::FleetCatalogAdmin;
use fleet_proto::v1::fleet_catalog_client::FleetCatalogClient;
use fleet_proto::v1::{
    CatalogItem, GrantCapabilityRequest, ListCapabilitiesRequest, ListCatalogRequest,
    RevokeCapabilityRequest, SetCatalogItemEnabledRequest, UpsertCatalogItemRequest,
};
use fleet_server::auth::{ADMIN_REQUIRED, ADMIN_RPCS, BearerAuth, Caller};
use fleet_server::catalog::{MAX_CATALOG_CURSOR_BYTES, REASON_CURSOR_INVALID, REASON_KIND_UNKNOWN};
use fleet_server::config::Token;
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::Users;
use fleet_server::service::{FleetService, router};
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request};
use tonic_prost::ProstCodec;

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";

#[derive(Clone, Copy, Debug)]
enum Rpc {
    Upsert,
    SetEnabled,
    Grant,
    Revoke,
    List,
}

#[derive(Clone, Copy, Debug)]
enum Cred {
    BoxToken,
    ClientToken,
    NonAdminApiToken,
    AdminApiToken,
    RevokedAdminToken,
    AdminDemotedAfterAuth,
}

struct Rig {
    addr: SocketAddr,
    users: Users,
    pool: PgPool,
}

async fn start(pool: PgPool) -> Rig {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    Rig { addr, users, pool }
}

fn channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

fn bearer<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

async fn make_user(rig: &Rig, name: &str, admin: bool) -> (i64, i64, String) {
    let id = run(&rig.pool, &AdminCommand::CreateUser(name.into()), "op")
        .await
        .unwrap()
        .user_id;
    if admin {
        rig.users.set_admin(id, true).await.unwrap();
    }
    let token = rig.users.create_api_token(id, "t").await.unwrap();
    (
        id,
        token.id,
        String::from_utf8(token.token.expose().to_vec()).unwrap(),
    )
}

async fn call(rig: &Rig, rpc: Rpc, token: &str) -> Result<(), tonic::Status> {
    let mut catalog = FleetCatalogAdminClient::new(channel(rig.addr));
    let mut caps = FleetCapabilityAdminClient::new(channel(rig.addr));
    match rpc {
        Rpc::Upsert => catalog
            .upsert_catalog_item(bearer(UpsertCatalogItemRequest::default(), token))
            .await
            .map(drop),
        Rpc::SetEnabled => catalog
            .set_catalog_item_enabled(bearer(SetCatalogItemEnabledRequest::default(), token))
            .await
            .map(drop),
        Rpc::Grant => caps
            .grant_capability(bearer(GrantCapabilityRequest::default(), token))
            .await
            .map(drop),
        Rpc::Revoke => caps
            .revoke_capability(bearer(RevokeCapabilityRequest::default(), token))
            .await
            .map(drop),
        Rpc::List => caps
            .list_capabilities(bearer(ListCapabilitiesRequest::default(), token))
            .await
            .map(drop),
    }
}

fn reached(rpc: Rpc) -> Code {
    match rpc {
        Rpc::Upsert => Code::InvalidArgument,
        Rpc::SetEnabled => Code::NotFound,
        Rpc::Grant | Rpc::Revoke | Rpc::List => Code::Unimplemented,
    }
}

async fn cell(pool: PgPool, rpc: Rpc, cred: Cred) {
    let rig = start(pool).await;
    let (admin_id, admin_token_id, admin_token) = make_user(&rig, "root", true).await;
    let (_, _, plain_token) = make_user(&rig, "plain", false).await;
    let control = call(&rig, rpc, &admin_token).await.unwrap_err();
    assert_eq!(control.code(), reached(rpc), "positive control {rpc:?}");

    let (token, expected) = match cred {
        Cred::BoxToken => (BOX.to_owned(), Code::PermissionDenied),
        Cred::ClientToken => (CLIENT.to_owned(), Code::PermissionDenied),
        Cred::NonAdminApiToken => (plain_token, Code::PermissionDenied),
        Cred::AdminApiToken => (admin_token, reached(rpc)),
        Cred::RevokedAdminToken => {
            rig.users
                .revoke_api_token(admin_id, admin_token_id)
                .await
                .unwrap();
            (admin_token, Code::Unauthenticated)
        }
        Cred::AdminDemotedAfterAuth => {
            rig.users.set_admin(admin_id, false).await.unwrap();
            (admin_token, Code::PermissionDenied)
        }
    };
    let err = call(&rig, rpc, &token).await.unwrap_err();
    assert_eq!(err.code(), expected, "{rpc:?} {cred:?}: {}", err.message());
    if expected == Code::PermissionDenied {
        assert_eq!(err.message(), ADMIN_REQUIRED, "{rpc:?} {cred:?}");
    }
}

macro_rules! cells {
    ($($name:ident: $rpc:expr, $cred:expr;)*) => {
        $(
            #[sqlx::test(migrations = false)]
            async fn $name(pool: PgPool) {
                cell(pool, $rpc, $cred).await;
            }
        )*
    };
}

cells! {
    upsert_box: Rpc::Upsert, Cred::BoxToken;
    upsert_client: Rpc::Upsert, Cred::ClientToken;
    upsert_non_admin: Rpc::Upsert, Cred::NonAdminApiToken;
    upsert_admin: Rpc::Upsert, Cred::AdminApiToken;
    upsert_revoked: Rpc::Upsert, Cred::RevokedAdminToken;
    upsert_demoted: Rpc::Upsert, Cred::AdminDemotedAfterAuth;
    set_enabled_box: Rpc::SetEnabled, Cred::BoxToken;
    set_enabled_client: Rpc::SetEnabled, Cred::ClientToken;
    set_enabled_non_admin: Rpc::SetEnabled, Cred::NonAdminApiToken;
    set_enabled_admin: Rpc::SetEnabled, Cred::AdminApiToken;
    set_enabled_revoked: Rpc::SetEnabled, Cred::RevokedAdminToken;
    set_enabled_demoted: Rpc::SetEnabled, Cred::AdminDemotedAfterAuth;
    grant_box: Rpc::Grant, Cred::BoxToken;
    grant_client: Rpc::Grant, Cred::ClientToken;
    grant_non_admin: Rpc::Grant, Cred::NonAdminApiToken;
    grant_admin: Rpc::Grant, Cred::AdminApiToken;
    grant_revoked: Rpc::Grant, Cred::RevokedAdminToken;
    grant_demoted: Rpc::Grant, Cred::AdminDemotedAfterAuth;
    revoke_box: Rpc::Revoke, Cred::BoxToken;
    revoke_client: Rpc::Revoke, Cred::ClientToken;
    revoke_non_admin: Rpc::Revoke, Cred::NonAdminApiToken;
    revoke_admin: Rpc::Revoke, Cred::AdminApiToken;
    revoke_revoked: Rpc::Revoke, Cred::RevokedAdminToken;
    revoke_demoted: Rpc::Revoke, Cred::AdminDemotedAfterAuth;
    list_box: Rpc::List, Cred::BoxToken;
    list_client: Rpc::List, Cred::ClientToken;
    list_non_admin: Rpc::List, Cred::NonAdminApiToken;
    list_admin: Rpc::List, Cred::AdminApiToken;
    list_revoked: Rpc::List, Cred::RevokedAdminToken;
    list_demoted: Rpc::List, Cred::AdminDemotedAfterAuth;
}

#[test]
fn the_matrix_covers_every_admin_rpc() {
    for path in ADMIN_RPCS {
        let rpc = path.rsplit('/').next().unwrap();
        assert!(
            [
                "UpsertCatalogItem",
                "SetCatalogItemEnabled",
                "GrantCapability",
                "RevokeCapability",
                "ListCapabilities"
            ]
            .contains(&rpc),
            "{path}"
        );
    }
    assert_eq!(ADMIN_RPCS.len(), 5);
}

#[sqlx::test(migrations = false)]
async fn an_unknown_admin_path_is_denied_even_to_an_admin(pool: PgPool) {
    let rig = start(pool).await;
    let (_, _, token) = make_user(&rig, "root", true).await;
    let mut grpc = tonic::client::Grpc::new(channel(rig.addr));
    for path in [
        "/fleet.v1.FleetCatalogAdmin/Nope",
        "/fleet.v1.FleetCatalogAdmin/",
        "/fleet.v1.FleetCapabilityAdmin/DeleteEverything",
        "/fleet.v1.FleetCatalogAdminX/UpsertCatalogItem",
    ] {
        grpc.ready().await.unwrap();
        let err = grpc
            .unary::<UpsertCatalogItemRequest, CatalogItem, _>(
                bearer(UpsertCatalogItemRequest::default(), &token),
                path.parse().unwrap(),
                ProstCodec::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
    }
}

#[sqlx::test(migrations = false)]
async fn the_handlers_deny_a_missing_or_non_admin_caller(pool: PgPool) {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    let svc = FleetService::new(store);
    let none = |status: tonic::Status| (status.code(), status.message().to_owned());
    let expected = (Code::PermissionDenied, ADMIN_REQUIRED.to_owned());
    let with = |caller: Option<Caller>| {
        let mut upsert = Request::new(UpsertCatalogItemRequest::default());
        let mut enable = Request::new(SetCatalogItemEnabledRequest::default());
        let mut grant = Request::new(GrantCapabilityRequest::default());
        let mut revoke = Request::new(RevokeCapabilityRequest::default());
        let mut list = Request::new(ListCapabilitiesRequest::default());
        if let Some(caller) = caller {
            upsert.extensions_mut().insert(caller);
            enable.extensions_mut().insert(caller);
            grant.extensions_mut().insert(caller);
            revoke.extensions_mut().insert(caller);
            list.extensions_mut().insert(caller);
        }
        (upsert, enable, grant, revoke, list)
    };
    for caller in [
        None,
        Some(Caller {
            user_id: 1,
            is_admin: false,
        }),
    ] {
        let (upsert, enable, grant, revoke, list) = with(caller);
        assert_eq!(
            none(svc.upsert_catalog_item(upsert).await.unwrap_err()),
            expected
        );
        assert_eq!(
            none(svc.set_catalog_item_enabled(enable).await.unwrap_err()),
            expected
        );
        assert_eq!(
            none(svc.grant_capability(grant).await.unwrap_err()),
            expected
        );
        assert_eq!(
            none(svc.revoke_capability(revoke).await.unwrap_err()),
            expected
        );
        assert_eq!(
            none(svc.list_capabilities(list).await.unwrap_err()),
            expected
        );
    }
    let (_, _, grant, _, _) = with(Some(Caller {
        user_id: 1,
        is_admin: true,
    }));
    assert_eq!(
        svc.grant_capability(grant).await.unwrap_err().code(),
        Code::Unimplemented
    );
}

async fn list(rig: &Rig, request: ListCatalogRequest) -> Result<(), tonic::Status> {
    FleetCatalogClient::new(channel(rig.addr))
        .list_catalog(bearer(request, CLIENT))
        .await
        .map(drop)
}

#[sqlx::test(migrations = false)]
async fn list_refuses_a_kind_outside_the_closed_set(pool: PgPool) {
    let rig = start(pool).await;
    list(&rig, ListCatalogRequest::default()).await.unwrap();
    for kind in [5, 99, -1, i32::MAX, i32::MIN] {
        let err = list(
            &rig,
            ListCatalogRequest {
                kind,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::InvalidArgument, REASON_KIND_UNKNOWN),
            "{kind}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn list_refuses_each_cursor_rule_with_the_fixed_reason(pool: PgPool) {
    let rig = start(pool).await;
    let cases = [
        ("nul", "a\0b".to_owned()),
        ("over the cap", "a".repeat(MAX_CATALOG_CURSOR_BYTES + 1)),
        ("leading dash", "-a".to_owned()),
        ("leading underscore", "_a".to_owned()),
        ("uppercase", "A".to_owned()),
        ("space", "a b".to_owned()),
        ("non ascii", "\u{e9}".to_owned()),
    ];
    for (label, after_id) in cases {
        let err = list(
            &rig,
            ListCatalogRequest {
                after_id,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (Code::InvalidArgument, REASON_CURSOR_INVALID),
            "{label}"
        );
    }
    for after_id in ["", "a", &"a".repeat(MAX_CATALOG_CURSOR_BYTES)] {
        list(
            &rig,
            ListCatalogRequest {
                after_id: after_id.to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
}

#[sqlx::test(migrations = false)]
async fn upsert_refuses_a_kind_outside_the_closed_set(pool: PgPool) {
    let rig = start(pool).await;
    let (_, _, token) = make_user(&rig, "root", true).await;
    for kind in [0, 5, 99, -1] {
        let err = FleetCatalogAdminClient::new(channel(rig.addr))
            .upsert_catalog_item(bearer(
                UpsertCatalogItemRequest {
                    id: "a".into(),
                    kind,
                    name: "a".into(),
                    content: "body".into(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{kind}");
    }
}
