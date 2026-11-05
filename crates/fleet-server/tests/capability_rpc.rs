//! The capability admin RPCs over a real tonic server built by the composition root, and the
//! handlers called directly with a stale admin caller. The tests need a Postgres superuser URL in
//! `DATABASE_URL` and live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::fleet_capability_admin_client::FleetCapabilityAdminClient;
use fleet_proto::v1::fleet_capability_admin_server::FleetCapabilityAdmin;
use fleet_proto::v1::{
    GrantCapabilityRequest, ListCapabilitiesRequest, RevokeCapabilityRequest, UserCapability,
};
use fleet_server::auth::{ADMIN_REQUIRED, BearerAuth, Caller};
use fleet_server::config::Token;
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::capability::{
    PROFILE_TOOLS, REASON_NO_SUCH_USER, REASON_UNKNOWN_CAPABILITY,
};
use fleet_server::cred::users::Users;
use fleet_server::service::{FleetService, router};
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const BAND: Duration = Duration::from_millis(500);
const OUTER: Duration = Duration::from_secs(20);

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

fn client(rig: &Rig) -> FleetCapabilityAdminClient<Channel> {
    FleetCapabilityAdminClient::new(
        Endpoint::from_shared(format!("http://{}", rig.addr))
            .unwrap()
            .connect_lazy(),
    )
}

fn bearer<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

async fn make_user(rig: &Rig, name: &str, admin: bool) -> (u64, String) {
    let id = run(&rig.pool, &AdminCommand::CreateUser(name.into()), "op")
        .await
        .unwrap()
        .user_id;
    if admin {
        rig.users.set_admin(id, true).await.unwrap();
    }
    let token = rig.users.create_api_token(id, "t").await.unwrap();
    (
        u64::try_from(id).unwrap(),
        String::from_utf8(token.token.expose().to_vec()).unwrap(),
    )
}

fn grant(user_id: u64, capability: &str) -> GrantCapabilityRequest {
    GrantCapabilityRequest {
        user_id,
        capability: capability.to_owned(),
    }
}

async fn stored(rig: &Rig) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM user_capabilities")
        .fetch_one(&rig.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn grant_list_revoke_cycle_echoes_only_the_target(pool: PgPool) {
    let rig = start(pool).await;
    let (root, token) = make_user(&rig, "root", true).await;
    let (alice, _) = make_user(&rig, "alice", false).await;
    let (bob, _) = make_user(&rig, "bob", false).await;
    let mut caps = client(&rig);

    let echoed: UserCapability = caps
        .grant_capability(bearer(grant(alice, PROFILE_TOOLS), &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            echoed.user_id,
            echoed.capability.as_str(),
            echoed.granted_by
        ),
        (alice, PROFILE_TOOLS, root)
    );
    assert!(echoed.granted_at_ms > 0);
    let other = caps
        .grant_capability(bearer(grant(bob, PROFILE_TOOLS), &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(other.user_id, bob);

    let again = caps
        .grant_capability(bearer(grant(alice, PROFILE_TOOLS), &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again, echoed);

    let listed = caps
        .list_capabilities(bearer(ListCapabilitiesRequest { user_id: alice }, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.capabilities, vec![echoed]);

    let removed = caps
        .revoke_capability(bearer(
            RevokeCapabilityRequest {
                user_id: alice,
                capability: PROFILE_TOOLS.to_owned(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(removed.removed);
    let removed = caps
        .revoke_capability(bearer(
            RevokeCapabilityRequest {
                user_id: alice,
                capability: PROFILE_TOOLS.to_owned(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!removed.removed);
    assert_eq!(stored(&rig).await, 1);
    let listed = caps
        .list_capabilities(bearer(ListCapabilitiesRequest { user_id: bob }, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.capabilities, vec![other]);
}

#[sqlx::test(migrations = false)]
async fn an_unknown_target_is_not_found_with_a_fixed_message(pool: PgPool) {
    let rig = start(pool).await;
    let (_, token) = make_user(&rig, "root", true).await;
    let mut caps = client(&rig);
    let err = caps
        .grant_capability(bearer(grant(9_999, PROFILE_TOOLS), &token))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::NotFound, REASON_NO_SUCH_USER)
    );
    let err = caps
        .list_capabilities(bearer(ListCapabilitiesRequest { user_id: 9_999 }, &token))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::NotFound, REASON_NO_SUCH_USER)
    );
    assert_eq!(stored(&rig).await, 0);
}

#[sqlx::test(migrations = false)]
async fn bad_capability_and_out_of_range_user_are_invalid_argument(pool: PgPool) {
    let rig = start(pool).await;
    let (_, token) = make_user(&rig, "root", true).await;
    let (alice, _) = make_user(&rig, "alice", false).await;
    let mut caps = client(&rig);
    let err = caps
        .grant_capability(bearer(grant(alice, "admin"), &token))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::InvalidArgument, REASON_UNKNOWN_CAPABILITY)
    );
    let err = caps
        .revoke_capability(bearer(
            RevokeCapabilityRequest {
                user_id: alice,
                capability: "admin".to_owned(),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    for huge in [u64::MAX, u64::try_from(i64::MAX).unwrap() + 1] {
        let err = caps
            .grant_capability(bearer(grant(huge, PROFILE_TOOLS), &token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{huge}");
    }
    assert_eq!(stored(&rig).await, 0);
}

#[sqlx::test(migrations = false)]
async fn a_non_admin_token_changes_nothing(pool: PgPool) {
    let rig = start(pool).await;
    let (alice, plain) = make_user(&rig, "alice", false).await;
    let mut caps = client(&rig);
    let err = caps
        .grant_capability(bearer(grant(alice, PROFILE_TOOLS), &plain))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::PermissionDenied, ADMIN_REQUIRED)
    );
    assert_eq!(stored(&rig).await, 0);
}

#[sqlx::test(migrations = false)]
async fn a_stale_admin_caller_is_refused_after_a_demotion_in_flight(pool: PgPool) {
    let rig = start(pool.clone()).await;
    let (root, _) = make_user(&rig, "root", true).await;
    let (alice, _) = make_user(&rig, "alice", false).await;
    let svc = FleetService::new(Store::new(pool.clone()));
    let stale = Caller {
        user_id: i64::try_from(root).unwrap(),
        is_admin: true,
    };
    let mut demotion = pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
        .bind(stale.user_id)
        .execute(&mut *demotion)
        .await
        .unwrap();
    let mut request = Request::new(grant(alice, PROFILE_TOOLS));
    request.extensions_mut().insert(stale);
    let mut task = tokio::spawn(async move { svc.grant_capability(request).await });
    assert!(tokio::time::timeout(BAND, &mut task).await.is_err());
    demotion.commit().await.unwrap();
    let err = tokio::time::timeout(OUTER, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (Code::PermissionDenied, ADMIN_REQUIRED)
    );
    assert_eq!(stored(&rig).await, 0);
}

#[sqlx::test(migrations = false)]
async fn the_actor_is_the_caller_never_a_request_field(pool: PgPool) {
    let rig = start(pool.clone()).await;
    let (root, _) = make_user(&rig, "root", true).await;
    let (alice, _) = make_user(&rig, "alice", false).await;
    let svc = FleetService::new(Store::new(pool));
    let mut request = Request::new(grant(alice, PROFILE_TOOLS));
    request.extensions_mut().insert(Caller {
        user_id: i64::try_from(alice).unwrap(),
        is_admin: true,
    });
    let err = svc.grant_capability(request).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let mut request = Request::new(grant(alice, PROFILE_TOOLS));
    request.extensions_mut().insert(Caller {
        user_id: i64::try_from(root).unwrap(),
        is_admin: true,
    });
    let echoed = svc.grant_capability(request).await.unwrap().into_inner();
    assert_eq!(echoed.granted_by, root);
}
