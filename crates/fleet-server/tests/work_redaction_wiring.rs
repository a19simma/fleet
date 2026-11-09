//! Stored work evidence is masked by the redactor that `router` wires from its `BearerAuth`:
//! the test goes through the real constructor path over a loopback gRPC server. It needs a
//! Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_work_client::FleetWorkClient;
use fleet_proto::v1::{
    AddWorkItemRequest, ClaimWorkRequest, CreateWorkProjectRequest, ReportAttemptRequest,
    SetWorkSlicesRequest, WorkSlice, WorkVerdict,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;
use tonic::transport::server::TcpIncoming;

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";

fn authed<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

#[sqlx::test]
async fn router_masks_box_and_client_tokens_in_stored_evidence(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let user_id: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let users = Users::new(pool.clone());
    let made = users.create_api_token(user_id, "t").await.unwrap();
    let api = String::from_utf8(made.token.expose().to_vec()).unwrap();
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users);
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let mut client = FleetWorkClient::new(channel);

    client
        .create_work_project(authed(
            &api,
            CreateWorkProjectRequest {
                key: "k".into(),
                name: "p".into(),
                repo: None,
            },
        ))
        .await
        .unwrap();
    client
        .set_work_slices(authed(
            &api,
            SetWorkSlicesRequest {
                key: "s".into(),
                project: "p".into(),
                slices: vec![WorkSlice {
                    name: "a".into(),
                    paths: vec!["src/a".into()],
                }],
                mergeable: Vec::new(),
            },
        ))
        .await
        .unwrap();
    client
        .add_work_item(authed(
            &api,
            AddWorkItemRequest {
                key: "i".into(),
                project: "p".into(),
                item_key: "w1".into(),
                title: "t".into(),
                body: String::new(),
                slices: vec!["a".into()],
                deps: Vec::new(),
            },
        ))
        .await
        .unwrap();
    let attempt = client
        .claim_work(authed(
            &api,
            ClaimWorkRequest {
                key: "c".into(),
                project: "p".into(),
                item_key: "w1".into(),
                holder: "worker-1".into(),
                ttl_secs: 0,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    client
        .report_attempt(authed(
            &api,
            ReportAttemptRequest {
                key: "r".into(),
                project: "p".into(),
                attempt_id: attempt.id,
                verdict: WorkVerdict::Pass as i32,
                note: "done".into(),
                evidence_tail: format!("client={CLIENT} box={BOX} tail"),
            },
        ))
        .await
        .unwrap();

    let stored: String = sqlx::query_scalar("SELECT evidence FROM work_attempt WHERE id = $1")
        .bind(i64::try_from(attempt.id).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(stored.contains("tail"), "{stored}");
    assert!(!stored.contains(CLIENT), "{stored}");
    assert!(!stored.contains(BOX), "{stored}");
}
