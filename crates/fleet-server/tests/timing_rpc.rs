//! `ReportTiming` and `GetJobTiming` over a real tonic server on a loopback port. Each
//! answers `PERMISSION_DENIED` for the other scope's token. `ReportTiming` refuses a report
//! with no matching lease, and `GetJobTiming` is still `UNIMPLEMENTED`.
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{GetJobTimingRequest, ReportTimingRequest};
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

fn channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

fn worker(
    addr: SocketAddr,
    i: Interceptor,
) -> FleetWorkerClient<InterceptedService<Channel, Interceptor>> {
    FleetWorkerClient::with_interceptor(channel(addr), i)
}

fn jobs(
    addr: SocketAddr,
    i: Interceptor,
) -> FleetJobsClient<InterceptedService<Channel, Interceptor>> {
    FleetJobsClient::with_interceptor(channel(addr), i)
}

async fn start(pool: PgPool) -> SocketAddr {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    serve(&store)
}

#[sqlx::test]
async fn report_timing_with_the_box_token_reaches_the_lease_check_and_refuses_a_default_request(
    pool: PgPool,
) {
    let addr = start(pool).await;
    let err = worker(addr, as_box)
        .report_timing(ReportTimingRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn get_job_timing_is_unimplemented_for_the_client_token(pool: PgPool) {
    let addr = start(pool).await;
    let err = jobs(addr, as_client)
        .get_job_timing(GetJobTimingRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unimplemented);
}

#[sqlx::test]
async fn the_client_token_cannot_report_timing(pool: PgPool) {
    let addr = start(pool).await;
    let err = worker(addr, as_client)
        .report_timing(ReportTimingRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[sqlx::test]
async fn the_box_token_cannot_read_timing(pool: PgPool) {
    let addr = start(pool).await;
    let err = jobs(addr, as_box)
        .get_job_timing(GetJobTimingRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}
