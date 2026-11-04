//! `ReportTiming` and `GetJobTiming` over a real tonic server on a loopback port. Each
//! answers `PERMISSION_DENIED` for the other scope's token. `ReportTiming` refuses a report
//! with no matching lease. `GetJobTiming` reads the caller's own job, answers one `NOT_FOUND`
//! for a foreign and an unknown job, and answers the absent state for a job with no report.
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_jobs_server::FleetJobs;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    GetJobTimingRequest, ReportTimingRequest, TimingSpan, TimingSpanKind, TimingSummary,
};
use fleet_server::auth::{BearerAuth, Caller};
use fleet_server::config::Token;
use fleet_server::service::{FleetService, router};
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const JOB: &str = "01JTIMINGRPC0000000000000A";
const STALE_MESSAGE: &str = "report does not match the running job";

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
async fn report_timing_validation_refuses_a_default_request(pool: PgPool) {
    let addr = start(pool).await;
    let err = worker(addr, as_box)
        .report_timing(ReportTimingRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn get_job_timing_without_a_user_identity_is_refused_for_a_valid_job(pool: PgPool) {
    let addr = start(pool.clone()).await;
    running_job(&pool).await;
    let err = jobs(addr, as_client)
        .get_job_timing(GetJobTimingRequest {
            job_id: JOB.to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "job timing needs a user token");
}

#[sqlx::test]
async fn an_over_cap_timing_reply_is_refused(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    owned_job(&pool, alice).await;
    sqlx::query(
        "INSERT INTO job_timing (job_id, wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, \
         overhead_ms) VALUES ($1, 5, 1, 1, 1, 1, 1)",
    )
    .bind(JOB)
    .execute(&pool)
    .await
    .unwrap();
    let request = |svc: FleetService| async move { read_as(&svc, alice, JOB).await };
    let small = FleetService::new(store.clone()).with_timing_reply_cap(1);
    let err = request(small).await.unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.message(), "job timing too large");
    let fits = request(FleetService::new(store)).await.unwrap();
    assert_eq!(fits.summary.unwrap().wall_ms, 5);
}

#[sqlx::test]
async fn a_worst_case_list_jobs_reply_is_not_capped_to_the_timing_limit(pool: PgPool) {
    let addr = start(pool.clone()).await;
    let prompt = "p".repeat(64 * 1024);
    let rows = fleet_server::service::MAX_JOB_TIMING_REPLY_BYTES / prompt.len() + 5;
    for n in 0..rows {
        sqlx::query(
            "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, attempt) \
             VALUES ($1, $2, 'r', 'main', 'b', false, 'QUEUED', 0)",
        )
        .bind(format!("01JBIG{n:020}"))
        .bind(&prompt)
        .execute(&pool)
        .await
        .unwrap();
    }
    let reply = jobs(addr, as_client)
        .max_decoding_message_size(64 * 1024 * 1024)
        .list_jobs(fleet_proto::v1::ListJobsRequest {
            limit: 200,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.jobs.len(), rows);
    assert!(
        tonic_prost::prost::Message::encoded_len(&reply)
            > fleet_server::service::MAX_JOB_TIMING_REPLY_BYTES
    );
}

fn as_user<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(Caller { user_id });
    request
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn owned_job(pool: &PgPool, owner: i64) {
    running_job(pool).await;
    sqlx::query("UPDATE jobs SET user_id = $1 WHERE job_id = $2")
        .bind(owner)
        .bind(JOB)
        .execute(pool)
        .await
        .unwrap();
}

async fn read_as(
    svc: &FleetService,
    user_id: i64,
    job_id: &str,
) -> Result<fleet_proto::v1::GetJobTimingReply, Status> {
    svc.get_job_timing(as_user(
        user_id,
        GetJobTimingRequest {
            job_id: job_id.to_owned(),
        },
    ))
    .await
    .map(tonic::Response::into_inner)
}

#[sqlx::test]
async fn the_owner_reads_rows_and_a_foreign_or_unknown_job_is_one_not_found(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    owned_job(&pool, alice).await;
    sqlx::query(
        "INSERT INTO job_timing (job_id, wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, \
         overhead_ms) VALUES ($1, 5, 1, 1, 1, 1, 1)",
    )
    .bind(JOB)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO job_timing_spans (job_id, seq, kind, start_ms, end_ms, name) \
         VALUES ($1, 0, 'tool', 0, 1, 'Read')",
    )
    .bind(JOB)
    .execute(&pool)
    .await
    .unwrap();
    let svc = FleetService::new(store);
    let own = read_as(&svc, alice, JOB).await.unwrap();
    assert_eq!(own.summary.unwrap().wall_ms, 5);
    assert_eq!(own.spans.len(), 1);
    let foreign = read_as(&svc, bob, JOB).await.unwrap_err();
    let unknown = read_as(&svc, alice, "01JTIMINGRPC0000000000000Z")
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(foreign.code(), unknown.code());
    assert_eq!(foreign.message(), unknown.message());
}

#[sqlx::test]
async fn a_job_with_no_report_reads_as_absent(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    owned_job(&pool, alice).await;
    let reply = read_as(&FleetService::new(store), alice, JOB)
        .await
        .unwrap();
    assert_eq!(reply.summary, None);
    assert!(reply.spans.is_empty() && reply.shell_commands.is_empty());
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

async fn running_job(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, attempt, \
         box, lease_expires_at, claimed_at) \
         VALUES ($1, 't', 'r', 'main', 'b', false, 'RUNNING', 1, $2, now() + interval '1 hour', \
         now() - interval '1 minute')",
    )
    .bind(JOB)
    .bind(holder())
    .execute(pool)
    .await
    .unwrap();
}

fn holder() -> String {
    format!("box-{}", 7)
}

fn report(job_id: &str, box_name: &str) -> ReportTimingRequest {
    ReportTimingRequest {
        job_id: job_id.to_owned(),
        attempt: 1,
        r#box: box_name.to_owned(),
        summary: Some(TimingSummary::default()),
        spans: Vec::new(),
        shell_commands: Vec::new(),
        agent_start_ms: 0,
        agent_end_ms: 0,
    }
}

async fn timing_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM job_timing")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn a_malformed_box_or_job_id_gets_the_fixed_refusal_and_stores_nothing(pool: PgPool) {
    running_job(&pool).await;
    let addr = start(pool.clone()).await;
    let long_box = "b".repeat(4096);
    let cases = [
        ("nul box", report(JOB, &format!("{}\0", holder()))),
        ("empty box", report(JOB, "")),
        ("over-long box", report(JOB, &long_box)),
        ("cr box", report(JOB, &format!("{}\r", holder()))),
        ("nel box", report(JOB, &format!("{}\u{85}", holder()))),
        (
            "line separator box",
            report(JOB, &format!("{}\u{2028}", holder())),
        ),
        (
            "nul job id",
            report("01JTIMINGRPC00000000\x0000A", &holder()),
        ),
    ];
    for (label, request) in cases {
        let err = worker(addr, as_box)
            .report_timing(request)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition, "{label}");
        assert_eq!(err.message(), STALE_MESSAGE, "{label}");
    }
    assert_eq!(timing_rows(&pool).await, 0);
}

#[sqlx::test]
async fn the_live_holder_still_persists_its_report(pool: PgPool) {
    running_job(&pool).await;
    let addr = start(pool.clone()).await;
    worker(addr, as_box)
        .report_timing(report(JOB, &holder()))
        .await
        .unwrap();
    assert_eq!(timing_rows(&pool).await, 1);
}

fn windowed_report() -> ReportTimingRequest {
    ReportTimingRequest {
        summary: Some(TimingSummary {
            wall_ms: 10_000,
            tool_ms: 1_000,
            idle_ms: 7_000,
            overhead_ms: 2_000,
            ..TimingSummary::default()
        }),
        spans: vec![TimingSpan {
            kind: TimingSpanKind::Tool as i32,
            start_ms: 2_000,
            end_ms: 3_000,
            name: "Read".to_owned(),
            tool_use_id: None,
        }],
        agent_start_ms: 1_000,
        agent_end_ms: 9_000,
        ..report(JOB, &holder())
    }
}

#[sqlx::test]
async fn each_agent_window_field_reaches_the_server_over_the_box_token_wire(pool: PgPool) {
    running_job(&pool).await;
    let addr = start(pool.clone()).await;
    let mismatch = "timing summary does not match its spans";
    let window = "timing agent window lies outside the job window";
    let rows = [
        (
            "start dropped",
            ReportTimingRequest {
                agent_start_ms: 0,
                ..windowed_report()
            },
            mismatch,
        ),
        (
            "end dropped",
            ReportTimingRequest {
                agent_end_ms: 0,
                ..windowed_report()
            },
            window,
        ),
        (
            "end moved",
            ReportTimingRequest {
                agent_end_ms: 8_999,
                ..windowed_report()
            },
            mismatch,
        ),
        (
            "end past wall",
            ReportTimingRequest {
                agent_end_ms: 10_001,
                ..windowed_report()
            },
            window,
        ),
        (
            "start after end",
            ReportTimingRequest {
                agent_start_ms: 9_001,
                ..windowed_report()
            },
            window,
        ),
    ];
    for (label, request, reason) in rows {
        let err = worker(addr, as_box)
            .report_timing(request)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{label}");
        assert_eq!(err.message(), reason, "{label}");
    }
    assert_eq!(timing_rows(&pool).await, 0);
    worker(addr, as_box)
        .report_timing(windowed_report())
        .await
        .unwrap();
    assert_eq!(timing_rows(&pool).await, 1);
}
