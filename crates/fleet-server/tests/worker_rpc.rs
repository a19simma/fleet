//! `FleetWorker` over a real tonic server on a loopback port. The tests need a Postgres
//! superuser URL in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database
//! per test. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, JobState, ReportJobRequest, SubmitJobRequest, TranscriptChunk,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::{CLAIM_INTERVAL_S, router};
use fleet_server::store::Store;
use sqlx::PgPool;
use tokio::time::timeout;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const TOKEN: &str = "test-token-0123456789abcdef0123456789";
const WAIT: Duration = Duration::from_secs(30);

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Worker = FleetWorkerClient<InterceptedService<Channel, Interceptor>>;

fn box_name(n: u32) -> String {
    format!("box-{n}")
}

fn bearer(mut request: Request<()>) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {TOKEN}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

fn spawn(store: &Store) -> Worker {
    let auth = BearerAuth::new(&Token::new(TOKEN.to_owned()).unwrap());
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(router(store, &auth).serve_with_incoming(incoming));
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let interceptor: Interceptor = bearer;
    FleetWorkerClient::with_interceptor(channel, interceptor)
}

async fn submit(store: &Store, key: &str) {
    store
        .submit_job(&SubmitJobRequest {
            idempotency_key: key.to_owned(),
            prompt: "add hello.txt".to_owned(),
            repo: "https://example.com/org/repo.git".to_owned(),
            base_ref: "main".to_owned(),
            open_pr: true,
        })
        .await
        .unwrap();
}

fn claim(name: &str) -> ClaimJobRequest {
    ClaimJobRequest {
        r#box: name.to_owned(),
    }
}

fn report(job_id: &str, attempt: u32, name: &str) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job_id.to_owned(),
        attempt,
        r#box: name.to_owned(),
        phase: "running".to_owned(),
        progress: "working".to_owned(),
        ..ReportJobRequest::default()
    }
}

async fn state_and_box(pool: &PgPool) -> (String, Option<String>) {
    sqlx::query_as("SELECT state, box FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn claim_then_report(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    let name = box_name(1);

    let empty = timeout(WAIT, worker.claim_job(claim(&name)))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert!(empty.job.is_none());
    assert_eq!(empty.next_in_s, CLAIM_INTERVAL_S);

    submit(&store, "k1").await;
    let claimed = timeout(WAIT, worker.claim_job(claim(&name)))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    let job = claimed.job.unwrap();
    assert_eq!(job.state(), JobState::Running);
    assert_eq!(job.r#box, name);
    assert_eq!(job.attempt, 1);
    assert_eq!(u64::from(claimed.lease_s), store.lease().as_secs());

    let mut progress = report(&job.job_id, job.attempt, &name);
    progress.chunks = vec![TranscriptChunk {
        seq: 1,
        ts_ms: 1,
        text: "hello".to_owned(),
        truncated: false,
    }];
    let reply = timeout(WAIT, worker.report_job(progress))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(reply.acked_through_seq, 1);
    assert!(!reply.cancel_requested);
    assert!(reply.lease_expires_at_ms > 0);
    assert_eq!(state_and_box(&pool).await.0, "RUNNING");

    let mut done = report(&job.job_id, job.attempt, &name);
    done.terminal_state = Some(JobState::Succeeded.into());
    done.pr_url = Some("https://example.com/org/repo/pull/1".to_owned());
    done.exit_code = Some(0);
    timeout(WAIT, worker.report_job(done))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        state_and_box(&pool).await,
        ("SUCCEEDED".to_owned(), Some(name))
    );

    let after = timeout(WAIT, worker.claim_job(claim(&box_name(1))))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert!(after.job.is_none());
}

#[sqlx::test]
async fn stale_attempt_is_failed_precondition(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    submit(&store, "k1").await;
    let name = box_name(1);
    let job = worker
        .claim_job(claim(&name))
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    let status = worker
        .report_job(report(&job.job_id, job.attempt + 1, &name))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "report does not match the running job");
    let missing = worker
        .report_job(report("no-such-job", 1, &name))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn another_box_cannot_report_or_claim_for_the_holder(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    submit(&store, "k1").await;
    let holder = box_name(1);
    let other = box_name(2);
    let job = worker
        .claim_job(claim(&holder))
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    assert_eq!(job.r#box, holder);

    let mut hijack = report(&job.job_id, job.attempt, &other);
    hijack.terminal_state = Some(JobState::Failed.into());
    let status = worker.report_job(hijack).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        state_and_box(&pool).await,
        ("RUNNING".to_owned(), Some(holder))
    );

    let none = worker.claim_job(claim(&other)).await.unwrap().into_inner();
    assert!(none.job.is_none());
}

#[sqlx::test]
async fn invalid_box_is_invalid_argument_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    submit(&store, "k1").await;
    let secret = "not-a-box-SECRET-marker";
    let padded = format!(" {}", box_name(1));
    let upper = box_name(1).to_uppercase();
    for raw in [secret, "", padded.as_str(), upper.as_str()] {
        let claim_status = worker.claim_job(claim(raw)).await.unwrap_err();
        assert_eq!(claim_status.code(), Code::InvalidArgument, "{raw:?}");
        assert!(!claim_status.message().contains("SECRET"));
        let report_status = worker.report_job(report("j", 1, raw)).await.unwrap_err();
        assert_eq!(report_status.code(), Code::InvalidArgument, "{raw:?}");
        assert!(!report_status.message().contains("SECRET"));
    }
    assert_eq!(
        state_and_box(&pool).await,
        ("QUEUED".to_owned(), Some(String::new()))
    );
}

#[sqlx::test]
async fn invalid_chunk_is_invalid_argument(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    submit(&store, "k1").await;
    let name = box_name(1);
    let job = worker
        .claim_job(claim(&name))
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    let mut bad = report(&job.job_id, job.attempt, &name);
    bad.chunks = vec![TranscriptChunk {
        seq: 1,
        ts_ms: 1,
        text: "bad\0text".to_owned(),
        truncated: false,
    }];
    let status = worker.report_job(bad).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "invalid transcript chunk");
}

#[sqlx::test]
async fn invalid_terminal_state_is_invalid_argument(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    submit(&store, "k1").await;
    let name = box_name(1);
    let job = worker
        .claim_job(claim(&name))
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    let mut bad = report(&job.job_id, job.attempt, &name);
    bad.terminal_state = Some(JobState::Queued.into());
    let status = worker.report_job(bad).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "invalid job report");
    assert_eq!(state_and_box(&pool).await.0, "RUNNING");
}

#[sqlx::test]
async fn database_failure_is_unavailable_with_a_fixed_message(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = spawn(&store);
    pool.close().await;
    let status = worker.claim_job(claim(&box_name(1))).await.unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), "storage unavailable");
    let status = worker
        .report_job(report("j", 1, &box_name(1)))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), "storage unavailable");
}
