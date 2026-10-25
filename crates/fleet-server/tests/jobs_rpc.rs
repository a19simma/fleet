//! `FleetJobs` over a real tonic server on a loopback port. The tests need a Postgres
//! superuser URL in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database
//! per test. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_core::BoxName;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, JobState, ListJobsRequest, ReadTranscriptRequest,
    ReportJobRequest, SubmitJobRequest, TranscriptChunk,
};
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

const TOKEN: &str = "test-token-0123456789abcdef0123456789";
const WAIT: Duration = Duration::from_secs(30);

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;

fn boxed(n: u32) -> BoxName {
    BoxName::new(&box_name(n)).unwrap()
}

fn box_name(n: u32) -> String {
    format!("box-{n}")
}
type Jobs = FleetJobsClient<InterceptedService<Channel, Interceptor>>;

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

fn spawn(store: &Store) -> Jobs {
    let auth = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        Some(&Token::new(TOKEN.to_owned()).unwrap()),
    );
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(router(store, &auth).serve_with_incoming(incoming));
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let interceptor: Interceptor = bearer;
    FleetJobsClient::with_interceptor(channel, interceptor)
}

fn submit_request(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: "https://example.com/org/repo.git".to_owned(),
        base_ref: "main".to_owned(),
        open_pr: true,
    }
}

fn get(job_id: &str) -> GetJobRequest {
    GetJobRequest {
        job_id: job_id.to_owned(),
    }
}

fn cancel(job_id: &str) -> CancelJobRequest {
    CancelJobRequest {
        job_id: job_id.to_owned(),
    }
}

fn read(job_id: &str, after_seq: u64, limit: u32) -> ReadTranscriptRequest {
    ReadTranscriptRequest {
        job_id: job_id.to_owned(),
        after_seq,
        limit,
    }
}

fn chunk(seq: u64) -> TranscriptChunk {
    TranscriptChunk {
        seq,
        ts_ms: 1_000 + seq,
        text: format!("line {seq}"),
        truncated: false,
    }
}

fn report(job_id: &str, chunks: Vec<TranscriptChunk>, end: bool) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job_id.to_owned(),
        attempt: 1,
        r#box: box_name(1),
        phase: "running".to_owned(),
        progress: "working".to_owned(),
        terminal_state: end.then_some(JobState::Succeeded as i32),
        chunks,
        ..ReportJobRequest::default()
    }
}

#[sqlx::test]
async fn submit_get_list(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);

    let first = timeout(WAIT, jobs.submit_job(submit_request("k1")))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(first.state(), JobState::Queued);
    assert_eq!(first.prompt, "add hello.txt");
    assert_eq!(
        first.branch.as_deref(),
        Some(format!("swarm/{}", first.job_id).as_str())
    );

    let again = jobs
        .submit_job(submit_request("k1"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.job_id, first.job_id);

    let second = jobs
        .submit_job(submit_request("k2"))
        .await
        .unwrap()
        .into_inner();
    let third = jobs
        .submit_job(submit_request("k3"))
        .await
        .unwrap()
        .into_inner();

    let fetched = jobs.get_job(get(&first.job_id)).await.unwrap().into_inner();
    assert_eq!(fetched, first);

    let all = jobs
        .list_jobs(ListJobsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .jobs;
    let ids: Vec<_> = all.iter().map(|job| job.job_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            third.job_id.as_str(),
            second.job_id.as_str(),
            first.job_id.as_str()
        ]
    );

    let limited = jobs
        .list_jobs(ListJobsRequest {
            state: None,
            limit: 2,
        })
        .await
        .unwrap()
        .into_inner()
        .jobs;
    assert_eq!(limited.len(), 2);

    store.claim_job(&boxed(1)).await.unwrap().unwrap();
    let running = jobs
        .list_jobs(ListJobsRequest {
            state: Some(JobState::Running as i32),
            limit: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .jobs;
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].job_id, first.job_id);
    let queued = jobs
        .list_jobs(ListJobsRequest {
            state: Some(JobState::Queued as i32),
            limit: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .jobs;
    assert_eq!(queued.len(), 2);
}

#[sqlx::test]
async fn errors_map_to_fixed_statuses(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut jobs = spawn(&store);
    let first = jobs
        .submit_job(submit_request("k1"))
        .await
        .unwrap()
        .into_inner();

    let mut other = submit_request("k1");
    other.prompt = "secret-prompt-text".to_owned();
    let conflict = jobs.submit_job(other).await.unwrap_err();
    assert_eq!(conflict.code(), Code::AlreadyExists);
    assert!(!conflict.message().contains("secret-prompt-text"));

    let missing = jobs.get_job(get("01ARZ3NDEKTSV4RRFFQ69G5FAV")).await;
    assert_eq!(missing.unwrap_err().code(), Code::NotFound);

    let bad_id = jobs.get_job(get("bad id\u{0}")).await.unwrap_err();
    assert_eq!(bad_id.code(), Code::InvalidArgument);
    assert!(!bad_id.message().contains("bad id"));
    let empty = jobs.get_job(get("")).await.unwrap_err();
    assert_eq!(empty.code(), Code::InvalidArgument);
    let long = jobs.get_job(get(&"a".repeat(65))).await.unwrap_err();
    assert_eq!(long.code(), Code::InvalidArgument);

    let mut dash = submit_request("k2");
    dash.base_ref = "--upload-pack=x".to_owned();
    let dash = jobs.submit_job(dash).await.unwrap_err();
    assert_eq!(dash.code(), Code::InvalidArgument);
    assert!(!dash.message().contains("upload-pack"));

    let mut no_prompt = submit_request("k3");
    no_prompt.prompt = String::new();
    let no_prompt = jobs.submit_job(no_prompt).await.unwrap_err();
    assert_eq!(no_prompt.code(), Code::InvalidArgument);

    for state in [0, 99] {
        let bad_state = jobs
            .list_jobs(ListJobsRequest {
                state: Some(state),
                limit: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(bad_state.code(), Code::InvalidArgument);
    }

    assert_eq!(
        jobs.cancel_job(cancel("")).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        jobs.read_transcript(read("", 0, 0))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        jobs.read_transcript(read("01ARZ3NDEKTSV4RRFFQ69G5FAV", 0, 0))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );

    pool.close().await;
    let down = jobs.get_job(get(&first.job_id)).await.unwrap_err();
    assert_eq!(down.code(), Code::Unavailable);
    assert_eq!(down.message(), "storage unavailable");
}

#[sqlx::test]
async fn cancel_queued_and_running(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let queued = jobs
        .submit_job(submit_request("k1"))
        .await
        .unwrap()
        .into_inner();
    let running = jobs
        .submit_job(submit_request("k2"))
        .await
        .unwrap()
        .into_inner();

    let cancelled = timeout(WAIT, jobs.cancel_job(cancel(&queued.job_id)))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(cancelled.state(), JobState::Cancelled);
    assert!(cancelled.finished_at_ms.is_some());

    let claimed = store.claim_job(&boxed(1)).await.unwrap().unwrap();
    assert_eq!(claimed.job_id, running.job_id);
    let flagged = jobs
        .cancel_job(cancel(&running.job_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(flagged.state(), JobState::Running);
    assert!(flagged.cancel_requested);

    let repeat = jobs
        .cancel_job(cancel(&queued.job_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(repeat.state(), JobState::Cancelled);

    let missing = jobs.cancel_job(cancel("01ARZ3NDEKTSV4RRFFQ69G5FAV")).await;
    assert_eq!(missing.unwrap_err().code(), Code::NotFound);
}

#[sqlx::test]
async fn read_transcript_pages_and_done(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let job = jobs
        .submit_job(submit_request("k1"))
        .await
        .unwrap()
        .into_inner();
    store.claim_job(&boxed(1)).await.unwrap().unwrap();

    let empty = timeout(WAIT, jobs.read_transcript(read(&job.job_id, 0, 0)))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(empty.chunks, Vec::<TranscriptChunk>::new());
    assert!(!empty.done);

    store
        .report_job(
            &boxed(1),
            &report(&job.job_id, vec![chunk(1), chunk(2), chunk(3)], false),
        )
        .await
        .unwrap();

    let page = jobs
        .read_transcript(read(&job.job_id, 0, 2))
        .await
        .unwrap()
        .into_inner();
    let seqs: Vec<_> = page.chunks.iter().map(|c| c.seq).collect();
    assert_eq!(seqs, [1, 2]);
    assert_eq!(page.chunks[0].text, "line 1");
    assert_eq!(page.chunks[0].ts_ms, 1_001);
    assert!(!page.done);

    let rest = jobs
        .read_transcript(read(&job.job_id, 2, 0))
        .await
        .unwrap()
        .into_inner();
    let seqs: Vec<_> = rest.chunks.iter().map(|c| c.seq).collect();
    assert_eq!(seqs, [3]);
    assert!(!rest.done);

    store
        .report_job(&boxed(1), &report(&job.job_id, Vec::new(), true))
        .await
        .unwrap();

    let last_page = jobs
        .read_transcript(read(&job.job_id, 0, 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(last_page.chunks.len(), 2);
    assert!(!last_page.done);

    let tail = jobs
        .read_transcript(read(&job.job_id, 1, 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(tail.chunks.len(), 2);
    assert!(tail.done);

    let past = jobs
        .read_transcript(read(&job.job_id, 3, 0))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(past.chunks, Vec::<TranscriptChunk>::new());
    assert!(past.done);
}

#[sqlx::test]
async fn list_limit_is_capped(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    for n in 0..201 {
        store
            .submit_job(&submit_request(&format!("k{n}")))
            .await
            .unwrap();
    }
    let capped = jobs
        .list_jobs(ListJobsRequest {
            state: None,
            limit: 1000,
        })
        .await
        .unwrap()
        .into_inner()
        .jobs;
    assert_eq!(capped.len(), 200);
    let default = jobs
        .list_jobs(ListJobsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .jobs;
    assert_eq!(default.len(), 50);
}
