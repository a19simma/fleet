//! `FleetJobs` over a real tonic server on a loopback port. The tests need a Postgres
//! superuser URL in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database
//! per test. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_core::BoxName;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, GetStatsRequest, JobEvent, JobEventKind, JobState, JobSummary,
    ListJobsRequest, ReadJobEventsRequest, ReadTranscriptRequest, ReportJobRequest,
    SubmitJobRequest, TranscriptChunk,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
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
        agent: String::new(),
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

fn events_request(job_id: &str, after_seq: Option<u32>, limit: u32) -> ReadJobEventsRequest {
    ReadJobEventsRequest {
        job_id: job_id.to_owned(),
        after_seq,
        limit,
    }
}

fn tool_event(seq: u32) -> JobEvent {
    JobEvent {
        seq,
        ts_ms: 5_000 + u64::from(seq),
        kind: JobEventKind::Tool.into(),
        ..JobEvent::default()
    }
}

async fn send_events(store: &Store, job_id: &str, seqs: std::ops::Range<u32>) {
    for start in seqs.clone().step_by(200) {
        let end = (start + 200).min(seqs.end);
        let mut request = report(job_id, Vec::new(), false);
        request.events = (start..end).map(tool_event).collect();
        store.report_job(&boxed(1), &request).await.unwrap();
    }
}

async fn running_job(store: &Store, jobs: &mut Jobs) -> String {
    let job = jobs
        .submit_job(submit_request("k1"))
        .await
        .unwrap()
        .into_inner();
    store.claim_job(&boxed(1)).await.unwrap().unwrap();
    job.job_id
}

fn seqs(events: &[JobEvent]) -> Vec<u32> {
    events.iter().map(|event| event.seq).collect()
}

#[sqlx::test]
async fn read_job_events_pages_by_keyset(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let id = running_job(&store, &mut jobs).await;

    let none = timeout(WAIT, jobs.read_job_events(events_request(&id, None, 0)))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&none.events), Vec::<u32>::new());
    assert_eq!(none.next_seq, 0);

    send_events(&store, &id, 0..5).await;

    let first = jobs
        .read_job_events(events_request(&id, None, 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&first.events), [0, 1]);
    assert_eq!(first.next_seq, 1);

    let second = jobs
        .read_job_events(events_request(&id, Some(first.next_seq), 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&second.events), [2, 3]);
    assert_eq!(second.next_seq, 3);

    let third = jobs
        .read_job_events(events_request(&id, Some(3), 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&third.events), [4]);
    assert_eq!(third.next_seq, 4);

    let at_end = jobs
        .read_job_events(events_request(&id, Some(4), 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&at_end.events), Vec::<u32>::new());
    assert_eq!(at_end.next_seq, 4);

    let past = jobs
        .read_job_events(events_request(&id, Some(99), 0))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&past.events), Vec::<u32>::new());
    assert_eq!(past.next_seq, 99);

    let zero = jobs
        .read_job_events(events_request(&id, Some(0), 0))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seqs(&zero.events), [1, 2, 3, 4]);
}

#[sqlx::test]
async fn read_job_events_clamps_the_limit(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let id = running_job(&store, &mut jobs).await;
    send_events(&store, &id, 0..1_100).await;

    let default = jobs
        .read_job_events(events_request(&id, None, 0))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(default.events.len(), 200);
    assert_eq!(default.next_seq, 199);

    let one = jobs
        .read_job_events(events_request(&id, None, 1))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(one.events.len(), 1);

    let exact = jobs
        .read_job_events(events_request(&id, None, 1_000))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exact.events.len(), 1_000);
    assert_eq!(exact.next_seq, 999);

    let clamped = jobs
        .read_job_events(events_request(&id, None, 5_000))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(clamped.events.len(), 1_000);
    assert_eq!(clamped.next_seq, 999);

    let rest = jobs
        .read_job_events(events_request(&id, Some(999), 5_000))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rest.events.len(), 100);
    assert_eq!(rest.next_seq, 1_099);
}

#[sqlx::test]
async fn read_job_events_returns_every_field(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let id = running_job(&store, &mut jobs).await;
    let full = JobEvent {
        seq: 7,
        ts_ms: 1_234,
        kind: JobEventKind::Tool.into(),
        tool_use_id: Some("tu1".to_owned()),
        tool: Some("Bash".to_owned()),
        ok: Some(false),
        exit_code: Some(-2),
        dur_ms: Some(31),
        out_bytes: Some(4_096),
        out_hash: Some("ab12".to_owned()),
        cmd: Some("ls -la".to_owned()),
        detail: Some("note".to_owned()),
    };
    let kinds = [
        JobEventKind::Denial,
        JobEventKind::ApiRetry,
        JobEventKind::Phase,
        JobEventKind::Stuck,
    ];
    let mut request = report(&id, Vec::new(), false);
    request.events = vec![full.clone()];
    request
        .events
        .extend(kinds.iter().enumerate().map(|(i, kind)| JobEvent {
            seq: 8 + u32::try_from(i).unwrap(),
            kind: (*kind).into(),
            ..JobEvent::default()
        }));
    store.report_job(&boxed(1), &request).await.unwrap();

    let reply = jobs
        .read_job_events(events_request(&id, None, 0))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.events[0], full);
    let got: Vec<_> = reply.events[1..].iter().map(JobEvent::kind).collect();
    assert_eq!(got, kinds);
    assert_eq!(reply.events[1].tool, None);
    assert_eq!(reply.events[1].ok, None);
    assert_eq!(reply.events[1].dur_ms, None);
}

#[sqlx::test]
async fn read_job_events_rejects_unknown_and_invalid_jobs(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut jobs = spawn(&store);
    let id = running_job(&store, &mut jobs).await;

    let missing = jobs
        .read_job_events(events_request("01ARZ3NDEKTSV4RRFFQ69G5FAV", None, 0))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);
    let empty = jobs
        .read_job_events(events_request("", None, 0))
        .await
        .unwrap_err();
    assert_eq!(empty.code(), Code::InvalidArgument);
    let bad = jobs
        .read_job_events(events_request("bad id\u{0}", None, 0))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), Code::InvalidArgument);
    assert!(!bad.message().contains("bad id"));

    pool.close().await;
    let down = jobs
        .read_job_events(events_request(&id, None, 0))
        .await
        .unwrap_err();
    assert_eq!(down.code(), Code::Unavailable);
    assert_eq!(down.message(), "storage unavailable");
}

#[sqlx::test]
async fn get_stats_over_the_wire_counts_jobs_and_maps_errors(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut jobs = spawn(&store);
    running_job(&store, &mut jobs).await;

    let reply = jobs
        .get_stats(GetStatsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.groups.len(), 1);
    assert_eq!(reply.groups[0].jobs, 1);
    assert_eq!(reply.groups[0].other, 1);
    assert!(reply.groups[0].duration_ms.is_none());

    let bad = jobs
        .get_stats(GetStatsRequest {
            repo: Some("bad\u{0}repo".to_owned()),
            ..GetStatsRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(bad.code(), Code::InvalidArgument);
    assert!(!bad.message().contains("bad"));

    pool.close().await;
    let down = jobs
        .get_stats(GetStatsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(down.code(), Code::Unavailable);
    assert_eq!(down.message(), "storage unavailable");
}

#[sqlx::test]
async fn get_job_carries_the_summary_only_when_stored(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let id = running_job(&store, &mut jobs).await;

    let before = jobs.get_job(get(&id)).await.unwrap().into_inner();
    assert_eq!(before.summary, None);

    let summary = JobSummary {
        turns: Some(1),
        duration_ms: Some(2),
        duration_api_ms: Some(3),
        stop_reason: Some("end_turn".to_owned()),
        result_subtype: Some("success".to_owned()),
        cost_est_usd: Some(0.25),
        tokens_in: Some(4),
        tokens_out: Some(5),
        tokens_cache_read: Some(6),
        tokens_cache_write: Some(7),
        tool_calls: Some(8),
        tool_errors: Some(9),
        bash_calls: Some(10),
        bash_nonzero: Some(11),
        denials: Some(12),
        api_retries: Some(13),
        first_edit_ms: Some(0),
        complete: true,
        missing: vec!["a".to_owned(), "b".to_owned()],
        stuck_rule: Some("monologue".to_owned()),
        stuck_at_seq: Some(14),
        stuck_at_ms: Some(15),
        bundle_sha: Some("b".repeat(64)),
        claude_version: Some("2.1.289 (Claude Code)".to_owned()),
        model: None,
        clone_ms: Some(16),
        push_ms: Some(17),
        pr_ms: None,
        queue_wait_ms: None,
    };
    let mut request = report(&id, Vec::new(), false);
    request.summary = Some(summary.clone());
    store.report_job(&boxed(1), &request).await.unwrap();

    let after = jobs.get_job(get(&id)).await.unwrap().into_inner();
    let stored = after.summary.unwrap();
    assert!(stored.queue_wait_ms.is_some());
    assert_eq!(
        stored,
        JobSummary {
            queue_wait_ms: stored.queue_wait_ms,
            ..summary
        }
    );

    let sparse = JobSummary {
        turns: Some(2),
        complete: false,
        missing: vec!["cost_est_usd".to_owned()],
        ..JobSummary::default()
    };
    let mut request = report(&id, Vec::new(), false);
    request.summary = Some(sparse.clone());
    store.report_job(&boxed(1), &request).await.unwrap();
    let replaced = jobs.get_job(get(&id)).await.unwrap().into_inner();
    let replaced = replaced.summary.unwrap();
    assert!(replaced.queue_wait_ms.is_some());
    assert_eq!(
        replaced,
        JobSummary {
            queue_wait_ms: replaced.queue_wait_ms,
            ..sparse
        }
    );
    let listed = jobs
        .list_jobs(ListJobsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .jobs;
    assert_eq!(listed[0].summary, None);
}

#[sqlx::test]
async fn submit_records_the_authenticated_caller_and_the_client_token_is_bootstrap(pool: PgPool) {
    let store = store(pool.clone()).await;
    sqlx::query("ALTER TABLE jobs ALTER COLUMN user_id DROP DEFAULT")
        .execute(&pool)
        .await
        .unwrap();
    let alice: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let users = Users::new(pool.clone());
    let made = users.create_api_token(alice, "cli").await.unwrap();
    let api_token = String::from_utf8(made.token.expose().to_vec()).unwrap();
    let boot = users.bootstrap_user().await.unwrap();
    let auth = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        Some(&Token::new(TOKEN.to_owned()).unwrap()),
    )
    .with_users(users);
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let client_as = |token: String| {
        FleetJobsClient::with_interceptor(channel.clone(), move |mut request: Request<()>| {
            request.metadata_mut().insert(
                "authorization",
                MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
            );
            Ok::<_, Status>(request)
        })
    };

    let by_alice = client_as(api_token)
        .submit_job(submit_request("k1"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(i64::try_from(by_alice.user_id), Ok(alice));
    let by_client = client_as(TOKEN.to_owned())
        .submit_job(submit_request("k2"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(i64::try_from(by_client.user_id), Ok(boot));
}

#[sqlx::test]
async fn submit_validates_and_stores_the_agent(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut jobs = spawn(&store);
    for (key, agent, stored) in [
        ("k1", "", "claude"),
        ("k2", "claude", "claude"),
        ("k3", "codex", "codex"),
        ("k4", "kimi", "kimi"),
    ] {
        let mut request = submit_request(key);
        request.agent = agent.to_owned();
        let job = jobs.submit_job(request).await.unwrap().into_inner();
        assert_eq!(job.agent, stored, "{agent:?}");
    }
    for (n, bad) in ["Claude", " codex", "gpt", "kimi\0"]
        .into_iter()
        .enumerate()
    {
        let mut request = submit_request(&format!("bad{n}"));
        request.agent = bad.to_owned();
        let err = jobs.submit_job(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{bad:?}");
        assert_eq!(err.message(), "invalid job request");
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 4);
}

#[sqlx::test]
async fn a_key_resubmitted_with_another_agent_conflicts(pool: PgPool) {
    let store = store(pool).await;
    let mut jobs = spawn(&store);
    let mut first = submit_request("k1");
    first.agent = "codex".to_owned();
    jobs.submit_job(first).await.unwrap();
    let again = jobs.submit_job(submit_request("k1")).await.unwrap_err();
    assert_eq!(again.code(), Code::AlreadyExists);
}
