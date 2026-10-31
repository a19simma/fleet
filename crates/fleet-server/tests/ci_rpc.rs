//! The CI status a Job reports after its pull request opens: storage, the terminal rule, the
//! failure log, validation and retention. The tests need a Postgres superuser URL in
//! `DATABASE_URL`. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    CiState, ClaimJobRequest, Job, JobCi, JobState, ReportJobRequest, SubmitJobRequest,
    SubmitJudgeRequest, TranscriptChunk,
};
use fleet_proto::{MAX_CI_LOG_BYTES, MAX_CI_URL_BYTES};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::{PgPool, Row};
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const REPO: &str = "https://example.com/org/repo.git";

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Worker = FleetWorkerClient<InterceptedService<Channel, Interceptor>>;

fn as_box(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, BOX)
}

fn with_token(mut request: Request<()>, token: &str) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {token}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

fn name(n: u32) -> String {
    format!("box-{n}")
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

fn channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

fn worker(addr: SocketAddr, interceptor: Interceptor) -> Worker {
    FleetWorkerClient::with_interceptor(channel(addr), interceptor)
        .max_decoding_message_size(fleet_proto::MAX_PROFILE_MESSAGE_BYTES)
}

fn chunk(seq: u64, text: &str) -> TranscriptChunk {
    TranscriptChunk {
        seq,
        ts_ms: 1_000 + seq,
        text: text.to_owned(),
        truncated: false,
    }
}

fn report(job: &Job, box_name: &str, state: Option<JobState>) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job.job_id.clone(),
        attempt: job.attempt,
        r#box: box_name.to_owned(),
        phase: "running".to_owned(),
        progress: "working".to_owned(),
        terminal_state: state.map(|s| s as i32),
        ..ReportJobRequest::default()
    }
}

const PR: &str = "https://example.com/org/repo/pull/7";
const CHECKS: &str = "https://example.com/org/repo/pull/7/checks";
const INVALID: &str = "invalid job telemetry";

fn submit(key: &str, open_pr: bool) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "do it".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr,
        agent: String::new(),
    }
}

async fn claim(worker: &mut Worker, box_name: &str) -> Job {
    worker
        .claim_job(ClaimJobRequest {
            r#box: box_name.to_owned(),
        })
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap()
}

async fn running(store: &Store, worker: &mut Worker, key: &str, open_pr: bool) -> Job {
    store.submit_job(&submit(key, open_pr)).await.unwrap();
    claim(worker, &name(1)).await
}

fn ci(state: CiState, url: Option<&str>, log: Option<&str>) -> JobCi {
    JobCi {
        state: state as i32,
        url: url.map(str::to_owned),
        failure_log: log.map(str::to_owned),
    }
}

fn with_ci(job: &Job, ci: JobCi) -> ReportJobRequest {
    ReportJobRequest {
        ci: Some(ci),
        ..report(job, &name(1), None)
    }
}

fn ending(job: &Job, ci: Option<JobCi>) -> ReportJobRequest {
    ReportJobRequest {
        ci,
        pr_url: Some(PR.to_owned()),
        ..report(job, &name(1), Some(JobState::Succeeded))
    }
}

async fn stored(store: &Store, job: &Job) -> (Option<CiState>, Option<String>, bool) {
    let row = store.get_job(&job.job_id).await.unwrap();
    (
        row.ci_state.map(|s| CiState::try_from(s).unwrap()),
        row.ci_url,
        row.ci_checked_at_ms.is_some(),
    )
}

async fn seed(pool: &PgPool, job: &Job, state: &str, url: Option<&str>, log: Option<&str>) {
    sqlx::query(
        "UPDATE jobs SET ci_state = $2, ci_checked_at = now(), ci_url = $3 WHERE job_id = $1",
    )
    .bind(&job.job_id)
    .bind(state)
    .bind(url)
    .execute(pool)
    .await
    .unwrap();
    if let Some(log) = log {
        sqlx::query("INSERT INTO job_ci_log (job_id, log) VALUES ($1, $2)")
            .bind(&job.job_id)
            .bind(log)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[sqlx::test]
async fn a_job_without_a_ci_report_has_no_ci_columns(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder.report_job(ending(&job, None)).await.unwrap();
    assert_eq!(stored(&store, &job).await, (None, None, false));
    assert!(store.get_ci_log(&job.job_id).await.unwrap().is_none());
}

#[sqlx::test]
async fn pending_then_success_is_stored_on_the_job(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    assert_eq!(
        stored(&store, &job).await,
        (Some(CiState::Pending), None, true)
    );
    holder
        .report_job(ending(&job, Some(ci(CiState::Success, Some(CHECKS), None))))
        .await
        .unwrap();
    assert_eq!(
        stored(&store, &job).await,
        (Some(CiState::Success), Some(CHECKS.to_owned()), true)
    );
    let fetched = store.get_job(&job.job_id).await.unwrap();
    assert_eq!(fetched.state(), JobState::Succeeded);
    assert_eq!(fetched.pr_url.as_deref(), Some(PR));
}

#[sqlx::test]
async fn the_checked_at_stamp_moves_on_each_accepted_pending_report(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    let first = store.get_job(&job.job_id).await.unwrap().ci_checked_at_ms;
    tokio::time::sleep(Duration::from_millis(20)).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    let second = store.get_job(&job.job_id).await.unwrap().ci_checked_at_ms;
    assert!(second > first, "{first:?} {second:?}");
}

#[sqlx::test]
async fn a_failure_stores_the_log_and_the_url(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    let log = "step one\n\tstep two failed\n";
    holder
        .report_job(ending(
            &job,
            Some(ci(CiState::Failure, Some(CHECKS), Some(log))),
        ))
        .await
        .unwrap();
    assert_eq!(
        stored(&store, &job).await,
        (Some(CiState::Failure), Some(CHECKS.to_owned()), true)
    );
    assert_eq!(
        store.get_ci_log(&job.job_id).await.unwrap().as_deref(),
        Some(log)
    );
}

#[sqlx::test]
async fn a_log_of_exactly_the_cap_is_kept_and_one_byte_more_is_refused(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    let over = "x".repeat(MAX_CI_LOG_BYTES + 1);
    let err = holder
        .report_job(ending(&job, Some(ci(CiState::Failure, None, Some(&over)))))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), INVALID);
    assert_eq!(stored(&store, &job).await, (None, None, false));
    let exact = "x".repeat(MAX_CI_LOG_BYTES);
    holder
        .report_job(ending(&job, Some(ci(CiState::Failure, None, Some(&exact)))))
        .await
        .unwrap();
    assert_eq!(
        store.get_ci_log(&job.job_id).await.unwrap().unwrap().len(),
        MAX_CI_LOG_BYTES
    );
}

#[sqlx::test]
async fn a_stored_terminal_state_is_never_overwritten(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    seed(&pool, &job, "timeout", Some(CHECKS), None).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    assert_eq!(
        stored(&store, &job).await,
        (Some(CiState::Timeout), Some(CHECKS.to_owned()), true)
    );
    holder
        .report_job(ending(
            &job,
            Some(ci(CiState::Failure, Some(PR), Some("late log"))),
        ))
        .await
        .unwrap();
    assert_eq!(
        stored(&store, &job).await,
        (Some(CiState::Timeout), Some(CHECKS.to_owned()), true)
    );
    assert!(store.get_ci_log(&job.job_id).await.unwrap().is_none());
}

#[sqlx::test]
async fn a_final_ci_state_on_a_progress_report_is_rejected_and_stores_nothing(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    for item in [
        ci(CiState::Success, Some(CHECKS), None),
        ci(CiState::Failure, Some(CHECKS), Some("log")),
        ci(CiState::Timeout, Some(CHECKS), None),
    ] {
        rejected(&mut holder, with_ci(&job, item)).await;
        assert_eq!(stored(&store, &job).await, (None, None, false));
        assert!(store.get_ci_log(&job.job_id).await.unwrap().is_none());
    }
}

#[sqlx::test]
async fn a_later_ending_never_replaces_a_stored_success_or_failure(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    for (key, later) in [
        ("success", ci(CiState::Success, Some(PR), None)),
        (
            "failure",
            ci(CiState::Failure, Some(PR), Some("second log")),
        ),
    ] {
        let job = running(&store, &mut holder, key, true).await;
        seed(&pool, &job, "failure", Some(CHECKS), Some("first log")).await;
        holder.report_job(ending(&job, Some(later))).await.unwrap();
        assert_eq!(
            stored(&store, &job).await,
            (Some(CiState::Failure), Some(CHECKS.to_owned()), true),
            "{key}"
        );
        assert_eq!(
            store.get_ci_log(&job.job_id).await.unwrap().as_deref(),
            Some("first log")
        );
    }
}

#[sqlx::test]
async fn a_job_that_ends_with_ci_still_pending_ends_with_timeout(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    holder.report_job(ending(&job, None)).await.unwrap();
    let (state, _, stamped) = stored(&store, &job).await;
    assert_eq!(state, Some(CiState::Timeout));
    assert!(stamped);
}

#[sqlx::test]
async fn a_failed_or_cancelled_ending_turns_pending_into_timeout(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    for (key, end) in [
        ("failed", JobState::Failed),
        ("cancelled", JobState::Cancelled),
    ] {
        let job = running(&store, &mut holder, key, true).await;
        holder
            .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET cancel_requested = true WHERE job_id = $1")
            .bind(&job.job_id)
            .execute(&pool)
            .await
            .unwrap();
        holder
            .report_job(report(&job, &name(1), Some(end)))
            .await
            .unwrap();
        assert_eq!(
            stored(&store, &job).await.0,
            Some(CiState::Timeout),
            "{key}"
        );
    }
}

#[sqlx::test]
async fn a_terminal_ci_state_survives_the_job_ending(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    seed(&pool, &job, "success", Some(CHECKS), None).await;
    holder.report_job(ending(&job, None)).await.unwrap();
    assert_eq!(stored(&store, &job).await.0, Some(CiState::Success));
}

#[sqlx::test]
async fn the_reaper_turns_a_pending_ci_state_into_timeout(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 minute' WHERE job_id = $1")
        .bind(&job.job_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(store.reap_expired().await.unwrap(), 1);
    let fetched = store.get_job(&job.job_id).await.unwrap();
    assert_eq!(fetched.state(), JobState::Lost);
    assert_eq!(fetched.ci_state(), CiState::Timeout);
    assert!(fetched.ci_checked_at_ms.is_some());
}

#[sqlx::test]
async fn the_reaper_leaves_a_terminal_ci_state_and_a_job_without_ci_alone(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let done = running(&store, &mut holder, "done", true).await;
    seed(&pool, &done, "failure", Some(CHECKS), None).await;
    let before = store.get_job(&done.job_id).await.unwrap().ci_checked_at_ms;
    let bare = running(&store, &mut holder, "bare", true).await;
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 minute'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(store.reap_expired().await.unwrap(), 2);
    let done = store.get_job(&done.job_id).await.unwrap();
    assert_eq!(done.ci_state(), CiState::Failure);
    assert_eq!(done.ci_checked_at_ms, before);
    assert!(
        store
            .get_job(&bare.job_id)
            .await
            .unwrap()
            .ci_state
            .is_none()
    );
}

async fn rejected(holder: &mut Worker, request: ReportJobRequest) {
    let err = holder.report_job(request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), INVALID);
}

#[sqlx::test]
async fn a_malformed_ci_report_is_rejected_and_stores_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    let bad = [
        ci(CiState::Unspecified, None, None),
        JobCi {
            state: 99,
            url: None,
            failure_log: None,
        },
        ci(CiState::Success, Some("http://example.com/x"), None),
        ci(CiState::Success, Some("https://user@example.com/x"), None),
        ci(CiState::Success, Some("https://example.com/a b"), None),
        ci(
            CiState::Success,
            Some(&format!("https://example.com/{}", "a".repeat(2048))),
            None,
        ),
        ci(
            CiState::Success,
            Some("https://example.com/caf\u{e9}"),
            None,
        ),
        ci(
            CiState::Pending,
            Some("https://example.com/a\u{200b}b"),
            None,
        ),
        ci(CiState::Success, None, Some("log with success")),
        ci(CiState::Pending, None, Some("log with pending")),
        ci(CiState::Timeout, None, Some("log with timeout")),
        ci(CiState::Failure, None, Some("")),
        ci(CiState::Failure, None, Some("esc \u{1b}[31m")),
        ci(CiState::Failure, None, Some("nul \0 byte")),
        ci(CiState::Failure, None, Some("cr \r line")),
        ci(CiState::Failure, None, Some("bidi \u{202e} text")),
    ];
    for item in bad {
        let mut request = ending(&job, Some(item));
        request.chunks = vec![chunk(1, "never stored")];
        rejected(&mut holder, request).await;
    }
    assert_eq!(stored(&store, &job).await, (None, None, false));
    assert!(store.get_ci_log(&job.job_id).await.unwrap().is_none());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM job_transcript")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[sqlx::test]
async fn a_ci_status_must_end_a_succeeded_job_with_a_pull_request_url(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    let good = ci(CiState::Success, Some(CHECKS), None);
    let mut no_pr = ending(&job, Some(good.clone()));
    no_pr.pr_url = None;
    rejected(&mut holder, no_pr).await;
    for state in [JobState::Failed, JobState::Cancelled] {
        let mut request = report(&job, &name(1), Some(state));
        request.ci = Some(good.clone());
        request.pr_url = Some(PR.to_owned());
        rejected(&mut holder, request).await;
    }
    let live: String = sqlx::query_scalar("SELECT state FROM jobs WHERE job_id = $1")
        .bind(&job.job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(live, "RUNNING");
    assert_eq!(stored(&store, &job).await, (None, None, false));
}

#[sqlx::test]
async fn a_job_that_opened_no_pull_request_takes_no_ci_status(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", false).await;
    rejected(&mut holder, with_ci(&job, ci(CiState::Pending, None, None))).await;
    assert_eq!(stored(&store, &job).await, (None, None, false));
}

#[sqlx::test]
async fn a_judge_job_takes_no_ci_status(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let target = running(&store, &mut holder, "target", true).await;
    holder.report_job(ending(&target, None)).await.unwrap();
    let judge = store
        .submit_judge(&SubmitJudgeRequest {
            idempotency_key: "judge".to_owned(),
            prompt: "grade".to_owned(),
            target_job_id: target.job_id.clone(),
        })
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET open_pr = true WHERE job_id = $1")
        .bind(&judge.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let claimed = claim(&mut holder, &name(1)).await;
    assert_eq!(claimed.job_id, judge.job_id);
    rejected(
        &mut holder,
        with_ci(&claimed, ci(CiState::Pending, None, None)),
    )
    .await;
}

#[sqlx::test]
async fn only_the_lease_holder_stores_a_ci_status(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    let mut other = with_ci(&job, ci(CiState::Pending, Some(CHECKS), None));
    other.r#box = name(2);
    assert_eq!(
        holder.report_job(other).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    let mut stale = with_ci(&job, ci(CiState::Pending, Some(CHECKS), None));
    stale.attempt += 1;
    assert_eq!(
        holder.report_job(stale).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(stored(&store, &job).await, (None, None, false));
}

#[sqlx::test]
async fn the_database_refuses_a_ci_state_outside_the_set_and_a_half_stamp(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    for sql in [
        "UPDATE jobs SET ci_state = 'passed', ci_checked_at = now()",
        "UPDATE jobs SET ci_state = 'success'",
        "UPDATE jobs SET ci_checked_at = now()",
        "UPDATE jobs SET ci_url = 'https://example.com/x'",
        "UPDATE jobs SET ci_state = 'success', ci_checked_at = now(), ci_url = ''",
    ] {
        assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{sql}");
    }
    assert_eq!(stored(&store, &job).await, (None, None, false));
    sqlx::query("INSERT INTO job_ci_log (job_id, log) VALUES ($1, '')")
        .bind(&job.job_id)
        .execute(&pool)
        .await
        .unwrap_err();
    sqlx::query("INSERT INTO job_ci_log (job_id, log) VALUES ($1, $2)")
        .bind(&job.job_id)
        .bind("x".repeat(MAX_CI_LOG_BYTES + 1))
        .execute(&pool)
        .await
        .unwrap_err();
}

#[sqlx::test]
async fn retention_deletes_the_ci_log_of_an_old_finished_job_only(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let old = running(&store, &mut holder, "old", true).await;
    holder
        .report_job(ending(
            &old,
            Some(ci(CiState::Failure, Some(CHECKS), Some("old log"))),
        ))
        .await
        .unwrap();
    let fresh = running(&store, &mut holder, "fresh", true).await;
    holder
        .report_job(ending(
            &fresh,
            Some(ci(CiState::Failure, Some(CHECKS), Some("fresh log"))),
        ))
        .await
        .unwrap();
    let live = running(&store, &mut holder, "live", true).await;
    seed(&pool, &live, "failure", Some(CHECKS), Some("live log")).await;
    sqlx::query("UPDATE jobs SET finished_at = now() - interval '40 days' WHERE job_id = $1")
        .bind(&old.job_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET created_at = now() - interval '40 days' WHERE job_id = $1")
        .bind(&live.job_id)
        .execute(&pool)
        .await
        .unwrap();
    store.prune_summaries(30, 100).await.unwrap();
    assert!(store.get_ci_log(&old.job_id).await.unwrap().is_none());
    assert_eq!(
        store.get_ci_log(&fresh.job_id).await.unwrap().as_deref(),
        Some("fresh log")
    );
    assert_eq!(
        store.get_ci_log(&live.job_id).await.unwrap().as_deref(),
        Some("live log")
    );
    let row = sqlx::query("SELECT ci_state FROM jobs WHERE job_id = $1")
        .bind(&old.job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("ci_state"), "failure");
}

#[sqlx::test]
async fn a_url_of_exactly_the_cap_is_kept_and_one_byte_more_is_refused(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    let prefix = "https://example.com/";
    let exact = format!("{prefix}{}", "a".repeat(MAX_CI_URL_BYTES - prefix.len()));
    assert_eq!(exact.len(), MAX_CI_URL_BYTES);
    let over = format!("{exact}a");
    let err = holder
        .report_job(with_ci(&job, ci(CiState::Pending, Some(&over), None)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), INVALID);
    assert_eq!(stored(&store, &job).await, (None, None, false));
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, Some(&exact), None)))
        .await
        .unwrap();
    assert_eq!(stored(&store, &job).await.1, Some(exact));
}

#[sqlx::test]
async fn a_later_pending_report_replaces_or_clears_the_stored_url(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    for url in [Some(CHECKS), Some(PR), None] {
        holder
            .report_job(with_ci(&job, ci(CiState::Pending, url, None)))
            .await
            .unwrap();
        assert_eq!(stored(&store, &job).await.1.as_deref(), url);
    }
}

#[sqlx::test]
async fn a_job_ending_with_ci_pending_moves_the_checked_at_stamp(pool: PgPool) {
    let store = store(pool).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    let before = store.get_job(&job.job_id).await.unwrap().ci_checked_at_ms;
    tokio::time::sleep(Duration::from_millis(20)).await;
    holder.report_job(ending(&job, None)).await.unwrap();
    let after = store.get_job(&job.job_id).await.unwrap().ci_checked_at_ms;
    assert!(after > before, "{before:?} {after:?}");
}

#[sqlx::test]
async fn the_reaper_moves_the_checked_at_stamp_of_a_pending_ci_state(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut holder = worker(serve(&store), as_box);
    let job = running(&store, &mut holder, "k", true).await;
    holder
        .report_job(with_ci(&job, ci(CiState::Pending, None, None)))
        .await
        .unwrap();
    let before = store.get_job(&job.job_id).await.unwrap().ci_checked_at_ms;
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 minute' WHERE job_id = $1")
        .bind(&job.job_id)
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(store.reap_expired().await.unwrap(), 1);
    let after = store.get_job(&job.job_id).await.unwrap().ci_checked_at_ms;
    assert!(after > before, "{before:?} {after:?}");
}
