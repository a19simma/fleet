//! The judge Job over a real tonic server on a loopback port: submit, transcript read,
//! verdict storage and the stats figure. The tests need a Postgres superuser URL in
//! `DATABASE_URL`. They live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::v1::fleet_judge_client::FleetJudgeClient;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, GetJobTranscriptRequest, GetStatsRequest, Job, JobKind, JobState, JobVerdict,
    ReportJobRequest, StatsGroupBy, SubmitJobRequest, SubmitJudgeRequest, TranscriptChunk,
};
use fleet_proto::{MAX_TRANSCRIPT_BYTES, MAX_VERDICT_REASON_BYTES};
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
const DENIED: &str = "lease does not match";
const MODEL: &str = "judge-model-1";

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Worker = FleetWorkerClient<InterceptedService<Channel, Interceptor>>;
type Judge = FleetJudgeClient<InterceptedService<Channel, Interceptor>>;

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

fn judge_client(addr: SocketAddr, interceptor: Interceptor) -> Judge {
    FleetJudgeClient::with_interceptor(channel(addr), interceptor)
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

fn verdict(score: u32, reason: &str, model: &str) -> JobVerdict {
    JobVerdict {
        score,
        reason: reason.to_owned(),
        judge_model: model.to_owned(),
    }
}

fn submit(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "do it".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
    }
}

fn judge_request(key: &str, target: &str) -> SubmitJudgeRequest {
    SubmitJudgeRequest {
        idempotency_key: key.to_owned(),
        prompt: "grade it".to_owned(),
        target_job_id: target.to_owned(),
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

async fn finished_target(store: &Store, worker: &mut Worker, texts: &[&str]) -> Job {
    store.submit_job(&submit("target-key")).await.unwrap();
    let job = claim(worker, &name(1)).await;
    let mut request = report(&job, &name(1), Some(JobState::Succeeded));
    request.chunks = texts
        .iter()
        .zip(1_u64..)
        .map(|(text, seq)| chunk(seq, text))
        .collect();
    worker.report_job(request).await.unwrap();
    job
}

fn transcript(job: &Job, attempt: u32, box_name: &str) -> GetJobTranscriptRequest {
    GetJobTranscriptRequest {
        job_id: job.job_id.clone(),
        attempt,
        r#box: box_name.to_owned(),
    }
}

#[sqlx::test]
async fn the_judge_is_its_own_job_with_a_target(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["a"]).await;
    let judge = judge_client(addr, as_client)
        .submit_judge(judge_request("j1", &target.job_id))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(judge.job_id, target.job_id);
    assert_eq!(judge.kind(), JobKind::Judge);
    assert_eq!(judge.target_job_id.as_deref(), Some(target.job_id.as_str()));
    assert_eq!(judge.state(), JobState::Queued);
    assert_eq!(target.kind(), JobKind::Agent);
    assert!(target.target_job_id.is_none());
    let claimed = claim(&mut holder, &name(2)).await;
    assert_eq!(claimed.job_id, judge.job_id);
    assert_eq!(claimed.kind(), JobKind::Judge);
    assert_eq!(claimed.target_job_id, judge.target_job_id);
}

#[sqlx::test]
async fn a_replayed_key_returns_the_same_judge_and_a_changed_target_conflicts(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["a"]).await;
    let first = store
        .submit_judge(&judge_request("j1", &target.job_id))
        .await
        .unwrap();
    let again = store
        .submit_judge(&judge_request("j1", &target.job_id))
        .await
        .unwrap();
    assert_eq!(first.job_id, again.job_id);
    let other = store.submit_job(&submit("other")).await.unwrap();
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&other.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let err = store
        .submit_judge(&judge_request("j1", &other.job_id))
        .await
        .unwrap_err();
    assert!(matches!(err, fleet_server::store::StoreError::KeyConflict));
}

#[sqlx::test]
async fn concurrent_submits_under_different_keys_admit_one_live_judge(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["a"]).await;
    sqlx::raw_sql(
        "CREATE FUNCTION slow_judge_insert() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$; \
         CREATE TRIGGER slow_judge_insert BEFORE INSERT ON jobs \
         FOR EACH ROW WHEN (NEW.kind = 'judge') EXECUTE FUNCTION slow_judge_insert();",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut set = tokio::task::JoinSet::new();
    for key in ["race-a", "race-b"] {
        let store = store.clone();
        let request = judge_request(key, &target.job_id);
        set.spawn(async move { store.submit_judge(&request).await });
    }
    let mut results = Vec::new();
    while let Some(done) = set.join_next().await {
        results.push(done.unwrap());
    }
    let admitted = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(admitted, 1, "{results:?}");
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE kind = 'judge' AND target_job_id = $1")
            .bind(&target.job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, 1);
}

#[sqlx::test]
async fn a_judge_target_must_be_a_finished_agent_job(pool: PgPool) {
    let store = store(pool).await;
    let queued = store.submit_job(&submit("queued")).await.unwrap();
    let mut judge = judge_client(serve(&store), as_client);
    for (key, target) in [
        ("a", queued.job_id.as_str()),
        ("b", "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        ("c", ""),
        ("d", "not an id"),
    ] {
        let err = judge
            .submit_judge(judge_request(key, target))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "target {target:?}");
    }
}

#[sqlx::test]
async fn a_judge_cannot_judge_a_judge(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["a"]).await;
    let first = store
        .submit_judge(&judge_request("j1", &target.job_id))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&first.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let err = judge_client(addr, as_client)
        .submit_judge(judge_request("j2", &first.job_id))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[sqlx::test]
async fn a_judge_request_is_validated(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["a"]).await;
    let mut judge = judge_client(addr, as_client);
    for request in [
        judge_request("", &target.job_id),
        SubmitJudgeRequest {
            prompt: String::new(),
            ..judge_request("k", &target.job_id)
        },
        SubmitJudgeRequest {
            prompt: "x".repeat(fleet_server::jobs::MAX_PROMPT_BYTES + 1),
            ..judge_request("k", &target.job_id)
        },
    ] {
        let err = judge.submit_judge(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}

#[sqlx::test]
async fn the_box_token_cannot_submit_a_judge(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["a"]).await;
    let err = judge_client(addr, as_box)
        .submit_judge(judge_request("j1", &target.job_id))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

async fn leased_judge(store: &Store, holder: &mut Worker, target: &Job) -> Job {
    store
        .submit_judge(&judge_request("j1", &target.job_id))
        .await
        .unwrap();
    claim(holder, &name(2)).await
}

#[sqlx::test]
async fn the_lease_holder_reads_the_targets_transcript(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n", "two\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let reply = holder
        .get_job_transcript(transcript(&judge, judge.attempt, &name(2)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.target_job_id, target.job_id);
    let text: String = reply.chunks.iter().map(|c| c.text.as_str()).collect();
    assert_eq!(text, "one\ntwo\n");
}

#[sqlx::test]
async fn every_mismatch_gets_the_same_fixed_denial(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let mut denied = Vec::new();
    denied.push(
        holder
            .get_job_transcript(transcript(&judge, judge.attempt, &name(3)))
            .await
            .unwrap_err(),
    );
    for attempt in [0, judge.attempt + 1, u32::MAX] {
        denied.push(
            holder
                .get_job_transcript(transcript(&judge, attempt, &name(2)))
                .await
                .unwrap_err(),
        );
    }
    denied.push(
        holder
            .get_job_transcript(transcript(&target, target.attempt, &name(1)))
            .await
            .unwrap_err(),
    );
    let missing = Job {
        job_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
        ..Job::default()
    };
    denied.push(
        holder
            .get_job_transcript(transcript(&missing, 1, &name(2)))
            .await
            .unwrap_err(),
    );
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE job_id = $1")
        .bind(&judge.job_id)
        .execute(&pool)
        .await
        .unwrap();
    denied.push(
        holder
            .get_job_transcript(transcript(&judge, judge.attempt, &name(2)))
            .await
            .unwrap_err(),
    );
    sqlx::query(
        "UPDATE jobs SET lease_expires_at = now() + interval '1 hour', state = 'SUCCEEDED' WHERE job_id = $1",
    )
    .bind(&judge.job_id)
    .execute(&pool)
    .await
    .unwrap();
    denied.push(
        holder
            .get_job_transcript(transcript(&judge, judge.attempt, &name(2)))
            .await
            .unwrap_err(),
    );
    for err in &denied {
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(err.message(), DENIED);
    }
    assert_eq!(denied.len(), 8);
}

#[sqlx::test]
async fn the_client_token_cannot_read_a_transcript(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let err = worker(addr, as_client)
        .get_job_transcript(transcript(&judge, judge.attempt, &name(2)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[sqlx::test]
async fn a_transcript_at_the_cap_flows_and_one_byte_over_is_refused(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["x"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let big = "a".repeat(MAX_TRANSCRIPT_BYTES);
    sqlx::query("UPDATE job_transcript SET chunk = $1 WHERE job_id = $2")
        .bind(&big)
        .bind(&target.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let reply = holder
        .get_job_transcript(transcript(&judge, judge.attempt, &name(2)))
        .await
        .unwrap()
        .into_inner();
    let total: usize = reply.chunks.iter().map(|c| c.text.len()).sum();
    assert_eq!(total, MAX_TRANSCRIPT_BYTES);
    sqlx::query("UPDATE job_transcript SET chunk = chunk || 'a' WHERE job_id = $1")
        .bind(&target.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let err = holder
        .get_job_transcript(transcript(&judge, judge.attempt, &name(2)))
        .await
        .unwrap_err();
    assert_ne!(err.code(), Code::Ok);
}

async fn stored(pool: &PgPool, judge: &Job) -> Option<(String, i16, String, String)> {
    sqlx::query(
        "SELECT target_job_id, score, reason, judge_model FROM job_verdict WHERE job_id = $1",
    )
    .bind(&judge.job_id)
    .fetch_optional(pool)
    .await
    .unwrap()
    .map(|row| {
        (
            row.get("target_job_id"),
            row.get("score"),
            row.get("reason"),
            row.get("judge_model"),
        )
    })
}

#[sqlx::test]
async fn a_succeeded_judge_stores_its_verdict_for_the_target(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let mut request = report(&judge, &name(2), Some(JobState::Succeeded));
    request.verdict = Some(verdict(87, "solid", MODEL));
    holder.report_job(request).await.unwrap();
    let row = stored(&pool, &judge).await.unwrap();
    assert_eq!(
        row,
        (target.job_id, 87, "solid".to_owned(), MODEL.to_owned())
    );
}

#[sqlx::test]
async fn the_highest_score_and_the_longest_reason_are_accepted(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let reason = "r".repeat(MAX_VERDICT_REASON_BYTES);
    let mut request = report(&judge, &name(2), Some(JobState::Succeeded));
    request.verdict = Some(verdict(100, &reason, MODEL));
    holder.report_job(request).await.unwrap();
    let row = stored(&pool, &judge).await.unwrap();
    assert_eq!((row.1, row.2.len()), (100, MAX_VERDICT_REASON_BYTES));
}

#[sqlx::test]
async fn a_running_agent_job_cannot_read_a_transcript(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    store.submit_job(&submit("second")).await.unwrap();
    let running = claim(&mut holder, &name(3)).await;
    assert_eq!(running.kind(), JobKind::Agent);
    for job in [&running, &target] {
        let err = holder
            .get_job_transcript(transcript(job, job.attempt, &name(3)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(err.message(), DENIED);
    }
}

#[sqlx::test]
async fn a_bad_verdict_is_refused_and_stores_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let long = "r".repeat(MAX_VERDICT_REASON_BYTES + 1);
    for bad in [
        verdict(101, "r", MODEL),
        verdict(5, "", MODEL),
        verdict(5, &long, MODEL),
        verdict(5, "r", ""),
        verdict(5, "bad\u{0}byte", MODEL),
    ] {
        let mut request = report(&judge, &name(2), Some(JobState::Succeeded));
        request.verdict = Some(bad);
        let err = holder.report_job(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
    assert!(stored(&pool, &judge).await.is_none());
    let job = store.get_job(&judge.job_id).await.unwrap();
    assert_eq!(job.state(), JobState::Running);
}

#[sqlx::test]
async fn a_verdict_needs_a_succeeded_judge_job(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    store.submit_job(&submit("agent")).await.unwrap();
    let agent = claim(&mut holder, &name(1)).await;
    let mut request = report(&agent, &name(1), Some(JobState::Succeeded));
    request.verdict = Some(verdict(5, "r", MODEL));
    let err = holder.report_job(request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM job_verdict")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test]
async fn a_failed_judge_cannot_carry_a_verdict(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let mut request = report(&judge, &name(2), Some(JobState::Failed));
    request.error = Some("no verdict".to_owned());
    request.verdict = Some(verdict(5, "r", MODEL));
    let err = holder.report_job(request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(stored(&pool, &judge).await.is_none());
}

#[sqlx::test]
async fn a_second_judge_is_refused_while_one_runs_or_holds_a_verdict(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let first = leased_judge(&store, &mut holder, &target).await;
    assert!(
        store
            .submit_judge(&judge_request("j2", &target.job_id))
            .await
            .is_err()
    );
    let mut request = report(&first, &name(2), Some(JobState::Succeeded));
    request.verdict = Some(verdict(10, "first", MODEL));
    holder.report_job(request).await.unwrap();
    assert!(
        store
            .submit_judge(&judge_request("j3", &target.job_id))
            .await
            .is_err()
    );
    let again = store
        .submit_judge(&judge_request("j1", &target.job_id))
        .await
        .unwrap();
    assert_eq!(again.job_id, first.job_id);
    assert_eq!(stored(&pool, &first).await.unwrap().1, 10);
}

#[sqlx::test]
async fn a_failed_judge_can_be_retried_with_a_new_judge(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let first = leased_judge(&store, &mut holder, &target).await;
    let mut request = report(&first, &name(2), Some(JobState::Failed));
    request.error = Some("no verdict".to_owned());
    holder.report_job(request).await.unwrap();
    store
        .submit_judge(&judge_request("j2", &target.job_id))
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_verdict_that_would_not_store_fails_the_report(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let first = leased_judge(&store, &mut holder, &target).await;
    let mut request = report(&first, &name(2), Some(JobState::Failed));
    request.error = Some("no verdict".to_owned());
    holder.report_job(request).await.unwrap();
    sqlx::query(
        "INSERT INTO job_verdict (job_id, target_job_id, score, reason, judge_model) \
         VALUES ($1, $2, 1, 'seeded', $3)",
    )
    .bind(&first.job_id)
    .bind(&target.job_id)
    .bind(MODEL)
    .execute(&pool)
    .await
    .unwrap();
    store
        .submit_judge(&judge_request("j2", &target.job_id))
        .await
        .unwrap_err();
    sqlx::query("DELETE FROM job_verdict")
        .execute(&pool)
        .await
        .unwrap();
    store
        .submit_judge(&judge_request("j2", &target.job_id))
        .await
        .unwrap();
    let second = claim(&mut holder, &name(2)).await;
    sqlx::query(
        "INSERT INTO job_verdict (job_id, target_job_id, score, reason, judge_model) \
         VALUES ($1, $2, 1, 'seeded', $3)",
    )
    .bind(&first.job_id)
    .bind(&target.job_id)
    .bind(MODEL)
    .execute(&pool)
    .await
    .unwrap();
    let mut request = report(&second, &name(2), Some(JobState::Succeeded));
    request.verdict = Some(verdict(90, "second", MODEL));
    let err = holder.report_job(request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(stored(&pool, &second).await.is_none());
}

#[sqlx::test]
async fn a_succeeded_judge_without_a_verdict_is_refused(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let judge = leased_judge(&store, &mut holder, &target).await;
    let err = holder
        .report_job(report(&judge, &name(2), Some(JobState::Succeeded)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(stored(&pool, &judge).await.is_none());
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE job_id = $1")
        .bind(&judge.job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "RUNNING");
}

#[sqlx::test]
async fn a_succeeded_agent_job_needs_no_verdict(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    finished_target(&store, &mut holder, &["one\n"]).await;
}

fn by_repo() -> GetStatsRequest {
    GetStatsRequest {
        group_by: StatsGroupBy::Repo.into(),
        ..GetStatsRequest::default()
    }
}

#[sqlx::test]
async fn stats_carry_a_model_graded_verdict_figure_with_its_own_n(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    let before = store.stats(&by_repo()).await.unwrap();
    assert!(before.groups.iter().all(|g| g.verdict.is_none()));
    let judge = leased_judge(&store, &mut holder, &target).await;
    let mut request = report(&judge, &name(2), Some(JobState::Succeeded));
    request.verdict = Some(verdict(80, "good", MODEL));
    holder.report_job(request).await.unwrap();
    let reply = store.stats(&by_repo()).await.unwrap();
    assert_eq!(reply.groups.len(), 1);
    let group = &reply.groups[0];
    assert_eq!(group.jobs, 1);
    let figure = group.verdict.as_ref().unwrap();
    assert_eq!(figure.n, 1);
    assert!(figure.model_graded);
    assert!((figure.mean - 80.0).abs() < 1e-9);
    assert!((figure.p50 - 80.0).abs() < 1e-9);
}

#[sqlx::test]
async fn a_target_without_a_verdict_has_no_figure_never_zero(pool: PgPool) {
    let store = store(pool).await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let target = finished_target(&store, &mut holder, &["one\n"]).await;
    leased_judge(&store, &mut holder, &target).await;
    let reply = store.stats(&by_repo()).await.unwrap();
    assert!(reply.groups.iter().all(|g| g.verdict.is_none()));
    assert_eq!(reply.groups.iter().map(|g| g.jobs).sum::<u64>(), 1);
}
