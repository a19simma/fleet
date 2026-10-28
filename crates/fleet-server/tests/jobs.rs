//! Job store tests. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_core::BoxName;
use fleet_proto::v1::{
    JobState, ReportJobReply, ReportJobRequest, SubmitJobRequest, TranscriptChunk,
};
use fleet_server::jobs::{
    JobInvalid, MAX_BASE_REF_BYTES, MAX_BRANCH_BYTES, MAX_CHUNKS_PER_REPORT, MAX_ERROR_CHARS,
    MAX_KEY_BYTES, MAX_PHASE_CHARS, MAX_PR_URL_BYTES, MAX_PROGRESS_CHARS, MAX_PROMPT_BYTES,
    MAX_REPO_BYTES, MAX_TRANSCRIPT_BYTES, MAX_TRANSCRIPT_ROWS, MIN_CHUNK_COST_BYTES,
};
use fleet_server::reaper::{MAX_BACKOFF, backoff_after, error_kind, run_reaper};
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(30);

trait Plain {
    async fn report_plain(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
        phase: &str,
        progress: &str,
        chunks: &[TranscriptChunk],
    ) -> Result<ReportJobReply, StoreError>;
}

impl Plain for Store {
    async fn report_plain(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
        phase: &str,
        progress: &str,
        chunks: &[TranscriptChunk],
    ) -> Result<ReportJobReply, StoreError> {
        self.report_job(
            &BoxName::new(box_name).unwrap(),
            &ReportJobRequest {
                job_id: job_id.to_owned(),
                attempt,
                r#box: box_name.to_owned(),
                phase: phase.to_owned(),
                progress: progress.to_owned(),
                chunks: chunks.to_vec(),
                ..ReportJobRequest::default()
            },
        )
        .await
    }
}

fn request(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: "https://example.com/org/repo.git".to_owned(),
        base_ref: "main".to_owned(),
        open_pr: true,
    }
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

async fn job_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn submit_is_idempotent(pool: PgPool) {
    let store = store(pool.clone()).await;
    let first = timeout(WAIT, store.submit_job(&request("k1")))
        .await
        .unwrap()
        .unwrap();
    let again = timeout(WAIT, store.submit_job(&request("k1")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(first.prompt, "add hello.txt");
    assert_eq!(first.job_id.len(), 26);
    assert!(first.job_id.parse::<fleet_core::EventId>().is_ok());
    assert_eq!(first.state, i32::from(JobState::Queued));
    assert_eq!(
        first.branch.as_deref(),
        Some(format!("swarm/{}", first.job_id).as_str())
    );
    assert_eq!(job_rows(&pool).await, 1);
    let other = store.submit_job(&request("k2")).await.unwrap();
    assert_ne!(other.job_id, first.job_id);
    assert_eq!(job_rows(&pool).await, 2);
}

#[sqlx::test]
async fn different_prompt_is_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let first = store.submit_job(&request("k1")).await.unwrap();
    let mut changed = request("k1");
    "other secret".clone_into(&mut changed.prompt);
    let err = timeout(WAIT, store.submit_job(&changed))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, StoreError::KeyConflict));
    assert!(!format!("{err} {err:?}").contains("secret"));
    let stored = store.submit_job(&request("k1")).await.unwrap();
    assert_eq!(stored, first);
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn each_other_field_mismatch_is_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    store.submit_job(&request("k1")).await.unwrap();
    let edits: [fn(&mut SubmitJobRequest); 3] = [
        |r| "https://example.com/org/other.git".clone_into(&mut r.repo),
        |r| "dev".clone_into(&mut r.base_ref),
        |r| r.open_pr = !r.open_pr,
    ];
    for edit in edits {
        let mut changed = request("k1");
        edit(&mut changed);
        let err = store.submit_job(&changed).await.unwrap_err();
        assert!(matches!(err, StoreError::KeyConflict));
    }
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn concurrent_submits_with_other_params_yield_one_winner(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut tasks = Vec::new();
    for i in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let mut r = request("race");
            r.prompt = format!("prompt {i}");
            store.submit_job(&r).await
        }));
    }
    let mut won = 0;
    let mut conflicts = 0;
    for task in tasks {
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Ok(_) => won += 1,
            Err(StoreError::KeyConflict) => conflicts += 1,
            Err(other) => panic!("unexpected {other}"),
        }
    }
    assert_eq!(won, 1);
    assert_eq!(conflicts, 15);
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn concurrent_submits_create_one_job(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.submit_job(&request("same")).await
        }));
    }
    let mut ids = Vec::new();
    for task in tasks {
        let job = timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        ids.push(job.job_id);
    }
    ids.dedup();
    assert_eq!(ids.len(), 1);
    assert_eq!(job_rows(&pool).await, 1);
}

#[sqlx::test]
async fn missing_key_is_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let err = store.submit_job(&request("")).await.unwrap_err();
    assert!(matches!(err, StoreError::InvalidJob(_)));
    assert_eq!(err.to_string(), "invalid idempotency key");
    assert_eq!(job_rows(&pool).await, 0);
}

#[sqlx::test]
async fn invalid_input_is_rejected_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let secret = "s3cret-token";
    let long = |n: usize| "a".repeat(n + 1);
    let mut cases = Vec::new();
    let mut with = |label: &str, edit: &dyn Fn(&mut SubmitJobRequest)| {
        let mut r = request("k");
        edit(&mut r);
        cases.push((label.to_owned(), r));
    };
    with("key long", &|r| r.idempotency_key = long(MAX_KEY_BYTES));
    with("key space", &|r| r.idempotency_key = format!("a {secret}"));
    with("key nul", &|r| r.idempotency_key = format!("a\0{secret}"));
    with("prompt empty", &|r| r.prompt = "  ".into());
    with("prompt long", &|r| r.prompt = long(MAX_PROMPT_BYTES));
    with("prompt nul", &|r| r.prompt = format!("a\0{secret}"));
    with("repo http", &|r| r.repo = format!("http://x/{secret}"));
    with("repo bare scheme", &|r| r.repo = "https://".into());
    with("repo userinfo", &|r| {
        r.repo = format!("https://user:{secret}@example.com/org/repo.git");
    });
    with("repo token userinfo", &|r| {
        r.repo = format!("https://{secret}@example.com/org/repo.git");
    });
    with("repo space", &|r| r.repo = format!("https://x/a {secret}"));
    with("repo long", &|r| {
        r.repo = format!("https://{}", long(MAX_REPO_BYTES));
    });
    with("repo backslash", &|r| {
        r.repo = format!("https://example.com\\{secret}/org/repo.git");
    });
    with("repo backslash userinfo", &|r| {
        r.repo = format!("https://example.com\\@{secret}/repo.git");
    });
    with("ref empty", &|r| r.base_ref = String::new());
    with("ref long", &|r| r.base_ref = long(MAX_BASE_REF_BYTES));
    with("ref newline", &|r| r.base_ref = format!("a\n{secret}"));
    for (label, case) in cases {
        let err = store.submit_job(&case).await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidJob(_)), "{label}");
        let text = format!("{err} {err:?}");
        assert!(!text.contains(secret), "{label} echoed input");
    }
    assert_eq!(job_rows(&pool).await, 0);
}

#[sqlx::test]
async fn boundary_sizes_are_accepted(pool: PgPool) {
    let store = store(pool).await;
    let mut r = request(&"k".repeat(MAX_KEY_BYTES));
    r.prompt = "p".repeat(MAX_PROMPT_BYTES);
    r.base_ref = "b".repeat(MAX_BASE_REF_BYTES);
    r.open_pr = false;
    let job = store.submit_job(&r).await.unwrap();
    assert!(!job.open_pr);
    assert_eq!(job.prompt.len(), MAX_PROMPT_BYTES);
}

fn claimer(n: u32) -> String {
    format!("box-{n}")
}

fn boxed(n: u32) -> BoxName {
    BoxName::new(&claimer(n)).unwrap()
}

async fn submit_n(store: &Store, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..n {
        let job = store.submit_job(&request(&format!("k{i}"))).await.unwrap();
        ids.push(job.job_id);
    }
    ids
}

#[sqlx::test]
async fn concurrent_claims_are_exclusive(pool: PgPool) {
    let store = store(pool).await;
    let jobs = 12;
    let mut expected = submit_n(&store, jobs).await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.claim_job(&boxed(i % 4 + 1)).await
        }));
    }
    let mut claimed = Vec::new();
    let mut empty = 0;
    for task in tasks {
        match timeout(WAIT, task).await.unwrap().unwrap().unwrap() {
            Some(job) => {
                assert_eq!(job.state, i32::from(JobState::Running));
                assert_eq!(job.attempt, 1);
                claimed.push(job.job_id);
            }
            None => empty += 1,
        }
    }
    claimed.sort();
    expected.sort();
    assert_eq!(claimed, expected);
    assert_eq!(empty, 12);
}

#[sqlx::test]
async fn claim_is_fifo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let ids = submit_n(&store, 3).await;
    let cancelled = store.submit_job(&request("late")).await.unwrap();
    sqlx::query("UPDATE jobs SET state = 'CANCELLED' WHERE job_id = $1")
        .bind(&cancelled.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut order = Vec::new();
    for _ in 0..=ids.len() {
        let claimed = timeout(WAIT, store.claim_job(&boxed(1)))
            .await
            .unwrap()
            .unwrap();
        order.extend(claimed.map(|job| job.job_id));
    }
    assert_eq!(order, ids);
    let left: String = sqlx::query_scalar("SELECT state FROM jobs WHERE job_id = $1")
        .bind(&cancelled.job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, "CANCELLED");
}

#[sqlx::test]
async fn claim_sets_lease_and_attempt(pool: PgPool) {
    let lease = Duration::from_secs(45);
    let store = store(pool.clone()).await.with_lease(lease);
    let queued = store.submit_job(&request("k")).await.unwrap();
    assert_eq!(queued.attempt, 0);
    assert_eq!(queued.lease_expires_at_ms, None);
    let job = timeout(WAIT, store.claim_job(&boxed(2)))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(job.job_id, queued.job_id);
    assert_eq!(job.state, i32::from(JobState::Running));
    assert_eq!(job.r#box, claimer(2));
    assert_eq!(job.attempt, 1);
    let claimed = job.claimed_at_ms.unwrap();
    let expires = job.lease_expires_at_ms.unwrap();
    assert_eq!(expires - claimed, 45_000);
    assert!(claimed >= job.created_at_ms);
    let default = Store::new(pool.clone());
    default.submit_job(&request("k2")).await.unwrap();
    let second = default.claim_job(&boxed(2)).await.unwrap().unwrap();
    assert_eq!(
        second.lease_expires_at_ms.unwrap() - second.claimed_at_ms.unwrap(),
        120_000
    );
}

#[sqlx::test]
async fn empty_queue_returns_none(pool: PgPool) {
    let store = store(pool.clone()).await;
    let first = timeout(WAIT, store.claim_job(&boxed(1)))
        .await
        .unwrap()
        .unwrap();
    assert!(first.is_none());
    submit_n(&store, 1).await;
    assert!(store.claim_job(&boxed(1)).await.unwrap().is_some());
    assert!(store.claim_job(&boxed(1)).await.unwrap().is_none());
}

async fn claimed(store: &Store, box_name: &str) -> fleet_proto::v1::Job {
    store.submit_job(&request("rk")).await.unwrap();
    store
        .claim_job(&BoxName::new(box_name).unwrap())
        .await
        .unwrap()
        .unwrap()
}

async fn set_lease_in_past(pool: &PgPool) {
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 hour'")
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test]
async fn report_renews_lease(pool: PgPool) {
    let store = store(pool.clone())
        .await
        .with_lease(Duration::from_secs(45));
    let job = claimed(&store, &claimer(1)).await;
    set_lease_in_past(&pool).await;
    let reply = timeout(
        WAIT,
        store.report_plain(
            &job.job_id,
            job.attempt,
            &claimer(1),
            "running",
            "step 2",
            &[],
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!reply.cancel_requested);
    let now: i64 = sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM now()) * 1000)::bigint")
        .fetch_one(&pool)
        .await
        .unwrap();
    let delta = i64::try_from(reply.lease_expires_at_ms).unwrap() - now;
    assert!((40_000..=45_000).contains(&delta), "delta {delta}");
    let (phase, progress, lease): (String, String, i64) = sqlx::query_as(
        "SELECT phase, progress, (EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint FROM jobs",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(phase, "running");
    assert_eq!(progress, "step 2");
    assert_eq!(lease, i64::try_from(reply.lease_expires_at_ms).unwrap());
    sqlx::query("UPDATE jobs SET cancel_requested = true")
        .execute(&pool)
        .await
        .unwrap();
    let again = store
        .report_plain(
            &job.job_id,
            job.attempt,
            &claimer(1),
            "running",
            "step 3",
            &[],
        )
        .await
        .unwrap();
    assert!(again.cancel_requested);
}

#[sqlx::test]
async fn stale_attempt_rejected(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let secret = "s3cret-job";
    let cases = [
        (job.job_id.clone(), job.attempt + 1, claimer(1)),
        (job.job_id.clone(), job.attempt - 1, claimer(1)),
        (job.job_id.clone(), job.attempt, claimer(2)),
        (secret.to_owned(), job.attempt, claimer(1)),
    ];
    for (id, attempt, box_name) in cases {
        let err = store
            .report_plain(&id, attempt, &box_name, "hijack", "hijack", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::StaleReport));
        assert!(!format!("{err} {err:?}").contains(secret));
    }
    for state in ["QUEUED", "SUCCEEDED", "LOST", "CANCELLED", "FAILED"] {
        sqlx::query("UPDATE jobs SET state = $1")
            .bind(state)
            .execute(&pool)
            .await
            .unwrap();
        let err = store
            .report_plain(&job.job_id, job.attempt, &claimer(1), "late", "late", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::StaleReport), "{state}");
    }
    let (phase, progress): (String, String) = sqlx::query_as("SELECT phase, progress FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((phase.as_str(), progress.as_str()), ("", ""));
}

fn chunk(seq: u64, text: &str) -> TranscriptChunk {
    TranscriptChunk {
        seq,
        ts_ms: 1,
        text: text.to_owned(),
        truncated: false,
    }
}

#[sqlx::test]
async fn transcript_dedupes_and_caps(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let id = job.job_id.as_str();
    let rows = || async {
        sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT seq, chunk, truncated FROM job_transcript ORDER BY seq",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let first = store
        .report_plain(
            id,
            job.attempt,
            &claimer(1),
            "r",
            "p",
            &[chunk(1, "a"), chunk(2, "b")],
        )
        .await
        .unwrap();
    assert_eq!(first.acked_through_seq, 2);
    assert!(!first.transcript_truncated);
    let again = store
        .report_plain(
            id,
            job.attempt,
            &claimer(1),
            "r",
            "p",
            &[chunk(2, "changed")],
        )
        .await
        .unwrap();
    assert_eq!(again.acked_through_seq, 2);
    assert_eq!(rows().await.len(), 2);
    assert_eq!(rows().await[1].1, "b");

    let stale = store
        .report_plain(id, job.attempt, &claimer(2), "r", "p", &[chunk(3, "x")])
        .await;
    assert!(matches!(stale, Err(StoreError::StaleReport)));
    let nul = store
        .report_plain(id, job.attempt, &claimer(1), "r", "p", &[chunk(3, "a\0b")])
        .await;
    assert!(matches!(nul, Err(StoreError::InvalidChunk)));
    assert_eq!(rows().await.len(), 2);

    let fill = "z".repeat(MAX_TRANSCRIPT_BYTES - 2 * MIN_CHUNK_COST_BYTES);
    let full = store
        .report_plain(id, job.attempt, &claimer(1), "r", "p", &[chunk(3, &fill)])
        .await
        .unwrap();
    assert!(!full.transcript_truncated);
    let over = store
        .report_plain(
            id,
            job.attempt,
            &claimer(1),
            "r",
            "p",
            &[chunk(4, "x"), chunk(5, "y")],
        )
        .await
        .unwrap();
    assert!(over.transcript_truncated);
    assert_eq!(over.acked_through_seq, 5);
    let replay = store
        .report_plain(
            id,
            job.attempt,
            &claimer(1),
            "r",
            "p",
            &[chunk(4, "x"), chunk(6, "w")],
        )
        .await
        .unwrap();
    assert!(replay.transcript_truncated);
    assert_eq!(replay.acked_through_seq, 6);
    let stored = rows().await;
    assert_eq!(stored.len(), 4);
    assert_eq!(stored.iter().filter(|row| row.2).count(), 1);
    assert_eq!(
        (stored[3].0, stored[3].1.as_str(), stored[3].2),
        (4, "", true)
    );
    let bytes: i64 = sqlx::query_scalar("SELECT transcript_bytes FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bytes, i64::try_from(MAX_TRANSCRIPT_BYTES).unwrap());
}

#[sqlx::test]
async fn report_cuts_progress_and_phase(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let progress = "\u{e9}".repeat(MAX_PROGRESS_CHARS + 50);
    let phase = "P".repeat(MAX_PHASE_CHARS + 50);
    store
        .report_plain(
            &job.job_id,
            job.attempt,
            &claimer(1),
            &phase,
            &progress,
            &[],
        )
        .await
        .unwrap();
    let (phase, progress): (String, String) = sqlx::query_as("SELECT phase, progress FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(phase.chars().count(), MAX_PHASE_CHARS);
    assert_eq!(progress.chars().count(), MAX_PROGRESS_CHARS);
}

async fn row_state(pool: &PgPool) -> (String, bool, bool) {
    sqlx::query_as("SELECT state, cancel_requested, finished_at IS NOT NULL FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn cancel_queued_is_immediate(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = store.submit_job(&request("c1")).await.unwrap();
    let cancelled = timeout(WAIT, store.cancel_job(&job.job_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancelled.state, i32::from(JobState::Cancelled));
    assert!(cancelled.finished_at_ms.is_some());
    assert_eq!(
        row_state(&pool).await,
        ("CANCELLED".to_owned(), false, true)
    );
    assert!(store.claim_job(&boxed(1)).await.unwrap().is_none());
    let again = store.cancel_job(&job.job_id).await.unwrap();
    assert_eq!(again, cancelled);
}

#[sqlx::test]
async fn cancel_running_sets_flag(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let flagged = timeout(WAIT, store.cancel_job(&job.job_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flagged.state, i32::from(JobState::Running));
    assert!(flagged.cancel_requested);
    assert_eq!(flagged.finished_at_ms, None);
    assert_eq!(row_state(&pool).await, ("RUNNING".to_owned(), true, false));
    let reply = store
        .report_plain(&job.job_id, job.attempt, &claimer(1), "r", "p", &[])
        .await
        .unwrap();
    assert!(reply.cancel_requested);
}

#[sqlx::test]
async fn cancel_terminal_is_unchanged_and_unknown_is_not_found(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED', finished_at = now()")
        .execute(&pool)
        .await
        .unwrap();
    let kept = store.cancel_job(&job.job_id).await.unwrap();
    assert_eq!(kept.state, i32::from(JobState::Succeeded));
    assert!(!kept.cancel_requested);
    assert_eq!(
        row_state(&pool).await,
        ("SUCCEEDED".to_owned(), false, true)
    );
    let secret = "s3cret-id";
    let err = store.cancel_job(secret).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
    assert!(!format!("{err} {err:?}").contains(secret));
}

fn terminal(job: &fleet_proto::v1::Job, state: JobState) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job.job_id.clone(),
        attempt: job.attempt,
        r#box: claimer(1),
        phase: "done".to_owned(),
        progress: "end".to_owned(),
        terminal_state: Some(state.into()),
        ..ReportJobRequest::default()
    }
}

#[sqlx::test]
async fn terminal_report_ends_job_once(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let mut report = terminal(&job, JobState::Succeeded);
    report.pr_url = Some("https://example.com/org/repo/pull/1".to_owned());
    report.exit_code = Some(0);
    report.chunks = vec![chunk(1, "last")];
    timeout(WAIT, store.report_job(&boxed(1), &report))
        .await
        .unwrap()
        .unwrap();
    let (state, pr, err, code, finished): (
        String,
        Option<String>,
        Option<String>,
        Option<i32>,
        bool,
    ) = sqlx::query_as("SELECT state, pr_url, error, exit_code, finished_at IS NOT NULL FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "SUCCEEDED");
    assert_eq!(pr.as_deref(), Some("https://example.com/org/repo/pull/1"));
    assert_eq!((err, code, finished), (None, Some(0), true));
    let again = store
        .report_job(&boxed(1), &terminal(&job, JobState::Failed))
        .await;
    assert!(matches!(again, Err(StoreError::StaleReport)));
    let state: String = sqlx::query_scalar("SELECT state FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "SUCCEEDED");
}

#[sqlx::test]
async fn terminal_failed_and_cancelled_store_error_and_code(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let mut report = terminal(&job, JobState::Failed);
    report.error = Some("e".repeat(MAX_ERROR_CHARS + 50));
    report.exit_code = Some(2);
    store.report_job(&boxed(1), &report).await.unwrap();
    let (state, err, code): (String, String, i32) =
        sqlx::query_as("SELECT state, error, exit_code FROM jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "FAILED");
    assert_eq!(err.chars().count(), MAX_ERROR_CHARS);
    assert_eq!(code, 2);
    sqlx::query("UPDATE jobs SET state = 'RUNNING', finished_at = NULL")
        .execute(&pool)
        .await
        .unwrap();
    let unrequested = store
        .report_job(&boxed(1), &terminal(&job, JobState::Cancelled))
        .await;
    assert!(matches!(unrequested, Err(StoreError::StaleReport)));
    assert_eq!(row_state(&pool).await, ("RUNNING".to_owned(), false, false));
    store.cancel_job(&job.job_id).await.unwrap();
    store
        .report_job(&boxed(1), &terminal(&job, JobState::Cancelled))
        .await
        .unwrap();
    assert_eq!(row_state(&pool).await, ("CANCELLED".to_owned(), true, true));
}

#[sqlx::test]
async fn terminal_branch_with_swarm_prefix_is_stored(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let mut report = terminal(&job, JobState::Succeeded);
    report.branch = Some(format!("swarm/{}", job.job_id));
    report.pr_url = Some("https://example.com/org/repo/pull/2?x=1#y".to_owned());
    store.report_job(&boxed(1), &report).await.unwrap();
    let branch: Option<String> = sqlx::query_scalar("SELECT branch FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(branch, report.branch);
}

#[sqlx::test]
async fn terminal_branch_of_another_job_is_refused(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    for branch in [
        "swarm/01J8ZOTHERJOB".to_owned(),
        "swarm/".to_owned(),
        format!("swarm/{}x", job.job_id),
        format!("swarm/{}/y", job.job_id),
    ] {
        let mut report = terminal(&job, JobState::Succeeded);
        report.branch = Some(branch);
        let err = store.report_job(&boxed(1), &report).await.unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidJob(JobInvalid::Branch)),
            "{err}"
        );
    }
    assert_eq!(row_state(&pool).await, ("RUNNING".to_owned(), false, false));
}

async fn stored_rows(pool: &PgPool) -> Vec<(i64, String, bool)> {
    sqlx::query_as("SELECT seq, chunk, truncated FROM job_transcript ORDER BY seq")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn report_chunk_limits_reject_the_whole_report(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let id = job.job_id.as_str();
    let name = claimer(1);
    let many: Vec<_> = (1..=u64::try_from(MAX_CHUNKS_PER_REPORT).unwrap() + 1)
        .map(|seq| chunk(seq, "x"))
        .collect();
    let bad = [
        many.clone(),
        vec![chunk(0, "x")],
        vec![chunk(1, "ok"), chunk(3, "x"), chunk(2, "y")],
        vec![chunk(1, "ok"), chunk(1, "dup")],
        vec![chunk(1, "ok"), chunk(u64::MAX, "x")],
    ];
    for chunks in &bad {
        let err = store
            .report_plain(id, job.attempt, &name, "r", "p", chunks)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidChunk));
    }
    assert_eq!(stored_rows(&pool).await, Vec::<(i64, String, bool)>::new());
    let exact = store
        .report_plain(
            id,
            job.attempt,
            &name,
            "r",
            "p",
            &many[..MAX_CHUNKS_PER_REPORT],
        )
        .await
        .unwrap();
    assert_eq!(
        exact.acked_through_seq,
        u64::try_from(MAX_CHUNKS_PER_REPORT).unwrap()
    );
    assert_eq!(stored_rows(&pool).await.len(), MAX_CHUNKS_PER_REPORT);
}

#[sqlx::test]
async fn ack_covers_only_the_contiguous_stored_prefix(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let id = job.job_id.as_str();
    let name = claimer(1);
    let ack = |chunks: Vec<TranscriptChunk>| {
        let store = &store;
        let name = &name;
        async move {
            store
                .report_plain(id, job.attempt, name, "r", "p", &chunks)
                .await
                .unwrap()
                .acked_through_seq
        }
    };
    assert_eq!(ack(vec![chunk(2, "b")]).await, 0);
    assert_eq!(ack(vec![chunk(4, "d"), chunk(5, "e")]).await, 0);
    assert_eq!(ack(vec![chunk(1, "a")]).await, 2);
    assert_eq!(ack(Vec::new()).await, 2);
    assert_eq!(ack(vec![chunk(3, "c")]).await, 5);
    assert_eq!(ack(vec![chunk(9, "i")]).await, 5);
    assert_eq!(stored_rows(&pool).await.len(), 6);
}

#[sqlx::test]
async fn empty_chunks_are_charged_the_minimum(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let near = i64::try_from(MAX_TRANSCRIPT_BYTES - MIN_CHUNK_COST_BYTES).unwrap();
    sqlx::query("UPDATE jobs SET transcript_bytes = $1")
        .bind(near)
        .execute(&pool)
        .await
        .unwrap();
    let reply = store
        .report_plain(
            &job.job_id,
            job.attempt,
            &claimer(1),
            "r",
            "p",
            &[chunk(1, ""), chunk(2, ""), chunk(3, "")],
        )
        .await
        .unwrap();
    assert!(reply.transcript_truncated);
    assert_eq!(reply.acked_through_seq, 3);
    assert_eq!(
        stored_rows(&pool).await,
        [(1, String::new(), false), (2, String::new(), true)]
    );
    let bytes: i64 = sqlx::query_scalar("SELECT transcript_bytes FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bytes, i64::try_from(MAX_TRANSCRIPT_BYTES).unwrap());
}

#[sqlx::test]
async fn transcript_rows_are_capped(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    sqlx::query(
        "INSERT INTO job_transcript (job_id, seq, ts_ms, chunk) \
         SELECT $1, g, 1, '' FROM generate_series(1, $2::bigint) g",
    )
    .bind(&job.job_id)
    .bind(MAX_TRANSCRIPT_ROWS)
    .execute(&pool)
    .await
    .unwrap();
    let next = u64::try_from(MAX_TRANSCRIPT_ROWS).unwrap() + 1;
    let reply = store
        .report_plain(
            &job.job_id,
            job.attempt,
            &claimer(1),
            "r",
            "p",
            &[chunk(next, "x"), chunk(next + 1, "y")],
        )
        .await
        .unwrap();
    assert!(reply.transcript_truncated);
    assert_eq!(reply.acked_through_seq, next + 1);
    let last: (i64, String, bool) = sqlx::query_as(
        "SELECT seq, chunk, truncated FROM job_transcript ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(last, (i64::try_from(next).unwrap(), String::new(), true));
}

#[sqlx::test]
async fn invalid_terminal_report_is_refused_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let secret = "s3cret-field";
    let mut cases = Vec::new();
    for state in [
        JobState::Running,
        JobState::Queued,
        JobState::Lost,
        JobState::Unspecified,
    ] {
        cases.push(terminal(&job, state));
    }
    let mut bad = terminal(&job, JobState::Succeeded);
    bad.terminal_state = Some(99);
    cases.push(bad);
    for url in [
        format!("http://{secret}"),
        format!("https://{secret} x"),
        format!("https://{}", "u".repeat(MAX_PR_URL_BYTES)),
        "https://".to_owned(),
    ] {
        let mut bad = terminal(&job, JobState::Succeeded);
        bad.pr_url = Some(url);
        cases.push(bad);
    }
    let mut bad = terminal(&job, JobState::Failed);
    bad.error = Some(format!("{secret}\0"));
    cases.push(bad);
    for url in [
        format!("https://{secret}@phish.example/x"),
        format!("https://user:{secret}@phish.example/x"),
        format!("https://example.com\\{secret}"),
        format!("https://example.com/a\\{secret}"),
    ] {
        let mut bad = terminal(&job, JobState::Succeeded);
        bad.pr_url = Some(url);
        cases.push(bad);
    }
    for branch in [
        format!("{secret} x"),
        format!("swarm/{secret} x"),
        format!("main-{secret}"),
        format!("-swarm/{secret}"),
        format!("--upload-pack={secret}"),
        format!("-{secret}"),
        format!("swarm/{}", "b".repeat(MAX_BRANCH_BYTES)),
    ] {
        let mut bad = terminal(&job, JobState::Failed);
        bad.branch = Some(branch);
        cases.push(bad);
    }
    for report in &cases {
        let err = store.report_job(&boxed(1), report).await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidJob(_)), "{err}");
        assert!(!format!("{err} {err:?}").contains(secret));
    }
    assert_eq!(row_state(&pool).await, ("RUNNING".to_owned(), false, false));
}

#[sqlx::test]
async fn progress_report_ignores_result_fields(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    let mut report = terminal(&job, JobState::Succeeded);
    report.terminal_state = None;
    report.pr_url = Some("https://example.com/x".to_owned());
    report.exit_code = Some(7);
    store.report_job(&boxed(1), &report).await.unwrap();
    let (state, pr, code): (String, Option<String>, Option<i32>) =
        sqlx::query_as("SELECT state, pr_url, exit_code FROM jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((state.as_str(), pr, code), ("RUNNING", None, None));
}

async fn lost_row(pool: &PgPool) -> (String, Option<String>, bool) {
    sqlx::query_as("SELECT state, error, finished_at IS NOT NULL FROM jobs")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn expired_lease_becomes_lost(pool: PgPool) {
    let store = store(pool.clone()).await.with_lease(Duration::from_secs(3));
    let job = claimed(&store, &claimer(1)).await;
    let reaped = Notify::new();
    let (stop_tx, stop_rx) = watch::channel(false);
    let run = run_reaper(
        store.clone(),
        Duration::from_millis(100),
        stop_rx,
        Some(&reaped),
    );
    let check = async {
        assert!(
            timeout(Duration::from_millis(300), reaped.notified())
                .await
                .is_err()
        );
        assert_eq!(lost_row(&pool).await.0, "RUNNING");
        timeout(Duration::from_secs(10), reaped.notified())
            .await
            .unwrap();
        stop_tx.send(true).unwrap();
    };
    tokio::join!(run, check);
    assert_eq!(
        lost_row(&pool).await,
        ("LOST".to_owned(), Some("lease expired".to_owned()), true)
    );
    let late = store
        .report_plain(
            &job.job_id,
            job.attempt,
            &claimer(1),
            "running",
            "late",
            &[],
        )
        .await;
    assert!(matches!(late, Err(StoreError::StaleReport)));
    assert!(store.claim_job(&boxed(2)).await.unwrap().is_none());
}

#[sqlx::test]
async fn reap_spares_live_and_finished_jobs(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store, &claimer(1)).await;
    assert_eq!(store.reap_expired().await.unwrap(), 0);
    store
        .report_job(&boxed(1), &terminal(&job, JobState::Succeeded))
        .await
        .unwrap();
    set_lease_in_past(&pool).await;
    assert_eq!(store.reap_expired().await.unwrap(), 0);
    assert_eq!(lost_row(&pool).await.0, "SUCCEEDED");
    sqlx::query("UPDATE jobs SET state = 'RUNNING', finished_at = NULL")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(store.reap_expired().await.unwrap(), 1);
    assert_eq!(store.reap_expired().await.unwrap(), 0);
}

#[test]
fn backoff_doubles_and_caps() {
    let period = Duration::from_millis(10);
    let first = backoff_after(None, period);
    assert_eq!(first, period);
    let second = backoff_after(Some(first), period);
    assert_eq!(second, Duration::from_millis(20));
    assert_eq!(backoff_after(Some(MAX_BACKOFF), period), MAX_BACKOFF);
    let mut wait = None;
    for _ in 0..40 {
        wait = Some(backoff_after(wait, period));
    }
    assert_eq!(wait, Some(MAX_BACKOFF));
    let slow = MAX_BACKOFF + Duration::from_secs(1);
    assert_eq!(backoff_after(None, slow), slow);
}

#[sqlx::test]
async fn a_failing_pass_logs_a_kind_and_the_loop_stops_on_request(pool: PgPool) {
    let store = store(pool.clone()).await;
    pool.close().await;
    let err = store.reap_expired().await.unwrap_err();
    assert_eq!(error_kind(&err), "pool_closed");
    let (stop_tx, stop_rx) = watch::channel(false);
    let run = run_reaper(store, Duration::from_millis(10), stop_rx, None);
    let check = async {
        tokio::task::yield_now().await;
        stop_tx.send(true).unwrap();
    };
    timeout(Duration::from_secs(5), async { tokio::join!(run, check) })
        .await
        .unwrap();
}
