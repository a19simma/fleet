//! A per-Box token whose name was re-issued to another user cannot act on the first user's
//! leased job through any lease-bound worker RPC (ADR-0069). They need a Postgres superuser
//! URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_core::BoxName;
use fleet_proto::v1::fleet_worker_server::FleetWorker;
use fleet_proto::v1::{
    GetJobTranscriptRequest, GetProfileBlobRequest, ReportJobRequest, ReportShellLogRequest,
    ReportTimingRequest, ShellStatus, SubmitJobRequest, SubmitJudgeRequest, TimingSummary,
};
use fleet_server::auth::BoxCaller;
use fleet_server::cred::users::{BoxTokenLabel, BoxTokenTtl, Users};
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request};

fn bx() -> String {
    format!("box-{}", 1)
}

struct World {
    svc: FleetService,
    pool: PgPool,
    alice: i64,
    bob: i64,
    job: String,
}

fn submit(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "p".to_owned(),
        repo: "https://example.com/o/r.git".to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
        agent: String::new(),
        profile: String::new(),
        environment: String::new(),
    }
}

async fn user(pool: &PgPool, username: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(username)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn as_token<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(BoxCaller {
        token_id: 1,
        user_id,
        box_name: bx(),
    });
    request
}

async fn world(pool: PgPool, judge: bool) -> World {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let users = Users::new(pool.clone());
    let name = BoxName::new(&bx()).unwrap();
    let label = BoxTokenLabel::new("t").unwrap();
    let first = users
        .issue_box_token(alice, &name, &label, BoxTokenTtl::new(1).unwrap())
        .await
        .unwrap();
    users.revoke_box_token(alice, first.id).await.unwrap();
    users
        .issue_box_token(bob, &name, &label, BoxTokenTtl::new(1).unwrap())
        .await
        .unwrap();
    let mut job = store
        .submit_job_for(Some(alice), &submit("a"))
        .await
        .unwrap()
        .job_id;
    if judge {
        sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
            .bind(&job)
            .execute(&pool)
            .await
            .unwrap();
        job = store
            .submit_judge(&SubmitJudgeRequest {
                idempotency_key: "j".to_owned(),
                prompt: "p".to_owned(),
                target_job_id: job,
            })
            .await
            .unwrap()
            .job_id;
    }
    let claimed = store
        .claim_job_for(&name, Some(alice))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.job_id, job);
    World {
        svc: FleetService::new(store),
        pool,
        alice,
        bob,
        job,
    }
}

async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut out: Vec<String> =
        sqlx::query_scalar("SELECT to_jsonb(j)::text FROM jobs j ORDER BY job_id")
            .fetch_all(pool)
            .await
            .unwrap();
    let counts: String = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM job_timing) || '/' || (SELECT count(*) FROM job_timing_spans) \
         || '/' || (SELECT count(*) FROM job_shell_commands) \
         || '/' || (SELECT count(*) FROM job_shell_log_chunks) \
         || '/' || (SELECT count(*) FROM job_transcript)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    out.push(counts);
    out
}

fn denied<T: std::fmt::Debug>(result: Result<T, tonic::Status>) {
    let status = result.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    assert_eq!(status.message(), fleet_proto::ERR_LEASE_MISMATCH);
}

fn report_job(job: &str) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job.to_owned(),
        attempt: 1,
        r#box: bx(),
        phase: "run".to_owned(),
        progress: "x".to_owned(),
        ..ReportJobRequest::default()
    }
}

fn report_timing(job: &str) -> ReportTimingRequest {
    ReportTimingRequest {
        job_id: job.to_owned(),
        attempt: 1,
        r#box: bx(),
        summary: Some(TimingSummary::default()),
        ..ReportTimingRequest::default()
    }
}

fn report_log(job: &str) -> ReportShellLogRequest {
    ReportShellLogRequest {
        job_id: job.to_owned(),
        attempt: 1,
        r#box: bx(),
        command_id: "c1".to_owned(),
        seq: 0,
        bytes: b"x".to_vec(),
        status: ShellStatus::Running as i32,
    }
}

#[sqlx::test]
async fn report_job_refuses_a_reissued_name(pool: PgPool) {
    let w = world(pool, false).await;
    let before = snapshot(&w.pool).await;
    denied(w.svc.report_job(as_token(w.bob, report_job(&w.job))).await);
    assert_eq!(snapshot(&w.pool).await, before);
    w.svc
        .report_job(as_token(w.alice, report_job(&w.job)))
        .await
        .unwrap();
}

#[sqlx::test]
async fn report_timing_refuses_a_reissued_name(pool: PgPool) {
    let w = world(pool, false).await;
    let before = snapshot(&w.pool).await;
    denied(
        w.svc
            .report_timing(as_token(w.bob, report_timing(&w.job)))
            .await,
    );
    assert_eq!(snapshot(&w.pool).await, before);
    w.svc
        .report_timing(as_token(w.alice, report_timing(&w.job)))
        .await
        .unwrap();
}

#[sqlx::test]
async fn report_shell_log_refuses_a_reissued_name(pool: PgPool) {
    let w = world(pool, false).await;
    let before = snapshot(&w.pool).await;
    denied(
        w.svc
            .report_shell_log(as_token(w.bob, report_log(&w.job)))
            .await,
    );
    assert_eq!(snapshot(&w.pool).await, before);
    w.svc
        .report_shell_log(as_token(w.alice, report_log(&w.job)))
        .await
        .unwrap();
}

#[sqlx::test]
async fn get_profile_blob_refuses_a_reissued_name(pool: PgPool) {
    let w = world(pool, false).await;
    let request = |user_id| {
        as_token(
            user_id,
            GetProfileBlobRequest {
                job_id: w.job.clone(),
                attempt: 1,
                r#box: bx(),
            },
        )
    };
    denied(w.svc.get_profile_blob(request(w.bob)).await);
    let own = w.svc.get_profile_blob(request(w.alice)).await.unwrap_err();
    assert_ne!(own.message(), fleet_proto::ERR_LEASE_MISMATCH, "{own:?}");
}

#[sqlx::test]
async fn get_job_transcript_refuses_a_reissued_name(pool: PgPool) {
    let w = world(pool, true).await;
    let request = |user_id| {
        as_token(
            user_id,
            GetJobTranscriptRequest {
                job_id: w.job.clone(),
                attempt: 1,
                r#box: bx(),
            },
        )
    };
    denied(w.svc.get_job_transcript(request(w.bob)).await);
    w.svc.get_job_transcript(request(w.alice)).await.unwrap();
}
