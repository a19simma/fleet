//! Owner-only reads: every read RPC scopes to the caller and answers one fixed `NOT_FOUND`
//! for another user's job and for an unknown id. The tests call the handlers directly with a
//! [`Caller`] extension. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_batches_server::FleetBatches;
use fleet_proto::v1::fleet_jobs_server::FleetJobs;
use fleet_proto::v1::fleet_judge_server::FleetJudge;
use fleet_proto::v1::{
    GetBatchRequest, GetJobRequest, ListJobsRequest, ReadJobEventsRequest, ReadTranscriptRequest,
    SubmitBatchRequest, SubmitJobRequest, SubmitJudgeRequest,
};
use fleet_server::auth::Caller;
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request, Status};

const REPO: &str = "https://example.com/org/repo.git";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const PROFILE: &str = r#"{"claude_md":"one"}"#;
const UNKNOWN: &str = "00000000000000000000000000";

struct World {
    svc: FleetService,
    alice: i64,
    bob: i64,
    job: String,
    batch: String,
}

fn as_user<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(Caller { user_id });
    request
}

fn job_request(key: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
    }
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world(pool: PgPool) -> World {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let job = store
        .submit_job_for(Some(alice), &job_request("alice-job"))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&job.job_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO job_transcript (job_id, seq, ts_ms, chunk, truncated) VALUES ($1, 1, 1, 'secret', false)",
    )
    .bind(&job.job_id)
    .execute(&pool)
    .await
    .unwrap();
    store.create_profile("alpha", PROFILE).await.unwrap();
    let batch = store
        .submit_batch_for(
            Some(alice),
            &SubmitBatchRequest {
                idempotency_key: "alice-batch".to_owned(),
                prompt: "fix".to_owned(),
                repo: REPO.to_owned(),
                base_sha: SHA.to_owned(),
                repeats: 0,
                profiles: vec!["alpha".to_owned()],
            },
        )
        .await
        .unwrap();
    World {
        svc: FleetService::new(store),
        alice,
        bob,
        job: job.job_id,
        batch: batch.batch_id,
    }
}

fn assert_hidden(status: &Status, fixed: &str) {
    assert_eq!(status.code(), Code::NotFound, "{status:?}");
    assert_eq!(status.message(), fixed);
}

async fn get_job(w: &World, who: Option<i64>, id: &str) -> Result<(), Status> {
    let message = GetJobRequest {
        job_id: id.to_owned(),
    };
    let request = match who {
        Some(u) => as_user(u, message),
        None => Request::new(message),
    };
    w.svc.get_job(request).await.map(|_| ())
}

#[sqlx::test]
async fn get_job_is_owner_only(pool: PgPool) {
    let w = world(pool).await;
    get_job(&w, Some(w.alice), &w.job).await.unwrap();
    get_job(&w, None, &w.job).await.unwrap();
    let other = get_job(&w, Some(w.bob), &w.job).await.unwrap_err();
    let unknown = get_job(&w, Some(w.bob), UNKNOWN).await.unwrap_err();
    assert_hidden(&other, "job not found");
    assert_hidden(&unknown, "job not found");
}

#[sqlx::test]
async fn list_jobs_shows_the_callers_own_only(pool: PgPool) {
    let w = world(pool).await;
    let list = |u: Option<i64>| {
        let message = ListJobsRequest {
            state: None,
            limit: 0,
        };
        u.map_or_else(|| Request::new(message), |u| as_user(u, message))
    };
    let own = w.svc.list_jobs(list(Some(w.alice))).await.unwrap();
    let own = own.into_inner().jobs;
    assert!(own.iter().any(|j| j.job_id == w.job));
    assert!(own.iter().all(|j| i64::try_from(j.user_id) == Ok(w.alice)));
    let theirs = w.svc.list_jobs(list(Some(w.bob))).await.unwrap();
    assert_eq!(theirs.into_inner().jobs.len(), 0);
    let all = w.svc.list_jobs(list(None)).await.unwrap();
    assert!(all.into_inner().jobs.iter().any(|j| j.job_id == w.job));
}

#[sqlx::test]
async fn read_transcript_is_owner_only(pool: PgPool) {
    let w = world(pool).await;
    let read = |u: i64, id: &str| {
        as_user(
            u,
            ReadTranscriptRequest {
                job_id: id.to_owned(),
                after_seq: 0,
                limit: 0,
            },
        )
    };
    let own = w.svc.read_transcript(read(w.alice, &w.job)).await.unwrap();
    assert_eq!(own.into_inner().chunks.len(), 1);
    let other = w
        .svc
        .read_transcript(read(w.bob, &w.job))
        .await
        .unwrap_err();
    let unknown = w
        .svc
        .read_transcript(read(w.bob, UNKNOWN))
        .await
        .unwrap_err();
    assert_hidden(&other, "job not found");
    assert_hidden(&unknown, "job not found");
}

#[sqlx::test]
async fn read_job_events_is_owner_only(pool: PgPool) {
    let w = world(pool).await;
    let read = |u: i64, id: &str| {
        as_user(
            u,
            ReadJobEventsRequest {
                job_id: id.to_owned(),
                after_seq: None,
                limit: 0,
            },
        )
    };
    w.svc.read_job_events(read(w.alice, &w.job)).await.unwrap();
    let other = w
        .svc
        .read_job_events(read(w.bob, &w.job))
        .await
        .unwrap_err();
    let unknown = w
        .svc
        .read_job_events(read(w.bob, UNKNOWN))
        .await
        .unwrap_err();
    assert_hidden(&other, "job not found");
    assert_hidden(&unknown, "job not found");
}

#[sqlx::test]
async fn get_batch_is_owner_only(pool: PgPool) {
    let w = world(pool).await;
    let get = |u: i64, id: &str| {
        as_user(
            u,
            GetBatchRequest {
                batch_id: id.to_owned(),
            },
        )
    };
    let own = w.svc.get_batch(get(w.alice, &w.batch)).await.unwrap();
    assert_eq!(own.into_inner().jobs.len(), 1);
    let other = w.svc.get_batch(get(w.bob, &w.batch)).await.unwrap_err();
    let unknown = w.svc.get_batch(get(w.bob, UNKNOWN)).await.unwrap_err();
    assert_hidden(&other, "batch not found");
    assert_hidden(&unknown, "batch not found");
}

#[sqlx::test]
async fn a_judge_may_target_only_an_owned_job(pool: PgPool) {
    let w = world(pool).await;
    let judge = |u: i64, key: &str, target: &str| {
        as_user(
            u,
            SubmitJudgeRequest {
                idempotency_key: key.to_owned(),
                prompt: "grade".to_owned(),
                target_job_id: target.to_owned(),
            },
        )
    };
    let other = w
        .svc
        .submit_judge(judge(w.bob, "b1", &w.job))
        .await
        .unwrap_err();
    let unknown = w
        .svc
        .submit_judge(judge(w.bob, "b2", UNKNOWN))
        .await
        .unwrap_err();
    assert_hidden(&other, "job not found");
    assert_hidden(&unknown, "job not found");
    let own = w
        .svc
        .submit_judge(judge(w.alice, "a1", &w.job))
        .await
        .unwrap();
    assert_eq!(
        own.into_inner().target_job_id.as_deref(),
        Some(w.job.as_str())
    );
}

#[sqlx::test]
async fn a_batch_lists_only_the_callers_jobs(pool: PgPool) {
    let w = world(pool.clone()).await;
    let store = Store::new(pool.clone());
    store.create_profile("beta", PROFILE).await.unwrap();
    let batch = store
        .submit_batch_for(
            Some(w.alice),
            &SubmitBatchRequest {
                idempotency_key: "mixed".to_owned(),
                prompt: "fix".to_owned(),
                repo: REPO.to_owned(),
                base_sha: SHA.to_owned(),
                repeats: 0,
                profiles: vec!["alpha".to_owned(), "beta".to_owned()],
            },
        )
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET user_id = $2 WHERE batch_id = $1 AND profile_name = 'beta'")
        .bind(&batch.batch_id)
        .bind(w.bob)
        .execute(&pool)
        .await
        .unwrap();
    let get = |u: i64| {
        as_user(
            u,
            GetBatchRequest {
                batch_id: batch.batch_id.clone(),
            },
        )
    };
    let alice = w.svc.get_batch(get(w.alice)).await.unwrap().into_inner();
    let bob = w.svc.get_batch(get(w.bob)).await.unwrap().into_inner();
    assert_eq!(alice.jobs.len(), 1);
    assert_eq!(bob.jobs.len(), 1);
    assert_ne!(alice.jobs[0].job_id, bob.jobs[0].job_id);
}
