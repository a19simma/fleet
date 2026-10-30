//! Owner-only reads: every read RPC scopes to the caller and answers one fixed `NOT_FOUND`
//! for another user's job and for an unknown id. The tests call the handlers directly with a
//! [`Caller`] extension. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_batches_server::FleetBatches;
use fleet_proto::v1::fleet_jobs_server::FleetJobs;
use fleet_proto::v1::fleet_judge_server::FleetJudge;
use fleet_proto::v1::fleet_query_server::FleetQuery;
use fleet_proto::v1::{
    CancelJobRequest, GetBatchRequest, GetJobRequest, GetStatsRequest, JobState, ListFleetRequest,
    ListJobsRequest, ReadJobEventsRequest, ReadTranscriptRequest, StatsGroupBy, SubmitBatchRequest,
    SubmitJobRequest, SubmitJudgeRequest,
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

async fn seed_stats(w: &World, pool: &PgPool) -> String {
    sqlx::query("UPDATE jobs SET box = 'box-a', state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&w.job)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO job_summary (job_id, cost_est_usd, complete, missing) \
         VALUES ($1, 12.5, true, '{}')",
    )
    .bind(&w.job)
    .execute(pool)
    .await
    .unwrap();
    "box-a".to_owned()
}

fn stats_request(
    group_by: StatsGroupBy,
    repo: Option<&str>,
    box_name: Option<&str>,
) -> GetStatsRequest {
    GetStatsRequest {
        since: None,
        until: None,
        repo: repo.map(str::to_owned),
        r#box: box_name.map(str::to_owned),
        group_by: group_by.into(),
    }
}

const GROUPINGS: [StatsGroupBy; 8] = [
    StatsGroupBy::None,
    StatsGroupBy::Repo,
    StatsGroupBy::Box,
    StatsGroupBy::State,
    StatsGroupBy::Day,
    StatsGroupBy::BundleSha,
    StatsGroupBy::ClaudeVersion,
    StatsGroupBy::Model,
];

#[sqlx::test]
async fn get_stats_aggregates_only_the_callers_jobs(pool: PgPool) {
    let w = world(pool.clone()).await;
    let box_name = seed_stats(&w, &pool).await;
    for group in GROUPINGS {
        let mine = w
            .svc
            .get_stats(as_user(w.alice, stats_request(group, None, None)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            mine.groups.iter().map(|g| g.jobs).sum::<u64>(),
            2,
            "{group:?}"
        );
        let theirs = w
            .svc
            .get_stats(as_user(w.bob, stats_request(group, None, None)))
            .await
            .unwrap()
            .into_inner();
        assert!(theirs.groups.is_empty(), "{group:?} {theirs:?}");
        let probe = w
            .svc
            .get_stats(as_user(
                w.bob,
                stats_request(group, Some(REPO), Some(&box_name)),
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(probe.groups.is_empty(), "{group:?} {probe:?}");
        let repo_probe = w
            .svc
            .get_stats(as_user(w.bob, stats_request(group, Some(REPO), None)))
            .await
            .unwrap()
            .into_inner();
        assert!(repo_probe.groups.is_empty(), "{group:?}");
        let box_probe = w
            .svc
            .get_stats(as_user(w.bob, stats_request(group, None, Some(&box_name))))
            .await
            .unwrap()
            .into_inner();
        assert!(box_probe.groups.is_empty(), "{group:?}");
    }
    let all = w
        .svc
        .get_stats(Request::new(stats_request(StatsGroupBy::Repo, None, None)))
        .await
        .unwrap()
        .into_inner();
    let cost = all.groups[0].cost_est_usd.as_ref().unwrap().sum;
    assert!((cost - 12.5).abs() < f64::EPSILON);
    let bob_cost = w
        .svc
        .get_stats(as_user(
            w.bob,
            stats_request(StatsGroupBy::Repo, None, None),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(bob_cost.groups.iter().all(|g| g.cost_est_usd.is_none()));
}

#[sqlx::test]
async fn cancel_job_is_owner_only(pool: PgPool) {
    let w = world(pool).await;
    let queued = w
        .svc
        .submit_job(as_user(w.alice, job_request("alice-queued")))
        .await
        .unwrap()
        .into_inner();
    let cancel = |u: i64, id: &str| {
        as_user(
            u,
            CancelJobRequest {
                job_id: id.to_owned(),
            },
        )
    };
    let other = w
        .svc
        .cancel_job(cancel(w.bob, &queued.job_id))
        .await
        .unwrap_err();
    let unknown = w.svc.cancel_job(cancel(w.bob, UNKNOWN)).await.unwrap_err();
    assert_hidden(&other, "job not found");
    assert_hidden(&unknown, "job not found");
    let kept = w
        .svc
        .get_job(as_user(
            w.alice,
            GetJobRequest {
                job_id: queued.job_id.clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(kept.state, JobState::Queued as i32);
    let own = w
        .svc
        .cancel_job(cancel(w.alice, &queued.job_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(own.state, JobState::Cancelled as i32);
}

#[sqlx::test]
async fn list_fleet_blanks_session_text_for_other_users(pool: PgPool) {
    let w = world(pool.clone()).await;
    sqlx::query(
        "INSERT INTO boxes (box, hostname, machine_id, boot_id) VALUES ('box-a', 'h', 'm', 'b')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sessions (box, session_id, state, state_at, workdir, last_prompt, \
         last_message, last_event_at, last_event_kind, state_event_at) \
         VALUES ('box-a', 's1', 'idle', now(), '/work/secret', 'private prompt', \
         'private reply', now(), 'stop', now())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let bootstrap: i64 = sqlx::query_scalar("SELECT bootstrap_user_id()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let list = |request: Request<ListFleetRequest>| {
        let svc = w.svc.clone();
        async move { svc.list_fleet(request).await.unwrap().into_inner().boxes }
    };
    let session = |boxes: Vec<fleet_proto::v1::BoxView>| {
        assert_eq!(boxes.len(), 1);
        let mut sessions = boxes.into_iter().next().unwrap().sessions;
        assert_eq!(sessions.len(), 1);
        sessions.remove(0)
    };
    let legacy = session(list(Request::new(ListFleetRequest::default())).await);
    assert_eq!(legacy.last_prompt.as_deref(), Some("private prompt"));
    assert_eq!(legacy.last_message.as_deref(), Some("private reply"));
    assert_eq!(legacy.workdir.as_deref(), Some("/work/secret"));
    let admin = session(list(as_user(bootstrap, ListFleetRequest::default())).await);
    assert_eq!(admin.last_prompt.as_deref(), Some("private prompt"));
    assert_eq!(admin.workdir.as_deref(), Some("/work/secret"));
    let bob = session(list(as_user(w.bob, ListFleetRequest::default())).await);
    assert_eq!(bob.session_id, "s1");
    assert_eq!(bob.last_prompt, None);
    assert_eq!(bob.last_message, None);
    assert_eq!(bob.workdir, None);
}

const CLASSIFIED: &[(&str, &str)] = &[
    ("FleetIngest", "PushEvents:box-only"),
    ("FleetIngest", "Heartbeat:box-only"),
    ("FleetQuery", "ListFleet:scoped-redacted"),
    ("FleetJobs", "SubmitJob:scoped"),
    ("FleetJobs", "GetJob:scoped"),
    ("FleetJobs", "ListJobs:scoped"),
    ("FleetJobs", "CancelJob:scoped"),
    ("FleetJobs", "ReadTranscript:scoped"),
    ("FleetJobs", "ReadJobEvents:scoped"),
    ("FleetJobs", "GetStats:scoped"),
    ("FleetProfiles", "CreateProfile:global"),
    ("FleetProfiles", "GetProfile:global"),
    ("FleetProfiles", "ListProfiles:global"),
    ("FleetJudge", "SubmitJudge:scoped"),
    ("FleetBatches", "SubmitBatch:scoped"),
    ("FleetBatches", "GetBatch:scoped"),
    ("FleetCredentials", "PutCredential:scoped"),
    ("FleetCredentials", "ListCredentials:scoped"),
    ("FleetCredentials", "DeleteCredential:scoped"),
    ("FleetCredentials", "VerifyCredential:scoped"),
    ("FleetWorker", "ClaimJob:box-only"),
    ("FleetWorker", "ReportJob:box-only"),
    ("FleetWorker", "GetProfileBlob:box-only"),
    ("FleetWorker", "GetJobTranscript:box-only"),
    ("FleetWorker", "GetJobCredentials:box-only"),
];

#[test]
fn every_rpc_in_the_proto_is_classified() {
    let proto = include_str!("../../fleet-proto/proto/fleet/v1/fleet.proto");
    let mut found = Vec::new();
    let mut service = "";
    for line in proto.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("service ") {
            service = rest.trim_end_matches('{').trim();
        } else if let Some(rest) = line.strip_prefix("rpc ") {
            let name = rest.split('(').next().unwrap().trim();
            found.push((service.to_owned(), name.to_owned()));
        }
    }
    let mut listed: Vec<(String, String)> = CLASSIFIED
        .iter()
        .map(|(s, entry)| ((*s).to_owned(), entry.split(':').next().unwrap().to_owned()))
        .collect();
    found.sort();
    listed.sort();
    assert_eq!(
        found, listed,
        "classify new RPCs in CLASSIFIED and ADR-0042"
    );
}

#[sqlx::test]
async fn get_stats_stuck_split_excludes_other_users(pool: PgPool) {
    let w = world(pool.clone()).await;
    seed_stats(&w, &pool).await;
    let theirs = w
        .svc
        .submit_job(as_user(w.bob, job_request("bob-job")))
        .await
        .unwrap()
        .into_inner();
    sqlx::query(
        "INSERT INTO job_summary (job_id, complete, missing, stuck_rule) \
         VALUES ($1, true, '{}', 'monologue')",
    )
    .bind(&theirs.job_id)
    .execute(&pool)
    .await
    .unwrap();
    let mine = w
        .svc
        .get_stats(as_user(
            w.alice,
            stats_request(StatsGroupBy::None, None, None),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(mine.groups.len(), 1);
    assert!(
        mine.groups[0].stuck_rules.is_empty(),
        "{:?}",
        mine.groups[0]
    );
    assert_eq!(mine.groups[0].stuck_jobs, 0);
}
