//! Ownership of per-Box tokens (ADR-0069): a bound token claims only its user's jobs and
//! releases credentials and environments only for them. The tests need a Postgres superuser
//! URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_core::BoxName;
use fleet_proto::v1::fleet_worker_server::FleetWorker;
use fleet_proto::v1::{
    ClaimJobRequest, GetJobCredentialsRequest, GetJobEnvironmentRequest, SubmitJobRequest,
    SubmitJudgeRequest,
};
use fleet_server::auth::BoxCaller;
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request};

fn name(n: u32) -> String {
    format!("box-{n}")
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

async fn store(pool: &PgPool) -> Store {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    store
}

fn bound<T>(user_id: i64, box_name: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(BoxCaller {
        token_id: 1,
        user_id,
        box_name: box_name.to_owned(),
    });
    request
}

#[sqlx::test]
async fn claim_takes_only_the_owners_jobs(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let first = store
        .submit_job_for(Some(alice), &submit("a"))
        .await
        .unwrap();
    let second = store.submit_job_for(Some(bob), &submit("b")).await.unwrap();
    let worker = BoxName::new(&name(1)).unwrap();
    let got = store
        .claim_job_for(&worker, Some(bob))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.job_id, second.job_id);
    assert!(
        store
            .claim_job_for(&worker, Some(bob))
            .await
            .unwrap()
            .is_none()
    );
    let got = store.claim_job_for(&worker, None).await.unwrap().unwrap();
    assert_eq!(got.job_id, first.job_id);
}

#[sqlx::test]
async fn claim_rpc_filters_by_the_bound_user(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    store
        .submit_job_for(Some(alice), &submit("a"))
        .await
        .unwrap();
    let svc = FleetService::new(store.clone());
    let reply = svc
        .claim_job(bound(bob, &name(1), ClaimJobRequest { r#box: name(1) }))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.job.is_none());
    let reply = svc
        .claim_job(bound(alice, &name(1), ClaimJobRequest { r#box: name(1) }))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.job.is_some());
}

#[sqlx::test]
async fn release_refuses_a_job_of_another_user(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let job = store
        .submit_job_for(Some(alice), &submit("a"))
        .await
        .unwrap();
    let svc = FleetService::new(store);
    let credentials = |user_id: i64| {
        bound(
            user_id,
            &name(1),
            GetJobCredentialsRequest {
                r#box: name(1),
                job_id: job.job_id.clone(),
                attempt: 1,
            },
        )
    };
    let environment = |user_id: i64| {
        bound(
            user_id,
            &name(1),
            GetJobEnvironmentRequest {
                r#box: name(1),
                job_id: job.job_id.clone(),
                attempt: 1,
            },
        )
    };
    let denied = svc.get_job_credentials(credentials(bob)).await.unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(denied.message(), fleet_proto::ERR_LEASE_MISMATCH);
    let denied = svc.get_job_environment(environment(bob)).await.unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(denied.message(), fleet_proto::ERR_LEASE_MISMATCH);
    let own = svc
        .get_job_credentials(credentials(alice))
        .await
        .unwrap_err();
    assert_eq!(own.code(), Code::FailedPrecondition);
    let own = svc
        .get_job_environment(environment(alice))
        .await
        .unwrap_err();
    assert_eq!(own.code(), Code::FailedPrecondition);
    let unknown = svc
        .get_job_credentials(bound(
            alice,
            &name(1),
            GetJobCredentialsRequest {
                r#box: name(1),
                job_id: "00000000000000000000000000".to_owned(),
                attempt: 1,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), Code::PermissionDenied);
}

#[sqlx::test]
async fn a_static_judge_submit_inherits_the_target_owner(pool: PgPool) {
    let store = store(&pool).await;
    let alice = user(&pool, "alice").await;
    let target = store
        .submit_job_for(Some(alice), &submit("a"))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&target.job_id)
        .execute(&pool)
        .await
        .unwrap();
    let judge = store
        .submit_judge(&SubmitJudgeRequest {
            idempotency_key: "j".to_owned(),
            prompt: "p".to_owned(),
            target_job_id: target.job_id.clone(),
        })
        .await
        .unwrap();
    let owner: i64 = sqlx::query_scalar("SELECT user_id FROM jobs WHERE job_id = $1")
        .bind(&judge.job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(owner, alice);
}
