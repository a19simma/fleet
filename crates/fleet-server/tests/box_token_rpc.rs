//! Per-Box token binding on every Box-scope RPC (ADR-0069): a request naming a Box other than
//! the bound one is refused before any work. The tests call the handlers directly and need a
//! Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_ingest_server::FleetIngest;
use fleet_proto::v1::fleet_worker_server::FleetWorker;
use fleet_proto::v1::{
    ClaimJobRequest, Envelope, GetJobCredentialsRequest, GetJobEnvironmentRequest,
    GetJobTranscriptRequest, GetProfileBlobRequest, HeartbeatRequest, PushEventsRequest,
    QueuedEvent, ReportJobRequest, ReportShellLogRequest, ReportTimingRequest, ShellStatus,
    SubmitJobRequest,
};
use fleet_server::auth::{BOX_MISMATCH, BoxCaller};
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request, Status};

fn name(n: u32) -> String {
    format!("box-{n}")
}

fn bound<T>(box_name: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(BoxCaller {
        token_id: 1,
        user_id: 1,
        box_name: box_name.to_owned(),
    });
    request
}

async fn service(pool: PgPool) -> FleetService {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    FleetService::new(store)
}

fn mismatch(result: Result<(), Status>) {
    let status = result.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(status.message(), BOX_MISMATCH);
}

fn not_mismatch(result: Result<(), Status>) {
    if let Err(status) = result {
        assert_ne!(status.message(), BOX_MISMATCH);
    }
}

fn event(box_name: &str) -> QueuedEvent {
    QueuedEvent {
        seq: 1,
        envelope: Some(Envelope {
            r#box: box_name.to_owned(),
            ..Envelope::default()
        }),
    }
}

async fn call(
    svc: &FleetService,
    rpc: usize,
    token: Option<&str>,
    requested: &str,
) -> Result<(), Status> {
    macro_rules! go {
        ($message:expr, $method:ident) => {{
            let request = match token {
                Some(bound_to) => bound(bound_to, $message),
                None => Request::new($message),
            };
            svc.$method(request).await.map(|_| ())
        }};
    }
    let job = "00000000000000000000000000".to_owned();
    let b = requested.to_owned();
    match rpc {
        0 => go!(
            PushEventsRequest {
                events: vec![event(requested), event(requested)]
            },
            push_events
        ),
        1 => go!(
            HeartbeatRequest {
                r#box: b,
                ..HeartbeatRequest::default()
            },
            heartbeat
        ),
        2 => go!(ClaimJobRequest { r#box: b }, claim_job),
        3 => go!(
            ReportJobRequest {
                r#box: b,
                job_id: job,
                ..ReportJobRequest::default()
            },
            report_job
        ),
        4 => go!(
            ReportTimingRequest {
                r#box: b,
                job_id: job,
                ..ReportTimingRequest::default()
            },
            report_timing
        ),
        5 => go!(
            ReportShellLogRequest {
                r#box: b,
                job_id: job,
                command_id: "c".to_owned(),
                status: ShellStatus::Running as i32,
                ..ReportShellLogRequest::default()
            },
            report_shell_log
        ),
        6 => go!(
            GetProfileBlobRequest {
                r#box: b,
                job_id: job,
                ..GetProfileBlobRequest::default()
            },
            get_profile_blob
        ),
        7 => go!(
            GetJobTranscriptRequest {
                r#box: b,
                job_id: job,
                ..GetJobTranscriptRequest::default()
            },
            get_job_transcript
        ),
        8 => go!(
            GetJobCredentialsRequest {
                r#box: b,
                job_id: job,
                ..GetJobCredentialsRequest::default()
            },
            get_job_credentials
        ),
        9 => go!(
            GetJobEnvironmentRequest {
                r#box: b,
                job_id: job,
                ..GetJobEnvironmentRequest::default()
            },
            get_job_environment
        ),
        _ => unreachable!(),
    }
}

const RPCS: [&str; 10] = [
    "PushEvents",
    "Heartbeat",
    "ClaimJob",
    "ReportJob",
    "ReportTiming",
    "ReportShellLog",
    "GetProfileBlob",
    "GetJobTranscript",
    "GetJobCredentials",
    "GetJobEnvironment",
];

#[sqlx::test]
async fn every_box_rpc_refuses_a_foreign_box(pool: PgPool) {
    let svc = service(pool).await;
    for (rpc, label) in RPCS.iter().enumerate() {
        let result = call(&svc, rpc, Some(&name(1)), &name(2)).await;
        let status = result.expect_err(label);
        assert_eq!(status.code(), Code::PermissionDenied, "{label}");
        assert_eq!(status.message(), BOX_MISMATCH, "{label}");
    }
}

#[sqlx::test]
async fn every_box_rpc_passes_the_bound_box_and_static_callers(pool: PgPool) {
    let svc = service(pool).await;
    for rpc in 0..RPCS.len() {
        not_mismatch(call(&svc, rpc, Some(&name(1)), &name(1)).await);
        not_mismatch(call(&svc, rpc, None, &name(2)).await);
    }
}

#[sqlx::test]
async fn bound_token_refuses_near_miss_names(pool: PgPool) {
    let svc = service(pool).await;
    for hostile in [
        String::new(),
        format!("{} ", name(1)),
        format!(" {}", name(1)),
        format!("{}\n", name(1)),
        format!("{}0", name(1)),
        name(1).to_uppercase(),
        format!("{}\0", name(1)),
    ] {
        for rpc in 0..RPCS.len() {
            mismatch(call(&svc, rpc, Some(&name(1)), &hostile).await);
        }
    }
}

#[sqlx::test]
async fn push_events_refuses_when_any_event_names_a_foreign_box(pool: PgPool) {
    let svc = service(pool).await;
    let request = bound(
        &name(1),
        PushEventsRequest {
            events: vec![event(&name(1)), event(&name(2))],
        },
    );
    let status = svc.push_events(request).await.unwrap_err();
    assert_ne!(status.message(), BOX_MISMATCH);
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[sqlx::test]
async fn shell_log_refuses_a_job_leased_to_another_box(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let svc = FleetService::new(store.clone());
    let job = store
        .submit_job_for(
            None,
            &SubmitJobRequest {
                idempotency_key: "k".to_owned(),
                prompt: "p".to_owned(),
                repo: "https://example.com/o/r.git".to_owned(),
                base_ref: "main".to_owned(),
                open_pr: false,
                agent: String::new(),
                profile: String::new(),
                environment: String::new(),
            },
        )
        .await
        .unwrap()
        .job_id;
    sqlx::query(
        "UPDATE jobs SET state = 'RUNNING', attempt = 1, box = $2, \
         lease_expires_at = now() + interval '1 hour' WHERE job_id = $1",
    )
    .bind(&job)
    .bind(name(2))
    .execute(&pool)
    .await
    .unwrap();
    let job = job.as_str();
    let report = |box_name: String| ReportShellLogRequest {
        r#box: box_name,
        job_id: job.to_owned(),
        attempt: 1,
        command_id: "c".to_owned(),
        status: ShellStatus::Running as i32,
        ..ReportShellLogRequest::default()
    };
    let own = svc.report_shell_log(bound(&name(2), report(name(2)))).await;
    own.unwrap();
    let foreign = svc
        .report_shell_log(bound(&name(1), report(name(1))))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::FailedPrecondition);
    svc.report_shell_log(Request::new(report(name(1))))
        .await
        .unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM job_shell_log_chunks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}
