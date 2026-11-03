//! `ReportShellLog` and `StreamShellLog` against a real database: lease binding, field
//! validation, per-job caps, owner scoping and the stream end conditions. The tests call
//! the handlers directly and need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_proto::v1::fleet_jobs_server::FleetJobs;
use fleet_proto::v1::fleet_worker_server::FleetWorker;
use fleet_proto::v1::{
    ReportShellLogRequest, ShellStatus, StreamShellLogChunk, StreamShellLogRequest,
    SubmitJobRequest,
};
use fleet_proto::{MAX_SHELL_LOG_CHUNK_BYTES, MAX_SHELL_LOG_CHUNKS};
use fleet_server::auth::Caller;
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use fleet_server::timing::{
    MAX_LOG_BYTES_PER_JOB, MAX_LOG_COMMANDS_PER_JOB, StreamLimits, stream_shell_log,
};
use sqlx::{Connection, PgConnection, PgPool};
use tonic::codegen::tokio_stream::StreamExt;
use tonic::{Code, Request, Status};

const OUTER: Duration = Duration::from_secs(20);
const MISSING: &str = "00000000000000000000000000";

struct World {
    svc: FleetService,
    pool: PgPool,
    alice: i64,
    bob: i64,
    job: String,
}

fn as_user<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(Caller { user_id });
    request
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
        .submit_job_for(
            Some(alice),
            &SubmitJobRequest {
                idempotency_key: "k".to_owned(),
                prompt: "p".to_owned(),
                repo: "https://example.com/o/r.git".to_owned(),
                base_ref: "main".to_owned(),
                open_pr: false,
                agent: String::new(),
            },
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE jobs SET state = 'RUNNING', attempt = 1, box = 'worker', \
         lease_expires_at = now() + interval '1 hour' WHERE job_id = $1",
    )
    .bind(&job.job_id)
    .execute(&pool)
    .await
    .unwrap();
    World {
        svc: FleetService::new(store),
        pool,
        alice,
        bob,
        job: job.job_id,
    }
}

fn report(
    job: &str,
    command: &str,
    seq: u32,
    bytes: &[u8],
    status: ShellStatus,
) -> ReportShellLogRequest {
    ReportShellLogRequest {
        job_id: job.to_owned(),
        attempt: 1,
        r#box: "worker".to_owned(),
        command_id: command.to_owned(),
        seq,
        bytes: bytes.to_vec(),
        status: status as i32,
    }
}

async fn send(w: &World, request: ReportShellLogRequest) -> Result<(), Status> {
    w.svc
        .report_shell_log(Request::new(request))
        .await
        .map(|_| ())
}

async fn rows(w: &World) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM job_shell_log_chunks")
        .fetch_one(&w.pool)
        .await
        .unwrap()
}

async fn open(
    w: &World,
    who: i64,
    job: &str,
    command: &str,
    from_seq: u32,
) -> Result<tonic::codegen::BoxStream<StreamShellLogChunk>, Status> {
    let message = StreamShellLogRequest {
        job_id: job.to_owned(),
        command_id: command.to_owned(),
        from_seq,
    };
    w.svc
        .stream_shell_log(as_user(who, message))
        .await
        .map(tonic::Response::into_inner)
}

async fn drain(
    stream: &mut tonic::codegen::BoxStream<StreamShellLogChunk>,
) -> Vec<StreamShellLogChunk> {
    let mut out = Vec::new();
    while let Some(item) = tokio::time::timeout(OUTER, stream.next()).await.unwrap() {
        out.push(item.unwrap());
    }
    out
}

#[sqlx::test]
async fn stored_chunks_replay_in_seq_order_and_a_done_status_ends_the_stream(pool: PgPool) {
    let w = world(pool).await;
    send(&w, report(&w.job, "c1", 1, b"two", ShellStatus::Running))
        .await
        .unwrap();
    send(&w, report(&w.job, "c1", 0, b"one", ShellStatus::Running))
        .await
        .unwrap();
    send(&w, report(&w.job, "c1", 2, b"", ShellStatus::Done))
        .await
        .unwrap();
    send(&w, report(&w.job, "c1", 3, b"after", ShellStatus::Running))
        .await
        .unwrap();
    let mut stream = open(&w, w.alice, &w.job, "c1", 0).await.unwrap();
    let got = drain(&mut stream).await;
    let seqs: Vec<u32> = got.iter().map(|c| c.seq).collect();
    assert_eq!(seqs, [0, 1, 2]);
    assert_eq!(got[0].bytes, b"one");
    assert_eq!(got[1].bytes, b"two");
    assert_eq!(got[2].status, ShellStatus::Done as i32);
    assert!(got.iter().all(|c| c.command_id == "c1"));
}

#[sqlx::test]
async fn from_seq_skips_earlier_chunks(pool: PgPool) {
    let w = world(pool).await;
    send(&w, report(&w.job, "c1", 0, b"a", ShellStatus::Running))
        .await
        .unwrap();
    send(&w, report(&w.job, "c1", 1, b"b", ShellStatus::Failed))
        .await
        .unwrap();
    let mut stream = open(&w, w.alice, &w.job, "c1", 1).await.unwrap();
    let got = drain(&mut stream).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq, 1);
    assert_eq!(got[0].status, ShellStatus::Failed as i32);
}

#[sqlx::test]
async fn a_stream_follows_chunks_reported_after_it_opened(pool: PgPool) {
    let w = world(pool).await;
    let mut stream = open(&w, w.alice, &w.job, "c1", 0).await.unwrap();
    send(&w, report(&w.job, "c1", 0, b"live", ShellStatus::Running))
        .await
        .unwrap();
    let first = tokio::time::timeout(OUTER, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.bytes, b"live");
    send(&w, report(&w.job, "c1", 1, b"", ShellStatus::Done))
        .await
        .unwrap();
    let rest = drain(&mut stream).await;
    assert_eq!(rest.len(), 1);
}

#[sqlx::test]
async fn an_ended_job_closes_the_stream_after_the_stored_chunks(pool: PgPool) {
    let w = world(pool).await;
    send(&w, report(&w.job, "c1", 0, b"x", ShellStatus::Running))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&w.job)
        .execute(&w.pool)
        .await
        .unwrap();
    let mut stream = open(&w, w.alice, &w.job, "c1", 0).await.unwrap();
    assert_eq!(drain(&mut stream).await.len(), 1);
}

#[sqlx::test]
async fn a_running_job_with_no_chunks_ends_the_stream_at_max_wait(pool: PgPool) {
    let w = world(pool).await;
    let limits = StreamLimits {
        poll: Duration::from_millis(20),
        max_wait: Duration::from_millis(200),
    };
    let request = StreamShellLogRequest {
        job_id: w.job.clone(),
        command_id: "c1".to_owned(),
        from_seq: 0,
    };
    let mut stream = stream_shell_log(&w.pool, &request, limits).unwrap();
    assert_eq!(drain(&mut stream).await.len(), 0);
}

async fn last_poll(probe: &mut PgConnection) -> Option<String> {
    sqlx::query_scalar(
        "SELECT max(query_start)::text FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid() \
         AND (query LIKE 'SELECT seq, bytes, status%' OR query LIKE 'SELECT state IN%')",
    )
    .fetch_one(probe)
    .await
    .unwrap()
}

#[sqlx::test]
async fn dropping_the_stream_ends_the_follow_task(pool: PgPool) {
    let w = world(pool).await;
    let limits = StreamLimits {
        poll: Duration::from_millis(20),
        max_wait: Duration::from_secs(600),
    };
    let request = StreamShellLogRequest {
        job_id: w.job.clone(),
        command_id: "c1".to_owned(),
        from_seq: 0,
    };
    let mut probe = PgConnection::connect_with(&w.pool.connect_options())
        .await
        .unwrap();
    let stream = stream_shell_log(&w.pool, &request, limits).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let live_a = last_poll(&mut probe).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let live_b = last_poll(&mut probe).await;
    assert!(
        live_a.is_some() && live_a != live_b,
        "the task must poll while open"
    );
    drop(stream);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let dead_a = last_poll(&mut probe).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        dead_a,
        last_poll(&mut probe).await,
        "the task kept polling after the drop"
    );
}

#[sqlx::test]
async fn a_deleted_job_ends_the_stream(pool: PgPool) {
    let w = world(pool).await;
    let mut stream = open(&w, w.alice, &w.job, "c1", 0).await.unwrap();
    sqlx::query("DELETE FROM jobs WHERE job_id = $1")
        .bind(&w.job)
        .execute(&w.pool)
        .await
        .unwrap();
    assert_eq!(drain(&mut stream).await.len(), 0);
}

#[sqlx::test]
async fn a_gap_holds_back_later_chunks_until_the_missing_one_arrives(pool: PgPool) {
    let w = world(pool).await;
    send(&w, report(&w.job, "c1", 1, b"b", ShellStatus::Done))
        .await
        .unwrap();
    let mut stream = open(&w, w.alice, &w.job, "c1", 0).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(600), stream.next())
            .await
            .is_err()
    );
    send(&w, report(&w.job, "c1", 0, b"a", ShellStatus::Running))
        .await
        .unwrap();
    assert_eq!(drain(&mut stream).await.len(), 2);
}

#[sqlx::test]
async fn a_missing_and_a_foreign_job_give_the_same_not_found(pool: PgPool) {
    let w = world(pool).await;
    send(&w, report(&w.job, "c1", 0, b"secret", ShellStatus::Running))
        .await
        .unwrap();
    let foreign = open(&w, w.bob, &w.job, "c1", 0).await.err().unwrap();
    let missing = open(&w, w.bob, MISSING, "c1", 0).await.err().unwrap();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(missing.code(), Code::NotFound);
    assert_eq!(foreign.message(), missing.message());
}

#[sqlx::test]
async fn stream_arguments_are_validated(pool: PgPool) {
    let w = world(pool).await;
    for id in [
        "", "a b", "a\r\nb", "a\u{85}b", "é", "a/b", "a@b", "a\\b", "[::1]", "a\0b",
    ] {
        let err = open(&w, w.alice, &w.job, id, 0).await.err().unwrap();
        assert_eq!(err.code(), Code::InvalidArgument, "{id:?}");
    }
    let long = "a".repeat(129);
    assert_eq!(
        open(&w, w.alice, &w.job, &long, 0)
            .await
            .err()
            .unwrap()
            .code(),
        Code::InvalidArgument
    );
    let past = u32::try_from(MAX_SHELL_LOG_CHUNKS).unwrap();
    for seq in [past, u32::MAX] {
        let err = open(&w, w.alice, &w.job, "c1", seq).await.err().unwrap();
        assert_eq!(err.code(), Code::InvalidArgument, "{seq}");
    }
}

#[sqlx::test]
async fn every_report_field_is_validated_and_nothing_is_stored(pool: PgPool) {
    let w = world(pool).await;
    let long = "a".repeat(129);
    let mut bad = Vec::new();
    for id in [
        "",
        long.as_str(),
        "a b",
        "a\r\nb",
        "a\u{2028}b",
        "a\u{85}b",
        "é",
        "a@b",
        "a\\b",
        "a\0b",
    ] {
        bad.push(report(&w.job, id, 0, b"x", ShellStatus::Running));
    }
    for seq in [
        u32::try_from(MAX_SHELL_LOG_CHUNKS).unwrap(),
        i32::MAX as u32,
        u32::MAX,
    ] {
        bad.push(report(&w.job, "c1", seq, b"x", ShellStatus::Running));
    }
    bad.push(report(
        &w.job,
        "c1",
        0,
        &vec![b'x'; MAX_SHELL_LOG_CHUNK_BYTES + 1],
        ShellStatus::Running,
    ));
    for status in [ShellStatus::Unspecified as i32, 5, -1, i32::MAX] {
        let mut request = report(&w.job, "c1", 0, b"x", ShellStatus::Running);
        request.status = status;
        bad.push(request);
    }
    for request in bad {
        let err = send(&w, request.clone()).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{request:?}");
    }
    assert_eq!(rows(&w).await, 0);
}

#[sqlx::test]
async fn the_client_supplied_box_is_ignored(pool: PgPool) {
    let w = world(pool).await;
    for name in ["", "other", "../etc", "worker\r\nx"] {
        let mut request = report(&w.job, "c1", 0, b"x", ShellStatus::Running);
        request.r#box = name.to_owned();
        request.seq = u32::try_from(name.len()).unwrap();
        send(&w, request).await.unwrap();
    }
    let boxes: Vec<String> = sqlx::query_scalar("SELECT box FROM jobs WHERE job_id = $1")
        .bind(&w.job)
        .fetch_all(&w.pool)
        .await
        .unwrap();
    assert_eq!(boxes, ["worker"]);
    assert_eq!(rows(&w).await, 4);
}

#[sqlx::test]
async fn a_report_without_a_live_lease_is_refused(pool: PgPool) {
    let w = world(pool).await;
    let mut wrong_attempt = report(&w.job, "c1", 0, b"x", ShellStatus::Running);
    wrong_attempt.attempt = 2;
    let mut huge_attempt = report(&w.job, "c1", 0, b"x", ShellStatus::Running);
    huge_attempt.attempt = u32::MAX;
    let unknown = report(MISSING, "c1", 0, b"x", ShellStatus::Running);
    for request in [wrong_attempt, huge_attempt, unknown] {
        let err = send(&w, request).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE job_id = $1")
        .bind(&w.job)
        .execute(&w.pool)
        .await
        .unwrap();
    let err = send(&w, report(&w.job, "c1", 0, b"x", ShellStatus::Running))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    sqlx::query(
        "UPDATE jobs SET state = 'SUCCEEDED', lease_expires_at = now() + interval '1 hour' \
         WHERE job_id = $1",
    )
    .bind(&w.job)
    .execute(&w.pool)
    .await
    .unwrap();
    let err = send(&w, report(&w.job, "c1", 0, b"x", ShellStatus::Running))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(rows(&w).await, 0);
}

#[sqlx::test]
async fn a_resent_chunk_succeeds_and_keeps_the_first(pool: PgPool) {
    let w = world(pool).await;
    send(&w, report(&w.job, "c1", 0, b"first", ShellStatus::Running))
        .await
        .unwrap();
    send(&w, report(&w.job, "c1", 0, b"second", ShellStatus::Running))
        .await
        .unwrap();
    assert_eq!(rows(&w).await, 1);
    let kept: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM job_shell_log_chunks")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(kept, b"first");
}

#[sqlx::test]
async fn a_job_may_not_log_more_than_the_command_cap(pool: PgPool) {
    let w = world(pool).await;
    sqlx::query(
        "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
         SELECT $1, 'c' || n, 0, ''::bytea, 'running' FROM generate_series(1, $2::int) n",
    )
    .bind(&w.job)
    .bind(i32::try_from(MAX_LOG_COMMANDS_PER_JOB).unwrap())
    .execute(&w.pool)
    .await
    .unwrap();
    let err = send(&w, report(&w.job, "extra", 0, b"x", ShellStatus::Running))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    send(&w, report(&w.job, "c1", 1, b"x", ShellStatus::Running))
        .await
        .unwrap();
    assert_eq!(
        rows(&w).await,
        i64::try_from(MAX_LOG_COMMANDS_PER_JOB).unwrap() + 1
    );
}

#[sqlx::test]
async fn a_job_may_not_store_more_than_the_byte_cap(pool: PgPool) {
    let w = world(pool).await;
    let per_command = MAX_SHELL_LOG_CHUNKS * MAX_SHELL_LOG_CHUNK_BYTES;
    let full = MAX_LOG_BYTES_PER_JOB / per_command;
    sqlx::query(
        "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
         SELECT $1, 'f' || c, s, decode(repeat('00', $2::int), 'hex'), 'running' \
         FROM generate_series(1, $3::int) c, generate_series(0, $4::int) s",
    )
    .bind(&w.job)
    .bind(i32::try_from(MAX_SHELL_LOG_CHUNK_BYTES).unwrap())
    .bind(i32::try_from(full).unwrap())
    .bind(i32::try_from(MAX_SHELL_LOG_CHUNKS - 1).unwrap())
    .execute(&w.pool)
    .await
    .unwrap();
    let stored: i64 =
        sqlx::query_scalar("SELECT sum(octet_length(bytes))::bigint FROM job_shell_log_chunks")
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert_eq!(usize::try_from(stored).unwrap(), MAX_LOG_BYTES_PER_JOB);
    send(
        &w,
        report(
            &w.job,
            "f2",
            0,
            &[0; MAX_SHELL_LOG_CHUNK_BYTES],
            ShellStatus::Running,
        ),
    )
    .await
    .unwrap();
    let err = send(&w, report(&w.job, "next", 0, b"x", ShellStatus::Running))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    send(&w, report(&w.job, "next", 0, b"", ShellStatus::Running))
        .await
        .unwrap();
    sqlx::query("DELETE FROM job_shell_log_chunks WHERE command_id = 'f1' AND seq = 0")
        .execute(&w.pool)
        .await
        .unwrap();
    send(
        &w,
        report(
            &w.job,
            "next",
            1,
            &vec![b'y'; MAX_SHELL_LOG_CHUNK_BYTES],
            ShellStatus::Running,
        ),
    )
    .await
    .unwrap();
    let err = send(&w, report(&w.job, "next", 2, b"y", ShellStatus::Running))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
}

#[sqlx::test]
async fn concurrent_reports_cannot_pass_the_command_cap_together(pool: PgPool) {
    let w = world(pool).await;
    let first = MAX_LOG_COMMANDS_PER_JOB - 1;
    sqlx::query(
        "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
         SELECT $1, 'c' || n, 0, ''::bytea, 'running' FROM generate_series(1, $2::int) n",
    )
    .bind(&w.job)
    .bind(i32::try_from(first).unwrap())
    .execute(&w.pool)
    .await
    .unwrap();
    let mut tasks = Vec::new();
    for n in 0..8 {
        let svc = w.svc.clone();
        let request = report(&w.job, &format!("race{n}"), 0, b"x", ShellStatus::Running);
        tasks.push(tokio::spawn(async move {
            svc.report_shell_log(Request::new(request))
                .await
                .map(|_| ())
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1);
}
