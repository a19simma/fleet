//! `store_timing` against Postgres: one idempotent write per job under a row lock, the
//! lease check, every cap just under and just over, and a hostile-text table. The tests
//! need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_proto::v1::{
    ReportTimingRequest, ShellCommand, TimingSpan, TimingSpanKind, TimingSummary,
};
use fleet_proto::{
    MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SPANS, MAX_TIMING_NAME_BYTES,
};
use fleet_server::timing::store_timing;
use sqlx::{PgPool, Row};
use tonic::Code;

const JOB: &str = "01JTIMINGSTORE00000000000A";

async fn running_job(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, attempt, \
         box, lease_expires_at) \
         VALUES ($1, 't', 'r', 'main', 'b', false, 'RUNNING', 1, 'worker', \
         now() + interval '1 hour')",
    )
    .bind(JOB)
    .execute(pool)
    .await
    .unwrap();
}

fn summary(api: u64) -> TimingSummary {
    TimingSummary {
        wall_ms: api + 10,
        api_wait_ms: api,
        tool_ms: 1,
        shell_ms: 2,
        idle_ms: 3,
        overhead_ms: 4,
    }
}

fn span(seq: u64) -> TimingSpan {
    TimingSpan {
        kind: TimingSpanKind::Tool as i32,
        start_ms: seq,
        end_ms: seq + 1,
        name: "Read".to_owned(),
        tool_use_id: None,
    }
}

fn command(id: &str) -> ShellCommand {
    ShellCommand {
        id: id.to_owned(),
        command: "ls".to_owned(),
        background: false,
        started_ms: 1,
        ended_ms: Some(3),
        duration_ms: 2,
        exit_code: Some(0),
        log: "out".to_owned(),
        log_truncated: false,
        ended_by: None,
    }
}

fn request(api: u64, spans: Vec<TimingSpan>, commands: Vec<ShellCommand>) -> ReportTimingRequest {
    ReportTimingRequest {
        job_id: JOB.to_owned(),
        attempt: 1,
        r#box: "ignored".to_owned(),
        summary: Some(summary(api)),
        spans,
        shell_commands: commands,
    }
}

async fn counts(pool: &PgPool) -> (i64, i64, i64) {
    let one = |sql: &'static str| async move {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .unwrap()
    };
    (
        one("SELECT count(*) FROM job_timing").await,
        one("SELECT count(*) FROM job_timing_spans").await,
        one("SELECT count(*) FROM job_shell_commands").await,
    )
}

#[sqlx::test]
async fn a_report_stores_the_summary_spans_and_commands(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let mut tagged = span(5);
    tagged.kind = TimingSpanKind::BgShell as i32;
    tagged.tool_use_id = Some("toolu_1".to_owned());
    let mut cmd = command("c1");
    cmd.ended_by = Some("job_exit".to_owned());
    cmd.ended_ms = None;
    cmd.exit_code = None;
    cmd.background = true;
    cmd.log_truncated = true;
    store_timing(&pool, &request(100, vec![span(0), tagged], vec![cmd]))
        .await
        .unwrap();
    let timing = sqlx::query(
        "SELECT wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, overhead_ms FROM job_timing",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let parts: Vec<i64> = (0..6).map(|i| timing.get(i)).collect();
    assert_eq!(parts, [110, 100, 1, 2, 3, 4]);
    let rows: Vec<(i32, String, i64, i64, String, Option<String>)> = sqlx::query_as(
        "SELECT seq, kind, start_ms, end_ms, name, tool_use_id FROM job_timing_spans ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            (0, "tool".into(), 0, 1, "Read".into(), None),
            (
                1,
                "bg_shell".into(),
                5,
                6,
                "Read".into(),
                Some("toolu_1".into())
            ),
        ]
    );
    let stored = sqlx::query(
        "SELECT id, command, background, started_ms, ended_ms, duration_ms, exit_code, log, \
         log_truncated, ended_by FROM job_shell_commands",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.get::<String, _>(0), "c1");
    assert!(stored.get::<bool, _>(2));
    assert_eq!(stored.get::<Option<i64>, _>(4), None);
    assert_eq!(stored.get::<Option<i32>, _>(6), None);
    assert!(stored.get::<bool, _>(8));
    assert_eq!(
        stored.get::<Option<String>, _>(9).as_deref(),
        Some("job_exit")
    );
}

#[sqlx::test]
async fn a_second_report_replaces_the_first(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let first = request(
        100,
        vec![span(0), span(1), span(2)],
        vec![command("a"), command("b")],
    );
    store_timing(&pool, &first).await.unwrap();
    store_timing(&pool, &first).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 3, 2));
    store_timing(&pool, &request(7, vec![span(9)], vec![command("z")]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 1));
    let api: i64 = sqlx::query_scalar("SELECT api_wait_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(api, 7);
    let start: i64 = sqlx::query_scalar("SELECT start_ms FROM job_timing_spans")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(start, 9);
    let id: String = sqlx::query_scalar("SELECT id FROM job_shell_commands")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(id, "z");
    store_timing(&pool, &request(8, vec![], vec![]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 0, 0));
}

#[sqlx::test]
async fn a_refused_report_leaves_the_first_in_place(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    store_timing(&pool, &request(100, vec![span(0)], vec![command("a")]))
        .await
        .unwrap();
    let mut bad = request(7, vec![span(1), span(2)], vec![command("b")]);
    bad.spans[1].name = "a\nb".to_owned();
    let err = store_timing(&pool, &bad).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(counts(&pool).await, (1, 1, 1));
    let api: i64 = sqlx::query_scalar("SELECT api_wait_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(api, 100);
}

#[sqlx::test]
async fn the_span_cap_holds_just_under_and_just_over(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let spans = |n: usize| (0..n as u64).map(span).collect::<Vec<_>>();
    store_timing(&pool, &request(1, spans(MAX_SPANS - 1), vec![]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await.1, 4095);
    store_timing(&pool, &request(1, spans(MAX_SPANS), vec![]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await.1, 4096);
    let err = store_timing(&pool, &request(2, spans(MAX_SPANS + 1), vec![]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), "too many timing spans");
    assert_eq!(counts(&pool).await.1, 4096);
}

#[sqlx::test]
async fn the_command_cap_holds_just_under_and_just_over(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let commands = |n: usize| {
        (0..n)
            .map(|i| command(&format!("c{i}")))
            .collect::<Vec<_>>()
    };
    store_timing(&pool, &request(1, vec![], commands(MAX_SHELL_COMMANDS - 1)))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await.2, 255);
    store_timing(&pool, &request(1, vec![], commands(MAX_SHELL_COMMANDS)))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await.2, 256);
    let err = store_timing(&pool, &request(2, vec![], commands(MAX_SHELL_COMMANDS + 1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), "too many timing shell commands");
    assert_eq!(counts(&pool).await.2, 256);
}

#[sqlx::test]
async fn the_log_byte_cap_holds_just_under_and_just_over(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    for len in [MAX_SHELL_LOG_BYTES - 1, MAX_SHELL_LOG_BYTES] {
        let mut cmd = command("c");
        cmd.log = "a".repeat(len);
        store_timing(&pool, &request(1, vec![], vec![cmd]))
            .await
            .unwrap();
        let stored: i32 = sqlx::query_scalar("SELECT octet_length(log) FROM job_shell_commands")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(usize::try_from(stored).unwrap(), len);
    }
    let mut cmd = command("c");
    cmd.log = "a".repeat(MAX_SHELL_LOG_BYTES + 1);
    let err = store_timing(&pool, &request(2, vec![], vec![cmd]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), "timing field log is too long");
    let api: i64 = sqlx::query_scalar("SELECT api_wait_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(api, 1);
}

#[sqlx::test]
async fn hostile_text_is_refused_without_an_echo(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let long = "n".repeat(MAX_TIMING_NAME_BYTES + 1);
    let long_command = "c".repeat(MAX_COMMAND_BYTES + 1);
    let single = [
        "a\rb",
        "a\r\nb",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\0b",
        "a\u{7f}b",
        "a\u{1b}[31mb",
        "",
        &long,
    ];
    let ids = [
        "a b",
        "a/b",
        "a\\b",
        "a\rb",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "é",
        "a@b",
        "a:b/c",
        "",
        &long,
    ];
    let mut cases: Vec<(&str, ReportTimingRequest)> = vec![];
    for text in single {
        let mut r = request(1, vec![span(0)], vec![]);
        r.spans[0].name = text.to_owned();
        cases.push(("name", r));
        let mut r = request(1, vec![span(0)], vec![]);
        r.spans[0].tool_use_id = Some(text.to_owned());
        cases.push(("tool_use_id", r));
        let mut r = request(1, vec![], vec![command("c")]);
        r.shell_commands[0].ended_by = Some(text.to_owned());
        cases.push(("ended_by", r));
    }
    for text in ids {
        let mut r = request(1, vec![], vec![command("c")]);
        r.shell_commands[0].id = text.to_owned();
        cases.push(("id", r));
    }
    for text in ["", long_command.as_str()] {
        let mut r = request(1, vec![], vec![command("c")]);
        r.shell_commands[0].command = text.to_owned();
        cases.push(("command", r));
    }
    for (field, r) in cases {
        let err = store_timing(&pool, &r).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{field}");
        assert!(err.message().contains(field), "{field}: {}", err.message());
        assert!(!err.message().contains("\u{2028}") && !err.message().contains('\r'));
    }
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

#[sqlx::test]
async fn a_bad_summary_span_or_number_is_refused(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let mut no_summary = request(1, vec![], vec![]);
    no_summary.summary = None;
    let mut mismatch = request(1, vec![], vec![]);
    mismatch.summary.as_mut().unwrap().wall_ms += 1;
    let mut huge = request(1, vec![], vec![]);
    huge.summary.as_mut().unwrap().tool_ms = u64::MAX;
    let mut reversed = request(1, vec![span(5)], vec![]);
    reversed.spans[0].end_ms = 4;
    let mut kind = request(1, vec![span(0)], vec![]);
    kind.spans[0].kind = 0;
    let mut big_start = request(1, vec![span(0)], vec![]);
    big_start.spans[0].start_ms = u64::MAX;
    let mut big_cmd = request(1, vec![], vec![command("c")]);
    big_cmd.shell_commands[0].duration_ms = u64::MAX;
    for r in [
        no_summary, mismatch, huge, reversed, kind, big_start, big_cmd,
    ] {
        let err = store_timing(&pool, &r).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

#[sqlx::test]
async fn a_report_without_a_live_lease_is_refused(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    let missing = store_timing(&pool, &request(1, vec![span(0)], vec![])).await;
    assert_eq!(missing.unwrap_err().code(), Code::FailedPrecondition);
    running_job(&pool).await;
    let mut wrong = request(1, vec![span(0)], vec![]);
    wrong.attempt = 2;
    assert_eq!(
        store_timing(&pool, &wrong).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    wrong.attempt = u32::MAX;
    assert_eq!(
        store_timing(&pool, &wrong).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    for (set, what) in [
        (
            "UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE job_id = $1",
            "expired",
        ),
        (
            "UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1",
            "ended",
        ),
        (
            "UPDATE jobs SET state = 'QUEUED' WHERE job_id = $1",
            "queued",
        ),
    ] {
        sqlx::query(set).bind(JOB).execute(&pool).await.unwrap();
        let err = store_timing(&pool, &request(1, vec![span(0)], vec![]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition, "{what}");
        sqlx::query("UPDATE jobs SET state = 'RUNNING', lease_expires_at = now() + interval '1 hour' WHERE job_id = $1")
            .bind(JOB)
            .execute(&pool)
            .await
            .unwrap();
    }
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

#[sqlx::test]
async fn a_report_waits_for_the_job_row_lock(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM jobs WHERE job_id = $1 FOR NO KEY UPDATE")
        .bind(JOB)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    let writer = {
        let pool = pool.clone();
        tokio::spawn(async move { store_timing(&pool, &request(1, vec![span(0)], vec![])).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!writer.is_finished());
    assert_eq!(counts(&pool).await.0, 0);
    holder.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 0));
}

#[sqlx::test]
async fn concurrent_reports_leave_one_whole_report(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let mut tasks = vec![];
    for n in 1..=8_u64 {
        let pool = pool.clone();
        let spans = (0..n).map(span).collect();
        let commands = (0..n).map(|i| command(&format!("c{i}"))).collect();
        tasks.push(tokio::spawn(async move {
            store_timing(&pool, &request(n, spans, commands)).await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let api: i64 = sqlx::query_scalar("SELECT api_wait_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (_, spans, commands) = counts(&pool).await;
    assert_eq!((spans, commands), (api, api));
}
