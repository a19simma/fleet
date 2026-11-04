//! `store_timing` against Postgres: one idempotent write per job under a row lock, the
//! lease check (job, attempt and box), every cap just under and just over, and a hostile-text table. The tests
//! need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_core::BoxName;
use fleet_core::timing::{Interval, Span, SpanKind, aggregate};
use fleet_proto::v1::{
    GetJobTimingRequest, ReportTimingRequest, ShellCommand, TimingSpan, TimingSpanKind,
    TimingSummary,
};
use fleet_proto::{
    MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SPANS, MAX_TIMING_NAME_BYTES,
};
use fleet_server::timing::{
    REASON_AGENT_WINDOW, REASON_PARTS_SUM, REASON_SPAN_OUTSIDE, REASON_SUMMARY_MISMATCH,
    REASON_WINDOW_AHEAD, WINDOW_TOLERANCE_MS, read_job_timing, store_timing,
};
use sqlx::{PgPool, Row};
use tonic::Code;

fn lease_box() -> BoxName {
    BoxName::new(&format!("box-{}", 1)).unwrap()
}

const JOB: &str = "01JTIMINGSTORE00000000000A";

const CLAIMED_MS: u64 = 1_704_067_200_000;
const WALL_BASE: u64 = 10_000;

async fn running_job(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, attempt, \
         box, lease_expires_at, claimed_at) \
         VALUES ($1, 't', 'r', 'main', 'b', false, 'RUNNING', 1, $2, \
         now() + interval '1 hour', to_timestamp(1704067200))",
    )
    .bind(JOB)
    .bind(lease_box().as_str())
    .execute(pool)
    .await
    .unwrap();
}

fn core_kind(kind: i32) -> SpanKind {
    match TimingSpanKind::try_from(kind).unwrap() {
        TimingSpanKind::Api => SpanKind::ApiWait,
        TimingSpanKind::Tool => SpanKind::Tool,
        TimingSpanKind::Shell => SpanKind::Shell,
        TimingSpanKind::BgShell => SpanKind::BgShell,
        TimingSpanKind::Unspecified => unreachable!(),
    }
}

fn summary(wall: u64, spans: &[TimingSpan]) -> TimingSummary {
    let core: Vec<Span> = spans
        .iter()
        .map(|s| Span {
            kind: core_kind(s.kind),
            interval: Interval::new(s.start_ms, s.end_ms).unwrap(),
        })
        .collect();
    let job = Interval::new(0, wall).unwrap();
    let parts = aggregate(&core, job, job);
    TimingSummary {
        wall_ms: wall,
        api_wait_ms: parts.api_wait_ms,
        tool_ms: parts.tool_ms,
        shell_ms: parts.shell_ms,
        idle_ms: parts.idle_ms,
        overhead_ms: parts.overhead_ms,
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

fn request(extra: u64, spans: Vec<TimingSpan>, commands: Vec<ShellCommand>) -> ReportTimingRequest {
    ReportTimingRequest {
        job_id: JOB.to_owned(),
        attempt: 1,
        r#box: "ignored".to_owned(),
        summary: Some(summary(WALL_BASE + extra, &spans)),
        spans,
        shell_commands: commands,
        agent_start_ms: 0,
        agent_end_ms: WALL_BASE + extra,
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
    store_timing(
        &pool,
        &lease_box(),
        &request(100, vec![span(0), tagged], vec![cmd]),
    )
    .await
    .unwrap();
    let timing = sqlx::query(
        "SELECT wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, overhead_ms FROM job_timing",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let parts: Vec<i64> = (0..6).map(|i| timing.get(i)).collect();
    assert_eq!(parts, [10_100, 0, 1, 1, 10_098, 0]);
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
    store_timing(&pool, &lease_box(), &first).await.unwrap();
    store_timing(&pool, &lease_box(), &first).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 3, 2));
    store_timing(
        &pool,
        &lease_box(),
        &request(7, vec![span(9)], vec![command("z")]),
    )
    .await
    .unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 1));
    let wall: i64 = sqlx::query_scalar("SELECT wall_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(wall, 10_007);
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
    store_timing(&pool, &lease_box(), &request(8, vec![], vec![]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 0, 0));
}

#[sqlx::test]
async fn a_refused_report_leaves_the_first_in_place(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    store_timing(
        &pool,
        &lease_box(),
        &request(100, vec![span(0)], vec![command("a")]),
    )
    .await
    .unwrap();
    let mut bad = request(7, vec![span(1), span(2)], vec![command("b")]);
    bad.spans[1].name = "a\nb".to_owned();
    let err = store_timing(&pool, &lease_box(), &bad).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(counts(&pool).await, (1, 1, 1));
    let wall: i64 = sqlx::query_scalar("SELECT wall_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(wall, 10_100);
}

#[sqlx::test]
async fn the_span_cap_holds_just_under_and_just_over(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let spans = |n: usize| (0..n as u64).map(span).collect::<Vec<_>>();
    store_timing(
        &pool,
        &lease_box(),
        &request(1, spans(MAX_SPANS - 1), vec![]),
    )
    .await
    .unwrap();
    assert_eq!(counts(&pool).await.1, 4095);
    store_timing(&pool, &lease_box(), &request(1, spans(MAX_SPANS), vec![]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await.1, 4096);
    let err = store_timing(
        &pool,
        &lease_box(),
        &request(2, spans(MAX_SPANS + 1), vec![]),
    )
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
    store_timing(
        &pool,
        &lease_box(),
        &request(1, vec![], commands(MAX_SHELL_COMMANDS - 1)),
    )
    .await
    .unwrap();
    assert_eq!(counts(&pool).await.2, 255);
    store_timing(
        &pool,
        &lease_box(),
        &request(1, vec![], commands(MAX_SHELL_COMMANDS)),
    )
    .await
    .unwrap();
    assert_eq!(counts(&pool).await.2, 256);
    let err = store_timing(
        &pool,
        &lease_box(),
        &request(2, vec![], commands(MAX_SHELL_COMMANDS + 1)),
    )
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
        store_timing(&pool, &lease_box(), &request(1, vec![], vec![cmd]))
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
    let err = store_timing(&pool, &lease_box(), &request(2, vec![], vec![cmd]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), "timing field log is too long");
    let wall: i64 = sqlx::query_scalar("SELECT wall_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(wall, 10_001);
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
        let err = store_timing(&pool, &lease_box(), &r).await.unwrap_err();
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
        let err = store_timing(&pool, &lease_box(), &r).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

#[sqlx::test]
async fn a_report_from_another_box_is_refused_and_stores_nothing(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let other = BoxName::new(&format!("box-{}", 2)).unwrap();
    let wrong = request(1, vec![span(0)], vec![command("c1")]);
    let err = store_timing(&pool, &other, &wrong).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), "report does not match the running job");
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

#[sqlx::test]
async fn a_non_holder_with_a_bad_body_gets_the_stale_refusal(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let other = BoxName::new(&format!("box-{}", 2)).unwrap();
    let mut no_summary = request(1, vec![], vec![]);
    no_summary.summary = None;
    let mut parts = request(1, vec![], vec![]);
    parts.summary.as_mut().unwrap().wall_ms += 1;
    let mut outside = request(1, vec![tool_span(CLAIMED_MS, CLAIMED_MS + 1)], vec![]);
    outside.summary = request(1, vec![], vec![]).summary;
    let mut kind = request(1, vec![span(0)], vec![]);
    kind.spans[0].kind = 0;
    let mut reversed = request(1, vec![span(5)], vec![]);
    reversed.spans[0].end_ms = 4;
    let mut big = request(1, vec![], vec![command("c")]);
    big.shell_commands[0].duration_ms = u64::MAX;
    for (label, bad) in [
        ("no_summary", no_summary),
        ("parts", parts),
        ("outside", outside),
        ("kind", kind),
        ("reversed", reversed),
        ("big", big),
    ] {
        let err = store_timing(&pool, &other, &bad).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition, "{label}");
        assert_eq!(
            err.message(),
            "report does not match the running job",
            "{label}"
        );
    }
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

#[sqlx::test]
async fn a_report_from_the_lease_holder_stores(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let right = request(1, vec![span(0)], vec![command("c1")]);
    store_timing(&pool, &lease_box(), &right).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 1));
}

#[sqlx::test]
async fn a_report_without_a_live_lease_is_refused(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    let missing = store_timing(&pool, &lease_box(), &request(1, vec![span(0)], vec![])).await;
    assert_eq!(missing.unwrap_err().code(), Code::FailedPrecondition);
    running_job(&pool).await;
    let mut wrong = request(1, vec![span(0)], vec![]);
    wrong.attempt = 2;
    assert_eq!(
        store_timing(&pool, &lease_box(), &wrong)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    wrong.attempt = u32::MAX;
    assert_eq!(
        store_timing(&pool, &lease_box(), &wrong)
            .await
            .unwrap_err()
            .code(),
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
        let err = store_timing(&pool, &lease_box(), &request(1, vec![span(0)], vec![]))
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
        tokio::spawn(async move {
            store_timing(&pool, &lease_box(), &request(1, vec![span(0)], vec![])).await
        })
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
            store_timing(&pool, &lease_box(), &request(n, spans, commands)).await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let wall: i64 = sqlx::query_scalar("SELECT wall_ms FROM job_timing")
        .fetch_one(&pool)
        .await
        .unwrap();
    let n = wall - i64::try_from(WALL_BASE).unwrap();
    let (_, spans, commands) = counts(&pool).await;
    assert_eq!((spans, commands), (n, n));
}

async fn db_now_ms(pool: &PgPool) -> u64 {
    let ms: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await
            .unwrap();
    u64::try_from(ms).unwrap()
}

fn tool_span(start_ms: u64, end_ms: u64) -> TimingSpan {
    TimingSpan {
        start_ms,
        end_ms,
        ..span(0)
    }
}

async fn refused(pool: &PgPool, request: &ReportTimingRequest, reason: &str, label: &str) {
    let err = store_timing(pool, &lease_box(), request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument, "{label}");
    assert_eq!(err.message(), reason, "{label}");
    assert_eq!(counts(pool).await, (0, 0, 0), "{label}");
}

#[sqlx::test]
async fn parts_that_do_not_sum_to_wall_are_refused_with_the_exact_reason(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let good = request(0, vec![span(0)], vec![]);
    let mut short = good.clone();
    short.summary.as_mut().unwrap().idle_ms -= 1;
    let mut long = good.clone();
    long.summary.as_mut().unwrap().wall_ms += 1;
    let mut overflow = good.clone();
    {
        let parts = overflow.summary.as_mut().unwrap();
        parts.api_wait_ms = u64::MAX;
        parts.shell_ms = u64::MAX;
    }
    for (label, r) in [("short", short), ("long", long), ("overflow", overflow)] {
        refused(&pool, &r, REASON_PARTS_SUM, label).await;
    }
    store_timing(&pool, &lease_box(), &good).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 0));
}

#[sqlx::test]
async fn spans_outside_the_job_window_are_refused_with_the_exact_reason(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let limit = WALL_BASE + WINDOW_TOLERANCE_MS;
    let past_end = tool_span(limit - 5, limit + 1);
    let far_past_end = tool_span(limit + 1, limit + 10 * WINDOW_TOLERANCE_MS);
    let epoch_based = tool_span(CLAIMED_MS, CLAIMED_MS + 10);
    for (label, bad) in [
        ("past_end", past_end),
        ("far_past_end", far_past_end),
        ("epoch_based", epoch_based),
    ] {
        refused(
            &pool,
            &request(0, vec![span(0), bad], vec![]),
            REASON_SPAN_OUTSIDE,
            label,
        )
        .await;
    }
    let edge = tool_span(limit - 10, limit);
    store_timing(&pool, &lease_box(), &request(0, vec![edge], vec![]))
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 0));
}

#[sqlx::test]
async fn a_gathered_request_shaped_report_is_accepted(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let wall = 60_000;
    let agent = Interval::new(4_000, 55_000).unwrap();
    let spans = vec![
        tool_span(4_500, 9_000),
        TimingSpan {
            kind: TimingSpanKind::Shell as i32,
            ..tool_span(10_000, 20_000)
        },
    ];
    let core: Vec<Span> = spans
        .iter()
        .map(|s| Span {
            kind: core_kind(s.kind),
            interval: Interval::new(s.start_ms, s.end_ms).unwrap(),
        })
        .collect();
    let parts = aggregate(&core, Interval::new(0, wall).unwrap(), agent);
    assert_eq!(parts.overhead_ms, 9_000);
    let mut report = request(0, spans, vec![]);
    report.agent_start_ms = 4_000;
    report.agent_end_ms = 55_000;
    report.summary = Some(TimingSummary {
        wall_ms: wall,
        api_wait_ms: parts.api_wait_ms,
        tool_ms: parts.tool_ms,
        shell_ms: parts.shell_ms,
        idle_ms: parts.idle_ms,
        overhead_ms: parts.overhead_ms,
    });
    store_timing(&pool, &lease_box(), &report).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 2, 0));
}

#[sqlx::test]
async fn a_wall_that_runs_past_now_is_refused_with_the_exact_reason(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let now = db_now_ms(&pool).await;
    let far = 20 * WINDOW_TOLERANCE_MS + now - CLAIMED_MS;
    let mut ahead = request(0, vec![], vec![]);
    *ahead.summary.as_mut().unwrap() = TimingSummary {
        wall_ms: far,
        overhead_ms: far,
        ..TimingSummary::default()
    };
    refused(&pool, &ahead, REASON_WINDOW_AHEAD, "ahead").await;
    let mut inside = ahead.clone();
    inside.agent_end_ms = 0;
    let near = now - CLAIMED_MS;
    *inside.summary.as_mut().unwrap() = TimingSummary {
        wall_ms: near,
        overhead_ms: near,
        ..TimingSummary::default()
    };
    store_timing(&pool, &lease_box(), &inside).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 0, 0));
}

#[sqlx::test]
async fn a_running_job_with_no_claim_time_is_refused_as_stale(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    sqlx::query("UPDATE jobs SET claimed_at = NULL WHERE job_id = $1")
        .bind(JOB)
        .execute(&pool)
        .await
        .unwrap();
    let err = store_timing(&pool, &lease_box(), &request(0, vec![span(0)], vec![]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(counts(&pool).await, (0, 0, 0));
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn own(pool: &PgPool, user_id: i64) {
    sqlx::query("UPDATE jobs SET user_id = $1 WHERE job_id = $2")
        .bind(user_id)
        .bind(JOB)
        .execute(pool)
        .await
        .unwrap();
}

fn get(job_id: &str) -> GetJobTimingRequest {
    GetJobTimingRequest {
        job_id: job_id.to_owned(),
    }
}

#[sqlx::test]
async fn a_read_returns_the_stored_report_in_order(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let alice = user(&pool, "alice").await;
    own(&pool, alice).await;
    let mut tagged = span(5);
    tagged.kind = TimingSpanKind::BgShell as i32;
    tagged.tool_use_id = Some("toolu_1".to_owned());
    let mut cmd = command("c1");
    cmd.ended_by = Some("job_exit".to_owned());
    cmd.ended_ms = None;
    cmd.exit_code = None;
    cmd.log_truncated = true;
    let report = request(100, vec![span(0), tagged], vec![cmd, command("c2")]);
    store_timing(&pool, &lease_box(), &report).await.unwrap();
    let reply = read_job_timing(&pool, Some(alice), &get(JOB))
        .await
        .unwrap();
    assert_eq!(reply.summary, report.summary);
    assert_eq!(reply.spans, report.spans);
    assert_eq!(reply.shell_commands, report.shell_commands);
    let any = read_job_timing(&pool, None, &get(JOB)).await.unwrap();
    assert_eq!(any, reply);
}

#[sqlx::test]
async fn a_job_without_a_report_reads_as_absent_not_zeros(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let alice = user(&pool, "alice").await;
    own(&pool, alice).await;
    let reply = read_job_timing(&pool, Some(alice), &get(JOB))
        .await
        .unwrap();
    assert_eq!(reply.summary, None);
    assert!(reply.spans.is_empty() && reply.shell_commands.is_empty());
    let zero = ReportTimingRequest {
        summary: Some(TimingSummary::default()),
        agent_end_ms: 0,
        ..request(0, vec![], vec![])
    };
    store_timing(&pool, &lease_box(), &zero).await.unwrap();
    let reply = read_job_timing(&pool, Some(alice), &get(JOB))
        .await
        .unwrap();
    assert_eq!(reply.summary, Some(TimingSummary::default()));
}

#[sqlx::test]
async fn unknown_and_foreign_jobs_get_the_same_not_found(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    own(&pool, alice).await;
    store_timing(&pool, &lease_box(), &request(0, vec![span(0)], vec![]))
        .await
        .unwrap();
    let foreign = read_job_timing(&pool, Some(bob), &get(JOB))
        .await
        .unwrap_err();
    let unknown = read_job_timing(&pool, Some(alice), &get("01JTIMINGSTORE00000000000Z"))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(unknown.code(), foreign.code());
    assert_eq!(unknown.message(), foreign.message());
    assert!(!foreign.message().contains(JOB));
}

#[sqlx::test]
async fn a_hostile_job_id_is_refused_before_any_query(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    pool.close().await;
    let long = "A".repeat(4096);
    let cases = [
        ("empty", String::new()),
        ("nul", "01JTIMINGSTORE0000000\x00000A".to_owned()),
        ("cr", format!("{JOB}\r")),
        ("crlf", format!("{JOB}\r\n")),
        ("lf", format!("{JOB}\n")),
        ("nel", format!("{JOB}\u{85}")),
        ("line separator", format!("{JOB}\u{2028}")),
        ("space", format!("{JOB} ")),
        ("non-ascii", format!("{JOB}\u{e9}")),
        ("over-long", long),
    ];
    for (label, id) in cases {
        let err = read_job_timing(&pool, Some(1), &get(&id))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{label}");
        assert!(!err.message().contains(JOB), "{label}");
    }
}

#[sqlx::test]
async fn a_stored_row_that_breaks_the_sum_fails_closed(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    store_timing(&pool, &lease_box(), &request(0, vec![span(0)], vec![]))
        .await
        .unwrap();
    sqlx::query("UPDATE job_timing SET wall_ms = wall_ms + 1")
        .execute(&pool)
        .await
        .unwrap();
    let err = read_job_timing(&pool, None, &get(JOB)).await.unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert!(!err.message().contains("wall"));
}

#[sqlx::test]
async fn a_report_at_the_caps_reads_back_whole(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let spans: Vec<TimingSpan> = (0..MAX_SPANS as u64).map(span).collect();
    let commands: Vec<ShellCommand> = (0..MAX_SHELL_COMMANDS)
        .map(|n| {
            let mut c = command(&format!("c{n}"));
            c.log = "x".repeat(MAX_SHELL_LOG_BYTES);
            c.command = "y".repeat(MAX_COMMAND_BYTES);
            c
        })
        .collect();
    store_timing(&pool, &lease_box(), &request(0, spans, commands))
        .await
        .unwrap();
    let reply = read_job_timing(&pool, None, &get(JOB)).await.unwrap();
    assert_eq!(reply.spans.len(), MAX_SPANS);
    assert_eq!(reply.shell_commands.len(), MAX_SHELL_COMMANDS);
    assert_eq!(reply.shell_commands[0].log.len(), MAX_SHELL_LOG_BYTES);
}

#[sqlx::test]
async fn printable_hostile_ids_are_inert_and_read_as_not_found(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let alice = user(&pool, "alice").await;
    own(&pool, alice).await;
    let unknown = read_job_timing(&pool, Some(alice), &get("01JTIMINGSTORE00000000000Z"))
        .await
        .unwrap_err();
    let cases = [
        format!("user@{JOB}"),
        format!("{JOB}\\"),
        "[::1]".to_owned(),
        format!("{JOB}%00"),
        format!("{JOB}'--"),
        format!("{JOB}'OR'1'='1"),
        "%".to_owned(),
        "_".to_owned(),
    ];
    for id in cases {
        let err = read_job_timing(&pool, Some(alice), &get(&id))
            .await
            .unwrap_err();
        assert_eq!(err.code(), unknown.code(), "{id}");
        assert_eq!(err.message(), unknown.message(), "{id}");
    }
}

type Bucket = fn(&mut TimingSummary) -> &mut u64;

const IDLE_BOTH_ENDS_WALL: u64 = 10_000;

fn idle_both_ends() -> ReportTimingRequest {
    let spans = vec![
        TimingSpan {
            kind: TimingSpanKind::Api as i32,
            ..tool_span(2_000, 3_000)
        },
        tool_span(3_000, 4_000),
        TimingSpan {
            kind: TimingSpanKind::Shell as i32,
            ..tool_span(4_000, 5_000)
        },
    ];
    let core: Vec<Span> = spans
        .iter()
        .map(|s| Span {
            kind: core_kind(s.kind),
            interval: Interval::new(s.start_ms, s.end_ms).unwrap(),
        })
        .collect();
    let job = Interval::new(0, IDLE_BOTH_ENDS_WALL).unwrap();
    let parts = aggregate(&core, job, Interval::new(1_000, 9_000).unwrap());
    assert_eq!(
        [
            parts.api_wait_ms,
            parts.tool_ms,
            parts.shell_ms,
            parts.idle_ms,
            parts.overhead_ms
        ],
        [1_000, 1_000, 1_000, 5_000, 2_000]
    );
    ReportTimingRequest {
        summary: Some(TimingSummary {
            wall_ms: IDLE_BOTH_ENDS_WALL,
            api_wait_ms: parts.api_wait_ms,
            tool_ms: parts.tool_ms,
            shell_ms: parts.shell_ms,
            idle_ms: parts.idle_ms,
            overhead_ms: parts.overhead_ms,
        }),
        agent_start_ms: 1_000,
        agent_end_ms: 9_000,
        spans,
        ..request(0, vec![], vec![])
    }
}

#[sqlx::test]
async fn an_honest_report_with_idle_time_at_both_ends_of_the_agent_window_is_accepted(
    pool: PgPool,
) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    store_timing(&pool, &lease_box(), &idle_both_ends())
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 3, 0));
}

#[sqlx::test]
async fn an_agent_window_outside_the_job_window_is_refused_with_the_exact_reason(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let honest = idle_both_ends();
    let mut cases = Vec::new();
    let mut past = honest.clone();
    past.agent_end_ms = IDLE_BOTH_ENDS_WALL + 1;
    cases.push(("end one past wall", past));
    let mut huge = honest.clone();
    huge.agent_end_ms = u64::MAX;
    cases.push(("end u64 max", huge));
    let mut reversed = honest.clone();
    reversed.agent_start_ms = honest.agent_end_ms + 1;
    cases.push(("start after end", reversed));
    let mut start_past = honest.clone();
    start_past.agent_start_ms = IDLE_BOTH_ENDS_WALL + 1;
    start_past.agent_end_ms = IDLE_BOTH_ENDS_WALL + 1;
    cases.push(("both past wall", start_past));
    for (label, bad) in cases {
        refused(&pool, &bad, REASON_AGENT_WINDOW, label).await;
    }
    store_timing(&pool, &lease_box(), &honest).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 3, 0));
}

#[sqlx::test]
async fn a_summary_that_differs_by_one_ms_in_any_bucket_is_refused_with_the_exact_reason(
    pool: PgPool,
) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let honest = idle_both_ends();
    let buckets: [(&str, Bucket); 5] = [
        ("api", |s| &mut s.api_wait_ms),
        ("tool", |s| &mut s.tool_ms),
        ("shell", |s| &mut s.shell_ms),
        ("idle", |s| &mut s.idle_ms),
        ("overhead", |s| &mut s.overhead_ms),
    ];
    for (up_label, up) in buckets {
        for (down_label, down) in buckets {
            if up_label == down_label {
                continue;
            }
            let mut r = honest.clone();
            let parts = r.summary.as_mut().unwrap();
            *up(parts) += 1;
            *down(parts) -= 1;
            refused(
                &pool,
                &r,
                REASON_SUMMARY_MISMATCH,
                &format!("{up_label} up {down_label} down"),
            )
            .await;
        }
    }
    store_timing(&pool, &lease_box(), &honest).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 3, 0));
}

#[sqlx::test]
async fn a_report_that_sends_no_agent_window_means_the_agent_never_ran(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let mut old = idle_both_ends();
    old.agent_start_ms = 0;
    old.agent_end_ms = 0;
    refused(&pool, &old, REASON_SUMMARY_MISMATCH, "old reporter").await;
    let mut never_ran = idle_both_ends();
    never_ran.agent_start_ms = 0;
    never_ran.agent_end_ms = 0;
    never_ran.spans.clear();
    never_ran.summary = Some(TimingSummary {
        wall_ms: IDLE_BOTH_ENDS_WALL,
        overhead_ms: IDLE_BOTH_ENDS_WALL,
        ..TimingSummary::default()
    });
    store_timing(&pool, &lease_box(), &never_ran).await.unwrap();
    assert_eq!(counts(&pool).await, (1, 0, 0));
}

#[sqlx::test]
async fn the_lease_check_still_comes_before_the_window_checks(pool: PgPool) {
    sqlx::migrate!().run(&pool).await.unwrap();
    running_job(&pool).await;
    let mut bad = idle_both_ends();
    bad.agent_end_ms = u64::MAX;
    let other = BoxName::new(&format!("box-{}", 2)).unwrap();
    let err = store_timing(&pool, &other, &bad).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(counts(&pool).await, (0, 0, 0));
}
