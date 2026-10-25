//! Job telemetry ingest through `report_job`. The tests need a Postgres superuser URL in
//! `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_core::BoxName;
use fleet_proto::v1::{
    Job, JobEvent, JobEventKind, JobState, JobSummary, ReportJobRequest, SubmitJobRequest,
};
use fleet_proto::{
    MAX_EVENT_CMD_BYTES, MAX_EVENT_DETAIL_BYTES, MAX_EVENTS_PER_JOB, MAX_EVENTS_PER_REPORT,
};
use fleet_server::store::{MAX_TS_MS, Store, StoreError};
use serde_json::{Value, json};
use sqlx::PgPool;

fn name(n: u32) -> String {
    format!("box-{n}")
}

fn boxed(n: u32) -> BoxName {
    BoxName::new(&name(n)).unwrap()
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

async fn claimed(store: &Store) -> Job {
    store
        .submit_job(&SubmitJobRequest {
            idempotency_key: "tk".to_owned(),
            prompt: "add hello.txt".to_owned(),
            repo: "https://example.com/org/repo.git".to_owned(),
            base_ref: "main".to_owned(),
            open_pr: true,
        })
        .await
        .unwrap();
    store.claim_job(&boxed(1)).await.unwrap().unwrap()
}

fn event(seq: u32) -> JobEvent {
    JobEvent {
        seq,
        ts_ms: u64::from(seq) * 10,
        kind: JobEventKind::Tool.into(),
        ..JobEvent::default()
    }
}

fn report(job: &Job, events: Vec<JobEvent>, summary: Option<JobSummary>) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job.job_id.clone(),
        attempt: job.attempt,
        r#box: name(1),
        phase: "running".to_owned(),
        progress: "working".to_owned(),
        events,
        summary,
        ..ReportJobRequest::default()
    }
}

async fn send(
    store: &Store,
    job: &Job,
    events: Vec<JobEvent>,
    summary: Option<JobSummary>,
) -> Result<(), StoreError> {
    store
        .report_job(&boxed(1), &report(job, events, summary))
        .await
        .map(|_| ())
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    let sql = match table {
        "job_event" => "SELECT count(*) FROM job_event",
        _ => "SELECT count(*) FROM job_summary",
    };
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

async fn event_row(pool: &PgPool, seq: i32) -> Value {
    let text: String =
        sqlx::query_scalar("SELECT (to_jsonb(e) - 'job_id')::text FROM job_event e WHERE seq = $1")
            .bind(seq)
            .fetch_one(pool)
            .await
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[sqlx::test]
async fn events_are_stored_and_replay_is_idempotent(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let mut full = event(2);
    full.tool_use_id = Some("tu".to_owned());
    full.tool = Some("Bash".to_owned());
    full.ok = Some(false);
    full.exit_code = Some(-3);
    full.dur_ms = Some(7);
    full.out_bytes = Some(9);
    full.out_hash = Some("abcd".to_owned());
    full.cmd = Some("ls".to_owned());
    full.detail = Some("d".to_owned());
    full.kind = JobEventKind::Denial.into();
    full.ts_ms = u64::MAX;
    let batch = vec![event(1), full, event(3)];
    send(&store, &job, batch.clone(), None).await.unwrap();
    send(&store, &job, batch, None).await.unwrap();
    assert_eq!(count(&pool, "job_event").await, 3);
    assert_eq!(
        event_row(&pool, 1).await,
        json!({
            "seq": 1, "ts_ms": 10, "kind": "tool", "tool_use_id": null, "tool": null,
            "ok": null, "exit_code": null, "dur_ms": null, "out_bytes": null,
            "out_hash": null, "cmd": null, "detail": null
        })
    );
    assert_eq!(
        event_row(&pool, 2).await,
        json!({
            "seq": 2, "ts_ms": MAX_TS_MS, "kind": "denial", "tool_use_id": "tu",
            "tool": "Bash", "ok": false, "exit_code": -3, "dur_ms": 7, "out_bytes": 9,
            "out_hash": "abcd", "cmd": "ls", "detail": "d"
        })
    );
}

#[sqlx::test]
async fn every_kind_maps_to_its_stored_name(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let kinds = [
        JobEventKind::Tool,
        JobEventKind::Denial,
        JobEventKind::ApiRetry,
        JobEventKind::Phase,
        JobEventKind::Stuck,
    ];
    let events = kinds
        .iter()
        .zip(0_u32..)
        .map(|(kind, seq)| JobEvent {
            kind: (*kind).into(),
            ..event(seq)
        })
        .collect();
    send(&store, &job, events, None).await.unwrap();
    let stored: Vec<String> = sqlx::query_scalar("SELECT kind FROM job_event ORDER BY seq")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(stored, ["tool", "denial", "api_retry", "phase", "stuck"]);
}

#[sqlx::test]
async fn oversized_batch_is_rejected_whole(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let max = u32::try_from(MAX_EVENTS_PER_REPORT).unwrap();
    send(&store, &job, (0..max).map(event).collect(), None)
        .await
        .unwrap();
    assert_eq!(count(&pool, "job_event").await, i64::from(max));
    let err = send(
        &store,
        &job,
        (0..=max).map(|n| event(n + 1000)).collect(),
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::TelemetryTooLarge));
    assert_eq!(count(&pool, "job_event").await, i64::from(max));
}

#[sqlx::test]
async fn events_at_or_past_the_job_cap_are_dropped(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let last = MAX_EVENTS_PER_JOB - 1;
    send(
        &store,
        &job,
        vec![
            event(last - 1),
            event(last),
            event(last + 1),
            event(u32::MAX),
        ],
        None,
    )
    .await
    .unwrap();
    let seqs: Vec<i32> = sqlx::query_scalar("SELECT seq FROM job_event ORDER BY seq")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        seqs,
        [
            i32::try_from(last - 1).unwrap(),
            i32::try_from(last).unwrap()
        ]
    );
}

#[sqlx::test]
async fn cmd_and_detail_are_cut_at_a_utf8_boundary(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let euro = "\u{20ac}";
    let mut cut = event(1);
    cut.cmd = Some(euro.repeat(300));
    cut.detail = Some(euro.repeat(400));
    let mut exact = event(2);
    exact.cmd = Some("a".repeat(MAX_EVENT_CMD_BYTES));
    exact.detail = Some("b".repeat(MAX_EVENT_DETAIL_BYTES));
    let mut over = event(3);
    over.cmd = Some("a".repeat(MAX_EVENT_CMD_BYTES + 1));
    over.detail = Some("b".repeat(MAX_EVENT_DETAIL_BYTES + 1));
    send(&store, &job, vec![cut, exact, over], None)
        .await
        .unwrap();
    let rows: Vec<(i32, i32, i32, String)> = sqlx::query_as(
        "SELECT seq, octet_length(cmd), octet_length(detail), left(cmd, 1) \
         FROM job_event ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let cap_cmd = i32::try_from(MAX_EVENT_CMD_BYTES).unwrap();
    let cap_detail = i32::try_from(MAX_EVENT_DETAIL_BYTES).unwrap();
    assert_eq!(
        rows,
        [
            (1, 510, 1023, euro.to_owned()),
            (2, cap_cmd, cap_detail, "a".to_owned()),
            (3, cap_cmd, cap_detail, "a".to_owned()),
        ]
    );
}

fn full_summary() -> JobSummary {
    JobSummary {
        turns: Some(3),
        duration_ms: Some(4),
        duration_api_ms: Some(5),
        stop_reason: Some("end_turn".to_owned()),
        result_subtype: Some("success".to_owned()),
        cost_est_usd: Some(0.25),
        tokens_in: Some(6),
        tokens_out: Some(7),
        tokens_cache_read: Some(8),
        tokens_cache_write: Some(9),
        tool_calls: Some(10),
        tool_errors: Some(11),
        bash_calls: Some(12),
        bash_nonzero: Some(13),
        denials: Some(14),
        api_retries: Some(15),
        first_edit_ms: Some(16),
        complete: true,
        missing: vec!["a".to_owned(), "b".to_owned()],
    }
}

async fn figures(pool: &PgPool) -> Value {
    let text: String = sqlx::query_scalar(
        "SELECT (to_jsonb(s) - 'job_id' - 'updated_at')::text FROM job_summary s",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[sqlx::test]
async fn summary_upsert_keeps_unobserved_as_null(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    send(&store, &job, Vec::new(), Some(full_summary()))
        .await
        .unwrap();
    assert_eq!(
        figures(&pool).await,
        json!({
            "turns": 3, "duration_ms": 4, "duration_api_ms": 5, "stop_reason": "end_turn",
            "result_subtype": "success", "cost_est_usd": 0.25, "tokens_in": 6, "tokens_out": 7,
            "tokens_cache_read": 8, "tokens_cache_write": 9, "tool_calls": 10,
            "tool_errors": 11, "bash_calls": 12, "bash_nonzero": 13, "denials": 14,
            "api_retries": 15, "first_edit_ms": 16, "complete": true, "missing": ["a", "b"]
        })
    );
    let sparse = JobSummary {
        turns: Some(0),
        missing: vec!["result".to_owned()],
        ..JobSummary::default()
    };
    send(&store, &job, Vec::new(), Some(sparse)).await.unwrap();
    assert_eq!(count(&pool, "job_summary").await, 1);
    assert_eq!(
        figures(&pool).await,
        json!({
            "turns": 0, "duration_ms": null, "duration_api_ms": null, "stop_reason": null,
            "result_subtype": null, "cost_est_usd": null, "tokens_in": null,
            "tokens_out": null, "tokens_cache_read": null, "tokens_cache_write": null,
            "tool_calls": null, "tool_errors": null, "bash_calls": null,
            "bash_nonzero": null, "denials": null, "api_retries": null,
            "first_edit_ms": null, "complete": false, "missing": ["result"]
        })
    );
}

#[sqlx::test]
async fn report_without_summary_keeps_the_stored_one(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    send(&store, &job, Vec::new(), Some(full_summary()))
        .await
        .unwrap();
    send(&store, &job, vec![event(1)], None).await.unwrap();
    assert_eq!(figures(&pool).await["turns"], 3);
}

#[sqlx::test]
async fn deleting_the_job_cascades(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    send(&store, &job, vec![event(1)], Some(full_summary()))
        .await
        .unwrap();
    assert_eq!(count(&pool, "job_event").await, 1);
    assert_eq!(count(&pool, "job_summary").await, 1);
    sqlx::query("DELETE FROM jobs")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "job_event").await, 0);
    assert_eq!(count(&pool, "job_summary").await, 0);
}

#[sqlx::test]
async fn only_the_claiming_box_at_the_current_attempt_may_write(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let batch = || (vec![event(1)], Some(full_summary()));
    let (events, summary) = batch();
    let other = store
        .report_job(&boxed(2), &report(&job, events, summary))
        .await
        .unwrap_err();
    assert!(matches!(other, StoreError::StaleReport));
    let (events, summary) = batch();
    let mut stale = report(&job, events, summary);
    stale.attempt += 1;
    let err = store.report_job(&boxed(1), &stale).await.unwrap_err();
    assert!(matches!(err, StoreError::StaleReport));
    let mut end = report(&job, Vec::new(), None);
    end.terminal_state = Some(JobState::Failed.into());
    store.report_job(&boxed(1), &end).await.unwrap();
    let (events, summary) = batch();
    let after = send(&store, &job, events, summary).await.unwrap_err();
    assert!(matches!(after, StoreError::StaleReport));
    assert_eq!(count(&pool, "job_event").await, 0);
    assert_eq!(count(&pool, "job_summary").await, 0);
}

#[sqlx::test]
async fn invalid_telemetry_stores_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let mut nul_cmd = event(1);
    nul_cmd.cmd = Some("a\0b".to_owned());
    let mut nul_detail = event(1);
    nul_detail.detail = Some("a\0b".to_owned());
    let mut nul_tool = event(1);
    nul_tool.tool = Some("a\0b".to_owned());
    let mut kindless = event(1);
    kindless.kind = JobEventKind::Unspecified.into();
    let mut unknown = event(1);
    unknown.kind = 99;
    let mut huge = event(1);
    huge.dur_ms = Some(u64::MAX);
    let events = [nul_cmd, nul_detail, nul_tool, kindless, unknown, huge];
    for bad in events {
        let err = send(&store, &job, vec![event(0), bad], None)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTelemetry));
    }
    let summaries = [
        JobSummary {
            cost_est_usd: Some(f64::NAN),
            ..full_summary()
        },
        JobSummary {
            cost_est_usd: Some(f64::INFINITY),
            ..full_summary()
        },
        JobSummary {
            turns: Some(u64::MAX),
            ..full_summary()
        },
        JobSummary {
            stop_reason: Some("a\0b".to_owned()),
            ..full_summary()
        },
        JobSummary {
            missing: vec!["a\0b".to_owned()],
            ..full_summary()
        },
        JobSummary {
            missing: vec!["m".to_owned(); 33],
            ..full_summary()
        },
    ];
    for bad in summaries {
        let err = send(&store, &job, vec![event(0)], Some(bad))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTelemetry));
    }
    assert_eq!(count(&pool, "job_event").await, 0);
    assert_eq!(count(&pool, "job_summary").await, 0);
}

#[sqlx::test]
async fn text_figures_are_cut_at_a_utf8_boundary(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let euro = "\u{20ac}";
    let summary = JobSummary {
        stop_reason: Some(euro.repeat(100)),
        result_subtype: Some(euro.repeat(100)),
        missing: vec![euro.repeat(100)],
        ..JobSummary::default()
    };
    let mut ev = event(1);
    ev.tool = Some(euro.repeat(100));
    ev.tool_use_id = Some(euro.repeat(100));
    ev.out_hash = Some(euro.repeat(100));
    send(&store, &job, vec![ev], Some(summary)).await.unwrap();
    let lens: (i32, i32, i32) = sqlx::query_as(
        "SELECT octet_length(tool), octet_length(tool_use_id), octet_length(out_hash) \
         FROM job_event",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lens, (126, 126, 63));
    let lens: (i32, i32, i32) = sqlx::query_as(
        "SELECT octet_length(stop_reason), octet_length(result_subtype), \
         octet_length(missing[1]) FROM job_summary",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lens, (63, 63, 63));
}

#[sqlx::test]
async fn ascii_text_is_cut_at_the_cap_and_32_missing_names_pass(pool: PgPool) {
    let store = store(pool.clone()).await;
    let job = claimed(&store).await;
    let long = "x".repeat(300);
    let summary = JobSummary {
        stop_reason: Some(long.clone()),
        result_subtype: Some(long.clone()),
        missing: vec![long.clone(); 32],
        ..JobSummary::default()
    };
    let mut ev = event(1);
    ev.tool = Some(long.clone());
    ev.tool_use_id = Some(long.clone());
    ev.out_hash = Some(long);
    send(&store, &job, vec![ev], Some(summary)).await.unwrap();
    let lens: (i32, i32, i32) = sqlx::query_as(
        "SELECT octet_length(tool), octet_length(tool_use_id), octet_length(out_hash) \
         FROM job_event",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lens, (128, 128, 64));
    let lens: (i32, i32, i32, i32) = sqlx::query_as(
        "SELECT octet_length(stop_reason), octet_length(result_subtype), \
         octet_length(missing[1]), cardinality(missing) FROM job_summary",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lens, (64, 64, 64, 32));
}

#[test]
fn wire_limits_are_pinned() {
    assert_eq!(MAX_EVENTS_PER_REPORT, 256);
    assert_eq!(MAX_EVENTS_PER_JOB, 2000);
    assert_eq!(MAX_EVENT_CMD_BYTES, 512);
    assert_eq!(MAX_EVENT_DETAIL_BYTES, 1024);
}
