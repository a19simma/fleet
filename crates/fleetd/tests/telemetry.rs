//! Telemetry parser over recorded and hand-written stream-json lines.

use fleetd::telemetry::{
    EventKind, FetchPhase, FetchRecordError, JobEvent, Limits, MAX_FETCH_URL_BYTES, Telemetry,
    Terminal,
};
use serde_json::{Value, json};

const SMOKE: &str = include_str!("fixtures/smoke-success.jsonl");
const TOOL_ERROR: &str = include_str!("fixtures/tool-error.jsonl");
const API_RETRY: &str = include_str!("fixtures/api-retry.jsonl");
const DENIED: &str = include_str!("fixtures/permission-denied.jsonl");
const MAX_TURNS: &str = include_str!("fixtures/max-turns.jsonl");
const TRUNCATED: &str = include_str!("fixtures/truncated.jsonl");

fn assert_no_events(events: &[JobEvent]) {
    assert_eq!(events, Vec::<JobEvent>::new());
}

fn feed_all(telemetry: &mut Telemetry, text: &str) -> Vec<JobEvent> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        out.extend(telemetry.feed_line(line, i as u64 * 100));
    }
    out
}

fn tool_use(id: &str, name: &str, input: &Value) -> String {
    json!({"type":"assistant","message":{"id":format!("m_{id}"),"content":[
        {"type":"tool_use","id":id,"name":name,"input":input}]}})
    .to_string()
}

fn tool_result(id: &str, content: &Value, is_error: bool) -> String {
    json!({"type":"user","message":{"content":[
        {"type":"tool_result","tool_use_id":id,"content":content,"is_error":is_error}]}})
    .to_string()
}

fn bash(command: &str) -> Value {
    json!({ "command": command })
}

fn pair(telemetry: &mut Telemetry, id: &str, command: &str, ts: u64) -> Vec<JobEvent> {
    telemetry.feed_line(&tool_use(id, "Bash", &bash(command)), ts);
    telemetry.feed_line(&tool_result(id, &json!("out"), false), ts + 10)
}

fn limits(max_events: usize, max_event_bytes: u64, cmd_cap: usize, detail_cap: usize) -> Limits {
    Limits {
        max_events,
        max_event_bytes,
        cmd_cap,
        detail_cap,
    }
}

#[test]
fn smoke_fixture_yields_one_tool_event_and_complete_summary() {
    let mut telemetry = Telemetry::new(Limits::default());
    let events = feed_all(&mut telemetry, SMOKE);
    assert_eq!(events.len(), 1);
    let event = events.first().unwrap();
    assert_eq!(event.seq, 0);
    assert_eq!(event.kind, EventKind::Tool);
    assert_eq!(event.tool.as_deref(), Some("Bash"));
    assert_eq!(
        event.tool_use_id.as_deref(),
        Some("toolu_01UPzudVTvR329xYwtdetTHx")
    );
    assert_eq!(event.ts_ms, 300);
    assert_eq!(event.dur_ms, Some(200));
    assert_eq!(event.ok, Some(true));
    assert_eq!(event.exit_code, None);
    assert_eq!(event.out_bytes, Some(86));
    assert_eq!(event.out_hash.as_ref().map(String::len), Some(16));
    assert!(event.cmd.as_deref().unwrap().starts_with("mkdir -p docs"));
    assert_eq!(telemetry.ignored(), 1);

    let summary = telemetry.finish(Terminal::Succeeded);
    assert!(summary.complete);
    assert_eq!(summary.turns, Some(2));
    assert_eq!(summary.duration_ms, Some(4146));
    assert_eq!(summary.duration_api_ms, Some(4075));
    assert_eq!(summary.stop_reason.as_deref(), Some("end_turn"));
    assert_eq!(summary.result_subtype.as_deref(), Some("success"));
    assert_eq!(summary.cost_est_usd, Some(0.032_247));
    assert_eq!(summary.tokens_in, Some(4));
    assert_eq!(summary.tokens_out, Some(292));
    assert_eq!(summary.tokens_cache_read, Some(26195));
    assert_eq!(summary.tokens_cache_write, Some(6020));
    assert_eq!(summary.tool_calls, Some(1));
    assert_eq!(summary.tool_errors, Some(0));
    assert_eq!(summary.bash_calls, Some(1));
    assert_eq!(summary.bash_nonzero, None);
    assert_eq!(summary.denials, Some(0));
    assert_eq!(summary.api_retries, Some(0));
    assert_eq!(summary.first_edit_ms, None);
    assert_eq!(
        summary.missing,
        vec!["exit_codes".to_owned(), "hooks".to_owned()]
    );
    assert_eq!(summary.terminal, Some(Terminal::Succeeded));
}

#[test]
fn transcript_without_result_is_incomplete_and_figures_stay_none() {
    let mut telemetry = Telemetry::new(Limits::default());
    let head: String = SMOKE.lines().take(5).collect::<Vec<_>>().join("\n");
    feed_all(&mut telemetry, &head);
    let summary = telemetry.finish(Terminal::Failed);
    assert!(!summary.complete);
    assert!(summary.missing.contains(&"result".to_owned()));
    assert_eq!(summary.cost_est_usd, None);
    assert_eq!(summary.turns, None);
    assert_eq!(summary.duration_ms, None);
    assert_eq!(summary.duration_api_ms, None);
    assert_eq!(summary.stop_reason, None);
    assert_eq!(summary.result_subtype, None);
    assert_eq!(summary.tokens_in, Some(4));
    assert_eq!(summary.tokens_out, Some(153));
    assert_eq!(summary.tokens_cache_read, Some(26195));
    assert_eq!(summary.tokens_cache_write, Some(6020));
    assert_eq!(summary.terminal, Some(Terminal::Failed));
}

#[test]
fn empty_stream_reports_nothing_observed() {
    let summary = Telemetry::new(Limits::default()).finish(Terminal::Cancelled);
    assert!(!summary.complete);
    assert_eq!(summary.tool_calls, None);
    assert_eq!(summary.tool_errors, None);
    assert_eq!(summary.bash_calls, None);
    assert_eq!(summary.denials, None);
    assert_eq!(summary.api_retries, None);
    assert_eq!(summary.tokens_in, None);
    assert_eq!(summary.bash_nonzero, None);
    assert!(summary.missing.contains(&"result".to_owned()));
    assert!(summary.missing.contains(&"exit_codes".to_owned()));
}

#[test]
fn fallback_tokens_count_one_message_once_and_result_overrides() {
    let mut telemetry = Telemetry::new(Limits::default());
    let line = json!({"type":"assistant","message":{"id":"m1","content":[],
        "usage":{"input_tokens":2,"output_tokens":3}}})
    .to_string();
    telemetry.feed_line(&line, 0);
    telemetry.feed_line(&line, 1);
    let other = json!({"type":"assistant","message":{"id":"m2","content":[],
        "usage":{"input_tokens":5,"output_tokens":7}}})
    .to_string();
    telemetry.feed_line(&other, 2);
    let summary = telemetry.summary();
    assert_eq!(summary.tokens_in, Some(7));
    assert_eq!(summary.tokens_out, Some(10));
    assert_eq!(summary.tokens_cache_read, None);
    telemetry.feed_line(
        &json!({"type":"result","subtype":"success","usage":{"input_tokens":1,"output_tokens":1}})
            .to_string(),
        3,
    );
    let summary = telemetry.summary();
    assert_eq!(summary.tokens_in, Some(1));
    assert_eq!(summary.tokens_out, Some(1));
}

#[test]
fn event_cap_drops_events_and_emits_one_truncation_marker() {
    let mut telemetry = Telemetry::new(limits(3, 1 << 20, 512, 1024));
    let mut emitted = Vec::new();
    for i in 0..5 {
        emitted.extend(pair(&mut telemetry, &format!("t{i}"), "ls", i * 100));
    }
    assert_eq!(emitted, telemetry.events());
    assert_eq!(emitted.len(), 4);
    let kinds: Vec<_> = emitted.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            EventKind::Tool,
            EventKind::Tool,
            EventKind::Tool,
            EventKind::Phase
        ]
    );
    let marker = emitted.last().unwrap();
    assert_eq!(marker.detail.as_deref(), Some("truncated"));
    assert_eq!(marker.seq, 3);
    let summary = telemetry.summary();
    assert!(summary.missing.contains(&"events_truncated".to_owned()));
    assert_eq!(summary.tool_calls, Some(5));
}

#[test]
fn event_cap_of_exactly_the_event_count_does_not_truncate() {
    let mut telemetry = Telemetry::new(limits(3, 1 << 20, 512, 1024));
    for i in 0..3 {
        pair(&mut telemetry, &format!("t{i}"), "ls", i * 100);
    }
    assert_eq!(telemetry.events().len(), 3);
    assert!(telemetry.events().iter().all(|e| e.kind == EventKind::Tool));
    assert!(
        !telemetry
            .summary()
            .missing
            .contains(&"events_truncated".to_owned())
    );
}

#[test]
fn byte_cap_boundary() {
    let mut probe = Telemetry::new(Limits::default());
    let size = pair(&mut probe, "t0", "ls", 0)
        .first()
        .unwrap()
        .approx_size();

    let mut fits = Telemetry::new(limits(100, size, 512, 1024));
    pair(&mut fits, "t0", "ls", 0);
    assert_eq!(fits.events().len(), 1);
    assert_eq!(fits.events().first().unwrap().kind, EventKind::Tool);
    pair(&mut fits, "t1", "ls", 100);
    pair(&mut fits, "t2", "ls", 200);
    let kinds: Vec<_> = fits.events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Tool, EventKind::Phase]);
    assert!(
        fits.summary()
            .missing
            .contains(&"events_truncated".to_owned())
    );

    let mut over = Telemetry::new(limits(100, size - 1, 512, 1024));
    pair(&mut over, "t0", "ls", 0);
    let kinds: Vec<_> = over.events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Phase]);
}

#[test]
fn cmd_truncates_at_cap_not_below() {
    let mut telemetry = Telemetry::new(limits(100, 1 << 20, 10, 1024));
    let at = pair(&mut telemetry, "a", "0123456789", 0);
    let over = pair(&mut telemetry, "b", "0123456789X", 100);
    assert_eq!(at.first().unwrap().cmd.as_deref(), Some("0123456789"));
    assert_eq!(over.first().unwrap().cmd.as_deref(), Some("0123456789"));
}

#[test]
fn cmd_truncation_respects_char_boundaries() {
    let mut telemetry = Telemetry::new(limits(100, 1 << 20, 3, 1024));
    let events = pair(&mut telemetry, "a", "\u{e9}\u{e9}", 0);
    assert_eq!(events.first().unwrap().cmd.as_deref(), Some("\u{e9}"));
}

fn mask(text: &str) -> String {
    text.replace("SECRETVALUE", "[R]")
}

#[test]
fn redaction_runs_before_the_cut_on_cmd_detail_and_tool() {
    let mut telemetry = Telemetry::new(limits(100, 1 << 20, 12, 12));
    let use_line = tool_use(
        "a",
        "SECRETVALUE",
        &json!({"file_path":"aaaaaaaaSECRETVALUE"}),
    );
    telemetry.feed_line_with(&use_line, 0, &mask);
    let result = tool_result("a", &json!("out"), false);
    let tool = telemetry.feed_line_with(&result, 1, &mask);
    assert_eq!(tool.first().unwrap().cmd.as_deref(), Some("aaaaaaaa[R]"));
    assert_eq!(tool.first().unwrap().tool.as_deref(), Some("[R]"));
    let denial = json!({"type":"system","subtype":"permission_denied",
        "tool_name":"SECRETVALUE","tool_use_id":"d","message":"aaaaaaaaSECRETVALUE"})
    .to_string();
    let denied = telemetry.feed_line_with(&denial, 2, &mask);
    assert_eq!(
        denied.first().unwrap().detail.as_deref(),
        Some("aaaaaaaa[R]")
    );
    assert_eq!(denied.first().unwrap().tool.as_deref(), Some("[R]"));
}

#[test]
fn feed_line_keeps_text_unredacted() {
    let mut telemetry = Telemetry::new(limits(100, 1 << 20, 12, 12));
    let events = pair(&mut telemetry, "a", "aaaaaaaaSECRETVALUE", 0);
    assert_eq!(events.first().unwrap().cmd.as_deref(), Some("aaaaaaaaSECR"));
}

#[test]
fn cmd_for_file_tools_is_the_file_path() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("r", "Read", &json!({"file_path":"/a/b.rs"})), 0);
    let events = telemetry.feed_line(&tool_result("r", &json!("x"), false), 5);
    assert_eq!(events.first().unwrap().cmd.as_deref(), Some("/a/b.rs"));
    assert_eq!(events.first().unwrap().tool.as_deref(), Some("Read"));
}

#[test]
fn detail_truncates_at_cap_not_below() {
    let at =
        json!({"type":"system","subtype":"permission_denied","tool_name":"Bash","message":"abcde"});
    let over = json!({"type":"system","subtype":"permission_denied","tool_name":"Bash","message":"abcdef"});
    let mut telemetry = Telemetry::new(limits(100, 1 << 20, 512, 5));
    let first = telemetry.feed_line(&at.to_string(), 0);
    let second = telemetry.feed_line(&over.to_string(), 1);
    assert_eq!(first.first().unwrap().detail.as_deref(), Some("abcde"));
    assert_eq!(second.first().unwrap().detail.as_deref(), Some("abcde"));
}

#[test]
fn api_retry_detail_is_capped() {
    let mut telemetry = Telemetry::new(limits(100, 1 << 20, 512, 3));
    let events = feed_all(&mut telemetry, API_RETRY);
    assert_eq!(events.first().unwrap().detail.as_deref(), Some("att"));
}

#[test]
fn out_hash_is_stable_sixteen_hex_of_sha256() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("a", "Bash", &bash("x")), 0);
    let first = telemetry.feed_line(&tool_result("a", &json!("hello"), false), 1);
    telemetry.feed_line(&tool_use("b", "Bash", &bash("x")), 2);
    let second = telemetry.feed_line(
        &tool_result(
            "b",
            &json!([{"type":"text","text":"hel"},{"type":"text","text":"lo"}]),
            false,
        ),
        3,
    );
    let first = first.first().unwrap();
    let second = second.first().unwrap();
    assert_eq!(first.out_hash.as_deref(), Some("2cf24dba5fb0a30e"));
    assert_eq!(first.out_hash, second.out_hash);
    assert_eq!(first.out_bytes, Some(5));
    assert_eq!(second.out_bytes, Some(5));
}

#[test]
fn out_bytes_counts_bytes_not_chars() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("a", "Bash", &bash("x")), 0);
    let events = telemetry.feed_line(&tool_result("a", &json!("\u{e9}"), false), 1);
    assert_eq!(events.first().unwrap().out_bytes, Some(2));
}

#[test]
fn garbage_truncated_and_non_object_lines_are_counted_not_fatal() {
    let mut telemetry = Telemetry::new(Limits::default());
    let lines = [
        "not json", TRUNCATED, "", "[1,2]", "42", "{}", "null", "\"s\"",
    ];
    for (i, line) in lines.iter().enumerate() {
        assert_no_events(&telemetry.feed_line(line, i as u64));
    }
    assert_eq!(telemetry.ignored(), 8);
    assert_no_events(telemetry.events());
    let summary = telemetry.finish(Terminal::Failed);
    assert!(!summary.complete);
}

#[test]
fn unknown_json_types_are_ignored() {
    let mut telemetry = Telemetry::new(Limits::default());
    assert_no_events(&telemetry.feed_line(r#"{"type":"mystery","x":1}"#, 0));
    assert_no_events(&telemetry.feed_line(r#"{"type":"system","subtype":"weird"}"#, 1));
    assert_no_events(&telemetry.feed_line(r#"{"type":5}"#, 2));
    assert_eq!(telemetry.ignored(), 3);
    assert_eq!(telemetry.summary().tool_calls, None);
}

#[test]
fn init_line_is_skipped_without_counting() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(r#"{"type":"system","subtype":"init","tools":[]}"#, 0);
    assert_eq!(telemetry.ignored(), 0);
    assert_eq!(telemetry.summary().tool_calls, None);
}

#[test]
fn tool_use_without_result_is_unmatched() {
    let mut telemetry = Telemetry::new(Limits::default());
    let events = telemetry.feed_line(&tool_use("a", "Bash", &bash("sleep 1")), 0);
    assert_no_events(&events);
    assert_eq!(telemetry.unmatched(), 1);
    let summary = telemetry.finish(Terminal::TimedOut);
    assert!(summary.missing.contains(&"tool_results".to_owned()));
    assert_eq!(summary.tool_calls, Some(1));
}

#[test]
fn matched_tool_use_is_not_unmatched() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    assert_eq!(telemetry.unmatched(), 0);
    assert!(
        !telemetry
            .summary()
            .missing
            .contains(&"tool_results".to_owned())
    );
}

#[test]
fn tool_result_for_unknown_id_is_ignored() {
    let mut telemetry = Telemetry::new(Limits::default());
    let events = telemetry.feed_line(&tool_result("ghost", &json!("x"), false), 0);
    assert_no_events(&events);
    assert_eq!(telemetry.ignored(), 1);
}

#[test]
fn error_result_sets_ok_false_and_counts_error() {
    let mut telemetry = Telemetry::new(Limits::default());
    let events = feed_all(&mut telemetry, TOOL_ERROR);
    let event = events.first().unwrap();
    assert_eq!(event.ok, Some(false));
    assert_eq!(event.dur_ms, Some(100));
    assert_eq!(event.out_bytes, Some(4));
    let summary = telemetry.summary();
    assert_eq!(summary.tool_errors, Some(1));
    assert_eq!(summary.tool_calls, Some(1));
    assert_eq!(summary.bash_calls, Some(1));
}

#[test]
fn duration_never_underflows_when_time_goes_backwards() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("a", "Bash", &bash("x")), 500);
    let events = telemetry.feed_line(&tool_result("a", &json!("x"), false), 100);
    assert_eq!(events.first().unwrap().dur_ms, Some(0));
}

#[test]
fn seq_counts_up_from_zero() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    pair(&mut telemetry, "b", "ls", 100);
    let seqs: Vec<_> = telemetry.events().iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![0, 1]);
}

#[test]
fn api_retry_event_carries_attempt() {
    let mut telemetry = Telemetry::new(Limits::default());
    let events = feed_all(&mut telemetry, API_RETRY);
    let event = events.first().unwrap();
    assert_eq!(event.kind, EventKind::ApiRetry);
    assert_eq!(event.detail.as_deref(), Some("attempt 2"));
    assert_eq!(event.ts_ms, 0);
    assert_eq!(telemetry.summary().api_retries, Some(1));
}

#[test]
fn permission_denied_emits_denial_event() {
    let mut telemetry = Telemetry::new(Limits::default());
    let events = feed_all(&mut telemetry, DENIED);
    let event = events.first().unwrap();
    assert_eq!(event.kind, EventKind::Denial);
    assert_eq!(event.tool.as_deref(), Some("Bash"));
    assert_eq!(event.tool_use_id.as_deref(), Some("toolu_d1"));
    assert_eq!(event.detail.as_deref(), Some("denied by policy"));
    assert_eq!(telemetry.summary().denials, Some(1));
}

#[test]
fn max_turns_result_fills_summary_and_takes_larger_denial_count() {
    let mut telemetry = Telemetry::new(Limits::default());
    feed_all(&mut telemetry, MAX_TURNS);
    let summary = telemetry.finish(Terminal::Failed);
    assert!(summary.complete);
    assert_eq!(summary.result_subtype.as_deref(), Some("error_max_turns"));
    assert_eq!(summary.turns, Some(30));
    assert_eq!(summary.duration_ms, Some(90_000));
    assert_eq!(summary.duration_api_ms, Some(80_000));
    assert_eq!(summary.stop_reason.as_deref(), Some("tool_use"));
    assert_eq!(summary.cost_est_usd, Some(1.5));
    assert_eq!(summary.tokens_in, Some(100));
    assert_eq!(summary.tokens_out, Some(200));
    assert_eq!(summary.tokens_cache_read, Some(300));
    assert_eq!(summary.tokens_cache_write, Some(400));
    assert_eq!(summary.denials, Some(2));
}

#[test]
fn result_denial_count_does_not_lower_observed_denials() {
    let mut telemetry = Telemetry::new(Limits::default());
    for i in 0..3 {
        telemetry.feed_line(DENIED, i);
    }
    feed_all(&mut telemetry, MAX_TURNS);
    assert_eq!(telemetry.summary().denials, Some(3));
}

#[test]
fn null_stop_reason_stays_none() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(
        r#"{"type":"result","subtype":"success","stop_reason":null}"#,
        0,
    );
    let summary = telemetry.summary();
    assert_eq!(summary.stop_reason, None);
    assert_eq!(summary.cost_est_usd, None);
    assert_eq!(summary.turns, None);
}

#[test]
fn first_edit_ms_is_the_first_edit_family_tool_use() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("r", "Read", &json!({"file_path":"a"})), 10);
    assert_eq!(telemetry.summary().first_edit_ms, None);
    telemetry.feed_line(&tool_use("e", "Edit", &json!({"file_path":"a"})), 50);
    telemetry.feed_line(&tool_use("w", "Write", &json!({"file_path":"b"})), 90);
    assert_eq!(telemetry.summary().first_edit_ms, Some(50));

    let mut multi = Telemetry::new(Limits::default());
    multi.feed_line(&tool_use("m", "MultiEdit", &json!({"file_path":"a"})), 70);
    assert_eq!(multi.summary().first_edit_ms, Some(70));

    let mut write = Telemetry::new(Limits::default());
    write.feed_line(&tool_use("w", "Write", &json!({"file_path":"a"})), 20);
    assert_eq!(write.summary().first_edit_ms, Some(20));
}

#[test]
fn apply_hook_fills_exit_code_and_duration_and_bash_nonzero() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    pair(&mut telemetry, "b", "false", 100);
    assert_eq!(telemetry.summary().bash_nonzero, None);
    assert!(
        telemetry
            .summary()
            .missing
            .contains(&"exit_codes".to_owned())
    );

    telemetry.apply_hook("a", Some(0), Some(7));
    assert_eq!(telemetry.summary().bash_nonzero, Some(0));
    assert!(
        !telemetry
            .summary()
            .missing
            .contains(&"exit_codes".to_owned())
    );
    telemetry.apply_hook("b", Some(2), Some(50));
    let events = telemetry.events();
    let a = events.first().unwrap();
    let b = events.get(1).unwrap();
    assert_eq!((a.exit_code, a.dur_ms), (Some(0), Some(7)));
    assert_eq!((b.exit_code, b.dur_ms), (Some(2), Some(50)));
    assert_eq!(telemetry.summary().bash_nonzero, Some(1));

    telemetry.apply_hook("a", Some(3), None);
    assert_eq!(telemetry.summary().bash_nonzero, Some(2));
    assert_eq!(telemetry.events().first().unwrap().dur_ms, Some(7));
    telemetry.apply_hook("b", Some(0), None);
    assert_eq!(telemetry.summary().bash_nonzero, Some(1));
}

#[test]
fn apply_hook_without_exit_code_keeps_existing_exit_code() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    telemetry.apply_hook("a", Some(4), Some(1));
    telemetry.apply_hook("a", None, Some(9));
    let event = telemetry.events().first().unwrap();
    assert_eq!(event.exit_code, Some(4));
    assert_eq!(event.dur_ms, Some(9));
    assert_eq!(telemetry.summary().bash_nonzero, Some(1));
}

#[test]
fn apply_hook_on_non_bash_event_does_not_touch_bash_nonzero() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("r", "Read", &json!({"file_path":"a"})), 0);
    telemetry.feed_line(&tool_result("r", &json!("x"), false), 1);
    telemetry.apply_hook("r", Some(1), None);
    assert_eq!(telemetry.events().first().unwrap().exit_code, Some(1));
    assert_eq!(telemetry.summary().bash_nonzero, None);
}

#[test]
fn apply_hook_unknown_id_is_a_no_op() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    let events = telemetry.events().to_vec();
    let summary = telemetry.summary();
    telemetry.apply_hook("nope", Some(9), Some(9));
    assert_eq!(telemetry.events(), events);
    assert_eq!(telemetry.summary(), summary);
}

#[test]
fn apply_hook_does_not_touch_non_tool_events() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(DENIED, 0);
    telemetry.apply_hook("toolu_d1", Some(1), Some(1));
    let event = telemetry.events().first().unwrap();
    assert_eq!(event.exit_code, None);
    assert_eq!(event.dur_ms, None);
}

#[test]
fn limits_default_matches_the_documented_caps() {
    let limits = Limits::default();
    assert_eq!(limits.max_events, 2000);
    assert_eq!(limits.max_event_bytes, 1 << 20);
    assert_eq!(limits.cmd_cap, 512);
    assert_eq!(limits.detail_cap, 1024);
}

#[test]
fn approx_size_is_overhead_plus_every_text_field() {
    assert_eq!(JobEvent::default().approx_size(), 48);
    let event = JobEvent {
        tool_use_id: Some("a".into()),
        tool: Some("bb".into()),
        out_hash: Some("ccc".into()),
        cmd: Some("dddd".into()),
        detail: Some("eeeee".into()),
        ..JobEvent::default()
    };
    assert_eq!(event.approx_size(), 48 + 1 + 2 + 3 + 4 + 5);
}

#[test]
fn truncation_marker_carries_the_dropped_events_time() {
    let mut telemetry = Telemetry::new(limits(1, 1 << 20, 512, 1024));
    pair(&mut telemetry, "a", "ls", 0);
    pair(&mut telemetry, "b", "ls", 700);
    let marker = telemetry.events().last().unwrap();
    assert_eq!(marker.kind, EventKind::Phase);
    assert_eq!(marker.ts_ms, 710);
}

#[test]
fn negative_exit_code_counts_as_nonzero() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    telemetry.apply_hook("a", Some(-1), None);
    assert_eq!(telemetry.summary().bash_nonzero, Some(1));
}

#[test]
fn assistant_messages_without_id_each_count_their_usage() {
    let mut telemetry = Telemetry::new(Limits::default());
    let line =
        json!({"type":"assistant","message":{"content":[],"usage":{"input_tokens":2}}}).to_string();
    telemetry.feed_line(&line, 0);
    telemetry.feed_line(&line, 1);
    assert_eq!(telemetry.summary().tokens_in, Some(4));
}

#[test]
fn tool_use_without_id_is_ignored_and_not_pending() {
    let mut telemetry = Telemetry::new(Limits::default());
    let line = json!({"type":"assistant","message":{"content":[
        {"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}})
    .to_string();
    telemetry.feed_line(&line, 0);
    assert_eq!(telemetry.ignored(), 1);
    assert_eq!(telemetry.unmatched(), 0);
    assert_eq!(telemetry.summary().tool_calls, Some(0));
}

#[test]
fn tool_result_without_is_error_is_ok() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("a", "Bash", &bash("ls")), 0);
    let line = json!({"type":"user","message":{"content":[
        {"type":"tool_result","tool_use_id":"a","content":"x"}]}})
    .to_string();
    let events = telemetry.feed_line(&line, 1);
    assert_eq!(events.first().unwrap().ok, Some(true));
    assert_eq!(telemetry.summary().tool_errors, Some(0));
}

#[test]
fn result_alone_marks_counters_as_observed() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(r#"{"type":"result","subtype":"success"}"#, 0);
    let summary = telemetry.summary();
    assert_eq!(summary.tool_calls, Some(0));
    assert_eq!(summary.denials, Some(0));
}

#[test]
fn the_init_line_gives_the_model_and_a_later_one_does_not_replace_it() {
    let mut parser = Telemetry::new(Limits::default());
    assert_eq!(parser.model(), None);
    parser.feed_line(
        r#"{"type":"system","subtype":"init","model":"claude-opus-4"}"#,
        1,
    );
    assert_eq!(parser.model(), Some("claude-opus-4"));
    parser.feed_line(r#"{"type":"system","subtype":"init","model":"other"}"#, 2);
    assert_eq!(parser.model(), Some("claude-opus-4"));
}

#[test]
fn an_init_line_without_a_usable_model_leaves_it_unset() {
    for line in [
        r#"{"type":"system","subtype":"init"}"#,
        r#"{"type":"system","subtype":"init","model":"  "}"#,
        r#"{"type":"system","subtype":"init","model":7}"#,
    ] {
        let mut parser = Telemetry::new(Limits::default());
        parser.feed_line(line, 1);
        assert_eq!(parser.model(), None, "{line}");
    }
    let mut parser = Telemetry::new(Limits::default());
    let long = format!(
        r#"{{"type":"system","subtype":"init","model":"{}"}}"#,
        "m".repeat(500)
    );
    parser.feed_line(&long, 1);
    assert_eq!(parser.model().map(str::len), Some(128));
}

#[test]
fn a_model_with_a_control_character_is_treated_as_unset() {
    for line in [
        r#"{"type":"system","subtype":"init","model":"a\u001bb"}"#,
        r#"{"type":"system","subtype":"init","model":"a\u001b[0mb"}"#,
        r#"{"type":"system","subtype":"init","model":"a\nb"}"#,
    ] {
        let mut parser = Telemetry::new(Limits::default());
        parser.feed_line(line, 1);
        assert_eq!(parser.model(), None, "{line}");
    }
}

#[test]
fn a_clean_model_still_works_after_a_rejected_one() {
    let mut parser = Telemetry::new(Limits::default());
    parser.feed_line(
        r#"{"type":"system","subtype":"init","model":"a\u001bb"}"#,
        1,
    );
    parser.feed_line(
        r#"{"type":"system","subtype":"init","model":"claude-opus-4"}"#,
        2,
    );
    assert_eq!(parser.model(), Some("claude-opus-4"));
}

#[test]
fn the_recorded_init_line_gives_the_model() {
    let mut telemetry = Telemetry::new(Limits::default());
    feed_all(&mut telemetry, SMOKE);
    let model = SMOKE
        .lines()
        .next()
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .and_then(|init| init["model"].as_str().map(str::to_owned));
    assert!(model.is_some());
    assert_eq!(telemetry.model(), model.as_deref());
}

fn has_hooks_missing(telemetry: &Telemetry) -> bool {
    telemetry.summary().missing.contains(&"hooks".to_owned())
}

#[test]
fn tool_calls_without_a_joined_hook_report_miss_hooks() {
    let mut telemetry = Telemetry::new(Limits::default());
    telemetry.feed_line(&tool_use("a", "Read", &json!({"file_path":"a"})), 0);
    assert_eq!(telemetry.summary().tool_calls, Some(1));
    assert!(has_hooks_missing(&telemetry));
    assert!(!telemetry.apply_hook("nope", Some(0), None));
    assert!(has_hooks_missing(&telemetry));
}

#[test]
fn a_joined_hook_report_clears_hooks_from_missing() {
    let mut telemetry = Telemetry::new(Limits::default());
    pair(&mut telemetry, "a", "ls", 0);
    assert!(telemetry.apply_hook("a", None, Some(3)));
    assert!(!has_hooks_missing(&telemetry));
    assert_eq!(telemetry.summary().tool_calls, Some(1));
}

#[test]
fn zero_tool_calls_never_miss_hooks() {
    let telemetry = Telemetry::new(Limits::default());
    assert_eq!(telemetry.summary().tool_calls, None);
    assert!(!has_hooks_missing(&telemetry));
    let mut with_result = Telemetry::new(Limits::default());
    feed_all(&mut with_result, SMOKE.lines().last().unwrap_or(""));
    assert!(!has_hooks_missing(&with_result));
}

#[test]
fn a_fetch_record_stores_the_whole_url_and_counts_toward_the_cap() {
    let mut telemetry = Telemetry::new(limits(2, 1 << 20, 512, 1024));
    let url = format!("https://h.example/{}", "p".repeat(MAX_FETCH_URL_BYTES - 18));
    let mut out = Vec::new();
    telemetry
        .record_fetch(&url, FetchPhase::Intent, 7, &str::to_owned, &mut out)
        .unwrap();
    telemetry
        .record_fetch(
            &url,
            FetchPhase::Failed { status: Some(502) },
            8,
            &str::to_owned,
            &mut out,
        )
        .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].kind, EventKind::Fetch);
    assert_eq!(out[0].cmd.as_deref(), Some(url.as_str()));
    assert_eq!(out[1].ok, Some(false));
    assert_eq!(out[1].exit_code, Some(502));
    assert_eq!(out[1].out_bytes, None);
    assert_eq!(out[0].exit_code, None);
    let mut marker = Vec::new();
    assert_eq!(
        telemetry.record_fetch(&url, FetchPhase::Intent, 9, &str::to_owned, &mut marker),
        Err(FetchRecordError::Truncated)
    );
    assert_eq!(marker.len(), 1);
    assert_eq!(marker[0].kind, EventKind::Phase);
    assert!(
        telemetry
            .summary()
            .missing
            .iter()
            .any(|m| m == "events_truncated")
    );
}

#[test]
fn a_succeeded_fetch_stores_status_and_bytes_on_the_event() {
    let mut telemetry = Telemetry::new(limits(8, 1 << 20, 512, 1024));
    let mut out = Vec::new();
    let phase = FetchPhase::Succeeded {
        status: 200,
        bytes: 123_456,
    };
    telemetry
        .record_fetch("https://h.example/", phase, 3, &str::to_owned, &mut out)
        .unwrap();
    assert_eq!(out[0].exit_code, Some(200));
    assert_eq!(out[0].out_bytes, Some(123_456));
    assert_eq!(out[0].ok, Some(true));
}
