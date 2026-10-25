//! Tool-call hook payloads: reduction, the hub and the daemon handler.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code asserts by panicking"
)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use fleet_core::{HookAllowlist, Identity, Redactor};
use fleetd::toolhook::{parse_exit_code, reduce};
use fleetd::{AppState, HookHub, Limits, Store, ToolReport, hook_router};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const SECRET_BODY: &str = "SECRET-FILE-CONTENT-do-not-forward";

fn common(tool: &str, id: &str, event: &str) -> Value {
    json!({
        "session_id": "s", "prompt_id": "p", "transcript_path": "/t.jsonl",
        "cwd": "/work/job1", "permission_mode": "dontAsk", "effort": {"level": "low"},
        "hook_event_name": event, "tool_name": tool, "tool_input": {"command": "ls"},
        "tool_use_id": id, "duration_ms": 42
    })
}

fn bash_success(id: &str) -> Vec<u8> {
    let mut payload = common("Bash", id, "PostToolUse");
    payload["tool_response"] = json!({
        "stdout": SECRET_BODY, "stderr": "", "interrupted": false,
        "isImage": false, "noOutputExpected": false
    });
    payload.to_string().into_bytes()
}

fn bash_failure_post(id: &str, text: &str) -> Vec<u8> {
    let mut payload = common("Bash", id, "PostToolUse");
    payload["tool_response"] = json!(text);
    payload.to_string().into_bytes()
}

fn bash_failure(id: &str, error: &str, interrupt: bool) -> Vec<u8> {
    let mut payload = common("Bash", id, "PostToolUseFailure");
    payload["error"] = json!(error);
    payload["is_interrupt"] = json!(interrupt);
    payload.to_string().into_bytes()
}

fn write_payload(id: &str) -> Vec<u8> {
    let mut payload = common("Write", id, "PostToolUse");
    payload["tool_response"] = json!({
        "type": "create", "filePath": "/work/a.txt", "content": SECRET_BODY,
        "structuredPatch": [], "originalFile": SECRET_BODY, "userModified": false
    });
    payload.to_string().into_bytes()
}

fn report(id: &str, exit: Option<i32>, dur: Option<u64>) -> ToolReport {
    ToolReport {
        tool_use_id: id.into(),
        tool_name: "Bash".into(),
        exit_code: exit,
        dur_ms: dur,
    }
}

#[test]
fn exit_code_text_edge_cases() {
    assert_eq!(parse_exit_code("Exit code 1"), Some(1));
    assert_eq!(parse_exit_code("Exit code 0"), Some(0));
    assert_eq!(parse_exit_code("Exit code 137\nKilled"), Some(137));
    assert_eq!(parse_exit_code("Exit code -1\nboom"), Some(-1));
    assert_eq!(parse_exit_code("Exit code 12abc"), Some(12));
    assert_eq!(parse_exit_code("Exit code 2147483647"), Some(i32::MAX));
    assert_eq!(parse_exit_code("Exit code -2147483648"), Some(i32::MIN));
    assert_eq!(parse_exit_code("Exit code 2147483648"), None);
    assert_eq!(parse_exit_code("Exit code 99999999999"), None);
    assert_eq!(parse_exit_code("Exit code 99999999999999999999999"), None);
    assert_eq!(parse_exit_code("Exit code "), None);
    assert_eq!(parse_exit_code("Exit code -"), None);
    assert_eq!(parse_exit_code("Exit code abc"), None);
    assert_eq!(parse_exit_code("Exit code +5"), None);
    assert_eq!(parse_exit_code("exit code 5"), None);
    assert_eq!(parse_exit_code("  Exit code 5"), None);
    assert_eq!(parse_exit_code("Error: Exit code 5"), None);
    assert_eq!(parse_exit_code(""), None);
}

#[test]
fn a_successful_bash_call_has_exit_code_zero_and_the_duration() {
    let got = reduce("PostToolUse", &bash_success("toolu_1")).unwrap();
    assert_eq!(got, report("toolu_1", Some(0), Some(42)));
}

#[test]
fn a_failed_bash_call_reads_the_code_from_both_event_shapes() {
    let post = reduce(
        "PostToolUse",
        &bash_failure_post("t", "Error: Exit code 137\nstderr text"),
    )
    .unwrap();
    assert_eq!(post.exit_code, Some(137));
    let failure = reduce(
        "PostToolUseFailure",
        &bash_failure("t", "Exit code -1\nstderr text", false),
    )
    .unwrap();
    assert_eq!(failure.exit_code, Some(-1));
    assert_eq!(failure.dur_ms, Some(42));
}

#[test]
fn unparseable_or_oversized_codes_leave_the_exit_code_unset() {
    for text in ["Exit code 99999999999\nx", "Exit code\nx", "weird", ""] {
        let failure = reduce("PostToolUseFailure", &bash_failure("t", text, false)).unwrap();
        assert_eq!(failure.exit_code, None, "{text}");
    }
    let post = reduce("PostToolUse", &bash_failure_post("t", "Exit code 3")).unwrap();
    assert_eq!(post.exit_code, None);
    let post = reduce("PostToolUse", &bash_failure_post("t", "Error: nonsense")).unwrap();
    assert_eq!(post.exit_code, None);
}

#[test]
fn an_interrupt_records_no_exit_code() {
    let failure = reduce(
        "PostToolUseFailure",
        &bash_failure("t", "Exit code 130\nx", true),
    )
    .unwrap();
    assert_eq!(failure.exit_code, None);
    assert_eq!(failure.dur_ms, Some(42));
    let mut payload: Value = serde_json::from_slice(&bash_success("t")).unwrap();
    payload["tool_response"]["interrupted"] = json!(true);
    let post = reduce("PostToolUse", payload.to_string().as_bytes()).unwrap();
    assert_eq!(post.exit_code, None);
}

#[test]
fn other_tools_have_no_exit_code() {
    let got = reduce("PostToolUse", &write_payload("w1")).unwrap();
    assert_eq!(got.tool_name, "Write");
    assert_eq!(got.exit_code, None);
    assert_eq!(got.dur_ms, Some(42));
    let mut payload: Value =
        serde_json::from_slice(&bash_failure("t", "Exit code 4", false)).unwrap();
    payload["tool_name"] = json!("Read");
    let got = reduce("PostToolUseFailure", payload.to_string().as_bytes()).unwrap();
    assert_eq!(got.exit_code, None);
}

#[test]
fn missing_fields_garbage_and_other_events_reduce_to_nothing() {
    assert_eq!(reduce("PostToolUse", b"not json"), None);
    assert_eq!(reduce("PostToolUse", b""), None);
    assert_eq!(reduce("PostToolUse", b"[1,2]"), None);
    assert_eq!(reduce("PostToolUse", b"\"str\""), None);
    assert_eq!(reduce("PostToolUse", b"{}"), None);
    assert_eq!(reduce("Stop", &bash_success("t")), None);
    assert_eq!(reduce("PreToolUse", &bash_success("t")), None);
    for key in ["tool_use_id", "tool_name"] {
        let mut payload: Value = serde_json::from_slice(&bash_success("t")).unwrap();
        payload.as_object_mut().unwrap().remove(key);
        assert_eq!(
            reduce("PostToolUse", payload.to_string().as_bytes()),
            None,
            "{key}"
        );
        payload[key] = json!(7);
        assert_eq!(
            reduce("PostToolUse", payload.to_string().as_bytes()),
            None,
            "{key}"
        );
        payload[key] = json!("");
        assert_eq!(
            reduce("PostToolUse", payload.to_string().as_bytes()),
            None,
            "{key}"
        );
    }
}

#[test]
fn ids_are_capped_and_must_be_printable_ascii() {
    let at_cap = "a".repeat(128);
    assert!(reduce("PostToolUse", &bash_success(&at_cap)).is_some());
    assert_eq!(reduce("PostToolUse", &bash_success(&"a".repeat(129))), None);
    assert_eq!(reduce("PostToolUse", &bash_success("has space")), None);
    assert_eq!(reduce("PostToolUse", &bash_success("line\nbreak")), None);
    assert_eq!(reduce("PostToolUse", &bash_success("caf\u{e9}")), None);
}

#[test]
fn a_missing_or_odd_duration_leaves_it_unset() {
    for value in [json!("12"), json!(-5), json!(1.5), json!(null)] {
        let mut payload: Value = serde_json::from_slice(&bash_success("t")).unwrap();
        payload["duration_ms"] = value;
        let got = reduce("PostToolUse", payload.to_string().as_bytes()).unwrap();
        assert_eq!(got.dur_ms, None);
    }
    let mut payload: Value = serde_json::from_slice(&bash_success("t")).unwrap();
    payload.as_object_mut().unwrap().remove("duration_ms");
    assert_eq!(
        reduce("PostToolUse", payload.to_string().as_bytes())
            .unwrap()
            .dur_ms,
        None
    );
}

#[test]
fn the_reduced_body_holds_four_fields_and_no_tool_content() {
    for payload in [
        write_payload("w"),
        bash_success("b"),
        bash_failure_post("f", &format!("Error: Exit code 2\n{SECRET_BODY}")),
        bash_failure("g", &format!("Exit code 2\n{SECRET_BODY}"), false),
    ] {
        let event = if serde_json::from_slice::<Value>(&payload).unwrap()["hook_event_name"]
            == "PostToolUseFailure"
        {
            "PostToolUseFailure"
        } else {
            "PostToolUse"
        };
        let body = reduce(event, &payload).unwrap().to_body();
        let text = String::from_utf8(body.clone()).unwrap();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!text.contains("/work"), "{text}");
        assert!(!text.contains("stdout"), "{text}");
        let value: Value = serde_json::from_slice(&body).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["dur_ms", "exit_code", "tool_name", "tool_use_id"]);
    }
}

#[test]
fn a_reduced_body_round_trips_and_extra_fields_are_ignored() {
    let original = report("toolu_9", Some(-1), Some(7));
    assert_eq!(
        ToolReport::from_reduced(&original.to_body()),
        Some(original)
    );
    let none = report("t", None, None);
    assert_eq!(ToolReport::from_reduced(&none.to_body()), Some(none));
    let wide = json!({"tool_use_id":"t","tool_name":"Bash","exit_code":1,"dur_ms":2,
        "tool_response":{"stdout":SECRET_BODY},"content":SECRET_BODY});
    let got = ToolReport::from_reduced(wide.to_string().as_bytes()).unwrap();
    assert_eq!(got, report("t", Some(1), Some(2)));
    let huge = json!({"tool_use_id":"t","tool_name":"Bash","exit_code":99_999_999_999_i64});
    assert_eq!(
        ToolReport::from_reduced(huge.to_string().as_bytes())
            .unwrap()
            .exit_code,
        None
    );
    assert_eq!(ToolReport::from_reduced(b"{}"), None);
    assert_eq!(ToolReport::from_reduced(b"garbage"), None);
}

#[test]
fn the_hub_delivers_in_order_to_registered_jobs_only() {
    let hub = HookHub::new();
    assert!(!hub.deliver("job1", report("a", None, None)));
    assert_eq!(hub.dropped(), 1);
    hub.register("job1");
    assert!(hub.deliver("job1", report("a", Some(0), None)));
    assert!(hub.deliver("job1", report("b", Some(1), None)));
    assert!(!hub.deliver("job2", report("c", None, None)));
    assert_eq!(hub.dropped(), 2);
    let ids: Vec<_> = hub
        .drain("job1")
        .into_iter()
        .map(|r| r.tool_use_id)
        .collect();
    assert_eq!(ids, ["a", "b"]);
    assert_eq!(hub.drain("job1").len(), 0);
    hub.register("job1");
    hub.unregister("job1");
    assert!(!hub.deliver("job1", report("d", None, None)));
    assert_eq!(hub.drain("job1").len(), 0);
}

#[test]
fn registering_again_keeps_queued_reports() {
    let hub = HookHub::new();
    hub.register("job1");
    hub.deliver("job1", report("a", None, None));
    hub.register("job1");
    assert_eq!(hub.drain("job1").len(), 1);
}

#[test]
fn a_mailbox_holds_1024_reports_and_counts_the_overflow() {
    let hub = HookHub::new();
    hub.register("job1");
    for n in 0..1024 {
        assert!(hub.deliver("job1", report(&format!("t{n}"), None, None)));
    }
    assert!(!hub.deliver("job1", report("late", None, None)));
    assert_eq!(hub.dropped(), 1);
    assert_eq!(hub.drain("job1").len(), 1024);
}

struct Harness {
    _dir: TempDir,
    store: Store,
    hub: Arc<HookHub>,
    state: Arc<AppState>,
}

async fn harness(allow: HookAllowlist) -> Harness {
    let dir = TempDir::new().unwrap();
    let store = Store::open(
        &dir.path().join("q.db"),
        Limits {
            max_bytes: u64::MAX,
            max_age: Duration::from_secs(86_400),
        },
    )
    .await
    .unwrap();
    let hub = HookHub::new();
    let state = AppState::with_hub(
        store.clone(),
        Identity {
            box_name: "alpha".into(),
            hostname: "host".into(),
            machine_id: "machine".into(),
            boot_id: "boot".into(),
        },
        allow,
        Redactor::default(),
        Duration::from_secs(10),
        hub.clone(),
    );
    Harness {
        _dir: dir,
        store,
        hub,
        state,
    }
}

fn tool_allow() -> HookAllowlist {
    HookAllowlist::new(["PostToolUse", "PostToolUseFailure"])
}

async fn post(h: &Harness, event: &str, job: Option<&str>, body: Vec<u8>) -> StatusCode {
    let mut request = Request::post(format!("/hook/{event}"));
    if let Some(job) = job {
        request = request.header("x-fleet-job", job);
    }
    let response = hook_router(h.state.clone())
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"{}");
    status
}

#[tokio::test]
async fn the_handler_hands_a_reduced_report_to_the_job_and_queues_nothing() {
    let h = harness(tool_allow()).await;
    h.hub.register("job1");
    let body = reduce(
        "PostToolUse",
        &bash_failure_post("t1", "Error: Exit code 2\nx"),
    )
    .unwrap()
    .to_body();
    assert_eq!(
        post(&h, "PostToolUse", Some("job1"), body).await,
        StatusCode::OK
    );
    let got = h.hub.drain("job1");
    assert_eq!(got, [report("t1", Some(2), Some(42))]);
    assert_eq!(h.store.list(None).await.unwrap().len(), 0);
    assert_eq!(h.hub.dropped(), 0);
}

#[tokio::test]
async fn the_handler_keeps_only_the_four_fields_of_a_full_payload() {
    let h = harness(tool_allow()).await;
    h.hub.register("job1");
    assert_eq!(
        post(&h, "PostToolUse", Some("job1"), write_payload("w1")).await,
        StatusCode::OK
    );
    assert_eq!(
        h.hub.drain("job1"),
        [ToolReport {
            tool_use_id: "w1".into(),
            tool_name: "Write".into(),
            exit_code: None,
            dur_ms: None
        }]
    );
    let wide = json!({"tool_use_id":"w1","tool_name":"Write","dur_ms":3,
        "tool_response":{"content":SECRET_BODY}});
    post(
        &h,
        "PostToolUseFailure",
        Some("job1"),
        wide.to_string().into_bytes(),
    )
    .await;
    let got = h.hub.drain("job1");
    assert_eq!(
        got,
        [ToolReport {
            tool_use_id: "w1".into(),
            tool_name: "Write".into(),
            exit_code: None,
            dur_ms: Some(3)
        }]
    );
}

#[tokio::test]
async fn unusable_deliveries_answer_200_and_count_a_drop() {
    let h = harness(tool_allow()).await;
    h.hub.register("job1");
    let good = report("t", Some(0), None).to_body();
    assert_eq!(
        post(&h, "PostToolUse", Some("unknown"), good.clone()).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.dropped(), 1);
    assert_eq!(
        post(&h, "PostToolUse", None, good.clone()).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.dropped(), 2);
    assert_eq!(
        post(&h, "PostToolUse", Some(" "), good.clone()).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.dropped(), 3);
    assert_eq!(
        post(&h, "PostToolUse", Some(&"j".repeat(129)), good).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.dropped(), 4);
    for body in [
        b"garbage".to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        Vec::new(),
    ] {
        assert_eq!(
            post(&h, "PostToolUseFailure", Some("job1"), body).await,
            StatusCode::OK
        );
    }
    assert_eq!(h.hub.dropped(), 8);
    assert_eq!(h.hub.drain("job1").len(), 0);
    assert_eq!(h.store.list(None).await.unwrap().len(), 0);
}

#[tokio::test]
async fn the_job_header_is_trimmed_and_may_be_128_bytes_but_not_empty() {
    let h = harness(tool_allow()).await;
    let long = "j".repeat(128);
    h.hub.register(&long);
    h.hub.register("job2");
    h.hub.register("");
    let good = report("t", Some(0), None).to_body();
    assert_eq!(
        post(&h, "PostToolUse", Some(&long), good.clone()).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.drain(&long).len(), 1);
    assert_eq!(
        post(&h, "PostToolUse", Some("  job2 "), good.clone()).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.drain("job2").len(), 1);
    assert_eq!(
        post(&h, "PostToolUse", Some(""), good).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.drain("").len(), 0);
    assert_eq!(h.hub.dropped(), 1);
}

#[tokio::test]
async fn an_event_off_the_allowlist_is_not_delivered_or_counted() {
    let h = harness(HookAllowlist::new(["Stop"])).await;
    h.hub.register("job1");
    let body = report("t", Some(0), None).to_body();
    assert_eq!(
        post(&h, "PostToolUse", Some("job1"), body).await,
        StatusCode::OK
    );
    assert_eq!(h.hub.drain("job1").len(), 0);
    assert_eq!(h.hub.dropped(), 0);
    assert_eq!(h.store.list(None).await.unwrap().len(), 0);
}
