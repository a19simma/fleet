//! OTLP/JSON parser over valid and hostile bodies.

#![expect(
    clippy::needless_pass_by_value,
    reason = "test helpers take owned literals"
)]

use fleetd::otel_parse::{
    ApiRequest, ClaudeEvent, MAX_COMMAND_BYTES, MAX_DURATION_MS, MAX_NAME_BYTES, MAX_RECORDS,
    ParseError, ToolDecision, ToolResult, parse_logs,
};
use serde_json::{Value, json};

fn s(key: &str, v: &str) -> Value {
    json!({"key": key, "value": {"stringValue": v}})
}

fn i(key: &str, v: Value) -> Value {
    json!({"key": key, "value": {"intValue": v}})
}

fn record(attrs: Vec<Value>) -> Value {
    json!({"timeUnixNano": "1700000000000000000", "attributes": attrs})
}

fn body(records: Vec<Value>) -> Vec<u8> {
    json!({"resourceLogs": [{"resource": {"attributes": []},
        "scopeLogs": [{"scope": {"name": "com.anthropic.claude_code"}, "logRecords": records}]}]})
    .to_string()
    .into_bytes()
}

fn one(attrs: Vec<Value>) -> Result<Vec<ClaudeEvent>, ParseError> {
    parse_logs(&body(vec![record(attrs)])).map(|p| p.events)
}

fn result_attrs() -> Vec<Value> {
    vec![
        s("event.name", "claude_code.tool_result"),
        s("tool_use_id", "toolu_1"),
        s("tool_name", "Bash"),
        i("duration_ms", json!("42")),
        s("success", "true"),
    ]
}

fn without(mut attrs: Vec<Value>, key: &str) -> Vec<Value> {
    attrs.retain(|a| a["key"] != key);
    attrs
}

fn with(mut attrs: Vec<Value>, attr: Value) -> Vec<Value> {
    attrs.retain(|a| a.get("key") != attr.get("key"));
    attrs.push(attr);
    attrs
}

#[test]
fn parses_the_three_known_events_in_order() {
    let records = vec![
        record(vec![
            s("event.name", "claude_code.api_request"),
            i("duration_ms", json!(1500)),
            s("model", "claude-x"),
        ]),
        record(vec![
            s("event.name", "claude_code.tool_decision"),
            s("tool_use_id", "toolu_1"),
            s("tool_name", "Bash"),
            s("decision", "accept"),
        ]),
        record(with(
            result_attrs(),
            s("command", "pueue add -- cargo test\nline2"),
        )),
    ];
    let parsed = parse_logs(&body(records)).expect("parses");
    assert_eq!(parsed.skipped, 0);
    assert_eq!(
        parsed.events,
        vec![
            ClaudeEvent::ApiRequest(ApiRequest {
                duration_ms: 1500,
                model: Some("claude-x".into())
            }),
            ClaudeEvent::ToolDecision(ToolDecision {
                tool_use_id: "toolu_1".into(),
                tool_name: "Bash".into(),
                decision: Some("accept".into())
            }),
            ClaudeEvent::ToolResult(ToolResult {
                tool_use_id: "toolu_1".into(),
                tool_name: "Bash".into(),
                duration_ms: 42,
                success: true,
                command: Some("pueue add -- cargo test\nline2".into())
            }),
        ]
    );
}

#[test]
fn an_absent_command_is_none_and_the_event_name_may_lack_the_prefix() {
    let attrs = with(result_attrs(), s("event.name", "tool_result"));
    let events = one(attrs).expect("parses");
    assert!(matches!(
        events.as_slice(),
        [ClaudeEvent::ToolResult(ToolResult { command: None, .. })]
    ));
}

#[test]
fn the_event_name_falls_back_to_the_body() {
    let mut rec = record(without(result_attrs(), "event.name"));
    rec["body"] = json!({"stringValue": "claude_code.tool_result"});
    let parsed = parse_logs(&body(vec![rec])).expect("parses");
    assert_eq!(parsed.events.len(), 1);
}

#[test]
fn the_event_name_attribute_wins_over_the_body() {
    let mut rec = record(result_attrs());
    rec["body"] = json!({"stringValue": "claude_code.api_request"});
    let parsed = parse_logs(&body(vec![rec])).expect("parses");
    assert!(matches!(
        parsed.events.as_slice(),
        [ClaudeEvent::ToolResult(_)]
    ));
}

#[test]
fn unknown_events_are_skipped_and_counted() {
    let records = vec![
        record(vec![s("event.name", "claude_code.user_prompt")]),
        record(result_attrs()),
        record(vec![s("event.name", "claude_code.tool_result_extra")]),
    ];
    let parsed = parse_logs(&body(records)).expect("parses");
    assert_eq!(parsed.skipped, 2);
    assert_eq!(parsed.events.len(), 1);
}

#[test]
fn an_empty_object_and_empty_lists_yield_nothing() {
    for text in [
        "{}",
        r#"{"resourceLogs":[]}"#,
        r#"{"resourceLogs":[{}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{}]}]}"#,
    ] {
        assert_eq!(
            parse_logs(text.as_bytes()).expect("parses"),
            fleetd::otel_parse::Parsed::default(),
            "{text}"
        );
    }
}

#[test]
fn records_across_resources_and_scopes_are_all_read() {
    let rec = record(result_attrs());
    let text = json!({"resourceLogs": [
        {"scopeLogs": [{"logRecords": [rec]}, {"logRecords": [rec]}]},
        {"scopeLogs": [{"logRecords": [rec]}]}
    ]})
    .to_string();
    assert_eq!(parse_logs(text.as_bytes()).expect("parses").events.len(), 3);
}

#[test]
fn int_values_read_as_string_or_number_and_doubles_round() {
    for v in [json!("42"), json!(42)] {
        let attrs = with(result_attrs(), i("duration_ms", v));
        assert!(
            matches!(
                one(attrs).expect("parses").as_slice(),
                [ClaudeEvent::ToolResult(ToolResult {
                    duration_ms: 42,
                    ..
                })]
            ),
            "int form"
        );
    }
    let attrs = with(
        result_attrs(),
        json!({"key": "duration_ms", "value": {"doubleValue": 41.6}}),
    );
    assert!(matches!(
        one(attrs).expect("parses").as_slice(),
        [ClaudeEvent::ToolResult(ToolResult {
            duration_ms: 42,
            ..
        })]
    ));
    let attrs = with(result_attrs(), s("duration_ms", "42"));
    assert!(one(attrs).is_ok(), "string duration");
}

#[test]
fn success_reads_bool_and_string_forms_only() {
    for (value, want) in [
        (json!({"boolValue": true}), true),
        (json!({"boolValue": false}), false),
        (json!({"stringValue": "true"}), true),
        (json!({"stringValue": "false"}), false),
    ] {
        let attrs = with(result_attrs(), json!({"key": "success", "value": value}));
        let events = one(attrs).expect("parses");
        assert!(
            matches!(events.as_slice(), [ClaudeEvent::ToolResult(r)] if r.success == want),
            "{value}"
        );
    }
    for value in [
        json!({"stringValue": "yes"}),
        json!({"stringValue": "TRUE"}),
        json!({"intValue": "1"}),
        json!({"stringValue": ""}),
    ] {
        let attrs = with(result_attrs(), json!({"key": "success", "value": value}));
        assert!(one(attrs).is_err(), "{value}");
    }
}

#[test]
fn bad_json_is_refused() {
    for text in [
        "",
        "not json",
        "{",
        r#"{"resourceLogs":[}"#,
        "[]",
        "null",
        "\"x\"",
        "{} trailing",
        "\u{feff}{}",
    ] {
        assert!(parse_logs(text.as_bytes()).is_err(), "{text:?}");
    }
    assert_eq!(parse_logs(&[0xff, 0xfe, b'{']), Err(ParseError::Json));
}

#[test]
fn deep_nesting_is_refused_before_the_serde_limit() {
    let depth = 64;
    let deep = format!(
        r#"{{"resourceLogs":[{{"x":{}0{}}}]}}"#,
        "[".repeat(depth),
        "]".repeat(depth)
    );
    assert_eq!(parse_logs(deep.as_bytes()), Err(ParseError::TooDeep));
    let huge = format!("{}0{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(parse_logs(huge.as_bytes()).is_err());
}

#[test]
fn out_of_range_and_negative_numbers_are_refused() {
    let cases = [
        json!("99999999999999999999"),
        json!("9223372036854775808"),
        json!("-1"),
        json!(-1),
        json!(18_446_744_073_709_551_615_u64),
        json!(MAX_DURATION_MS + 1),
        json!(1.5),
        json!("1.5"),
        json!("0x10"),
        json!(" 5"),
        json!("+5"),
        json!(""),
        json!(true),
        json!(null),
    ];
    for v in cases {
        let attrs = with(result_attrs(), i("duration_ms", v.clone()));
        assert!(one(attrs).is_err(), "{v}");
    }
    for raw in ["1e999", "-1.0", "1e30"] {
        let text = format!(
            r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"attributes":[
{{"key":"event.name","value":{{"stringValue":"api_request"}}}},
{{"key":"duration_ms","value":{{"doubleValue":{raw}}}}}]}}]}}]}}]}}"#
        );
        assert!(parse_logs(text.as_bytes()).is_err(), "{raw}");
    }
    let attrs = with(result_attrs(), i("duration_ms", json!(MAX_DURATION_MS)));
    assert!(one(attrs).is_ok());
    let attrs = with(result_attrs(), i("duration_ms", json!(0)));
    assert!(one(attrs).is_ok());
}

#[test]
fn a_missing_required_attribute_is_refused_per_field() {
    for key in ["tool_use_id", "tool_name", "duration_ms", "success"] {
        assert_eq!(
            one(without(result_attrs(), key)),
            Err(ParseError::Missing(match key {
                "tool_use_id" => "tool_use_id",
                "tool_name" => "tool_name",
                "duration_ms" => "duration_ms",
                _ => "success",
            })),
            "{key}"
        );
    }
    let decision = vec![
        s("event.name", "tool_decision"),
        s("tool_use_id", "t"),
        s("tool_name", "Bash"),
    ];
    assert!(one(decision.clone()).is_ok());
    for key in ["tool_use_id", "tool_name"] {
        assert!(one(without(decision.clone(), key)).is_err(), "{key}");
    }
    assert_eq!(
        one(vec![s("event.name", "api_request")]),
        Err(ParseError::Missing("duration_ms"))
    );
    assert_eq!(
        one(vec![i("duration_ms", json!(1))]),
        Err(ParseError::Missing("event.name"))
    );
    assert_eq!(
        parse_logs(&body(vec![json!({})])),
        Err(ParseError::Missing("event.name"))
    );
}

#[test]
fn a_known_event_with_one_bad_record_fails_the_whole_body() {
    let bad = record(without(result_attrs(), "tool_use_id"));
    let records = vec![record(result_attrs()), bad, record(result_attrs())];
    assert!(parse_logs(&body(records)).is_err());
}

#[test]
fn duplicate_object_keys_are_refused_at_every_level() {
    let cases = [
        r#"{"resourceLogs":[],"resourceLogs":[]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[],"scopeLogs":[]}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[],"logRecords":[]}]}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[],"attributes":[]}]}]}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[{"key":"a","key":"b","value":{"stringValue":"x"}}]}]}]}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[{"key":"a","value":{"stringValue":"x","stringValue":"y"}}]}]}]}]}"#,
        r#"{"resourceLogs":[{"unknown":{"a":1,"a":2}}]}"#,
    ];
    for text in cases {
        assert_eq!(
            parse_logs(text.as_bytes()),
            Err(ParseError::DuplicateKey),
            "{text}"
        );
    }
}

#[test]
fn a_repeated_attribute_key_is_refused() {
    let attrs = with(result_attrs(), s("tool_name", "Bash"));
    let mut dup = attrs.clone();
    dup.push(s("tool_name", "Read"));
    assert_eq!(one(dup), Err(ParseError::DuplicateKey));
    assert!(one(attrs).is_ok());
}

#[test]
fn over_long_strings_are_refused_and_the_cap_itself_passes() {
    let long = "a".repeat(MAX_NAME_BYTES + 1);
    let exact = "a".repeat(MAX_NAME_BYTES);
    for key in ["tool_use_id", "tool_name"] {
        assert!(one(with(result_attrs(), s(key, &long))).is_err(), "{key}");
        assert!(one(with(result_attrs(), s(key, &exact))).is_ok(), "{key}");
    }
    assert!(one(with(result_attrs(), s("event.name", &long))).is_err());
    let model = vec![
        s("event.name", "api_request"),
        i("duration_ms", json!(1)),
        s("model", &long),
    ];
    assert!(one(model).is_err());
    let cmd_ok = "c".repeat(MAX_COMMAND_BYTES);
    let cmd_long = "c".repeat(MAX_COMMAND_BYTES + 1);
    assert!(one(with(result_attrs(), s("command", &cmd_ok))).is_ok());
    assert_eq!(
        one(with(result_attrs(), s("command", &cmd_long))),
        Err(ParseError::TooLong)
    );
    let huge = "z".repeat(MAX_COMMAND_BYTES * 8);
    let mut extra = record(result_attrs());
    extra["unrelated"] = json!(huge);
    assert_eq!(parse_logs(&body(vec![extra])), Err(ParseError::TooLong));
}

#[test]
fn non_string_where_a_string_is_expected_is_refused() {
    for key in ["tool_use_id", "tool_name", "event.name"] {
        for value in [
            json!({"intValue": "5"}),
            json!({"boolValue": true}),
            json!({"doubleValue": 1.0}),
            json!({"arrayValue": {"values": []}}),
            json!({"kvlistValue": {"values": []}}),
            json!({}),
            json!(null),
            json!("plain"),
            json!({"stringValue": 5}),
            json!({"stringValue": null}),
            json!({"stringValue": "a", "intValue": "1"}),
        ] {
            let attrs = with(result_attrs(), json!({"key": key, "value": value}));
            assert!(one(attrs).is_err(), "{key} {value}");
        }
    }
    let attrs = with(
        result_attrs(),
        json!({"key": 7, "value": {"stringValue": "x"}}),
    );
    assert!(one(attrs).is_err());
    let mut rec = record(result_attrs());
    rec["attributes"] = json!("nope");
    assert!(parse_logs(&body(vec![rec])).is_err());
    for text in [
        r#"{"resourceLogs":{}}"#,
        r#"{"resourceLogs":[1]}"#,
        r#"{"resourceLogs":[{"scopeLogs":{}}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":"x"}]}]}"#,
        r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[1]}]}]}"#,
    ] {
        assert!(parse_logs(text.as_bytes()).is_err(), "{text}");
    }
}

#[test]
fn hostile_characters_in_names_are_refused() {
    let bad = [
        "a\rb",
        "a\r\nb",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{0}b",
        "a\u{202e}b",
        "a\u{200b}b",
        "a\u{1b}[31mb",
        "",
    ];
    for key in ["tool_use_id", "tool_name", "event.name"] {
        for v in bad {
            let attrs = with(result_attrs(), s(key, v));
            assert!(one(attrs).is_err(), "{key} {v:?}");
        }
    }
    let model = vec![
        s("event.name", "api_request"),
        i("duration_ms", json!(1)),
        s("model", "m\u{2028}"),
    ];
    assert!(one(model).is_err());
    let decision = vec![
        s("event.name", "tool_decision"),
        s("tool_use_id", "t"),
        s("tool_name", "Bash"),
        s("decision", "ok\r"),
    ];
    assert!(one(decision).is_err());
}

#[test]
fn a_hostile_event_name_on_a_skipped_event_is_still_refused() {
    let attrs = vec![s("event.name", "claude_code.other\u{2028}")];
    assert!(one(attrs).is_err());
}

#[test]
fn a_command_is_returned_raw_and_an_empty_one_is_none() {
    let raw = "echo ghp_secret \u{2028} $(x)\r\n";
    let events = one(with(result_attrs(), s("command", raw))).expect("parses");
    assert!(
        matches!(events.as_slice(), [ClaudeEvent::ToolResult(r)] if r.command.as_deref() == Some(raw))
    );
    let events = one(with(result_attrs(), s("command", ""))).expect("parses");
    assert!(matches!(
        events.as_slice(),
        [ClaudeEvent::ToolResult(ToolResult { command: None, .. })]
    ));
    let events = one(with(result_attrs(), s("bash_command", "ls"))).expect("parses");
    assert!(
        matches!(events.as_slice(), [ClaudeEvent::ToolResult(r)] if r.command.as_deref() == Some("ls"))
    );
    let attrs = with(result_attrs(), i("command", json!(5)));
    assert!(one(attrs).is_err());
}

#[test]
fn too_many_records_are_refused_and_the_cap_passes() {
    let rec = record(vec![s("event.name", "other")]);
    let at_cap = parse_logs(&body(vec![rec.clone(); MAX_RECORDS])).expect("parses");
    assert_eq!(at_cap.skipped, MAX_RECORDS);
    assert_eq!(
        parse_logs(&body(vec![rec; MAX_RECORDS + 1])),
        Err(ParseError::TooMany)
    );
}

#[test]
fn records_are_capped_across_scopes_not_per_list() {
    let rec = record(vec![s("event.name", "other")]);
    let half = vec![rec; MAX_RECORDS / 2 + 1];
    let text = json!({"resourceLogs": [
        {"scopeLogs": [{"logRecords": half}, {"logRecords": half}]}
    ]})
    .to_string();
    assert_eq!(parse_logs(text.as_bytes()), Err(ParseError::TooMany));
}

#[test]
fn too_many_attributes_are_refused() {
    let attrs: Vec<Value> = (0..300).map(|n| s(&format!("k{n}"), "v")).collect();
    assert_eq!(one(attrs), Err(ParseError::TooMany));
}

#[test]
fn error_text_never_echoes_input() {
    let attrs = with(result_attrs(), s("tool_name", "SECRETVALUE\r"));
    let err = one(attrs).expect_err("refused");
    assert!(!err.to_string().contains("SECRETVALUE"));
}

use fleet_core::timing::{Interval, Span, SpanKind, aggregate};
use fleetd::otel_parse::{MAX_DECISIONS, MAX_SEEN_IDS, Observed, SpanMapper};

#[expect(clippy::expect_used, reason = "test helper over literal bounds")]
fn win(a: u64, b: u64) -> Interval {
    Interval::new(a, b).expect("ordered")
}

fn span(kind: SpanKind, a: u64, b: u64) -> Span {
    Span {
        kind,
        interval: win(a, b),
    }
}

fn api(ts: u64, ms: u64) -> Observed {
    Observed::new(
        ts,
        ClaudeEvent::ApiRequest(ApiRequest {
            duration_ms: ms,
            model: None,
        }),
    )
}

fn tool(ts: u64, ms: u64, id: &str, name: &str) -> Observed {
    Observed::new(
        ts,
        ClaudeEvent::ToolResult(ToolResult {
            tool_use_id: id.to_owned(),
            tool_name: name.to_owned(),
            duration_ms: ms,
            success: true,
            command: None,
        }),
    )
}

fn decision(ts: u64, id: &str, name: &str, text: Option<&str>) -> Observed {
    Observed::new(
        ts,
        ClaudeEvent::ToolDecision(ToolDecision {
            tool_use_id: id.to_owned(),
            tool_name: name.to_owned(),
            decision: text.map(str::to_owned),
        }),
    )
}

fn run(job: Interval, events: Vec<Observed>) -> Vec<Span> {
    let mut m = SpanMapper::new(job);
    events.into_iter().filter_map(|e| m.push(e)).collect()
}

#[test]
fn api_request_is_an_api_wait_ending_at_the_event() {
    assert_eq!(
        run(win(0, 10_000), vec![api(5000, 1200)]),
        vec![span(SpanKind::ApiWait, 3800, 5000)]
    );
}

#[test]
fn tool_result_is_tool_and_bash_is_shell() {
    let got = run(
        win(0, 10_000),
        vec![tool(2000, 500, "a", "Read"), tool(4000, 500, "b", "Bash")],
    );
    assert_eq!(
        got,
        vec![
            span(SpanKind::Tool, 1500, 2000),
            span(SpanKind::Shell, 3500, 4000)
        ]
    );
}

#[test]
fn only_the_exact_name_bash_is_shell() {
    let got = run(
        win(0, 10_000),
        vec![tool(2000, 500, "a", "bash"), tool(4000, 500, "b", "Bash ")],
    );
    assert!(got.iter().all(|s| s.kind == SpanKind::Tool));
}

#[test]
fn background_comes_from_the_structured_flag_only() {
    let mut yes = tool(4000, 500, "a", "Bash");
    yes.run_in_background = Some(true);
    let mut no = tool(6000, 500, "b", "Bash");
    no.run_in_background = Some(false);
    let mut other = tool(8000, 500, "c", "Read");
    other.run_in_background = Some(true);
    let mut with_text = tool(9000, 500, "d", "Bash");
    with_text.event = ClaudeEvent::ToolResult(ToolResult {
        tool_use_id: "d".to_owned(),
        tool_name: "Bash".to_owned(),
        duration_ms: 500,
        success: true,
        command: Some("sleep 9 &".to_owned()),
    });
    let got = run(win(0, 10_000), vec![yes, no, other, with_text]);
    let kinds: Vec<SpanKind> = got.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        vec![
            SpanKind::BgShell,
            SpanKind::Shell,
            SpanKind::Tool,
            SpanKind::Shell
        ]
    );
}

#[test]
fn a_decision_alone_yields_no_span_and_a_result_alone_does() {
    assert_eq!(
        run(win(0, 10_000), vec![decision(1, "a", "Bash", None)]).len(),
        0
    );
    assert_eq!(
        run(win(0, 10_000), vec![tool(2000, 100, "a", "Bash")]).len(),
        1
    );
}

#[test]
fn a_matching_decision_keeps_the_span() {
    let got = run(
        win(0, 10_000),
        vec![
            decision(1, "a", "Bash", Some("accept")),
            tool(2000, 100, "a", "Bash"),
        ],
    );
    assert_eq!(got, vec![span(SpanKind::Shell, 1900, 2000)]);
}

#[test]
fn a_decision_naming_another_tool_or_rejecting_drops_the_result() {
    for d in [
        decision(1, "a", "Read", Some("accept")),
        decision(1, "a", "Bash", Some("reject")),
    ] {
        let mut m = SpanMapper::new(win(0, 10_000));
        assert!(m.push(d).is_none());
        assert!(m.push(tool(2000, 100, "a", "Bash")).is_none());
        assert_eq!(m.stats().contradicted, 1);
    }
}

#[test]
fn a_decision_joins_one_result_only() {
    let mut m = SpanMapper::new(win(0, 10_000));
    m.push(decision(1, "a", "Bash", Some("reject")));
    assert!(m.push(tool(2000, 100, "a", "Bash")).is_none());
    assert!(m.push(tool(3000, 100, "a", "Bash")).is_some());
}

#[test]
fn the_decision_table_is_bounded() {
    let mut m = SpanMapper::new(win(0, 10_000));
    for n in 0..MAX_DECISIONS + 10 {
        m.push(decision(1, &format!("id{n}"), "Bash", Some("reject")));
    }
    assert_eq!(m.stats().decisions_dropped, 10);
    assert!(m.push(tool(2000, 100, "id0", "Bash")).is_none());
    assert!(
        m.push(tool(2000, 100, &format!("id{}", MAX_DECISIONS + 5), "Bash"))
            .is_some()
    );
}

#[test]
fn duplicate_event_ids_are_dropped() {
    let mut m = SpanMapper::new(win(0, 10_000));
    assert!(m.push(api(5000, 100).with_id("e1")).is_some());
    assert!(m.push(api(5000, 100).with_id("e1")).is_none());
    assert!(m.push(api(5000, 100).with_id("e2")).is_some());
    assert_eq!(m.stats().duplicates, 1);
}

#[test]
fn the_id_set_stops_growing_at_its_cap_and_drops_new_ids() {
    let mut m = SpanMapper::new(win(0, 10_000));
    for n in 0..MAX_SEEN_IDS {
        assert!(m.push(api(5000, 1).with_id(&format!("e{n}"))).is_some());
    }
    assert!(m.push(api(5000, 1).with_id("fresh")).is_none());
    assert!(m.push(api(5000, 1).with_id("e0")).is_none());
    assert_eq!(m.stats().ids_dropped, 1);
    assert_eq!(m.stats().duplicates, 1);
    assert!(m.push(api(5000, 1)).is_some());
}

#[test]
fn spans_are_clamped_to_the_job_window() {
    let job = win(1000, 5000);
    let got = run(
        job,
        vec![
            api(1500, 1000),
            api(6000, 2000),
            api(5000, 9000),
            api(500, 100),
            api(9000, 100),
        ],
    );
    assert_eq!(
        got,
        vec![
            span(SpanKind::ApiWait, 1000, 1500),
            span(SpanKind::ApiWait, 4000, 5000),
            span(SpanKind::ApiWait, 1000, 5000),
        ]
    );
}

#[test]
fn hostile_durations_and_times_never_panic_or_reverse() {
    let job = win(0, u64::MAX);
    let mut m = SpanMapper::new(job);
    for (ts, ms) in [
        (0, 0),
        (0, 5),
        (5, u64::MAX),
        (u64::MAX, u64::MAX),
        (u64::MAX, 0),
        (u64::MAX, 1),
        (3, 2),
        (1, 2),
    ] {
        if let Some(s) = m.push(api(ts, ms)) {
            assert!(s.interval.start_ms() <= s.interval.end_ms());
            assert!(!s.interval.is_empty());
        }
    }
    assert_eq!(m.stats().empty, 3);
}

#[test]
fn a_zero_duration_yields_no_span() {
    assert_eq!(run(win(0, 10_000), vec![api(5000, 0)]).len(), 0);
}

#[test]
fn non_monotonic_times_map_independently() {
    let got = run(win(0, 10_000), vec![api(8000, 100), api(2000, 100)]);
    assert_eq!(
        got,
        vec![
            span(SpanKind::ApiWait, 7900, 8000),
            span(SpanKind::ApiWait, 1900, 2000)
        ]
    );
}

#[test]
fn overlapping_subagent_spans_stay_overlapping_for_core_to_merge() {
    let job = win(0, 10_000);
    let got = run(
        job,
        vec![tool(5000, 2000, "a", "Task"), tool(5500, 2000, "b", "Task")],
    );
    assert_eq!(
        got,
        vec![
            span(SpanKind::Tool, 3000, 5000),
            span(SpanKind::Tool, 3500, 5500)
        ]
    );
    let s = aggregate(&got, job, job);
    assert_eq!(s.tool_ms, 2500);
}

#[test]
fn a_batch_past_the_cap_is_cut_and_counted() {
    let mut m = SpanMapper::new(win(0, 10_000));
    let batch: Vec<Observed> = (0..MAX_RECORDS + 3).map(|_| api(5000, 1)).collect();
    assert_eq!(m.push_all(batch).len(), MAX_RECORDS);
    assert_eq!(m.stats().batch_cut, 3);
}
