//! Kimi wire.jsonl pairing, skipping, caps, truncation and interleaving.

use std::io::Cursor;

use fleet_core::timing::SpanKind;
use fleetd::wire_timing::{MAX_LINE_BYTES, MAX_LINES, MAX_PENDING, WireTiming, parse_wire};

const SYNTHETIC: &[u8] = include_bytes!("fixtures/kimi-wire.synthetic.jsonl");

fn run(input: &[u8]) -> WireTiming {
    parse_wire(Cursor::new(input)).unwrap_or_default()
}

fn bounds(t: &WireTiming) -> Vec<(u64, u64)> {
    t.spans
        .iter()
        .map(|s| (s.interval.start_ms(), s.interval.end_ms()))
        .collect()
}

#[test]
fn the_synthetic_fixture_pairs_interleaved_requests() {
    let t = run(SYNTHETIC);
    assert_eq!(bounds(&t), [(1150, 1400), (1100, 1900), (2000, 2600)]);
    assert!(t.spans.iter().all(|s| s.kind == SpanKind::ApiWait));
    assert_eq!(t.stats.skipped_unknown, 2);
    assert_eq!(t.stats.malformed, 0);
    assert_eq!(t.stats.unclosed, 0);
}

#[test]
fn a_truncated_last_line_is_malformed_and_its_request_stays_unclosed() {
    let t = run(b"{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":5}\n{\"type\":\"usage.record\",\"request_id\":\"a\",\"ts_");
    assert_eq!(t.spans.len(), 0);
    assert_eq!(t.stats.malformed, 1);
    assert_eq!(t.stats.unclosed, 1);
}

#[test]
fn a_complete_last_line_without_newline_counts() {
    let t = run(b"{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":5}\n{\"type\":\"usage.record\",\"request_id\":\"a\",\"ts_ms\":9}");
    assert_eq!(bounds(&t), [(5, 9)]);
}

#[test]
fn an_unknown_type_is_skipped_and_counted_never_guessed() {
    let t = run(b"{\"type\":\"llm.reply\",\"id\":\"a\",\"ts_ms\":5}\n{\"kind\":\"llm.request\"}\n");
    assert_eq!(t.spans.len(), 0);
    assert_eq!(t.stats.skipped_unknown, 1);
    assert_eq!(t.stats.malformed, 1);
}

#[test]
fn malformed_lines_are_counted_and_do_not_stop_the_scan() {
    let input = b"not json\n[1]\n{\"type\":1}\n{\"type\":\"llm.request\",\"ts_ms\":5}\n{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":-1}\n{\"type\":\"llm.request\",\"id\":\"b\",\"ts_ms\":1}\n{\"type\":\"usage.record\",\"request_id\":\"b\",\"ts_ms\":3}\n";
    let t = run(input);
    assert_eq!(t.stats.malformed, 5);
    assert_eq!(bounds(&t), [(1, 3)]);
}

#[test]
fn a_duplicate_key_at_any_level_refuses_the_line() {
    let t = run(b"{\"type\":\"llm.request\",\"type\":\"x\",\"id\":\"a\",\"ts_ms\":1}\n{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":1,\"x\":{\"k\":1,\"k\":2}}\n");
    assert_eq!(t.stats.malformed, 2);
    assert_eq!(t.stats.unclosed, 0);
}

#[test]
fn deep_nesting_is_refused() {
    let mut line = String::from("{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":1,\"x\":");
    line.push_str(&"[".repeat(200));
    line.push_str(&"]".repeat(200));
    line.push_str("}\n");
    let t = run(line.as_bytes());
    assert_eq!(t.stats.malformed, 1);
}

#[test]
fn a_usage_without_a_request_or_a_repeat_is_unpaired() {
    let t = run(b"{\"type\":\"usage.record\",\"request_id\":\"z\",\"ts_ms\":9}\n{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":1}\n{\"type\":\"usage.record\",\"request_id\":\"a\",\"ts_ms\":2}\n{\"type\":\"usage.record\",\"request_id\":\"a\",\"ts_ms\":3}\n");
    assert_eq!(bounds(&t), [(1, 2)]);
    assert_eq!(t.stats.unpaired, 2);
}

#[test]
fn a_usage_before_its_request_start_is_malformed_and_closes_nothing() {
    let t = run(b"{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":9}\n{\"type\":\"usage.record\",\"request_id\":\"a\",\"ts_ms\":2}\n");
    assert_eq!(t.spans.len(), 0);
    assert_eq!(t.stats.malformed, 1);
    assert_eq!(t.stats.unclosed, 1);
}

#[test]
fn a_repeated_pending_request_id_is_malformed() {
    let t = run(b"{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":1}\n{\"type\":\"llm.request\",\"id\":\"a\",\"ts_ms\":2}\n{\"type\":\"usage.record\",\"request_id\":\"a\",\"ts_ms\":5}\n");
    assert_eq!(t.stats.malformed, 1);
    assert_eq!(bounds(&t), [(1, 5)]);
}

#[test]
fn an_over_long_line_is_dropped_whole_and_the_next_line_still_parses() {
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"type\":\"llm.request\",\"id\":\"");
    input.extend(std::iter::repeat_n(b'a', MAX_LINE_BYTES));
    input.extend_from_slice(b"\",\"ts_ms\":1}\n{\"type\":\"llm.request\",\"id\":\"b\",\"ts_ms\":1}\n{\"type\":\"usage.record\",\"request_id\":\"b\",\"ts_ms\":4}\n");
    let t = run(&input);
    assert_eq!(t.stats.oversized, 1);
    assert_eq!(bounds(&t), [(1, 4)]);
}

#[test]
fn a_line_of_exactly_the_cap_is_read() {
    let head = b"{\"type\":\"session.start\",\"pad\":\"";
    let tail = b"\"}";
    let mut input = head.to_vec();
    input.extend(std::iter::repeat_n(
        b'a',
        MAX_LINE_BYTES - head.len() - tail.len(),
    ));
    input.extend_from_slice(tail);
    input.push(b'\n');
    let t = run(&input);
    assert_eq!(t.stats.oversized, 0);
    assert_eq!(t.stats.skipped_unknown, 1);
}

#[test]
fn reading_stops_at_the_line_cap() {
    let mut input = Vec::new();
    for _ in 0..MAX_LINES + 5 {
        input.extend_from_slice(b"{\"type\":\"noise\"}\n");
    }
    let t = run(&input);
    assert!(t.stats.line_cap_hit);
    assert_eq!(t.stats.skipped_unknown, MAX_LINES);
}

#[test]
fn requests_past_the_pending_cap_are_counted_not_kept() {
    let mut input = Vec::new();
    for i in 0..MAX_PENDING + 3 {
        input.extend_from_slice(
            format!("{{\"type\":\"llm.request\",\"id\":\"r{i}\",\"ts_ms\":1}}\n").as_bytes(),
        );
    }
    let t = run(&input);
    assert_eq!(t.stats.dropped_requests, 3);
    assert_eq!(t.stats.unclosed, MAX_PENDING);
}

#[test]
fn a_blank_line_is_ignored() {
    let t = run(b"\n\n");
    assert_eq!(t.stats.malformed, 0);
    assert_eq!(t.stats.skipped_unknown, 0);
}
