//! Shadow-mode stuck detector through the telemetry parser and directly.

use fleetd::stuck::{Detector, Stuck, StuckRule, StuckRules};
use fleetd::telemetry::{EventKind, JobEvent, Limits, Telemetry, Terminal};
use serde_json::{Value, json};

struct Run {
    telemetry: Telemetry,
    n: u64,
}

impl Run {
    fn new() -> Self {
        Self::with(Telemetry::new(Limits::default()))
    }

    fn rules(rules: StuckRules) -> Self {
        Self::with(Telemetry::new(Limits::default()).with_stuck_rules(rules))
    }

    fn with(telemetry: Telemetry) -> Self {
        Self { telemetry, n: 0 }
    }

    fn line(&mut self, line: &Value) -> Vec<JobEvent> {
        self.n += 1;
        self.telemetry.feed_line(&line.to_string(), self.n * 10)
    }

    fn call(&mut self, tool: &str, input: &Value, out: &str, error: bool) -> Vec<JobEvent> {
        let id = format!("t{}", self.n);
        self.line(
            &json!({"type":"assistant","message":{"id":format!("m_{id}"),"content":[
            {"type":"tool_use","id":id,"name":tool,"input":input}]}}),
        );
        self.line(&json!({"type":"user","message":{"content":[
            {"type":"tool_result","tool_use_id":id,"content":out,"is_error":error}]}}))
    }

    fn bash(&mut self, cmd: &str, out: &str, error: bool) -> Vec<JobEvent> {
        self.call("Bash", &json!({ "command": cmd }), out, error)
    }

    fn text(&mut self, id: &str) {
        self.line(&json!({"type":"assistant","message":{"id":id,"content":[
            {"type":"text","text":"thinking"}]}}));
    }

    fn result(&mut self) {
        self.line(&json!({"type":"result","subtype":"success","num_turns":1}));
    }

    fn fired(&self) -> Option<Stuck> {
        self.telemetry.summary().stuck
    }
}

fn rule(run: &Run) -> Option<&'static str> {
    run.fired().map(|stuck| stuck.rule.name())
}

fn step_event(tool: &str, cmd: &str, out: &str, ok: bool, exit: Option<i32>) -> JobEvent {
    JobEvent {
        kind: EventKind::Tool,
        tool: Some(tool.into()),
        cmd: Some(cmd.into()),
        out_hash: Some(out.into()),
        out_bytes: Some(out.len() as u64),
        ok: Some(ok),
        exit_code: exit,
        ..JobEvent::default()
    }
}

#[test]
fn stable_rule_names() {
    assert_eq!(
        StuckRule::RepeatActionObservation.name(),
        "repeat_action_observation"
    );
    assert_eq!(StuckRule::RepeatError.name(), "repeat_error");
    assert_eq!(StuckRule::Alternating.name(), "alternating");
    assert_eq!(StuckRule::Monologue.name(), "monologue");
}

#[test]
fn default_thresholds_are_named_in_one_struct() {
    assert_eq!(
        StuckRules::default(),
        StuckRules {
            repeat_action_observation: 4,
            repeat_error: 3,
            alternating_cycles: 3,
            monologue_turns: 3,
        }
    );
}

#[test]
fn repeat_action_observation_fires_at_four_not_three() {
    let mut run = Run::new();
    for _ in 0..3 {
        run.bash("ls", "same", false);
    }
    assert_eq!(run.fired(), None);
    run.bash("ls", "same", false);
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::RepeatActionObservation);
    assert_eq!(stuck.seq, 3);
    assert_eq!(stuck.ts_ms, 80);
}

#[test]
fn a_differing_tuple_breaks_the_consecutive_run() {
    let mut run = Run::new();
    for _ in 0..3 {
        run.bash("ls", "same", false);
    }
    run.bash("pwd", "same", false);
    for _ in 0..3 {
        run.bash("ls", "same", false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn the_same_tool_with_distinct_inputs_does_not_fire() {
    let mut run = Run::new();
    for i in 0..10 {
        run.bash(&format!("echo {i}"), "same", false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn the_same_input_with_differing_output_does_not_fire_rule_one() {
    let mut run = Run::new();
    for i in 0..10 {
        run.bash("ls", &format!("out {i}"), false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn the_same_command_on_a_different_tool_is_a_different_input() {
    let mut run = Run::new();
    for _ in 0..2 {
        run.call("Bash", &json!({"command": "x"}), "same", false);
        run.call("Read", &json!({"file_path": "x"}), "same", false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn interleaved_non_tool_events_do_not_break_a_run() {
    let mut run = Run::new();
    run.bash("ls", "same", false);
    run.line(&json!({"type":"system","subtype":"api_retry","attempt":1}));
    run.bash("ls", "same", false);
    run.line(&json!({"type":"system","subtype":"permission_denied","tool_name":"Bash"}));
    run.bash("ls", "same", false);
    run.line(&json!({"type":"rate_limit_event"}));
    assert_eq!(run.fired(), None);
    let events = run.bash("ls", "same", false);
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::RepeatActionObservation);
    assert_eq!(Some(stuck.seq), events.last().map(|event| event.seq));
    assert_eq!(stuck.seq, 5);
}

#[test]
fn repeat_error_fires_at_three_failures_not_two() {
    let mut run = Run::new();
    for _ in 0..2 {
        run.bash("make", "boom", true);
    }
    assert_eq!(run.fired(), None);
    run.bash("make", "boom", true);
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::RepeatError);
    assert_eq!(stuck.seq, 2);
}

#[test]
fn successful_repeats_do_not_fire_repeat_error() {
    let mut run = Run::new();
    for _ in 0..3 {
        run.bash("make", "boom", false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn a_success_between_failures_breaks_the_error_run() {
    let mut run = Run::new();
    run.bash("make", "boom", true);
    run.bash("make", "boom", true);
    run.bash("make", "fine", false);
    run.bash("make", "boom", true);
    run.bash("make", "boom", true);
    assert_eq!(run.fired(), None);
}

#[test]
fn failures_with_differing_output_do_not_fire_repeat_error() {
    let mut run = Run::new();
    for i in 0..6 {
        run.bash("make", &format!("boom {i}"), true);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn failures_with_empty_output_fire_repeat_error() {
    let mut run = Run::new();
    for _ in 0..3 {
        run.bash("make", "", true);
    }
    assert_eq!(rule(&run), Some("repeat_error"));
}

#[test]
fn empty_output_matches_any_output_in_a_failing_run() {
    let mut detector = Detector::new(StuckRules::default());
    detector.tool(&step_event("Bash", "make", "aaa", false, None));
    detector.tool(&step_event("Bash", "make", "", false, None));
    detector.tool(&step_event("Bash", "make", "aaa", false, None));
    assert_eq!(
        detector.fired().map(|stuck| stuck.rule),
        Some(StuckRule::RepeatError)
    );
}

#[test]
fn a_nonzero_exit_code_counts_as_failed_and_zero_does_not() {
    let mut failing = Detector::new(StuckRules::default());
    for _ in 0..3 {
        failing.tool(&step_event("Bash", "make", "boom", true, Some(2)));
    }
    assert_eq!(
        failing.fired().map(|stuck| stuck.rule),
        Some(StuckRule::RepeatError)
    );
    let mut fine = Detector::new(StuckRules::default());
    for _ in 0..3 {
        fine.tool(&step_event("Bash", "make", "boom", true, Some(0)));
    }
    assert_eq!(fine.fired(), None);
}

#[test]
fn the_first_rule_wins_and_is_never_replaced() {
    let mut run = Run::new();
    for _ in 0..6 {
        run.bash("make", "boom", true);
    }
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::RepeatError);
    assert_eq!(stuck.seq, 2);
    for _ in 0..3 {
        run.text("later");
    }
    run.result();
    assert_eq!(run.fired(), Some(stuck));
}

#[test]
fn alternating_needs_three_full_cycles() {
    let mut run = Run::new();
    for _ in 0..2 {
        run.bash("a", "oa", false);
        run.bash("b", "ob", false);
    }
    run.bash("a", "oa", false);
    assert_eq!(run.fired(), None);
    run.bash("b", "ob", false);
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::Alternating);
    assert_eq!(stuck.seq, 5);
}

#[test]
fn three_distinct_tuples_in_rotation_do_not_alternate() {
    let mut run = Run::new();
    for _ in 0..4 {
        run.bash("a", "oa", false);
        run.bash("b", "ob", false);
        run.bash("c", "oc", false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn alternating_cycles_are_injectable() {
    let mut run = Run::rules(StuckRules {
        alternating_cycles: 2,
        ..StuckRules::default()
    });
    for _ in 0..2 {
        run.bash("a", "oa", false);
        run.bash("b", "ob", false);
    }
    assert_eq!(rule(&run), Some("alternating"));
}

#[test]
fn thresholds_are_injectable_for_rules_one_and_two() {
    let mut run = Run::rules(StuckRules {
        repeat_action_observation: 2,
        ..StuckRules::default()
    });
    run.bash("ls", "same", false);
    assert_eq!(run.fired(), None);
    run.bash("ls", "same", false);
    assert_eq!(rule(&run), Some("repeat_action_observation"));
    let mut run = Run::rules(StuckRules {
        repeat_error: 2,
        ..StuckRules::default()
    });
    run.bash("ls", "x", true);
    run.bash("ls", "x", true);
    assert_eq!(rule(&run), Some("repeat_error"));
}

#[test]
fn zero_thresholds_act_as_one_and_never_panic() {
    let mut detector = Detector::new(StuckRules {
        repeat_action_observation: 0,
        repeat_error: 0,
        alternating_cycles: 0,
        monologue_turns: 0,
    });
    detector.tool(&step_event("Bash", "a", "x", true, None));
    assert_eq!(
        detector.fired().map(|stuck| stuck.rule),
        Some(StuckRule::RepeatActionObservation)
    );
    let mut alternating = Detector::new(StuckRules {
        repeat_action_observation: 99,
        repeat_error: 99,
        alternating_cycles: 0,
        monologue_turns: 99,
    });
    alternating.tool(&step_event("Bash", "a", "x", true, None));
    alternating.tool(&step_event("Bash", "b", "y", true, None));
    assert_eq!(
        alternating.fired().map(|stuck| stuck.rule),
        Some(StuckRule::Alternating)
    );
}

#[test]
fn monologue_fires_on_three_text_only_turns() {
    let mut run = Run::new();
    run.text("m1");
    run.text("m2");
    run.result();
    assert_eq!(run.fired(), None);
    let mut run = Run::new();
    run.text("m1");
    run.text("m2");
    run.text("m3");
    assert_eq!(run.fired(), None);
    run.result();
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::Monologue);
    assert_eq!(stuck.seq, 0);
    assert_eq!(stuck.ts_ms, 40);
}

#[test]
fn monologue_fires_when_a_fourth_turn_starts() {
    let mut run = Run::new();
    run.text("m1");
    run.text("m2");
    run.text("m3");
    run.text("m4");
    assert_eq!(rule(&run), Some("monologue"));
    assert_eq!(run.fired().map(|stuck| stuck.ts_ms), Some(40));
}

#[test]
fn a_tool_turn_resets_the_monologue_run() {
    let mut run = Run::new();
    run.text("m1");
    run.text("m2");
    run.bash("ls", "x", false);
    run.text("m3");
    run.text("m4");
    run.result();
    assert_eq!(run.fired(), None);
}

#[test]
fn text_and_tool_use_lines_of_one_message_are_one_tool_turn() {
    let mut run = Run::new();
    for i in 0..5 {
        let id = format!("m{i}");
        run.text(&id);
        run.line(&json!({"type":"assistant","message":{"id":id,"content":[
            {"type":"tool_use","id":format!("u{i}"),"name":"Bash","input":{"command":format!("c{i}")}}]}}));
    }
    run.result();
    assert_eq!(run.fired(), None);
}

#[test]
fn monologue_turns_are_injectable_and_lines_without_ids_are_separate_turns() {
    let mut run = Run::rules(StuckRules {
        monologue_turns: 2,
        ..StuckRules::default()
    });
    let anonymous = json!({"type":"assistant","message":{"content":[{"type":"text","text":"x"}]}});
    run.line(&anonymous);
    run.line(&anonymous);
    run.result();
    assert_eq!(rule(&run), Some("monologue"));
}

#[test]
fn the_history_window_stays_capped_on_a_long_stream() {
    let limits = Limits {
        max_events: 100_000,
        max_event_bytes: u64::MAX,
        ..Limits::default()
    };
    let mut run = Run::with(Telemetry::new(limits));
    for i in 0..3000 {
        run.bash(&format!("c{i}"), &format!("o{i}"), i % 2 == 0);
    }
    assert_eq!(run.fired(), None);
    let detector = run.telemetry.detector();
    assert_eq!(detector.window_cap(), 6);
    assert_eq!(detector.window_len(), 6);
}

#[test]
fn the_window_cap_follows_the_largest_threshold() {
    let rules = StuckRules {
        repeat_action_observation: 9,
        repeat_error: 3,
        alternating_cycles: 3,
        monologue_turns: 50,
    };
    assert_eq!(Detector::new(rules).window_cap(), 9);
    let rules = StuckRules {
        repeat_action_observation: 2,
        repeat_error: 2,
        alternating_cycles: 7,
        monologue_turns: 3,
    };
    assert_eq!(Detector::new(rules).window_cap(), 14);
    let rules = StuckRules {
        repeat_action_observation: 2,
        repeat_error: 5,
        alternating_cycles: 1,
        monologue_turns: 3,
    };
    assert_eq!(Detector::new(rules).window_cap(), 5);
}

#[test]
fn redacted_text_keys_deterministically() {
    let limits = Limits::default();
    let mut telemetry = Telemetry::new(limits);
    let mask = |text: &str| text.replace("s3cret-1", "[x]").replace("s3cret-2", "[x]");
    let mut n = 0_u64;
    for secret in ["s3cret-1", "s3cret-2", "s3cret-1", "s3cret-2"] {
        n += 1;
        let id = format!("t{n}");
        let use_line = json!({"type":"assistant","message":{"id":id,"content":[
            {"type":"tool_use","id":id,"name":"Bash","input":{"command":format!("echo {secret}")}}]}});
        telemetry.feed_line_with(&use_line.to_string(), n, &mask);
        let result = json!({"type":"user","message":{"content":[
            {"type":"tool_result","tool_use_id":id,"content":"same","is_error":false}]}});
        telemetry.feed_line_with(&result.to_string(), n, &mask);
    }
    assert_eq!(
        telemetry.summary().stuck.map(|stuck| stuck.rule),
        Some(StuckRule::RepeatActionObservation)
    );
}

#[test]
fn capped_text_keys_on_the_cut_text() {
    let limits = Limits {
        cmd_cap: 4,
        ..Limits::default()
    };
    let mut run = Run::with(Telemetry::new(limits));
    for tail in ["a", "b", "c", "d"] {
        run.bash(&format!("echo {tail}"), "same", false);
    }
    assert_eq!(rule(&run), Some("repeat_action_observation"));
}

#[test]
fn the_summary_carries_rule_and_seq_through_finish() {
    let mut run = Run::new();
    run.bash("make", "boom", true);
    assert_eq!(run.telemetry.summary().stuck, None);
    run.bash("make", "boom", true);
    run.bash("make", "boom", true);
    let expected = Stuck {
        rule: StuckRule::RepeatError,
        seq: 2,
        ts_ms: 60,
    };
    assert_eq!(run.telemetry.summary().stuck, Some(expected));
    assert_eq!(run.telemetry.finish(Terminal::Failed).stuck, Some(expected));
}

#[test]
fn a_stream_with_no_pattern_records_nothing() {
    let mut run = Run::new();
    run.bash("a", "1", false);
    run.bash("b", "2", false);
    run.result();
    assert_eq!(run.telemetry.finish(Terminal::Succeeded).stuck, None);
}

#[test]
fn tool_events_after_truncation_are_not_judged() {
    let limits = Limits {
        max_events: 1,
        ..Limits::default()
    };
    let mut run = Run::with(Telemetry::new(limits));
    for _ in 0..6 {
        run.bash("ls", "same", false);
    }
    assert_eq!(run.fired(), None);
}

#[test]
fn a_zero_monologue_threshold_acts_as_one() {
    let mut detector = Detector::new(StuckRules {
        monologue_turns: 0,
        ..StuckRules::default()
    });
    detector.assistant(Some("a"), false, 0, 0);
    assert_eq!(detector.fired(), None);
    detector.end_turn(0, 0);
    assert_eq!(
        detector.fired().map(|stuck| stuck.rule),
        Some(StuckRule::Monologue)
    );
}

#[test]
fn monologue_records_the_stored_event_position() {
    let mut run = Run::new();
    run.bash("ls", "x", false);
    run.text("m1");
    run.text("m2");
    run.text("m3");
    run.result();
    let stuck = run.fired().unwrap();
    assert_eq!(stuck.rule, StuckRule::Monologue);
    assert_eq!(stuck.seq, 1);
}

#[test]
fn tool_use_then_text_lines_of_one_message_are_one_tool_turn() {
    let mut run = Run::new();
    for i in 0..5 {
        let id = format!("m{i}");
        run.line(&json!({"type":"assistant","message":{"id":id,"content":[
            {"type":"tool_use","id":format!("u{i}"),"name":"Bash","input":{"command":format!("c{i}")}}]}}));
        run.text(&id);
    }
    run.result();
    assert_eq!(run.fired(), None);
}

#[test]
fn a_broken_cycle_in_either_half_does_not_alternate() {
    let mut run = Run::new();
    for _ in 0..2 {
        run.bash("a", "oa", false);
        run.bash("b", "ob", false);
    }
    run.bash("a", "oa", false);
    run.bash("c", "oc", false);
    assert_eq!(run.fired(), None);
    let mut run = Run::new();
    run.bash("a", "oa", false);
    run.bash("b", "ob", false);
    run.bash("a", "oa", false);
    run.bash("b", "ob", false);
    run.bash("c", "oc", false);
    run.bash("b", "ob", false);
    assert_eq!(run.fired(), None);
}

#[test]
fn a_fourth_turn_start_records_the_stored_event_position() {
    let mut run = Run::new();
    run.bash("ls", "x", false);
    for i in 0..4 {
        run.text(&format!("m{i}"));
    }
    assert_eq!(run.fired().map(|stuck| stuck.seq), Some(1));
}
