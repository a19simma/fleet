//! Tests for `fleet_core::transcript`: goldens per fixture, a hostile-input table per field,
//! every cap with a shrunk value, and the chunk and line edge cases.

use std::error::Error;

use fleet_core::Redactor;
use fleet_core::transcript::{
    Assembler, Item, MAX_VIEW_BYTES, MAX_VIEW_ENTRIES, Pair, PairStatus, Transcript, TurnUsage,
    Update, ViewLimits,
};
use fleet_core::transcript::{
    Entry, Limits, MAX_CHUNK_BYTES, MAX_ENTRIES_PER_LINE, MAX_ID_BYTES, MAX_INPUT_BYTES,
    MAX_LABEL_BYTES, MAX_OBJECT_KEYS, MAX_OUTPUT_BYTES, MAX_SUMMARY_CHARS, MAX_TEXT_BYTES,
    MAX_TOOL_NAME_BYTES, Role, ToolId, ToolIdError, Usage, parse_chunk, parse_chunk_with,
};
use serde_json::json;

type Res = Result<(), Box<dyn Error>>;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transcript/");

fn fixture(name: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(format!("{FIXTURES}{name}"))
}

fn fixture_line(name: &str, n: usize) -> Result<String, Box<dyn Error>> {
    let text = fixture(name)?;
    text.lines()
        .nth(n)
        .map(str::to_owned)
        .ok_or_else(|| format!("{name} has no line {n}").into())
}

fn parse(chunk: &str) -> Vec<Entry> {
    parse_chunk(chunk, false, None)
}

fn parse_with(chunk: &str, limits: &Limits) -> Vec<Entry> {
    parse_chunk_with(chunk, false, None, limits)
}

fn one(entries: Vec<Entry>) -> Result<Entry, String> {
    let mut entries = entries;
    if entries.len() != 1 {
        return Err(format!("want one entry, got {entries:?}"));
    }
    entries.pop().ok_or_else(|| "empty".to_owned())
}

fn id(s: &str) -> Result<ToolId, ToolIdError> {
    ToolId::new(s)
}

fn msg(role: Role, text: &str) -> Entry {
    Entry::Message {
        role,
        text: text.to_owned(),
        subagent: None,
    }
}

fn call(
    i: &str,
    name: &str,
    summary: &str,
    input: &str,
    parent: Option<&str>,
) -> Result<Entry, ToolIdError> {
    Ok(Entry::ToolCall {
        id: id(i)?,
        name: name.to_owned(),
        summary: summary.to_owned(),
        input: input.to_owned(),
        parent: parent.map(ToolId::new).transpose()?,
    })
}

fn res(i: &str, is_error: bool, output: &str, parent: Option<&str>) -> Result<Entry, ToolIdError> {
    Ok(Entry::ToolResult {
        id: id(i)?,
        is_error,
        output: output.to_owned(),
        parent: parent.map(ToolId::new).transpose()?,
    })
}

fn sys(subtype: &str, collapsed: bool) -> Entry {
    Entry::System {
        subtype: subtype.to_owned(),
        collapsed,
    }
}

fn done(is_error: bool, turns: u64, denials: u64) -> Entry {
    Entry::Result {
        is_error,
        turns,
        duration_ms: 12345,
        cost_usd: Some(0.0421),
        usage: Usage {
            input_tokens: 120,
            output_tokens: 340,
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
        },
        terminal_reason: Some("completed".to_owned()),
        denials,
    }
}

fn unknown(kind: &str, raw: &str) -> Entry {
    Entry::Unknown {
        kind: kind.to_owned(),
        raw: raw.to_owned(),
    }
}

fn init() -> Entry {
    sys("init", true)
}

fn assistant_blocks(blocks: &serde_json::Value) -> String {
    json!({"type": "assistant", "message": {"content": blocks}}).to_string()
}

fn assistant_text(text: &str) -> String {
    assistant_blocks(&json!([{"type": "text", "text": text}]))
}

fn capped_output(multi: &str) -> String {
    let more = multi.len().saturating_sub(MAX_OUTPUT_BYTES);
    let kept = cut(multi, MAX_OUTPUT_BYTES);
    if more > 0 {
        format!("{kept}\n[{more} bytes more]")
    } else {
        kept
    }
}

fn cut(s: &str, cap: usize) -> String {
    s.chars().take(cap).collect()
}

fn small(f: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::DEFAULT;
    f(&mut limits);
    limits
}

#[test]
fn constants_hold_the_documented_caps() {
    assert_eq!(MAX_CHUNK_BYTES, 256 * 1024);
    assert_eq!(MAX_TEXT_BYTES, 16 * 1024);
    assert_eq!(MAX_OUTPUT_BYTES, 16 * 1024);
    assert_eq!(MAX_ENTRIES_PER_LINE, 256);
    assert_eq!(MAX_SUMMARY_CHARS, 200);
    assert_eq!(MAX_INPUT_BYTES, 4 * 1024);
    assert_eq!(MAX_TOOL_NAME_BYTES, 64);
    assert_eq!(MAX_ID_BYTES, 128);
    assert_eq!(MAX_LABEL_BYTES, 64);
    assert_eq!(Limits::default(), Limits::DEFAULT);
    assert_eq!(Limits::DEFAULT.chunk_bytes, MAX_CHUNK_BYTES);
    assert_eq!(Limits::DEFAULT.text_bytes, MAX_TEXT_BYTES);
    assert_eq!(Limits::DEFAULT.output_bytes, MAX_OUTPUT_BYTES);
    assert_eq!(Limits::DEFAULT.summary_chars, MAX_SUMMARY_CHARS);
    assert_eq!(Limits::DEFAULT.input_bytes, MAX_INPUT_BYTES);
    assert_eq!(Limits::DEFAULT.name_bytes, MAX_TOOL_NAME_BYTES);
    assert_eq!(Limits::DEFAULT.id_bytes, MAX_ID_BYTES);
    assert_eq!(Limits::DEFAULT.label_bytes, MAX_LABEL_BYTES);
    assert_eq!(Limits::DEFAULT.line_entries, MAX_ENTRIES_PER_LINE);
}

#[test]
fn tool_id_accepts_printable_ascii_up_to_the_cap() -> Res {
    assert_eq!(id("toolu_01A1")?.as_str(), "toolu_01A1");
    assert_eq!(id("toolu_01A1")?.to_string(), "toolu_01A1");
    assert!(id(&"a".repeat(MAX_ID_BYTES)).is_ok());
    assert_eq!(id(&"a".repeat(MAX_ID_BYTES + 1)), Err(ToolIdError::TooLong));
    assert_eq!(id(""), Err(ToolIdError::Empty));
    for bad in [
        "a b",
        " ",
        "a\tb",
        "a\nb",
        "a\u{7f}b",
        "caf\u{e9}",
        "a\u{202e}b",
    ] {
        assert_eq!(id(bad), Err(ToolIdError::NotPrintable), "{bad:?}");
    }
    assert_eq!(ToolIdError::Empty.to_string(), "tool id is empty");
    assert_eq!(ToolIdError::TooLong.to_string(), "tool id is too long");
    assert_eq!(
        ToolIdError::NotPrintable.to_string(),
        "tool id holds a non-printable byte"
    );
    Ok(())
}

#[test]
fn golden_sample_job() -> Res {
    let want = vec![
        sys("hook_started", true),
        sys("hook_response", true),
        init(),
        Entry::RateLimit {
            status: "allowed".to_owned(),
            utilization: None,
            resets_at: Some(1_760_000_000),
        },
        msg(Role::Assistant, "Listing the repo."),
        call("toolu_01A1", "Bash", "ls", r#"{"command":"ls"}"#, None)?,
        res("toolu_01A1", false, "Cargo.toml\nsrc", None)?,
        call(
            "toolu_01A2",
            "Read",
            "/work/repo/Cargo.toml",
            r#"{"file_path":"/work/repo/Cargo.toml"}"#,
            None,
        )?,
        res("toolu_01A2", false, "[package]\nname = \"demo\"", None)?,
        msg(Role::Assistant, "The repo is a demo crate."),
        done(false, 3, 0),
        Entry::FleetNote {
            text: "no_changes".to_owned(),
        },
    ];
    assert_eq!(parse(&fixture("sample_job.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_per_line_chunks_match_the_whole_file() -> Res {
    let text = fixture("sample_job.jsonl")?;
    let whole = parse(&text);
    let per_line: Vec<Entry> = text.lines().flat_map(parse).collect();
    assert_eq!(per_line, whole);
    Ok(())
}

#[test]
fn golden_subagent() -> Res {
    let task_input =
        r#"{"description":"scan","prompt":"find TODOs","subagent_type":"general-purpose"}"#;
    let want = vec![
        init(),
        call("toolu_02T1", "Task", "scan", task_input, None)?,
        call(
            "toolu_02C1",
            "Bash",
            "grep -rn TODO .",
            r#"{"command":"grep -rn TODO ."}"#,
            Some("toolu_02T1"),
        )?,
        res("toolu_02C1", false, "none", Some("toolu_02T1"))?,
        Entry::Message {
            role: Role::Assistant,
            text: "No TODOs found.".to_owned(),
            subagent: Some(id("toolu_02T1")?),
        },
        res("toolu_02T1", false, "No TODOs found.", None)?,
        msg(Role::Assistant, "Sub-agent found nothing."),
        done(false, 2, 0),
    ];
    assert_eq!(parse(&fixture("subagent.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_thinking() -> Res {
    let want = vec![
        init(),
        Entry::Thinking {
            text: "The user wants a summary. Check the file first.".to_owned(),
        },
        call(
            "toolu_03A",
            "Read",
            "/work/repo/README.md",
            r#"{"file_path":"/work/repo/README.md"}"#,
            None,
        )?,
        res("toolu_03A", false, "# Demo", None)?,
        Entry::Thinking {
            text: "Short readme.".to_owned(),
        },
        msg(Role::Assistant, "It is a demo."),
        done(false, 2, 0),
    ];
    assert_eq!(parse(&fixture("thinking.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_result_block_array() -> Res {
    let want = vec![
        init(),
        call(
            "toolu_04A",
            "Read",
            "/work/repo/shot.png",
            r#"{"file_path":"/work/repo/shot.png"}"#,
            None,
        )?,
        res(
            "toolu_04A",
            false,
            "Image follows.\nSecond text block.\n[image]",
            None,
        )?,
        msg(Role::Assistant, "Saw the image."),
        done(false, 2, 0),
    ];
    assert_eq!(parse(&fixture("result_block_array.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_error_result() -> Res {
    let want = vec![
        init(),
        call(
            "toolu_05A",
            "Bash",
            "cat missing.txt",
            r#"{"command":"cat missing.txt"}"#,
            None,
        )?,
        res(
            "toolu_05A",
            true,
            "cat: missing.txt: No such file or directory",
            None,
        )?,
        msg(Role::Assistant, "The file is missing."),
        done(true, 2, 0),
    ];
    assert_eq!(parse(&fixture("error_result.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_denial() -> Res {
    let want = vec![
        init(),
        call(
            "toolu_06A",
            "Bash",
            "rm -rf build",
            r#"{"command":"rm -rf build"}"#,
            None,
        )?,
        res(
            "toolu_06A",
            true,
            "Permission denied for this tool use.",
            None,
        )?,
        msg(Role::Assistant, "I was not allowed to delete build."),
        done(false, 2, 1),
    ];
    assert_eq!(parse(&fixture("denial.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_interleaved_calls() -> Res {
    let want = vec![
        init(),
        call(
            "toolu_07A",
            "Bash",
            "sleep 1; echo a",
            r#"{"command":"sleep 1; echo a"}"#,
            None,
        )?,
        call(
            "toolu_07B",
            "Bash",
            "echo b",
            r#"{"command":"echo b"}"#,
            None,
        )?,
        res("toolu_07B", false, "b", None)?,
        res("toolu_07A", false, "a", None)?,
        msg(Role::Assistant, "Both done."),
        done(false, 2, 0),
    ];
    assert_eq!(parse(&fixture("interleaved_calls.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_call_without_result() -> Res {
    let want = vec![
        init(),
        call(
            "toolu_08A",
            "Bash",
            "sleep 600",
            r#"{"command":"sleep 600"}"#,
            None,
        )?,
    ];
    assert_eq!(parse(&fixture("call_without_result.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_result_without_call() -> Res {
    let want = vec![
        init(),
        res("toolu_09ORPHAN", false, "stray output", None)?,
        msg(Role::Assistant, "Continuing."),
        done(false, 1, 0),
    ];
    assert_eq!(parse(&fixture("result_without_call.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_truncated_chunk() -> Res {
    let text = fixture("truncated_chunk.jsonl")?;
    let cut_line = fixture_line("truncated_chunk.jsonl", 2)?;
    let want = vec![
        init(),
        msg(Role::Assistant, "First line is whole."),
        unknown("?", &cut_line),
    ];
    assert_eq!(parse(&text), want);
    assert_eq!(parse_chunk(&cut_line, true, None), vec![Entry::Truncated]);
    Ok(())
}

#[test]
fn golden_unknown_top_level() -> Res {
    let sorted = concat!(
        r#"{"payload":{"k":"v"},"session_id":"5d0f1c2e-7b1a-4c53-9a0e-3f6b2d8c4a11","#,
        r#""type":"future_thing","uuid":"00000000-0000-4000-8000-000000000055"}"#
    );
    let want = vec![
        init(),
        unknown("future_thing", sorted),
        msg(Role::Assistant, "Still parsing."),
        done(false, 1, 0),
    ];
    assert_eq!(parse(&fixture("unknown_top_level.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_unknown_subtype() -> Res {
    let want = vec![
        sys("novel_notice", false),
        init(),
        msg(Role::Assistant, "ok"),
        done(false, 1, 0),
    ];
    assert_eq!(parse(&fixture("unknown_subtype.jsonl")?), want);
    Ok(())
}

#[test]
fn golden_unknown_block() -> Res {
    let want = vec![
        init(),
        unknown(
            "citation_x",
            r#"{"cited":"doc-1","span":[0,4],"type":"citation_x"}"#,
        ),
        msg(Role::Assistant, "After the unknown block."),
        done(false, 1, 0),
    ];
    assert_eq!(parse(&fixture("unknown_block.jsonl")?), want);
    Ok(())
}

struct Case {
    label: String,
    value: String,
    multi: String,
    single: String,
    json: String,
}

fn decode(raw: &str) -> Result<String, Box<dyn Error>> {
    if let Some(n) = raw
        .strip_prefix("<LONG:")
        .and_then(|rest| rest.strip_suffix('>'))
    {
        return Ok("a".repeat(n.parse()?));
    }
    let mut units: Vec<u16> = Vec::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars.next() != Some('u') {
                return Err("only the backslash-u escape exists".into());
            }
            let hex: String = chars.by_ref().take(4).collect();
            units.push(u16::from_str_radix(&hex, 16)?);
        } else {
            let mut buf = [0u16; 2];
            units.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    Ok(String::from_utf16(&units)?)
}

const ROWS: [(&str, &str, &str, &str); 15] = [
    ("cr", "ab", "a b", "ab"),
    ("crlf", "a\nb", "a b", "a\\nb"),
    ("nel", "ab", "a b", "ab"),
    ("line_sep", "ab", "a b", "ab"),
    ("para_sep", "ab", "a b", "ab"),
    ("bidi_rlo", "ab", "ab", "ab"),
    ("bidi_lri", "ab", "ab", "ab"),
    ("ansi_sgr", "[31mred[0m", "[31mred[0m", "[31mred[0m"),
    (
        "osc8",
        "]8;;http://example.invalid/link]8;;",
        "]8;;http://example.invalid/link]8;;",
        "]8;;http://example.invalid/link]8;;",
    ),
    ("nul", "ab", "ab", "ab"),
    (
        "script",
        "<script>alert(1)</script>",
        "<script>alert(1)</script>",
        "<script>alert(1)</script>",
    ),
    (
        "md_link",
        "[click](http://example.invalid/x)",
        "[click](http://example.invalid/x)",
        "[click](http://example.invalid/x)",
    ),
    (
        "html_entity",
        "&lt;b&gt;&amp;#x3c;",
        "&lt;b&gt;&amp;#x3c;",
        "&lt;b&gt;&amp;#x3c;",
    ),
    ("empty", "", "", ""),
    (
        "non_ascii",
        "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f680}",
        "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f680}",
        "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f680}",
    ),
];

fn cases() -> Result<Vec<Case>, Box<dyn Error>> {
    let text = fixture("hostile_values.txt")?;
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (label, raw) = line.split_once('\t').ok_or("row without a tab")?;
        let value = decode(raw)?;
        let (multi, single, json) = if label == "overlong" {
            (value.clone(), value.clone(), value.clone())
        } else {
            let row = ROWS
                .iter()
                .find(|r| r.0 == label)
                .ok_or_else(|| format!("no expectation for {label}"))?;
            (row.1.to_owned(), row.2.to_owned(), row.3.to_owned())
        };
        out.push(Case {
            label: label.to_owned(),
            value,
            multi,
            single,
            json,
        });
    }
    if out.len() != ROWS.len() + 1 {
        return Err(format!("hostile_values.txt has {} rows", out.len()).into());
    }
    Ok(out)
}

#[test]
fn hostile_value_decoder_follows_the_documented_syntax() -> Res {
    assert_eq!(decode("a\\u000d\\u000ab")?, "a\r\nb");
    assert_eq!(decode("\\ud83d\\ude80")?, "\u{1f680}");
    assert_eq!(decode("<LONG:3>")?, "aaa");
    assert_eq!(decode("")?, "");
    assert!(decode("a\\nb").is_err());
    Ok(())
}

#[test]
fn hostile_message_text() -> Res {
    for c in cases()? {
        let want = msg(Role::Assistant, &cut(&c.multi, MAX_TEXT_BYTES));
        assert_eq!(one(parse(&assistant_text(&c.value)))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_user_message_text() -> Res {
    for c in cases()? {
        let line = json!({"type": "user", "message": {"content": c.value}}).to_string();
        let want = msg(Role::User, &cut(&c.multi, MAX_TEXT_BYTES));
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_thinking_text() -> Res {
    for c in cases()? {
        let line = assistant_blocks(&json!([{"type": "thinking", "thinking": c.value}]));
        let want = Entry::Thinking {
            text: cut(&c.multi, MAX_TEXT_BYTES),
        };
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_tool_name() -> Res {
    for c in cases()? {
        let line = assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": c.value, "input": {}}
        ]));
        let want = call("t1", &cut(&c.single, MAX_TOOL_NAME_BYTES), "", "{}", None)?;
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_summary_and_input() -> Res {
    for c in cases()? {
        let line = assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": c.value}}
        ]));
        let input = cut(&format!("{{\"command\":\"{}\"}}", c.json), MAX_INPUT_BYTES);
        let want = call(
            "t1",
            "Bash",
            &cut(&c.single, MAX_SUMMARY_CHARS),
            &input,
            None,
        )?;
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_tool_output() -> Res {
    for c in cases()? {
        let line = json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": c.value}
        ]}})
        .to_string();
        let want_out = capped_output(&c.multi);
        let want = res("t1", false, &want_out, None)?;
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_output_from_the_stdout_fallback() -> Res {
    for c in cases()? {
        let line = json!({
            "type": "user",
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t1"}]},
            "tool_use_result": {"stdout": c.value, "stderr": ""}
        })
        .to_string();
        let want_out = capped_output(&c.multi);
        assert_eq!(
            one(parse(&line))?,
            res("t1", false, &want_out, None)?,
            "{}",
            c.label
        );
    }
    Ok(())
}

#[test]
fn hostile_raw_of_an_unknown_type() -> Res {
    let prefix = "{\"type\":\"future\",\"v\":\"";
    for c in cases()? {
        let line = json!({"type": "future", "v": c.value}).to_string();
        let want = cut(&format!("{prefix}{}\"}}", c.json), MAX_TEXT_BYTES);
        assert_eq!(one(parse(&line))?, unknown("future", &want), "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_raw_of_an_unknown_block() -> Res {
    for c in cases()? {
        let line = assistant_blocks(&json!([{"type": "future_block", "v": c.value}]));
        let want = cut(
            &format!("{{\"type\":\"future_block\",\"v\":\"{}\"}}", c.json),
            MAX_TEXT_BYTES,
        );
        assert_eq!(
            one(parse(&line))?,
            unknown("future_block", &want),
            "{}",
            c.label
        );
    }
    Ok(())
}

#[test]
fn hostile_kind_and_subtype_become_a_question_mark() -> Res {
    for c in cases()? {
        let kind_line = json!({"type": c.value}).to_string();
        match one(parse(&kind_line))? {
            Entry::Unknown { kind, .. } => assert_eq!(kind, "?", "{}", c.label),
            other => return Err(format!("{}: {other:?}", c.label).into()),
        }
        let sub_line = json!({"type": "system", "subtype": c.value}).to_string();
        assert_eq!(one(parse(&sub_line))?, sys("?", false), "{}", c.label);
    }
    Ok(())
}

#[test]
fn allowlisted_labels_pass_through() -> Res {
    let label = "good_Type-1.x:y/z";
    let line = json!({"type": "system", "subtype": label}).to_string();
    assert_eq!(one(parse(&line))?, sys(label, false));
    match one(parse(&json!({"type": label}).to_string()))? {
        Entry::Unknown { kind, .. } => assert_eq!(kind, label),
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn hostile_fleet_note() -> Res {
    for c in cases()? {
        let line = format!("fleet: {}", c.value);
        let got = parse(&line);
        if c.label == "crlf" {
            let want = vec![
                Entry::FleetNote {
                    text: "a".to_owned(),
                },
                unknown("?", "b"),
            ];
            assert_eq!(got, want, "{}", c.label);
        } else {
            let want = Entry::FleetNote {
                text: cut(&c.single, MAX_TEXT_BYTES),
            };
            assert_eq!(one(got)?, want, "{}", c.label);
        }
    }
    Ok(())
}

#[test]
fn hostile_rate_limit_status() -> Res {
    for c in cases()? {
        let line =
            json!({"type": "rate_limit_event", "rate_limit_info": {"status": c.value}}).to_string();
        let want = Entry::RateLimit {
            status: cut(&c.single, MAX_LABEL_BYTES),
            utilization: None,
            resets_at: None,
        };
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

#[test]
fn hostile_terminal_reason() -> Res {
    for c in cases()? {
        let line = json!({"type": "result", "terminal_reason": c.value}).to_string();
        let want = Entry::Result {
            is_error: false,
            turns: 0,
            duration_ms: 0,
            cost_usd: None,
            usage: Usage::default(),
            terminal_reason: Some(cut(&c.single, MAX_LABEL_BYTES)),
            denials: 0,
        };
        assert_eq!(one(parse(&line))?, want, "{}", c.label);
    }
    Ok(())
}

const VALID_IDS: [&str; 3] = ["script", "md_link", "html_entity"];

#[test]
fn hostile_tool_call_id() -> Res {
    for c in cases()? {
        let line = assistant_blocks(&json!([
            {"type": "tool_use", "id": c.value, "name": "Bash", "input": {}}
        ]));
        let got = one(parse(&line))?;
        if VALID_IDS.contains(&c.label.as_str()) {
            assert_eq!(got, call(&c.value, "Bash", "", "{}", None)?, "{}", c.label);
        } else {
            let raw = cut(
                &format!(
                    "{{\"id\":\"{}\",\"input\":{{}},\"name\":\"Bash\",\"type\":\"tool_use\"}}",
                    c.json
                ),
                MAX_TEXT_BYTES,
            );
            assert_eq!(got, unknown("tool_use", &raw), "{}", c.label);
        }
    }
    Ok(())
}

#[test]
fn hostile_tool_result_id() -> Res {
    for c in cases()? {
        let line = json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": c.value, "content": "x"}
        ]}})
        .to_string();
        let got = one(parse(&line))?;
        if VALID_IDS.contains(&c.label.as_str()) {
            assert_eq!(got, res(&c.value, false, "x", None)?, "{}", c.label);
        } else {
            match got {
                Entry::Unknown { kind, .. } => assert_eq!(kind, "tool_result", "{}", c.label),
                other => return Err(format!("{}: {other:?}", c.label).into()),
            }
        }
    }
    Ok(())
}

#[test]
fn hostile_parent_id() -> Res {
    for c in cases()? {
        let line = json!({
            "type": "assistant",
            "parent_tool_use_id": c.value,
            "message": {"content": [{"type": "text", "text": "hi"}]}
        })
        .to_string();
        let got = one(parse(&line))?;
        if VALID_IDS.contains(&c.label.as_str()) {
            let want = Entry::Message {
                role: Role::Assistant,
                text: "hi".to_owned(),
                subagent: Some(id(&c.value)?),
            };
            assert_eq!(got, want, "{}", c.label);
        } else {
            match got {
                Entry::Unknown { kind, .. } => assert_eq!(kind, "assistant", "{}", c.label),
                other => return Err(format!("{}: {other:?}", c.label).into()),
            }
        }
    }
    Ok(())
}

#[test]
fn hostile_non_json_line_becomes_unknown_with_clean_raw() {
    let got = parse("x\u{202e}y\u{85}z\x1b[0m");
    assert_eq!(got, vec![unknown("?", "xy z[0m")]);
}

#[test]
fn chunk_cap_rejects_a_line_one_over_before_parsing() {
    let line = assistant_text("hi");
    let limits = small(|l| l.chunk_bytes = line.len());
    assert_eq!(parse_with(&line, &limits), vec![msg(Role::Assistant, "hi")]);
    let longer = assistant_text("hi!");
    assert_eq!(longer.len(), line.len() + 1);
    assert_eq!(parse_with(&longer, &limits), vec![Entry::Truncated]);
    let note = "fleet: abcdef";
    let note_limits = small(|l| l.chunk_bytes = note.len() - 1);
    assert_eq!(parse_with(note, &note_limits), vec![Entry::Truncated]);
    let two = format!("{longer}\n{line}\n");
    assert_eq!(
        parse_with(&two, &limits),
        vec![Entry::Truncated, msg(Role::Assistant, "hi")]
    );
}

#[test]
fn chunk_cap_default_is_checked_with_a_real_oversize_line() {
    let at_cap = format!("fleet: {}", "a".repeat(MAX_CHUNK_BYTES - 7));
    assert_eq!(at_cap.len(), MAX_CHUNK_BYTES);
    assert_eq!(
        parse(&at_cap),
        vec![Entry::FleetNote {
            text: "a".repeat(MAX_TEXT_BYTES)
        }]
    );
    let over = format!("{at_cap}a");
    assert_eq!(parse(&over), vec![Entry::Truncated]);
}

#[test]
fn text_cap_cuts_one_over_on_a_char_boundary() {
    let limits = small(|l| l.text_bytes = 10);
    let cases = [
        ("aaaaaaaaaa", "aaaaaaaaaa"),
        ("aaaaaaaaaaa", "aaaaaaaaaa"),
        ("aaaaaaaaa\u{e9}", "aaaaaaaaa"),
        ("aaaaaaaa\u{e9}", "aaaaaaaa\u{e9}"),
    ];
    for (input, want) in cases {
        assert_eq!(
            parse_with(&assistant_text(input), &limits),
            vec![msg(Role::Assistant, want)],
            "{input:?}"
        );
        assert_eq!(
            parse_with(&format!("fleet: {input}"), &limits),
            vec![Entry::FleetNote {
                text: want.to_owned()
            }],
            "{input:?}"
        );
    }
    let thinking = assistant_blocks(&json!([{"type": "thinking", "thinking": "aaaaaaaaaaa"}]));
    assert_eq!(
        parse_with(&thinking, &limits),
        vec![Entry::Thinking {
            text: "aaaaaaaaaa".to_owned()
        }]
    );
    assert_eq!(
        parse_with("not json at all", &limits),
        vec![unknown("?", "not json a")]
    );
}

#[test]
fn output_cap_appends_the_bytes_more_note() -> Res {
    let limits = small(|l| l.output_bytes = 10);
    let line = |out: &str| {
        json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": out}
        ]}})
        .to_string()
    };
    assert_eq!(
        parse_with(&line("aaaaaaaaaa"), &limits),
        vec![res("t1", false, "aaaaaaaaaa", None)?]
    );
    assert_eq!(
        parse_with(&line("aaaaaaaaaab"), &limits),
        vec![res("t1", false, "aaaaaaaaaa\n[1 bytes more]", None)?]
    );
    assert_eq!(
        parse_with(&line("aaaaaaaaa\u{e9}\u{e9}"), &limits),
        vec![res("t1", false, "aaaaaaaaa\n[4 bytes more]", None)?]
    );
    Ok(())
}

#[test]
fn summary_cap_counts_characters() -> Res {
    let limits = small(|l| l.summary_chars = 5);
    let line = |cmd: &str| {
        assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": cmd}}
        ]))
    };
    let summary_of = |cmd: &str| -> Result<String, String> {
        match one(parse_with(&line(cmd), &limits))? {
            Entry::ToolCall { summary, .. } => Ok(summary),
            other => Err(format!("{other:?}")),
        }
    };
    assert_eq!(
        summary_of("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}")?,
        "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"
    );
    assert_eq!(
        summary_of("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}x")?,
        "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"
    );
    assert_eq!(summary_of("abcde")?, "abcde");
    assert_eq!(summary_of("abcdef")?, "abcde");
    Ok(())
}

#[test]
fn input_cap_cuts_the_compact_json() -> Res {
    let limits = small(|l| l.input_bytes = 8);
    let input_of = |value: &serde_json::Value| -> Result<String, String> {
        let line = assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": "X", "input": value}
        ]));
        match one(parse_with(&line, &limits))? {
            Entry::ToolCall { input, .. } => Ok(input),
            other => Err(format!("{other:?}")),
        }
    };
    assert_eq!(input_of(&json!({"a": 1}))?, r#"{"a":1}"#);
    assert_eq!(input_of(&json!({"a": 10}))?, r#"{"a":10}"#);
    assert_eq!(input_of(&json!({"a": 100}))?, r#"{"a":100"#);
    Ok(())
}

#[test]
fn name_cap_cuts_one_over() -> Res {
    let limits = small(|l| l.name_bytes = 4);
    let name_of = |name: &str| -> Result<String, String> {
        let line = assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": name, "input": {}}
        ]));
        match one(parse_with(&line, &limits))? {
            Entry::ToolCall { name, .. } => Ok(name),
            other => Err(format!("{other:?}")),
        }
    };
    assert_eq!(name_of("Bash")?, "Bash");
    assert_eq!(name_of("Bashx")?, "Bash");
    Ok(())
}

#[test]
fn id_cap_rejects_one_over() -> Res {
    let limits = small(|l| l.id_bytes = 4);
    let line = |i: &str| {
        assistant_blocks(&json!([
            {"type": "tool_use", "id": i, "name": "X", "input": {}}
        ]))
    };
    assert_eq!(
        parse_with(&line("abcd"), &limits),
        vec![call("abcd", "X", "", "{}", None)?]
    );
    match one(parse_with(&line("abcde"), &limits))? {
        Entry::Unknown { kind, .. } => assert_eq!(kind, "tool_use"),
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn label_cap_applies_to_kind_status_and_reason() -> Res {
    let limits = small(|l| l.label_bytes = 4);
    match one(parse_with(&json!({"type": "abcd"}).to_string(), &limits))? {
        Entry::Unknown { kind, .. } => assert_eq!(kind, "abcd"),
        other => return Err(format!("{other:?}").into()),
    }
    match one(parse_with(&json!({"type": "abcde"}).to_string(), &limits))? {
        Entry::Unknown { kind, .. } => assert_eq!(kind, "?"),
        other => return Err(format!("{other:?}").into()),
    }
    let sub = |s: &str| json!({"type": "system", "subtype": s}).to_string();
    assert_eq!(one(parse_with(&sub("abcd"), &limits))?, sys("abcd", false));
    assert_eq!(one(parse_with(&sub("abcde"), &limits))?, sys("?", false));
    let status =
        |s: &str| json!({"type": "rate_limit_event", "rate_limit_info": {"status": s}}).to_string();
    for (input, want) in [("abcd", "abcd"), ("abcde", "abcd")] {
        let entry = Entry::RateLimit {
            status: want.to_owned(),
            utilization: None,
            resets_at: None,
        };
        assert_eq!(one(parse_with(&status(input), &limits))?, entry);
    }
    for (input, want) in [("abcd", "abcd"), ("abcde", "abcd")] {
        let line = json!({"type": "result", "terminal_reason": input}).to_string();
        match one(parse_with(&line, &limits))? {
            Entry::Result {
                terminal_reason, ..
            } => assert_eq!(terminal_reason.as_deref(), Some(want)),
            other => return Err(format!("{other:?}").into()),
        }
    }
    Ok(())
}

const SECRET: &str = "SECRETVALUE";

#[test]
fn secret_straddling_the_text_cap_is_redacted_before_the_cut() {
    let redactor = Redactor::new([SECRET]);
    let limits = small(|l| l.text_bytes = 10);
    let got = parse_chunk_with(
        &assistant_text("aaaaaaSECRETVALUE"),
        false,
        Some(&redactor),
        &limits,
    );
    assert_eq!(got, vec![msg(Role::Assistant, "aaaaaa[RED")]);
    let note = parse_chunk_with("fleet: aaaaaaSECRETVALUE", false, Some(&redactor), &limits);
    assert_eq!(
        note,
        vec![Entry::FleetNote {
            text: "aaaaaa[RED".to_owned()
        }]
    );
}

#[test]
fn secret_straddling_the_output_cap_is_redacted_before_the_cut() -> Res {
    let redactor = Redactor::new([SECRET]);
    let limits = small(|l| l.output_bytes = 10);
    let line = json!({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": "aaaaaaSECRETVALUE"}
    ]}})
    .to_string();
    let got = parse_chunk_with(&line, false, Some(&redactor), &limits);
    assert_eq!(
        got,
        vec![res("t1", false, "aaaaaa[RED\n[6 bytes more]", None)?]
    );
    Ok(())
}

#[test]
fn secret_hidden_by_hostile_characters_is_redacted() {
    let redactor = Redactor::new([SECRET]);
    let text = "x SECRET\u{202e}VALUE y";
    let got = parse_chunk(&assistant_text(text), false, Some(&redactor));
    assert_eq!(got, vec![msg(Role::Assistant, "x [REDACTED] y")]);
}

#[test]
fn secret_is_redacted_in_every_field() {
    let redactor = Redactor::new([SECRET]);
    let lines = [
        assistant_text(SECRET),
        assistant_blocks(&json!([{"type": "thinking", "thinking": SECRET}])),
        assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": SECRET, "input": {"command": SECRET}}
        ])),
        json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": SECRET}
        ]}})
        .to_string(),
        json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1"}]},
            "tool_use_result": {"stdout": SECRET, "stderr": SECRET}})
        .to_string(),
        json!({"type": "future", "v": SECRET}).to_string(),
        assistant_blocks(&json!([{"type": "future_block", "v": SECRET}])),
        json!({"type": SECRET}).to_string(),
        json!({"type": "system", "subtype": SECRET}).to_string(),
        json!({"type": "rate_limit_event", "rate_limit_info": {"status": SECRET}}).to_string(),
        json!({"type": "result", "terminal_reason": SECRET}).to_string(),
        format!("fleet: {SECRET}"),
        format!("not json {SECRET}"),
    ];
    for line in lines {
        let got = parse_chunk(&line, false, Some(&redactor));
        assert!(!got.is_empty(), "{line}");
        assert!(!format!("{got:?}").contains(SECRET), "{line}: {got:?}");
    }
}

#[test]
fn truncated_flag_wins_over_content() {
    let valid = assistant_text("hi");
    assert_eq!(parse_chunk(&valid, true, None), vec![Entry::Truncated]);
    assert_eq!(parse_chunk("", true, None), vec![Entry::Truncated]);
    assert_eq!(parse_chunk("a\nb\nc", true, None), vec![Entry::Truncated]);
}

#[test]
fn empty_chunk_has_no_entries() {
    assert_eq!(parse(""), Vec::<Entry>::new());
    assert_eq!(parse("\n"), Vec::<Entry>::new());
    assert_eq!(parse("\r\n"), Vec::<Entry>::new());
}

#[test]
fn trailing_newline_adds_no_entry() {
    let line = assistant_text("hi");
    assert_eq!(
        parse(&format!("{line}\n")),
        vec![msg(Role::Assistant, "hi")]
    );
}

#[test]
fn two_lines_in_one_chunk_parse_in_order() {
    let a = assistant_text("one");
    let b = assistant_text("two");
    assert_eq!(
        parse(&format!("{a}\n{b}")),
        vec![msg(Role::Assistant, "one"), msg(Role::Assistant, "two")]
    );
    assert_eq!(
        parse(&format!("{a}\n\n{b}\n")),
        vec![msg(Role::Assistant, "one"), msg(Role::Assistant, "two")]
    );
}

#[test]
fn crlf_line_endings_parse_like_lf() {
    let a = assistant_text("one");
    let b = assistant_text("two");
    assert_eq!(
        parse(&format!("{a}\r\n{b}\r\n")),
        vec![msg(Role::Assistant, "one"), msg(Role::Assistant, "two")]
    );
    assert_eq!(
        parse("fleet: no_changes\r\n"),
        vec![Entry::FleetNote {
            text: "no_changes".to_owned()
        }]
    );
}

#[test]
fn lines_are_never_joined_across_chunks() {
    let line = assistant_text("split me");
    let (head, tail) = line.split_at(line.len() / 2);
    let mut got = parse(head);
    got.extend(parse(tail));
    assert_eq!(got, vec![unknown("?", head), unknown("?", tail)]);
}

#[test]
fn only_the_exact_prefix_makes_a_fleet_note() {
    let note = |t: &str| Entry::FleetNote { text: t.to_owned() };
    assert_eq!(parse("fleet: no_changes"), vec![note("no_changes")]);
    assert_eq!(parse("fleet: "), vec![note("")]);
    assert_eq!(parse("fleet: fleet: x"), vec![note("fleet: x")]);
    for line in ["fleet:no", " fleet: x", "FLEET: x", "fleet : x", "hello"] {
        assert_eq!(parse(line), vec![unknown("?", line)], "{line:?}");
    }
    assert_eq!(parse("fleet:  x"), vec![note(" x")]);
}

fn nested(depth: usize) -> String {
    format!(
        "{{\"type\":\"future\",\"d\":{}{}}}",
        "[".repeat(depth),
        "]".repeat(depth)
    )
}

#[test]
fn nesting_at_the_json_depth_limit_parses_and_one_deeper_is_unknown() {
    let ok = nested(126);
    let sorted = format!(
        "{{\"d\":{}{},\"type\":\"future\"}}",
        "[".repeat(126),
        "]".repeat(126)
    );
    assert_eq!(parse(&ok), vec![unknown("future", &sorted)]);
    let deep = nested(127);
    assert_eq!(parse(&deep), vec![unknown("?", &deep)]);
    let bare = format!("{}{}", "[".repeat(129), "]".repeat(129));
    assert_eq!(parse(&bare), vec![unknown("?", &bare)]);
}

#[test]
fn one_assistant_line_emits_one_entry_per_block_in_order() -> Res {
    let line = assistant_blocks(&json!([
        {"type": "thinking", "thinking": "hmm"},
        {"type": "text", "text": "first"},
        {"type": "tool_use", "id": "a", "name": "Bash", "input": {"command": "ls"}},
        {"type": "future_block"},
        {"type": "tool_use", "id": "b", "name": "Read", "input": {"file_path": "/f"}},
        {"type": "text", "text": "last"}
    ]));
    let want = vec![
        Entry::Thinking {
            text: "hmm".to_owned(),
        },
        msg(Role::Assistant, "first"),
        call("a", "Bash", "ls", r#"{"command":"ls"}"#, None)?,
        unknown("future_block", r#"{"type":"future_block"}"#),
        call("b", "Read", "/f", r#"{"file_path":"/f"}"#, None)?,
        msg(Role::Assistant, "last"),
    ];
    assert_eq!(parse(&line), want);
    assert_eq!(parse(&assistant_blocks(&json!([]))), Vec::<Entry>::new());
    Ok(())
}

#[test]
fn user_line_with_text_blocks_is_a_user_message() {
    let line = json!({"type": "user", "message": {"content": [
        {"type": "text", "text": "do it"}
    ]}})
    .to_string();
    assert_eq!(parse(&line), vec![msg(Role::User, "do it")]);
}

#[test]
fn summary_follows_the_tool_name() -> Res {
    let long = "x".repeat(MAX_SUMMARY_CHARS + 1);
    let table: Vec<(&str, serde_json::Value, String)> = vec![
        (
            "Bash",
            json!({"command": "ls -l", "description": "d"}),
            "ls -l".to_owned(),
        ),
        (
            "Read",
            json!({"file_path": "/a", "command": "c"}),
            "/a".to_owned(),
        ),
        (
            "Edit",
            json!({"file_path": "/b", "old_string": "o"}),
            "/b".to_owned(),
        ),
        (
            "Write",
            json!({"file_path": "/c", "content": "k"}),
            "/c".to_owned(),
        ),
        (
            "WebFetch",
            json!({"url": "http://example.invalid/", "prompt": "p"}),
            "http://example.invalid/".to_owned(),
        ),
        (
            "Task",
            json!({"description": "scan", "prompt": "pp"}),
            "scan".to_owned(),
        ),
        (
            "Grep",
            json!({"pattern": "foo", "path": "/p"}),
            "/p".to_owned(),
        ),
        ("Grep", json!({"a": 1, "b": "second"}), "second".to_owned()),
        ("Grep", json!({"a": long, "b": "short"}), "short".to_owned()),
        (
            "Grep",
            json!({"a": "x".repeat(MAX_SUMMARY_CHARS), "b": "short"}),
            "x".repeat(MAX_SUMMARY_CHARS),
        ),
        ("Grep", json!({"a": 1}), String::new()),
        ("Grep", json!(null), String::new()),
        ("Bash", json!({"other": "fallback"}), "fallback".to_owned()),
        (
            "Bash",
            json!({"command": long}),
            "x".repeat(MAX_SUMMARY_CHARS),
        ),
    ];
    for (name, input, want) in table {
        let line = assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": name, "input": input}
        ]));
        match one(parse(&line))? {
            Entry::ToolCall { summary, .. } => assert_eq!(summary, want, "{name} {input}"),
            other => return Err(format!("{other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn tool_result_output_shapes() -> Res {
    let result = |content: serde_json::Value| {
        json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": content}
        ]}})
        .to_string()
    };
    assert_eq!(
        parse(&result(json!("plain"))),
        vec![res("t1", false, "plain", None)?]
    );
    assert_eq!(
        parse(&result(json!([
            {"type": "text", "text": "a"},
            {"type": "image", "source": {}},
            {"type": "text", "text": "b"}
        ]))),
        vec![res("t1", false, "a\n[image]\nb", None)?]
    );
    assert_eq!(parse(&result(json!([]))), vec![res("t1", false, "", None)?]);
    assert_eq!(
        parse(&result(json!(null))),
        vec![res("t1", false, "", None)?]
    );
    match one(parse(&result(json!([{"type": "audio"}]))))? {
        Entry::Unknown { kind, .. } => assert_eq!(kind, "tool_result"),
        other => return Err(format!("{other:?}").into()),
    }
    match one(parse(&result(json!(5))))? {
        Entry::Unknown { kind, .. } => assert_eq!(kind, "tool_result"),
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn tool_result_falls_back_to_stdout_and_stderr() -> Res {
    let line = |extra: serde_json::Value| {
        json!({
            "type": "user",
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "is_error": true}]},
            "tool_use_result": extra
        })
        .to_string()
    };
    assert_eq!(
        parse(&line(json!({"stdout": "out", "stderr": "err"}))),
        vec![res("t1", true, "out\nerr", None)?]
    );
    assert_eq!(
        parse(&line(json!({"stdout": "out", "stderr": ""}))),
        vec![res("t1", true, "out", None)?]
    );
    assert_eq!(
        parse(&line(json!({"stdout": "", "stderr": "err"}))),
        vec![res("t1", true, "err", None)?]
    );
    assert_eq!(
        parse(&line(json!({"interrupted": false}))),
        vec![res("t1", true, "", None)?]
    );
    let present = json!({
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "main"}]},
        "tool_use_result": {"stdout": "ignored"}
    })
    .to_string();
    assert_eq!(parse(&present), vec![res("t1", false, "main", None)?]);
    Ok(())
}

#[test]
fn result_line_fields() -> Res {
    let line = json!({
        "type": "result", "is_error": true, "num_turns": 7, "duration_ms": 99,
        "total_cost_usd": 1.5,
        "usage": {"input_tokens": 1, "output_tokens": 2,
                  "cache_read_input_tokens": 3, "cache_creation_input_tokens": 4},
        "permission_denials": [{}, {}, {}], "terminal_reason": "max_turns"
    })
    .to_string();
    let want = Entry::Result {
        is_error: true,
        turns: 7,
        duration_ms: 99,
        cost_usd: Some(1.5),
        usage: Usage {
            input_tokens: 1,
            output_tokens: 2,
            cache_read_input_tokens: 3,
            cache_creation_input_tokens: 4,
        },
        terminal_reason: Some("max_turns".to_owned()),
        denials: 3,
    };
    assert_eq!(one(parse(&line))?, want);
    let bare = Entry::Result {
        is_error: false,
        turns: 0,
        duration_ms: 0,
        cost_usd: None,
        usage: Usage::default(),
        terminal_reason: None,
        denials: 0,
    };
    assert_eq!(one(parse(r#"{"type":"result"}"#))?, bare);
    Ok(())
}

#[test]
fn rate_limit_fields() -> Res {
    let line = json!({"type": "rate_limit_event", "rate_limit_info": {
        "status": "allowed_warning", "utilization": 0.5, "resetsAt": 42}})
    .to_string();
    let want = Entry::RateLimit {
        status: "allowed_warning".to_owned(),
        utilization: Some(0.5),
        resets_at: Some(42),
    };
    assert_eq!(one(parse(&line))?, want);
    Ok(())
}

#[test]
fn malformed_shapes_become_unknown_with_the_line_as_raw() {
    let table: [(&str, &str); 17] = [
        ("null", "?"),
        ("1", "?"),
        (r#""x""#, "?"),
        ("[]", "?"),
        ("{}", "?"),
        (r#"{"type":1}"#, "?"),
        (r#"{"type":"assistant"}"#, "assistant"),
        (r#"{"type":"assistant","message":5}"#, "assistant"),
        (r#"{"type":"assistant","message":{"content":[1]}}"#, "?"),
        (r#"{"type":"assistant","message":{"content":[{}]}}"#, "?"),
        (
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use"}]}}"#,
            "tool_use",
        ),
        (
            r#"{"type":"assistant","message":{"content":[{"type":"text"}]}}"#,
            "text",
        ),
        (
            r#"{"type":"assistant","message":{"content":[{"type":"thinking"}]}}"#,
            "thinking",
        ),
        (
            r#"{"type":"user","message":{"content":[{"type":"tool_result"}]}}"#,
            "tool_result",
        ),
        (r#"{"type":"system"}"#, "system"),
        (r#"{"type":"rate_limit_event"}"#, "rate_limit_event"),
        (r#"{"type":"user","message":{"content":7}}"#, "user"),
    ];
    for (line, kind) in table {
        let got = parse(line);
        let raw = match line {
            r#"{"type":"assistant","message":{"content":[1]}}"# => "1",
            r#"{"type":"assistant","message":{"content":[{}]}}"# => "{}",
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use"}]}}"# => {
                r#"{"type":"tool_use"}"#
            }
            r#"{"type":"assistant","message":{"content":[{"type":"text"}]}}"# => {
                r#"{"type":"text"}"#
            }
            r#"{"type":"assistant","message":{"content":[{"type":"thinking"}]}}"# => {
                r#"{"type":"thinking"}"#
            }
            r#"{"type":"user","message":{"content":[{"type":"tool_result"}]}}"# => {
                r#"{"type":"tool_result"}"#
            }
            r#"{"type":"assistant","message":5}"# => r#"{"message":5,"type":"assistant"}"#,
            r#"{"type":"user","message":{"content":7}}"# => {
                r#"{"message":{"content":7},"type":"user"}"#
            }
            other => other,
        };
        assert_eq!(got, vec![unknown(kind, raw)], "{line}");
    }
}

#[test]
fn tabs_survive_in_multi_line_fields_and_go_from_single_line_ones() -> Res {
    assert_eq!(
        one(parse(&assistant_text("a\tb\nc")))?,
        msg(Role::Assistant, "a\tb\nc")
    );
    assert_eq!(
        parse("fleet: a\tb"),
        vec![Entry::FleetNote {
            text: "a b".to_owned()
        }]
    );
    let line = assistant_blocks(&json!([
        {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "a\tb"}}
    ]));
    match one(parse(&line))? {
        Entry::ToolCall { summary, .. } => assert_eq!(summary, "a b"),
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn text_blocks_of_a_result_keep_their_whitespace() -> Res {
    let line = json!({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "text", "text": "  a "}, {"type": "text", "text": " b\n"}
        ]}
    ]}})
    .to_string();
    assert_eq!(parse(&line), vec![res("t1", false, "  a \n b\n", None)?]);
    Ok(())
}

const ESCAPED_SECRETS: [(&str, &str); 4] = [
    ("sk-escape", "sk-SECRET"),
    ("quote", "sk-ab\"cdef"),
    ("backslash", "sk-ab\\cdef"),
    ("newline", "sk-ab\ncdef"),
];

fn with_escaped(label: &str, line: String) -> String {
    if label == "sk-escape" {
        line.replace("sk-SECRET", "sk-\\u0053ECRET")
    } else {
        line
    }
}

#[test]
fn escaped_secret_is_redacted_in_every_unknown_path() {
    type Path = (&'static str, &'static str, fn(&serde_json::Value) -> String);
    let paths: [Path; 11] = [
        ("array line", "?", |s| json!([s]).to_string()),
        ("no type", "?", |s| json!({"a": s}).to_string()),
        ("unknown type", "zzz", |s| {
            json!({"type": "zzz", "a": s}).to_string()
        }),
        ("system without subtype", "system", |s| {
            json!({"type": "system", "a": s}).to_string()
        }),
        ("rate limit without status", "rate_limit_event", |s| {
            json!({"type": "rate_limit_event", "a": s}).to_string()
        }),
        ("bad parent", "user", |s| {
            json!({"type": "user", "parent_tool_use_id": 7, "a": s}).to_string()
        }),
        ("bad content", "assistant", |s| {
            json!({"type": "assistant", "message": {"content": 5}, "a": s}).to_string()
        }),
        ("unknown block", "future", |s| {
            assistant_blocks(&json!([{"type": "future", "a": s}]))
        }),
        ("malformed tool_use", "tool_use", |s| {
            assistant_blocks(&json!([{"type": "tool_use", "a": s}]))
        }),
        ("malformed tool_result", "tool_result", |s| {
            json!({"type": "user", "message": {"content": [{"type": "tool_result", "a": s}]}})
                .to_string()
        }),
        ("secret as key", "zzz", |s| {
            json!({"type": "zzz", s.as_str().unwrap_or_default(): 1}).to_string()
        }),
    ];
    for (label, secret) in ESCAPED_SECRETS {
        let redactor = Redactor::new([secret]);
        for (path, kind, build) in paths {
            let line = with_escaped(label, build(&json!(secret)));
            let want_raw = match path {
                "array line" => r#"["[REDACTED]"]"#.to_owned(),
                "secret as key" => r#"{"[REDACTED]":1,"type":"zzz"}"#.to_owned(),
                "bad parent" => {
                    r#"{"a":"[REDACTED]","parent_tool_use_id":7,"type":"user"}"#.to_owned()
                }
                "bad content" => {
                    r#"{"a":"[REDACTED]","message":{"content":5},"type":"assistant"}"#.to_owned()
                }
                _ if kind == "?" => r#"{"a":"[REDACTED]"}"#.to_owned(),
                _ => format!(r#"{{"a":"[REDACTED]","type":"{kind}"}}"#),
            };
            let got = parse_chunk(&line, false, Some(&redactor));
            assert_eq!(got, vec![unknown(kind, &want_raw)], "{label} {path}");
        }
    }
}

#[test]
fn escaped_secret_is_redacted_in_tool_call_input() -> Res {
    for (label, secret) in ESCAPED_SECRETS {
        let redactor = Redactor::new([secret]);
        let line = with_escaped(
            label,
            assistant_blocks(&json!([
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": secret}}
            ])),
        );
        let got = parse_chunk(&line, false, Some(&redactor));
        assert_eq!(
            got,
            vec![call(
                "t1",
                "Bash",
                "[REDACTED]",
                r#"{"command":"[REDACTED]"}"#,
                None
            )?],
            "{label}"
        );
        let nested = with_escaped(
            label,
            assistant_blocks(&json!([
                {"type": "tool_use", "id": "t2", "name": "Other", "input": {"k": [secret], "n": {secret: secret}}}
            ])),
        );
        let got = parse_chunk(&nested, false, Some(&redactor));
        assert_eq!(
            got,
            vec![call(
                "t2",
                "Other",
                "",
                r#"{"k":["[REDACTED]"],"n":{"[REDACTED]":"[REDACTED]"}}"#,
                None
            )?],
            "{label}"
        );
    }
    Ok(())
}

#[test]
fn deep_unknown_value_is_scrubbed_without_overflow() {
    let redactor = Redactor::new([SECRET]);
    let depth = 120;
    let line = format!(
        "{{\"type\":\"zzz\",\"d\":{}\"{SECRET}\"{}}}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    let want = format!(
        "{{\"d\":{}\"[REDACTED]\"{},\"type\":\"zzz\"}}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    let got = parse_chunk(&line, false, Some(&redactor));
    assert_eq!(got, vec![unknown("zzz", &want)]);
}

#[test]
fn single_line_fields_turn_line_breaks_into_spaces() -> Res {
    let line = assistant_blocks(&json!([
        {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "echo ok\nrm -rf /\r\nx\ty"}}
    ]));
    assert_eq!(
        parse(&line),
        vec![call(
            "t1",
            "Bash",
            "echo ok rm -rf / x y",
            r#"{"command":"echo ok\nrm -rf /\nx\ty"}"#,
            None
        )?]
    );
    Ok(())
}

fn json_escaped(label: &str, secret: &str) -> String {
    if label == "sk-escape" {
        return "sk-\\u0053ECRET".to_owned();
    }
    let quoted = json!(secret).to_string();
    quoted
        .get(1..quoted.len() - 1)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn unparseable_line_with_an_escaped_secret_keeps_no_text() {
    for (label, secret) in ESCAPED_SECRETS {
        let redactor = Redactor::new([secret]);
        let escaped = json_escaped(label, secret);
        let deep = format!(
            "{{\"type\":\"zzz\",\"d\":{}\"{escaped}\"{}}}",
            "[".repeat(127),
            "]".repeat(127)
        );
        let fragment = format!("tail of a line\", \"k\": \"{escaped}\", \"z\": 1}}");
        for line in [deep, fragment] {
            let want = unknown("?", &format!("[unparseable line, {} bytes]", line.len()));
            let got = parse_chunk(&line, false, Some(&redactor));
            assert_eq!(got, vec![want], "{label}");
        }
    }
}

#[test]
fn unparseable_line_without_a_backslash_is_redacted_text() {
    let redactor = Redactor::new([SECRET]);
    let got = parse_chunk("half a line SECRETVALUE end", false, Some(&redactor));
    assert_eq!(got, vec![unknown("?", "half a line [REDACTED] end")]);
}

#[test]
fn unparseable_line_with_a_backslash_and_no_redactor_stays_text() {
    let got = parse("tail \\\" more");
    assert_eq!(got, vec![unknown("?", "tail \\\" more")]);
}

#[test]
fn secret_with_a_crlf_is_redacted_in_a_tool_result() -> Res {
    let redactor = Redactor::new(["line1\r\nline2-secret"]);
    let line = json!({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": "pre line1\r\nline2-secret post"}
    ]}})
    .to_string();
    assert_eq!(
        parse_chunk(&line, false, Some(&redactor)),
        vec![res("t1", false, "pre [REDACTED] post", None)?]
    );
    Ok(())
}

#[test]
fn secret_with_a_hostile_character_is_redacted_in_a_message() {
    let redactor = Redactor::new(["sk-ab\u{200b}cdefgh"]);
    let got = parse_chunk(
        &assistant_text("key sk-ab\u{200b}cdefgh end"),
        false,
        Some(&redactor),
    );
    assert_eq!(got, vec![msg(Role::Assistant, "key [REDACTED] end")]);
}

#[test]
fn secret_reassembled_by_the_strip_is_redacted() {
    let redactor = Redactor::new(["abcdefgh"]);
    let got = parse_chunk(
        &assistant_text("key abcd\u{200b}efgh end"),
        false,
        Some(&redactor),
    );
    assert_eq!(got, vec![msg(Role::Assistant, "key [REDACTED] end")]);
}

#[test]
fn single_line_secret_with_a_break_is_redacted_before_flattening() -> Res {
    let redactor = Redactor::new(["line1\r\nline2-secret"]);
    let line = assistant_blocks(&json!([
        {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "x line1\r\nline2-secret y"}}
    ]));
    let got = parse_chunk(&line, false, Some(&redactor));
    assert_eq!(
        got,
        vec![call(
            "t1",
            "Bash",
            "x [REDACTED] y",
            r#"{"command":"x [REDACTED] y"}"#,
            None
        )?]
    );
    Ok(())
}

const BREAKS: [char; 8] = [
    '\n', '\r', '\t', '\u{b}', '\u{c}', '\u{85}', '\u{2028}', '\u{2029}',
];

#[test]
fn every_line_break_becomes_a_space_in_every_single_line_field() -> Res {
    for brk in BREAKS {
        let text = format!("echo ok{brk}rm -rf /");
        let want = "echo ok rm -rf /";
        let kept = if matches!(brk, '\n' | '\t') {
            text.clone()
        } else {
            text.replace(brk, "")
        };
        let tool = assistant_blocks(&json!([
            {"type": "tool_use", "id": "t1", "name": text, "input": {"command": text}}
        ]));
        assert_eq!(
            parse(&tool),
            vec![Entry::ToolCall {
                id: id("t1")?,
                name: want.to_owned(),
                summary: want.to_owned(),
                input: json!({"command": kept}).to_string(),
                parent: None,
            }],
            "tool {brk:?}"
        );
        let rate = json!({"type": "rate_limit_event", "rate_limit_info": {"status": text}});
        assert_eq!(
            parse(&rate.to_string()),
            vec![Entry::RateLimit {
                status: want.to_owned(),
                utilization: None,
                resets_at: None,
            }],
            "status {brk:?}"
        );
        let result = json!({"type": "result", "terminal_reason": text}).to_string();
        let got = one(parse(&result))?;
        let Entry::Result {
            terminal_reason, ..
        } = got
        else {
            return Err(format!("want a result, got {got:?}").into());
        };
        assert_eq!(terminal_reason.as_deref(), Some(want), "reason {brk:?}");
        if brk != '\n' {
            assert_eq!(
                parse(&format!("fleet: {text}")),
                vec![Entry::FleetNote {
                    text: want.to_owned()
                }],
                "note {brk:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_crlf_in_a_single_line_field_is_one_space() {
    let rate = json!({"type": "rate_limit_event", "rate_limit_info": {"status": "a\r\nb"}});
    assert_eq!(
        parse(&rate.to_string()),
        vec![Entry::RateLimit {
            status: "a b".to_owned(),
            utilization: None,
            resets_at: None,
        }]
    );
}

#[test]
fn ten_thousand_hostile_keys_are_bounded_and_fast() {
    let controls: Vec<char> = (0u8..32).map(char::from).collect();
    let mut map = serde_json::Map::new();
    'fill: for a in &controls {
        for b in &controls {
            for c in &controls {
                if map.len() == 10_000 {
                    break 'fill;
                }
                map.insert(format!("{a}{b}{c}"), json!(1));
            }
        }
    }
    assert_eq!(map.len(), 10_000);
    let line = serde_json::Value::Object(map).to_string();
    let limits = small(|l| l.chunk_bytes = 8 * 1024 * 1024);
    let start = std::time::Instant::now();
    let got = parse_with(&line, &limits);
    assert!(start.elapsed().as_secs() < 20, "took {:?}", start.elapsed());
    let Ok(Entry::Unknown { raw, .. }) = one(got) else {
        panic!("want one unknown entry");
    };
    assert!(raw.len() <= MAX_TEXT_BYTES);
    assert_eq!(raw.matches(":1").count(), MAX_OBJECT_KEYS);
}

#[test]
fn colliding_keys_get_one_suffix_and_a_clash_after_it_is_dropped() {
    let line = r#"{"a\u0001":1,"a\u0002":2,"a#1":3,"a\u0003":4,"type":"zzz"}"#;
    let got = parse(line);
    let Ok(Entry::Unknown { raw, .. }) = one(got) else {
        panic!("want one unknown entry");
    };
    assert_eq!(raw, r#"{"a":1,"a#1":2,"a#2":4,"type":"zzz"}"#);
}

#[test]
fn tool_id_the_redactor_changes_is_rejected() -> Res {
    let redactor = Redactor::new(["toolid-secret"]);
    let call_line = assistant_blocks(&json!([
        {"type": "tool_use", "id": "toolid-secret", "name": "Bash", "input": {}}
    ]));
    let got = one(parse_chunk(&call_line, false, Some(&redactor)))?;
    let Entry::Unknown { raw, .. } = got else {
        return Err(format!("want unknown, got {got:?}").into());
    };
    assert!(!raw.contains("toolid-secret"), "{raw}");
    let result_line = json!({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolid-secret", "content": "x"}
    ]}})
    .to_string();
    let got = one(parse_chunk(&result_line, false, Some(&redactor)))?;
    assert!(matches!(got, Entry::Unknown { .. }), "{got:?}");
    let parent_line = json!({"type": "assistant", "parent_tool_use_id": "toolid-secret",
        "message": {"content": "hi"}})
    .to_string();
    let got = one(parse_chunk(&parent_line, false, Some(&redactor)))?;
    assert!(matches!(got, Entry::Unknown { .. }), "{got:?}");
    Ok(())
}

fn fleet_note(text: &str) -> Entry {
    Entry::FleetNote {
        text: text.to_owned(),
    }
}

#[test]
fn fleet_note_with_an_escape_and_a_redactor_keeps_no_text() {
    let redactor = Redactor::new([SECRET]);
    let table = [
        ("quote", "x\\\"SECRETVALUE\\\"".to_owned()),
        ("backslash", "C:\\dir\\SECRETVALUE".to_owned()),
        ("unicode", "x\\u0053ECRETVALUE".to_owned()),
        ("api key", "sk-abcdefghijklmnop\\n".to_owned()),
    ];
    for (label, note) in table {
        let line = format!("fleet: {note}");
        let want = fleet_note(&format!("[unparseable note, {} bytes]", note.len()));
        assert_eq!(
            parse_chunk(&line, false, Some(&redactor)),
            vec![want],
            "{label}"
        );
        assert_eq!(
            parse(&line),
            vec![fleet_note(&note)],
            "{label} without a redactor"
        );
    }
}

#[test]
fn fleet_note_escaped_secret_never_reaches_the_text() {
    for (label, secret) in ESCAPED_SECRETS {
        let redactor = Redactor::new([secret]);
        let escaped = json_escaped(label, secret);
        let got = parse_chunk(&format!("fleet: {escaped}"), false, Some(&redactor));
        assert_eq!(got.len(), 1, "{label}");
        let Some(Entry::FleetNote { text }) = got.first() else {
            panic!("{label}: {got:?}");
        };
        assert!(text.starts_with("[unparseable note, "), "{label}: {text}");
    }
}

#[test]
fn fleet_note_without_a_backslash_is_redacted_by_the_normal_path() {
    let redactor = Redactor::new([SECRET]);
    let got = parse_chunk("fleet: a SECRETVALUE b", false, Some(&redactor));
    assert_eq!(got, vec![fleet_note("a [REDACTED] b")]);
    assert_eq!(
        parse("fleet: a SECRETVALUE b"),
        vec![fleet_note("a SECRETVALUE b")]
    );
}

fn empty_results_line(blocks: usize, stdout: &str) -> String {
    let block = json!({"type": "tool_result", "tool_use_id": "t1"});
    json!({
        "type": "user",
        "message": {"content": vec![block; blocks]},
        "tool_use_result": {"stdout": stdout}
    })
    .to_string()
}

#[test]
fn amplification_line_is_capped_and_parses_fast() {
    let stdout = "x".repeat(200_000);
    let line = empty_results_line(1300, &stdout);
    assert!(line.len() <= MAX_CHUNK_BYTES, "{}", line.len());
    let redactor = Redactor::new([SECRET]);
    let start = std::time::Instant::now();
    let got = parse_chunk(&line, false, Some(&redactor));
    assert!(start.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(got.len(), MAX_ENTRIES_PER_LINE + 1);
    assert_eq!(got.last(), Some(&Entry::Truncated));
    let results = got.iter().filter(|e| matches!(e, Entry::ToolResult { .. }));
    assert_eq!(results.count(), MAX_ENTRIES_PER_LINE);
}

#[test]
fn entry_cap_applies_with_a_shrunk_value_just_over_it() {
    let limits = small(|l| l.line_entries = 3);
    let blocks = |n: usize| {
        let block = json!({"type": "text", "text": "hi"});
        json!({"type": "assistant", "message": {"content": vec![block; n]}}).to_string()
    };
    let at = parse_with(&blocks(3), &limits);
    assert_eq!(at.len(), 3);
    assert!(!at.contains(&Entry::Truncated));
    let over = parse_with(&blocks(4), &limits);
    assert_eq!(over.len(), 4);
    assert_eq!(over.last(), Some(&Entry::Truncated));
    assert_eq!(over.iter().filter(|e| **e == Entry::Truncated).count(), 1);
    let two = format!("{}\n{}", blocks(3), blocks(1));
    let both = parse_with(&two, &limits);
    assert_eq!(both.len(), 4);
    assert!(!both.contains(&Entry::Truncated));
}

fn chunks_of(name: &str) -> Result<Vec<String>, std::io::Error> {
    Ok(fixture(name)?.lines().map(str::to_owned).collect())
}

fn view_of(name: &str, done: bool) -> Result<Transcript, std::io::Error> {
    let chunks = chunks_of(name)?;
    Ok(Transcript::build(
        chunks.iter().map(|c| (c.as_str(), false)),
        done,
        None,
    ))
}

fn view_limits(f: impl FnOnce(&mut ViewLimits)) -> ViewLimits {
    let mut limits = ViewLimits::DEFAULT;
    f(&mut limits);
    limits
}

fn build_lines(lines: &[String], done: bool, limits: &ViewLimits) -> Transcript {
    Transcript::build_with(
        lines.iter().map(|c| (c.as_str(), false)),
        done,
        None,
        limits,
    )
}

fn pair(item: &Item) -> Result<&Pair, String> {
    match item {
        Item::Pair(p) => Ok(p),
        other => Err(format!("want a pair, got {other:?}")),
    }
}

fn pairs(view: &Transcript) -> Vec<&Pair> {
    view.items()
        .iter()
        .filter_map(|i| match i {
            Item::Pair(p) => Some(p),
            _ => None,
        })
        .collect()
}

fn done_status(is_error: bool, output: &str) -> PairStatus {
    PairStatus::Done {
        is_error,
        output: output.to_owned(),
    }
}

fn task_call(i: &str, parent: Option<&str>) -> String {
    json!({
        "type": "assistant",
        "message": {"id": format!("m_{i}"), "content": [
            {"type": "tool_use", "id": i, "name": "Task", "input": {"description": "d"}}
        ]},
        "parent_tool_use_id": parent,
    })
    .to_string()
}

fn text_line(text: &str, parent: Option<&str>) -> String {
    json!({
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": text}]},
        "parent_tool_use_id": parent,
    })
    .to_string()
}

fn result_line(i: &str, output: &str, parent: Option<&str>) -> String {
    json!({
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_use_id": i, "content": output}]},
        "parent_tool_use_id": parent,
    })
    .to_string()
}

fn total_items(items: &[Item]) -> usize {
    let mut stack: Vec<&Item> = items.iter().collect();
    let mut n = 0;
    while let Some(item) = stack.pop() {
        n += 1;
        if let Item::Pair(p) = item {
            stack.extend(p.children.iter());
        }
    }
    n
}

fn max_depth(items: &[Item]) -> usize {
    let mut stack: Vec<(&Item, usize)> = items.iter().map(|i| (i, 0)).collect();
    let mut deepest = 0;
    while let Some((item, d)) = stack.pop() {
        deepest = deepest.max(d);
        if let Item::Pair(p) = item {
            stack.extend(p.children.iter().map(|c| (c, d + 1)));
        }
    }
    deepest
}

#[test]
fn interleaved_results_join_their_calls() -> Res {
    let view = view_of("interleaved_calls.jsonl", false)?;
    let found = pairs(&view);
    assert_eq!(found.len(), 2);
    let ids: Vec<&str> = found.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["toolu_07A", "toolu_07B"]);
    assert_eq!(found[0].status, done_status(false, "a"));
    assert_eq!(found[1].status, done_status(false, "b"));
    assert!(
        view.items()
            .iter()
            .all(|i| !matches!(i, Item::Orphan { .. }))
    );
    Ok(())
}

#[test]
fn a_call_without_result_is_pending_until_the_job_is_done() -> Res {
    let live = view_of("call_without_result.jsonl", false)?;
    let open = pairs(&live);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].status, PairStatus::Pending);
    assert!(!live.done());
    let ended = view_of("call_without_result.jsonl", true)?;
    assert_eq!(pairs(&ended)[0].status, PairStatus::NoResult);
    assert!(ended.done());
    Ok(())
}

#[test]
fn a_result_without_a_call_is_an_orphan() -> Res {
    let view = view_of("result_without_call.jsonl", true)?;
    let orphans: Vec<&Item> = view
        .items()
        .iter()
        .filter(|i| matches!(i, Item::Orphan { .. }))
        .collect();
    assert_eq!(orphans.len(), 1);
    assert!(matches!(
        orphans[0],
        Item::Orphan { id, output, .. } if id.as_str() == "toolu_09ORPHAN" && !output.is_empty()
    ));
    assert_eq!(pairs(&view).len(), 0);
    Ok(())
}

#[test]
fn subagent_work_nests_under_its_task_call() -> Res {
    let view = view_of("subagent.jsonl", true)?;
    let tasks = pairs(&view);
    assert_eq!(tasks.len(), 1);
    let task = tasks[0];
    assert_eq!(task.id.as_str(), "toolu_02T1");
    assert_eq!(task.status, done_status(false, "No TODOs found."));
    assert_eq!(task.children.len(), 2);
    let inner = pair(&task.children[0])?;
    assert_eq!(inner.id.as_str(), "toolu_02C1");
    assert_eq!(inner.status, done_status(false, "none"));
    assert!(matches!(
        &task.children[1],
        Item::Entry(Entry::Message { subagent: Some(s), .. }) if s.as_str() == "toolu_02T1"
    ));
    Ok(())
}

#[test]
fn duplicate_ids_keep_the_first_pair_and_the_first_usage() -> Res {
    let view = view_of("duplicate_ids.jsonl", true)?;
    let found = pairs(&view);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "Bash");
    assert_eq!(found[0].status, done_status(false, "first"));
    assert_eq!(view.dropped(), 2);
    let turns: Vec<(&str, u64)> = view
        .turns()
        .iter()
        .map(|t| (t.message_id.as_str(), t.usage.output_tokens))
        .collect();
    assert_eq!(turns, [("msg_14A", 20), ("msg_14B", 20)]);
    assert_eq!(view.totals().map(|u| u.output_tokens), Some(340));
    Ok(())
}

#[test]
fn totals_come_from_the_last_result_line() -> Res {
    let view = view_of("sample_job.jsonl", true)?;
    assert_eq!(
        view.totals(),
        Some(Usage {
            input_tokens: 120,
            output_tokens: 340,
            ..Usage::default()
        })
    );
    assert_eq!(view.turns().len(), 3);
    let first = r#"{"type":"result","usage":{"input_tokens":1}}"#;
    let second = r#"{"type":"result","usage":{"input_tokens":2}}"#;
    let two = Transcript::build([(first, false), (second, false)], true, None);
    assert_eq!(two.totals().map(|u| u.input_tokens), Some(2));
    let none = Transcript::build([(&text_line("x", None)[..], false)], true, None);
    assert_eq!(none.totals(), None);
    Ok(())
}

#[test]
fn hostile_parents_render_at_the_top_level() {
    let lines = vec![
        task_call("self", Some("self")),
        task_call("a", Some("b")),
        task_call("b", Some("a")),
        task_call("lost", Some("nowhere")),
        text_line("hi", Some("nowhere")),
        result_line("self", "r", Some("a")),
    ];
    let view = build_lines(&lines, true, &ViewLimits::DEFAULT);
    let ids: Vec<&str> = pairs(&view).iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["self", "a", "lost"]);
    assert_eq!(view.items().len(), 4);
    assert_eq!(total_items(view.items()), 5);
    assert_eq!(pairs(&view)[1].children.len(), 1);
    assert_eq!(pairs(&view)[0].children.len(), 0);
    assert_eq!(pairs(&view)[0].status, done_status(false, "r"));
}

#[test]
fn a_child_nests_only_under_a_call_that_came_first() {
    let lines = vec![
        text_line("early", Some("late")),
        task_call("late", None),
        text_line("after", Some("late")),
    ];
    let view = build_lines(&lines, true, &ViewLimits::DEFAULT);
    assert_eq!(view.items().len(), 2);
    assert_eq!(pairs(&view)[0].children.len(), 1);
}

fn chain(n: usize) -> Vec<String> {
    (0..n)
        .map(|k| {
            let parent = (k > 0).then(|| format!("t{}", k - 1));
            task_call(&format!("t{k}"), parent.as_deref())
        })
        .collect()
}

#[test]
fn nesting_stops_at_depth_eight() {
    let at = build_lines(&chain(9), true, &ViewLimits::DEFAULT);
    assert_eq!(max_depth(at.items()), 8);
    assert_eq!(total_items(at.items()), 9);
    let over = build_lines(&chain(12), true, &ViewLimits::DEFAULT);
    assert_eq!(max_depth(over.items()), 8);
    assert_eq!(total_items(over.items()), 12);
    assert_eq!(over.dropped(), 0);
}

#[test]
fn nesting_depth_cap_applies_with_a_shrunk_value_just_over_it() {
    let limits = view_limits(|l| l.depth = 2);
    let at = build_lines(&chain(3), true, &limits);
    assert_eq!(max_depth(at.items()), 2);
    let over = build_lines(&chain(4), true, &limits);
    assert_eq!(max_depth(over.items()), 2);
    assert_eq!(total_items(over.items()), 4);
    let huge = view_limits(|l| l.depth = 1000);
    assert_eq!(max_depth(build_lines(&chain(20), true, &huge).items()), 8);
}

#[test]
fn a_child_past_the_cap_sits_beside_its_parent() -> Res {
    let limits = view_limits(|l| l.depth = 1);
    let mut lines = chain(2);
    lines.push(task_call("deep", Some("t1")));
    let view = build_lines(&lines, true, &limits);
    let top = pair(&view.items()[0])?;
    let names: Vec<&str> = top
        .children
        .iter()
        .map(|c| pair(c).map(|p| p.id.as_str()))
        .collect::<Result<_, _>>()?;
    assert_eq!(names, ["t1", "deep"]);
    Ok(())
}

fn many_lines(n: usize) -> String {
    (0..n)
        .map(|k| text_line(&format!("m{k}"), None))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn view_entry_cap_applies_with_a_shrunk_value_just_over_it() {
    let limits = view_limits(|l| l.entries = 3);
    let at = Transcript::build_with([(many_lines(3).as_str(), false)], false, None, &limits);
    assert_eq!(at.items().len(), 3);
    assert!(!at.capped());
    assert_eq!(at.dropped(), 0);
    let over = Transcript::build_with([(many_lines(4).as_str(), false)], false, None, &limits);
    assert_eq!(over.items().len(), 3);
    assert!(over.capped());
    assert_eq!(over.dropped(), 1);
}

#[test]
fn nested_items_count_against_the_entry_cap() {
    let limits = view_limits(|l| l.entries = 3);
    let lines = vec![
        task_call("t", None),
        text_line("a", Some("t")),
        text_line("b", Some("t")),
        text_line("c", Some("t")),
    ];
    let view = build_lines(&lines, true, &limits);
    assert_eq!(total_items(view.items()), 3);
    assert!(view.capped());
}

#[test]
fn the_view_holds_at_most_twenty_thousand_entries() {
    assert_eq!(MAX_VIEW_ENTRIES, 20_000);
    let at = Transcript::build(
        [(many_lines(MAX_VIEW_ENTRIES).as_str(), false)],
        false,
        None,
    );
    assert_eq!(at.items().len(), MAX_VIEW_ENTRIES);
    assert!(!at.capped());
    let over = Transcript::build(
        [(many_lines(MAX_VIEW_ENTRIES + 1).as_str(), false)],
        false,
        None,
    );
    assert_eq!(over.items().len(), MAX_VIEW_ENTRIES);
    assert!(over.capped());
    assert_eq!(over.dropped(), 1);
}

#[test]
fn many_pending_calls_stay_inside_the_cap_and_close_on_finish() {
    let lines: Vec<String> = (0..=MAX_VIEW_ENTRIES)
        .map(|k| task_call(&format!("p{k}"), None))
        .collect();
    let mut asm = Assembler::new(None);
    for line in &lines {
        asm.push(line, false);
    }
    let closed = asm.finish();
    assert_eq!(closed.len(), MAX_VIEW_ENTRIES);
    let view = asm.snapshot();
    assert!(view.capped());
    assert!(
        pairs(&view)
            .iter()
            .all(|p| p.status == PairStatus::NoResult)
    );
}

#[test]
fn huge_orphan_counts_stay_inside_the_cap() {
    let lines: Vec<String> = (0..MAX_VIEW_ENTRIES + 5)
        .map(|k| result_line(&format!("o{k}"), "x", None))
        .collect();
    let view = build_lines(&lines, true, &ViewLimits::DEFAULT);
    assert_eq!(view.items().len(), MAX_VIEW_ENTRIES);
    assert_eq!(view.dropped(), 5);
}

fn weight_of(items: &[Item]) -> usize {
    let mut stack: Vec<&Item> = items.iter().collect();
    let mut bytes = 0;
    while let Some(item) = stack.pop() {
        match item {
            Item::Orphan { output, .. } => bytes += output.len(),
            Item::Pair(p) => stack.extend(p.children.iter()),
            _ => {}
        }
    }
    bytes
}

#[test]
fn byte_cap_applies_with_a_shrunk_value_just_over_it() {
    let limits = view_limits(|l| l.bytes = 45);
    let at = Transcript::build_with(
        [(many_lines(2).as_str(), false)],
        false,
        None,
        &view_limits(|l| l.bytes = 4),
    );
    assert_eq!(at.items().len(), 2);
    assert!(!at.capped());
    let over = Transcript::build_with(
        [(many_lines(2).as_str(), false)],
        false,
        None,
        &view_limits(|l| l.bytes = 3),
    );
    assert_eq!(over.items().len(), 1);
    assert!(over.capped());
    let lines = vec![
        task_call("t", None),
        result_line("t", &"y".repeat(21), None),
    ];
    let lost = build_lines(&lines, true, &limits);
    assert_eq!(pairs(&lost)[0].status, done_status(false, ""));
    assert!(lost.capped());
    let fits = vec![
        task_call("t", None),
        result_line("t", &"y".repeat(20), None),
    ];
    let kept = build_lines(&fits, true, &limits);
    assert_eq!(pairs(&kept)[0].status, done_status(false, &"y".repeat(20)));
    assert!(!kept.capped());
}

#[test]
fn one_line_of_257_large_entries_cannot_fill_memory() {
    assert_eq!(MAX_VIEW_BYTES, 8 * 1024 * 1024);
    let make = |n: usize| {
        let blocks: Vec<_> = (0..=MAX_ENTRIES_PER_LINE)
            .map(|k| json!({"type": "tool_result", "tool_use_id": format!("t{n}_{k}")}))
            .collect();
        json!({
            "type": "user",
            "message": {"content": blocks},
            "tool_use_result": {"stdout": "z".repeat(20_000)},
        })
        .to_string()
    };
    let line = make(0);
    assert!(line.len() <= MAX_CHUNK_BYTES);
    let single = Transcript::build([(line.as_str(), false)], true, None);
    assert_eq!(single.items().len(), MAX_ENTRIES_PER_LINE + 1);
    assert!(weight_of(single.items()) <= MAX_VIEW_BYTES);
    let lines: Vec<String> = (0..6).map(make).collect();
    let view = build_lines(&lines, true, &ViewLimits::DEFAULT);
    assert!(view.capped());
    assert!(weight_of(view.items()) <= MAX_VIEW_BYTES);
    assert!(weight_of(view.items()) > MAX_VIEW_BYTES - 2 * (MAX_OUTPUT_BYTES + 64));
}

#[test]
fn a_cap_still_lets_the_result_line_set_the_totals() {
    let limits = view_limits(|l| l.entries = 1);
    let lines = vec![
        text_line("a", None),
        text_line("b", None),
        r#"{"type":"result","usage":{"output_tokens":7}}"#.to_owned(),
    ];
    let view = build_lines(&lines, true, &limits);
    assert_eq!(view.items().len(), 1);
    assert_eq!(view.totals().map(|u| u.output_tokens), Some(7));
}

#[test]
fn distinct_message_ids_are_capped() {
    let limits = view_limits(|l| l.entries = 2);
    let turn = |k: usize| {
        json!({"type": "assistant", "message": {"id": format!("m{k}"),
            "content": [], "usage": {"output_tokens": 1}}})
        .to_string()
    };
    let at = build_lines(&[turn(1), turn(2)], true, &limits);
    assert_eq!(at.turns().len(), 2);
    let over = build_lines(&[turn(1), turn(2), turn(3), turn(1)], true, &limits);
    assert_eq!(over.turns().len(), 2);
    assert!(over.turns_capped());
    assert!(!over.capped());
    assert!(!at.turns_capped());
}

#[test]
fn a_truncated_chunk_is_one_truncated_item_and_is_not_parsed() {
    let view = Transcript::build(
        [(r#"{"type":"result","usage":{"input_tokens":9}}"#, true)],
        true,
        None,
    );
    assert_eq!(view.items(), [Item::Entry(Entry::Truncated)]);
    assert_eq!(view.totals(), None);
}

#[test]
fn a_secret_in_a_call_id_never_pairs() {
    const SECRET: &str = "sk-live-0123456789";
    let redactor = Redactor::new([SECRET]);
    let call_line = task_call(&format!("t_{SECRET}"), None);
    let result = result_line(&format!("t_{SECRET}"), "out", None);
    let view = Transcript::build(
        [(call_line.as_str(), false), (result.as_str(), false)],
        true,
        Some(&redactor),
    );
    assert_eq!(pairs(&view).len(), 0);
    assert!(
        view.items()
            .iter()
            .all(|i| !matches!(i, Item::Orphan { .. }))
    );
    assert!(!format!("{view:?}").contains(SECRET));
}

#[test]
fn push_after_finish_changes_nothing_and_finish_is_idempotent() {
    let mut asm = Assembler::new(None);
    asm.push(&task_call("t", None), false);
    assert_eq!(asm.finish().len(), 1);
    assert_eq!(asm.finish().len(), 0);
    assert_eq!(asm.push(&result_line("t", "late", None), false).len(), 0);
    assert_eq!(asm.push(&text_line("late", None), false).len(), 0);
    assert_eq!(asm.snapshot().items().len(), 1);
    let view = asm.snapshot();
    assert_eq!(pairs(&view)[0].status, PairStatus::NoResult);
}

fn place_in(items: &mut Vec<Item>, under: Option<&ToolId>, item: Item) -> bool {
    let Some(id) = under else {
        items.push(item);
        return true;
    };
    for existing in items.iter_mut() {
        if let Item::Pair(p) = existing {
            if &p.id == id {
                p.children.push(item);
                return true;
            }
            if place_in(&mut p.children, under, item.clone()) {
                return true;
            }
        }
    }
    false
}

fn pair_mut<'a>(items: &'a mut [Item], id: &ToolId) -> Option<&'a mut Pair> {
    for item in items {
        if let Item::Pair(p) = item {
            if &p.id == id {
                return Some(p);
            }
            if let Some(found) = pair_mut(&mut p.children, id) {
                return Some(found);
            }
        }
    }
    None
}

fn adopt_in(item: &mut Item, adopted: &Pair) {
    match item {
        Item::Orphan { id, .. } if *id == adopted.id => *item = Item::Pair(adopted.clone()),
        Item::Pair(p) => {
            for child in &mut p.children {
                adopt_in(child, adopted);
            }
        }
        _ => {}
    }
}

fn replay(updates: &[Update]) -> (Vec<Item>, Vec<TurnUsage>, Option<Usage>, bool) {
    let mut items = Vec::new();
    let mut turns = Vec::new();
    let mut totals = None;
    let mut capped = false;
    for update in updates {
        match update {
            Update::Appended { under, item } => {
                place_in(&mut items, under.as_ref(), item.clone());
            }
            Update::Paired {
                id,
                is_error,
                output,
            } => {
                if let Some(p) = pair_mut(&mut items, id) {
                    p.status = done_status(*is_error, output);
                }
            }
            Update::NoResult { id } => {
                if let Some(p) = pair_mut(&mut items, id) {
                    p.status = PairStatus::NoResult;
                }
            }
            Update::Adopted { pair } => {
                for item in &mut items {
                    adopt_in(item, pair);
                }
            }
            Update::Turn(t) => turns.push(t.clone()),
            Update::Totals(u) => totals = Some(*u),
            Update::Capped => capped = true,
            _ => {}
        }
    }
    (items, turns, totals, capped)
}

const ALL_FIXTURES: [&str; 15] = [
    "sample_job.jsonl",
    "subagent.jsonl",
    "thinking.jsonl",
    "result_block_array.jsonl",
    "error_result.jsonl",
    "denial.jsonl",
    "interleaved_calls.jsonl",
    "call_without_result.jsonl",
    "result_without_call.jsonl",
    "truncated_chunk.jsonl",
    "unknown_top_level.jsonl",
    "unknown_subtype.jsonl",
    "unknown_block.jsonl",
    "duplicate_ids.jsonl",
    "late_call.jsonl",
];

#[test]
fn every_fixture_pushed_chunk_by_chunk_equals_the_batch_and_its_replay() -> Res {
    for name in ALL_FIXTURES {
        let lines = chunks_of(name)?;
        let mut asm = Assembler::new(None);
        let mut updates = Vec::new();
        for line in &lines {
            updates.extend(asm.push(line, false));
        }
        updates.extend(asm.finish());
        let batch = build_lines(&lines, true, &ViewLimits::DEFAULT);
        assert_eq!(asm.snapshot(), batch, "{name}");
        let whole = Transcript::build([(fixture(name)?.as_str(), false)], true, None);
        assert_eq!(whole, batch, "{name}");
        let (items, turns, totals, capped) = replay(&updates);
        assert_eq!(items, batch.items(), "{name}");
        assert_eq!(turns, batch.turns(), "{name}");
        assert_eq!(totals, batch.totals(), "{name}");
        assert_eq!(capped, batch.capped(), "{name}");
    }
    Ok(())
}

#[test]
fn every_split_point_of_interleaved_calls_gives_the_same_view() -> Res {
    let lines = chunks_of("interleaved_calls.jsonl")?;
    let want = build_lines(&lines, false, &ViewLimits::DEFAULT);
    for at in 0..=lines.len() {
        let (head, tail) = lines.split_at(at);
        let (a, b) = (head.join("\n"), tail.join("\n"));
        let view = Transcript::build([(a.as_str(), false), (b.as_str(), false)], false, None);
        assert_eq!(view, want, "split at {at}");
    }
    Ok(())
}

#[test]
fn updates_arrive_in_input_order() -> Res {
    let lines = chunks_of("interleaved_calls.jsonl")?;
    let mut asm = Assembler::new(None);
    let mut kinds = Vec::new();
    for line in &lines {
        for update in asm.push(line, false) {
            kinds.push(match update {
                Update::Appended {
                    item: Item::Pair(p),
                    ..
                } => format!("call {}", p.id),
                Update::Appended { .. } => "item".to_owned(),
                Update::Paired { id, .. } => format!("result {id}"),
                Update::Turn(t) => format!("turn {}", t.message_id),
                Update::Totals(_) => "totals".to_owned(),
                other => format!("{other:?}"),
            });
        }
    }
    let at = |s: &str| kinds.iter().position(|k| k == s);
    assert!(at("call toolu_07A") < at("call toolu_07B"));
    assert!(at("call toolu_07B") < at("result toolu_07B"));
    assert!(at("result toolu_07B") < at("result toolu_07A"));
    Ok(())
}

fn kept_with_bytes(entry_line: &str, bytes: usize) -> (usize, bool) {
    let limits = view_limits(|l| l.bytes = bytes);
    let view = Transcript::build_with([(entry_line, false)], false, None, &limits);
    (view.items().len(), view.capped())
}

#[test]
fn every_entry_kind_weighs_its_text_against_the_byte_cap() {
    let msg = json!({"type": "user", "message": {"content": "abcd"}, "parent_tool_use_id": null});
    let sub_msg =
        json!({"type": "assistant", "message": {"content": "abcd"}, "parent_tool_use_id": "tt"});
    let thinking = text_block_line("thinking", "thinking", "abcd");
    let note = "fleet: abcd".to_owned();
    let system = r#"{"type":"system","subtype":"init"}"#.to_owned();
    let rate = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"abcd"}}"#.to_owned();
    let result = r#"{"type":"result","terminal_reason":"abcd"}"#.to_owned();
    let unknown = r#"{"type":"zz"}"#.to_owned();
    let table: [(&str, String, usize); 8] = [
        ("message", msg.to_string(), 4),
        ("thinking", thinking, 4),
        ("fleet note", note, 4),
        ("system", system, 4),
        ("rate limit", rate, 4),
        ("result", result, 4),
        ("unknown", unknown, 2 + 13),
        ("sub-agent message", sub_msg.to_string(), 4 + 2),
    ];
    for (label, line, weight) in table {
        assert_eq!(kept_with_bytes(&line, weight), (1, false), "{label} fits");
        assert_eq!(
            kept_with_bytes(&line, weight - 1),
            (0, true),
            "{label} over"
        );
    }
    let orphan = result_line("abc", "wxyz", None);
    assert_eq!(kept_with_bytes(&orphan, 7), (1, false));
    assert_eq!(kept_with_bytes(&orphan, 6), (0, true));
}

fn text_block_line(kind: &str, key: &str, text: &str) -> String {
    json!({"type": "assistant", "message": {"content": [{"type": kind, key: text}]}}).to_string()
}

#[test]
fn a_stored_result_counts_against_the_byte_cap() {
    let limits = view_limits(|l| l.bytes = 45);
    let lines = vec![
        task_call("t", None),
        result_line("t", &"y".repeat(20), None),
        text_line("a", None),
    ];
    let view = build_lines(&lines, true, &limits);
    assert_eq!(view.items().len(), 1);
    assert!(view.capped());
}

#[test]
fn the_line_cap_decides_whether_a_turn_is_read() {
    let line = |pad: usize| {
        json!({"type": "assistant", "message": {"id": "m1", "usage": {"output_tokens": 5},
            "content": [{"type": "text", "text": "a".repeat(pad)}]}})
        .to_string()
    };
    let base = line(0).len();
    let limits = view_limits(|l| l.parse.chunk_bytes = base + 10);
    let at = build_lines(&[line(10)], true, &limits);
    assert_eq!(at.turns().len(), 1);
    assert_eq!(at.items().len(), 1);
    let over = build_lines(&[line(11)], true, &limits);
    assert_eq!(over.turns().len(), 0);
    assert_eq!(over.items(), [Item::Entry(Entry::Truncated)]);
}

#[test]
fn the_result_line_stays_in_the_view() -> Res {
    let view = view_of("sample_job.jsonl", true)?;
    assert!(
        view.items()
            .iter()
            .any(|i| matches!(i, Item::Entry(Entry::Result { .. })))
    );
    Ok(())
}

fn push_all(asm: &mut Assembler<'_>, lines: &[String]) -> Vec<Update> {
    lines.iter().flat_map(|l| asm.push(l, false)).collect()
}

#[test]
fn late_call_adopts_the_orphan_in_place() -> Res {
    let lines = vec![
        result_line("t", "out", None),
        text_line("between", None),
        task_call("t", None),
        text_line("child", Some("t")),
        result_line("t", "again", None),
    ];
    let view = build_lines(&lines, true, &ViewLimits::DEFAULT);
    assert_eq!(view.items().len(), 2);
    let first = pair(&view.items()[0])?;
    assert_eq!(first.status, done_status(false, "out"));
    assert_eq!(first.children.len(), 1);
    assert_eq!(view.dropped(), 1);
    assert!(!view.capped());
    for at in 0..=lines.len() {
        let (a, b) = lines.split_at(at);
        let (a, b) = (a.join("\n"), b.join("\n"));
        let split = Transcript::build([(a.as_str(), false), (b.as_str(), false)], true, None);
        assert_eq!(split, view, "split at {at}");
    }
    Ok(())
}

#[test]
fn nothing_lands_after_a_cap_except_a_result_for_a_call_in_view() {
    let limits = view_limits(|l| l.bytes = 30);
    let mut asm = Assembler::with_limits(None, &limits);
    let lines = vec![
        task_call("t", None),
        text_line(&"x".repeat(10), None),
        text_line("z", None),
        task_call("late", None),
        result_line("late", "r", None),
        result_line("t", "ab", None),
    ];
    let updates = push_all(&mut asm, &lines);
    let at = updates.iter().position(|u| *u == Update::Capped);
    assert!(at.is_some());
    let after = updates.iter().skip(at.unwrap_or(0) + 1);
    assert_eq!(
        after
            .filter(|u| matches!(u, Update::Appended { .. }))
            .count(),
        0
    );
    let view = asm.snapshot();
    assert_eq!(view.items().len(), 1);
    assert_eq!(pairs(&view)[0].status, done_status(false, "ab"));
    assert_eq!(view.dropped(), 4);
}

#[test]
fn push_after_finish_counts_the_lines_as_dropped() {
    let mut asm = Assembler::new(None);
    asm.push(&task_call("t", None), false);
    asm.finish();
    assert_eq!(asm.push("a\n\nb\r\n", false).len(), 0);
    assert_eq!(asm.snapshot().dropped(), 2);
    assert_eq!(asm.push("ignored", true).len(), 0);
    assert_eq!(asm.snapshot().dropped(), 3);
}

#[test]
fn a_turn_cap_is_not_an_item_cap() {
    let limits = view_limits(|l| l.entries = 1);
    let turn = |k: usize| {
        json!({"type": "assistant", "message": {"id": format!("m{k}"),
            "content": [], "usage": {"output_tokens": 1}}})
        .to_string()
    };
    let mut asm = Assembler::with_limits(None, &limits);
    let updates = push_all(&mut asm, &[turn(1), turn(2)]);
    assert!(!updates.contains(&Update::Capped));
    let view = asm.snapshot();
    assert!(!view.capped());
    assert_eq!(view.dropped(), 0);
}

#[test]
fn after_a_cap_only_result_bearing_lines_are_parsed() {
    let limits = view_limits(|l| l.entries = 1);
    let three = json!({"type": "assistant", "message": {"id": "mm", "usage": {"output_tokens": 4},
        "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"},
                    {"type": "text", "text": "c"}]}})
    .to_string();
    let mut asm = Assembler::with_limits(None, &limits);
    push_all(&mut asm, &[task_call("t", None), text_line("over", None)]);
    assert_eq!(asm.snapshot().dropped(), 1);
    let updates = asm.push(&three, false);
    assert_eq!(updates.len(), 1);
    assert!(matches!(&updates[0], Update::Turn(t) if t.message_id.as_str() == "mm"));
    assert_eq!(asm.snapshot().dropped(), 2);
    asm.push(&result_line("t", "ok", None), false);
    asm.push(r#"{"type":"result","usage":{"input_tokens":5}}"#, false);
    let view = asm.snapshot();
    assert_eq!(pairs(&view)[0].status, done_status(false, "ok"));
    assert_eq!(view.totals().map(|u| u.input_tokens), Some(5));
    assert_eq!(view.dropped(), 3);
}

#[test]
fn a_fixture_with_a_late_call_adopts_the_orphan() -> Res {
    let view = view_of("late_call.jsonl", true)?;
    assert_eq!(view.dropped(), 1);
    let kinds: Vec<&str> = view
        .items()
        .iter()
        .map(|i| match i {
            Item::Pair(_) => "pair",
            Item::Orphan { .. } => "orphan",
            Item::Entry(_) => "entry",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["entry", "pair", "entry", "entry"]);
    assert_eq!(pairs(&view)[0].status, done_status(false, "early output"));
    Ok(())
}

fn kinds(updates: &[Update]) -> Vec<&'static str> {
    updates
        .iter()
        .map(|u| match u {
            Update::Appended {
                item: Item::Pair(_),
                ..
            } => "append pair",
            Update::Appended {
                item: Item::Orphan { .. },
                ..
            } => "append orphan",
            Update::Appended { .. } => "append",
            Update::Paired { .. } => "paired",
            Update::Adopted { .. } => "adopted",
            Update::NoResult { .. } => "no result",
            Update::Turn(_) => "turn",
            Update::Totals(_) => "totals",
            Update::Capped => "capped",
            _ => "other",
        })
        .collect()
}

#[test]
fn an_adopted_error_keeps_its_flag_and_its_bytes_count() {
    let error = json!({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t", "content": "bad", "is_error": true}]}})
    .to_string();
    let lines = vec![error, task_call("t", None), text_line("xx", None)];
    let view = build_lines(&lines, true, &view_limits(|l| l.bytes = 29));
    assert_eq!(pairs(&view)[0].status, done_status(true, "bad"));
    assert_eq!(view.items().len(), 1);
    assert!(view.capped());
    let roomy = build_lines(&lines, true, &view_limits(|l| l.bytes = 30));
    assert_eq!(roomy.items().len(), 2);
    assert!(!roomy.capped());
}

#[test]
fn after_a_cap_an_assistant_line_with_a_result_block_still_pairs() {
    let limits = view_limits(|l| l.entries = 1);
    let mut asm = Assembler::with_limits(None, &limits);
    push_all(&mut asm, &[task_call("t", None), text_line("over", None)]);
    let line = json!({"type": "assistant", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t", "content": "odd"}]}})
    .to_string();
    assert_eq!(kinds(&asm.push(&line, false)), ["paired"]);
    assert_eq!(pairs(&asm.snapshot())[0].status, done_status(false, "odd"));
}

#[test]
fn a_carriage_return_ends_a_pushed_line() {
    let mut asm = Assembler::new(None);
    asm.push("fleet: hi\r\n", false);
    assert_eq!(
        asm.snapshot().items(),
        [Item::Entry(Entry::FleetNote {
            text: "hi".to_owned()
        })]
    );
    asm.finish();
    asm.push("\r\na\r\n\r", false);
    assert_eq!(asm.snapshot().dropped(), 1);
}

#[test]
fn a_call_in_a_parsed_line_after_a_cap_is_dropped_not_adopted() {
    let mut asm = capped_assembler(false);
    let line = json!({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "p", "content": "ab"},
        {"type": "tool_use", "id": "o", "name": "Task", "input": {}}]}})
    .to_string();
    assert_eq!(step(&mut asm, &line), (vec!["paired"], 1));
    assert!(matches!(asm.snapshot().items()[0], Item::Orphan { .. }));
}

const RESULT_LINE: &str = r#"{"type":"result","usage":{"input_tokens":5}}"#;

fn step(asm: &mut Assembler<'_>, line: &str) -> (Vec<&'static str>, usize) {
    let before = asm.snapshot().dropped();
    let updates = asm.push(line, false);
    (kinds(&updates), asm.snapshot().dropped() - before)
}

fn step_truncated(asm: &mut Assembler<'_>) -> (Vec<&'static str>, usize) {
    let before = asm.snapshot().dropped();
    let updates = asm.push("cut", true);
    (kinds(&updates), asm.snapshot().dropped() - before)
}

#[test]
fn table_open_cells() {
    let mut asm = Assembler::new(None);
    assert_eq!(
        step(&mut asm, &task_call("a", None)),
        (vec!["append pair"], 0),
        "call"
    );
    assert_eq!(
        step(&mut asm, &result_line("a", "r", None)),
        (vec!["paired"], 0),
        "result"
    );
    assert_eq!(
        step(&mut asm, &result_line("a", "r2", None)),
        (vec![], 1),
        "duplicate result"
    );
    assert_eq!(
        step(&mut asm, &task_call("a", None)),
        (vec![], 1),
        "duplicate call"
    );
    assert_eq!(
        step(&mut asm, &result_line("o", "early", None)),
        (vec!["append orphan"], 0),
        "orphan"
    );
    assert_eq!(
        step(&mut asm, &result_line("o", "again", None)),
        (vec![], 1),
        "duplicate orphan"
    );
    assert_eq!(
        step(&mut asm, &task_call("o", None)),
        (vec!["adopted"], 0),
        "late call"
    );
    assert_eq!(
        step(&mut asm, &result_line("o", "again", None)),
        (vec![], 1),
        "result after adopt"
    );
    assert_eq!(
        step(&mut asm, &text_line("m", None)),
        (vec!["append"], 0),
        "message"
    );
    assert_eq!(
        step(&mut asm, RESULT_LINE),
        (vec!["totals", "append"], 0),
        "result line"
    );
    assert_eq!(asm.push("cut", true).len(), 1, "truncated");
    assert!(!asm.snapshot().capped());
}

#[test]
fn table_open_cells_that_go_over() {
    let full = |lines: &[String]| {
        let mut asm = Assembler::with_limits(None, &view_limits(|l| l.entries = lines.len()));
        push_all(&mut asm, lines);
        asm
    };
    let filler = vec![text_line("f", None)];
    let mut asm = full(&filler);
    assert_eq!(
        step(&mut asm, &task_call("n", None)),
        (vec!["capped"], 1),
        "call"
    );
    assert_eq!(
        step(&mut asm, &task_call("m", None)),
        (vec![], 1),
        "second drop is silent"
    );
    let mut asm = full(&filler);
    assert_eq!(
        step(&mut asm, &result_line("o", "r", None)),
        (vec!["capped"], 1),
        "orphan"
    );
    let mut asm = full(&filler);
    assert_eq!(
        step(&mut asm, &text_line("m", None)),
        (vec!["capped"], 1),
        "message"
    );
    let mut asm = full(&filler);
    assert_eq!(
        step(&mut asm, RESULT_LINE),
        (vec!["totals", "capped"], 1),
        "result line"
    );
    let mut asm = full(&filler);
    assert_eq!(step_truncated(&mut asm), (vec!["capped"], 1), "truncated");
    let mut asm = Assembler::with_limits(None, &view_limits(|l| l.bytes = 26));
    push_all(&mut asm, &[task_call("t", None)]);
    assert_eq!(
        step(&mut asm, &result_line("t", "ab", None)),
        (vec!["paired", "capped"], 0),
        "result over budget"
    );
    assert_eq!(pairs(&asm.snapshot())[0].status, done_status(false, ""));
    let mut asm = Assembler::with_limits(None, &view_limits(|l| l.bytes = 10));
    push_all(&mut asm, &[result_line("o", "r", None)]);
    assert_eq!(
        step(&mut asm, &task_call("o", None)),
        (vec!["capped"], 1),
        "late call body over"
    );
    assert!(matches!(asm.snapshot().items(), [Item::Orphan { .. }]));
}

fn capped_assembler(by_bytes: bool) -> Assembler<'static> {
    let limits = if by_bytes {
        view_limits(|l| l.bytes = 40)
    } else {
        view_limits(|l| l.entries = 2)
    };
    let mut asm = Assembler::with_limits(None, &limits);
    push_all(
        &mut asm,
        &[
            result_line("o", "r", None),
            task_call("p", None),
            text_line(&"x".repeat(20), None),
        ],
    );
    assert!(asm.snapshot().capped());
    assert_eq!(asm.snapshot().dropped(), 1);
    asm
}

#[test]
fn table_capped_cells() {
    for by_bytes in [true, false] {
        let mut asm = capped_assembler(by_bytes);
        let at = |what: &str| format!("{what}, bytes {by_bytes}");
        assert_eq!(
            step(&mut asm, &task_call("n", None)),
            (vec![], 1),
            "{}",
            at("call")
        );
        assert_eq!(
            step(&mut asm, &result_line("n", "r", None)),
            (vec![], 1),
            "{}",
            at("dropped call's result")
        );
        assert_eq!(
            step(&mut asm, &result_line("q", "r", None)),
            (vec![], 1),
            "{}",
            at("orphan")
        );
        assert_eq!(
            step(&mut asm, &task_call("o", None)),
            (vec![], 1),
            "{}",
            at("late call")
        );
        assert_eq!(
            step(&mut asm, &task_call("p", None)),
            (vec![], 1),
            "{}",
            at("duplicate call")
        );
        assert_eq!(
            step(&mut asm, &result_line("o", "r", None)),
            (vec![], 1),
            "{}",
            at("duplicate orphan")
        );
        assert_eq!(
            step(&mut asm, &text_line("m", None)),
            (vec![], 1),
            "{}",
            at("message")
        );
        assert_eq!(
            step(&mut asm, RESULT_LINE),
            (vec!["totals"], 1),
            "{}",
            at("result line")
        );
        assert_eq!(step_truncated(&mut asm), (vec![], 1), "{}", at("truncated"));
        assert_eq!(
            step(&mut asm, &result_line("p", "ab", None)),
            (vec!["paired"], 0),
            "{}",
            at("result")
        );
        assert_eq!(
            step(&mut asm, &result_line("p", "ab", None)),
            (vec![], 1),
            "{}",
            at("duplicate result")
        );
        let view = asm.snapshot();
        assert!(
            matches!(view.items()[0], Item::Orphan { .. }),
            "{}",
            at("orphan stays")
        );
        assert_eq!(pairs(&view)[0].status, done_status(false, "ab"));
        assert_eq!(view.items().len(), 2);
    }
    let mut asm = capped_assembler(true);
    assert_eq!(
        step(&mut asm, &result_line("p", &"y".repeat(14), None)),
        (vec!["paired"], 0),
        "result over the remaining bytes"
    );
    assert_eq!(pairs(&asm.snapshot())[0].status, done_status(false, ""));
}

#[test]
fn table_turn_capped_cells_behave_like_open() {
    let turn = |k: usize| {
        json!({"type": "assistant", "message": {"id": format!("m{k}"),
            "content": [], "usage": {"output_tokens": 1}}})
        .to_string()
    };
    let mut asm = Assembler::with_limits(None, &view_limits(|l| l.entries = 3));
    push_all(&mut asm, &[turn(1), turn(2), turn(3)]);
    assert_eq!(step(&mut asm, &turn(4)), (vec![], 0), "dropped turn");
    assert_eq!(step(&mut asm, &turn(1)), (vec![], 0), "repeated turn");
    assert!(asm.snapshot().turns_capped());
    assert_eq!(
        step(&mut asm, &task_call("a", None)),
        (vec!["append pair"], 0),
        "call"
    );
    assert_eq!(
        step(&mut asm, &result_line("a", "r", None)),
        (vec!["paired"], 0),
        "result"
    );
    assert_eq!(
        step(&mut asm, &result_line("o", "r", None)),
        (vec!["append orphan"], 0),
        "orphan"
    );
    assert_eq!(
        step(&mut asm, &task_call("o", None)),
        (vec!["adopted"], 0),
        "late call"
    );
    assert_eq!(
        step(&mut asm, &task_call("a", None)),
        (vec![], 1),
        "duplicate call"
    );
    assert_eq!(
        step(&mut asm, &text_line("m", None)),
        (vec!["append"], 0),
        "message"
    );
    assert_eq!(
        step(&mut asm, &text_line("n", None)),
        (vec!["capped"], 1),
        "message past the item cap"
    );
}

#[test]
fn table_finished_cells() {
    let mut asm = Assembler::new(None);
    push_all(
        &mut asm,
        &[task_call("p", None), result_line("o", "r", None)],
    );
    assert_eq!(kinds(&asm.finish()), ["no result"]);
    let lines = [
        task_call("n", None),
        result_line("p", "late", None),
        result_line("q", "late", None),
        task_call("o", None),
        task_call("p", None),
        result_line("o", "again", None),
        text_line("m", None),
        RESULT_LINE.to_owned(),
    ];
    for (k, line) in lines.iter().enumerate() {
        assert_eq!(step(&mut asm, line), (vec![], 1), "event {k}");
    }
    assert_eq!(step_truncated(&mut asm), (vec![], 1), "truncated");
    let view = asm.snapshot();
    assert_eq!(view.dropped(), 9);
    assert_eq!(view.totals(), None);
    assert_eq!(pairs(&view)[0].status, PairStatus::NoResult);
    assert!(matches!(view.items()[1], Item::Orphan { .. }));
}

#[test]
fn an_adopted_pair_takes_children_and_replays() {
    let lines = vec![
        result_line("t", "out", None),
        task_call("t", None),
        text_line("child", Some("t")),
    ];
    let mut asm = Assembler::new(None);
    let updates = push_all(&mut asm, &lines);
    assert_eq!(kinds(&updates), ["append orphan", "adopted", "append"]);
    let (items, ..) = replay(&updates);
    assert_eq!(items, asm.snapshot().items());
    assert!(matches!(&updates[2], Update::Appended { under: Some(u), .. } if u.as_str() == "t"));
}

#[test]
fn a_late_call_over_the_byte_budget_leaves_the_orphan() {
    let limits = view_limits(|l| l.bytes = 25);
    let lines = vec![result_line("t", "r", None), task_call("t", None)];
    let view = build_lines(&lines, true, &limits);
    assert!(matches!(view.items(), [Item::Orphan { .. }]));
    assert!(view.capped());
    assert_eq!(view.dropped(), 1);
    let fits = build_lines(&lines, true, &view_limits(|l| l.bytes = 26));
    assert_eq!(pairs(&fits).len(), 1);
    assert!(!fits.capped());
}
