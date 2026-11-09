//! Shell command records: redaction before truncation, NUL handling, caps.

use fleet_core::text::is_hostile;
use fleet_core::{PLACEHOLDER, Redactor};
use fleet_proto::{MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES};
use fleetd::shell_timing::{ShellError, ShellInput, ShellRecorder};

const SECRET: &str = "s3cr3t-token-value-xyz";

fn redactor() -> Redactor {
    Redactor::new([SECRET])
}

fn input(command: &str, output: &str) -> ShellInput {
    ShellInput {
        command: command.to_owned(),
        output: output.to_owned(),
        started: 1000,
        ended: Some(1500),
        exit_code: Some(0),
        background: false,
    }
}

#[test]
fn a_plain_record_keeps_every_field() {
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&ShellInput {
        exit_code: Some(3),
        background: true,
        ..input("ls", "out")
    })
    .expect("record");
    let r = &rec.records()[0];
    assert_eq!(r.command, "ls");
    assert_eq!(r.output, "out");
    assert_eq!((r.started, r.ended, r.duration), (1000, Some(1500), 500));
    assert_eq!(r.exit_code, Some(3));
    assert!(r.background);
    assert!(!r.truncated);
}

#[test]
fn an_unfinished_command_has_no_end_and_zero_duration() {
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&ShellInput {
        ended: None,
        exit_code: None,
        ..input("sleep 9", "")
    })
    .expect("record");
    let r = &rec.records()[0];
    assert_eq!((r.ended, r.duration, r.exit_code), (None, 0, None));
}

#[test]
fn a_secret_straddling_the_log_cap_is_redacted_whole() {
    let pad = "a".repeat(MAX_SHELL_LOG_BYTES - SECRET.len() / 2);
    let output = format!("{pad}{SECRET}tail");
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input("x", &output)).expect("record");
    let r = &rec.records()[0];
    assert!(r.truncated);
    assert!(r.output.len() <= MAX_SHELL_LOG_BYTES);
    assert!(!r.output.contains(&SECRET[..8]));
    assert!(r.output.contains(PLACEHOLDER) || r.output.ends_with(&PLACEHOLDER[..3]));
}

#[test]
fn a_secret_straddling_the_command_cap_is_redacted_whole() {
    let pad = "a".repeat(MAX_COMMAND_BYTES - SECRET.len() / 2);
    let command = format!("{pad}{SECRET}tail");
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input(&command, "")).expect("record");
    let r = &rec.records()[0];
    assert!(r.truncated);
    assert!(r.command.len() <= MAX_COMMAND_BYTES);
    assert!(!r.command.contains(&SECRET[..8]));
}

#[test]
fn a_secret_split_by_nul_is_still_redacted() {
    let split = format!("{}\0{}", &SECRET[..10], &SECRET[10..]);
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input(&format!("run {split}"), &format!("got {split}")))
        .expect("record");
    let r = &rec.records()[0];
    assert!(!r.command.contains('\0') && !r.output.contains('\0'));
    assert_eq!(r.command, format!("run {PLACEHOLDER}"));
    assert_eq!(r.output, format!("got {PLACEHOLDER}"));
}

#[test]
fn a_secret_in_each_field_is_redacted() {
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input(&format!("c {SECRET}"), &format!("o {SECRET}")))
        .expect("record");
    let r = &rec.records()[0];
    assert!(!r.command.contains(SECRET));
    assert!(!r.output.contains(SECRET));
}

#[test]
fn truncation_never_splits_a_character() {
    let output = "é".repeat(MAX_SHELL_LOG_BYTES);
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input("x", &output)).expect("record");
    let r = &rec.records()[0];
    assert!(r.truncated);
    assert_eq!(r.output.len(), MAX_SHELL_LOG_BYTES);
}

#[test]
fn output_at_the_cap_is_not_truncated() {
    let output = "a".repeat(MAX_SHELL_LOG_BYTES);
    let command = "c".repeat(MAX_COMMAND_BYTES);
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input(&command, &output)).expect("record");
    assert!(!rec.records()[0].truncated);
}

#[test]
fn an_empty_or_nul_only_command_is_refused() {
    let mut rec = ShellRecorder::new(redactor());
    assert_eq!(rec.record(&input("", "o")), Err(ShellError::EmptyCommand));
    assert_eq!(
        rec.record(&input("\0\0", "o")),
        Err(ShellError::EmptyCommand)
    );
    assert_eq!(rec.records().len(), 0);
}

#[test]
fn bad_times_are_refused() {
    let mut rec = ShellRecorder::new(redactor());
    let early = ShellInput {
        ended: Some(999),
        ..input("x", "")
    };
    assert_eq!(rec.record(&early), Err(ShellError::EndBeforeStart));
    let huge = ShellInput {
        started: u64::try_from(i64::MAX).expect("fits") + 1,
        ended: None,
        ..input("x", "")
    };
    assert_eq!(rec.record(&huge), Err(ShellError::TimeOutOfRange));
    assert_eq!(rec.records().len(), 0);
}

#[test]
fn records_over_the_cap_count_as_overflow_and_store_nothing() {
    let mut rec = ShellRecorder::new(redactor());
    for _ in 0..MAX_SHELL_COMMANDS + 5 {
        rec.record(&input("x", "")).expect("record");
    }
    assert_eq!(rec.records().len(), MAX_SHELL_COMMANDS);
    assert_eq!(rec.overflow(), 5);
}

#[test]
fn a_refused_record_over_the_cap_does_not_count() {
    let mut rec = ShellRecorder::new(redactor());
    for _ in 0..MAX_SHELL_COMMANDS {
        rec.record(&input("x", "")).expect("record");
    }
    assert!(rec.record(&input("", "")).is_err());
    assert_eq!(rec.overflow(), 0);
}

const SPLITTERS: [char; 3] = ['\u{1}', '\u{1b}', '\u{200b}'];

fn split_secret(by: char) -> String {
    format!("{}{by}{}", &SECRET[..10], &SECRET[10..])
}

#[test]
fn a_command_split_by_a_hidden_char_is_redacted() {
    for by in SPLITTERS {
        let mut rec = ShellRecorder::new(redactor());
        rec.record(&input(&format!("run {}", split_secret(by)), "x"))
            .expect("record");
        assert_eq!(
            rec.records()[0].command,
            format!("run {PLACEHOLDER}"),
            "{by:?}"
        );
    }
}

#[test]
fn a_log_split_by_a_hidden_char_is_redacted() {
    for by in SPLITTERS {
        let mut rec = ShellRecorder::new(redactor());
        rec.record(&input("x", &format!("got {}", split_secret(by))))
            .expect("record");
        assert_eq!(
            rec.records()[0].output,
            format!("got {PLACEHOLDER}"),
            "{by:?}"
        );
    }
}

#[test]
fn a_split_secret_straddling_the_command_cap_leaves_no_fragment() {
    for by in SPLITTERS {
        let pad = "a".repeat(MAX_COMMAND_BYTES - SECRET.len() / 2);
        let command = format!("{pad}{}tail", split_secret(by));
        let mut rec = ShellRecorder::new(redactor());
        rec.record(&input(&command, "")).expect("record");
        let r = &rec.records()[0];
        assert!(r.command.len() <= MAX_COMMAND_BYTES, "{by:?}");
        assert!(!r.command.contains(&SECRET[..8]), "{by:?}");
    }
}

#[test]
fn a_split_secret_straddling_the_log_cap_leaves_no_fragment() {
    for by in SPLITTERS {
        let pad = "a".repeat(MAX_SHELL_LOG_BYTES - SECRET.len() / 2);
        let output = format!("{pad}{}tail", split_secret(by));
        let mut rec = ShellRecorder::new(redactor());
        rec.record(&input("x", &output)).expect("record");
        let r = &rec.records()[0];
        assert!(r.output.len() <= MAX_SHELL_LOG_BYTES, "{by:?}");
        assert!(!r.output.contains(&SECRET[..8]), "{by:?}");
    }
}

#[test]
fn ordinary_text_survives_the_strip() {
    let mut rec = ShellRecorder::new(redactor());
    rec.record(&input(
        "ls -la\n\techo \u{e9}\u{65e5}",
        "l1\nl2\ttab \u{1F600}",
    ))
    .expect("record");
    let r = &rec.records()[0];
    assert_eq!(r.command, "ls -la\n\techo \u{e9}\u{65e5}");
    assert_eq!(r.output, "l1\nl2\ttab \u{1F600}");
}

#[test]
fn a_command_of_only_hidden_chars_is_refused_as_empty() {
    let mut rec = ShellRecorder::new(redactor());
    let result = rec.record(&input("\u{1}\u{200b}\0", "x"));
    assert_eq!(result, Err(ShellError::EmptyCommand));
    assert_eq!(rec.records().len(), 0);
}

#[test]
fn every_scalar_is_stripped_exactly_when_the_core_calls_it_hostile() {
    let record = |text: &str| {
        let mut rec = ShellRecorder::new(redactor());
        rec.record(&input("x", text)).expect("record");
        rec.records()[0].output.clone()
    };
    let all: Vec<char> = (0..=0x0010_FFFF_u32).filter_map(char::from_u32).collect();
    for chunk in all.chunks(2048) {
        let text: String = chunk.iter().collect();
        let want: String = chunk
            .iter()
            .filter(|&&c| c == '\n' || c == '\t' || !is_hostile(c))
            .collect();
        assert_eq!(record(&text), want, "from {:#x}", u32::from(chunk[0]));
    }
}

const HOSTILE_SAMPLES: [char; 8] = [
    '\0',
    '\r',
    '\u{1b}',
    '\u{85}',
    '\u{200b}',
    '\u{2028}',
    '\u{feff}',
    '\u{e0041}',
];

fn secret_holding(by: char) -> (Redactor, String) {
    let secret = format!("{}{by}{}", &SECRET[..10], &SECRET[10..]);
    (Redactor::new([secret.clone()]), secret)
}

#[test]
fn a_secret_that_itself_holds_a_hostile_char_is_redacted_in_the_command() {
    for by in HOSTILE_SAMPLES {
        let (redactor, secret) = secret_holding(by);
        let mut rec = ShellRecorder::new(redactor);
        rec.record(&input(&format!("run {secret}"), "x"))
            .expect("record");
        assert_eq!(
            rec.records()[0].command,
            format!("run {PLACEHOLDER}"),
            "{by:?}"
        );
    }
}

#[test]
fn a_secret_that_itself_holds_a_hostile_char_is_redacted_in_the_output() {
    for by in HOSTILE_SAMPLES {
        let (redactor, secret) = secret_holding(by);
        let mut rec = ShellRecorder::new(redactor);
        rec.record(&input("x", &format!("got {secret}")))
            .expect("record");
        assert_eq!(
            rec.records()[0].output,
            format!("got {PLACEHOLDER}"),
            "{by:?}"
        );
    }
}

#[test]
fn every_hostile_sample_is_stripped_from_command_and_output() {
    for by in HOSTILE_SAMPLES {
        let mut rec = ShellRecorder::new(redactor());
        rec.record(&input(&format!("a{by}b"), &format!("c{by}d")))
            .expect("record");
        let r = &rec.records()[0];
        assert_eq!(r.command, "ab", "{by:?}");
        assert_eq!(r.output, "cd", "{by:?}");
    }
}
