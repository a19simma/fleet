//! Shell command records: redaction before truncation, NUL handling, caps.

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
