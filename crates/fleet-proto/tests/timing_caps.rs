//! The timing caps fleetd and the server share, pinned against the migration that enforces them.

use fleet_proto::{
    MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SPANS, MAX_TIMING_NAME_BYTES,
};

const MIGRATION: &str = include_str!("../../fleet-server/migrations/0022_job_timing.sql");

#[test]
fn the_caps_have_their_documented_values() {
    assert_eq!(MAX_SPANS, 4096);
    assert_eq!(MAX_SHELL_COMMANDS, 256);
    assert_eq!(MAX_SHELL_LOG_BYTES, 16 * 1024);
    assert_eq!(MAX_COMMAND_BYTES, 2048);
    assert_eq!(MAX_TIMING_NAME_BYTES, 128);
}

#[test]
fn max_spans_matches_the_span_seq_check() {
    assert!(
        MIGRATION.contains(&format!("seq BETWEEN 0 AND {}", MAX_SPANS - 1)),
        "span seq check"
    );
}

#[test]
fn max_shell_commands_matches_the_shell_seq_check() {
    assert!(
        MIGRATION.contains(&format!("seq BETWEEN 0 AND {}", MAX_SHELL_COMMANDS - 1)),
        "shell seq check"
    );
}

#[test]
fn max_shell_log_bytes_matches_the_log_check() {
    assert!(
        MIGRATION.contains(&format!("octet_length(log) <= {MAX_SHELL_LOG_BYTES}")),
        "log check"
    );
}

#[test]
fn max_command_bytes_matches_the_command_check() {
    assert!(
        MIGRATION.contains(&format!(
            "octet_length(command) BETWEEN 1 AND {MAX_COMMAND_BYTES}"
        )),
        "command check"
    );
}

#[test]
fn max_timing_name_bytes_matches_every_name_check() {
    for column in ["name", "tool_use_id", "id", "ended_by"] {
        let needle = format!("octet_length({column}) BETWEEN 1 AND {MAX_TIMING_NAME_BYTES}");
        assert!(MIGRATION.contains(&needle), "{column}");
    }
}
