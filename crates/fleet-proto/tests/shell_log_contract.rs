//! The live shell log contract: status values, the shared chunk caps, the validators and the
//! migration that backs them.

use fleet_proto::v1::ShellStatus;
use fleet_proto::{
    MAX_COMMAND_ID_BYTES, MAX_SHELL_LOG_CHUNK_BYTES, MAX_SHELL_LOG_CHUNKS, shell_status_name,
    validate_shell_log_bytes, validate_shell_log_command_id, validate_shell_log_seq,
    validate_shell_log_status,
};

const MIGRATION: &str = include_str!("../../fleet-server/migrations/0025_job_shell_log_chunks.sql");
const PROTO: &str = include_str!("../proto/fleet/v1/fleet.proto");

#[test]
fn status_values_are_pinned() {
    assert_eq!(ShellStatus::Unspecified as i32, 0);
    assert_eq!(ShellStatus::Queued as i32, 1);
    assert_eq!(ShellStatus::Running as i32, 2);
    assert_eq!(ShellStatus::Done as i32, 3);
    assert_eq!(ShellStatus::Failed as i32, 4);
}

#[test]
fn caps_have_their_documented_values() {
    assert_eq!(MAX_SHELL_LOG_CHUNK_BYTES, 4096);
    assert_eq!(MAX_SHELL_LOG_CHUNKS, 64);
    assert_eq!(MAX_COMMAND_ID_BYTES, 128);
    const { assert!(MAX_SHELL_LOG_CHUNK_BYTES <= fleet_proto::MAX_SHELL_LOG_BYTES) };
}

#[test]
fn migration_literals_equal_the_consts() {
    let bytes = format!("octet_length(bytes) <= {MAX_SHELL_LOG_CHUNK_BYTES}");
    assert!(MIGRATION.contains(&bytes), "bytes check");
    let seq = format!("seq BETWEEN 0 AND {}", MAX_SHELL_LOG_CHUNKS - 1);
    assert!(MIGRATION.contains(&seq), "seq check");
    let id = format!("{{1,{MAX_COMMAND_ID_BYTES}}}$");
    assert!(MIGRATION.contains(&id), "command_id check");
}

#[test]
fn migration_status_names_match_the_enum() {
    let all = [
        ShellStatus::Queued,
        ShellStatus::Running,
        ShellStatus::Done,
        ShellStatus::Failed,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|s| shell_status_name(*s).unwrap_or(""))
        .collect();
    assert_eq!(names, ["queued", "running", "done", "failed"]);
    let list = names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        MIGRATION.contains(&format!("status IN ({list})")),
        "status check"
    );
    assert_eq!(shell_status_name(ShellStatus::Unspecified), None);
}

#[test]
fn migration_cascades_and_keys_on_job_command_seq() {
    assert!(MIGRATION.contains("REFERENCES jobs (job_id) ON DELETE CASCADE"));
    assert!(MIGRATION.contains("PRIMARY KEY (job_id, command_id, seq)"));
}

#[test]
fn rpcs_sit_in_the_documented_services() {
    let worker = PROTO
        .split("service FleetWorker {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .unwrap_or("");
    assert!(
        worker.contains("rpc ReportShellLog(ReportShellLogRequest) returns (ReportShellLogReply);")
    );
    let jobs = PROTO
        .split("service FleetJobs {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .unwrap_or("");
    assert!(jobs.contains(
        "rpc StreamShellLog(StreamShellLogRequest) returns (stream StreamShellLogChunk);"
    ));
}

#[test]
fn command_id_hostile_table() {
    let long = "a".repeat(MAX_COMMAND_ID_BYTES + 1);
    let hostile: [&str; 24] = [
        "",
        "a\n",
        "\na",
        "a\r\n",
        "a\r",
        "a\u{85}",
        "a\u{2028}",
        "a\u{2029}",
        "a b",
        " a",
        "a ",
        "a\tb",
        "a\0",
        "a/b",
        "a\\b",
        "a@b",
        "http://u@h",
        "[::1]",
        "a;b",
        "a%2fb",
        "\u{e9}",
        "a\u{202e}b",
        "\u{ff21}",
        &long,
    ];
    for id in hostile {
        assert!(!validate_shell_log_command_id(id), "{id:?}");
    }
}

#[test]
fn command_id_accepts_the_tool_use_and_pueue_shapes() {
    let longest = "a".repeat(MAX_COMMAND_ID_BYTES);
    for id in ["a", "toolu_01AbC", "bg-17", "a.b:c-d_e", "A", "0", &longest] {
        assert!(validate_shell_log_command_id(id), "{id:?}");
    }
}

#[test]
fn seq_bounds() {
    let max = u32::try_from(MAX_SHELL_LOG_CHUNKS).unwrap_or(0);
    assert!(validate_shell_log_seq(0));
    assert!(validate_shell_log_seq(max - 1));
    assert!(!validate_shell_log_seq(max));
    assert!(!validate_shell_log_seq(u32::MAX));
    assert!(!validate_shell_log_seq(i32::MAX as u32));
}

#[test]
fn bytes_bounds_allow_a_status_only_chunk() {
    assert!(validate_shell_log_bytes(&[]));
    assert!(validate_shell_log_bytes(&[0xff]));
    assert!(validate_shell_log_bytes(&vec![
        b'x';
        MAX_SHELL_LOG_CHUNK_BYTES
    ]));
    assert!(!validate_shell_log_bytes(&vec![
        b'x';
        MAX_SHELL_LOG_CHUNK_BYTES
            + 1
    ]));
}

#[test]
fn status_from_the_wire_rejects_unspecified_and_unknown() {
    assert_eq!(validate_shell_log_status(1), Some(ShellStatus::Queued));
    assert_eq!(validate_shell_log_status(4), Some(ShellStatus::Failed));
    for bad in [0, 5, -1, i32::MAX, i32::MIN] {
        assert_eq!(validate_shell_log_status(bad), None, "{bad}");
    }
}
