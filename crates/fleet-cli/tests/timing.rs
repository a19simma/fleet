//! `fleet timing` arguments, command list and live log printing.

use std::collections::VecDeque;
use std::future::Future;

use clap::Parser;
use fleet_cli::timing::{
    ChunkSource, FOLLOW_DEADLINE, MAX_PRINT_CHUNK_BYTES, MAX_PRINT_TOTAL_BYTES, print_log,
    write_commands,
};
use fleet_cli::{Cli, CliError, Command, run};
use fleet_proto::v1::{ShellCommand, ShellStatus, StreamShellLogChunk};
use tonic::{Code, Status};

async fn invoke(args: &[&str]) -> Result<(), CliError> {
    let mut full = vec!["fleet", "--server", "http://127.0.0.1:1"];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).map_err(|err| CliError::Usage(err.to_string()))?;
    run(parsed, |_| None, &mut b"".as_slice(), &mut Vec::new()).await
}

#[test]
fn the_command_parses_job_commands_and_json() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1", "--commands", "--json"])?;
    let Command::Timing {
        job,
        commands,
        json,
    } = cli.command
    else {
        return Err(clap::Error::new(clap::error::ErrorKind::InvalidValue));
    };
    assert_eq!(job, "job-1");
    assert!(commands);
    assert!(json);
    Ok(())
}

#[test]
fn the_flags_default_off() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1"])?;
    let Command::Timing { commands, json, .. } = cli.command else {
        return Err(clap::Error::new(clap::error::ErrorKind::InvalidValue));
    };
    assert!(!commands);
    assert!(!json);
    Ok(())
}

#[test]
fn the_job_is_required() {
    assert!(Cli::try_parse_from(["fleet", "timing"]).is_err());
}

#[tokio::test]
async fn running_it_returns_a_not_implemented_error() {
    let result = invoke(&["timing", "job-1"]).await;
    let Err(CliError::Rpc(status)) = result else {
        panic!("expected an rpc error, got {result:?}");
    };
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(
        CliError::Rpc(status).exit_code(),
        1,
        "a runtime failure, not a usage error"
    );
}

struct Script(VecDeque<Result<Option<StreamShellLogChunk>, Status>>);

impl ChunkSource for Script {
    fn next_chunk(
        &mut self,
    ) -> impl Future<Output = Result<Option<StreamShellLogChunk>, Status>> + Send {
        let next = self.0.pop_front().unwrap_or(Ok(None));
        async move { next }
    }
}

fn chunk(seq: u32, bytes: &[u8], status: ShellStatus) -> StreamShellLogChunk {
    StreamShellLogChunk {
        command_id: "c1".into(),
        seq,
        bytes: bytes.to_vec(),
        status: status as i32,
    }
}

fn script(chunks: Vec<StreamShellLogChunk>) -> Script {
    Script(chunks.into_iter().map(|c| Ok(Some(c))).collect())
}

async fn printed(mut source: Script, json: bool) -> (Result<(), CliError>, String) {
    let mut out = Vec::new();
    let result = print_log(&mut source, "c1", json, &mut out).await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn chunks_print_in_order_until_done() {
    let (result, text) = printed(
        script(vec![
            chunk(0, b"one\n", ShellStatus::Running),
            chunk(1, b"two\n", ShellStatus::Running),
            chunk(2, b"", ShellStatus::Done),
            chunk(3, b"after\n", ShellStatus::Running),
        ]),
        false,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(text, "one\ntwo\n");
}

#[tokio::test]
async fn a_failed_status_ends_the_follow_with_an_error() {
    let (result, text) = printed(
        script(vec![chunk(0, b"boom\n", ShellStatus::Failed)]),
        false,
    )
    .await;
    assert!(matches!(result, Err(CliError::JobEnded("failed"))));
    assert_eq!(text, "boom\n");
}

#[tokio::test]
async fn escape_and_carriage_return_never_reach_the_output() {
    let (_, text) = printed(
        script(vec![chunk(
            0,
            b"a\x1b[31mred\x1b]0;title\x07\rb\x00\tc\xe2\x80\xaed\n",
            ShellStatus::Done,
        )]),
        false,
    )
    .await;
    assert_eq!(text, "a[31mred]0;titleb\tcd\n");
}

#[tokio::test]
async fn a_multibyte_char_split_across_chunks_survives() {
    let bytes = "h\u{e9}llo\n".as_bytes();
    let (first, second) = bytes.split_at(2);
    let (_, text) = printed(
        script(vec![
            chunk(0, first, ShellStatus::Running),
            chunk(1, second, ShellStatus::Done),
        ]),
        false,
    )
    .await;
    assert_eq!(text, "h\u{e9}llo\n");
}

#[tokio::test]
async fn a_repeated_or_lower_seq_prints_once() {
    let (_, text) = printed(
        script(vec![
            chunk(0, b"a\n", ShellStatus::Running),
            chunk(0, b"a\n", ShellStatus::Running),
            chunk(1, b"b\n", ShellStatus::Running),
            chunk(0, b"late\n", ShellStatus::Running),
        ]),
        false,
    )
    .await;
    assert_eq!(text, "a\nb\n");
}

#[tokio::test]
async fn an_oversize_chunk_is_cut_with_a_marker() {
    let big = vec![b'x'; MAX_PRINT_CHUNK_BYTES + 100];
    let (_, text) = printed(script(vec![chunk(0, &big, ShellStatus::Running)]), false).await;
    assert!(text.starts_with(&"x".repeat(MAX_PRINT_CHUNK_BYTES)));
    assert!(!text.starts_with(&"x".repeat(MAX_PRINT_CHUNK_BYTES + 1)));
    assert!(text.contains("-- log output cut --"), "{text}");
}

#[tokio::test]
async fn the_total_is_capped_and_the_stream_dropped() {
    let per = vec![b'y'; MAX_PRINT_CHUNK_BYTES];
    let count = u32::try_from(MAX_PRINT_TOTAL_BYTES / MAX_PRINT_CHUNK_BYTES + 5).unwrap();
    let chunks = (0..count)
        .map(|seq| chunk(seq, &per, ShellStatus::Running))
        .collect();
    let (_, text) = printed(script(chunks), false).await;
    assert!(text.contains("-- log output cut --"));
    let ys = text.bytes().filter(|b| *b == b'y').count();
    assert_eq!(ys, MAX_PRINT_TOTAL_BYTES);
}

#[tokio::test]
async fn a_stream_error_is_returned() {
    let mut source = Script(VecDeque::from([
        Ok(Some(chunk(0, b"a\n", ShellStatus::Running))),
        Err(Status::not_found("no such job")),
    ]));
    let mut out = Vec::new();
    let result = print_log(&mut source, "c1", false, &mut out).await;
    let Err(CliError::Rpc(status)) = result else {
        panic!("expected an rpc error, got {result:?}");
    };
    assert_eq!(status.code(), Code::NotFound);
}

#[tokio::test]
async fn another_commands_chunks_are_ignored() {
    let mut other = chunk(0, b"intruder\n", ShellStatus::Done);
    other.command_id = "c2".into();
    let (_, text) = printed(
        script(vec![other, chunk(0, b"mine\n", ShellStatus::Done)]),
        false,
    )
    .await;
    assert_eq!(text, "mine\n");
}

#[tokio::test]
async fn json_prints_one_object_per_chunk() {
    let (_, text) = printed(
        script(vec![
            chunk(0, b"a\"b\x1b\n", ShellStatus::Running),
            chunk(1, b"z", ShellStatus::Done),
        ]),
        true,
    )
    .await;
    assert_eq!(
        text,
        "{\"command_id\":\"c1\",\"seq\":0,\"status\":\"running\",\"text\":\"a\\\"b\\n\"}\n\
         {\"command_id\":\"c1\",\"seq\":1,\"status\":\"done\",\"text\":\"z\"}\n"
    );
}

#[tokio::test(start_paused = true)]
async fn a_silent_stream_stops_at_the_deadline() {
    struct Silent;
    impl ChunkSource for Silent {
        fn next_chunk(
            &mut self,
        ) -> impl Future<Output = Result<Option<StreamShellLogChunk>, Status>> + Send {
            std::future::pending()
        }
    }
    let mut out = Vec::new();
    let started = tokio::time::Instant::now();
    let result = print_log(&mut Silent, "c1", false, &mut out).await;
    assert!(result.is_ok());
    assert!(started.elapsed() >= FOLLOW_DEADLINE);
    assert!(String::from_utf8_lossy(&out).contains("time limit"));
}

fn command(id: &str, ended: Option<u64>, exit: Option<i32>) -> ShellCommand {
    ShellCommand {
        id: id.into(),
        command: "make \u{1b}[2Jtest".into(),
        background: ended.is_none(),
        started_ms: 1,
        ended_ms: ended,
        duration_ms: 1500,
        exit_code: exit,
        ..ShellCommand::default()
    }
}

#[test]
fn the_status_list_shows_running_done_and_failed_rows() {
    let mut out = Vec::new();
    write_commands(
        &mut out,
        &[
            command("a", None, None),
            command("b", Some(9), Some(0)),
            command("c", Some(9), Some(2)),
        ],
        false,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "a\trunning\t-\t1500ms\tbg\tmake [2Jtest\n\
         b\tdone\t0\t1500ms\tfg\tmake [2Jtest\n\
         c\tfailed\t2\t1500ms\tfg\tmake [2Jtest\n"
    );
}

#[test]
fn the_status_list_json_is_one_object_per_command() {
    let mut out = Vec::new();
    write_commands(&mut out, &[command("a", None, None)], true).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "{\"id\":\"a\",\"status\":\"running\",\"exit_code\":null,\"duration_ms\":1500,\"background\":true,\"command\":\"make [2Jtest\"}\n"
    );
}
