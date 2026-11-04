//! `fleet timing` arguments, command list and live log printing.

use std::collections::VecDeque;
use std::future::Future;

use clap::Parser;
use fleet_cli::timing::{
    ChunkSource, FOLLOW_DEADLINE, MAX_PRINT_CHUNK_BYTES, MAX_PRINT_TOTAL_BYTES,
    MAX_STREAM_MESSAGES, print_log, write_commands,
};
use fleet_cli::{Cli, CliError, Command};
use fleet_proto::v1::{ShellCommand, ShellStatus, StreamShellLogChunk};
use tonic::{Code, Status};

#[test]
fn the_command_parses_job_commands_and_json() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1", "--commands", "--json"])?;
    let Command::Timing {
        job,
        commands,
        json,
        ..
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

const BAD_ID: &str = "command id must be 1 to 128 characters of letters, digits and _ . : -";

#[test]
fn follow_parses_with_a_command_id_and_json() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1", "--follow", "cmd-1", "--json"])?;
    let shown = format!("{:?}", cli.command);
    assert!(shown.contains("follow: Some(\"cmd-1\")"), "{shown}");
    assert!(shown.contains("json: true"), "{shown}");
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1"])?;
    assert!(format!("{:?}", cli.command).contains("follow: None"));
    Ok(())
}

#[test]
fn follow_needs_a_value() {
    assert!(Cli::try_parse_from(["fleet", "timing", "job-1", "--follow"]).is_err());
}

#[test]
fn follow_and_commands_together_are_refused() {
    let err = Cli::try_parse_from(["fleet", "timing", "job-1", "--follow", "c1", "--commands"])
        .err()
        .map(|e| e.kind());
    assert_eq!(err, Some(clap::error::ErrorKind::ArgumentConflict));
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

fn chunks_before_the_last(count: u32) -> Vec<StreamShellLogChunk> {
    let per = vec![b'y'; MAX_PRINT_CHUNK_BYTES];
    (0..count)
        .map(|seq| chunk(seq, &per, ShellStatus::Running))
        .collect()
}

#[tokio::test]
async fn a_failed_status_survives_a_cut_at_the_total_cap() {
    let full = u32::try_from(MAX_PRINT_TOTAL_BYTES / MAX_PRINT_CHUNK_BYTES).unwrap();
    let per = vec![b'y'; MAX_PRINT_CHUNK_BYTES];
    for (status, failed) in [(ShellStatus::Failed, true), (ShellStatus::Done, false)] {
        let mut chunks = chunks_before_the_last(full - 1);
        chunks.push(chunk(full - 1, &per, status));
        let (result, text) = printed(script(chunks), false).await;
        assert!(text.contains("-- log output cut --"), "{text}");
        assert_eq!(result.is_err(), failed, "{status:?}");
        if failed {
            assert!(matches!(result, Err(CliError::JobEnded("failed"))));
        }
    }
}

#[tokio::test]
async fn a_failed_status_survives_a_mid_chunk_cut() {
    let big = vec![b'y'; MAX_PRINT_CHUNK_BYTES + 100];
    for (status, failed) in [(ShellStatus::Failed, true), (ShellStatus::Done, false)] {
        let (result, text) = printed(script(vec![chunk(0, &big, status)]), false).await;
        assert!(text.contains("-- log output cut --"), "{text}");
        assert_eq!(result.is_err(), failed, "{status:?}");
        if failed {
            assert!(matches!(result, Err(CliError::JobEnded("failed"))));
        }
    }
}

fn at_the_byte_cap_then(tail: Vec<StreamShellLogChunk>) -> Vec<StreamShellLogChunk> {
    let full = u32::try_from(MAX_PRINT_TOTAL_BYTES / MAX_PRINT_CHUNK_BYTES).unwrap_or_default();
    let mut chunks = chunks_before_the_last(full);
    chunks.extend(tail);
    chunks
}

#[tokio::test]
async fn a_failed_status_after_a_cut_on_a_running_chunk_is_kept() {
    let (result, text) = printed(
        script(at_the_byte_cap_then(vec![
            chunk(0, b"ignored\n", ShellStatus::Running),
            chunk(0, b"", ShellStatus::Failed),
        ])),
        false,
    )
    .await;
    assert!(text.contains("-- log output cut --"), "{text}");
    assert!(!text.contains("ignored"), "{text}");
    assert!(
        matches!(result, Err(CliError::JobEnded("failed"))),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_done_status_after_a_cut_is_ok() {
    let (result, text) = printed(
        script(at_the_byte_cap_then(vec![
            chunk(0, b"", ShellStatus::Running),
            chunk(0, b"", ShellStatus::Done),
        ])),
        false,
    )
    .await;
    assert!(text.contains("-- log output cut --"), "{text}");
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn a_failed_status_after_status_only_messages_past_a_cut_is_kept() {
    let mut tail: Vec<_> = (0..100)
        .map(|_| chunk(0, b"", ShellStatus::Running))
        .collect();
    tail.push(chunk(1, b"", ShellStatus::Failed));
    let (result, text) = printed(script(at_the_byte_cap_then(tail)), false).await;
    assert!(text.contains("-- log output cut --"), "{text}");
    assert!(
        matches!(result, Err(CliError::JobEnded("failed"))),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_failed_status_on_the_message_that_trips_the_cap_is_kept() {
    let mut chunks = vec![chunk(0, b"a\n", ShellStatus::Running)];
    chunks.extend((0..MAX_STREAM_MESSAGES - 1).map(|_| chunk(0, b"", ShellStatus::Running)));
    chunks.push(chunk(1, b"", ShellStatus::Failed));
    let (result, text) = printed(script(chunks), false).await;
    assert!(text.contains("-- log output cut --"), "{text}");
    assert!(
        matches!(result, Err(CliError::JobEnded("failed"))),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_terminal_status_past_the_drain_bound_is_unknown() {
    let mut chunks = vec![chunk(0, b"a\n", ShellStatus::Running)];
    chunks.extend((0..MAX_STREAM_MESSAGES).map(|_| chunk(0, b"", ShellStatus::Running)));
    chunks.push(chunk(1, b"", ShellStatus::Failed));
    let (result, text) = printed(script(chunks), false).await;
    assert!(text.contains("-- log output cut --"), "{text}");
    assert!(
        matches!(result, Err(CliError::JobEnded("status unknown"))),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_cut_followed_by_stream_end_has_unknown_status() {
    let (result, text) = printed(
        script(at_the_byte_cap_then(vec![chunk(
            0,
            b"",
            ShellStatus::Running,
        )])),
        false,
    )
    .await;
    assert!(text.contains("-- log output cut --"), "{text}");
    assert!(
        matches!(result, Err(CliError::JobEnded("status unknown"))),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_stream_ending_without_a_cut_or_terminal_status_is_unknown() {
    let (result, text) = printed(
        script(vec![
            chunk(0, b"one\n", ShellStatus::Running),
            chunk(1, b"two\n", ShellStatus::Running),
        ]),
        false,
    )
    .await;
    assert!(
        matches!(result, Err(CliError::JobEnded("status unknown"))),
        "{result:?}"
    );
    assert_eq!(text, "one\ntwo\n");
}

#[tokio::test]
async fn a_stream_of_only_foreign_chunks_is_unknown() {
    let mut other = chunk(0, b"intruder\n", ShellStatus::Done);
    other.command_id = "c2".into();
    let (result, text) = printed(script(vec![other]), false).await;
    assert!(
        matches!(result, Err(CliError::JobEnded("status unknown"))),
        "{result:?}"
    );
    assert_eq!(text, "");
}

#[tokio::test]
async fn an_empty_stream_is_unknown() {
    let (result, _) = printed(script(vec![]), false).await;
    assert!(
        matches!(result, Err(CliError::JobEnded("status unknown"))),
        "{result:?}"
    );
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
    assert!(
        matches!(result, Err(CliError::JobEnded("timed out"))),
        "{result:?}"
    );
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

mod served {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use clap::Parser;
    use fleet_cli::{Cli, CliError, run};
    use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
    use fleet_proto::v1::{
        CancelJobRequest, GetJobRequest, GetJobTimingReply, GetJobTimingRequest, GetStatsReply,
        GetStatsRequest, Job, ListJobsReply, ListJobsRequest, ReadJobEventsReply,
        ReadJobEventsRequest, ReadTranscriptReply, ReadTranscriptRequest, ShellCommand,
        ShellStatus, StreamShellLogChunk, StreamShellLogRequest, SubmitJobRequest, TimingSummary,
    };
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TOKEN: &str = "client-token-0123456789";

    #[derive(Default, Clone)]
    struct Stub {
        chunks: Vec<StreamShellLogChunk>,
        commands: Vec<ShellCommand>,
        summary: Option<TimingSummary>,
        refuse: Option<tonic::Code>,
        follows: Arc<Mutex<Vec<StreamShellLogRequest>>>,
    }

    fn unused<T>() -> Result<Response<T>, Status> {
        Err(Status::unimplemented("not used"))
    }

    #[tonic::async_trait]
    impl FleetJobs for Stub {
        async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
            unused()
        }
        async fn get_job(&self, _: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
            unused()
        }
        async fn list_jobs(
            &self,
            _: Request<ListJobsRequest>,
        ) -> Result<Response<ListJobsReply>, Status> {
            unused()
        }
        async fn cancel_job(&self, _: Request<CancelJobRequest>) -> Result<Response<Job>, Status> {
            unused()
        }
        async fn read_transcript(
            &self,
            _: Request<ReadTranscriptRequest>,
        ) -> Result<Response<ReadTranscriptReply>, Status> {
            unused()
        }
        async fn read_job_events(
            &self,
            _: Request<ReadJobEventsRequest>,
        ) -> Result<Response<ReadJobEventsReply>, Status> {
            unused()
        }
        async fn get_stats(
            &self,
            _: Request<GetStatsRequest>,
        ) -> Result<Response<GetStatsReply>, Status> {
            unused()
        }

        type StreamShellLogStream = tonic::codegen::BoxStream<StreamShellLogChunk>;

        async fn stream_shell_log(
            &self,
            request: Request<StreamShellLogRequest>,
        ) -> Result<Response<Self::StreamShellLogStream>, Status> {
            self.follows
                .lock()
                .map_err(|_| Status::internal("poisoned"))?
                .push(request.into_inner());
            let items: Vec<Result<StreamShellLogChunk, Status>> =
                self.chunks.iter().cloned().map(Ok).collect();
            Ok(Response::new(Box::pin(tokio_stream::iter(items))))
        }

        async fn get_job_timing(
            &self,
            _: Request<GetJobTimingRequest>,
        ) -> Result<Response<GetJobTimingReply>, Status> {
            if let Some(code) = self.refuse {
                return Err(Status::new(code, "job not found"));
            }
            Ok(Response::new(GetJobTimingReply {
                shell_commands: self.commands.clone(),
                summary: self.summary,
                ..GetJobTimingReply::default()
            }))
        }
    }

    async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetJobsServer::new(stub))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        Ok(url)
    }

    async fn cli(url: &str, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut full = vec!["fleet", "--server", url];
        full.extend_from_slice(args);
        let Ok(parsed) = Cli::try_parse_from(full) else {
            return (Err(CliError::Usage("parse".into())), String::new());
        };
        let mut out = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run(
                parsed,
                |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
                &mut &b""[..],
                &mut out,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(CliError::Usage("timed out".into())));
        (result, String::from_utf8_lossy(&out).into_owned())
    }

    fn chunk(seq: u32, bytes: &[u8], status: ShellStatus) -> StreamShellLogChunk {
        StreamShellLogChunk {
            command_id: "cmd-1".to_owned(),
            seq,
            bytes: bytes.to_vec(),
            status: status as i32,
        }
    }

    #[tokio::test]
    async fn follow_streams_the_log_until_done() -> TestResult {
        let stub = Stub {
            chunks: vec![
                chunk(0, b"one\n", ShellStatus::Running),
                chunk(1, b"two\n", ShellStatus::Done),
            ],
            ..Stub::default()
        };
        let follows = stub.follows.clone();
        let url = serve(stub).await?;
        let (result, text) = cli(&url, &["timing", "job-1", "--follow", "cmd-1"]).await;
        result?;
        assert_eq!(text, "one\ntwo\n");
        let seen = follows.lock().map_err(|_| "poisoned")?.clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].job_id, "job-1");
        assert_eq!(seen[0].command_id, "cmd-1");
        Ok(())
    }

    #[tokio::test]
    async fn follow_json_prints_one_object_per_chunk() -> TestResult {
        let stub = Stub {
            chunks: vec![chunk(0, b"hi", ShellStatus::Done)],
            ..Stub::default()
        };
        let url = serve(stub).await?;
        let (result, text) = cli(&url, &["timing", "job-1", "--follow", "cmd-1", "--json"]).await;
        result?;
        assert_eq!(
            text,
            "{\"command_id\":\"cmd-1\",\"seq\":0,\"status\":\"done\",\"text\":\"hi\"}\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_command_ends_the_follow_with_an_error() -> TestResult {
        let stub = Stub {
            chunks: vec![chunk(0, b"boom\n", ShellStatus::Failed)],
            ..Stub::default()
        };
        let url = serve(stub).await?;
        let (result, text) = cli(&url, &["timing", "job-1", "--follow", "cmd-1"]).await;
        assert!(
            matches!(result, Err(CliError::JobEnded("failed"))),
            "{result:?}"
        );
        assert_eq!(text, "boom\n");
        Ok(())
    }

    #[tokio::test]
    async fn commands_lists_the_status_rows_and_json() -> TestResult {
        let stub = Stub {
            commands: vec![ShellCommand {
                id: "cmd-1".to_owned(),
                command: "make test".to_owned(),
                ended_ms: Some(9),
                exit_code: Some(0),
                duration_ms: 7,
                ..ShellCommand::default()
            }],
            ..Stub::default()
        };
        let url = serve(stub).await?;
        let (result, text) = cli(&url, &["timing", "job-1", "--commands"]).await;
        result?;
        assert_eq!(text, "cmd-1\tdone\t0\t7ms\tfg\tmake test\n");
        let (result, text) = cli(&url, &["timing", "job-1", "--commands", "--json"]).await;
        result?;
        assert_eq!(
            text,
            "{\"id\":\"cmd-1\",\"status\":\"done\",\"exit_code\":0,\"duration_ms\":7,\"background\":false,\"command\":\"make test\"}\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_bad_command_id_is_refused_with_the_fixed_error() -> TestResult {
        let url = serve(Stub::default()).await?;
        for bad in ["bad id", "a/b", "x\u{1b}y", &"a".repeat(129)] {
            let (result, text) = cli(&url, &["timing", "job-1", "--follow", bad]).await;
            let Err(CliError::Usage(message)) = result else {
                panic!("expected a usage error for {bad:?}, got {result:?}");
            };
            assert_eq!(message, super::BAD_ID);
            assert_eq!(text, "");
        }
        Ok(())
    }

    async fn run_no_token(url: &str, args: &[&str]) -> Result<(), CliError> {
        let mut full = vec!["fleet", "--server", url];
        full.extend_from_slice(args);
        let Ok(parsed) = Cli::try_parse_from(full) else {
            return Err(CliError::Usage("parse".into()));
        };
        let mut out = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            run(parsed, |_| None, &mut &b""[..], &mut out),
        )
        .await
        .unwrap_or_else(|_| Err(CliError::Usage("timed out".into())))
    }

    #[tokio::test]
    async fn a_bad_id_is_refused_before_any_connection_or_token_check() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = accepts.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let result = run_no_token(&url, &["timing", "job-1", "--follow", "bad id"]).await;
        let Err(CliError::Usage(message)) = result else {
            panic!("expected the usage error, got {result:?}");
        };
        assert_eq!(message, super::BAD_ID);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn the_plain_summary_needs_a_token() -> TestResult {
        let result = run_no_token("http://127.0.0.1:1", &["timing", "job-1"]).await;
        let Err(err @ CliError::Config(_)) = result else {
            panic!("expected a config error, got {result:?}");
        };
        assert_eq!(err.exit_code(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_chunk_number_past_the_cap_refuses_the_stream() -> TestResult {
        let stub = Stub {
            chunks: vec![chunk(u32::MAX, b"x", ShellStatus::Running)],
            ..Stub::default()
        };
        let url = serve(stub).await?;
        let (result, text) = cli(&url, &["timing", "job-1", "--follow", "cmd-1"]).await;
        let Err(CliError::Rpc(status)) = result else {
            panic!("expected an rpc error, got {result:?}");
        };
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), "log stream sent an invalid chunk number");
        assert_eq!(text, "");
        Ok(())
    }

    fn summary(parts: [u64; 5]) -> TimingSummary {
        TimingSummary {
            wall_ms: 0,
            api_wait_ms: parts[0],
            tool_ms: parts[1],
            shell_ms: parts[2],
            idle_ms: parts[3],
            overhead_ms: parts[4],
        }
    }

    async fn plain(
        summary: Option<TimingSummary>,
        args: &[&str],
    ) -> Result<(Result<(), CliError>, String), Box<dyn std::error::Error>> {
        let url = serve(Stub {
            summary,
            ..Stub::default()
        })
        .await?;
        let mut full = vec!["timing", "job-1"];
        full.extend_from_slice(args);
        Ok(cli(&url, &full).await)
    }

    #[tokio::test]
    async fn the_summary_prints_five_parts_and_shares_in_job_relative_ms() -> TestResult {
        let (result, text) = plain(Some(summary([1000, 2000, 3000, 1000, 3000])), &[]).await?;
        result?;
        assert_eq!(
            text,
            "job: job-1\nunit: ms, job-relative (0 is the claim)\nAPI wait\t1000ms\t10.0%\nTools\t2000ms\t20.0%\nShell\t3000ms\t30.0%\nIdle\t1000ms\t10.0%\nOverhead\t3000ms\t30.0%\nTotal\t10000ms\t100.0%\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn shares_sum_to_one_hundred_percent_when_parts_do_not_divide() -> TestResult {
        let (result, text) = plain(Some(summary([1, 1, 1, 0, 0])), &[]).await?;
        result?;
        assert!(text.contains("API wait\t1ms\t33.4%\n"), "{text}");
        assert!(text.contains("Tools\t1ms\t33.3%\n"), "{text}");
        assert!(text.contains("Shell\t1ms\t33.3%\n"), "{text}");
        assert!(text.ends_with("Total\t3ms\t100.0%\n"), "{text}");
        Ok(())
    }

    #[tokio::test]
    async fn a_zero_wall_prints_zero_shares_and_no_division() -> TestResult {
        let (result, text) = plain(Some(summary([0; 5])), &[]).await?;
        result?;
        assert_eq!(text.matches("0ms\t0.0%\n").count(), 6, "{text}");
        assert!(!text.contains("NaN") && !text.contains("100.0%"), "{text}");
        Ok(())
    }

    #[tokio::test]
    async fn the_largest_parts_print_without_overflow() -> TestResult {
        let (result, text) = plain(Some(summary([u64::MAX; 5])), &[]).await?;
        result?;
        assert!(
            text.contains("API wait\t18446744073709551615ms\t20.0%\n"),
            "{text}"
        );
        assert!(
            text.ends_with("Total\t18446744073709551615ms\t100.0%\n"),
            "{text}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn json_carries_unit_total_and_the_five_parts() -> TestResult {
        let (result, text) =
            plain(Some(summary([1000, 2000, 3000, 1000, 3000])), &["--json"]).await?;
        result?;
        assert_eq!(
            text,
            "{\"unit\":\"ms\",\"job\":\"job-1\",\"total_ms\":10000,\"parts\":[{\"key\":\"api_wait\",\"ms\":1000,\"permille\":100},{\"key\":\"tool\",\"ms\":2000,\"permille\":200},{\"key\":\"shell\",\"ms\":3000,\"permille\":300},{\"key\":\"idle\",\"ms\":1000,\"permille\":100},{\"key\":\"overhead\",\"ms\":3000,\"permille\":300}]}\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_absent_report_exits_three_and_prints_nothing() -> TestResult {
        let (result, text) = plain(None, &[]).await?;
        let Err(err @ CliError::NoTimingReport) = result else {
            panic!("expected no timing report, got {result:?}");
        };
        assert_eq!(err.exit_code(), 3);
        assert_eq!(err.to_string(), "no timing report for this job");
        assert_eq!(text, "");
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_job_is_an_rpc_not_found_that_exits_one() -> TestResult {
        let url = serve(Stub {
            refuse: Some(tonic::Code::NotFound),
            ..Stub::default()
        })
        .await?;
        let (result, text) = cli(&url, &["timing", "job-1"]).await;
        let Err(err @ CliError::Rpc(_)) = result else {
            panic!("expected an rpc error, got {result:?}");
        };
        assert_eq!(err.exit_code(), 1);
        assert_eq!(text, "");
        Ok(())
    }

    #[tokio::test]
    async fn the_echoed_job_id_loses_control_and_bidi_characters() -> TestResult {
        let url = serve(Stub {
            summary: Some(summary([1, 0, 0, 0, 0])),
            ..Stub::default()
        })
        .await?;
        let hostile = "j\u{1b}[31m\u{202e}\r\u{2028}x";
        for args in [&["timing", hostile][..], &["timing", hostile, "--json"][..]] {
            let (result, text) = cli(&url, args).await;
            result?;
            assert!(text.contains("j[31mx"), "{text:?}");
            assert!(
                !text
                    .chars()
                    .any(|c| matches!(c, '\u{1b}' | '\u{202e}' | '\r' | '\u{2028}')),
                "{text:?}"
            );
        }
        Ok(())
    }
}
