//! `fleet timing` arguments, command list and live log printing.

use std::collections::VecDeque;
use std::future::Future;

use clap::Parser;
use fleet_cli::timing::{
    ChunkSource, FOLLOW_DEADLINE, MAX_PRINT_CHUNK_BYTES, MAX_PRINT_TOTAL_BYTES, print_log,
    write_commands,
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
        ShellStatus, StreamShellLogChunk, StreamShellLogRequest, SubmitJobRequest,
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
            Ok(Response::new(GetJobTimingReply {
                shell_commands: self.commands.clone(),
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

    #[tokio::test]
    async fn the_plain_summary_is_still_not_implemented() -> TestResult {
        let url = serve(Stub::default()).await?;
        let (result, _) = cli(&url, &["timing", "job-1"]).await;
        let Err(CliError::Rpc(status)) = result else {
            panic!("expected an rpc error, got {result:?}");
        };
        assert_eq!(status.code(), tonic::Code::Unimplemented);
        assert_eq!(CliError::Rpc(status).exit_code(), 1);
        Ok(())
    }
}
