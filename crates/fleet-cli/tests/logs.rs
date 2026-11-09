//! Runs `fleet logs` against an in-process `FleetJobs` stub with scripted transcript replies.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, color_wanted, run_with, run_with_color};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, ListJobsReply, ListJobsRequest,
    ReadTranscriptReply, ReadTranscriptRequest, SubmitJobRequest, TranscriptChunk,
};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Clone)]
struct Stub {
    replies: Arc<Mutex<VecDeque<Result<ReadTranscriptReply, Status>>>>,
    after: Arc<Mutex<Vec<u64>>>,
    end_state: JobState,
}

fn lock<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, Status> {
    m.lock().map_err(|_| Status::internal("poisoned"))
}

fn check(request: &Request<impl Sized>) -> Result<(), Status> {
    let expected = format!("Bearer {TOKEN}");
    match request.metadata().get("authorization") {
        Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(Status::unauthenticated("bad token")),
    }
}

#[tonic::async_trait]
impl FleetJobs for Stub {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_job(&self, request: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        check(&request)?;
        Ok(Response::new(Job {
            job_id: request.into_inner().job_id,
            state: self.end_state as i32,
            ..Job::default()
        }))
    }

    async fn list_jobs(
        &self,
        _: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn cancel_job(&self, _: Request<CancelJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_stats(
        &self,
        _: Request<fleet_proto::v1::GetStatsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetStatsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn read_job_events(
        &self,
        _: Request<fleet_proto::v1::ReadJobEventsRequest>,
    ) -> Result<Response<fleet_proto::v1::ReadJobEventsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn read_transcript(
        &self,
        request: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        check(&request)?;
        lock(&self.after)?.push(request.into_inner().after_seq);
        let next = lock(&self.replies)?.pop_front();
        next.unwrap_or_else(|| Err(Status::failed_precondition("script exhausted")))
            .map(Response::new)
    }

    type StreamShellLogStream = tonic::codegen::BoxStream<fleet_proto::v1::StreamShellLogChunk>;

    async fn stream_shell_log(
        &self,
        _: Request<fleet_proto::v1::StreamShellLogRequest>,
    ) -> Result<Response<Self::StreamShellLogStream>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_job_timing(
        &self,
        _: Request<fleet_proto::v1::GetJobTimingRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobTimingReply>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

fn chunk(seq: u64, text: &str) -> TranscriptChunk {
    TranscriptChunk {
        seq,
        ts_ms: seq,
        text: text.into(),
        truncated: false,
    }
}

type Scripted = Result<ReadTranscriptReply, Status>;

#[expect(
    clippy::unnecessary_wraps,
    reason = "shares the Scripted type with fail"
)]
fn reply(chunks: Vec<TranscriptChunk>, done: bool) -> Scripted {
    Ok(ReadTranscriptReply { chunks, done })
}

fn fail(code: Code) -> Scripted {
    Err(Status::new(code, "scripted"))
}

async fn serve(
    script: Vec<Scripted>,
    end_state: JobState,
) -> Result<(String, Stub), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let stub = Stub {
        replies: Arc::new(Mutex::new(script.into())),
        after: Arc::default(),
        end_state,
    };
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetJobsServer::new(stub.clone()))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok((url, stub))
}

async fn logs(url: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    logs_with(url, args, |name| match name {
        "FLEET_CLIENT_TOKEN" => Some(TOKEN.to_owned()),
        _ => None,
    })
    .await
}

async fn logs_with(
    url: &str,
    args: &[&str],
    lookup: impl Fn(&str) -> Option<String>,
) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url, "logs"];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let mut out = Vec::new();
    let result = run_with(parsed, lookup, false, &mut std::io::empty(), &mut out).await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn after(stub: &Stub) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    Ok(stub.after.lock().map_err(|_| "poisoned")?.clone())
}

#[tokio::test(start_paused = true)]
async fn logs_follow_until_done() -> TestResult {
    let (url, stub) = serve(
        vec![
            reply(vec![chunk(2, "two\n"), chunk(1, "one\n")], false),
            reply(vec![], false),
            reply(vec![chunk(3, "three")], true),
        ],
        JobState::Succeeded,
    )
    .await?;
    let started = Instant::now();
    let (res, out) = logs(&url, &["--raw", "job-1", "-f"]).await;
    res?;
    assert_eq!(out, "one\ntwo\nthree\n");
    assert_eq!(after(&stub)?, vec![0, 2, 2]);
    assert!(started.elapsed() >= Duration::from_secs(1));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_exits_nonzero_when_the_job_did_not_succeed() -> TestResult {
    for state in [JobState::Failed, JobState::Cancelled, JobState::Lost] {
        let (url, _) = serve(vec![reply(vec![chunk(1, "x\n")], true)], state).await?;
        let (res, out) = logs(&url, &["--raw", "job-1", "--follow"]).await;
        let err = res.err().ok_or("expected failure")?;
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().starts_with("job ended"), "{err}");
        assert_eq!(out, "x\n");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn without_follow_it_prints_what_exists_and_stops() -> TestResult {
    let (url, stub) = serve(
        vec![reply(vec![chunk(1, "a\n")], false), reply(vec![], false)],
        JobState::Running,
    )
    .await?;
    let (res, out) = logs(&url, &["--raw", "job-1"]).await;
    res?;
    assert_eq!(out, "a\n");
    assert_eq!(after(&stub)?, vec![0, 1]);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn terminal_escapes_in_chunks_are_stripped_and_truncation_is_marked() -> TestResult {
    let mut marked = chunk(2, "");
    marked.truncated = true;
    let (url, _) = serve(
        vec![reply(
            vec![chunk(1, "\u{1b}[31mred\u{1b}[0m\n"), marked],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["--raw", "job-1"]).await;
    res?;
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.starts_with("[31mred[0m\n"), "{out}");
    assert!(out.ends_with("-- transcript truncated --\n"), "{out}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_retries_transient_statuses_and_keeps_after_seq() -> TestResult {
    for code in [Code::Unavailable, Code::DeadlineExceeded, Code::Aborted] {
        let (url, stub) = serve(
            vec![
                reply(vec![chunk(1, "one\n"), chunk(2, "two\n")], false),
                fail(code),
                fail(code),
                reply(vec![chunk(3, "three\n")], true),
            ],
            JobState::Succeeded,
        )
        .await?;
        let started = Instant::now();
        let (res, out) = logs(&url, &["--raw", "job-1", "-f"]).await;
        res?;
        assert_eq!(out, "one\ntwo\nthree\n", "{code:?}");
        assert_eq!(after(&stub)?, vec![0, 2, 2, 2], "{code:?}");
        assert!(started.elapsed() >= Duration::from_secs(2));
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_does_not_retry_other_statuses() -> TestResult {
    for code in [Code::Unauthenticated, Code::NotFound, Code::Internal] {
        let (url, stub) = serve(
            vec![fail(code), reply(vec![chunk(1, "x\n")], true)],
            JobState::Succeeded,
        )
        .await?;
        let (res, out) = logs(&url, &["--raw", "job-1", "-f"]).await;
        assert!(
            matches!(res, Err(CliError::Rpc(ref s)) if s.code() == code),
            "{code:?}"
        );
        assert_eq!(out, "");
        assert_eq!(after(&stub)?, vec![0], "{code:?}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn retries_are_bounded() -> TestResult {
    let script = (0..20).map(|_| fail(Code::Unavailable)).collect();
    let (url, stub) = serve(script, JobState::Succeeded).await?;
    let (res, _) = logs(&url, &["--raw", "job-1", "-f"]).await;
    assert!(matches!(res, Err(CliError::Rpc(ref s)) if s.code() == Code::Unavailable));
    assert_eq!(after(&stub)?.len(), 5);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn bidi_and_separator_characters_are_stripped_but_newline_and_tab_stay() -> TestResult {
    let (url, _) = serve(
        vec![reply(
            vec![chunk(
                1,
                "a\u{202E}b\u{2028}c\u{2029}d\u{200B}e\u{FEFF}f\tg\n",
            )],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["--raw", "job-1"]).await;
    res?;
    assert_eq!(out, "abcdef\tg\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_transcript_page_above_the_default_decode_limit_is_accepted() -> TestResult {
    let big = "y".repeat(5 * 1024 * 1024);
    let (url, _) = serve(vec![reply(vec![chunk(1, &big)], true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["--raw", "job-1"]).await;
    res?;
    assert_eq!(out.len(), big.len() + 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_file_token_with_the_env_unset_is_redacted_from_logs() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let fleet_dir = dir.path().join("fleet");
    std::fs::create_dir_all(&fleet_dir)?;
    let file = fleet_dir.join("token");
    std::fs::write(&file, format!("{TOKEN}\n"))?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let base = dir.path().display().to_string();
    let (url, _) = serve(
        vec![reply(vec![chunk(1, &format!("key={TOKEN}\n"))], true)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs_with(&url, &["--raw", "job-1", "--follow"], |name| {
        (name == "XDG_CONFIG_HOME").then(|| base.clone())
    })
    .await;
    res?;
    assert_eq!(out, "key=[REDACTED]\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_token_with_zero_width_and_bidi_characters_is_redacted_from_logs() -> TestResult {
    let (url, _) = serve(
        vec![reply(
            vec![chunk(
                1,
                "k=client-\u{200B}token\u{202E}-0123\u{FEFF}456789\u{2028}!\n",
            )],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["--raw", "job-1", "--follow"]).await;
    res?;
    assert_eq!(out, "k=[REDACTED]!\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_token_straddling_chunk_and_page_boundaries_is_redacted() -> TestResult {
    let (url, _) = serve(
        vec![
            reply(vec![chunk(1, "a client-tok"), chunk(2, "en-0123")], false),
            reply(vec![chunk(3, "456789 b\n")], true),
        ],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["--raw", "job-1", "--follow"]).await;
    res?;
    assert!(!out.contains("client-tok"), "{out:?}");
    assert!(out.contains("a "), "{out:?}");
    assert!(out.contains("[REDACTED] b"), "{out:?}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_held_prefix_is_printed_when_the_stream_ends() -> TestResult {
    let (url, _) = serve(
        vec![reply(vec![chunk(1, "tail client-tok")], true)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["--raw", "job-1", "--follow"]).await;
    res?;
    assert_eq!(out, "tail \nclient-tok\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn an_rpc_status_message_carrying_the_token_is_redacted_in_the_error() -> TestResult {
    let (url, _) = serve(
        vec![Err(Status::failed_precondition(format!(
            "bad {TOKEN} here"
        )))],
        JobState::Succeeded,
    )
    .await?;
    let (res, _) = logs(&url, &["--raw", "job-1"]).await;
    let Err(error) = res else {
        return Err("expected an error".into());
    };
    let shown = error.to_string();
    assert!(!shown.contains(TOKEN), "{shown}");
    assert!(shown.contains("bad [REDACTED] here"), "{shown}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_token_prefix_held_at_a_server_cut_is_dropped() -> TestResult {
    let mut cut = chunk(1, "ok client-tok");
    cut.truncated = true;
    let (url, _) = serve(vec![reply(vec![cut], true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["--raw", "job-1"]).await;
    res?;
    assert_eq!(out, "ok \n-- transcript truncated --\n");
    Ok(())
}

fn assistant(blocks: &str) -> String {
    format!(r#"{{"type":"assistant","message":{{"id":"m1","content":[{blocks}]}}}}"#)
}

fn user(blocks: &str) -> String {
    format!(r#"{{"type":"user","message":{{"content":[{blocks}]}}}}"#)
}

fn text_block(text: &str) -> String {
    format!(r#"{{"type":"text","text":"{text}"}}"#)
}

fn call_block(id: &str, name: &str, command: &str) -> String {
    format!(
        r#"{{"type":"tool_use","id":"{id}","name":"{name}","input":{{"command":"{command}"}}}}"#
    )
}

fn result_block(id: &str, content: &str, is_error: bool) -> String {
    format!(
        r#"{{"type":"tool_result","tool_use_id":"{id}","is_error":{is_error},"content":"{content}"}}"#
    )
}

const RESULT_LINE: &str = r#"{"type":"result","is_error":false,"num_turns":2,"duration_ms":3250,"total_cost_usd":0.1234,"usage":{"input_tokens":10,"output_tokens":20}}"#;

async fn logs_color(url: &str, args: &[&str], color: bool) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url, "logs"];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let mut out = Vec::new();
    let result = run_with_color(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
        false,
        color,
        &mut std::io::empty(),
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test(start_paused = true)]
async fn the_default_view_is_an_indented_plain_text_transcript() -> TestResult {
    let lines = [
        assistant(&text_block("hello")),
        assistant(&call_block("t1", "Bash", "ls -la")),
        user(&result_block("t1", r"a\nb", false)),
        RESULT_LINE.to_owned(),
    ];
    let chunks = lines
        .iter()
        .zip(1..)
        .map(|(l, i)| chunk(i, &format!("{l}\n")))
        .collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(
        out,
        "assistant: hello\n> Bash ls -la\n  < ok\n    a\n    b\n-- 2 turns, 3.250s, $0.1234, tokens in 10 out 20 --\n"
    );
    Ok(())
}

async fn footer_for(usage: &str) -> Result<String, Box<dyn std::error::Error>> {
    let line = format!(
        r#"{{"type":"result","is_error":false,"num_turns":1,"duration_ms":5,"usage":{usage}}}"#
    );
    let chunks = vec![chunk(1, &format!("{line}\n"))];
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    Ok(out)
}

#[tokio::test(start_paused = true)]
async fn the_footer_prints_present_cache_figures_and_omits_absent_ones() -> TestResult {
    let both = footer_for(
        r#"{"input_tokens":1,"output_tokens":2,"cache_read_input_tokens":3,"cache_creation_input_tokens":4}"#,
    )
    .await?;
    assert_eq!(
        both,
        "-- 1 turns, 0.005s, tokens in 1 out 2 cache read 3 write 4 --\n"
    );
    let zeros =
        footer_for(r#"{"cache_read_input_tokens":0,"cache_creation_input_tokens":0}"#).await?;
    assert_eq!(
        zeros,
        "-- 1 turns, 0.005s, tokens in 0 out 0 cache read 0 write 0 --\n"
    );
    let read = footer_for(r#"{"cache_read_input_tokens":7}"#).await?;
    assert_eq!(
        read,
        "-- 1 turns, 0.005s, tokens in 0 out 0 cache read 7 --\n"
    );
    let write = footer_for(r#"{"cache_creation_input_tokens":8}"#).await?;
    assert_eq!(write, "-- 1 turns, 0.005s, tokens in 0 out 0 write 8 --\n");
    let neither = footer_for(r#"{"input_tokens":1,"output_tokens":2}"#).await?;
    assert_eq!(neither, "-- 1 turns, 0.005s, tokens in 1 out 2 --\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn raw_keeps_json_lines_byte_for_byte_and_the_default_does_not() -> TestResult {
    let line = format!("{}\n", assistant(&text_block("hi")));
    let (url, _) = serve(
        vec![
            reply(vec![chunk(1, &line)], true),
            reply(vec![chunk(1, &line)], true),
        ],
        JobState::Succeeded,
    )
    .await?;
    let (res, raw) = logs(&url, &["--raw", "job-1"]).await;
    res?;
    assert_eq!(raw, line);
    let (res, pretty) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(pretty, "assistant: hi\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn an_error_result_is_marked() -> TestResult {
    let lines = [
        assistant(&call_block("t1", "Bash", "false")),
        user(&result_block("t1", "boom", true)),
    ];
    let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out, "> Bash false\n  < ERROR\n    boom\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_result_block_is_cut_to_a_short_block() -> TestResult {
    let output = (1..=30)
        .map(|i| format!("l{i}"))
        .collect::<Vec<_>>()
        .join(r"\n");
    let lines = [
        assistant(&call_block("t1", "Bash", "seq")),
        user(&result_block("t1", &output, false)),
    ];
    let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert!(out.contains("    l8\n"), "{out}");
    assert!(!out.contains("l9\n"), "{out}");
    assert!(out.contains("    ... 22 more lines\n"), "{out}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_pending_call_and_a_missing_result_are_shown() -> TestResult {
    let call = assistant(&call_block("t1", "Bash", "sleep"));
    let (url, _) = serve(
        vec![
            reply(vec![chunk(1, &call)], false),
            reply(vec![], false),
            reply(vec![chunk(1, &call)], true),
        ],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out, "> Bash sleep\n  < pending\n");
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out, "> Bash sleep\n  < no result\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn sub_agent_work_is_nested_under_its_call() -> TestResult {
    let task = assistant(&call_block("t1", "Task", "dig"));
    let inner = format!(
        r#"{{"type":"assistant","parent_tool_use_id":"t1","message":{{"id":"m2","content":[{}]}}}}"#,
        text_block("inside")
    );
    let done = user(&result_block("t1", "found", false));
    let (url, _) = serve(
        vec![reply(
            vec![chunk(1, &task), chunk(2, &inner), chunk(3, &done)],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out, "> Task dig\n  assistant: inside\n  < ok\n    found\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn notes_truncation_and_unknown_lines_are_neutral() -> TestResult {
    let mut cut = chunk(3, "");
    cut.truncated = true;
    let (url, _) = serve(
        vec![reply(
            vec![
                chunk(1, "fleet: runner started\n"),
                chunk(2, "not json at all\n"),
                cut,
            ],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(
        out,
        "note: runner started\nunknown ?: not json at all\n-- transcript truncated --\n"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_result_without_its_call_is_shown_as_an_orphan() -> TestResult {
    let (url, _) = serve(
        vec![reply(
            vec![chunk(1, &user(&result_block("t9", "late", false)))],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out, "< t9 ok (no call)\n  late\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_prints_a_call_when_seen_and_its_result_later_with_the_id() -> TestResult {
    let call = assistant(&call_block("t1", "Bash", "ls"));
    let done = user(&result_block("t1", "x", false));
    let (url, _) = serve(
        vec![reply(vec![chunk(1, &call)], false), fail(Code::Internal)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
    assert!(matches!(res, Err(CliError::Rpc(_))));
    assert_eq!(out, "> Bash ls (t1)\n");
    let (url, _) = serve(
        vec![
            reply(vec![chunk(1, &call)], false),
            reply(vec![chunk(2, &done)], true),
        ],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
    res?;
    assert_eq!(out, "> Bash ls (t1)\n  < t1 ok\n    x\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_closes_a_call_that_never_got_a_result_when_the_job_is_done() -> TestResult {
    let call = assistant(&call_block("t1", "Bash", "ls"));
    let (url, _) = serve(
        vec![reply(vec![chunk(1, &call)], true)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
    res?;
    assert_eq!(out, "> Bash ls (t1)\n  < t1 no result\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_adopts_an_orphan_result_when_its_call_arrives_late() -> TestResult {
    let call = assistant(&call_block("t1", "Bash", "ls"));
    let done = user(&result_block("t1", "x", false));
    let (url, _) = serve(
        vec![reply(vec![chunk(1, &done), chunk(2, &call)], true)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
    res?;
    assert_eq!(
        out,
        "< t1 ok (no call)\n  x\n> Bash ls (t1)\n  < t1 ok (shown above)\n"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn follow_nests_a_sub_agent_result_under_its_call() -> TestResult {
    let task = assistant(&call_block("t1", "Task", "dig"));
    let inner_call = format!(
        r#"{{"type":"assistant","parent_tool_use_id":"t1","message":{{"id":"m2","content":[{}]}}}}"#,
        call_block("t2", "Bash", "ls")
    );
    let inner_done = format!(
        r#"{{"type":"user","parent_tool_use_id":"t1","message":{{"content":[{}]}}}}"#,
        result_block("t2", "x", false)
    );
    let (url, _) = serve(
        vec![reply(
            vec![
                chunk(1, &task),
                chunk(2, &inner_call),
                chunk(3, &inner_done),
            ],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
    res?;
    assert_eq!(
        out,
        "> Task dig (t1)\n  > Bash ls (t2)\n    < t2 ok\n      x\n  < t1 no result\n"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn color_is_applied_only_when_the_color_parameter_is_set() -> TestResult {
    let lines = [
        assistant(&call_block("t1", "Bash", "false")),
        user(&result_block("t1", "boom", true)),
    ];
    let make = || lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(
        vec![
            reply(make(), true),
            reply(make(), true),
            reply(make(), true),
        ],
        JobState::Succeeded,
    )
    .await?;
    let (res, plain) = logs_color(&url, &["job-1"], false).await;
    res?;
    assert!(!plain.contains('\u{1b}'), "{plain:?}");
    let (res, colored) = logs_color(&url, &["job-1"], true).await;
    res?;
    assert!(
        colored.contains("\u{1b}[31m< ERROR\u{1b}[0m"),
        "{colored:?}"
    );
    assert!(
        colored.contains("\u{1b}[1m> Bash false\u{1b}[0m"),
        "{colored:?}"
    );
    let (res, default) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(default, plain);
    Ok(())
}

#[test]
fn color_needs_a_terminal_and_no_no_color_value() {
    assert!(color_wanted(true, None));
    assert!(color_wanted(true, Some("")));
    assert!(!color_wanted(true, Some("1")));
    assert!(!color_wanted(false, None));
    assert!(!color_wanted(false, Some("")));
}

#[tokio::test(start_paused = true)]
async fn raw_output_never_carries_color() -> TestResult {
    let (url, _) = serve(
        vec![reply(vec![chunk(1, "plain\n")], true)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs_color(&url, &["--raw", "job-1"], true).await;
    res?;
    assert_eq!(out, "plain\n");
    Ok(())
}

fn hostile(c: char) -> bool {
    c != '\n' && c != '\t' && fleet_core::text::is_hostile(c)
}

#[tokio::test(start_paused = true)]
async fn the_hostile_input_table_holds_on_the_pretty_surface() -> TestResult {
    let rows: [(&str, &str, &str, &str, &str); 9] = [
        ("cr", r"\r", "ab", "ab", "a b"),
        ("crlf", r"\r\n", "a\n  b", "a\n    b", "a b"),
        ("nel", r"\u0085", "ab", "ab", "a b"),
        ("line separator", r"\u2028", "ab", "ab", "a b"),
        ("paragraph separator", r"\u2029", "ab", "ab", "a b"),
        ("ansi escape", r"\u001b[31m", "a[31mb", "a[31mb", "a[31mb"),
        ("bidi override", r"\u202e", "ab", "ab", "ab"),
        ("backslash", r"\\", r"a\b", r"a\b", r"a\b"),
        ("non-ascii", "é日", "aé日b", "aé日b", "aé日b"),
    ];
    for (label, fragment, text, output, summary) in rows {
        let value = format!("a{fragment}b");
        let lines = [
            assistant(&text_block(&value)),
            assistant(&call_block("t1", "Bash", &value)),
            user(&result_block("t1", &value, false)),
        ];
        let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
        let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
        let (res, out) = logs(&url, &["job-1"]).await;
        res?;
        let expected = format!("assistant: {text}\n> Bash {summary}\n  < ok\n    {output}\n");
        assert_eq!(out, expected, "{label}");
        assert!(!out.chars().any(hostile), "{label}: {out:?}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn hostile_values_in_a_note_an_unknown_line_and_the_footer_reason_are_stripped() -> TestResult
{
    let reason = r#"{"type":"result","is_error":true,"num_turns":1,"duration_ms":5,"terminal_reason":"x\u001b[31m y","usage":{}}"#;
    let (url, _) = serve(
        vec![reply(
            vec![
                chunk(1, "fleet: a\u{1b}[2J\u{85}b\n"),
                chunk(2, "{\"type\":\"weird\",\"v\":\"p\\u001bq\\u2028r\"}\n"),
                chunk(3, reason),
            ],
            true,
        )],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert!(!out.chars().any(hostile), "{out:?}");
    assert!(out.contains("note: a[2J b\n"), "{out}");
    assert!(out.contains("unknown weird: "), "{out}");
    assert!(out.contains("reason x[31m y"), "{out}");
    assert!(
        out.contains("-- run failed: 1 turns, 0.005s, tokens"),
        "{out}"
    );
    assert!(!out.contains("denials"), "{out}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn over_long_values_are_cut_to_a_bounded_line() -> TestResult {
    let long = "x".repeat(10_000);
    let lines = [
        assistant(&call_block("t1", "Bash", "seq")),
        user(&result_block("t1", &long, false)),
        "{\"type\":\"weird\",\"v\":\"".to_owned() + &long + "\"}",
    ];
    let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    let widest = out.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    assert!(widest <= 200, "{widest}");
    assert!(
        out.contains(&format!("    {}...\n", "x".repeat(160))),
        "{out}"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_client_token_in_a_tool_result_is_redacted_in_the_pretty_view() -> TestResult {
    let lines = [
        assistant(&call_block("t1", "Bash", "env")),
        user(&result_block("t1", &format!("key={TOKEN}"), false)),
    ];
    let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert!(!out.contains(TOKEN), "{out}");
    assert!(out.contains("key=[REDACTED]"), "{out}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn message_roles_thinking_system_rate_limit_and_denials_are_shown() -> TestResult {
    let lines = [
        r#"{"type":"system","subtype":"init"}"#.to_owned(),
        r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","utilization":0.83}}"#
            .to_owned(),
        r#"{"type":"user","message":{"content":"question"}}"#.to_owned(),
        assistant(r#"{"type":"thinking","thinking":"hmm\nmore"}"#),
        assistant(&text_block("")),
        r#"{"type":"result","is_error":false,"num_turns":1,"duration_ms":61001,"terminal_reason":"done","permission_denials":[1,2],"usage":{}}"#
            .to_owned(),
    ];
    let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(
        out,
        "system: init\nrate limit: allowed, 83% used\nuser: question\nthinking: hmm\n  more\nassistant:\n-- 1 turns, 61.001s, tokens in 0 out 0, reason done, 2 denials --\n"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn an_error_orphan_and_a_single_extra_line_are_marked() -> TestResult {
    let lines = [
        user(&result_block("t9", r"a\nb\nc\nd\ne\nf\ng\nh\ni", true)),
        assistant(&call_block("t1", "Bash", "x")),
        user(&result_block("t1", "", false)),
    ];
    let chunks = lines.iter().zip(1..).map(|(l, i)| chunk(i, l)).collect();
    let (url, _) = serve(vec![reply(chunks, true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(
        out,
        "< t9 ERROR (no call)\n  a\n  b\n  c\n  d\n  e\n  f\n  g\n  h\n  ... 1 more line\n> Bash x\n  < ok\n"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_capped_view_says_so_in_both_modes() -> TestResult {
    let line = format!("{}\n", assistant(&text_block("x")));
    let page = || vec![chunk(1, &line.repeat(20_010))];
    let (url, _) = serve(
        vec![reply(page(), true), reply(page(), true)],
        JobState::Succeeded,
    )
    .await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out.lines().count(), 20_001);
    assert!(
        out.ends_with("-- view capped, 10 items not shown --\n"),
        "{}",
        &out[out.len() - 80..]
    );
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
    res?;
    assert_eq!(out.lines().count(), 20_001);
    assert!(
        out.ends_with("-- view capped, later items not shown --\n"),
        "{}",
        &out[out.len() - 80..]
    );
    Ok(())
}
