//! Runs `fleet logs` against an in-process `FleetJobs` stub with scripted transcript replies.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run_with};
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
    let mut full = vec!["fleet", "--server", url, "logs"];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let mut out = Vec::new();
    let result = run_with(
        parsed,
        |name| match name {
            "FLEET_CLIENT_TOKEN" => Some(TOKEN.to_owned()),
            _ => None,
        },
        false,
        &mut std::io::empty(),
        &mut out,
    )
    .await;
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
    let (res, out) = logs(&url, &["job-1", "-f"]).await;
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
        let (res, out) = logs(&url, &["job-1", "--follow"]).await;
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
    let (res, out) = logs(&url, &["job-1"]).await;
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
    let (res, out) = logs(&url, &["job-1"]).await;
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
        let (res, out) = logs(&url, &["job-1", "-f"]).await;
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
        let (res, out) = logs(&url, &["job-1", "-f"]).await;
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
    let (res, _) = logs(&url, &["job-1", "-f"]).await;
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
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out, "abcdef\tg\n");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_transcript_page_above_the_default_decode_limit_is_accepted() -> TestResult {
    let big = "y".repeat(5 * 1024 * 1024);
    let (url, _) = serve(vec![reply(vec![chunk(1, &big)], true)], JobState::Succeeded).await?;
    let (res, out) = logs(&url, &["job-1"]).await;
    res?;
    assert_eq!(out.len(), big.len() + 1);
    Ok(())
}
