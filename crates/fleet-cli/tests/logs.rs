//! Runs `fleet logs` against an in-process `FleetJobs` stub with scripted transcript replies.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, ListJobsReply, ListJobsRequest,
    ReadTranscriptReply, ReadTranscriptRequest, SubmitJobRequest, TranscriptChunk,
};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Clone)]
struct Stub {
    replies: Arc<Mutex<VecDeque<ReadTranscriptReply>>>,
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

    async fn read_transcript(
        &self,
        request: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        check(&request)?;
        lock(&self.after)?.push(request.into_inner().after_seq);
        let next = lock(&self.replies)?.pop_front();
        next.map(Response::new)
            .ok_or_else(|| Status::failed_precondition("script exhausted"))
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

fn reply(chunks: Vec<TranscriptChunk>, done: bool) -> ReadTranscriptReply {
    ReadTranscriptReply { chunks, done }
}

async fn serve(
    script: Vec<ReadTranscriptReply>,
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
    let result = run(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
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
