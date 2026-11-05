//! Every path that prints server-supplied job text redacts the client token, end to end over a
//! real socket, and one resolution of the configuration serves the whole run.

use std::sync::atomic::{AtomicUsize, Ordering};

use clap::Parser;
use fleet_cli::{Cli, CliError, run_with};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, JobSummary, ListJobsReply, ListJobsRequest,
    SubmitJobRequest,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

fn laden(field: &str) -> String {
    format!("{field}-{TOKEN}")
}

fn hostile_job() -> Job {
    Job {
        job_id: laden("id"),
        state: JobState::Failed as i32,
        repo: laden("repo"),
        phase: laden("phase"),
        progress: laden("progress"),
        branch: Some(laden("branch")),
        pr_url: Some(format!("https://{TOKEN}@host.example/pr/1")),
        error: Some(laden("error")),
        summary: Some(JobSummary {
            stop_reason: Some(laden("stop")),
            stuck_rule: Some(laden("rule")),
            missing: vec![laden("missing")],
            bundle_sha: Some(laden("bundle")),
            claude_version: Some(laden("version")),
            model: Some(laden("model")),
            complete: false,
            ..JobSummary::default()
        }),
        ..Job::default()
    }
}

#[derive(Clone)]
struct Stub;

fn unused<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented("not used"))
}

#[tonic::async_trait]
impl FleetJobs for Stub {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Ok(Response::new(hostile_job()))
    }

    async fn get_job(&self, _: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        Ok(Response::new(hostile_job()))
    }

    async fn list_jobs(
        &self,
        _: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        Ok(Response::new(ListJobsReply {
            jobs: vec![hostile_job()],
        }))
    }

    async fn cancel_job(&self, _: Request<CancelJobRequest>) -> Result<Response<Job>, Status> {
        Ok(Response::new(hostile_job()))
    }

    async fn get_stats(
        &self,
        _: Request<fleet_proto::v1::GetStatsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetStatsReply>, Status> {
        unused()
    }

    async fn read_job_events(
        &self,
        _: Request<fleet_proto::v1::ReadJobEventsRequest>,
    ) -> Result<Response<fleet_proto::v1::ReadJobEventsReply>, Status> {
        unused()
    }

    async fn read_transcript(
        &self,
        _: Request<fleet_proto::v1::ReadTranscriptRequest>,
    ) -> Result<Response<fleet_proto::v1::ReadTranscriptReply>, Status> {
        unused()
    }

    type StreamShellLogStream = tonic::codegen::BoxStream<fleet_proto::v1::StreamShellLogChunk>;

    async fn stream_shell_log(
        &self,
        _: Request<fleet_proto::v1::StreamShellLogRequest>,
    ) -> Result<Response<Self::StreamShellLogStream>, Status> {
        unused()
    }

    async fn get_job_timing(
        &self,
        _: Request<fleet_proto::v1::GetJobTimingRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobTimingReply>, Status> {
        unused()
    }
}

async fn serve() -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetJobsServer::new(Stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

fn lookup(name: &str) -> Option<String> {
    (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned())
}

async fn fleet(
    args: &[&str],
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(Result<(), CliError>, String), Box<dyn std::error::Error>> {
    let url = serve().await?;
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full)?;
    let mut out = Vec::new();
    let result = run_with(parsed, lookup, false, &mut std::io::empty(), &mut out).await;
    Ok((result, String::from_utf8_lossy(&out).into_owned()))
}

fn assert_redacted(text: &str, row: &str, expected: &str) {
    assert!(!text.contains("client-token"), "{row}: {text:?}");
    assert!(
        text.contains(expected),
        "{row}: missing {expected:?} in {text:?}"
    );
}

#[tokio::test]
async fn status_redacts_every_server_field() -> TestResult {
    let (result, text) = fleet(&["status", "j"], lookup).await?;
    result?;
    for (row, expected) in [
        ("job_id", "id: id-[REDACTED]\n"),
        ("phase", "phase: phase-[REDACTED]\n"),
        ("branch", "branch: branch-[REDACTED]\n"),
        ("pr_url", "pr_url: https://[REDACTED]@host.example/pr/1\n"),
        ("error", "error: error-[REDACTED]\n"),
        ("stop_reason", "stop_reason: stop-[REDACTED]\n"),
        ("stuck_rule", "stuck (shadow): rule-[REDACTED] at event -\n"),
        ("bundle_sha", "bundle_sha: bundle-[REDACTED]\n"),
        ("claude_version", "claude_version: version-[REDACTED]\n"),
        ("model", "model: model-[REDACTED]\n"),
        ("missing", "INCOMPLETE (missing: missing-[REDACTED])\n"),
    ] {
        assert_redacted(&text, row, expected);
    }
    Ok(())
}

#[tokio::test]
async fn jobs_redacts_every_server_field() -> TestResult {
    let (result, text) = fleet(&["jobs"], lookup).await?;
    result?;
    for (row, expected) in [
        ("job_id", "id-[REDACTED]\tFAILED"),
        ("repo", "\trepo-[REDACTED]\t"),
        ("phase", "\tphase-[REDACTED]\n"),
    ] {
        assert_redacted(&text, row, expected);
    }
    Ok(())
}

#[tokio::test]
async fn cancel_redacts_the_job_id() -> TestResult {
    let (result, text) = fleet(&["cancel", "j"], lookup).await?;
    result?;
    assert_redacted(&text, "job_id", "id-[REDACTED]\tFAILED\n");
    Ok(())
}

#[tokio::test]
async fn submit_redacts_the_job_id() -> TestResult {
    let (result, text) = fleet(
        &["submit", "--repo", "r", "--base", "main", "do it"],
        lookup,
    )
    .await?;
    result?;
    assert_redacted(&text, "job_id", "id-[REDACTED]\n");
    Ok(())
}

#[tokio::test]
async fn watch_redacts_every_server_field() -> TestResult {
    let (result, text) = fleet(&["watch", "j"], lookup).await?;
    assert!(result.is_err());
    for (row, expected) in [
        ("phase", "FAILED\tphase-[REDACTED]\tprogress-[REDACTED]\n"),
        ("pr_url", "pr_url: https://[REDACTED]@host.example/pr/1\n"),
        ("error", "error: error-[REDACTED]\n"),
    ] {
        assert_redacted(&text, row, expected);
    }
    Ok(())
}

#[tokio::test]
async fn the_configuration_is_resolved_once_per_run() -> TestResult {
    let token_lookups = AtomicUsize::new(0);
    let once = |name: &str| match name {
        "FLEET_CLIENT_TOKEN" => {
            (token_lookups.fetch_add(1, Ordering::SeqCst) == 0).then(|| TOKEN.to_owned())
        }
        _ => None,
    };
    let (result, text) = fleet(&["status", "j"], once).await?;
    result?;
    assert_eq!(token_lookups.load(Ordering::SeqCst), 1);
    assert!(!text.contains("client-token"), "{text:?}");
    assert!(text.contains("error: error-[REDACTED]\n"), "{text:?}");
    Ok(())
}

#[tokio::test]
async fn a_failed_lookup_fails_closed_with_a_configuration_error() -> TestResult {
    let (result, text) = fleet(&["status", "j"], |_| None).await?;
    let error = result.err().ok_or("expected a configuration error")?;
    assert_eq!(error.exit_code(), 2);
    assert!(text.is_empty(), "{text:?}");
    Ok(())
}
