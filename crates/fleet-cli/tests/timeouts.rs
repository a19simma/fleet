//! Runs the CLI against servers that accept a connection and never answer.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, ListJobsReply, ListJobsRequest, ReadTranscriptReply,
    ReadTranscriptRequest, SubmitJobRequest,
};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn silent_server(seen: Arc<Notify>) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            seen.notify_one();
            tokio::spawn(async move {
                let _keep = socket;
                std::future::pending::<()>().await;
            });
        }
    });
    Ok(url)
}

async fn status(url: &str) -> Result<(), CliError> {
    let cli = Cli::try_parse_from(["fleet", "--server", url, "status", "job-1"])
        .map_err(|e| CliError::Usage(e.to_string()))?;
    run(
        cli,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| "tok".to_owned()),
        &mut std::io::empty(),
        &mut Vec::new(),
    )
    .await
}

async fn pause_once(seen: &Notify) {
    seen.notified().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::pause();
}

#[tokio::test]
async fn a_half_open_socket_ends_the_request_instead_of_hanging() -> TestResult {
    let seen = Arc::new(Notify::new());
    let url = silent_server(seen.clone()).await?;
    let call = tokio::spawn(async move { status(&url).await });
    pause_once(&seen).await;
    let started = Instant::now();
    let res = call.await?;
    assert!(res.is_err(), "expected an error");
    assert!(
        started.elapsed() <= Duration::from_secs(40),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

struct Hang(Arc<Notify>);

#[tonic::async_trait]
impl FleetJobs for Hang {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn get_job(&self, _: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        self.0.notify_one();
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Err(Status::unimplemented("never"))
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
        _: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

#[tokio::test]
async fn a_request_the_server_never_answers_ends_after_the_request_timeout() -> TestResult {
    let seen = Arc::new(Notify::new());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetJobsServer::new(Hang(seen.clone())))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let call = tokio::spawn(async move { status(&url).await });
    pause_once(&seen).await;
    let started = Instant::now();
    let res = call.await?;
    assert!(res.is_err(), "expected an error");
    let elapsed = started.elapsed();
    assert!(elapsed <= Duration::from_secs(120), "{elapsed:?}");
    Ok(())
}
