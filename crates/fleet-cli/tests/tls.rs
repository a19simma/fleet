//! Runs the CLI against a TLS `FleetJobs` stub with a self-signed certificate.

use std::collections::HashMap;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, ListJobsReply, ListJobsRequest, ReadTranscriptReply,
    ReadTranscriptRequest, SubmitJobRequest,
};
use rcgen::SanType;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, ServerTlsConfig};
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Empty;

#[tonic::async_trait]
impl FleetJobs for Empty {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn get_job(&self, _: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }
    async fn list_jobs(
        &self,
        _: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        Ok(Response::new(ListJobsReply { jobs: Vec::new() }))
    }
    async fn cancel_job(&self, _: Request<CancelJobRequest>) -> Result<Response<Job>, Status> {
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

struct Fixture {
    url: String,
    ca_path: String,
    _dir: tempfile::TempDir,
}

async fn serve_tls() -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse()?));
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let dir = tempfile::tempdir()?;
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, cert.pem())?;
    let identity = Identity::from_pem(cert.pem(), key.serialize_pem());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(FleetJobsServer::new(Empty))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(Fixture {
        url,
        ca_path: ca.to_str().ok_or("utf8")?.to_owned(),
        _dir: dir,
    })
}

async fn jobs(fixture: &Fixture, ca: bool) -> Result<(), CliError> {
    let parsed = Cli::try_parse_from(["fleet", "--server", &fixture.url, "jobs"])
        .map_err(|e| CliError::Usage(e.to_string()))?;
    let mut env: HashMap<&str, &str> = HashMap::from([("FLEET_CLIENT_TOKEN", "t")]);
    if ca {
        env.insert("FLEET_CA_CERT", &fixture.ca_path);
    }
    run(
        parsed,
        |name| env.get(name).map(|v| (*v).to_owned()),
        &mut std::io::empty(),
        &mut Vec::new(),
    )
    .await
}

#[tokio::test]
async fn ca_cert_env_trusts_a_self_signed_server() -> TestResult {
    let fixture = serve_tls().await?;
    jobs(&fixture, true).await?;
    Ok(())
}

#[tokio::test]
async fn self_signed_server_is_rejected_without_the_ca_cert() -> TestResult {
    let fixture = serve_tls().await?;
    let err = jobs(&fixture, false)
        .await
        .err()
        .ok_or("expected failure")?;
    assert!(matches!(err, CliError::Connect(_)), "{err}");
    assert_eq!(err.exit_code(), 1);
    Ok(())
}
