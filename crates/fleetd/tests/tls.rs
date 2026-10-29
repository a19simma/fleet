//! Runs the fleetd channels against a TLS stub with a self-signed certificate.

use std::error::Error;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Identity;
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, GetProfileBlobReply, GetProfileBlobRequest, HeartbeatReply,
    HeartbeatRequest, PushEventsReply, PushEventsRequest, ReportJobReply, ReportJobRequest,
};
use fleetd::heartbeat::{Heartbeat, QueueSnapshot, QueueSource};
use fleetd::poller::{CALL_BACKSTOP, GrpcReporter, Token, channel, channel_with_ca};
use fleetd::runner::Reporter;
use rcgen::SanType;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Identity as TlsIdentity, ServerTlsConfig};
use tonic::{Request, Response, Status};

type Test = Result<(), Box<dyn Error>>;

const TOKEN: &str = "tls-token-0123456789abcdef0123456789";
const BOUND: Duration = Duration::from_secs(12);

#[derive(Clone, Default)]
struct Stub {
    auth: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn record<T>(&self, request: &Request<T>) {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(header);
    }

    fn seen(&self) -> Vec<String> {
        self.auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[tonic::async_trait]
impl FleetWorker for Stub {
    async fn claim_job(
        &self,
        request: Request<ClaimJobRequest>,
    ) -> Result<Response<ClaimJobReply>, Status> {
        self.record(&request);
        Ok(Response::new(ClaimJobReply {
            job: None,
            lease_s: 0,
            next_in_s: 1,
        }))
    }

    async fn get_profile_blob(
        &self,
        _request: Request<GetProfileBlobRequest>,
    ) -> Result<Response<GetProfileBlobReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_job_transcript(
        &self,
        _request: Request<fleet_proto::v1::GetJobTranscriptRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobTranscriptReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_job_credentials(
        &self,
        _request: Request<fleet_proto::v1::GetJobCredentialsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobCredentialsReply>, Status> {
        Err(Status::unimplemented("get_job_credentials"))
    }

    async fn report_job(
        &self,
        _request: Request<ReportJobRequest>,
    ) -> Result<Response<ReportJobReply>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

#[tonic::async_trait]
impl FleetIngest for Stub {
    async fn push_events(
        &self,
        _request: Request<PushEventsRequest>,
    ) -> Result<Response<PushEventsReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        self.record(&request);
        Ok(Response::new(HeartbeatReply { next_in_s: 30 }))
    }
}

struct Fixture {
    host: String,
    ca_pem: String,
    stub: Stub,
}

struct Idle;

impl QueueSource for Idle {
    fn snapshot(&self) -> impl Future<Output = QueueSnapshot> + Send {
        std::future::ready(QueueSnapshot::default())
    }
}

fn certificate() -> Result<(String, String), Box<dyn Error>> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse()?));
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

async fn serve(tls: bool) -> Result<Fixture, Box<dyn Error>> {
    let (cert, key) = certificate()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let host = listener.local_addr()?.to_string();
    let stub = Stub::default();
    let mut builder = tonic::transport::Server::builder();
    if tls {
        builder = builder.tls_config(
            ServerTlsConfig::new().identity(TlsIdentity::from_pem(cert.clone(), key)),
        )?;
    }
    tokio::spawn(
        builder
            .add_service(FleetWorkerServer::new(stub.clone()))
            .add_service(FleetIngestServer::new(stub.clone()))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(Fixture {
        host,
        ca_pem: cert,
        stub,
    })
}

async fn claim(channel: Channel) -> Result<(), Box<dyn Error>> {
    let mut request = Request::new(ClaimJobRequest::default());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse()?);
    tokio::time::timeout(BOUND, FleetWorkerClient::new(channel).claim_job(request)).await??;
    Ok(())
}

#[tokio::test]
async fn https_claim_succeeds_with_the_ca_and_sends_the_token() -> Test {
    let fixture = serve(true).await?;
    let url = format!("https://{}", fixture.host);
    claim(channel_with_ca(&url, Some(fixture.ca_pem.as_bytes()))?).await?;
    assert_eq!(fixture.stub.seen(), vec![format!("Bearer {TOKEN}")]);
    Ok(())
}

#[tokio::test]
async fn https_claim_fails_bounded_without_the_ca_and_never_echoes_the_token() -> Test {
    let fixture = serve(true).await?;
    let url = format!("https://{}", fixture.host);
    let started = std::time::Instant::now();
    let err = claim(channel(&url)?)
        .await
        .err()
        .ok_or("expected failure")?;
    assert!(started.elapsed() < BOUND, "{:?}", started.elapsed());
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(TOKEN), "{shown}");
    assert_eq!(fixture.stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn https_claim_rejects_a_different_ca() -> Test {
    let fixture = serve(true).await?;
    let (other, _) = certificate()?;
    let url = format!("https://{}", fixture.host);
    let err = claim(channel_with_ca(&url, Some(other.as_bytes()))?)
        .await
        .err()
        .ok_or("expected failure")?;
    assert!(!format!("{err:?}").contains(TOKEN));
    assert_eq!(fixture.stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn http_claim_still_works() -> Test {
    let fixture = serve(false).await?;
    claim(channel(&format!("http://{}", fixture.host))?).await?;
    assert_eq!(fixture.stub.seen(), vec![format!("Bearer {TOKEN}")]);
    Ok(())
}

#[tokio::test]
async fn https_heartbeat_reaches_the_server_with_the_ca() -> Test {
    let fixture = serve(true).await?;
    let url = format!("https://{}", fixture.host);
    let target = Heartbeat::new_with_ca(&url, TOKEN, Some(fixture.ca_pem.as_bytes()))?
        .with_period(Duration::from_millis(50));
    let identity = Identity {
        box_name: "alpha".into(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
    };
    let stub = fixture.stub.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        target.run(identity, Idle, async move {
            while stub.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }),
    )
    .await?;
    assert_eq!(fixture.stub.seen()[0], format!("Bearer {TOKEN}"));
    Ok(())
}

#[tokio::test]
async fn a_server_that_never_answers_the_handshake_fails_at_the_call_backstop() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://{}", listener.local_addr()?);
    let held = tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _held = conn;
                std::future::pending::<()>().await;
            });
        }
    });
    let started = std::time::Instant::now();
    let reporter = GrpcReporter::new(channel(&url)?, &Token::new(TOKEN))?;
    let outcome = tokio::time::timeout(
        CALL_BACKSTOP + Duration::from_secs(2),
        reporter.report(ReportJobRequest::default()),
    )
    .await;
    held.abort();
    let err = outcome?.err().ok_or("expected failure")?;
    assert!(started.elapsed() < CALL_BACKSTOP + Duration::from_secs(2));
    assert!(!format!("{err:?}").contains(TOKEN));
    Ok(())
}
