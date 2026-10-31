//! The `GetJobCredentials` client and the credential holder against a fake in-process
//! `FleetWorker` on a loopback port. Own test binary because it binds sockets.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::Redactor;
use std::fmt::Write as _;

use fleet_core::credential::{CredentialKind, Secret};
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, GetJobCredentialsReply, GetJobCredentialsRequest,
    GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply, GetProfileBlobRequest,
    Job, JobCredential, JobState, ReportJobReply, ReportJobRequest,
};
use fleetd::DaemonRunner;
use fleetd::cred::{
    CredentialBook, CredentialClient, CredentialFailure, ERR_EXPIRED, ERR_LEASE, ERR_MALFORMED,
    ERR_NO_AGENT, ERR_NO_GITHUB, ERR_NOT_CONFIGURED, ERR_UNAVAILABLE,
};
use fleetd::poller::{JobRunner, Shutdown, channel};
use fleetd::runner::{AgentRunner, JobEnd, Reporter, RunConfig};
use fleetd::workspace::Workspace;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "cred-test-token-0123456789";
const GITHUB: &str = "gh-pat-value-0123456789abcdef";
const AGENT: &str = "agent-key-value-0123456789abcdef";

#[derive(Default)]
struct Fake {
    reply: Mutex<Option<Result<GetJobCredentialsReply, Status>>>,
    seen: Mutex<Vec<(String, GetJobCredentialsRequest)>>,
}

struct Stub(Arc<Fake>);

#[tonic::async_trait]
impl FleetWorker for Stub {
    async fn claim_job(
        &self,
        _: Request<ClaimJobRequest>,
    ) -> Result<Response<ClaimJobReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_profile_blob(
        &self,
        _: Request<GetProfileBlobRequest>,
    ) -> Result<Response<GetProfileBlobReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_job_transcript(
        &self,
        _: Request<GetJobTranscriptRequest>,
    ) -> Result<Response<GetJobTranscriptReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_job_credentials(
        &self,
        request: Request<GetJobCredentialsRequest>,
    ) -> Result<Response<GetJobCredentialsReply>, Status> {
        let auth = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.0
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((auth, request.into_inner()));
        self.0
            .reply
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| Err(Status::unimplemented("no reply set")))
            .map(Response::new)
    }

    async fn report_job(
        &self,
        _: Request<ReportJobRequest>,
    ) -> Result<Response<ReportJobReply>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

fn wire(kind: &str, shape: &str, value: &str) -> JobCredential {
    JobCredential {
        kind: kind.into(),
        shape: shape.into(),
        value: value.into(),
    }
}

fn good() -> GetJobCredentialsReply {
    GetJobCredentialsReply {
        credentials: vec![
            wire("github_pat", "static_secret", GITHUB),
            wire("anthropic_api_key", "static_secret", AGENT),
        ],
    }
}

fn box_name() -> String {
    format!("box-{}", 7)
}

async fn serve(
    reply: Result<GetJobCredentialsReply, Status>,
) -> Result<(Arc<CredentialBook>, Arc<Fake>), Box<dyn std::error::Error>> {
    let fake = Arc::new(Fake::default());
    *fake.reply.lock().unwrap_or_else(PoisonError::into_inner) = Some(reply);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetWorkerServer::new(Stub(Arc::clone(&fake))))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    Ok((Arc::new(CredentialBook::new(client)), fake))
}

#[tokio::test]
async fn a_fetch_sends_the_lease_and_the_bearer_and_holds_both_values() -> TestResult {
    let (book, fake) = serve(Ok(good())).await?;
    let held = book.fetch("job1", 3, &box_name()).await?;
    assert_eq!(held.github().map(Secret::expose), Some(GITHUB.as_bytes()));
    assert_eq!(
        held.get(CredentialKind::AnthropicApiKey)
            .map(Secret::expose),
        Some(AGENT.as_bytes())
    );
    assert_eq!(held.iter().count(), 2);
    let seen = fake.seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, format!("Bearer {TOKEN}"));
    assert_eq!(seen[0].1.job_id, "job1");
    assert_eq!(seen[0].1.attempt, 3);
    assert_eq!(seen[0].1.r#box, box_name());
    drop(seen);
    assert!(book.get("job1").is_some());
    assert!(book.get("job2").is_none());
    Ok(())
}

#[tokio::test]
async fn each_fixed_server_error_maps_to_its_own_failure_and_holds_nothing() -> TestResult {
    let cases = [
        (
            Status::permission_denied("lease does not match"),
            CredentialFailure::LeaseMismatch,
            ERR_LEASE,
        ),
        (
            Status::failed_precondition("no github credential"),
            CredentialFailure::NoGithub,
            ERR_NO_GITHUB,
        ),
        (
            Status::failed_precondition("no agent credential"),
            CredentialFailure::NoAgent,
            ERR_NO_AGENT,
        ),
        (
            Status::failed_precondition("credential expired"),
            CredentialFailure::Expired,
            ERR_EXPIRED,
        ),
        (
            Status::failed_precondition("credentials are not configured"),
            CredentialFailure::NotConfigured,
            ERR_NOT_CONFIGURED,
        ),
        (
            Status::failed_precondition("something else"),
            CredentialFailure::Unavailable,
            ERR_UNAVAILABLE,
        ),
        (
            Status::unavailable("storage unavailable"),
            CredentialFailure::Unavailable,
            ERR_UNAVAILABLE,
        ),
        (
            Status::internal("credential store error"),
            CredentialFailure::Unavailable,
            ERR_UNAVAILABLE,
        ),
    ];
    let mut reasons = Vec::new();
    for (status, failure, reason) in cases {
        let (book, _fake) = serve(Err(status)).await?;
        let got = book.fetch("job1", 1, &box_name()).await;
        assert_eq!(got.err(), Some(failure));
        assert_eq!(failure.reason(), reason);
        assert_eq!(failure.to_string(), reason);
        assert!(book.get("job1").is_none());
        reasons.push(reason);
    }
    let distinct: std::collections::HashSet<_> = reasons.iter().collect();
    assert_eq!(distinct.len(), 6);
    Ok(())
}

#[tokio::test]
async fn a_reply_that_breaks_a_server_rule_is_malformed() -> TestResult {
    let long = "x".repeat(fleet_proto::MAX_CREDENTIAL_VALUE_BYTES + 1);
    let replies = [
        vec![
            wire("github_pat", "static_secret", GITHUB),
            wire("nope", "static_secret", AGENT),
        ],
        vec![
            wire("github_pat", "refreshing_file", GITHUB),
            wire("anthropic_api_key", "static_secret", AGENT),
        ],
        vec![
            wire("github_pat", "static_secret", GITHUB),
            wire("anthropic_api_key", "static_secret", "short"),
        ],
        vec![
            wire("github_pat", "static_secret", GITHUB),
            wire("anthropic_api_key", "static_secret", &long),
        ],
        vec![
            wire("github_pat", "static_secret", GITHUB),
            wire("anthropic_api_key", "static_secret", AGENT),
            wire("anthropic_api_key", "static_secret", AGENT),
        ],
    ];
    for credentials in replies {
        let (book, _fake) = serve(Ok(GetJobCredentialsReply { credentials })).await?;
        let got = book.fetch("job1", 1, &box_name()).await;
        assert_eq!(got.err(), Some(CredentialFailure::Malformed));
        assert!(book.get("job1").is_none());
    }
    assert_eq!(CredentialFailure::Malformed.reason(), ERR_MALFORMED);
    Ok(())
}

#[tokio::test]
async fn a_reply_without_github_or_without_an_agent_credential_fails_closed() -> TestResult {
    let (book, _fake) = serve(Ok(GetJobCredentialsReply {
        credentials: vec![wire("anthropic_api_key", "static_secret", AGENT)],
    }))
    .await?;
    assert_eq!(
        book.fetch("job1", 1, &box_name()).await.err(),
        Some(CredentialFailure::NoGithub)
    );
    let (book, _fake) = serve(Ok(GetJobCredentialsReply {
        credentials: vec![wire("github_pat", "static_secret", GITHUB)],
    }))
    .await?;
    assert_eq!(
        book.fetch("job1", 1, &box_name()).await.err(),
        Some(CredentialFailure::NoAgent)
    );
    let (book, _fake) = serve(Ok(GetJobCredentialsReply::default())).await?;
    assert_eq!(
        book.fetch("job1", 1, &box_name()).await.err(),
        Some(CredentialFailure::NoGithub)
    );
    Ok(())
}

#[tokio::test]
async fn values_at_the_length_bounds_pass_and_one_byte_outside_fails() -> TestResult {
    use fleet_core::credential::{MAX_CREDENTIAL_LEN, MIN_CREDENTIAL_LEN};
    for (len, ok) in [
        (MIN_CREDENTIAL_LEN - 1, false),
        (MIN_CREDENTIAL_LEN, true),
        (MAX_CREDENTIAL_LEN, true),
        (MAX_CREDENTIAL_LEN + 1, false),
    ] {
        let value = "k".repeat(len);
        let (book, _fake) = serve(Ok(GetJobCredentialsReply {
            credentials: vec![
                wire("github_pat", "static_secret", GITHUB),
                wire("codex_api_key", "static_secret", &value),
            ],
        }))
        .await?;
        let got = book.fetch("job1", 1, &box_name()).await;
        assert_eq!(got.is_ok(), ok, "{len}");
    }
    Ok(())
}

#[tokio::test]
async fn no_debug_or_error_text_carries_a_value() -> TestResult {
    let (book, _fake) = serve(Ok(good())).await?;
    let held = book.fetch("job1", 1, &box_name()).await?;
    let mut text = format!("{held:?} {book:?}");
    for credential in held.iter() {
        let _ = write!(text, "{credential:?} {:?}", credential.value());
    }
    assert!(text.contains("REDACTED"), "{text}");
    for secret in [GITHUB, AGENT, TOKEN] {
        assert!(!text.contains(secret), "{text}");
    }
    let client = CredentialClient::new(channel("http://127.0.0.1:1")?, TOKEN)?;
    assert!(!format!("{client:?}").contains(TOKEN));
    for failure in [
        CredentialFailure::LeaseMismatch,
        CredentialFailure::NoGithub,
        CredentialFailure::NoAgent,
        CredentialFailure::Expired,
        CredentialFailure::NotConfigured,
        CredentialFailure::Unavailable,
        CredentialFailure::Malformed,
    ] {
        let text = format!("{failure:?} {failure}");
        assert!(!text.contains(GITHUB) && !text.contains(AGENT), "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn a_bad_token_is_refused_without_echoing_it() -> TestResult {
    let bad = "bad\ntoken-value";
    let err = CredentialClient::new(channel("http://127.0.0.1:1")?, bad)
        .err()
        .map(|err| err.to_string());
    let text = err.ok_or("accepted a bad token")?;
    assert!(!text.contains("token-value"), "{text}");
    Ok(())
}

#[tokio::test]
async fn the_redactor_masks_every_held_value() -> TestResult {
    let (book, _fake) = serve(Ok(good())).await?;
    let held = book.fetch("job1", 1, &box_name()).await?;
    let redactor = held.redactor();
    assert_eq!(redactor.len(), 2);
    let line = format!("push with {GITHUB} and call with {AGENT}");
    let clean = redactor.redact_str(&line);
    assert!(!clean.contains(GITHUB) && !clean.contains(AGENT), "{clean}");
    Ok(())
}

#[tokio::test]
async fn a_second_fetch_replaces_the_first_and_forget_is_idempotent() -> TestResult {
    let (book, fake) = serve(Ok(good())).await?;
    book.fetch("job1", 1, &box_name()).await?;
    let mut next = good();
    next.credentials[0].value = "gh-pat-second-0123456789abcdef".into();
    *fake.reply.lock().unwrap_or_else(PoisonError::into_inner) = Some(Ok(next));
    book.fetch("job1", 2, &box_name()).await?;
    let held = book.get("job1").ok_or("missing")?;
    assert_eq!(
        held.github().map(Secret::expose),
        Some(&b"gh-pat-second-0123456789abcdef"[..])
    );
    drop(held);
    book.forget("job1");
    book.forget("job1");
    book.forget("never");
    assert!(book.get("job1").is_none());
    Ok(())
}

struct Silent;

impl Reporter for Silent {
    fn report(
        &self,
        _: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

fn job() -> Job {
    Job {
        job_id: "job1".into(),
        attempt: 1,
        ..Job::default()
    }
}

async fn ending() -> Result<(Arc<CredentialBook>, AgentRunner<Silent>), Box<dyn std::error::Error>>
{
    let (book, _fake) = serve(Ok(good())).await?;
    book.fetch("job1", 1, &box_name()).await?;
    let runner = AgentRunner::new(
        RunConfig::new("claude-fake", false),
        Silent,
        Redactor::default(),
    )
    .with_job_end(JobEnd::new().on_end(book.end_hook()));
    Ok((book, runner))
}

#[tokio::test]
async fn the_credentials_drop_when_the_job_succeeds() -> TestResult {
    let (book, runner) = ending().await?;
    let job = job();
    {
        let _guard = runner.end_guard(&job);
        assert!(book.get("job1").is_some());
    }
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn the_credentials_drop_when_the_job_is_cancelled() -> TestResult {
    let (book, runner) = ending().await?;
    let runner = Arc::new(runner);
    let (started, mut running) = mpsc::unbounded_channel();
    let task = tokio::spawn({
        let runner = Arc::clone(&runner);
        async move {
            let job = job();
            let _guard = runner.end_guard(&job);
            let _ = started.send(());
            std::future::pending::<()>().await;
        }
    });
    running.recv().await.ok_or("never started")?;
    assert!(book.get("job1").is_some());
    task.abort();
    let _ = task.await;
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn the_credentials_drop_when_the_lease_is_lost_and_the_job_ends_twice() -> TestResult {
    let (book, runner) = ending().await?;
    let job = job();
    runner.end_job(&job);
    assert!(book.get("job1").is_none());
    runner.end_job(&job);
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn the_credentials_drop_when_the_job_panics() -> TestResult {
    let (book, runner) = ending().await?;
    let job = job();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _guard = runner.end_guard(&job);
        assert!(std::hint::black_box(false), "job panic");
    }));
    assert!(unwound.is_err());
    assert!(book.get("job1").is_none());
    Ok(())
}

struct Recording(mpsc::UnboundedSender<ReportJobRequest>);

impl Reporter for Recording {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let _ = self.0.send(request);
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

#[tokio::test]
async fn a_refused_fetch_fails_the_job_with_the_fixed_reason_before_any_clone() -> TestResult {
    let (book, fake) = serve(Err(Status::failed_precondition("no github credential"))).await?;
    let dir = tempfile::tempdir()?;
    let jobs = dir.path().join("jobs");
    let (tx, mut reports) = mpsc::unbounded_channel();
    let agent = AgentRunner::new(
        RunConfig::new("claude-fake", false),
        Recording(tx),
        Redactor::default(),
    )
    .with_job_end(JobEnd::new().on_end(book.end_hook()));
    let runner = DaemonRunner::new(Workspace::new(jobs.clone()), agent, &box_name())
        .with_credentials(Arc::clone(&book));
    let (_trigger, shutdown) = Shutdown::channel();
    let result = runner
        .run(
            Job {
                repo: "file:///nonexistent".into(),
                attempt: 4,
                ..job()
            },
            shutdown,
        )
        .await;
    assert!(result.is_err());
    let mut last = None;
    while let Ok(report) = reports.try_recv() {
        last = Some(report);
    }
    let last = last.ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert_eq!(last.error.as_deref(), Some(ERR_NO_GITHUB));
    assert!(!jobs.exists() || std::fs::read_dir(&jobs)?.next().is_none());
    assert!(book.get("job1").is_none());
    let seen = fake.seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1.r#box, box_name());
    assert_eq!(seen[0].1.attempt, 4);
    Ok(())
}
