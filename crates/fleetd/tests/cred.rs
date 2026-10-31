//! The `GetJobCredentials` client and the credential holder against a fake in-process
//! `FleetWorker` on a loopback port. Own test binary because it binds sockets.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use std::fmt::Write as _;

use fleet_core::credential::{CredentialKind, Secret};
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, GetJobCredentialsReply, GetJobCredentialsRequest,
    GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply, GetProfileBlobRequest,
    Job, JobCredential, JobState, ProfileRef, ReportJobReply, ReportJobRequest,
};
use fleet_proto::{
    PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
    PRECONDITION_NOT_CONFIGURED,
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
use tokio::sync::{Notify, mpsc};
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
    hang: AtomicBool,
    started: Notify,
    order: Mutex<Vec<&'static str>>,
}

impl Fake {
    fn mark(&self, step: &'static str) {
        self.order
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(step);
    }

    fn steps(&self) -> Vec<&'static str> {
        self.order
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
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
        self.0.mark("credentials");
        self.0.started.notify_one();
        if self.0.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
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

async fn spawn_fake(
    reply: Result<GetJobCredentialsReply, Status>,
) -> Result<(String, Arc<Fake>), Box<dyn std::error::Error>> {
    let fake = Arc::new(Fake::default());
    *fake.reply.lock().unwrap_or_else(PoisonError::into_inner) = Some(reply);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetWorkerServer::new(Stub(Arc::clone(&fake))))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok((url, fake))
}

async fn serve(
    reply: Result<GetJobCredentialsReply, Status>,
) -> Result<(Arc<CredentialBook>, Arc<Fake>), Box<dyn std::error::Error>> {
    let (url, fake) = spawn_fake(reply).await?;
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
            Status::failed_precondition(PRECONDITION_NO_GITHUB),
            CredentialFailure::NoGithub,
            ERR_NO_GITHUB,
        ),
        (
            Status::failed_precondition(PRECONDITION_NO_AGENT),
            CredentialFailure::NoAgent,
            ERR_NO_AGENT,
        ),
        (
            Status::failed_precondition(PRECONDITION_EXPIRED),
            CredentialFailure::Expired,
            ERR_EXPIRED,
        ),
        (
            Status::failed_precondition(PRECONDITION_NOT_CONFIGURED),
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

#[tokio::test]
async fn a_failed_fetch_leaves_nothing_readable_from_an_earlier_one() -> TestResult {
    let (book, fake) = serve(Ok(good())).await?;
    book.fetch("job1", 1, &box_name()).await?;
    assert!(book.get("job1").is_some());
    *fake.reply.lock().unwrap_or_else(PoisonError::into_inner) =
        Some(Err(Status::permission_denied("lease does not match")));
    let got = book.fetch("job1", 2, &box_name()).await;
    assert_eq!(got.err(), Some(CredentialFailure::LeaseMismatch));
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn the_reply_debug_text_carries_no_value() -> TestResult {
    let reply = good();
    for text in [format!("{reply:?}"), format!("{reply:#?}")] {
        assert!(!text.contains(GITHUB), "{text}");
        assert!(!text.contains(AGENT), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }
    Ok(())
}

#[test]
fn the_precondition_messages_are_distinct_and_the_client_maps_each_one() {
    let messages = [
        (PRECONDITION_NO_GITHUB, CredentialFailure::NoGithub),
        (PRECONDITION_NO_AGENT, CredentialFailure::NoAgent),
        (PRECONDITION_EXPIRED, CredentialFailure::Expired),
        (
            PRECONDITION_NOT_CONFIGURED,
            CredentialFailure::NotConfigured,
        ),
    ];
    let distinct: std::collections::HashSet<_> = messages.iter().map(|(m, _)| m).collect();
    assert_eq!(distinct.len(), messages.len());
}

enum Renew {
    Quiet,
    Cancel,
    Lost,
}

struct Scripted {
    reports: mpsc::UnboundedSender<ReportJobRequest>,
    renew: Renew,
    fake: Arc<Fake>,
}

impl Reporter for Scripted {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let renewal = request.terminal_state.is_none();
        let _ = self.reports.send(request);
        let reply = match (&self.renew, renewal) {
            (Renew::Cancel, true) => Ok(ReportJobReply {
                cancel_requested: true,
                ..ReportJobReply::default()
            }),
            (Renew::Lost, true) => Err(Status::failed_precondition("stale")),
            _ => Ok(ReportJobReply::default()),
        };
        std::future::ready(reply)
    }

    fn profile_blob(
        &self,
        _: GetProfileBlobRequest,
    ) -> impl Future<Output = Result<GetProfileBlobReply, Status>> + Send {
        self.fake.mark("profile");
        std::future::ready(Err(Status::unavailable("no blob")))
    }
}

struct Lane {
    runner: DaemonRunner<Scripted>,
    book: Arc<CredentialBook>,
    fake: Arc<Fake>,
    reports: mpsc::UnboundedReceiver<ReportJobRequest>,
    jobs: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn lane(
    reply: Result<GetJobCredentialsReply, Status>,
    renew: Renew,
    backstop: Option<Duration>,
) -> Result<Lane, Box<dyn std::error::Error>> {
    let (url, fake) = spawn_fake(reply).await?;
    let mut client = CredentialClient::new(channel(&url)?, TOKEN)?;
    if let Some(backstop) = backstop {
        client = client.with_backstop(backstop);
    }
    let book = Arc::new(CredentialBook::new(client));
    let dir = tempfile::tempdir()?;
    let jobs = dir.path().join("jobs");
    let (tx, reports) = mpsc::unbounded_channel();
    let mut config = RunConfig::new("claude-fake", false);
    config.report_interval = Duration::from_millis(50);
    let agent = AgentRunner::new(
        config,
        Scripted {
            reports: tx,
            renew,
            fake: Arc::clone(&fake),
        },
        Redactor::default(),
    )
    .with_job_end(JobEnd::new().on_end(book.end_hook()));
    let runner = DaemonRunner::new(Workspace::new(jobs.clone()), agent, &box_name())
        .with_credentials(Arc::clone(&book));
    Ok(Lane {
        runner,
        book,
        fake,
        reports,
        jobs,
        _dir: dir,
    })
}

fn repo_job() -> Job {
    Job {
        repo: "file:///nonexistent".into(),
        ..job()
    }
}

fn drain(reports: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> Vec<ReportJobRequest> {
    let mut all = Vec::new();
    while let Ok(report) = reports.try_recv() {
        all.push(report);
    }
    all
}

fn terminal(all: &[ReportJobRequest]) -> Option<&ReportJobRequest> {
    all.iter().rev().find(|r| r.terminal_state.is_some())
}

async fn bounded<T>(work: impl Future<Output = T>) -> Result<T, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(8), work).await?)
}

#[tokio::test]
async fn run_drops_the_credentials_after_a_fetch_that_succeeded() -> TestResult {
    let mut lane = lane(Ok(good()), Renew::Quiet, None).await?;
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    assert!(result.is_err());
    assert_eq!(lane.fake.steps(), ["credentials"]);
    let all = drain(&mut lane.reports);
    let last = terminal(&all).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert!(last.error.as_deref().is_some_and(|e| e != ERR_UNAVAILABLE));
    assert!(lane.book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn run_cancels_the_job_when_cancel_arrives_during_the_fetch() -> TestResult {
    let mut lane = lane(Ok(good()), Renew::Cancel, None).await?;
    lane.fake.hang.store(true, Ordering::SeqCst);
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    assert!(result.is_err());
    let all = drain(&mut lane.reports);
    let last = terminal(&all).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Cancelled as i32));
    assert!(lane.book.get("job1").is_none());
    assert!(!lane.jobs.exists() || std::fs::read_dir(&lane.jobs)?.next().is_none());
    Ok(())
}

#[tokio::test]
async fn run_stops_without_a_terminal_report_when_the_lease_is_lost_during_the_fetch() -> TestResult
{
    let mut lane = lane(Ok(good()), Renew::Lost, None).await?;
    lane.fake.hang.store(true, Ordering::SeqCst);
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    assert!(result.is_err());
    let all = drain(&mut lane.reports);
    assert!(terminal(&all).is_none());
    assert!(lane.book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn run_fails_the_job_when_shutdown_arrives_during_the_fetch() -> TestResult {
    let mut lane = lane(Ok(good()), Renew::Quiet, None).await?;
    lane.fake.hang.store(true, Ordering::SeqCst);
    let (trigger, shutdown) = Shutdown::channel();
    let fake = Arc::clone(&lane.fake);
    let stopper = tokio::spawn(async move {
        fake.started.notified().await;
        let _ = trigger.send(true);
    });
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    stopper.abort();
    assert!(result.is_err());
    let all = drain(&mut lane.reports);
    let last = terminal(&all).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert_eq!(
        last.error.as_deref(),
        Some("agent stopped by daemon shutdown")
    );
    assert!(lane.book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn run_fails_the_job_when_a_fetch_hangs_past_the_backstop() -> TestResult {
    let mut lane = lane(Ok(good()), Renew::Quiet, Some(Duration::from_millis(100))).await?;
    lane.fake.hang.store(true, Ordering::SeqCst);
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    assert!(result.is_err());
    let all = drain(&mut lane.reports);
    let last = terminal(&all).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert_eq!(last.error.as_deref(), Some(ERR_UNAVAILABLE));
    assert!(lane.book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn run_loads_the_profile_before_it_fetches_credentials() -> TestResult {
    let mut lane = lane(Ok(good()), Renew::Quiet, None).await?;
    let (_trigger, shutdown) = Shutdown::channel();
    let job = Job {
        profile: Some(ProfileRef::default()),
        ..repo_job()
    };
    let result = bounded(Box::pin(lane.runner.run(job, shutdown))).await?;
    assert!(result.is_err());
    assert_eq!(lane.fake.steps(), ["profile"]);
    drain(&mut lane.reports);
    assert!(lane.book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn run_fetches_credentials_before_it_prepares_the_workspace() -> TestResult {
    let lane = lane(Ok(good()), Renew::Quiet, None).await?;
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    assert!(result.is_err());
    assert_eq!(lane.fake.steps(), ["credentials"]);
    Ok(())
}

#[tokio::test]
async fn a_refused_fetch_fails_the_job_with_the_fixed_reason_before_any_clone() -> TestResult {
    let mut lane = lane(
        Err(Status::failed_precondition(PRECONDITION_NO_GITHUB)),
        Renew::Quiet,
        None,
    )
    .await?;
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(
        Job {
            attempt: 4,
            ..repo_job()
        },
        shutdown,
    )))
    .await?;
    assert!(result.is_err());
    let all = drain(&mut lane.reports);
    let last = terminal(&all).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert_eq!(last.error.as_deref(), Some(ERR_NO_GITHUB));
    assert!(!lane.jobs.exists() || std::fs::read_dir(&lane.jobs)?.next().is_none());
    assert!(lane.book.get("job1").is_none());
    let seen = lane
        .fake
        .seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1.r#box, box_name());
    assert_eq!(seen[0].1.attempt, 4);
    Ok(())
}
