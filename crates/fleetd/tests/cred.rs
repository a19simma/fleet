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
    CredentialBook, CredentialClient, CredentialFailure, ERR_APP_IDENTITY_INVALID,
    ERR_APP_IDENTITY_MISSING, ERR_EXPIRED, ERR_LEASE, ERR_MALFORMED, ERR_NO_AGENT, ERR_NO_GITHUB,
    ERR_NOT_CONFIGURED, ERR_UNAVAILABLE,
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

    async fn report_shell_log(
        &self,
        _: Request<fleet_proto::v1::ReportShellLogRequest>,
    ) -> Result<Response<fleet_proto::v1::ReportShellLogReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn report_timing(
        &self,
        _: Request<fleet_proto::v1::ReportTimingRequest>,
    ) -> Result<Response<fleet_proto::v1::ReportTimingReply>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

fn wire(kind: &str, shape: &str, value: &str) -> JobCredential {
    JobCredential {
        kind: kind.into(),
        shape: shape.into(),
        value: value.into(),
        expires_at_ms: None,
        git_identity: None,
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

const APP_TOKEN: &str = "ghs_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
const BOT_NAME: &str = "fleet-bot[bot]";
const BOT_EMAIL: &str = "123456+fleet-bot[bot]@users.noreply.github.com";
const INSTALLATION_KIND: &str = "github_installation_token";

fn app_wire(value: &str, name: &str, email: &str) -> JobCredential {
    JobCredential {
        expires_at_ms: Some(1_700_000_000_000),
        git_identity: Some(fleet_proto::v1::GitIdentity {
            name: name.into(),
            email: email.into(),
        }),
        ..wire(INSTALLATION_KIND, "static_secret", value)
    }
}

fn agent_wire() -> JobCredential {
    wire("anthropic_api_key", "static_secret", AGENT)
}

async fn app_fetch(
    credentials: Vec<JobCredential>,
) -> Result<
    (
        Result<Arc<fleetd::cred::JobCredentials>, CredentialFailure>,
        Arc<CredentialBook>,
    ),
    Box<dyn std::error::Error>,
> {
    let (book, _fake) = serve(Ok(GetJobCredentialsReply { credentials })).await?;
    let got = book.fetch("job1", 1, &box_name()).await;
    Ok((got, book))
}

#[tokio::test]
async fn an_installation_token_reply_is_held_as_the_github_token_with_its_identity() -> TestResult {
    let (got, book) =
        app_fetch(vec![app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL), agent_wire()]).await?;
    let held = got?;
    assert_eq!(
        held.github().map(Secret::expose),
        Some(APP_TOKEN.as_bytes())
    );
    assert_eq!(
        held.get(CredentialKind::GithubApp).map(Secret::expose),
        Some(APP_TOKEN.as_bytes())
    );
    assert!(held.get(CredentialKind::GithubPat).is_none());
    let identity = held.git_identity().ok_or("no identity")?;
    assert_eq!(identity.name(), BOT_NAME);
    assert_eq!(identity.email(), BOT_EMAIL);
    let app = held
        .iter()
        .find(|c| c.kind() == CredentialKind::GithubApp)
        .ok_or("no app credential")?;
    assert_eq!(app.expires_at_ms(), Some(1_700_000_000_000));
    assert!(book.get("job1").is_some());
    let text = format!("{held:?}");
    assert!(!text.contains(APP_TOKEN), "{text}");
    let clean = held
        .redactor()
        .redact_str(&format!("echo GH_TOKEN={APP_TOKEN} end"))
        .into_owned();
    assert_eq!(clean, "echo GH_TOKEN=[REDACTED] end");
    Ok(())
}

#[tokio::test]
async fn a_pat_reply_holds_no_identity_and_no_expiry() -> TestResult {
    let (got, _book) = app_fetch(good().credentials).await?;
    let held = got?;
    assert!(held.git_identity().is_none());
    assert!(held.iter().all(|c| c.expires_at_ms().is_none()));
    Ok(())
}

fn hostile_names() -> Vec<String> {
    let long = format!("a{}", "b".repeat(64));
    let mut names = vec![
        String::new(),
        " bot".into(),
        "bot ".into(),
        "bot\r".into(),
        "bot\n".into(),
        "bot\r\nx".into(),
        "bo\0t".into(),
        "bot\u{85}".into(),
        "bot\u{2028}".into(),
        "bot<x>".into(),
        "<bot>".into(),
        "bot@host".into(),
        "bot\\".into(),
        "bot:x".into(),
        "bot,x".into(),
        "-bot".into(),
        "[bot".into(),
        "b\u{f6}t".into(),
        long,
    ];
    names.push(format!("{BOT_NAME}\n{BOT_NAME}"));
    names
}

fn hostile_emails() -> Vec<String> {
    let long = format!("1+{}[bot]@users.noreply.github.com", "a".repeat(110));
    vec![
        String::new(),
        BOT_EMAIL.to_uppercase(),
        format!("{BOT_EMAIL}\r"),
        format!("{BOT_EMAIL}\n"),
        format!("{BOT_EMAIL}\r\n"),
        format!(" {BOT_EMAIL}"),
        format!("{BOT_EMAIL} "),
        format!("{BOT_EMAIL}\u{85}"),
        format!("{BOT_EMAIL}\u{2028}"),
        format!("<{BOT_EMAIL}>"),
        format!("x@{BOT_EMAIL}"),
        format!("a:b@{BOT_EMAIL}"),
        BOT_EMAIL.replace('+', "\\"),
        "123456+fleet-bot[bot]@users.noreply.github.com.evil.test".into(),
        "123456+fleet-bot[bot]@users.noreply.github.co".into(),
        "+fleet-bot[bot]@users.noreply.github.com".into(),
        "12a+fleet-bot[bot]@users.noreply.github.com".into(),
        "123456+[bot]@users.noreply.github.com".into(),
        "123456+Fleet-Bot[bot]@users.noreply.github.com".into(),
        "123456+fleet\u{f6}[bot]@users.noreply.github.com".into(),
        "123456+fleet-bot@users.noreply.github.com".into(),
        long,
    ]
}

#[tokio::test]
async fn a_hostile_identity_fails_closed_with_the_fixed_reason_and_holds_nothing() -> TestResult {
    let mut cases: Vec<(String, String, &str)> = Vec::new();
    for name in hostile_names() {
        cases.push((name, BOT_EMAIL.to_owned(), "name"));
    }
    for email in hostile_emails() {
        cases.push((BOT_NAME.to_owned(), email, "email"));
    }
    assert!(cases.len() >= 40);
    for (name, email, field) in cases {
        let (got, book) = app_fetch(vec![app_wire(APP_TOKEN, &name, &email), agent_wire()]).await?;
        assert_eq!(
            got.err(),
            Some(CredentialFailure::AppIdentityInvalid),
            "{field}: {name:?} {email:?}"
        );
        assert!(book.get("job1").is_none());
    }
    assert_eq!(
        CredentialFailure::AppIdentityInvalid.reason(),
        ERR_APP_IDENTITY_INVALID
    );
    Ok(())
}

#[tokio::test]
async fn the_longest_legal_identity_passes() -> TestResult {
    let name = format!("a{}]", "b".repeat(62));
    let slug = "a".repeat(128 - "1+[bot]@users.noreply.github.com".len());
    let email = format!("1+{slug}[bot]@users.noreply.github.com");
    assert_eq!(name.len(), 64);
    assert_eq!(email.len(), 128);
    let (got, _book) = app_fetch(vec![app_wire(APP_TOKEN, &name, &email), agent_wire()]).await?;
    assert!(got.is_ok());
    Ok(())
}

#[tokio::test]
async fn an_installation_token_without_an_identity_fails_closed() -> TestResult {
    let mut app = app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL);
    app.git_identity = None;
    let (got, book) = app_fetch(vec![app, agent_wire()]).await?;
    assert_eq!(got.err(), Some(CredentialFailure::AppIdentityMissing));
    assert!(book.get("job1").is_none());
    assert_eq!(
        CredentialFailure::AppIdentityMissing.reason(),
        ERR_APP_IDENTITY_MISSING
    );
    assert_ne!(ERR_APP_IDENTITY_MISSING, ERR_APP_IDENTITY_INVALID);
    assert_ne!(ERR_APP_IDENTITY_MISSING, ERR_MALFORMED);
    Ok(())
}

#[tokio::test]
async fn a_broken_installation_token_reply_is_malformed() -> TestResult {
    let long = format!(
        "ghs_{}",
        "a".repeat(fleet_proto::MAX_CREDENTIAL_VALUE_BYTES)
    );
    let mut refreshing = app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL);
    refreshing.shape = "refreshing_file".into();
    let mut pat_identity = wire("github_pat", "static_secret", GITHUB);
    pat_identity.git_identity = app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL).git_identity;
    let replies = [
        vec![wire("github_app", "static_secret", APP_TOKEN), agent_wire()],
        vec![app_wire("ghs_short", BOT_NAME, BOT_EMAIL), agent_wire()],
        vec![app_wire(&long, BOT_NAME, BOT_EMAIL), agent_wire()],
        vec![app_wire(GITHUB, BOT_NAME, BOT_EMAIL), agent_wire()],
        vec![
            app_wire("ghs_AbCdEfGhIjKlMnOpQrSt UvWxYz0123", BOT_NAME, BOT_EMAIL),
            agent_wire(),
        ],
        vec![
            app_wire("ghs_AbCdEfGhIjKlMnOpQrStUvWx\nYz0123", BOT_NAME, BOT_EMAIL),
            agent_wire(),
        ],
        vec![refreshing, agent_wire()],
        vec![
            app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL),
            app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL),
            agent_wire(),
        ],
        vec![
            app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL),
            wire("github_pat", "static_secret", GITHUB),
            agent_wire(),
        ],
        vec![pat_identity, agent_wire()],
    ];
    for credentials in replies {
        let (got, book) = app_fetch(credentials).await?;
        assert_eq!(got.err(), Some(CredentialFailure::Malformed));
        assert!(book.get("job1").is_none());
    }
    Ok(())
}

#[tokio::test]
async fn an_installation_token_alone_still_needs_an_agent_credential() -> TestResult {
    let (got, _book) = app_fetch(vec![app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL)]).await?;
    assert_eq!(got.err(), Some(CredentialFailure::NoAgent));
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
        CredentialFailure::AppIdentityMissing,
        CredentialFailure::AppIdentityInvalid,
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
async fn run_fails_a_claude_job_with_no_claude_credential_and_never_uses_the_box_token()
-> TestResult {
    let reply = GetJobCredentialsReply {
        credentials: vec![
            wire("github_pat", "static_secret", GITHUB),
            wire("codex_api_key", "static_secret", AGENT),
        ],
    };
    let mut lane = lane(Ok(reply), Renew::Quiet, None).await?;
    let (_trigger, shutdown) = Shutdown::channel();
    let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
    assert!(result.is_err());
    assert_eq!(lane.fake.steps(), ["credentials"]);
    let all = drain(&mut lane.reports);
    let last = terminal(&all).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert_eq!(last.error.as_deref(), Some(ERR_NO_AGENT));
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

#[tokio::test]
async fn a_bad_identity_fails_the_job_with_the_fixed_reason_before_any_clone() -> TestResult {
    for (identity, reason) in [
        (Some(("bot\nname", BOT_EMAIL)), ERR_APP_IDENTITY_INVALID),
        (
            Some((BOT_NAME, "evil@example.com")),
            ERR_APP_IDENTITY_INVALID,
        ),
        (None, ERR_APP_IDENTITY_MISSING),
    ] {
        let mut app = app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL);
        app.git_identity = identity.map(|(name, email)| fleet_proto::v1::GitIdentity {
            name: name.into(),
            email: email.into(),
        });
        let mut lane = lane(
            Ok(GetJobCredentialsReply {
                credentials: vec![app, agent_wire()],
            }),
            Renew::Quiet,
            None,
        )
        .await?;
        let (_trigger, shutdown) = Shutdown::channel();
        let result = bounded(Box::pin(lane.runner.run(repo_job(), shutdown))).await?;
        assert!(result.is_err());
        let all = drain(&mut lane.reports);
        let last = terminal(&all).ok_or("no terminal report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
        assert_eq!(last.error.as_deref(), Some(reason));
        assert!(!lane.jobs.exists() || std::fs::read_dir(&lane.jobs)?.next().is_none());
        assert!(lane.book.get("job1").is_none());
        for report in &all {
            let text = format!("{report:?}");
            assert!(!text.contains(APP_TOKEN), "{text}");
        }
    }
    Ok(())
}
