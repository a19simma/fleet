//! The `GetJobCredentials` client and the credential holder against a fake in-process
//! `FleetWorker` on a loopback port. Own test binary because it binds sockets.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT_CAP, PRECONDITION_APP_MINT_RATE,
    PRECONDITION_APP_REPO, PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
    PRECONDITION_NOT_CONFIGURED,
};
use fleetd::DaemonRunner;
use fleetd::cred::{
    Clock, CredentialBook, CredentialClient, CredentialFailure, ERR_APP_IDENTITY_INVALID,
    ERR_APP_IDENTITY_MISSING, ERR_APP_INSTALLATION, ERR_APP_REPO, ERR_EXPIRED, ERR_LEASE,
    ERR_MALFORMED, ERR_MINT_CAP, ERR_NO_AGENT, ERR_NO_GITHUB, ERR_NOT_CONFIGURED, ERR_RATE_LIMITED,
    ERR_UNAVAILABLE, REFRESH_SKEW_MS, REFRESH_SKEW_SLACK_MS,
};
use fleetd::poller::{JobRunner, Shutdown, channel};
use fleetd::revoke::{RevokeError, Revoker};
use fleetd::runner::{AgentRunner, JobEnd, Reporter, RunConfig};
use fleetd::workspace::Workspace;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    gate_job: Mutex<Option<String>>,
    release: Notify,
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
        let job_id = request.get_ref().job_id.clone();
        self.0
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((auth, request.into_inner()));
        self.0.mark("credentials");
        self.0.started.notify_one();
        let gated = self
            .0
            .gate_job
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            == Some(job_id.as_str());
        if gated {
            self.0.release.notified().await;
        }
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
            Status::failed_precondition(PRECONDITION_APP_INSTALLATION),
            CredentialFailure::InstallationRefused,
            ERR_APP_INSTALLATION,
        ),
        (
            Status::failed_precondition(PRECONDITION_APP_REPO),
            CredentialFailure::RepoRefused,
            ERR_APP_REPO,
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
    assert_eq!(distinct.len(), 8);
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
const APP_TOKEN_2: &str = "ghs_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210";
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

fn app_without_expiry() -> JobCredential {
    let mut app = app_wire(APP_TOKEN, BOT_NAME, BOT_EMAIL);
    app.expires_at_ms = None;
    app
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
        vec![app_without_expiry(), agent_wire()],
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
        CredentialFailure::InstallationRefused,
        CredentialFailure::RepoRefused,
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

const NEW_TOKEN: &str = "ghs_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210";
const MINUTE_MS: u64 = 60_000;
const NOW_MS: u64 = 1_800_000_000_000;

#[derive(Debug)]
struct TestClock(AtomicU64);

impl TestClock {
    fn at(ms: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(ms)))
    }

    fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn app_reply(token: &str, expires_ms: Option<u64>) -> GetJobCredentialsReply {
    let mut app = app_wire(token, BOT_NAME, BOT_EMAIL);
    app.expires_at_ms = expires_ms;
    GetJobCredentialsReply {
        credentials: vec![app, agent_wire()],
    }
}

fn set_reply(fake: &Fake, reply: Result<GetJobCredentialsReply, Status>) {
    *fake.reply.lock().unwrap_or_else(PoisonError::into_inner) = Some(reply);
}

fn calls(fake: &Fake) -> usize {
    fake.seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len()
}

async fn held_app(
    expires_in_ms: u64,
) -> Result<(Arc<CredentialBook>, Arc<Fake>, Arc<TestClock>), Box<dyn std::error::Error>> {
    let (url, fake) = spawn_fake(Ok(app_reply(APP_TOKEN, Some(NOW_MS + expires_in_ms)))).await?;
    let clock = TestClock::at(NOW_MS);
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = Arc::new(CredentialBook::new(client).with_clock(clock.clone()));
    book.fetch("job1", 4, &box_name()).await?;
    Ok((book, fake, clock))
}

fn github_text(book: &CredentialBook) -> Option<String> {
    let held = book.get("job1")?;
    String::from_utf8(held.github()?.expose().to_vec()).ok()
}

#[tokio::test]
async fn exactly_ten_minutes_left_is_not_due() -> TestResult {
    let (book, fake, _clock) = held_app(10 * MINUTE_MS).await?;
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 1);
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    Ok(())
}

#[tokio::test]
async fn one_second_over_the_window_is_not_due() -> TestResult {
    let (book, fake, _clock) = held_app(10 * MINUTE_MS + 1000).await?;
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 1);
    Ok(())
}

#[tokio::test]
async fn one_second_under_the_window_refreshes_once_and_swaps_the_token() -> TestResult {
    let (book, fake, _clock) = held_app(10 * MINUTE_MS - 1000).await?;
    set_reply(
        &fake,
        Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    let fresh = book.refresh_if_due("job1").await?.ok_or("not refreshed")?;
    assert_eq!(
        fresh.github().map(Secret::expose),
        Some(NEW_TOKEN.as_bytes())
    );
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    assert_eq!(calls(&fake), 2);
    let (second_attempt, second_box) = {
        let sent = fake.seen.lock().unwrap_or_else(PoisonError::into_inner);
        (sent[1].1.attempt, sent[1].1.r#box.clone())
    };
    assert_eq!(second_attempt, 4);
    assert_eq!(second_box, box_name());
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 2);
    let identity = fresh.git_identity().ok_or("identity")?;
    assert_eq!(identity.name(), BOT_NAME);
    assert_eq!(
        fresh
            .get(CredentialKind::AnthropicApiKey)
            .map(Secret::expose),
        Some(AGENT.as_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn the_new_token_is_masked_and_the_old_one_stays_masked() -> TestResult {
    let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
    let old = book.get("job1").ok_or("held")?;
    set_reply(
        &fake,
        Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    let fresh = book.refresh_if_due("job1").await?.ok_or("not refreshed")?;
    let text = format!("a {APP_TOKEN} b {NEW_TOKEN}");
    let merged = old.redactor().merged(&fresh.redactor());
    assert_eq!(merged.redact_str(&text), "a [REDACTED] b [REDACTED]");
    assert_eq!(
        fresh.redactor().redact_str(&text),
        "a [REDACTED] b [REDACTED]"
    );
    Ok(())
}

#[tokio::test]
async fn the_mint_cap_fails_the_step_with_the_fixed_reason_and_is_not_retried() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(
        &fake,
        Err(Status::failed_precondition(PRECONDITION_APP_MINT_CAP)),
    );
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::MintCap));
    assert_eq!(CredentialFailure::MintCap.reason(), ERR_MINT_CAP);
    assert_eq!(ERR_MINT_CAP, PRECONDITION_APP_MINT_CAP);
    assert_eq!(calls(&fake), 2);
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    clock.set(NOW_MS + 31_000);
    let again = book.refresh_if_due("job1").await;
    assert_eq!(again.err(), Some(CredentialFailure::MintCap));
    Ok(())
}

#[tokio::test]
async fn an_expired_refusal_keeps_the_last_good_token_while_it_lasts() -> TestResult {
    let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(
        &fake,
        Err(Status::failed_precondition(PRECONDITION_EXPIRED)),
    );
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    assert_eq!(calls(&fake), 2);
    Ok(())
}

#[tokio::test]
async fn a_mint_failure_keeps_the_last_good_token_until_it_expires() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(
        &fake,
        Err(Status::failed_precondition(
            fleet_proto::PRECONDITION_APP_MINT,
        )),
    );
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    assert_eq!(calls(&fake), 2);
    clock.set(NOW_MS + 29_999);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 2);
    clock.set(NOW_MS + 30_000);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 3);
    clock.set(NOW_MS + 5 * MINUTE_MS - 1);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    clock.set(NOW_MS + 5 * MINUTE_MS);
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Unavailable));
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    set_reply(
        &fake,
        Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 90 * MINUTE_MS))),
    );
    clock.set(NOW_MS + 6 * MINUTE_MS);
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_refresh_during_backoff_after_expiry_fails_without_a_call() -> TestResult {
    let (book, fake, clock) = held_app(10_000).await?;
    set_reply(&fake, Err(Status::unavailable("down")));
    assert!(book.refresh_if_due("job1").await?.is_none());
    clock.set(NOW_MS + 10_000);
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Unavailable));
    assert_eq!(calls(&fake), 2);
    Ok(())
}

#[tokio::test]
async fn every_non_transient_refusal_fails_the_step_and_keeps_the_held_token() -> TestResult {
    for (status, want) in [
        (
            Status::permission_denied("x"),
            CredentialFailure::LeaseMismatch,
        ),
        (
            Status::failed_precondition(PRECONDITION_NO_GITHUB),
            CredentialFailure::NoGithub,
        ),
        (
            Status::failed_precondition(PRECONDITION_NO_AGENT),
            CredentialFailure::NoAgent,
        ),
        (
            Status::failed_precondition(PRECONDITION_APP_INSTALLATION),
            CredentialFailure::InstallationRefused,
        ),
        (
            Status::failed_precondition(PRECONDITION_APP_REPO),
            CredentialFailure::RepoRefused,
        ),
    ] {
        let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
        set_reply(&fake, Err(status));
        assert_eq!(book.refresh_if_due("job1").await.err(), Some(want));
        assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    }
    Ok(())
}

#[tokio::test]
async fn a_refreshed_token_without_an_expiry_is_refused_and_the_old_token_stays() -> TestResult {
    let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(&fake, Ok(app_reply(NEW_TOKEN, None)));
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Malformed));
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_refreshed_expiry_in_the_past_is_clock_skew_and_the_new_token_is_taken() -> TestResult {
    for expiry in [NOW_MS + 1, NOW_MS, NOW_MS - 1, 0] {
        let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
        set_reply(&fake, Ok(app_reply(NEW_TOKEN, Some(expiry))));
        assert!(book.refresh_if_due("job1").await?.is_some(), "{expiry}");
        assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    }
    Ok(())
}

async fn skewed(
    ahead_ms: u64,
) -> Result<(Arc<CredentialBook>, Arc<Fake>, Arc<TestClock>), Box<dyn std::error::Error>> {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(
        &fake,
        Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    clock.set(NOW_MS + ahead_ms);
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(calls(&fake), 2);
    Ok((book, fake, clock))
}

#[tokio::test]
async fn a_clock_ahead_of_the_server_does_not_burn_the_mint_cap_or_fail_a_step() -> TestResult {
    for ahead in [55 * MINUTE_MS, 2 * 60 * MINUTE_MS, 10 * 24 * 60 * MINUTE_MS] {
        let (book, fake, clock) = skewed(ahead).await?;
        for later in [0, 1000, 31_000, 10 * MINUTE_MS, REFRESH_SKEW_MS - 1] {
            clock.set(NOW_MS + ahead + later);
            assert!(
                book.refresh_if_due("job1").await?.is_none(),
                "{ahead} {later}"
            );
        }
        assert_eq!(calls(&fake), 2, "{ahead}");
        assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    }
    Ok(())
}

#[tokio::test]
async fn a_skewed_clock_refreshes_by_elapsed_time_every_skew_interval() -> TestResult {
    let ahead = 2 * 60 * MINUTE_MS;
    let (book, fake, clock) = skewed(ahead).await?;
    set_reply(
        &fake,
        Ok(app_reply(APP_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    clock.set(NOW_MS + ahead + REFRESH_SKEW_MS);
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(calls(&fake), 3);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 3);
    Ok(())
}

#[tokio::test]
async fn a_clock_stepped_back_does_not_leave_a_skewed_entry_waiting_past_the_skew_interval()
-> TestResult {
    let ahead = 2 * 60 * MINUTE_MS;
    let (book, fake, clock) = skewed(ahead).await?;
    set_reply(
        &fake,
        Ok(app_reply(APP_TOKEN, Some(NOW_MS + 120 * MINUTE_MS))),
    );
    clock.set(NOW_MS + 55 * MINUTE_MS);
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(calls(&fake), 3);
    Ok(())
}

#[tokio::test]
async fn a_skewed_entry_keeps_its_token_through_a_transient_failure() -> TestResult {
    let ahead = 2 * 60 * MINUTE_MS;
    let (book, fake, clock) = skewed(ahead).await?;
    set_reply(&fake, Err(Status::unavailable("down")));
    clock.set(NOW_MS + ahead + REFRESH_SKEW_MS);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 3);
    clock.set(NOW_MS + ahead + REFRESH_SKEW_MS + 1000);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 3);
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn an_allowlist_refusal_on_refresh_fails_the_step_with_its_reason_and_is_not_retried()
-> TestResult {
    for (status, want, reason) in [
        (
            Status::failed_precondition(PRECONDITION_APP_INSTALLATION),
            CredentialFailure::InstallationRefused,
            ERR_APP_INSTALLATION,
        ),
        (
            Status::failed_precondition(PRECONDITION_APP_REPO),
            CredentialFailure::RepoRefused,
            ERR_APP_REPO,
        ),
    ] {
        let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
        set_reply(&fake, Err(status));
        let got = book.refresh_if_due("job1").await.err();
        assert_eq!(got, Some(want));
        assert_eq!(got.map(CredentialFailure::reason), Some(reason));
        assert_eq!(calls(&fake), 2);
        clock.set(NOW_MS + 10_000);
        assert_eq!(book.refresh_if_due("job1").await.err(), Some(want));
        assert_eq!(calls(&fake), 2);
        clock.set(NOW_MS + 10 * MINUTE_MS);
        assert_eq!(book.refresh_if_due("job1").await.err(), Some(want));
        assert_eq!(calls(&fake), 2);
        assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    }
    Ok(())
}

#[tokio::test]
async fn a_skewed_entry_past_its_bound_with_the_server_down_reports_expired() -> TestResult {
    let ahead = 2 * 60 * MINUTE_MS;
    let bound = ahead + REFRESH_SKEW_MS + REFRESH_SKEW_SLACK_MS;
    let (book, fake, clock) = skewed(ahead).await?;
    set_reply(&fake, Err(Status::unavailable("down")));
    clock.set(NOW_MS + bound - 1);
    assert!(book.refresh_if_due("job1").await?.is_none());
    clock.set(NOW_MS + bound + 31_000);
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Expired));
    Ok(())
}

#[tokio::test]
async fn a_skewed_entry_whose_retry_wait_is_pending_reports_expired_past_its_bound() -> TestResult {
    let ahead = 2 * 60 * MINUTE_MS;
    let bound = ahead + REFRESH_SKEW_MS + REFRESH_SKEW_SLACK_MS;
    let (book, fake, clock) = skewed(ahead).await?;
    set_reply(&fake, Err(Status::unavailable("down")));
    clock.set(NOW_MS + bound - 1000);
    assert!(book.refresh_if_due("job1").await?.is_none());
    clock.set(NOW_MS + bound);
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Expired));
    Ok(())
}

#[tokio::test]
async fn a_skewed_entry_still_fails_a_step_on_the_mint_cap() -> TestResult {
    let ahead = 2 * 60 * MINUTE_MS;
    let (book, fake, clock) = skewed(ahead).await?;
    set_reply(
        &fake,
        Err(Status::failed_precondition(PRECONDITION_APP_MINT_CAP)),
    );
    clock.set(NOW_MS + ahead + REFRESH_SKEW_MS);
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::MintCap));
    Ok(())
}

#[tokio::test]
async fn a_pat_reply_to_a_refresh_is_malformed_and_the_old_token_stays() -> TestResult {
    let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(&fake, Ok(good()));
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Malformed));
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_token_already_expired_refreshes() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(
        &fake,
        Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 200 * MINUTE_MS))),
    );
    clock.set(NOW_MS + 2 * 60 * MINUTE_MS);
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_clock_far_behind_the_token_never_refreshes() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    clock.set(0);
    assert!(book.refresh_if_due("job1").await?.is_none());
    clock.set(NOW_MS - 5 * MINUTE_MS);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 1);
    Ok(())
}

#[tokio::test]
async fn a_pat_job_and_an_unknown_job_never_refresh() -> TestResult {
    let (url, fake) = spawn_fake(Ok(good())).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = CredentialBook::new(client).with_clock(TestClock::at(u64::MAX));
    book.fetch("job1", 1, &box_name()).await?;
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert!(book.refresh_if_due("job9").await?.is_none());
    assert_eq!(calls(&fake), 1);
    Ok(())
}

#[tokio::test]
async fn two_steps_that_find_the_token_due_make_one_request() -> TestResult {
    let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(
        &fake,
        Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    let (a, b) = tokio::join!(book.refresh_if_due("job1"), book.refresh_if_due("job1"));
    assert_eq!(
        [a?.is_some(), b?.is_some()].iter().filter(|x| **x).count(),
        1
    );
    assert_eq!(calls(&fake), 2);
    Ok(())
}

#[tokio::test]
async fn a_forgotten_job_is_not_revived_by_a_refresh() -> TestResult {
    let (book, fake, _clock) = held_app(5 * MINUTE_MS).await?;
    book.forget("job1");
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 1);
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn a_first_fetch_that_hits_the_cap_maps_to_the_fixed_failure() -> TestResult {
    let (book, _fake) = serve(Err(Status::failed_precondition(PRECONDITION_APP_MINT_CAP))).await?;
    let got = book.fetch("job1", 1, &box_name()).await;
    assert_eq!(got.err(), Some(CredentialFailure::MintCap));
    assert!(book.get("job1").is_none());
    Ok(())
}

#[derive(Default)]
struct Revokes {
    seen: Mutex<Vec<(String, String)>>,
}

impl Revokes {
    fn count(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn tokens(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, auth)| auth.clone())
            .collect()
    }

    fn lines(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(line, _)| line.clone())
            .collect()
    }
}

async fn revoke_endpoint(
    status: &'static str,
    hang: bool,
) -> Result<(Revoker, Arc<Revokes>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let seen = Arc::new(Revokes::default());
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0_u8; 512];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let line = text.lines().next().unwrap_or_default().to_owned();
                let auth = text
                    .lines()
                    .find_map(|l| l.strip_prefix("authorization: "))
                    .unwrap_or_default()
                    .to_owned();
                log.seen
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((line, auth));
                if hang {
                    std::future::pending::<()>().await;
                }
                let reply =
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    Ok((
        Revoker::plain(addr).with_timeout(Duration::from_millis(500)),
        seen,
    ))
}

async fn eventually_count(revokes: &Revokes, want: usize) -> TestResult {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while revokes.count() < want {
        if std::time::Instant::now() > deadline {
            return Err(format!("waited for {want} revokes, saw {}", revokes.count()).into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn quiet(revokes: &Revokes) {
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        revokes.count(),
        0,
        "unexpected revoke: {:?}",
        revokes.lines()
    );
}

async fn revoking(
    expires_in_ms: u64,
    status: &'static str,
    hang: bool,
) -> Result<(Arc<CredentialBook>, Arc<Fake>, Arc<Revokes>), Box<dyn std::error::Error>> {
    revoking_draining(expires_in_ms, status, hang, None).await
}

async fn revoking_draining(
    expires_in_ms: u64,
    status: &'static str,
    hang: bool,
    drain_limit: Option<Duration>,
) -> Result<(Arc<CredentialBook>, Arc<Fake>, Arc<Revokes>), Box<dyn std::error::Error>> {
    let (url, fake) = spawn_fake(Ok(app_reply(APP_TOKEN, Some(NOW_MS + expires_in_ms)))).await?;
    let (endpoint, revokes) = revoke_endpoint(status, hang).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let mut book = CredentialBook::new(client)
        .with_clock(TestClock::at(NOW_MS))
        .with_revoker(Arc::new(endpoint));
    if let Some(limit) = drain_limit {
        book = book.with_drain_limit(limit);
    }
    let book = Arc::new(book);
    book.fetch("job1", 4, &box_name()).await?;
    Ok((book, fake, revokes))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "set_reply takes the stub's whole reply"
)]
fn fresh_reply() -> Result<GetJobCredentialsReply, Status> {
    Ok(app_reply(NEW_TOKEN, Some(NOW_MS + 60 * MINUTE_MS)))
}

#[tokio::test]
async fn a_refresh_revokes_the_replaced_token_and_only_that_one() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.lines(), ["DELETE /installation/token HTTP/1.1"]);
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn the_hook_runs_before_the_new_token_is_readable() -> TestResult {
    let (book, fake, _revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, fresh_reply());
    let seen = Mutex::new(None);
    book.refresh_if_due_with("job1", |fresh| {
        *seen.lock().unwrap_or_else(PoisonError::into_inner) = Some((
            github_text(&book),
            fresh.github().map(|s| s.expose().to_vec()),
        ));
    })
    .await?;
    let (readable, offered) = seen
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .ok_or("hook did not run")?;
    assert_eq!(readable.as_deref(), Some(APP_TOKEN));
    assert_eq!(offered.as_deref(), Some(NEW_TOKEN.as_bytes()));
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn the_hook_does_not_run_when_nothing_swaps() -> TestResult {
    let (book, fake, _revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, Err(Status::unavailable("down")));
    let ran = AtomicBool::new(false);
    book.refresh_if_due_with("job1", |_| ran.store(true, Ordering::SeqCst))
        .await?;
    assert!(!ran.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn a_revoke_that_answers_5xx_never_fails_the_refresh() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "503 Service Unavailable", false).await?;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    eventually_count(&revokes, 1).await?;
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_revoke_that_never_answers_does_not_hold_the_refresh() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", true).await?;
    set_reply(&fake, fresh_reply());
    let got = tokio::time::timeout(Duration::from_secs(5), book.refresh_if_due("job1")).await?;
    assert!(got?.is_some());
    eventually_count(&revokes, 1).await?;
    Ok(())
}

#[tokio::test]
async fn the_revoke_call_is_bounded_by_its_timeout() -> TestResult {
    let (endpoint, revokes) = revoke_endpoint("204 No Content", true).await?;
    let limit = Duration::from_millis(200);
    let started = std::time::Instant::now();
    let got = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.with_timeout(limit).revoke(APP_TOKEN),
    )
    .await?;
    assert_eq!(got, Err(RevokeError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(revokes.count(), 1);
    assert_eq!(fleetd::revoke::REVOKE_TIMEOUT, Duration::from_secs(10));
    Ok(())
}

#[tokio::test]
async fn the_revoke_call_reports_each_failure_without_the_token() -> TestResult {
    let (revoker, _revokes) = revoke_endpoint("204 No Content", false).await?;
    assert_eq!(revoker.revoke(APP_TOKEN).await, Ok(()));
    assert_eq!(
        revoker.revoke("ghs_bad\r\nX: y").await,
        Err(RevokeError::BadToken)
    );
    let (refusing, _) = revoke_endpoint("401 Unauthorized", false).await?;
    assert_eq!(
        refusing.revoke(APP_TOKEN).await,
        Err(RevokeError::Status(401))
    );
    let (failing, _) = revoke_endpoint("503 Service Unavailable", false).await?;
    assert_eq!(
        failing.revoke(APP_TOKEN).await,
        Err(RevokeError::Status(503))
    );
    let closed = TcpListener::bind(("127.0.0.1", 0)).await?.local_addr()?;
    assert_eq!(
        Revoker::plain(closed).revoke(APP_TOKEN).await,
        Err(RevokeError::Transport)
    );
    for err in [
        RevokeError::Timeout,
        RevokeError::Transport,
        RevokeError::Status(401),
        RevokeError::BadToken,
    ] {
        assert!(!format!("{err} {err:?}").contains(APP_TOKEN));
    }
    assert!(!format!("{revoker:?}").contains("127.0.0.1"));
    Ok(())
}

#[tokio::test]
async fn a_refresh_that_fails_never_revokes_the_last_good_token() -> TestResult {
    for failure in [
        Err(Status::unavailable("down")),
        Err(Status::failed_precondition(PRECONDITION_APP_MINT_CAP)),
        Err(Status::failed_precondition(PRECONDITION_EXPIRED)),
        Err(Status::permission_denied("lease")),
        Ok(good()),
    ] {
        let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
        set_reply(&fake, failure);
        let _ = book.refresh_if_due("job1").await;
        quiet(&revokes).await;
        assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    }
    Ok(())
}

#[tokio::test]
async fn a_refresh_that_returns_the_same_token_does_not_revoke_it() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(
        &fake,
        Ok(app_reply(APP_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    assert!(book.refresh_if_due("job1").await?.is_some());
    quiet(&revokes).await;
    Ok(())
}

#[tokio::test]
async fn the_job_end_revokes_the_held_app_token_once() -> TestResult {
    let (book, _fake, revokes) = revoking(30 * MINUTE_MS, "204 No Content", false).await?;
    let end = book.end_hook();
    end("job1");
    end("job1");
    eventually_count(&revokes, 1).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn the_job_end_after_a_refresh_revokes_the_new_token() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, fresh_reply());
    book.refresh_if_due("job1").await?;
    eventually_count(&revokes, 1).await?;
    book.end("job1");
    eventually_count(&revokes, 2).await?;
    assert_eq!(
        revokes.tokens(),
        [format!("Bearer {APP_TOKEN}"), format!("Bearer {NEW_TOKEN}")]
    );
    Ok(())
}

#[tokio::test]
async fn the_job_end_of_a_pat_job_revokes_nothing() -> TestResult {
    let (url, _fake) = spawn_fake(Ok(good())).await?;
    let (endpoint, revokes) = revoke_endpoint("204 No Content", false).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = Arc::new(CredentialBook::new(client).with_revoker(Arc::new(endpoint)));
    book.fetch("job1", 1, &box_name()).await?;
    book.end_hook()("job1");
    assert!(book.get("job1").is_none());
    quiet(&revokes).await;
    Ok(())
}

#[tokio::test]
async fn a_forget_does_not_revoke_and_an_unknown_job_end_does_nothing() -> TestResult {
    let (book, _fake, revokes) = revoking(30 * MINUTE_MS, "204 No Content", false).await?;
    book.end("job9");
    book.forget("job1");
    quiet(&revokes).await;
    Ok(())
}

#[tokio::test]
async fn a_job_that_ends_during_a_refresh_revokes_both_tokens() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, fresh_reply());
    *fake.gate_job.lock().unwrap_or_else(PoisonError::into_inner) = Some("job1".to_owned());
    let refresh = tokio::spawn({
        let book = Arc::clone(&book);
        async move { book.refresh_if_due("job1").await }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while calls(&fake) < 2 {
        assert!(std::time::Instant::now() < deadline, "refresh never called");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    book.end("job1");
    fake.release.notify_one();
    let got = tokio::time::timeout(Duration::from_secs(5), refresh).await??;
    assert!(got?.is_none());
    assert!(book.get("job1").is_none());
    eventually_count(&revokes, 2).await?;
    let mut tokens = revokes.tokens();
    tokens.sort();
    let mut want = vec![format!("Bearer {APP_TOKEN}"), format!("Bearer {NEW_TOKEN}")];
    want.sort();
    assert_eq!(tokens, want);
    Ok(())
}

#[tokio::test]
async fn a_slow_refresh_of_one_job_does_not_hold_another() -> TestResult {
    let (book, fake, _revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    book.fetch("job2", 4, &box_name()).await?;
    set_reply(&fake, fresh_reply());
    *fake.gate_job.lock().unwrap_or_else(PoisonError::into_inner) = Some("job1".to_owned());
    let slow = tokio::spawn({
        let book = Arc::clone(&book);
        async move { book.refresh_if_due("job1").await }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while calls(&fake) < 3 {
        assert!(std::time::Instant::now() < deadline, "refresh never called");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let other = tokio::time::timeout(Duration::from_secs(5), book.refresh_if_due("job2")).await?;
    assert!(other?.is_some());
    fake.release.notify_one();
    assert!(slow.await??.is_some());
    Ok(())
}

#[tokio::test]
async fn a_second_fetch_revokes_the_token_the_first_one_held() -> TestResult {
    let (book, fake, revokes) = revoking(30 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, fresh_reply());
    book.fetch("job1", 5, &box_name()).await?;
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_failed_second_fetch_still_revokes_the_token_the_first_one_held() -> TestResult {
    let (book, fake, revokes) = revoking(30 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, Err(Status::unavailable("down")));
    let got = book.fetch("job1", 5, &box_name()).await;
    assert_eq!(got.err(), Some(CredentialFailure::Unavailable));
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn a_first_fetch_and_a_pat_refetch_revoke_nothing() -> TestResult {
    let (url, _fake) = spawn_fake(Ok(good())).await?;
    let (endpoint, revokes) = revoke_endpoint("204 No Content", false).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = CredentialBook::new(client).with_revoker(Arc::new(endpoint));
    book.fetch("job1", 1, &box_name()).await?;
    book.fetch("job1", 2, &box_name()).await?;
    quiet(&revokes).await;
    Ok(())
}

#[tokio::test]
async fn a_replaced_token_is_not_revoked_while_a_child_holds_it() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    let lease = book.lease_held("job1").ok_or("no lease")?.1;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    quiet(&revokes).await;
    drop(lease);
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    Ok(())
}

#[tokio::test]
async fn a_replaced_token_waits_for_every_child_that_holds_it() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    let first = book.lease_held("job1").ok_or("no lease")?.1;
    let second = book.lease_held("job1").ok_or("no lease")?.1;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    drop(first);
    quiet(&revokes).await;
    drop(second);
    eventually_count(&revokes, 1).await?;
    Ok(())
}

#[tokio::test]
async fn a_leased_read_returns_the_token_the_lease_covers_across_a_swap() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    assert!(book.lease_held("nobody").is_none());
    let (held, lease) = book.lease_held("job1").ok_or("no lease")?;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(
        held.github().map(Secret::expose),
        Some(APP_TOKEN.as_bytes())
    );
    assert_eq!(github_text(&book).as_deref(), Some(NEW_TOKEN));
    quiet(&revokes).await;
    drop(lease);
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    Ok(())
}

#[tokio::test]
async fn a_child_started_after_the_swap_does_not_delay_the_old_revoke() -> TestResult {
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    let lease = book.lease_held("job1").ok_or("no lease")?.1;
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    drop(lease);
    Ok(())
}

#[tokio::test]
async fn a_replaced_token_is_revoked_after_the_drain_limit_when_a_child_never_ends() -> TestResult {
    let (book, fake, revokes) = revoking_draining(
        5 * MINUTE_MS,
        "204 No Content",
        false,
        Some(Duration::from_millis(150)),
    )
    .await?;
    let lease = book.lease_held("job1").ok_or("no lease")?.1;
    set_reply(&fake, fresh_reply());
    assert!(book.refresh_if_due("job1").await?.is_some());
    eventually_count(&revokes, 1).await?;
    assert_eq!(revokes.tokens(), [format!("Bearer {APP_TOKEN}")]);
    drop(lease);
    Ok(())
}

#[tokio::test]
async fn the_job_end_revokes_the_held_token_without_waiting_for_a_child() -> TestResult {
    let (book, _fake, revokes) = revoking(30 * MINUTE_MS, "204 No Content", false).await?;
    let lease = book.lease_held("job1").ok_or("no lease")?.1;
    book.end("job1");
    eventually_count(&revokes, 1).await?;
    drop(lease);
    Ok(())
}

#[tokio::test]
async fn a_lease_needs_a_held_job() -> TestResult {
    let (book, _fake, _revokes) = revoking(30 * MINUTE_MS, "204 No Content", false).await?;
    assert!(book.lease_held("job9").is_none());
    book.forget("job1");
    assert!(book.lease_held("job1").is_none());
    Ok(())
}

#[test]
fn the_request_timeout_is_the_shared_call_budget() {
    assert_eq!(fleetd::poller::REQUEST_TIMEOUT, fleet_proto::CALL_BUDGET);
}

const THIRD_TOKEN: &str = "ghs_ThirdTokenOfTheNewAttempt0123456789AB";

fn rejected_replies() -> Vec<(&'static str, CredentialFailure, GetJobCredentialsReply)> {
    let mut no_identity = app_wire(NEW_TOKEN, BOT_NAME, BOT_EMAIL);
    no_identity.git_identity = None;
    let bad_identity = app_wire(NEW_TOKEN, "bad\nname", BOT_EMAIL);
    let ok_app = app_wire(NEW_TOKEN, BOT_NAME, BOT_EMAIL);
    let two_forges = vec![
        ok_app,
        wire("github_pat", "static_secret", GITHUB),
        agent_wire(),
    ];
    vec![
        (
            "identity missing",
            CredentialFailure::AppIdentityMissing,
            GetJobCredentialsReply {
                credentials: vec![no_identity, agent_wire()],
            },
        ),
        (
            "identity invalid",
            CredentialFailure::AppIdentityInvalid,
            GetJobCredentialsReply {
                credentials: vec![bad_identity, agent_wire()],
            },
        ),
        (
            "no expiry",
            CredentialFailure::Malformed,
            app_reply(NEW_TOKEN, None),
        ),
        (
            "malformed",
            CredentialFailure::Malformed,
            GetJobCredentialsReply {
                credentials: two_forges,
            },
        ),
    ]
}

#[tokio::test]
async fn a_fetch_reply_the_client_rejects_revokes_the_app_token_it_carried() -> TestResult {
    for (name, want, reply) in rejected_replies() {
        let (url, _fake) = spawn_fake(Ok(reply)).await?;
        let (endpoint, revokes) = revoke_endpoint("204 No Content", false).await?;
        let client = CredentialClient::new(channel(&url)?, TOKEN)?;
        let book = CredentialBook::new(client).with_revoker(Arc::new(endpoint));
        let got = book.fetch("job1", 1, &box_name()).await;
        assert_eq!(got.err(), Some(want), "{name}");
        eventually_count(&revokes, 1).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(revokes.tokens(), [format!("Bearer {NEW_TOKEN}")], "{name}");
        assert!(book.get("job1").is_none(), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn a_refresh_reply_the_client_rejects_revokes_its_token_and_keeps_the_held_one() -> TestResult
{
    for (name, want, reply) in rejected_replies() {
        let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
        set_reply(&fake, Ok(reply));
        let got = book.refresh_if_due("job1").await;
        assert_eq!(got.err(), Some(want), "{name}");
        eventually_count(&revokes, 1).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(revokes.tokens(), [format!("Bearer {NEW_TOKEN}")], "{name}");
        assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn a_late_refresh_cannot_overwrite_a_refetched_entry_and_its_token_is_revoked() -> TestResult
{
    let (book, fake, revokes) = revoking(5 * MINUTE_MS, "204 No Content", false).await?;
    *fake.gate_job.lock().unwrap_or_else(PoisonError::into_inner) = Some("job1".to_owned());
    let refresh = tokio::spawn({
        let book = Arc::clone(&book);
        async move { book.refresh_if_due("job1").await }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while calls(&fake) < 2 {
        assert!(std::time::Instant::now() < deadline, "refresh never called");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    *fake.gate_job.lock().unwrap_or_else(PoisonError::into_inner) = None;
    set_reply(
        &fake,
        Ok(app_reply(THIRD_TOKEN, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    book.fetch("job1", 5, &box_name()).await?;
    set_reply(&fake, fresh_reply());
    fake.release.notify_one();
    let late = tokio::time::timeout(Duration::from_secs(5), refresh).await??;
    assert!(late?.is_none());
    assert_eq!(github_text(&book).as_deref(), Some(THIRD_TOKEN));
    eventually_count(&revokes, 2).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut tokens = revokes.tokens();
    tokens.sort();
    let mut want = vec![format!("Bearer {APP_TOKEN}"), format!("Bearer {NEW_TOKEN}")];
    want.sort();
    assert_eq!(tokens, want);
    Ok(())
}

fn rate_limited() -> Status {
    Status::failed_precondition(PRECONDITION_APP_MINT_RATE)
}

#[tokio::test]
async fn the_rate_limit_reason_is_distinct_from_the_job_cap() {
    assert_eq!(ERR_RATE_LIMITED, PRECONDITION_APP_MINT_RATE);
    assert_ne!(ERR_RATE_LIMITED, ERR_MINT_CAP);
    assert_eq!(
        CredentialFailure::RateLimited.reason(),
        PRECONDITION_APP_MINT_RATE
    );
}

#[tokio::test]
async fn a_rate_limited_refresh_keeps_the_held_token_and_backs_off() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(&fake, Err(rate_limited()));
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 2);
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    clock.set(NOW_MS + 10_000);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 2);
    clock.set(NOW_MS + 31_000);
    assert!(book.refresh_if_due("job1").await?.is_none());
    assert_eq!(calls(&fake), 3);
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_rate_limited_refresh_recovers_when_the_limit_lifts() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(&fake, Err(rate_limited()));
    assert!(book.refresh_if_due("job1").await?.is_none());
    set_reply(
        &fake,
        Ok(app_reply(APP_TOKEN_2, Some(NOW_MS + 60 * MINUTE_MS))),
    );
    clock.set(NOW_MS + 31_000);
    assert!(book.refresh_if_due("job1").await?.is_some());
    assert_eq!(github_text(&book).as_deref(), Some(APP_TOKEN_2));
    Ok(())
}

#[tokio::test]
async fn a_rate_limited_refresh_fails_the_step_once_the_token_lapsed() -> TestResult {
    let (book, fake, clock) = held_app(5 * MINUTE_MS).await?;
    set_reply(&fake, Err(rate_limited()));
    clock.set(NOW_MS + 5 * MINUTE_MS + 1000);
    let got = book.refresh_if_due("job1").await;
    assert_eq!(got.err(), Some(CredentialFailure::Unavailable));
    Ok(())
}

#[tokio::test]
async fn a_first_fetch_retries_the_rate_limit_and_then_gives_up() -> TestResult {
    let (url, fake) = spawn_fake(Err(rate_limited())).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = CredentialBook::new(client).with_rate_retry(3, Duration::from_millis(5));
    let got = book.fetch("job1", 1, &box_name()).await;
    assert_eq!(got.err(), Some(CredentialFailure::RateLimited));
    assert_eq!(calls(&fake), 4);
    assert!(book.get("job1").is_none());
    Ok(())
}

#[tokio::test]
async fn a_first_fetch_succeeds_once_the_rate_limit_lifts() -> TestResult {
    let (url, fake) = spawn_fake(Err(rate_limited())).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = CredentialBook::new(client).with_rate_retry(200, Duration::from_millis(5));
    let lifter = Arc::clone(&fake);
    tokio::spawn(async move {
        while calls(&lifter) < 3 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        set_reply(&lifter, Ok(good()));
    });
    let held =
        tokio::time::timeout(Duration::from_secs(20), book.fetch("job1", 1, &box_name())).await??;
    assert_eq!(held.github().map(Secret::expose), Some(GITHUB.as_bytes()));
    assert!(calls(&fake) >= 4);
    Ok(())
}

#[tokio::test]
async fn a_first_fetch_does_not_retry_the_job_cap() -> TestResult {
    let (url, fake) =
        spawn_fake(Err(Status::failed_precondition(PRECONDITION_APP_MINT_CAP))).await?;
    let client = CredentialClient::new(channel(&url)?, TOKEN)?;
    let book = CredentialBook::new(client).with_rate_retry(3, Duration::from_millis(5));
    let got = book.fetch("job1", 1, &box_name()).await;
    assert_eq!(got.err(), Some(CredentialFailure::MintCap));
    assert_eq!(calls(&fake), 1);
    Ok(())
}
