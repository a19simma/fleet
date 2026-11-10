//! The `GetJobEnvironment` client, the denial path and the redaction of released values against
//! a fake in-process `FleetWorker` on a loopback port. Own test binary because it binds sockets.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::text::{Cap, HOSTILE_RANGES, is_hostile, sanitise_text};
use fleet_core::transcript::{Entry, parse_chunk};
use fleet_core::{PLACEHOLDER, Redactor};
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, GetJobEnvironmentReply, GetJobEnvironmentRequest,
    GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply, GetProfileBlobRequest,
    Job, JobEnvironmentSecret, JobState, ReportJobReply, ReportJobRequest,
};
use fleetd::DaemonRunner;
use fleetd::agent::notes::sanitise_note;
use fleetd::envd::{
    ERR_ENV_DENIED, EnvDenied, EnvironmentClient, MAX_REDACT_LINES, ReleasedEnvironment,
};
use fleetd::poller::{JobRunner, Shutdown, channel};
use fleetd::runner::{AgentRunner, JobEnd, Reporter, RunConfig};
use fleetd::workspace::Workspace;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};
use zeroize::ZeroizeOnDrop;

#[path = "common/logs.rs"]
mod logs;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "env-test-token-0123456789";
const BOX: &str = "lane-box";
const MARKER: &str = "zq-marker-value-4471-unlikely";
const PEM: &str = "-----BEGIN KEY-----\nAAAAbbbbCCCC\n-----END KEY-----";

#[derive(Default)]
struct Fake {
    reply: Mutex<Option<Result<GetJobEnvironmentReply, Status>>>,
    seen: Mutex<Vec<(String, GetJobEnvironmentRequest)>>,
    calls: AtomicUsize,
    hang: AtomicBool,
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

    async fn get_job_environment(
        &self,
        request: Request<GetJobEnvironmentRequest>,
    ) -> Result<Response<GetJobEnvironmentReply>, Status> {
        let auth = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        self.0
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((auth, request.into_inner()));
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

    async fn get_job_credentials(
        &self,
        _: Request<fleet_proto::v1::GetJobCredentialsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobCredentialsReply>, Status> {
        Err(Status::unimplemented("unused"))
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

fn secret(name: &str, value: &str) -> JobEnvironmentSecret {
    JobEnvironmentSecret {
        name: name.into(),
        value: value.into(),
        ..JobEnvironmentSecret::default()
    }
}

fn reply_of(secrets: Vec<JobEnvironmentSecret>) -> GetJobEnvironmentReply {
    GetJobEnvironmentReply {
        environment: "prod".into(),
        version: 1,
        secrets,
        ..GetJobEnvironmentReply::default()
    }
}

async fn spawn_fake(
    reply: Result<GetJobEnvironmentReply, Status>,
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

async fn client_of(
    reply: Result<GetJobEnvironmentReply, Status>,
) -> Result<(EnvironmentClient, Arc<Fake>), Box<dyn std::error::Error>> {
    let (url, fake) = spawn_fake(reply).await?;
    Ok((EnvironmentClient::new(channel(&url)?, TOKEN)?, fake))
}

fn denial_causes() -> Vec<Status> {
    vec![
        Status::permission_denied("lease does not match"),
        Status::permission_denied(fleet_proto::ERR_ENV_RELEASE_DENIED),
        Status::not_found(fleet_proto::ERR_ENV_NOT_FOUND),
        Status::failed_precondition(fleet_proto::ERR_ENV_SCRIPTS_NOT_GRANTED),
        Status::unavailable("storage unavailable"),
        Status::internal(MARKER),
        Status::unauthenticated("bad token"),
        Status::resource_exhausted("too big"),
    ]
}

#[tokio::test]
async fn a_fetch_sends_the_lease_and_the_bearer_and_holds_the_values() -> TestResult {
    let (client, fake) = client_of(Ok(reply_of(vec![
        secret("PVE_TOKEN", "pve-token-0123456789"),
        secret("KUBECONFIG_DATA", PEM),
    ])))
    .await?;
    let held = client.fetch("job1", 3, BOX).await?;
    assert_eq!(held.len(), 2);
    assert_eq!(held.get("PVE_TOKEN"), Some("pve-token-0123456789"));
    assert_eq!(held.get("KUBECONFIG_DATA"), Some(PEM));
    assert_eq!(held.get("OTHER"), None);
    let seen = fake.seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, format!("Bearer {TOKEN}"));
    assert_eq!(seen[0].1.job_id, "job1");
    assert_eq!(seen[0].1.attempt, 3);
    assert_eq!(seen[0].1.r#box, BOX);
    Ok(())
}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn the_held_map_prints_no_value_and_zeroes_on_wipe_and_drop() {
    assert_zeroize_on_drop::<ReleasedEnvironment>();
    let mut held = ReleasedEnvironment::from_reply(reply_of(vec![
        secret("PVE_TOKEN", MARKER),
        secret("KUBECONFIG_DATA", PEM),
    ]));
    let text = format!("{held:?}");
    assert!(!text.contains(MARKER), "{text}");
    assert!(!text.contains("AAAAbbbbCCCC"), "{text}");
    assert!(text.contains("PVE_TOKEN"), "{text}");
    assert_eq!(held.len(), 2);
    held.wipe();
    assert!(held.is_empty());
    assert_eq!(held.get("PVE_TOKEN"), None);
}

#[tokio::test]
async fn every_denial_cause_gives_the_one_fixed_error_and_no_value() -> TestResult {
    let mut texts = Vec::new();
    for status in denial_causes() {
        let (client, _fake) = client_of(Err(status)).await?;
        let denied = client.fetch("job1", 1, BOX).await.err();
        assert_eq!(denied, Some(EnvDenied));
        let denied = denied.ok_or("no error")?;
        texts.push((
            denied.to_string(),
            format!("{denied:?}"),
            denied.reason().to_owned(),
        ));
    }
    let (url, fake) = spawn_fake(Ok(reply_of(Vec::new()))).await?;
    fake.hang.store(true, Ordering::SeqCst);
    let slow =
        EnvironmentClient::new(channel(&url)?, TOKEN)?.with_backstop(Duration::from_millis(100));
    let denied = slow.fetch("job1", 1, BOX).await.err().ok_or("no error")?;
    texts.push((
        denied.to_string(),
        format!("{denied:?}"),
        denied.reason().to_owned(),
    ));
    assert!(texts.len() > 8);
    for (display, debug, reason) in &texts {
        assert_eq!(display, ERR_ENV_DENIED);
        assert_eq!(reason, ERR_ENV_DENIED);
        assert!(!debug.contains(MARKER), "{debug}");
    }
    assert_eq!(ERR_ENV_DENIED, fleet_proto::ERR_ENV_RELEASE_DENIED);
    Ok(())
}

struct Scripted {
    reports: mpsc::UnboundedSender<ReportJobRequest>,
}

impl Reporter for Scripted {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let _ = self.reports.send(request);
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

struct Lane {
    runner: DaemonRunner<Scripted>,
    fake: Arc<Fake>,
    reports: mpsc::UnboundedReceiver<ReportJobRequest>,
    jobs: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn lane(
    reply: Result<GetJobEnvironmentReply, Status>,
) -> Result<Lane, Box<dyn std::error::Error>> {
    let (url, fake) = spawn_fake(reply).await?;
    let client =
        EnvironmentClient::new(channel(&url)?, TOKEN)?.with_backstop(Duration::from_millis(500));
    let dir = tempfile::tempdir()?;
    let jobs = dir.path().join("jobs");
    let (tx, reports) = mpsc::unbounded_channel();
    let mut config = RunConfig::new("claude-fake", false);
    config.report_interval = Duration::from_millis(50);
    let agent = AgentRunner::new(config, Scripted { reports: tx }, Redactor::default());
    let runner = DaemonRunner::new(Workspace::new(jobs.clone()), agent, BOX)
        .with_environment(Arc::new(client));
    Ok(Lane {
        runner,
        fake,
        reports,
        jobs,
        _dir: dir,
    })
}

fn pinned_job() -> Job {
    Job {
        job_id: "job1".into(),
        attempt: 1,
        repo: "file:///nonexistent".into(),
        has_environment: true,
        ..Job::default()
    }
}

fn terminal(reports: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> Option<ReportJobRequest> {
    let mut last = None;
    while let Ok(report) = reports.try_recv() {
        if report.terminal_state.is_some() {
            last = Some(report);
        }
    }
    last
}

async fn run_bounded(lane: &Lane, job: Job) -> TestResult {
    let (_trigger, shutdown) = Shutdown::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(lane.runner.run(job, shutdown)),
    )
    .await?;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn a_job_without_a_pin_makes_no_call() -> TestResult {
    let mut lane = lane(Ok(reply_of(vec![secret("PVE_TOKEN", MARKER)]))).await?;
    let job = Job {
        has_environment: false,
        ..pinned_job()
    };
    run_bounded(&lane, job).await?;
    assert_eq!(lane.fake.calls.load(Ordering::SeqCst), 0);
    let last = terminal(&mut lane.reports).ok_or("no terminal report")?;
    assert_ne!(last.error.as_deref(), Some(ERR_ENV_DENIED));
    Ok(())
}

#[tokio::test]
async fn a_pinned_job_fetches_once_before_the_clone() -> TestResult {
    let mut lane = lane(Ok(reply_of(vec![secret("PVE_TOKEN", MARKER)]))).await?;
    run_bounded(&lane, pinned_job()).await?;
    assert_eq!(lane.fake.calls.load(Ordering::SeqCst), 1);
    let last = terminal(&mut lane.reports).ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
    assert_ne!(last.error.as_deref(), Some(ERR_ENV_DENIED));
    Ok(())
}

#[tokio::test]
async fn a_denied_fetch_fails_the_job_before_the_clone_with_nothing_on_disk() -> TestResult {
    let mut errors = Vec::new();
    for status in denial_causes() {
        let mut lane = lane(Err(status)).await?;
        run_bounded(&lane, pinned_job()).await?;
        assert_eq!(lane.fake.calls.load(Ordering::SeqCst), 1);
        let last = terminal(&mut lane.reports).ok_or("no terminal report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed as i32));
        errors.push(last.error.clone());
        assert!(!lane.jobs.exists() || std::fs::read_dir(&lane.jobs)?.next().is_none());
    }
    let mut hung = lane(Ok(reply_of(Vec::new()))).await?;
    hung.fake.hang.store(true, Ordering::SeqCst);
    run_bounded(&hung, pinned_job()).await?;
    let last = terminal(&mut hung.reports).ok_or("no terminal report")?;
    errors.push(last.error);
    assert!(!hung.jobs.exists() || std::fs::read_dir(&hung.jobs)?.next().is_none());
    assert!(errors.iter().all(|e| e.as_deref() == Some(ERR_ENV_DENIED)));
    Ok(())
}

fn pem_env() -> ReleasedEnvironment {
    ReleasedEnvironment::from_reply(reply_of(vec![
        secret("KUBECONFIG_DATA", PEM),
        secret("PVE_TOKEN", "pve-token-0123456789"),
    ]))
}

fn assistant_text(text: &str) -> String {
    serde_json::json!({"type": "assistant", "message": {"content": [
        {"type": "text", "text": text}
    ]}})
    .to_string()
}

fn transcript_message(redactor: &Redactor, text: &str) -> String {
    parse_chunk(&assistant_text(text), false, Some(redactor))
        .into_iter()
        .filter_map(|entry| match entry {
            Entry::Message { text, .. } => Some(text),
            _ => None,
        })
        .collect()
}

fn transcript_text(redactor: &Redactor, text: &str) -> String {
    format!(
        "{:?}",
        parse_chunk(&assistant_text(text), false, Some(redactor))
    )
}

#[test]
fn every_secret_and_every_long_line_is_registered() {
    let redaction = pem_env().redaction();
    assert!(!redaction.reduced);
    let redactor = &redaction.redactor;
    for needle in [
        PEM,
        "pve-token-0123456789",
        "-----BEGIN KEY-----",
        "AAAAbbbbCCCC",
        "-----END KEY-----",
    ] {
        assert_eq!(
            redactor.redact_str(&format!("x {needle} y")),
            format!("x {PLACEHOLDER} y"),
            "{needle}"
        );
    }
    assert_eq!(redactor.len(), 5);
}

#[test]
fn a_line_of_seven_bytes_is_not_registered() {
    let env = ReleasedEnvironment::from_reply(reply_of(vec![secret(
        "KEY",
        "AAAAbbbbCCCC\nshort77\nDDDDeeeeFFFF",
    )]));
    let redaction = env.redaction();
    assert_eq!(redaction.redactor.redact_str("a short77 b"), "a short77 b");
    assert_eq!(redaction.redactor.len(), 3);
    let eight = ReleasedEnvironment::from_reply(reply_of(vec![secret(
        "KEY",
        "AAAAbbbbCCCC\nshort778\nDDDDeeeeFFFF",
    )]));
    assert_eq!(eight.redaction().redactor.len(), 4);
}

#[test]
fn a_three_line_pem_is_masked_per_line_in_the_transcript_and_joined_on_sanitise_text() {
    let redactor = pem_env().redaction().redactor;
    let text = transcript_text(&redactor, "cat: AAAAbbbbCCCC and -----END KEY----- done");
    assert!(!text.contains("AAAAbbbbCCCC"), "{text}");
    assert!(!text.contains("END KEY"), "{text}");
    assert!(text.contains(PLACEHOLDER), "{text}");
    let whole = transcript_text(&redactor, &format!("k {PEM} k"));
    assert!(!whole.contains("AAAAbbbbCCCC"), "{whole}");
    let joined = PEM.replace('\n', "");
    let clean = sanitise_text(&redactor, &format!("k {joined} k"), Cap::Bytes(4096));
    assert!(!clean.text.contains("AAAA"), "{}", clean.text);
    assert!(!clean.text.contains("BEGIN KEY"), "{}", clean.text);
    assert!(!clean.text.contains("END KEY"), "{}", clean.text);
    assert_eq!(clean.text, format!("k {PLACEHOLDER} k"));
}

#[test]
fn the_line_limit_seam_is_tested_just_under_and_just_over() {
    assert_eq!(MAX_REDACT_LINES, 4096);
    let value = "aaaaaaaa1\nbbbbbbbb22\ncccccccc333\ndddddddd4444";
    let env = ReleasedEnvironment::from_reply(reply_of(vec![secret("KEY", value)]));
    let at = env.redaction_with_limit(4);
    assert!(!at.reduced);
    assert_eq!(at.redactor.len(), 5);
    let over = env.redaction_with_limit(3);
    assert!(over.reduced);
    assert_eq!(over.redactor.len(), 4);
    assert_eq!(over.redactor.redact_str("aaaaaaaa1"), "aaaaaaaa1");
    for kept in ["bbbbbbbb22", "cccccccc333", "dddddddd4444", value] {
        assert_eq!(over.redactor.redact_str(kept), PLACEHOLDER, "{kept}");
    }
    let none = env.redaction_with_limit(0);
    assert!(none.reduced);
    assert_eq!(none.redactor.len(), 1);
    let default = env.redaction();
    assert!(!default.reduced);
    let with_short = ReleasedEnvironment::from_reply(reply_of(vec![secret(
        "KEY",
        "aaaaaaaa1\nshort77\nbbbbbbbb22",
    )]));
    assert!(!with_short.redaction_with_limit(2).reduced);
    assert!(with_short.redaction_with_limit(1).reduced);
}

fn hostile_set() -> Vec<char> {
    let mut set: Vec<char> = (0..=0x9F_u32).filter_map(char::from_u32).collect();
    for (lo, hi) in HOSTILE_RANGES {
        set.extend((lo..=hi).filter_map(char::from_u32));
    }
    set.retain(|c| is_hostile(*c));
    set
}

#[test]
fn zwsp_split_and_newline_values_are_masked_on_the_note_and_transcript_paths() {
    let set = hostile_set();
    assert!(set.contains(&'\u{200b}'));
    assert!(set.contains(&'\n'));
    let env = ReleasedEnvironment::from_reply(reply_of(vec![secret("KEY", "abcdefgh12345678")]));
    let redactor = env.redaction().redactor;
    let survives = |c: char| transcript_message(&Redactor::default(), &format!("a{c}b")) != "ab";
    assert!(survives('\n'));
    assert!(survives('\t'));
    assert!(!survives('\u{200b}'));
    for c in &set {
        let text = format!("x abcdefgh{c}12345678 y");
        let note = sanitise_note(&text, &redactor);
        assert!(!note.contains("abcdefgh"), "{c:?}: {note}");
        assert!(!note.contains("12345678"), "{c:?}: {note}");
        if survives(*c) {
            continue;
        }
        let transcript = transcript_text(&redactor, &text);
        assert!(!transcript.contains("abcdefgh"), "{c:?}: {transcript}");
        assert!(!transcript.contains("12345678"), "{c:?}: {transcript}");
    }
    let multi = ReleasedEnvironment::from_reply(reply_of(vec![secret(
        "KEY",
        "first-line-secret\nsecond-line-secret",
    )]))
    .redaction()
    .redactor;
    for text in [
        "x first-line-secret\nsecond-line-secret y",
        "x first-line-secret\r\nsecond-line-secret y",
        "x first-line-secret\u{200b}second-line-secret y",
    ] {
        let note = sanitise_note(text, &multi);
        assert!(!note.contains("line-secret"), "{note}");
        let transcript = transcript_text(&multi, text);
        assert!(!transcript.contains("line-secret"), "{transcript}");
    }
}

#[tokio::test]
async fn no_value_reaches_tracing_on_either_path_and_the_capture_sees_the_denial() -> TestResult {
    let (logs, _guard) = logs::capture_logs();
    let mut denied = lane(Err(Status::internal(MARKER))).await?;
    run_bounded(&denied, pinned_job()).await?;
    let mut granted = lane(Ok(reply_of(vec![secret("PVE_TOKEN", MARKER)]))).await?;
    run_bounded(&granted, pinned_job()).await?;
    let _ = terminal(&mut denied.reports);
    let _ = terminal(&mut granted.reports);
    let text = logs.text();
    assert!(text.contains(ERR_ENV_DENIED), "positive control: {text}");
    assert!(!text.contains(MARKER), "{text}");
    Ok(())
}

#[derive(Debug)]
struct OnTmpfs;

impl fleetd::envd::MountCheck for OnTmpfs {
    fn is_tmpfs(&self, _dir: std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool> {
        Ok(true)
    }
}

#[tokio::test]
async fn a_delivering_runner_holds_the_fetched_values_until_the_end_hook_shreds_them() -> TestResult
{
    use fleetd::envd::{EnvDelivery, Owner};
    let (url, fake) = spawn_fake(Ok(reply_of(vec![secret("PVE_TOKEN", MARKER)]))).await?;
    let client = EnvironmentClient::new(channel(&url)?, TOKEN)?;
    let dir = tempfile::tempdir()?;
    let seen = Arc::new(Mutex::new(Vec::<bool>::new()));
    let slot: Arc<Mutex<Option<Arc<EnvDelivery>>>> = Arc::default();
    let probe = {
        let seen = Arc::clone(&seen);
        let slot = Arc::clone(&slot);
        Arc::new(move |id: &str| {
            let held = slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_some_and(|delivery| delivery.is_held(id));
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(held);
        })
    };
    let delivery = Arc::new(
        EnvDelivery::new(
            dir.path(),
            Owner {
                uid: None,
                gid: None,
            },
            Arc::new(OnTmpfs),
        )?
        .with_shred_probe(probe),
    );
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&delivery));
    let (tx, mut reports) = mpsc::unbounded_channel();
    let mut config = RunConfig::new("claude-fake", false);
    config.report_interval = Duration::from_millis(50);
    let agent = AgentRunner::new(config, Scripted { reports: tx }, Redactor::default())
        .with_job_end(JobEnd::new().on_end(delivery.end_hook()));
    let runner = DaemonRunner::new(Workspace::new(dir.path().join("jobs")), agent, BOX)
        .with_environment(Arc::new(client))
        .with_delivery(Arc::clone(&delivery));
    let (_trigger, shutdown) = Shutdown::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(runner.run(pinned_job(), shutdown)),
    )
    .await?;
    assert!(result.is_err());
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*seen.lock().unwrap_or_else(PoisonError::into_inner), [true]);
    assert!(!delivery.is_held("job1"));
    let last = terminal(&mut reports).ok_or("no terminal report")?;
    assert_ne!(last.error.as_deref(), Some(ERR_ENV_DENIED));
    Ok(())
}

#[test]
fn a_script_timeout_is_clamped_to_one_through_the_adr_maximum() {
    use fleet_proto::v1::{EnvironmentScriptSpec, GetJobEnvironmentReply};
    let reply = |timeout_s| GetJobEnvironmentReply {
        scripts: vec![EnvironmentScriptSpec {
            name: "s".to_owned(),
            body: "#!/bin/sh\n".to_owned(),
            timeout_s,
            ..EnvironmentScriptSpec::default()
        }],
        ..GetJobEnvironmentReply::default()
    };
    let got = |timeout_s| {
        ReleasedEnvironment::from_reply(reply(timeout_s)).scripts()[0]
            .timeout
            .as_secs()
    };
    assert_eq!(got(Some(0)), 1);
    assert_eq!(got(Some(1)), 1);
    assert_eq!(got(Some(600)), 600);
    assert_eq!(got(Some(601)), 600);
    assert_eq!(got(Some(u32::MAX)), 600);
    assert_eq!(got(None), 120);
}
