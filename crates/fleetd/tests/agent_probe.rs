//! Mock Codex and Kimi CLIs run through the live egress proxy with a stored per-user credential
//! (CRED-65). Own test binary because it spawns children and binds sockets.
//!
//! The mocks are shell scripts shaped from the ADR-0044 runner contract: argv, environment names
//! and the model host. They check the contract, then tunnel through `HTTPS_PROXY` to a fake model
//! host that records what it receives. They stand in for the real CLIs, whose flags, variable
//! names, hosts and key prefixes stay unverified until CRED-65L.

use std::error::Error;
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, GetJobCredentialsReply, GetJobCredentialsRequest,
    GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply, GetProfileBlobRequest,
    Job, JobCredential, ReportJobReply, ReportJobRequest,
};
use fleetd::agent_exec::{ForwardLimits, Forwarder};
use fleetd::cred::{CredentialBook, CredentialClient};
use fleetd::fetch::{Dialer, Resolver, tls_config_with_roots};
use fleetd::fetch_service::FeedBook;
use fleetd::jobsock::{AGENT_SLICE, JobSocket, Limits, Peer, PeerId, socket_path};
use fleetd::poller::{Shutdown, channel};
use fleetd::runner::{
    AgentOutcome, AgentRunner, AgentSpec, DirectLauncher, Launched, Launcher, Reporter, RunConfig,
};
use fleetd::{Config, job_services_with};
use rustls::RootCertStore;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[path = "common/bounded.rs"]
mod common;
#[path = "common/logs.rs"]
mod logs;

type TestResult = Result<(), Box<dyn Error>>;

const JOB: &str = "job1";
const FLEET_TOKEN: &str = "probe-fleet-token-0123456789";
const GITHUB: &str = "probe-github-value-0123456789abcdef";
const CODEX_KEY: &str = "probe-codex-key-value-0123456789abcdef";
const KIMI_KEY: &str = "sk-kimi-probe-key-value-0123456789abcdef";
const CODEX_HOST: &str = "api.openai.com";
const KIMI_HOST: &str = "api.kimi.ai";
const TARGET_IP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const CONFIG: &str = "agent_launcher = \"systemd\"\nfetch_connect_timeout_secs = 5\negress_allow = [\"api.openai.com\", \"api.kimi.ai\"]\n";

const PROXY_STEP: &str = r#"
probe_proxy() {
  perl -e '
use IO::Socket::INET;
my ($target, $var) = @ARGV;
$ENV{HTTPS_PROXY} =~ m{^http://([^:]+):(\d+)$} or exit 4;
my $s = IO::Socket::INET->new(PeerAddr => $1, PeerPort => $2, Timeout => 10) or exit 5;
$s->autoflush(1);
print $s "CONNECT $target:443 HTTP/1.1\r\nHost: $target:443\r\n\r\n";
my $head = <$s>;
defined $head && $head =~ m{^HTTP/1\.1 200} or exit 6;
while (my $line = <$s>) { last if $line =~ /^\r?\n$/ }
print $s "Bearer $ENV{$var}\n";
my $reply = <$s>;
defined $reply && $reply =~ /^ok/ or exit 7;
' "$1" "$2" || fail "proxy$?"
}
"#;

const CODEX_MOCK: &str = r#"#!/bin/sh
fail() { echo "bad:$1" >&2; exit 9; }
here=$(dirname "$0")
[ "$1" = "exec" ] || fail exec
[ "$2" = "--json" ] || fail json
for last; do :; done
[ "$last" = "reply with pong" ] || fail prompt
[ -d "$CODEX_HOME" ] || fail home
[ -f "$CODEX_HOME/config.toml" ] || fail config
[ "$CODEX_API_KEY" = "$(cat "$here/expect")" ] || fail key
[ -z "${OPENAI_API_KEY+x}" ] || fail openai
[ -z "${KIMI_MODEL_API_KEY+x}" ] || fail kimi
[ -z "${GH_TOKEN+x}" ] || fail gh
[ -z "${FLEET_TOKEN+x}" ] || fail fleet
case "$HTTPS_PROXY" in http://127.0.0.1:*) ;; *) fail proxyenv ;; esac
"#;

const KIMI_MOCK: &str = r#"#!/bin/sh
fail() { echo "bad:$1" >&2; exit 9; }
here=$(dirname "$0")
[ "$#" -eq 4 ] || fail count
[ "$1" = "-p" ] || fail p
[ "$2" = "reply with pong" ] || fail prompt
[ "$3" = "--output-format" ] || fail format
[ "$4" = "stream-json" ] || fail json
[ "$KIMI_MODEL_BASE_URL" = "https://api.kimi.ai/coding/v1" ] || fail base
[ -d "$KIMI_CODE_HOME" ] || fail home
[ "$KIMI_MODEL_API_KEY" = "$(cat "$here/expect")" ] || fail key
[ -z "${KIMI_API_KEY+x}" ] || fail legacy
[ -z "${CODEX_API_KEY+x}" ] || fail codex
[ -z "${GH_TOKEN+x}" ] || fail gh
[ -z "${FLEET_TOKEN+x}" ] || fail fleet
case "$HTTPS_PROXY" in http://127.0.0.1:*) ;; *) fail proxyenv ;; esac
"#;

struct Mock {
    _dir: TempDir,
    path: PathBuf,
}

fn mock(body: &str, step: &str, key: &str, host: &str, var: &str, name: &str) -> io::Result<Mock> {
    let dir = TempDir::new()?;
    let path = dir.path().join(name);
    let script = format!(
        "{body}{PROXY_STEP}probe_proxy {host} {var}\nprintf '{{\"mock\":\"{name}\",\"key\":\"ok\",\"proxy\":\"ok\",\"step\":\"{step}\"}}\\n'\n"
    );
    std::fs::write(&path, script)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    let expect = dir.path().join("expect");
    std::fs::write(&expect, key)?;
    std::fs::set_permissions(&expect, std::fs::Permissions::from_mode(0o600))?;
    Ok(Mock { _dir: dir, path })
}

#[derive(Clone)]
struct Net {
    target_port: u16,
}

impl Resolver for Net {
    fn resolve(&self, host: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
        let found = match host {
            CODEX_HOST | KIMI_HOST => Ok(vec![IpAddr::V4(TARGET_IP)]),
            _ => Err(io::Error::other("no such host")),
        };
        std::future::ready(found)
    }
}

impl Dialer for Net {
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send {
        let port = match addr.ip() {
            IpAddr::V4(ip) if ip == TARGET_IP => Some(self.target_port),
            _ => None,
        };
        async move {
            let port = port.ok_or_else(|| io::Error::other("unexpected address"))?;
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await
        }
    }
}

type Received = Arc<Mutex<Vec<String>>>;

async fn recording_target() -> io::Result<(u16, Received)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let received = Received::default();
    let sink = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut reader = BufReader::new(tcp);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok_and(|n| n > 0) {
                    sink.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(line.trim_end().to_owned());
                    let _ = reader.get_mut().write_all(b"ok\n").await;
                }
            });
        }
    });
    Ok((port, received))
}

struct Agent;

impl Peer for Agent {
    fn identity(&self, _: &UnixStream) -> io::Result<PeerId> {
        Ok(PeerId {
            pid: 7,
            cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@{JOB}.service\n"),
        })
    }
}

struct Recorder(mpsc::UnboundedSender<ReportJobRequest>);

impl Reporter for Recorder {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let _ = self.0.send(request);
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

#[derive(Debug)]
struct Proxied {
    port: u16,
}

impl Launcher for Proxied {
    fn launch(&self, mut spec: AgentSpec) -> io::Result<Launched> {
        let url = OsString::from(format!("http://127.0.0.1:{}", self.port));
        spec.env.insert("HTTPS_PROXY".into(), url);
        DirectLauncher.launch(spec)
    }
}

struct Worker {
    kind: &'static str,
    key: &'static str,
}

#[tonic::async_trait]
impl FleetWorker for Worker {
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
        _: Request<GetJobCredentialsRequest>,
    ) -> Result<Response<GetJobCredentialsReply>, Status> {
        let wire = |kind: &str, value: &str| JobCredential {
            kind: kind.into(),
            shape: "static_secret".into(),
            value: value.into(),
            expires_at_ms: None,
            git_identity: None,
        };
        Ok(Response::new(GetJobCredentialsReply {
            credentials: vec![wire("github_pat", GITHUB), wire(self.kind, self.key)],
        }))
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

fn box_name() -> String {
    format!("box-{}", 7)
}

struct Done {
    result: AgentOutcome,
    reports: Vec<ReportJobRequest>,
    received: Vec<String>,
    logs: String,
    book_after: bool,
}

async fn probe(
    agent: &str,
    mock: &Mock,
    kind: &'static str,
    key: &'static str,
) -> Result<Done, Box<dyn Error>> {
    let (logs, _guard) = logs::capture_logs();
    let (target_port, received) = recording_target().await?;
    let net = Net { target_port };
    let config = Config::resolve(Some(CONFIG), &|_| None)?;
    let feeds = Arc::new(FeedBook::default());
    let wired = job_services_with(
        &config,
        &feeds,
        net.clone(),
        net,
        tls_config_with_roots(RootCertStore::empty()),
    );
    let run_dir = TempDir::new()?;
    let path = socket_path(run_dir.path(), JOB).ok_or("socket path")?;
    let parent = path.parent().ok_or("socket parent")?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    let _socket = JobSocket::bind(
        &path,
        JOB,
        wired.services.clone(),
        Arc::new(Agent),
        Limits::default(),
    )?;
    let uid = std::fs::metadata(parent)?.uid();
    let forwarder = Forwarder::start(path, uid, ForwardLimits::default())?;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetWorkerServer::new(Worker { kind, key }))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let book = Arc::new(CredentialBook::new(CredentialClient::new(
        channel(&url)?,
        FLEET_TOKEN,
    )?));
    book.fetch(JOB, 1, &box_name()).await?;

    let work = TempDir::new()?;
    let mut run = RunConfig::new(&mock.path, true);
    run.codex_bin.clone_from(&mock.path);
    run.kimi_bin.clone_from(&mock.path);
    run.jobs_dir = Some(work.path().join("jobs"));
    run.flush_interval = Duration::from_millis(20);
    run.base_env = vec![
        ("PATH".into(), std::env::var_os("PATH").unwrap_or_default()),
        ("GH_TOKEN".into(), "box-gh-value".into()),
        ("FLEET_TOKEN".into(), "box-fleet-value".into()),
        ("OPENAI_API_KEY".into(), "box-openai-value".into()),
    ];
    let (tx, mut rx) = mpsc::unbounded_channel();
    let runner = AgentRunner::new(run, Recorder(tx), Redactor::default())
        .with_launcher(Arc::new(Proxied {
            port: forwarder.port(),
        }))
        .with_feed_book(feeds)
        .with_credentials(Arc::clone(&book))
        .with_job_end(wired.end.clone().on_end(book.end_hook()));
    let job = Job {
        job_id: JOB.into(),
        attempt: 1,
        r#box: box_name(),
        agent: agent.into(),
        prompt: "reply with pong".into(),
        ..Job::default()
    };
    let (_trigger, shutdown) = Shutdown::channel();
    let cwd = work.path().join("cwd");
    std::fs::create_dir_all(&cwd)?;
    let outcome = runner.run(&job, &cwd, shutdown).await?;
    runner.end_job(&job);
    drop(forwarder);
    let mut reports = Vec::new();
    while let Ok(request) = rx.try_recv() {
        reports.push(request);
    }
    let received = received
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    Ok(Done {
        result: outcome,
        reports,
        received,
        logs: logs.text(),
        book_after: book.get(JOB).is_some(),
    })
}

fn feed_text(reports: &[ReportJobRequest]) -> String {
    reports
        .iter()
        .flat_map(|r| r.chunks.iter().map(|c| c.text.as_str()))
        .collect()
}

fn assert_clean(done: &Done, key: &str, name: &str) {
    let feed = feed_text(&done.reports);
    assert!(feed.contains(&format!("\"mock\":\"{name}\"")), "{feed}");
    assert!(feed.contains("\"key\":\"ok\""), "{feed}");
    assert!(feed.contains("\"proxy\":\"ok\""), "{feed}");
    assert!(!feed.contains(key), "key reached the feed");
    assert!(
        !format!("{:?}", done.reports).contains(key),
        "key reached a report"
    );
    assert!(!done.logs.contains(key), "key reached the logs");
    assert!(
        done.reports
            .iter()
            .all(|r| r.events.iter().all(|e| !format!("{e:?}").contains(key))),
        "key reached an event"
    );
    assert_eq!(done.received, [format!("Bearer {key}")]);
    assert!(!done.book_after, "credential outlived the job");
}

#[tokio::test]
async fn a_mock_codex_job_completes_through_the_proxy_with_the_stored_key() -> TestResult {
    common::bounded(Box::pin(async {
        let mock = mock(
            CODEX_MOCK,
            "codex",
            CODEX_KEY,
            CODEX_HOST,
            "CODEX_API_KEY",
            "codex",
        )?;
        let done = probe("codex", &mock, "codex_api_key", CODEX_KEY).await?;
        assert_eq!(done.result, AgentOutcome::Succeeded, "{:?}", done.reports);
        assert_clean(&done, CODEX_KEY, "codex");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_mock_kimi_job_completes_through_the_proxy_with_the_stored_key() -> TestResult {
    common::bounded(Box::pin(async {
        let mock = mock(
            KIMI_MOCK,
            "kimi",
            KIMI_KEY,
            KIMI_HOST,
            "KIMI_MODEL_API_KEY",
            "kimi",
        )?;
        let done = probe("kimi", &mock, "kimi_membership_key", KIMI_KEY).await?;
        assert_eq!(done.result, AgentOutcome::Succeeded, "{:?}", done.reports);
        assert_clean(&done, KIMI_KEY, "kimi");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_mock_aimed_at_another_runners_host_is_refused_by_the_proxy() -> TestResult {
    common::bounded(Box::pin(async {
        let mock = mock(
            CODEX_MOCK,
            "codex",
            CODEX_KEY,
            KIMI_HOST,
            "CODEX_API_KEY",
            "codex",
        )?;
        let done = probe("codex", &mock, "codex_api_key", CODEX_KEY).await?;
        assert!(
            matches!(done.result, AgentOutcome::Failed { .. }),
            "{:?}",
            done.result
        );
        assert!(done.received.is_empty(), "{:?}", done.received);
        assert!(!feed_text(&done.reports).contains(CODEX_KEY));
        Ok(())
    }))
    .await
}
