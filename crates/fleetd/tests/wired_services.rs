//! Serves the three job services for real: a live job socket over the production wiring, a fake
//! peer, fake upstreams behind the injected resolver and dialer, and a job run by `DaemonRunner`.

use std::collections::BTreeSet;
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{Job, JobEventKind, ReportJobReply, ReportJobRequest};
use fleetd::agent_exec::{ForwardLimits, Forwarder};
use fleetd::connect_proxy::{ESTABLISHED, FORBIDDEN};
use fleetd::fetch::{Dialer, Resolver, tls_config_with_roots};
use fleetd::fetch_service::{FeedBook, Refusal};
use fleetd::jobsock::{
    AGENT_SLICE, JobSocket, Limits, Peer, PeerId, ServiceName, connect, read_frame, socket_path,
    write_frame,
};
use fleetd::poller::{JobRunner, RunError, Shutdown};
use fleetd::runner::{AgentProc, AgentRunner, AgentSpec, Launched, Launcher, Reporter, RunConfig};
use fleetd::workspace::{RepoPolicy, Workspace};
use fleetd::{AgentLauncher, BrokerWiring, Config, DaemonRunner, JobServices, job_services_with};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tonic::Status;

type TestResult = Result<(), Box<dyn Error>>;

const OUTER: Duration = Duration::from_secs(30);
const RUN: Duration = Duration::from_secs(90);
const ORIGIN_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const TARGET_IP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PAGE_HOST: &str = "fake.example";
const PAGE_URL: &str = "https://fake.example/page";
const PAGE_TEXT: &str = "the fixture page text";
const PRIVATE_HOST: &str = "private.example";
const PRIVATE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const GREETING: &[u8] = b"hello-from-target";
const PR_URL: &str = "https://github.com/o/r/pull/1";
const TOKEN: &str = "tok-secret-value";
const CONFIG: &str = "agent_launcher = \"systemd\"\nfetch_connect_timeout_secs = 5\negress_allow = [\"private.example\"]\n";

struct Tools {
    _dir: TempDir,
    claude: PathBuf,
    gh: PathBuf,
    gh_env: PathBuf,
}

fn tools() -> io::Result<&'static Tools> {
    static TOOLS: OnceLock<Result<Tools, String>> = OnceLock::new();
    TOOLS
        .get_or_init(|| make_tools().map_err(|err| err.to_string()))
        .as_ref()
        .map_err(|err| io::Error::other(err.clone()))
}

fn script(path: &Path, body: &str) -> io::Result<()> {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

fn make_tools() -> io::Result<Tools> {
    let dir = TempDir::new()?;
    let root = std::fs::canonicalize(dir.path())?;
    let claude = root.join("claude");
    script(
        &claude,
        "if [ \"$1\" = \"--version\" ]; then echo '2.1.289 (Claude Code)'; fi\nexit 0",
    )?;
    let gh = root.join("gh");
    let gh_env = root.join("gh.env");
    script(
        &gh,
        &format!(
            "if [ \"$1\" = pr ] && [ \"$2\" = create ]; then\nprintf '%s\\n' '{PR_URL}'\nfi\nif [ \"$1\" = pr ] && [ \"$2\" = checks ]; then\n/usr/bin/env > \"${{0%/*}}/gh.env\"\nprintf '%s' '[{{\"bucket\":\"pass\",\"name\":\"build\",\"link\":\"{PR_URL}/checks\"}}]'\nfi\nexit 0"
        ),
    )?;
    Ok(Tools {
        _dir: dir,
        claude,
        gh,
        gh_env,
    })
}

#[derive(Clone)]
struct Net {
    origin_port: u16,
    target_port: u16,
    dialed: Arc<Mutex<Vec<IpAddr>>>,
}

impl Resolver for Net {
    fn resolve(&self, host: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
        let found = match host {
            PAGE_HOST => Ok(vec![IpAddr::V4(ORIGIN_IP)]),
            "api.anthropic.com" => Ok(vec![IpAddr::V4(TARGET_IP)]),
            PRIVATE_HOST => Ok(vec![IpAddr::V4(PRIVATE_IP)]),
            _ => Err(io::Error::other("no such host")),
        };
        std::future::ready(found)
    }
}

impl Dialer for Net {
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send {
        self.dialed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(addr.ip());
        let port = match addr.ip() {
            IpAddr::V4(ip) if ip == ORIGIN_IP => Some(self.origin_port),
            IpAddr::V4(ip) if ip == TARGET_IP => Some(self.target_port),
            _ => None,
        };
        async move {
            let port = port.ok_or_else(|| io::Error::other("unexpected address"))?;
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await
        }
    }
}

async fn origin() -> Result<(u16, RootCertStore, Arc<AtomicUsize>), Box<dyn Error>> {
    let key = rcgen::generate_simple_self_signed(vec![PAGE_HOST.to_owned()])?;
    let der = key.cert.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(der.clone())?;
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der.to_vec())], private)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                    }
                }
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAGE_TEXT}",
                    PAGE_TEXT.len()
                );
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Ok((port, roots, hits))
}

async fn echo_target() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if tcp.write_all(GREETING).await.is_err() {
                    return;
                }
                let mut buf = [0_u8; 256];
                while let Ok(n @ 1..) = tcp.read(&mut buf).await {
                    if tcp
                        .write_all(buf.get(..n).unwrap_or_default())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Ok(port)
}

struct Agent(Arc<Mutex<String>>);

impl Peer for Agent {
    fn identity(&self, _: &UnixStream) -> io::Result<PeerId> {
        let id = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok(PeerId {
            pid: 7,
            cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@{id}.service\n"),
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

struct Held(Option<oneshot::Receiver<()>>);

impl AgentProc for Held {
    fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + '_>> {
        Box::pin(async {
            if let Some(rx) = self.0.as_mut() {
                let _ = rx.await;
            }
            self.0 = None;
            Ok(ExitStatus::from_raw(0))
        })
    }

    fn terminate(&mut self) {}

    fn kill(&mut self) {}
}

#[derive(Debug)]
struct Hold {
    launched: mpsc::UnboundedSender<()>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

impl Launcher for Hold {
    fn launch(&self, _spec: AgentSpec) -> io::Result<Launched> {
        let release = self
            .release
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| io::Error::other("one launch only"))?;
        let _ = self.launched.send(());
        Ok(Launched {
            stdout: Box::new(tokio::io::empty()),
            proc: Box::new(Held(Some(release))),
        })
    }
}

fn git(dir: &Path, args: &[&str]) -> io::Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@t.invalid"])
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("git {args:?}")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

struct Origin {
    dir: TempDir,
    bare: PathBuf,
}

impl Origin {
    fn new() -> io::Result<Self> {
        let dir = TempDir::new()?;
        let bare = dir.path().join("origin.git");
        std::fs::create_dir_all(&bare)?;
        git(&bare, &["init", "--bare", "-b", "main"])?;
        git(dir.path(), &["clone", &bare.display().to_string(), "seed"])?;
        let seed = dir.path().join("seed");
        git(&seed, &["commit", "--allow-empty", "-m", "init"])?;
        git(&seed, &["push", "origin", "HEAD:main"])?;
        git(&seed, &["push", "origin", "HEAD:swarm/root1"])?;
        Ok(Self { dir, bare })
    }

    fn advance(&self) -> io::Result<String> {
        let seed = self.dir.path().join("seed");
        git(&seed, &["commit", "--allow-empty", "-m", "later"])?;
        git(&seed, &["push", "origin", "HEAD:main"])?;
        git(&seed, &["rev-parse", "HEAD"])
    }

    fn repo(&self) -> String {
        format!("file://{}", self.bare.display())
    }
}

fn own_job(origin: &Origin, id: &str) -> Job {
    Job {
        job_id: id.into(),
        repo: origin.repo(),
        base_ref: "main".into(),
        attempt: 1,
        ..Job::default()
    }
}

fn chain_job(origin: &Origin, id: &str) -> Job {
    Job {
        job_id: id.into(),
        repo: origin.repo(),
        base_ref: "swarm/root1".into(),
        parent_job_id: Some("root1".into()),
        pr_url: Some(PR_URL.into()),
        attempt: 1,
        ..Job::default()
    }
}

struct Running {
    release: oneshot::Sender<()>,
    task: JoinHandle<Result<(), RunError>>,
    reports: mpsc::UnboundedReceiver<ReportJobRequest>,
}

struct World {
    origin: Origin,
    run_dir: TempDir,
    jobs: PathBuf,
    wired: JobServices<Net, Net>,
    hits: Arc<AtomicUsize>,
    dialed: Arc<Mutex<Vec<IpAddr>>>,
    runner: Arc<DaemonRunner<Recorder>>,
    who: Arc<Mutex<String>>,
    _socket: JobSocket,
    launched: mpsc::UnboundedReceiver<()>,
    release: Option<oneshot::Sender<()>>,
    reports: Option<mpsc::UnboundedReceiver<ReportJobRequest>>,
}

fn bind(
    run_dir: &Path,
    id: &str,
    wired: &JobServices<Net, Net>,
    who: Arc<Mutex<String>>,
) -> Result<JobSocket, Box<dyn Error>> {
    let path = socket_path(run_dir, id).ok_or("socket path")?;
    let parent = path.parent().ok_or("socket parent")?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    Ok(JobSocket::bind(
        &path,
        id,
        wired.services.clone(),
        Arc::new(Agent(who)),
        Limits::default(),
    )?)
}

async fn world(job_id: &str) -> Result<World, Box<dyn Error>> {
    let tools = tools()?;
    let origin_repo = Origin::new()?;
    let (origin_port, roots, hits) = origin().await?;
    let dialed = Arc::new(Mutex::new(Vec::new()));
    let net = Net {
        origin_port,
        target_port: echo_target().await?,
        dialed: Arc::clone(&dialed),
    };
    let jobs = origin_repo.dir.path().join("jobs");
    let mut config = Config::resolve(Some(CONFIG), &|_| None)?;
    config.jobs_dir.clone_from(&jobs);
    let feeds = Arc::new(FeedBook::default());
    let wired = job_services_with(
        &config,
        &feeds,
        net.clone(),
        net,
        tls_config_with_roots(roots),
    );
    let run_dir = TempDir::new()?;
    let who = Arc::new(Mutex::new(job_id.to_owned()));
    let socket = bind(run_dir.path(), job_id, &wired, Arc::clone(&who))?;
    let policy = RepoPolicy::new(Vec::<String>::new()).with_file_repos();
    let workspace = Workspace::new(jobs.clone()).with_policy(policy.clone());
    let mut run = RunConfig::new(&tools.claude, false);
    run.repo_policy = policy;
    run.gh_bin.clone_from(&tools.gh);
    run.report_interval = Duration::from_millis(50);
    run.flush_interval = Duration::from_millis(50);
    let (tx, reports) = mpsc::unbounded_channel();
    let (launched_tx, launched) = mpsc::unbounded_channel();
    let (release, release_rx) = oneshot::channel();
    let hold = Hold {
        launched: launched_tx,
        release: Mutex::new(Some(release_rx)),
    };
    let agent = AgentRunner::new(run, Recorder(tx), Redactor::default())
        .with_launcher(Arc::new(hold))
        .with_feed_book(feeds)
        .with_job_end(wired.end.clone());
    let wiring = BrokerWiring::new(
        wired.broker.clone(),
        AgentLauncher::Systemd,
        tools.gh.clone(),
        "github.com".to_owned(),
        TOKEN.to_owned(),
        Redactor::default(),
    );
    let runner = Arc::new(DaemonRunner::new(workspace, agent, "").with_broker(wiring));
    Ok(World {
        origin: origin_repo,
        run_dir,
        jobs,
        wired,
        hits,
        dialed,
        runner,
        who,
        _socket: socket,
        launched,
        release: Some(release),
        reports: Some(reports),
    })
}

impl World {
    fn sock(&self, id: &str) -> io::Result<PathBuf> {
        socket_path(self.run_dir.path(), id).ok_or_else(|| io::Error::other("socket path"))
    }

    async fn start(&mut self, job: Job) -> Result<Running, Box<dyn Error>> {
        let agent_runner = Arc::clone(&self.runner);
        let task = tokio::spawn(async move {
            let (_trigger, shutdown) = Shutdown::channel();
            agent_runner.run(job, shutdown).await
        });
        let mut task = task;
        tokio::select! {
            launched = timeout(RUN, self.launched.recv()) => {
                launched?.ok_or("the agent never launched")?;
            }
            ended = &mut task => {
                let mut seen = Vec::new();
                if let Some(reports) = self.reports.as_mut() {
                    while let Ok(r) = reports.try_recv() {
                        seen.push((r.phase, r.progress, r.error));
                    }
                }
                return Err(format!("run ended before launch: {:?} {seen:?}", ended?).into());
            }
        }
        Ok(Running {
            release: self.release.take().ok_or("started twice")?,
            task,
            reports: self.reports.take().ok_or("started twice")?,
        })
    }
}

async fn exchange(
    world: &World,
    id: &str,
    service: ServiceName,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let socket = world.sock(id)?;
    let uid = std::fs::metadata(socket.parent().ok_or_else(|| io::Error::other("parent"))?)?.uid();
    timeout(OUTER, async {
        let mut stream = connect(&socket, service, uid).await?;
        write_frame(&mut stream, request).await?;
        read_frame(&mut BufReader::new(stream)).await
    })
    .await
    .map_err(|_| io::Error::other("timed out"))?
}

/// Whether the listener closed the connection and sent no reply frame. A close with the
/// request unread surfaces as end of file on macOS and as a reset on Linux.
fn closed_without_reply(reply: &io::Result<Vec<u8>>) -> bool {
    reply.as_ref().is_err_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        )
    })
}

fn json(frame: &[u8]) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(frame)?)
}

async fn fetch_reply(world: &World, id: &str) -> io::Result<Vec<u8>> {
    exchange(
        world,
        id,
        ServiceName::Fetch,
        format!("{{\"url\":\"{PAGE_URL}\"}}").as_bytes(),
    )
    .await
}

async fn broker_reply(world: &World, id: &str, op: &str) -> io::Result<Vec<u8>> {
    exchange(
        world,
        id,
        ServiceName::Broker,
        format!("{{\"op\":\"{op}\"}}").as_bytes(),
    )
    .await
}

async fn finish(running: Running) -> TestResult {
    let _ = running.release.send(());
    timeout(RUN, running.task).await???;
    Ok(())
}

#[tokio::test]
async fn fetch_succeeds_and_reaches_the_feed() -> TestResult {
    let mut world = world("joba").await?;
    let mut running = world.start(own_job(&world.origin, "joba")).await?;
    let frame = fetch_reply(&world, "joba").await?;
    let reply = json(&frame)?;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(
        reply["body"]
            .as_str()
            .is_some_and(|body| body.contains(PAGE_TEXT)),
        "{reply}"
    );
    let seen = timeout(RUN, async {
        while let Some(report) = running.reports.recv().await {
            if report.events.iter().any(|e| {
                e.kind == JobEventKind::Fetch as i32
                    && e.cmd.as_deref().is_some_and(|c| c.contains(PAGE_URL))
            }) {
                return true;
            }
        }
        false
    })
    .await?;
    assert!(seen, "no fetch event for {PAGE_URL} reached the feed");
    finish(running).await
}

#[tokio::test]
async fn egress_proxy_tunnels_allowed_and_refuses_the_rest() -> TestResult {
    let mut world = world("joba").await?;
    let running = world.start(own_job(&world.origin, "joba")).await?;
    let socket = world.sock("joba")?;
    let uid = std::fs::metadata(socket.parent().ok_or("parent")?)?.uid();
    let forwarder = Forwarder::start(socket, uid, ForwardLimits::default())?;
    let port = forwarder.port();

    let mut tcp = timeout(OUTER, TcpStream::connect((Ipv4Addr::LOCALHOST, port))).await??;
    tcp.write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await?;
    let mut head = vec![0_u8; ESTABLISHED.len()];
    timeout(OUTER, tcp.read_exact(&mut head)).await??;
    assert_eq!(head, ESTABLISHED);
    let mut greeting = vec![0_u8; GREETING.len()];
    timeout(OUTER, tcp.read_exact(&mut greeting)).await??;
    assert_eq!(greeting, GREETING);
    tcp.write_all(b"ping-through").await?;
    let mut echoed = vec![0_u8; 12];
    timeout(OUTER, tcp.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, b"ping-through");

    for host in [PAGE_HOST, PRIVATE_HOST] {
        let mut denied = timeout(OUTER, TcpStream::connect((Ipv4Addr::LOCALHOST, port))).await??;
        denied
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut reply = Vec::new();
        timeout(OUTER, denied.read_to_end(&mut reply)).await??;
        assert_eq!(reply, FORBIDDEN, "{host}");
    }
    let dialed = world
        .dialed
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(
        dialed,
        vec![IpAddr::V4(TARGET_IP)],
        "a refused host was dialed"
    );
    drop(forwarder);
    finish(running).await
}

#[tokio::test]
async fn broker_serves_pr_checks_and_fetch_with_a_scrubbed_env() -> TestResult {
    let mut world = world("joba").await?;
    let running = world.start(chain_job(&world.origin, "joba")).await?;
    let created = json(
        &exchange(
            &world,
            "joba",
            ServiceName::Broker,
            br#"{"op":"pr_create","title":"t","body":"b"}"#,
        )
        .await?,
    )?;
    assert_eq!(created["status"], "done", "{created}");
    let checks = json(&broker_reply(&world, "joba", "pr_checks").await?)?;
    assert_eq!(checks["status"], "done", "{checks}");
    assert!(
        checks["output"]
            .as_str()
            .is_some_and(|out| out.contains("build")),
        "{checks}"
    );
    let env = std::fs::read_to_string(&tools()?.gh_env)?;
    let names: BTreeSet<&str> = env
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, _)| k)
        .collect();
    let allowed: BTreeSet<&str> = [
        "PATH",
        "HOME",
        "XDG_CONFIG_HOME",
        "GH_CONFIG_DIR",
        "GH_TOKEN",
        "GH_HOST",
        "GH_PROMPT_DISABLED",
        "GH_NO_UPDATE_NOTIFIER",
        "NO_COLOR",
        "PWD",
        "SHLVL",
        "_",
        "OLDPWD",
    ]
    .into_iter()
    .collect();
    let extra: Vec<_> = names.difference(&allowed).collect();
    assert!(extra.is_empty(), "leaked env: {extra:?}");
    assert!(env.contains(&format!("GH_TOKEN={TOKEN}")) && env.contains("GH_HOST=github.com"));
    let advanced = world.origin.advance()?;
    let fetched = json(&broker_reply(&world, "joba", "fetch").await?)?;
    assert_eq!(fetched["status"], "done", "{fetched}");
    let mut mirrors = Vec::new();
    for entry in std::fs::read_dir(world.jobs.join(".cache"))? {
        let path = entry?.path();
        if path.is_dir() && git(&path, &["for-each-ref"]).is_ok_and(|r| r.contains(&advanced)) {
            mirrors.push(path);
        }
    }
    assert_eq!(mirrors.len(), 1, "mirror lacking {advanced}: {mirrors:?}");
    finish(running).await
}

#[tokio::test]
async fn another_jobs_entry_is_refused() -> TestResult {
    let mut world = world("joba").await?;
    let running = world.start(own_job(&world.origin, "joba")).await?;
    let other = bind(
        world.run_dir.path(),
        "jobb",
        &world.wired,
        Arc::new(Mutex::new(String::from("jobb"))),
    )?;
    let reply = broker_reply(&world, "jobb", "pr_checks").await;
    assert!(closed_without_reply(&reply), "jobb used the broker of joba");
    let theirs = json(&fetch_reply(&world, "jobb").await?)?;
    assert_eq!(theirs["status"], "error", "{theirs}");
    assert_eq!(theirs["error"], Refusal::NotRecorded.message(), "{theirs}");
    assert_eq!(
        world.hits.load(Ordering::SeqCst),
        0,
        "jobb reached the origin"
    );
    let spoof = bind(
        world.run_dir.path(),
        "jobc",
        &world.wired,
        Arc::clone(&world.who),
    )?;
    let reply = exchange(
        &world,
        "jobc",
        ServiceName::Broker,
        b"{\"op\":\"pr_checks\"}",
    )
    .await;
    assert!(
        closed_without_reply(&reply),
        "joba identity served on jobc socket"
    );
    drop((other, spoof));
    finish(running).await
}

#[tokio::test]
async fn reconnect_after_job_end_closes_without_reply() -> TestResult {
    let mut world = world("joba").await?;
    let running = world.start(own_job(&world.origin, "joba")).await?;
    let live = json(&fetch_reply(&world, "joba").await?)?;
    assert_eq!(live["status"], "ok", "{live}");
    finish(running).await?;
    let reached = world.hits.load(Ordering::SeqCst);
    let reply = broker_reply(&world, "joba", "pr_checks").await;
    assert!(closed_without_reply(&reply), "broker replied after end");
    let after = json(&fetch_reply(&world, "joba").await?)?;
    assert_eq!(after["status"], "error", "{after}");
    assert_eq!(after["error"], Refusal::NotRecorded.message(), "{after}");
    assert_eq!(
        world.hits.load(Ordering::SeqCst),
        reached,
        "origin reached after end"
    );
    Ok(())
}
