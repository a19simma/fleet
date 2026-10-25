//! The daemon claims a job from a fake `FleetWorker`, runs a fake agent in a real git repo
//! served over `file://`, and reports `SUCCEEDED` with a pull request url. Own test binary
//! because it spawns children and binds sockets.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, Job, JobState, ReportJobReply, ReportJobRequest,
};
use fleetd::{Config, run_with_env};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "daemon-test-token-0123456789";
const PR_URL: &str = "https://example.invalid/pr/9";

const AGENT: &str = r#"#!/bin/sh
echo '{"type":"assistant","message":{"content":[{"type":"text","text":"adding the file"}]}}'
echo fake-agent-output > hello.txt
git add hello.txt
git -c user.name=t -c user.email=t@example.invalid commit -q -m "add hello.txt"
"#;

const BLOCKING_AGENT: &str = r#"#!/bin/sh
mkdir ../.finish-job1
echo '{"type":"assistant","message":{"content":[{"type":"text","text":"working"}]}}'
exec tail -f /dev/null
"#;

const GH: &str = "#!/bin/sh\necho created\necho https://example.invalid/pr/9\n";

struct Stub(Arc<Worker>);

struct Worker {
    job: Mutex<Option<Job>>,
    reports: mpsc::UnboundedSender<(String, ReportJobRequest)>,
}

fn bearer(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tonic::async_trait]
impl FleetWorker for Stub {
    async fn claim_job(
        &self,
        request: Request<ClaimJobRequest>,
    ) -> Result<Response<ClaimJobReply>, Status> {
        if bearer(request.metadata()) != format!("Bearer {TOKEN}") {
            return Err(Status::unauthenticated("bad token"));
        }
        let job = self
            .0
            .job
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(|mut job| {
                job.r#box = request.into_inner().r#box;
                job
            });
        Ok(Response::new(ClaimJobReply {
            lease_s: 60,
            next_in_s: if job.is_some() { 0 } else { 60 },
            job,
        }))
    }

    async fn report_job(
        &self,
        request: Request<ReportJobRequest>,
    ) -> Result<Response<ReportJobReply>, Status> {
        let auth = bearer(request.metadata());
        let _ = self.0.reports.send((auth, request.into_inner()));
        Ok(Response::new(ReportJobReply::default()))
    }
}

fn script(dir: &Path, name: &str, body: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = dir.join(name);
    std::fs::write(&path, body)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn git(dir: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()?;
    assert!(out.status.success());
    Ok(String::from_utf8(out.stdout)?)
}

struct Launched {
    inbox: mpsc::UnboundedReceiver<(String, ReportJobRequest)>,
    stop: oneshot::Sender<()>,
    daemon: tokio::task::JoinHandle<Result<(), fleetd::Error>>,
    server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    origin: std::path::PathBuf,
    box_name: String,
}

async fn launch(dir: &TempDir, agent: &str) -> Result<Launched, Box<dyn std::error::Error>> {
    let origin = dir.path().join("origin.git");
    let seed = dir.path().join("seed");
    std::fs::create_dir(&origin)?;
    std::fs::create_dir(&seed)?;
    git(&origin, &["init", "--bare", "--quiet", "-b", "main"])?;
    git(&seed, &["init", "--quiet", "-b", "main"])?;
    std::fs::write(seed.join("a.txt"), "a")?;
    git(&seed, &["add", "."])?;
    git(&seed, &["commit", "--quiet", "-m", "seed"])?;
    git(
        &seed,
        &["push", "--quiet", &origin.to_string_lossy(), "main"],
    )?;
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin)?;
    let claude = script(&bin, "claude", agent)?;
    let gh = script(&bin, "gh", GH)?;

    let (reports, inbox) = mpsc::unbounded_channel();
    let worker = Arc::new(Worker {
        job: Mutex::new(Some(Job {
            job_id: "job1".into(),
            prompt: "add hello.txt".into(),
            repo: format!("file://{}", origin.display()),
            base_ref: "main".into(),
            open_pr: true,
            attempt: 1,
            ..Job::default()
        })),
        reports,
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetWorkerServer::new(Stub(Arc::clone(&worker))))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    let box_name = format!("box-{}", 7);
    let file = format!(
        "http_port = 0\nsocket_path = {:?}\ndb_path = {:?}\njobs_dir = {:?}\nbox_name = {box_name:?}\nclaude_bin = {:?}\ngh_bin = {:?}\nsecrets_file = {:?}\n",
        dir.path().join("fleetd.sock").to_string_lossy(),
        dir.path().join("queue.db").to_string_lossy(),
        dir.path().join("jobs").to_string_lossy(),
        claude.to_string_lossy(),
        gh.to_string_lossy(),
        dir.path().join("secrets.env").to_string_lossy(),
    );
    std::fs::write(dir.path().join("secrets.env"), "")?;
    let mut config = Config::resolve(Some(&file), &|_| None)?;
    config.allow_file_repos = true;
    config.repo_hosts.clear();
    let env = move |name: &str| match name {
        "FLEET_SERVER_URL" => Some(url.clone()),
        "FLEET_TOKEN" => Some(TOKEN.to_owned()),
        _ => None,
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let daemon = tokio::spawn(async move {
        run_with_env(config, &env, async {
            let _ = stopped.await;
        })
        .await
    });
    Ok(Launched {
        inbox,
        stop,
        daemon,
        server,
        origin,
        box_name,
    })
}

#[tokio::test]
async fn the_daemon_runs_a_claimed_job_to_a_pushed_branch_and_a_pull_request() -> TestResult {
    let dir = TempDir::new()?;
    let Launched {
        mut inbox,
        stop,
        daemon,
        server,
        origin,
        box_name,
    } = launch(&dir, AGENT).await?;

    let terminal = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some((auth, report)) = inbox.recv().await {
            assert_eq!(auth, format!("Bearer {TOKEN}"));
            if report.terminal_state.is_some() {
                return Some(report);
            }
        }
        None
    })
    .await?
    .ok_or("no terminal report")?;
    assert_eq!(terminal.job_id, "job1");
    assert_eq!(terminal.r#box, box_name);
    assert_eq!(terminal.attempt, 1);
    assert_eq!(terminal.terminal_state, Some(JobState::Succeeded.into()));
    assert_eq!(terminal.pr_url.as_deref(), Some(PR_URL));
    assert_eq!(terminal.branch.as_deref(), Some("swarm/job1"));
    assert_eq!(
        git(&origin, &["show", "swarm/job1:hello.txt"])?.trim(),
        "fake-agent-output"
    );

    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(30), daemon).await???;
    server.abort();
    assert!(!dir.path().join("jobs").join("job1").exists());
    assert!(!dir.path().join("jobs").join(".finish-job1").exists());
    assert!(dir.path().join("jobs").join(".cache").is_dir());
    Ok(())
}

#[tokio::test]
async fn a_job_cut_short_by_shutdown_still_loses_its_worktree_and_scratch() -> TestResult {
    let dir = TempDir::new()?;
    let Launched {
        mut inbox,
        stop,
        daemon,
        server,
        ..
    } = launch(&dir, BLOCKING_AGENT).await?;

    tokio::time::timeout(Duration::from_secs(60), inbox.recv())
        .await?
        .ok_or("no report")?;
    let jobs = dir.path().join("jobs");
    assert!(jobs.join("job1").is_dir());
    assert!(jobs.join(".finish-job1").is_dir());

    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(30), daemon).await???;
    server.abort();
    assert!(!jobs.join("job1").exists());
    assert!(!jobs.join(".finish-job1").exists());
    Ok(())
}
