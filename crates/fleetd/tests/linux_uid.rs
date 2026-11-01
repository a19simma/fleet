//! Container integration suite for the real uid and directory setup (LOCAL-IT).
//!
//! Two layers share this binary. The host layer, [`container_suite_passes`], needs docker: it
//! builds an image with the users `fleetd` (986, in group `fleet-work` 987) and `fleet-job`
//! (985), compiles this binary and `fleetd` inside it, and runs the container layer there as
//! uid 986. The container layer drives the real job path (`AgentRunner` with
//! `SystemdLauncher`) against a fake `systemctl` that drops to uid 985 with `setpriv` and runs
//! `fleetd agent-exec`, so a directory a job user cannot write fails the way it does on a box.
//!
//! The host test is `#[ignore]`, so nextest and `cargo test` skip it; run
//! `mise run it:linux`. Container tests skip with a message outside the image, where
//! `/etc/fleet-it` is absent. Own test binary because it spawns children and containers.

use std::error::Error;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_core::Redactor;
use fleet_proto::v1::{Job, ReportJobReply, ReportJobRequest};
use fleetd::agent::kimi::KimiHome;
use fleetd::jobenv::share_tree;
use fleetd::poller::Shutdown;
use fleetd::runner::{AgentOutcome, AgentRunner, Reporter, RunConfig};
use fleetd::systemd::SystemdLauncher;
use tokio::sync::mpsc;
use tonic::Status;

type TestResult = Result<(), Box<dyn Error>>;

const SKIP_NO_DOCKER: &str =
    "SKIP: docker not available, run mise run it:linux with docker or colima";
const SKIP_NO_IMAGE: &str = "SKIP: not inside the fleet-it container, run mise run it:linux";
const MARKER: &str = "/etc/fleet-it";
const JOB_UID: u32 = 985;
const WORK_GID: u32 = 987;
const FLEETD_UID: u32 = 986;
const AGENT: &str = "/opt/fleet-it/agent";
const SYSTEMCTL: &str = "/opt/fleet-it/systemctl";
const JOBS: &str = "/jobs";
const RUN_DIR: &str = "/run/fleet";
const AGENT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const WIDE: Duration = Duration::from_secs(120);
const HOST_BOUND: Duration = Duration::from_secs(15 * 60);
const TAIL_LINES: usize = 80;

const DOCKERFILE: &str = include_str!("linux_uid/Dockerfile");
const SHIM: &str = include_str!("linux_uid/systemctl");
const FAKE_AGENT: &str = include_str!("linux_uid/agent");

const IN_CONTAINER_SCRIPT: &str = r#"set -eu
cd /src
cargo test --locked -p fleetd --test linux_uid --no-run --message-format=json > /tmp/build.json
exe=$(sed -n 's/.*"executable":"\([^"]*linux_uid-[^"]*\)".*/\1/p' /tmp/build.json | tail -n 1)
test -n "$exe"
install -m 0755 "$exe" /opt/fleet-it/linux_uid
install -m 0755 /target/debug/fleetd /opt/fleet-it/fleetd
exec setpriv --reuid=986 --regid=986 --groups=987 \
  env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp \
  /opt/fleet-it/linux_uid --test-threads=4
"#;

#[derive(Debug, PartialEq, Eq)]
enum HostRun {
    Skipped(&'static str),
    Passed(String),
    Failed(String),
}

fn docker_available(docker: &str) -> bool {
    Command::new(docker)
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let from = lines.len().saturating_sub(TAIL_LINES);
    lines.get(from..).unwrap_or_default().join("\n")
}

struct Cleanup {
    docker: String,
    container: String,
    image: String,
}

impl Cleanup {
    fn quiet(&self, args: &[&str]) {
        let _ = Command::new(&self.docker)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.quiet(&["rm", "-f", &self.container]);
        self.quiet(&["rmi", "-f", &self.image]);
    }
}

fn unique() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{}-{nanos}", std::process::id())
}

fn write_context(dir: &Path) -> io::Result<()> {
    for (name, body) in [
        ("Dockerfile", DOCKERFILE),
        ("systemctl", SHIM),
        ("agent", FAKE_AGENT),
    ] {
        let path = dir.join(name);
        fs::write(&path, body)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn wait_bounded(child: &mut std::process::Child, bound: Duration) -> io::Result<Option<bool>> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status.success()));
        }
        if start.elapsed() >= bound {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn run_host_suite(docker: &str, repo: &Path, bound: Duration) -> io::Result<HostRun> {
    if !docker_available(docker) {
        return Ok(HostRun::Skipped(SKIP_NO_DOCKER));
    }
    let id = unique();
    let guard = Cleanup {
        docker: docker.to_owned(),
        container: format!("fleet-it-run-{id}"),
        image: format!("fleet-it-img:{id}"),
    };
    let scratch = tempfile::tempdir()?;
    let context = scratch.path().join("context");
    fs::create_dir(&context)?;
    write_context(&context)?;
    let build_out = scratch.path().join("build.out");
    let built = Command::new(docker)
        .args(["build", "-q", "-t", &guard.image])
        .arg(&context)
        .stdin(Stdio::null())
        .stdout(File::create(&build_out)?)
        .stderr(File::create(scratch.path().join("build.err"))?)
        .status()?;
    if !built.success() {
        return Ok(HostRun::Failed(format!(
            "image build failed\n{}",
            tail(&scratch.path().join("build.err"))
        )));
    }
    let out = scratch.path().join("run.out");
    let err = scratch.path().join("run.err");
    let mut child = Command::new(docker)
        .args(["run", "--rm", "--name", &guard.container])
        .arg("-v")
        .arg(format!("{}:/src:ro", repo.display()))
        .args([
            "-v",
            "fleet-it-target:/target",
            "-v",
            "fleet-it-cargo:/usr/local/cargo/registry",
            "-e",
            "CARGO_TARGET_DIR=/target",
            "--tmpfs",
            "/jobs:rw,mode=3770,uid=986,gid=987",
            "--tmpfs",
            "/run/fleet:rw,mode=0755,uid=986,gid=986",
            &guard.image,
            "sh",
            "-c",
            IN_CONTAINER_SCRIPT,
        ])
        .stdin(Stdio::null())
        .stdout(File::create(&out)?)
        .stderr(File::create(&err)?)
        .spawn()?;
    let verdict = wait_bounded(&mut child, bound)?;
    if verdict.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let report = format!("stdout tail:\n{}\nstderr tail:\n{}", tail(&out), tail(&err));
    Ok(match verdict {
        Some(true) => HostRun::Passed(tail(&out)),
        Some(false) => HostRun::Failed(report),
        None => HostRun::Failed(format!("timed out after {bound:?}\n{report}")),
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[test]
fn docker_absent_skips_with_message() -> TestResult {
    let ran = run_host_suite(
        "fleet-it-no-such-docker-binary",
        &repo_root(),
        Duration::from_secs(5),
    )?;
    assert_eq!(ran, HostRun::Skipped(SKIP_NO_DOCKER));
    assert!(SKIP_NO_DOCKER.contains("mise run it:linux"));
    Ok(())
}

#[test]
#[ignore = "needs docker; run mise run it:linux"]
fn container_suite_passes() -> TestResult {
    match run_host_suite("docker", &repo_root(), HOST_BOUND)? {
        HostRun::Skipped(message) => {
            eprintln!("{message}");
            Ok(())
        }
        HostRun::Passed(report) => {
            eprintln!("{report}");
            Ok(())
        }
        HostRun::Failed(report) => {
            eprintln!("{report}");
            Err("container suite failed".into())
        }
    }
}

fn outside_container() -> bool {
    let outside = !Path::new(MARKER).exists();
    if outside {
        eprintln!("{SKIP_NO_IMAGE}");
    }
    outside
}

struct Sink(mpsc::UnboundedSender<ReportJobRequest>);

impl Reporter for Sink {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let _ = self.0.send(request);
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

struct Ran {
    outcome: AgentOutcome,
    text: String,
}

impl Ran {
    fn field(&self, key: &str) -> Option<&str> {
        let prefix = format!("{key}=");
        self.text
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
    }

    fn has_line(&self, wanted: &str) -> bool {
        self.text.lines().any(|line| line == wanted)
    }
}

async fn run_job(agent: &str, id: &str) -> Result<Ran, Box<dyn Error>> {
    let cwd = Path::new(JOBS).join(format!("work_{id}"));
    fs::create_dir(&cwd)?;
    share_tree(&cwd, WORK_GID)?;
    let mut config = RunConfig::new(AGENT, true);
    config.kimi_bin = PathBuf::from(AGENT);
    config.jobs_dir = Some(PathBuf::from(JOBS));
    config.job_gid = Some(WORK_GID);
    config.base_env = vec![(OsString::from("PATH"), OsString::from(AGENT_PATH))];
    let launcher = SystemdLauncher::new(SYSTEMCTL)
        .with_run_dir(RUN_DIR)
        .with_job_gid(Some(WORK_GID))
        .with_poll_interval(Duration::from_millis(100))
        .with_run_timeout(WIDE);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let runner =
        AgentRunner::new(config, Sink(tx), Redactor::default()).with_launcher(Arc::new(launcher));
    let job = Job {
        job_id: id.to_owned(),
        attempt: 1,
        r#box: "boxa".to_owned(),
        prompt: "write your directories".to_owned(),
        agent: agent.to_owned(),
        ..Job::default()
    };
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = tokio::time::timeout(WIDE, runner.run(&job, &cwd, shutdown)).await??;
    runner.end_job(&job);
    let mut text = String::new();
    while let Ok(request) = rx.try_recv() {
        for chunk in &request.chunks {
            writeln!(text, "{}", chunk.text.trim_end())?;
        }
        if let Some(message) = &request.error {
            writeln!(text, "terminal={message}")?;
        }
    }
    Ok(Ran { outcome, text })
}

fn assert_clean(ran: &Ran, wanted_config_suffix: &str) {
    assert_eq!(ran.outcome, AgentOutcome::Succeeded, "{}", ran.text);
    for probe in ["home", "config", "cache", "workdir"] {
        assert!(
            ran.has_line(&format!("ok:{probe}")),
            "{probe}: {}",
            ran.text
        );
    }
    assert!(!ran.text.contains("fail:"), "{}", ran.text);
    assert!(
        ran.field("config_dir")
            .is_some_and(|dir| dir.ends_with(wanted_config_suffix)),
        "{}",
        ran.text
    );
}

#[tokio::test]
async fn claude_job_writes_home_config_cache_and_workdir() -> TestResult {
    if outside_container() {
        return Ok(());
    }
    let ran = run_job("claude", "claude_files").await?;
    assert_clean(&ran, "/home/.claude");
    assert_eq!(
        ran.field("home").map(str::to_owned),
        Some("/jobs/.agent/claude_files/home".to_owned()),
        "{}",
        ran.text
    );
    Ok(())
}

#[tokio::test]
async fn kimi_job_writes_home_config_cache_and_workdir() -> TestResult {
    if outside_container() {
        return Ok(());
    }
    let ran = run_job("kimi", "kimi_files").await?;
    assert_clean(&ran, "/.kimi/kimi_files");
    Ok(())
}

#[tokio::test]
async fn agent_runs_as_985_gid_987() -> TestResult {
    if outside_container() {
        return Ok(());
    }
    let ran = run_job("kimi", "kimi_who").await?;
    assert_eq!(
        ran.field("who").map(str::to_owned),
        Some(format!("{JOB_UID}:{WORK_GID}")),
        "{}",
        ran.text
    );
    assert_eq!(
        ran.field("groups").map(str::to_owned),
        Some(WORK_GID.to_string()),
        "{}",
        ran.text
    );
    Ok(())
}

#[tokio::test]
async fn kimi_home_modes_2770_group_987() -> TestResult {
    if outside_container() {
        return Ok(());
    }
    let ran = run_job("kimi", "kimi_modes").await?;
    let wanted = format!("2770:{FLEETD_UID}:{WORK_GID}");
    assert_eq!(
        ran.field("config_mode"),
        Some(wanted.as_str()),
        "{}",
        ran.text
    );
    assert_eq!(
        ran.field("config_parent_mode"),
        Some(wanted.as_str()),
        "{}",
        ran.text
    );
    Ok(())
}

#[tokio::test]
async fn agent_cannot_read_run_env_file() -> TestResult {
    if outside_container() {
        return Ok(());
    }
    let ran = run_job("claude", "claude_env").await?;
    assert_eq!(ran.field("env_file"), Some("denied"), "{}", ran.text);
    Ok(())
}

#[test]
fn control_old_0700_kimi_home_is_eacces() -> TestResult {
    if outside_container() {
        return Ok(());
    }
    let home = KimiHome::create(Path::new(JOBS), "kimi_control")?;
    let out = Command::new("sudo")
        .args(["-n", "setpriv"])
        .arg(format!("--reuid={JOB_UID}"))
        .arg(format!("--regid={WORK_GID}"))
        .args(["--clear-groups", "sh", "-c", ": > \"$1/config.toml\"", "sh"])
        .arg(home.path())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "write succeeded as {JOB_UID}");
    assert!(stderr.contains("Permission denied"), "{stderr}");
    Ok(())
}
