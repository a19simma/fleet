//! Runs the systemd launcher against a fake `systemctl` and the `fleetd agent-exec` binary.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fleetd::agent_exec::write_spec;
use fleetd::jobsock::{
    AGENT_SLICE, JobContext, Limits, Peer, PeerId, ServeFuture, Service, ServiceName, Services,
    connect,
};
use fleetd::runner::{AgentProc, AgentSpec, Launched, Launcher};
use fleetd::systemd::{JobSocketSetup, SystemdLauncher, select_launcher, sweep_stale_runs};
use fleetd::{AgentLauncher, Config, Error};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SCRIPT: &str = r#"#!/bin/sh
root=$(dirname "$0")
unit=
for a in "$@"; do
  case "$a" in fleet-agent@*) unit=$a;; esac
done
id=${unit#fleet-agent@}
id=${id%.service}
st=$root/$id
mkdir -p "$st"
echo "$*" >> "$st/log"
if [ -f "$st/rundir" ]; then
  if [ -S "$(cat "$st/rundir")/$id/job.sock" ]; then s=sock; else s=nosock; fi
  echo "$1 $s" >> "$st/seen"
fi
case "$1" in
  stop)
    if [ -f "$st/stop.to" ]; then cp "$st/stop.to" "$st/show.last"; rm -f "$st"/show.[0-9]*; fi
    ;;
  show)
    n=$(cat "$st/n" 2>/dev/null || echo 0)
    n=$((n+1))
    echo "$n" > "$st/n"
    if [ -f "$st/show.$n" ]; then cat "$st/show.$n"; else cat "$st/show.last"; fi
    exit "$(cat "$st/show.rc" 2>/dev/null || echo 0)"
    ;;
  start)
    exit "$(cat "$st/start.rc" 2>/dev/null || echo 0)"
    ;;
esac
exit 0
"#;

const WIDE: Duration = Duration::from_secs(60);

fn root() -> &'static Path {
    static ROOT: OnceLock<TempDir> = OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("systemctl");
        fs::write(&path, SCRIPT).unwrap_or_else(|_| std::process::abort());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        dir
    })
    .path()
}

fn show(state: &str, result: &str, code: u32, status: u32) -> String {
    let sub = match state {
        "active" => "running",
        "inactive" => "dead",
        other => other,
    };
    show_sub(state, sub, result, code, status)
}

fn show_sub(state: &str, sub: &str, result: &str, code: u32, status: u32) -> String {
    format!(
        "ActiveState={state}\nSubState={sub}\nResult={result}\nExecMainCode={code}\nExecMainStatus={status}\n"
    )
}

struct Case {
    id: String,
    state: PathBuf,
    run: TempDir,
}

impl Case {
    fn new(id: &str) -> Result<Self, io::Error> {
        let state = root().join(id);
        fs::create_dir_all(&state)?;
        let run = tempfile::tempdir()?;
        fs::write(
            state.join("rundir"),
            run.path().as_os_str().as_encoded_bytes(),
        )?;
        Ok(Self {
            id: id.to_owned(),
            state,
            run,
        })
    }

    fn seen(&self) -> Vec<String> {
        fs::read_to_string(self.state.join("seen"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn socket_launcher(&self, services: Services) -> SystemdLauncher {
        self.launcher().with_job_socket(JobSocketSetup {
            services,
            peer: Arc::new(AgentPeer(self.id.clone())),
            limits: Limits::default(),
        })
    }

    fn put(&self, name: &str, text: &str) -> io::Result<()> {
        fs::write(self.state.join(name), text)
    }

    fn last(&self, text: &str) -> io::Result<()> {
        self.put("show.last", text)
    }

    fn launcher(&self) -> SystemdLauncher {
        SystemdLauncher::new(root().join("systemctl"))
            .with_run_dir(self.run.path())
            .with_poll_interval(Duration::from_millis(10))
    }

    fn spec(&self) -> AgentSpec {
        let mut spec = AgentSpec {
            argv: vec!["/bin/echo".into(), "hi".into()],
            cwd: self.run.path().to_path_buf(),
            ..AgentSpec::default()
        };
        spec.env
            .insert("FLEET_JOB_ID".into(), OsString::from(&self.id));
        spec.env
            .insert("PROBE".into(), OsString::from("probe-value-1"));
        spec
    }

    fn launch(&self) -> io::Result<Launched> {
        self.launcher().launch(self.spec())
    }

    fn log(&self) -> Vec<String> {
        fs::read_to_string(self.state.join("log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn dir(&self) -> PathBuf {
        self.run.path().join(&self.id)
    }

    fn unit(&self) -> String {
        format!("fleet-agent@{}.service", self.id)
    }
}

async fn waited(proc: &mut dyn AgentProc) -> io::Result<std::process::ExitStatus> {
    tokio::time::timeout(WIDE, proc.wait())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[tokio::test]
async fn bad_job_ids_are_rejected_before_anything_is_created() -> TestResult {
    let long = "a".repeat(65);
    for (n, bad) in ["", "a-b", "a b", "../x", "a/b", "a.b", long.as_str()]
        .into_iter()
        .enumerate()
    {
        let case = Case::new(&format!("t_badid_{n}"))?;
        let mut spec = case.spec();
        spec.env.insert("FLEET_JOB_ID".into(), bad.into());
        let err = case.launcher().launch(spec).err().map(|e| e.kind());
        assert_eq!(err, Some(io::ErrorKind::InvalidInput), "{bad:?}");
        assert_eq!(fs::read_dir(case.run.path())?.count(), 0, "{bad:?}");
        assert!(!case.state.join("log").exists(), "{bad:?}");
    }
    let case = Case::new("t_badid_missing")?;
    let mut spec = case.spec();
    spec.env.clear();
    let err = case.launcher().launch(spec).err().map(|e| e.kind());
    assert_eq!(err, Some(io::ErrorKind::InvalidInput));
    let ok = Case::new(&"b".repeat(64))?;
    ok.last(&show("active", "success", 0, 0))?;
    assert!(ok.launch().is_ok());
    Ok(())
}

#[tokio::test]
async fn show_outputs_map_to_exit_outcomes() -> TestResult {
    let cases: [(&str, String, Option<i32>, Option<i32>); 8] = [
        ("t_map_ok", show("inactive", "success", 1, 0), Some(0), None),
        (
            "t_map_exit",
            show("failed", "exit-code", 1, 3),
            Some(3),
            None,
        ),
        (
            "t_map_signal",
            show("failed", "signal", 2, 15),
            None,
            Some(15),
        ),
        (
            "t_map_signal_odd",
            show("failed", "signal", 2, 0),
            None,
            Some(9),
        ),
        (
            "t_map_core",
            show("failed", "core-dump", 3, 11),
            None,
            Some(11),
        ),
        (
            "t_map_timeout",
            show("failed", "timeout", 2, 15),
            None,
            Some(15),
        ),
        (
            "t_map_watchdog",
            show("failed", "watchdog", 2, 6),
            None,
            Some(15),
        ),
        ("t_map_oom", show("failed", "oom-kill", 2, 9), None, Some(9)),
    ];
    for (id, text, code, signal) in cases {
        let case = Case::new(id)?;
        case.last(&text)?;
        let mut launched = case.launch()?;
        let status = waited(launched.proc.as_mut()).await?;
        assert_eq!((status.code(), status.signal()), (code, signal), "{id}");
        assert!(!case.dir().exists(), "{id}");
        assert_eq!(
            case.log().last().map(String::as_str),
            Some(format!("reset-failed {}", case.unit()).as_str()),
            "{id}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn wait_polls_until_the_unit_has_run_and_ended() -> TestResult {
    let case = Case::new("t_poll")?;
    case.put("show.1", &show("inactive", "success", 0, 0))?;
    case.put("show.2", &show("activating", "success", 0, 0))?;
    case.put("show.3", &show("active", "success", 1, 0))?;
    case.put("show.4", &show("deactivating", "success", 1, 0))?;
    case.last(&show("inactive", "success", 1, 0))?;
    let mut launched = case.launch()?;
    let status = waited(launched.proc.as_mut()).await?;
    assert_eq!(status.code(), Some(0));
    let shows = case.log().iter().filter(|l| l.starts_with("show ")).count();
    assert_eq!(shows, 5);
    assert_eq!(
        case.log().first().map(String::as_str),
        Some(format!("start --no-block {}", case.unit()).as_str())
    );
    assert_eq!(
        case.log().get(1).map(String::as_str),
        Some(
            format!(
                "show {} -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus",
                case.unit()
            )
            .as_str()
        )
    );
    Ok(())
}

#[tokio::test]
async fn unparsable_show_output_is_an_error_after_cleanup() -> TestResult {
    let big = format!(
        "ActiveState=inactive\nSubState=dead\n{}\n",
        "x".repeat(5000)
    );
    let bad: Vec<(&str, String)> = vec![
        ("t_bad_empty", String::new()),
        ("t_bad_garbage", "garbage\n".to_owned()),
        (
            "t_bad_nan",
            show("inactive", "success", 1, 0).replace("ExecMainStatus=0", "ExecMainStatus=x"),
        ),
        ("t_bad_result", show("failed", "resources", 1, 1)),
        ("t_bad_state", show("exploded", "success", 1, 0)),
        (
            "t_bad_dup",
            format!("{}ActiveState=active\n", show("inactive", "success", 1, 0)),
        ),
        (
            "t_bad_extra",
            format!("{}Other=1\n", show("inactive", "success", 1, 0)),
        ),
        (
            "t_bad_missing",
            "ActiveState=inactive\nSubState=dead\nResult=success\n".to_owned(),
        ),
        ("t_bad_big", big),
        ("t_bad_success_status", show("inactive", "success", 1, 3)),
        ("t_bad_exit_zero", show("failed", "exit-code", 1, 0)),
        ("t_bad_exit_wide", show("failed", "exit-code", 1, 256)),
    ];
    for (id, text) in bad {
        let case = Case::new(id)?;
        case.last(&text)?;
        let mut launched = case.launch()?;
        let err = waited(launched.proc.as_mut()).await.err().map(|e| e.kind());
        assert_eq!(err, Some(io::ErrorKind::InvalidData), "{id}");
        assert!(!case.dir().exists(), "{id}");
        assert!(
            case.log().iter().any(|l| l.starts_with("reset-failed ")),
            "{id}"
        );
        let again = waited(launched.proc.as_mut()).await.err().map(|e| e.kind());
        assert_eq!(again, Some(io::ErrorKind::InvalidData), "{id}");
    }
    let case = Case::new("t_bad_rc")?;
    case.last(&show("inactive", "success", 1, 0))?;
    case.put("show.rc", "1")?;
    let mut launched = case.launch()?;
    assert!(waited(launched.proc.as_mut()).await.is_err());
    assert!(!case.dir().exists());
    assert!(case.log().iter().any(|l| l.starts_with("reset-failed ")));
    Ok(())
}

#[tokio::test]
async fn terminate_and_kill_run_the_right_argv_and_drop_cleans_up() -> TestResult {
    let case = Case::new("t_signals")?;
    case.last(&show("active", "success", 1, 0))?;
    let mut launched = case.launch()?;
    launched.proc.terminate();
    launched.proc.kill();
    let unit = case.unit();
    assert_eq!(
        case.log(),
        vec![
            format!("start --no-block {unit}"),
            format!("kill --kill-whom=all --signal=SIGTERM {unit}"),
            format!("kill --kill-whom=all --signal=SIGKILL {unit}"),
        ]
    );
    assert!(case.dir().exists());
    drop(launched);
    let log = case.log();
    assert_eq!(
        log.get(3).map(String::as_str),
        Some(format!("kill --kill-whom=all --signal=SIGKILL {unit}").as_str())
    );
    assert_eq!(
        log.get(4).map(String::as_str),
        Some(format!("reset-failed {unit}").as_str())
    );
    assert!(!case.dir().exists());
    Ok(())
}

#[tokio::test]
async fn files_stdout_and_a_finished_wait_behave() -> TestResult {
    let case = Case::new("t_files")?;
    case.last(&show("active", "success", 1, 0))?;
    let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let launched = case.launch();
    rustix::process::umask(previous);
    let mut launched = launched?;
    let dir = case.dir();
    let mode = |name: &str| fs::metadata(dir.join(name)).map(|m| m.mode() & 0o7777);
    assert_eq!(mode("env")?, 0o600);
    assert_eq!(mode("spec.json")?, 0o600);
    assert_eq!(mode("stdout")?, 0o660);
    assert_eq!(fs::metadata(&dir)?.mode() & 0o7777, 0o750);
    assert_eq!(fs::read_to_string(dir.join("env"))?.lines().count(), 2);
    assert!(fs::read_to_string(dir.join("env"))?.contains("PROBE=\"probe-value-1\""));
    let spec = fs::read_to_string(dir.join("spec.json"))?;
    assert!(!spec.contains("probe-value-1"));
    assert!(spec.contains("\"/bin/echo\""));
    {
        use std::io::Write;
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("stdout"))?;
        writer.write_all(b"hi\n")?;
    }
    let mut first = [0_u8; 3];
    tokio::time::timeout(WIDE, launched.stdout.read_exact(&mut first)).await??;
    assert_eq!(&first, b"hi\n");
    case.last(&show("inactive", "success", 1, 0))?;
    assert_eq!(waited(launched.proc.as_mut()).await?.code(), Some(0));
    let mut rest = Vec::new();
    tokio::time::timeout(WIDE, launched.stdout.read_to_end(&mut rest)).await??;
    assert_eq!(rest.len(), 0);
    let before = case.log().len();
    launched.proc.terminate();
    launched.proc.kill();
    assert_eq!(waited(launched.proc.as_mut()).await?.code(), Some(0));
    drop(launched);
    assert_eq!(case.log().len(), before);
    Ok(())
}

#[tokio::test]
async fn a_failed_start_leaves_nothing_behind() -> TestResult {
    let case = Case::new("t_startfail")?;
    case.put("start.rc", "1")?;
    assert!(case.launch().is_err());
    assert_eq!(fs::read_dir(case.run.path())?.count(), 0);
    let again = case.launch().err().map(|e| e.kind());
    assert_ne!(again, Some(io::ErrorKind::AlreadyExists));
    let rel = SystemdLauncher::new("systemctl").with_run_dir(case.run.path());
    let err = rel.launch(case.spec()).err().map(|e| e.kind());
    assert_eq!(err, Some(io::ErrorKind::InvalidInput));
    assert_eq!(fs::read_dir(case.run.path())?.count(), 0);
    Ok(())
}

const BOUND: Duration = Duration::from_secs(20);

struct AgentPeer(String);

impl Peer for AgentPeer {
    fn identity(&self, _stream: &UnixStream) -> io::Result<PeerId> {
        Ok(PeerId {
            pid: 1,
            cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@{}.service\n", self.0),
        })
    }
}

struct Probe(mpsc::UnboundedSender<&'static str>);

struct Closed(mpsc::UnboundedSender<&'static str>);

impl Drop for Closed {
    fn drop(&mut self) {
        let _ = self.0.send("closed");
    }
}

impl Service for Probe {
    fn serve(&self, _ctx: JobContext, _stream: UnixStream) -> ServeFuture<'_> {
        let closed = Closed(self.0.clone());
        let _ = self.0.send("serving");
        Box::pin(async move {
            let _closed = closed;
            std::future::pending::<()>().await;
        })
    }
}

fn probe() -> (Services, mpsc::UnboundedReceiver<&'static str>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let service: Arc<dyn Service> = Arc::new(Probe(tx));
    (Services::from([(ServiceName::Fetch, service)]), rx)
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("capture poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn captured(run: impl FnOnce()) -> String {
    let capture = Capture::default();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish(),
    );
    run();
    drop(guard);
    let bytes = capture.0.lock().map(|b| b.clone()).unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn the_job_socket_exists_before_start_and_is_gone_before_stop() -> TestResult {
    let case = Case::new("t_sock_order")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let mut launched = case.socket_launcher(Services::new()).launch(case.spec())?;
    let socket = case.dir().join("job.sock");
    assert!(fs::symlink_metadata(&socket)?.file_type().is_socket());
    assert_eq!(fs::metadata(&socket)?.permissions().mode() & 0o777, 0o660);
    waited(launched.proc.as_mut()).await?;
    let seen = case.seen();
    assert_eq!(seen.first().map(String::as_str), Some("start sock"));
    assert!(seen.iter().any(|line| line == "stop nosock"), "{seen:?}");
    assert!(!seen.iter().any(|line| line == "stop sock"), "{seen:?}");
    assert!(!case.dir().exists());
    Ok(())
}

#[tokio::test]
async fn no_job_socket_is_made_without_a_setup() -> TestResult {
    let case = Case::new("t_sock_none")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let mut launched = case.launch()?;
    assert!(!case.dir().join("job.sock").exists());
    waited(launched.proc.as_mut()).await?;
    assert_eq!(
        case.seen().first().map(String::as_str),
        Some("start nosock")
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_start_removes_the_job_socket_with_the_dir() -> TestResult {
    let case = Case::new("t_sock_startfail")?;
    case.put("start.rc", "1")?;
    assert!(
        case.socket_launcher(Services::new())
            .launch(case.spec())
            .is_err()
    );
    assert_eq!(case.seen(), ["start sock"]);
    assert_eq!(fs::read_dir(case.run.path())?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn cancel_services_stops_a_serving_connection_while_the_unit_runs() -> TestResult {
    let case = Case::new("t_sock_cancel")?;
    case.last(&show("active", "success", 1, 0))?;
    let (services, mut events) = probe();
    let mut launched = case.socket_launcher(services).launch(case.spec())?;
    let uid = fs::metadata(case.dir())?.uid();
    let _client = connect(&case.dir().join("job.sock"), ServiceName::Fetch, uid).await?;
    assert_eq!(
        tokio::time::timeout(BOUND, events.recv()).await?,
        Some("serving")
    );
    launched.proc.cancel_services();
    assert_eq!(
        tokio::time::timeout(BOUND, events.recv()).await?,
        Some("closed")
    );
    assert!(case.dir().exists());
    launched.proc.kill();
    Ok(())
}

#[test]
fn a_direct_launcher_refuses_the_job_socket_with_one_fixed_line() -> TestResult {
    let none = |_: &str| None;
    let direct = Config::resolve(None, &none)?;
    let systemd = Config::resolve(Some("agent_launcher = \"systemd\"\n"), &none)?;
    let (services, _events) = probe();
    let logged = captured(|| {
        let launcher = select_launcher(&direct, None, services.clone());
        assert_eq!(launcher.job_services(), Vec::new());
    });
    assert_eq!(logged.matches("job socket refused").count(), 1, "{logged}");
    assert!(logged.contains("job socket refused: agent_launcher is direct"));
    let quiet = captured(|| {
        let _ = select_launcher(&direct, None, Services::new());
        let launcher = select_launcher(&systemd, None, services.clone());
        assert_eq!(launcher.job_services(), [ServiceName::Fetch]);
    });
    assert!(!quiet.contains("job socket"), "{quiet}");
    Ok(())
}

#[test]
fn a_systemd_launcher_without_services_warns_once() -> TestResult {
    let none = |_: &str| None;
    let direct = Config::resolve(None, &none)?;
    let systemd = Config::resolve(Some("agent_launcher = \"systemd\"\n"), &none)?;
    let (services, _events) = probe();
    let warned = captured(|| {
        let _ = select_launcher(&systemd, None, Services::new());
    });
    assert_eq!(
        warned.matches("no services are registered").count(),
        1,
        "{warned}"
    );
    assert!(warned.contains("PrivateNetwork=yes"), "{warned}");
    let quiet = captured(|| {
        let _ = select_launcher(&systemd, None, services.clone());
        let _ = select_launcher(&direct, None, Services::new());
    });
    assert!(!quiet.contains("no services"), "{quiet}");
    Ok(())
}

fn show_count(case: &Case) -> usize {
    case.log().iter().filter(|l| l.starts_with("show ")).count()
}

fn reset_count(case: &Case) -> usize {
    case.log()
        .iter()
        .filter(|l| l.starts_with("reset-failed "))
        .count()
}

fn tail(case: &Case, n: usize) -> Vec<String> {
    let log = case.log();
    log.iter()
        .skip(log.len().saturating_sub(n))
        .cloned()
        .collect()
}

#[tokio::test]
async fn an_active_exited_unit_finishes_as_success_after_stop_and_reset_failed() -> TestResult {
    let case = Case::new("t_remain_ok")?;
    case.last(&show_sub("active", "exited", "success", 1, 0))?;
    case.put("stop.to", &show("inactive", "success", 0, 0))?;
    let mut launched = case.launch()?;
    let status = tokio::time::timeout(BOUND, launched.proc.wait())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    assert_eq!((status.code(), status.signal()), (Some(0), None));
    let unit = case.unit();
    assert_eq!(
        tail(&case, 2),
        vec![format!("stop {unit}"), format!("reset-failed {unit}")]
    );
    assert!(!case.dir().exists());
    drop(launched);
    assert_eq!(reset_count(&case), 1);
    Ok(())
}

#[tokio::test]
async fn a_failed_unit_is_stopped_and_reset_after_its_status_is_read() -> TestResult {
    let case = Case::new("t_remain_fail")?;
    case.last(&show("failed", "exit-code", 1, 7))?;
    let mut launched = case.launch()?;
    let status = tokio::time::timeout(BOUND, launched.proc.wait())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    assert_eq!(status.code(), Some(7));
    let unit = case.unit();
    assert_eq!(
        tail(&case, 2),
        vec![format!("stop {unit}"), format!("reset-failed {unit}")]
    );
    Ok(())
}

#[tokio::test]
async fn an_active_running_unit_keeps_waiting() -> TestResult {
    let case = Case::new("t_remain_running")?;
    case.last(&show_sub("active", "running", "success", 1, 0))?;
    let mut launched = case.launch()?;
    let waiting = tokio::time::timeout(Duration::from_millis(500), launched.proc.wait()).await;
    assert!(waiting.is_err());
    assert!(show_count(&case) >= 3);
    assert!(!case.log().iter().any(|l| l.starts_with("stop ")));
    assert!(case.dir().exists());
    Ok(())
}

#[tokio::test]
async fn kill_ends_a_unit_that_never_ran() -> TestResult {
    for (id, signal) in [("t_never_kill", 9), ("t_never_term", 15)] {
        let case = Case::new(id)?;
        case.last(&show("inactive", "success", 0, 0))?;
        let mut launched = case.launch()?;
        if signal == 9 {
            launched.proc.kill();
        } else {
            launched.proc.terminate();
        }
        let status = tokio::time::timeout(BOUND, launched.proc.wait())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        assert_eq!(status.signal(), Some(signal), "{id}");
        assert!(!case.dir().exists(), "{id}");
        assert_eq!(reset_count(&case), 1, "{id}");
    }
    Ok(())
}

#[tokio::test]
async fn a_unit_that_never_runs_fails_at_the_start_deadline() -> TestResult {
    let case = Case::new("t_never_deadline")?;
    case.last(&show("inactive", "success", 0, 0))?;
    let mut launched = case
        .launcher()
        .with_start_deadline(Duration::from_millis(300))
        .launch(case.spec())?;
    let err = tokio::time::timeout(BOUND, launched.proc.wait())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .err()
        .map(|e| e.kind());
    assert_eq!(err, Some(io::ErrorKind::TimedOut));
    assert!(!case.dir().exists());
    assert_eq!(reset_count(&case), 1);
    Ok(())
}

#[tokio::test]
async fn a_kill_after_the_run_deadline_reads_as_timed_out() -> TestResult {
    let case = Case::new("t_run_deadline")?;
    case.last(&show_sub("active", "exited", "success", 0, 0))?;
    let mut launched = case
        .launcher()
        .with_run_timeout(Duration::from_millis(50))
        .launch(case.spec())?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    launched.proc.kill();
    let status = waited(launched.proc.as_mut()).await?;
    assert_eq!(status.signal(), Some(9));
    assert!(launched.proc.timed_out());
    Ok(())
}

#[tokio::test]
async fn a_kill_before_the_run_deadline_stays_a_plain_signal() -> TestResult {
    let case = Case::new("t_before_deadline")?;
    case.last(&show_sub("active", "exited", "success", 0, 0))?;
    let mut launched = case.launcher().with_run_timeout(WIDE).launch(case.spec())?;
    launched.proc.kill();
    let status = waited(launched.proc.as_mut()).await?;
    assert_eq!(status.signal(), Some(9));
    assert!(!launched.proc.timed_out());
    Ok(())
}

#[tokio::test]
async fn a_real_exit_zero_after_a_signal_still_maps_to_exit_zero() -> TestResult {
    let case = Case::new("t_exit_zero_signalled")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let mut launched = case.launch()?;
    launched.proc.terminate();
    launched.proc.kill();
    let status = tokio::time::timeout(BOUND, launched.proc.wait())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    assert_eq!((status.code(), status.signal()), (Some(0), None));
    Ok(())
}

#[tokio::test]
async fn recreating_wait_does_not_spawn_a_show_per_call() -> TestResult {
    let case = Case::new("t_wait_churn")?;
    case.last(&show("active", "success", 1, 0))?;
    let poll = Duration::from_millis(100);
    let mut launched = case
        .launcher()
        .with_poll_interval(poll)
        .launch(case.spec())?;
    let started = Instant::now();
    let mut calls = 0_u32;
    while calls < 150 {
        let _ = tokio::time::timeout(Duration::from_millis(2), launched.proc.wait()).await;
        calls += 1;
    }
    let elapsed = started.elapsed();
    let shows = show_count(&case);
    let allowed = usize::try_from(elapsed.as_millis() / poll.as_millis())? * 3 + 3;
    assert!(
        shows <= allowed,
        "{shows} shows in {elapsed:?}, allowed {allowed}"
    );
    case.last(&show("inactive", "success", 1, 0))?;
    let status = tokio::time::timeout(BOUND, launched.proc.wait())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    assert_eq!(status.code(), Some(0));
    Ok(())
}

#[tokio::test]
async fn cleanup_runs_exactly_once() -> TestResult {
    let case = Case::new("t_cleanup_once")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let mut launched = case.launch()?;
    for _ in 0..3 {
        let status = tokio::time::timeout(BOUND, launched.proc.wait())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        assert_eq!(status.code(), Some(0));
    }
    assert_eq!(reset_count(&case), 1);
    drop(launched);
    assert_eq!(reset_count(&case), 1);
    assert!(!case.log().iter().any(|l| l.starts_with("kill ")));
    assert!(!case.dir().exists());
    Ok(())
}

#[test]
fn config_defaults_to_direct_and_rejects_bad_values() -> TestResult {
    let none = |_: &str| None;
    let cfg = Config::resolve(None, &none)?;
    assert_eq!(cfg.agent_launcher, AgentLauncher::Direct);
    assert_eq!(cfg.systemctl_path, PathBuf::from("/usr/bin/systemctl"));
    let file = "agent_launcher = \"systemd\"\nsystemctl_path = \"/opt/systemctl\"\n";
    let cfg = Config::resolve(Some(file), &none)?;
    assert_eq!(cfg.agent_launcher, AgentLauncher::Systemd);
    assert_eq!(cfg.systemctl_path, PathBuf::from("/opt/systemctl"));
    let env = |name: &str| (name == "FLEETD_AGENT_LAUNCHER").then(|| "direct".to_owned());
    let cfg = Config::resolve(Some(file), &env)?;
    assert_eq!(cfg.agent_launcher, AgentLauncher::Direct);
    let env = |name: &str| (name == "FLEETD_SYSTEMCTL_PATH").then(|| "/env/ctl".to_owned());
    let cfg = Config::resolve(Some(file), &env)?;
    assert_eq!(cfg.systemctl_path, PathBuf::from("/env/ctl"));
    for bad in ["\"Systemd\"", "\"\"", "\"docker\"", "\"direct \""] {
        let file = format!("agent_launcher = {bad}\n");
        assert!(
            matches!(
                Config::resolve(Some(&file), &none),
                Err(Error::InvalidValue {
                    name: "agent_launcher",
                    ..
                })
            ),
            "{bad}"
        );
    }
    let env = |name: &str| (name == "FLEETD_AGENT_LAUNCHER").then(|| "nope".to_owned());
    assert!(matches!(
        Config::resolve(None, &env),
        Err(Error::InvalidValue {
            name: "agent_launcher",
            ..
        })
    ));
    let file = "systemctl_path = \"systemctl\"\n";
    assert!(matches!(
        Config::resolve(Some(file), &none),
        Err(Error::InvalidValue {
            name: "systemctl_path",
            ..
        })
    ));
    Ok(())
}

#[test]
fn select_launcher_follows_the_config() -> TestResult {
    let none = |_: &str| None;
    let direct = Config::resolve(None, &none)?;
    assert!(
        format!("{:?}", select_launcher(&direct, None, Services::new())).contains("DirectLauncher")
    );
    let file = "agent_launcher = \"systemd\"\n";
    let systemd = Config::resolve(Some(file), &none)?;
    assert!(
        format!("{:?}", select_launcher(&systemd, None, Services::new()))
            .contains("SystemdLauncher")
    );
    let timed = Config::resolve(
        Some("agent_launcher = \"systemd\"\nagent_timeout_secs = 321\n"),
        &none,
    )?;
    let shown = format!("{:?}", select_launcher(&timed, None, Services::new()));
    assert!(shown.contains("321"), "{shown}");
    Ok(())
}

struct Exec {
    run: TempDir,
    cwd: TempDir,
}

impl Exec {
    fn new() -> Result<Self, io::Error> {
        root();
        Ok(Self {
            run: tempfile::tempdir()?,
            cwd: tempfile::tempdir()?,
        })
    }

    fn spec(&self, argv: &[&str]) -> AgentSpec {
        AgentSpec {
            argv: argv.iter().map(OsString::from).collect(),
            cwd: self.cwd.path().to_path_buf(),
            ..AgentSpec::default()
        }
    }

    fn put(&self, dir_id: &str, spec_id: &str, argv: &[&str]) -> TestResult {
        fs::create_dir_all(self.run.path().join(dir_id))?;
        let path = self.run.path().join(dir_id).join("spec.json");
        write_spec(&path, spec_id, &self.spec(argv), None)?;
        Ok(())
    }

    fn run(&self, id: &str) -> Result<(Option<i32>, String, String), io::Error> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fleetd"))
            .arg("agent-exec")
            .arg(id)
            .arg("--run-dir")
            .arg(self.run.path())
            .env("PROBE", "probe-value-2")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let start = Instant::now();
        while child.try_wait()?.is_none() {
            if start.elapsed() > WIDE {
                child.kill()?;
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output()?;
        Ok((
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }
}

#[test]
fn agent_exec_runs_the_argv_in_the_spec_cwd_with_the_inherited_env() -> TestResult {
    let exec = Exec::new()?;
    let out = exec.cwd.path().join("out.txt");
    let script = format!("pwd -P > '{0}'; echo \"$PROBE\" >> '{0}'", out.display());
    exec.put("ex_ok", "ex_ok", &["/bin/sh", "-c", &script])?;
    let (code, stdout, stderr) = exec.run("ex_ok")?;
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!((stdout.as_str(), stderr.as_str()), ("", ""));
    let want = fs::canonicalize(exec.cwd.path())?;
    assert_eq!(
        fs::read_to_string(&out)?,
        format!("{}\nprobe-value-2\n", want.display())
    );
    let (code, ..) = exec.run("ex_ok")?;
    assert_eq!(code, Some(0));
    Ok(())
}

#[test]
fn agent_exec_exits_2_without_printing_env_values_on_bad_specs() -> TestResult {
    let exec = Exec::new()?;
    exec.put("ex_empty", "ex_empty", &[])?;
    exec.put("ex_a", "ex_other", &["/bin/true"])?;
    exec.put("ex_nocmd", "ex_nocmd", &["/nonexistent/program"])?;
    fs::create_dir_all(exec.run.path().join("ex_junk"))?;
    fs::write(exec.run.path().join("ex_junk/spec.json"), "{not json")?;
    fs::create_dir_all(exec.run.path().join("ex_nospec"))?;
    for id in [
        "ex_empty",
        "ex_a",
        "ex_nocmd",
        "ex_junk",
        "ex_nospec",
        "ex_absent",
        "bad-id",
    ] {
        let (code, stdout, stderr) = exec.run(id)?;
        assert_eq!(code, Some(2), "{id}: {stderr}");
        assert!(stderr.starts_with("fleetd agent-exec: "), "{id}: {stderr}");
        assert!(!stderr.contains("probe-value-2"), "{id}");
        assert!(!stdout.contains("probe-value-2"), "{id}");
        assert_eq!(stdout, "", "{id}");
    }
    let (_, _, stderr) = exec.run("ex_empty")?;
    assert!(stderr.contains("empty command line"));
    let (_, _, stderr) = exec.run("ex_a")?;
    assert!(stderr.contains("different job"));
    let (_, _, stderr) = exec.run("ex_nospec")?;
    assert!(stderr.contains("missing"));
    Ok(())
}

fn stale_dir(case: &Case) -> io::Result<()> {
    fs::create_dir_all(case.dir())?;
    fs::write(case.dir().join("env"), "SECRET=1\n")?;
    fs::write(case.dir().join("spec.json"), "{}")
}

fn systemd_config() -> Result<Config, Error> {
    Config::resolve(None, &|name| {
        (name == "FLEETD_AGENT_LAUNCHER").then(|| String::from("systemd"))
    })
}

#[tokio::test]
async fn a_stale_run_dir_is_removed_and_a_live_unit_is_stopped_then_reset_first() -> TestResult {
    let case = Case::new("t_sweep_live")?;
    case.last(&show("active", "success", 0, 0))?;
    stale_dir(&case)?;
    case.launcher().sweep_stale().await;
    let unit = case.unit();
    assert_eq!(
        case.log(),
        vec![
            format!(
                "show {unit} -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus"
            ),
            format!("stop {unit}"),
            format!("reset-failed {unit}"),
        ]
    );
    assert!(!case.dir().exists());
    Ok(())
}

#[tokio::test]
async fn a_stale_run_dir_of_a_failed_unit_is_reset_without_stop_before_removal() -> TestResult {
    let case = Case::new("t_sweep_failed")?;
    case.last(&show("failed", "signal", 1, 9))?;
    stale_dir(&case)?;
    case.launcher().sweep_stale().await;
    let unit = case.unit();
    assert_eq!(
        case.log(),
        vec![
            format!(
                "show {unit} -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus"
            ),
            format!("reset-failed {unit}"),
        ]
    );
    assert!(!case.dir().exists());
    Ok(())
}

#[tokio::test]
async fn a_stale_run_dir_of_an_inactive_unit_is_removed_without_stop() -> TestResult {
    let case = Case::new("t_sweep_idle")?;
    case.last(&show("inactive", "success", 0, 0))?;
    stale_dir(&case)?;
    case.launcher().sweep_stale().await;
    assert!(!case.dir().exists());
    assert!(case.log().iter().all(|line| line.starts_with("show ")));
    Ok(())
}

#[tokio::test]
async fn the_sweep_leaves_unsafe_names_symlinks_files_and_the_hook_dir() -> TestResult {
    let case = Case::new("t_sweep_skip")?;
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("keep"), "x")?;
    let root = case.run.path();
    fs::create_dir(root.join("bad name"))?;
    fs::create_dir(root.join("a.b"))?;
    fs::create_dir(root.join("hook"))?;
    fs::write(root.join("plainfile"), "x")?;
    std::os::unix::fs::symlink(outside.path(), root.join("linked"))?;
    case.launcher().sweep_stale().await;
    for name in ["bad name", "a.b", "hook", "plainfile", "linked"] {
        assert!(root.join(name).symlink_metadata().is_ok(), "{name}");
    }
    assert!(outside.path().join("keep").exists());
    assert!(!case.state.join("log").exists());
    Ok(())
}

#[tokio::test]
async fn a_sweep_that_cannot_run_returns_quietly_and_keeps_the_dir() -> TestResult {
    let case = Case::new("t_sweep_fail")?;
    stale_dir(&case)?;
    case.put("show.rc", "1")?;
    case.last("")?;
    case.launcher().sweep_stale().await;
    assert!(case.dir().exists());
    let file = case.run.path().join("not-a-dir");
    fs::write(&file, "x")?;
    SystemdLauncher::new(root().join("systemctl"))
        .with_run_dir(&file)
        .sweep_stale()
        .await;
    SystemdLauncher::new(root().join("systemctl"))
        .with_run_dir(case.run.path().join("missing"))
        .sweep_stale()
        .await;
    Ok(())
}

#[tokio::test]
async fn startup_sweeps_only_for_the_systemd_launcher() -> TestResult {
    let case = Case::new("t_sweep_cfg")?;
    case.last(&show("inactive", "success", 0, 0))?;
    stale_dir(&case)?;
    let direct = Config::resolve(None, &|_| None)?;
    sweep_stale_runs(&direct, case.run.path()).await;
    assert!(case.dir().exists());
    let mut config = systemd_config()?;
    config.systemctl_path = root().join("systemctl");
    sweep_stale_runs(&config, case.run.path()).await;
    assert!(!case.dir().exists());
    Ok(())
}

fn unit_directives(name: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(name);
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn agent_unit_runs_in_a_private_network_namespace() {
    let lines = unit_directives("fleet-agent@.service");
    assert!(lines.iter().any(|l| l == "PrivateNetwork=yes"));
    assert!(!lines.iter().any(|l| l == "PrivateNetwork=no"));
    let drop_in = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/fleet-agent@.service.d/allow-network.conf.example");
    assert!(!drop_in.exists());
}

#[test]
fn managed_settings_use_only_command_hooks() {
    let text = unit_directives("managed-settings.json").join("\n");
    assert!(!text.contains("\"type\": \"http\""));
    assert!(!text.contains("7071"));
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "Stop",
        "SessionEnd",
        "Notification",
        "PostToolUse",
        "PostToolUseFailure",
    ] {
        let want = format!("\"command\": \"fleetd hook {event}\", \"timeout\": 5");
        assert!(text.contains(&want), "{event}");
    }
}

#[test]
fn agent_unit_exposes_only_own_run_dir_and_hook_dir() {
    let lines = unit_directives("fleet-agent@.service");
    let has = |l: &str| lines.iter().any(|x| x == l);
    assert!(has("TemporaryFileSystem=/run/fleet:ro"));
    assert!(has("BindPaths=/run/fleet/%i"));
    assert!(has("BindReadOnlyPaths=/run/fleet/hook"));
    assert!(has("ReadWritePaths=/var/lib/fleet/jobs"));
    assert!(has("ReadOnlyPaths=-/var/lib/fleet/jobs/.cache"));
    let binds = lines
        .iter()
        .filter(|l| l.starts_with("BindPaths=") || l.starts_with("BindReadOnlyPaths="))
        .count();
    assert_eq!(binds, 2);
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("/run/fleet ") || l == "ReadWritePaths=/run/fleet")
    );
}
