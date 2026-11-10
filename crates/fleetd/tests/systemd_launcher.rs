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

use fleet_core::tools::ToolName;
use fleetd::agent_exec::write_spec;
use fleetd::envd::{DELIVERY_DIR, EnvDelivery, MountCheck, Owner, ReleasedEnvironment};
use fleetd::jobsock::{
    AGENT_SLICE, JobContext, Limits, Peer, PeerId, ServeFuture, Service, ServiceName, Services,
    connect,
};
use fleetd::runner::{AgentProc, AgentSpec, Launched, Launcher};
use fleetd::systemd::{
    JobSocketSetup, SystemdLauncher, TOOL_HOSTS_REFUSED, TelemetrySetup, ToolInstallSetup,
    select_launcher, sweep_stale_runs,
};
use fleetd::tools::{TOOL_ENV_FILE, tool_hosts};
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
  if [ -f "$(cat "$st/rundir")/$id/tool-env" ]; then te=tool-env; else te=no-tool-env; fi
  echo "$1 $te" >> "$st/seen_env"
  if [ -d "$(cat "$st/rundir")/$id/envd" ]; then ed=envd; else ed=no-envd; fi
  echo "$1 $ed" >> "$st/seen_envd"
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

    fn seen_envd(&self) -> Vec<String> {
        fs::read_to_string(self.state.join("seen_envd"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn seen_env(&self) -> Vec<String> {
        fs::read_to_string(self.state.join("seen_env"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
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

fn tool_setup(tools: &[ToolName], ceiling: &[String]) -> ToolInstallSetup {
    let tools = tools.to_vec();
    ToolInstallSetup::new(Arc::new(move |_| tools.clone()), ceiling.to_vec())
}

fn covering(tools: &[ToolName]) -> Vec<String> {
    tool_hosts(tools).into_iter().map(str::to_owned).collect()
}

#[tokio::test]
async fn tool_env_is_written_before_the_unit_starts() -> TestResult {
    let case = Case::new("t_toolenv_ok")?;
    case.last(&show("active", "success", 0, 0))?;
    let tools = [ToolName::Node];
    let launcher = case
        .launcher()
        .with_tool_install(tool_setup(&tools, &covering(&tools)));
    let _launched = launcher.launch(case.spec())?;
    let env = fs::read_to_string(case.dir().join(TOOL_ENV_FILE))?;
    assert!(env.starts_with("HTTPS_PROXY=http://127.0.0.1:"), "{env}");
    assert_eq!(
        fs::metadata(case.dir().join(TOOL_ENV_FILE))?
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(case.seen_env(), ["start tool-env"]);
    Ok(())
}

#[tokio::test]
async fn a_refused_host_set_fails_before_any_directory_or_unit() -> TestResult {
    let tools = [ToolName::Node];
    let mut short = covering(&tools);
    short.pop();
    let wild = vec!["*.github.com".to_owned()];
    let upper = vec!["GITHUB.com".to_owned()];
    for (n, ceiling) in [short, wild, upper, Vec::new()].into_iter().enumerate() {
        let case = Case::new(&format!("t_toolenv_refused_{n}"))?;
        case.last(&show("active", "success", 0, 0))?;
        let launcher = case
            .launcher()
            .with_tool_install(tool_setup(&tools, &ceiling));
        let err = launcher.launch(case.spec()).err();
        assert_eq!(
            err.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied),
            "{ceiling:?}"
        );
        assert_eq!(
            err.map(|e| e.to_string()).as_deref(),
            Some(TOOL_HOSTS_REFUSED)
        );
        assert_eq!(fs::read_dir(case.run.path())?.count(), 0, "{ceiling:?}");
        assert!(case.log().is_empty(), "{ceiling:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_job_without_tools_writes_no_tool_env_and_still_starts() -> TestResult {
    let case = Case::new("t_toolenv_none")?;
    case.last(&show("active", "success", 0, 0))?;
    let launcher = case.launcher().with_tool_install(tool_setup(&[], &[]));
    let _launched = launcher.launch(case.spec())?;
    assert!(!case.dir().join(TOOL_ENV_FILE).exists());
    assert_eq!(case.seen_env(), ["start no-tool-env"]);
    Ok(())
}

#[tokio::test]
async fn a_launcher_without_tool_install_writes_no_tool_env() -> TestResult {
    let case = Case::new("t_toolenv_unset")?;
    case.last(&show("active", "success", 0, 0))?;
    let _launched = case.launch()?;
    assert!(!case.dir().join(TOOL_ENV_FILE).exists());
    Ok(())
}

#[tokio::test]
async fn the_tool_lookup_is_asked_with_the_job_id() -> TestResult {
    let case = Case::new("t_toolenv_id")?;
    case.last(&show("active", "success", 0, 0))?;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&asked);
    let setup = ToolInstallSetup::new(
        Arc::new(move |id| {
            if let Ok(mut seen) = sink.lock() {
                seen.push(id.to_owned());
            }
            Vec::new()
        }),
        Vec::new(),
    );
    let _launched = case
        .launcher()
        .with_tool_install(setup)
        .launch(case.spec())?;
    let seen = asked.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(seen, ["t_toolenv_id"]);
    Ok(())
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
async fn a_model_secret_reaches_the_0600_env_file_only_and_leaves_with_the_dir() -> TestResult {
    const KEY: &str = "sk-ant-model-secret-0123456789";
    const TOKEN: &str = "oauth-model-secret-0123456789";
    let case = Case::new("t_model_secret")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let mut spec = case.spec();
    spec.env.insert("ANTHROPIC_API_KEY".into(), KEY.into());
    spec.env
        .insert("CLAUDE_CODE_OAUTH_TOKEN".into(), TOKEN.into());
    let mut launched = case.launcher().launch(spec)?;
    let dir = case.dir();
    assert_eq!(fs::metadata(dir.join("env"))?.mode() & 0o7777, 0o600);
    let env = fs::read_to_string(dir.join("env"))?;
    assert!(env.contains(&format!("ANTHROPIC_API_KEY=\"{KEY}\"")));
    assert!(env.contains(&format!("CLAUDE_CODE_OAUTH_TOKEN=\"{TOKEN}\"")));
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name == "env") || !path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.contains(KEY) && !text.contains(TOKEN), "{path:?}");
    }
    assert_eq!(waited(launched.proc.as_mut()).await?.code(), Some(0));
    assert!(!dir.join("env").exists());
    drop(launched);
    assert!(!dir.exists());
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while show_count(&case) < 3 {
        assert!(Instant::now() < deadline, "fewer than 3 shows");
        let waiting = tokio::time::timeout(Duration::from_millis(50), launched.proc.wait()).await;
        assert!(waiting.is_err());
    }
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

const EXEC_PREFIX_CHARS: [char; 5] = ['@', '-', ':', '+', '!'];

fn exec_prefix(value: &str) -> &str {
    let value = value.trim_start();
    let rest = value.trim_start_matches(EXEC_PREFIX_CHARS);
    &value[..value.len() - rest.len()]
}

fn privileged_exec_lines(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|l| {
            l.split_once('=').is_some_and(|(key, value)| {
                key.starts_with("Exec") && exec_prefix(value).contains(['+', '!'])
            })
        })
        .collect()
}

#[test]
fn exec_prefix_guard_rejects_every_privileged_prefix() {
    for value in [
        "+/bin/x",
        "!/bin/x",
        "-+/bin/x",
        ":+/bin/x",
        "+-/bin/x",
        "!!/bin/x",
        "@-!/bin/x",
        " +/bin/x",
    ] {
        let lines = vec![format!("ExecStopPost={value}")];
        assert_eq!(privileged_exec_lines(&lines).len(), 1, "{value}");
    }
    for value in ["/bin/x", "-/bin/x", "@/bin/x", "-:/bin/x", "/bin/x +a !b"] {
        let lines = vec![format!("ExecStopPost={value}")];
        assert!(privileged_exec_lines(&lines).is_empty(), "{value}");
    }
}

#[test]
fn agent_unit_makes_its_agent_tree_group_writable_as_the_job_user_on_stop() {
    let lines = unit_directives("fleet-agent@.service");
    let stops: Vec<_> = lines
        .iter()
        .filter(|l| l.starts_with("ExecStopPost="))
        .collect();
    assert_eq!(
        stops,
        ["ExecStopPost=-/bin/chmod -R g+rwX /var/lib/fleet/jobs/.agent/%i"]
    );
    assert!(lines.iter().any(|l| l == "User=fleet-job"));
    let privileged = privileged_exec_lines(&lines);
    assert!(privileged.is_empty(), "{privileged:?}");
}

fn deploy_file(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(rel);
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn agent_unit_refuses_the_docker_socket() {
    let lines = unit_directives("fleet-agent@.service");
    let inaccessible: Vec<String> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("InaccessiblePaths="))
        .flat_map(|v| v.split_whitespace())
        .map(|p| p.trim_start_matches('-').to_owned())
        .collect();
    for want in ["/run/docker.sock", "/var/run/docker.sock", "/etc/swarm"] {
        assert!(inaccessible.iter().any(|p| p == want), "{want}");
    }
}

#[test]
fn no_deploy_file_adds_fleet_job_to_a_docker_group() {
    let sysusers = deploy_file("sysusers.d/fleet.conf");
    assert!(sysusers.contains("fleet-job"));
    for line in sysusers.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"m") {
            assert_ne!(fields.get(1), Some(&"fleet-job"), "{line}");
            assert_ne!(fields.get(2), Some(&"docker"), "{line}");
        }
        if fields.first() == Some(&"u") && fields.get(1) == Some(&"fleet-job") {
            assert_eq!(
                fields.get(2).map(|g| g.split(':').next_back()),
                Some(Some("fleet-work")),
                "{line}"
            );
        }
    }
    for rel in [
        "fleet-agent@.service",
        "fleetd.service",
        "fleetd-systemd.service",
        "sysusers.d/fleet.conf",
        "tmpfiles.d/fleet.conf",
    ] {
        let text = deploy_file(rel);
        assert!(!text.is_empty(), "{rel}");
        for line in text.lines() {
            let docker_group = line.starts_with("SupplementaryGroups=") && line.contains("docker")
                || line.starts_with("Group=") && line.contains("docker")
                || line.starts_with("m ") && line.contains("docker");
            assert!(!docker_group, "{rel}: {line}");
        }
    }
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

#[test]
fn agent_unit_reads_the_env_file_then_the_optional_delivery_env_file() {
    let lines = unit_directives("fleet-agent@.service");
    let files: Vec<&str> = lines
        .iter()
        .filter(|l| l.starts_with("EnvironmentFile="))
        .map(String::as_str)
        .collect();
    assert_eq!(
        files,
        [
            "EnvironmentFile=/run/fleet/%i/env",
            "EnvironmentFile=-/run/fleet/%i/envd/envd.env"
        ]
    );
}

const INSTALL_UNIT: &str = "fleet-tool-install@.service";

fn has_line(lines: &[String], want: &str) -> bool {
    lines.iter().any(|l| l == want)
}

#[test]
fn install_unit_runs_the_locked_bundled_mise_as_fleet_job_with_safe_mode() {
    let lines = unit_directives(INSTALL_UNIT);
    assert_ne!(lines.len(), 0);
    for want in [
        "User=fleet-job",
        "Group=fleet-work",
        "Environment=MISE_SAFE=1",
        "Environment=MISE_CONFIG_FILE=/run/fleet/%i/mise.toml",
        "ExecStart=/usr/local/bin/fleetd tool-install-exec %i",
        "ConditionPathExists=/run/fleet/%i/mise.toml",
    ] {
        assert!(has_line(&lines, want), "{want}");
    }
    let starts = lines.iter().filter(|l| l.starts_with("ExecStart=")).count();
    assert_eq!(starts, 1);
    assert_eq!(privileged_exec_lines(&lines).len(), 0);
    assert!(!has_line(
        &lines,
        "ExecStart=/usr/local/libexec/fleet/mise install --locked"
    ));
}

#[test]
fn install_unit_runs_the_same_fleetd_binary_as_the_agent_unit_with_its_own_subcommand() {
    let install = unit_directives(INSTALL_UNIT);
    let agent = unit_directives("fleet-agent@.service");
    let exec_of = |lines: &[String]| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix("ExecStart="))
            .map(str::to_owned)
    };
    let install_exec = exec_of(&install).unwrap_or_default();
    let agent_exec = exec_of(&agent).unwrap_or_default();
    assert_eq!(install_exec.split(' ').next(), agent_exec.split(' ').next());
    assert_eq!(agent_exec, "/usr/local/bin/fleetd agent-exec %i");
    assert_eq!(install_exec, "/usr/local/bin/fleetd tool-install-exec %i");
}

#[test]
fn install_unit_stays_private_network_and_gets_no_extra_reach() {
    let install = unit_directives(INSTALL_UNIT);
    for want in [
        "PrivateNetwork=yes",
        "InaccessiblePaths=/etc/swarm",
        "InaccessiblePaths=-/run/docker.sock",
        "InaccessiblePaths=-/var/run/docker.sock",
        "BindReadOnlyPaths=/run/fleet/%i",
        "ReadWritePaths=/var/lib/fleet/tools",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    ] {
        assert!(has_line(&install, want), "{want}");
    }
    assert!(!install.iter().any(|l| l.starts_with("BindPaths=")));
    assert!(!install.iter().any(|l| l.starts_with("Slice=")));
}

#[test]
fn install_unit_keeps_the_agent_hardening_that_fits() {
    let install = unit_directives(INSTALL_UNIT);
    let agent = unit_directives("fleet-agent@.service");
    for key in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "PrivateNetwork=yes",
        "PrivateTmp=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "CapabilityBoundingSet=",
        "InaccessiblePaths=/etc/swarm",
        "InaccessiblePaths=-/run/docker.sock",
        "InaccessiblePaths=-/var/run/docker.sock",
        "TemporaryFileSystem=/run/fleet:ro",
        "BindReadOnlyPaths=/run/fleet/%i",
    ] {
        assert!(has_line(&install, key), "{key}");
    }
    assert!(!has_line(&install, "PrivateNetwork=no"));
    assert!(has_line(&agent, "PrivateNetwork=yes"));
    assert!(
        !install
            .iter()
            .any(|l| l.contains("docker") && !l.starts_with("InaccessiblePaths="))
    );
    assert!(install.iter().any(|l| l.starts_with("RuntimeMaxSec=")));
    assert!(install.iter().any(|l| l.starts_with("MemoryMax=")));
    assert!(install.iter().any(|l| l.starts_with("TasksMax=")));
}

#[test]
fn install_unit_writes_only_to_the_tools_dir_and_the_agent_mounts_it_read_only() {
    let install = unit_directives(INSTALL_UNIT);
    let agent = unit_directives("fleet-agent@.service");
    let tmpfiles = deploy_file("tmpfiles.d/fleet.conf");
    let writable: Vec<&String> = install
        .iter()
        .filter(|l| l.starts_with("ReadWritePaths="))
        .collect();
    assert_eq!(writable, ["ReadWritePaths=/var/lib/fleet/tools"]);
    assert!(
        !install
            .iter()
            .any(|l| { l.starts_with("ReadWritePaths=") && l.contains("/var/lib/fleet/jobs") })
    );
    assert!(has_line(
        &install,
        "Environment=MISE_DATA_DIR=/var/lib/fleet/tools"
    ));
    assert!(
        tmpfiles
            .lines()
            .any(|l| l == "d /var/lib/fleet/tools 0750 fleet-job fleet-work -")
    );
    assert!(has_line(&agent, "ReadOnlyPaths=/var/lib/fleet/tools"));
    assert!(
        !agent
            .iter()
            .any(|l| l.starts_with("ReadWritePaths=") && l.contains("tools"))
    );
}

#[test]
fn a_failed_install_unit_blocks_the_agent_unit() {
    let agent = unit_directives("fleet-agent@.service");
    let install = unit_directives(INSTALL_UNIT);
    assert!(has_line(&agent, "Requires=fleet-tool-install@%i.service"));
    assert!(has_line(&agent, "After=fleet-tool-install@%i.service"));
    assert!(has_line(&install, "Type=oneshot"));
    assert!(has_line(&install, "RemainAfterExit=yes"));
    assert!(has_line(&install, "BindsTo=fleetd.service"));
    assert!(has_line(&install, "After=fleetd.service"));
    assert!(!install.iter().any(|l| l.starts_with("SuccessExitStatus=")));
    assert!(!install.iter().any(|l| l.starts_with("ExecStart=-")));
    assert!(!install.iter().any(|l| l.contains("fleet-agent@")));
}

fn polkit_pattern(rule: &str, prefix: &str) -> String {
    rule.lines()
        .find(|l| l.contains(prefix))
        .and_then(|l| l.split_once("/^").map(|(_, r)| r))
        .and_then(|r| r.split_once("/.test").map(|(p, _)| format!("^{p}")))
        .unwrap_or_default()
}

fn instance_pattern_accepts(pattern: &str, prefix: &str, id: &str) -> bool {
    let want = format!("^{prefix}@[A-Za-z0-9_]{{1,64}}\\.service$");
    if pattern != want {
        return false;
    }
    let suffix = ".service";
    let Some(rest) = id.strip_prefix(&format!("{prefix}@")) else {
        return false;
    };
    let Some(inst) = rest.strip_suffix(suffix) else {
        return false;
    };
    (1..=64).contains(&inst.len())
        && inst.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !id.contains('\n')
}

#[test]
fn polkit_allows_the_install_template_with_the_same_instance_charset() {
    let rule = deploy_file("polkit/50-fleet-agent.rules");
    let install = polkit_pattern(&rule, "fleet-tool-install@");
    let agent = polkit_pattern(&rule, "fleet-agent@");
    assert_eq!(install, "^fleet-tool-install@[A-Za-z0-9_]{1,64}\\.service$");
    assert_eq!(
        agent.replace("fleet-agent", "X"),
        install.replace("fleet-tool-install", "X")
    );
    assert!(rule.contains("subject.user !== \"fleetd\""));
    assert!(rule.contains("polkit.Result.NO;"));
}

#[test]
fn install_instance_names_are_confined_to_the_agent_charset() {
    let rule = deploy_file("polkit/50-fleet-agent.rules");
    let pattern = polkit_pattern(&rule, "fleet-tool-install@");
    let good = ["a", "A_9", &"x".repeat(64)];
    for id in good {
        let unit = format!("fleet-tool-install@{id}.service");
        assert!(
            instance_pattern_accepts(&pattern, "fleet-tool-install", &unit),
            "{id}"
        );
    }
    let long = "x".repeat(65);
    let hostile = [
        "",
        "a-b",
        "a.b",
        "a/b",
        "a b",
        "a\r",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\\b",
        "a@b",
        "..",
        "a%20b",
        "\u{e9}",
        "a\0b",
        "a:b",
        "[::1]",
        long.as_str(),
    ];
    for id in hostile {
        let unit = format!("fleet-tool-install@{id}.service");
        assert!(
            !instance_pattern_accepts(&pattern, "fleet-tool-install", &unit),
            "{id:?}"
        );
    }
    assert!(!rule.contains("fleet-tool-install@.*"));
    assert!(!rule.contains("fleet-tool-install@[^"));
}

fn telemetry_case(id: &str) -> Result<Case, io::Error> {
    let case = Case::new(id)?;
    case.last(&show("active", "success", 0, 0))?;
    Ok(case)
}

fn spec_json(case: &Case) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(
        case.dir().join("spec.json"),
    )?)?)
}

fn fixed_port(port: u16) -> fleetd::systemd::PortSource {
    Arc::new(move || std::num::NonZeroU16::new(port).ok_or_else(|| io::Error::other("zero port")))
}

#[tokio::test]
async fn the_spec_carries_the_port_and_the_receiver_socket_is_group_shared() -> TestResult {
    let case = telemetry_case("t_tele_ok")?;
    let gid = fs::metadata(case.run.path())?.gid();
    let setup =
        TelemetrySetup::new(fleetd::otel::Limits::default()).with_port_source(fixed_port(4318));
    let launched = case
        .launcher()
        .with_job_gid(Some(gid))
        .with_telemetry(setup)
        .launch(otel_spec(&case, true))?;
    assert_eq!(spec_json(&case)?["telemetry_port"], 4318);
    let capture = launched.telemetry.as_ref().ok_or("no capture")?;
    assert_eq!(capture.port.get(), 4318);
    assert_eq!(capture.token.len(), 48);
    let meta = fs::symlink_metadata(case.dir().join("otel.sock"))?;
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o660);
    assert_eq!(meta.gid(), gid);
    assert_eq!(meta.uid(), fs::metadata(case.run.path())?.uid());
    Ok(())
}

#[tokio::test]
async fn the_default_port_is_nonzero() -> TestResult {
    let case = telemetry_case("t_tele_default")?;
    let setup = TelemetrySetup::new(fleetd::otel::Limits::default());
    let _launched = case
        .launcher()
        .with_telemetry(setup)
        .launch(otel_spec(&case, true))?;
    let port = spec_json(&case)?["telemetry_port"]
        .as_u64()
        .ok_or("no port")?;
    assert!(port > 0 && port <= 65535, "{port}");
    Ok(())
}

#[tokio::test]
async fn a_failed_port_or_token_fails_the_capture_and_not_the_job() -> TestResult {
    let no_port: fleetd::systemd::PortSource =
        Arc::new(|| Err(io::Error::other("no port available")));
    let short_token: fleetd::systemd::TokenSource = Arc::new(|| Ok("short".to_owned()));
    let failing = [
        ("t_tele_noport", Some(no_port), None),
        ("t_tele_badtoken", None, Some(short_token)),
    ];
    for (id, port, token) in failing {
        let case = telemetry_case(id)?;
        let mut setup =
            TelemetrySetup::new(fleetd::otel::Limits::default()).with_port_source(fixed_port(4318));
        if let Some(port) = port {
            setup = setup.with_port_source(port);
        }
        if let Some(token) = token {
            setup = setup.with_token_source(token);
        }
        let launched = case
            .launcher()
            .with_telemetry(setup)
            .launch(otel_spec(&case, true))?;
        assert!(launched.telemetry.is_none(), "{id}");
        assert!(spec_json(&case)?.get("telemetry_port").is_none(), "{id}");
        assert!(!case.dir().join("otel.sock").exists(), "{id}");
    }
    Ok(())
}

#[tokio::test]
async fn a_launcher_without_telemetry_writes_no_port() -> TestResult {
    let case = telemetry_case("t_tele_off")?;
    let launched = case.launch()?;
    assert!(launched.telemetry.is_none());
    assert!(spec_json(&case)?.get("telemetry_port").is_none());
    assert!(!case.dir().join("otel.sock").exists());
    Ok(())
}

const OTEL_NAMES: [&str; 7] = [
    "CLAUDE_CODE_ENABLE_TELEMETRY",
    "OTEL_LOGS_EXPORTER",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_LOGS_EXPORT_INTERVAL",
    "OTEL_LOG_TOOL_DETAILS",
];

fn otel_spec(case: &Case, otel: bool) -> AgentSpec {
    AgentSpec {
        otel,
        ..case.spec()
    }
}

fn env_file(case: &Case) -> Result<String, io::Error> {
    fs::read_to_string(case.dir().join("env"))
}

fn token_source(token: &'static str) -> fleetd::systemd::TokenSource {
    Arc::new(move || Ok(token.to_owned()))
}

#[tokio::test]
async fn a_claude_job_with_capture_gets_the_otel_env_in_the_env_file() -> TestResult {
    let case = telemetry_case("t_otel_claude")?;
    let setup = TelemetrySetup::new(fleetd::otel::Limits::default())
        .with_port_source(fixed_port(4318))
        .with_token_source(token_source("0123456789abcdef0123456789abcdef"));
    let launched = case
        .launcher()
        .with_telemetry(setup)
        .launch(otel_spec(&case, true))?;
    assert!(launched.telemetry.is_some());
    let env = env_file(&case)?;
    for name in OTEL_NAMES {
        let prefix = format!("{name}=");
        assert_eq!(
            env.lines().filter(|line| line.starts_with(&prefix)).count(),
            1,
            "{name}"
        );
    }
    assert!(env.contains("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=\"http://127.0.0.1:4318/v1/logs\"\n"));
    assert!(env.contains(
        "OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer 0123456789abcdef0123456789abcdef\"\n"
    ));
    assert!(env.contains("PROBE=\"probe-value-1\"\n"));
    Ok(())
}

#[tokio::test]
async fn a_claude_job_without_capture_gets_no_otel_variable() -> TestResult {
    let no_port: fleetd::systemd::PortSource = Arc::new(|| Err(io::Error::other("no port")));
    let case = telemetry_case("t_otel_nocapture")?;
    let setup = TelemetrySetup::new(fleetd::otel::Limits::default()).with_port_source(no_port);
    let launched = case
        .launcher()
        .with_telemetry(setup)
        .launch(otel_spec(&case, true))?;
    assert!(launched.telemetry.is_none());
    let env = env_file(&case)?;
    for name in OTEL_NAMES {
        assert!(!env.contains(name), "{name}");
    }
    assert!(env.contains("PROBE="));
    Ok(())
}

#[tokio::test]
async fn a_launcher_without_telemetry_gets_no_otel_variable_for_a_claude_job() -> TestResult {
    let case = telemetry_case("t_otel_unset")?;
    let launched = case.launcher().launch(otel_spec(&case, true))?;
    assert!(launched.telemetry.is_none());
    let env = env_file(&case)?;
    for name in OTEL_NAMES {
        assert!(!env.contains(name), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn a_codex_kimi_or_judge_job_gets_no_capture_and_no_otel_variable() -> TestResult {
    for id in ["t_otel_codex", "t_otel_kimi", "t_otel_judge"] {
        let case = telemetry_case(id)?;
        let setup =
            TelemetrySetup::new(fleetd::otel::Limits::default()).with_port_source(fixed_port(4318));
        let launched = case
            .launcher()
            .with_telemetry(setup)
            .launch(otel_spec(&case, false))?;
        assert!(launched.telemetry.is_none(), "{id}");
        assert!(spec_json(&case)?.get("telemetry_port").is_none(), "{id}");
        assert!(!case.dir().join("otel.sock").exists(), "{id}");
        let env = env_file(&case)?;
        for name in OTEL_NAMES {
            assert!(!env.contains(name), "{id} {name}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn the_fleet_otel_values_replace_any_value_already_in_the_spec_env() -> TestResult {
    let case = telemetry_case("t_otel_replace")?;
    let mut spec = otel_spec(&case, true);
    for name in OTEL_NAMES {
        spec.env.insert(name.into(), "planted-value".into());
    }
    let setup = TelemetrySetup::new(fleetd::otel::Limits::default())
        .with_port_source(fixed_port(4318))
        .with_token_source(token_source("0123456789abcdef0123456789abcdef"));
    let _launched = case.launcher().with_telemetry(setup).launch(spec)?;
    assert!(!env_file(&case)?.contains("planted-value"));
    Ok(())
}

#[tokio::test]
async fn a_token_outside_the_safe_alphabet_starts_no_capture_and_never_reaches_the_env_file()
-> TestResult {
    let hostile: [&'static str; 12] = [
        "aaaa,bbbb0123456789abcdef",
        "aaaa=bbbb0123456789abcdef",
        "aaaa\"bbbb0123456789abcdef",
        "aaaa\\bbbb0123456789abcdef",
        "aaaa$bbbb0123456789abcdef",
        "aaaa'bbbb0123456789abcdef",
        "aaaa bbbb0123456789abcdef",
        "aaaa%bbbb0123456789abcdef",
        "aaaa;bbbb0123456789abcdef",
        "aaaa\nbbbb0123456789abcdef",
        "aaaa\u{e9}bbbb0123456789abcdef",
        "aaaa+bbbb/0123456789abcdef==",
    ];
    for (n, token) in hostile.into_iter().enumerate() {
        let case = telemetry_case(&format!("t_otel_hostile{n}"))?;
        let setup = TelemetrySetup::new(fleetd::otel::Limits::default())
            .with_port_source(fixed_port(4318))
            .with_token_source(token_source(token));
        let launched = case
            .launcher()
            .with_telemetry(setup)
            .launch(otel_spec(&case, true))?;
        assert!(launched.telemetry.is_none(), "{token:?}");
        let env = env_file(&case)?;
        for name in OTEL_NAMES {
            assert!(!env.contains(name), "{token:?} {name}");
        }
        assert!(!case.dir().join("otel.sock").exists(), "{token:?}");
    }
    Ok(())
}

#[tokio::test]
async fn the_bearer_token_is_only_in_the_env_file_and_never_in_argv_or_logs() -> TestResult {
    const TOKEN: &str = "Zx9-_Qw8Er7TyUi6OpAs5DfGh4JkLz3X";
    let case = telemetry_case("t_otel_secret")?;
    let setup = TelemetrySetup::new(fleetd::otel::Limits::default())
        .with_port_source(fixed_port(4318))
        .with_token_source(token_source(TOKEN));
    let spec = otel_spec(&case, true);
    let mut launched = None;
    let logged = captured(|| {
        launched = case.launcher().with_telemetry(setup).launch(spec).ok();
    });
    let launched = launched.ok_or("launch failed")?;
    assert!(!logged.contains(TOKEN), "{logged}");
    assert!(!format!("{:?}", launched.telemetry).contains(TOKEN));
    assert!(!case.log().join("\n").contains(TOKEN));
    assert!(env_file(&case)?.contains(TOKEN));
    for entry in fs::read_dir(case.dir())? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name == "env") || !path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.contains(TOKEN), "{path:?}");
    }
    Ok(())
}

fn attested_config(launcher: &str) -> Result<Config, Error> {
    let none = |_: &str| None;
    Config::resolve(
        Some(&format!(
            "agent_launcher = \"{launcher}\"\nhost_netns_attested = true\n"
        )),
        &none,
    )
}

#[test]
fn select_launcher_enables_telemetry_only_when_the_host_netns_is_attested() -> TestResult {
    let none = |_: &str| None;
    let unattested = Config::resolve(Some("agent_launcher = \"systemd\"\n"), &none)?;
    assert_eq!(
        unattested.require_host_netns(),
        Err(fleetd::jobenv::TelemetryRefused::HostNetnsUnattested)
    );
    let attested = attested_config("systemd")?;
    assert_eq!(attested.require_host_netns(), Ok(()));
    let on = format!("{:?}", select_launcher(&attested, None, Services::new()));
    assert!(on.contains("telemetry: Some("), "{on}");
    let logged = captured(|| {
        let off = format!("{:?}", select_launcher(&unattested, None, Services::new()));
        assert!(off.contains("telemetry: None"), "{off}");
    });
    assert!(
        logged.contains("telemetry needs host_netns_attested = true in the fleetd config"),
        "{logged}"
    );
    let quiet = captured(|| {
        let _ = select_launcher(&attested, None, Services::new());
    });
    assert!(!quiet.contains("host_netns_attested"), "{quiet}");
    Ok(())
}

#[test]
fn an_attested_direct_launcher_starts_no_telemetry() -> TestResult {
    let direct = attested_config("direct")?;
    let shown = format!("{:?}", select_launcher(&direct, None, Services::new()));
    assert!(!shown.contains("TelemetrySetup"), "{shown}");
    Ok(())
}

#[test]
fn the_fleetd_unit_shares_the_host_network_namespace() -> TestResult {
    let unit = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/fleetd-systemd.service"
    ))?;
    assert!(!unit.contains("PrivateNetwork"), "{unit}");
    assert!(!unit.contains("NetworkNamespacePath"), "{unit}");
    Ok(())
}

#[derive(Debug)]
struct TmpfsIs(bool);

impl MountCheck for TmpfsIs {
    fn is_tmpfs(&self, _dir: std::os::fd::BorrowedFd<'_>) -> io::Result<bool> {
        Ok(self.0)
    }
}

fn held_env(marker: &str) -> ReleasedEnvironment {
    ReleasedEnvironment::from_reply(fleet_proto::v1::GetJobEnvironmentReply {
        secrets: vec![fleet_proto::v1::JobEnvironmentSecret {
            name: "PVE_TOKEN".into(),
            value: marker.into(),
            agent_visible: true,
            delivery: fleet_proto::v1::EnvironmentDelivery::File.into(),
        }],
        ..fleet_proto::v1::GetJobEnvironmentReply::default()
    })
}

fn delivery_for(case: &Case, tmpfs: bool, marker: &str) -> io::Result<Arc<EnvDelivery>> {
    let delivery = Arc::new(
        EnvDelivery::new(
            case.run.path(),
            Owner {
                uid: None,
                gid: None,
            },
            Arc::new(TmpfsIs(tmpfs)),
        )
        .map_err(io::Error::other)?,
    );
    delivery.hold(&case.id, held_env(marker));
    Ok(delivery)
}

#[tokio::test]
async fn the_delivery_tree_exists_before_the_unit_starts_and_leaves_with_the_dir() -> TestResult {
    const MARKER: &str = "zq-env-marker-9981-unlikely";
    let case = Case::new("t_delivery_tree")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let delivery = delivery_for(&case, true, MARKER)?;
    let unit = case.launcher().with_delivery(Arc::clone(&delivery));
    let mut launched = unit.launch(case.spec())?;
    let secret = case.dir().join(DELIVERY_DIR).join("PVE_TOKEN");
    assert_eq!(fs::read_to_string(&secret)?, MARKER);
    assert_eq!(fs::metadata(&secret)?.mode() & 0o7777, 0o400);
    assert_eq!(case.seen_envd(), ["start envd"]);
    let env = fs::read_to_string(case.dir().join("env"))?;
    assert!(!env.contains(MARKER));
    assert_eq!(waited(launched.proc.as_mut()).await?.code(), Some(0));
    drop(launched);
    assert!(!case.dir().exists());
    Ok(())
}

#[tokio::test]
async fn a_refused_delivery_write_fails_the_launch_before_the_unit_and_leaves_nothing() -> TestResult
{
    const MARKER: &str = "zq-env-marker-5513-unlikely";
    let case = Case::new("t_delivery_refused")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let delivery = delivery_for(&case, false, MARKER)?;
    let launcher = case.launcher().with_delivery(delivery);
    let err = launcher.launch(case.spec()).err().ok_or("launched")?;
    assert!(!err.to_string().contains(MARKER), "{err}");
    assert!(case.log().iter().all(|line| !line.starts_with("start")));
    assert_eq!(fs::read_dir(case.run.path())?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn a_launcher_without_delivery_writes_no_tree_for_a_held_environment() -> TestResult {
    let case = Case::new("t_delivery_none")?;
    case.last(&show("inactive", "success", 1, 0))?;
    let _held = delivery_for(&case, true, "zq-env-marker-0042-unlikely")?;
    let launched = case.launch()?;
    assert!(!case.dir().join(DELIVERY_DIR).exists());
    drop(launched);
    Ok(())
}
