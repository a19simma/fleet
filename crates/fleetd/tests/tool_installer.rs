//! The production tool installer against a fake `systemctl`: a missing tool starts exactly one
//! `fleet-tool-install@<id>.service` with the expected argv, the unit sees `mise.toml`,
//! `tool-env` and the job socket, a hit starts nothing, and every failure (non-zero unit,
//! start refused, deadline, ambiguous or hostile state, host list too small) ends the job with
//! the one fixed message and cleans up the unit and the run dir. Own test binary because it
//! spawns children. Nothing here touches a live box.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::ffi::OsString;
use std::fs;
use std::future::{Future, ready};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fleet_core::tools::{ToolName, ToolSpec};
use fleet_core::{Profile, Redactor};
use fleet_proto::v1::{
    GetProfileBlobReply, GetProfileBlobRequest, Job, ProfileRef, ReportJobReply, ReportJobRequest,
};
use fleetd::Config;
use fleetd::jobsock::Services;
use fleetd::poller::Shutdown;
use fleetd::runner::{
    AgentOutcome, AgentRunner, Reporter, RunConfig, TOOL_PREFLIGHT_FAILED, ToolInstaller,
    ToolPreflight,
};
use fleetd::systemd::{
    JobSocketSetup, SystemdToolInstaller, select_launcher, select_tool_installer,
};
use fleetd::tools::{ToolCache, tool_hosts};
use tempfile::TempDir;
use tonic::Status;

const SCRIPT: &str = r#"#!/bin/sh
root=$(dirname "$0")
unit=
for a in "$@"; do
  case "$a" in fleet-tool-install@*) unit=$a;; esac
done
id=${unit#fleet-tool-install@}
id=${id%.service}
st=$root/$id
mkdir -p "$st"
echo "$*" >> "$st/log"
case "$1" in
  start)
    rd=$(cat "$st/rundir")
    cp "$rd/$id/mise.toml" "$st/seen-mise.toml"
    cp "$rd/$id/tool-env" "$st/seen-tool-env"
    ls -ln "$rd/$id/mise.toml" > "$st/seen-mise-ls"
    if [ -S "$rd/$id/job.sock" ]; then echo sock > "$st/seen-sock"; fi
    if [ -f "$st/cache" ]; then
      cache=$(cat "$st/cache")
      mkdir -p "$cache/jq/1.7.1/bin"
      chmod 755 "$cache/jq" "$cache/jq/1.7.1" "$cache/jq/1.7.1/bin"
    fi
    exit "$(cat "$st/start.rc" 2>/dev/null || echo 0)"
    ;;
  stop)
    rd=$(cat "$st/rundir")
    if [ -S "$rd/$id/job.sock" ]; then echo sock > "$st/stop-sock"; fi
    ;;
  show)
    n=$(cat "$st/n" 2>/dev/null || echo 0)
    n=$((n+1))
    echo "$n" > "$st/n"
    if [ -f "$st/show.$n" ]; then cat "$st/show.$n"; else cat "$st/show.last"; fi
    exit "$(cat "$st/show.rc" 2>/dev/null || echo 0)"
    ;;
esac
exit 0
"#;

const AGENT: &str = r#"#!/bin/sh
[ "$1" = --version ] && { echo '2.0.0 (Claude Code)'; exit 0; }
printf '%s' "$PATH" > "$PWD/seen-path"
"#;

const ID: &str = "job1";

fn show(state: &str, sub: &str, result: &str, code: u32, status: u32) -> String {
    format!(
        "ActiveState={state}\nSubState={sub}\nResult={result}\nExecMainCode={code}\nExecMainStatus={status}\n"
    )
}

fn ok_show() -> String {
    show("active", "exited", "success", 1, 0)
}

struct Fx {
    dir: TempDir,
    ctl: PathBuf,
    run: PathBuf,
    cache: PathBuf,
    state: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let ctl = dir.path().join("systemctl");
        fs::write(&ctl, SCRIPT).unwrap();
        fs::set_permissions(&ctl, fs::Permissions::from_mode(0o755)).unwrap();
        let run = dir.path().join("run");
        let cache = dir.path().join("tools");
        fs::create_dir(&run).unwrap();
        fs::create_dir(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
        let state = dir.path().join(ID);
        fs::create_dir(&state).unwrap();
        fs::write(state.join("rundir"), run.to_str().unwrap()).unwrap();
        fs::write(state.join("cache"), cache.to_str().unwrap()).unwrap();
        fs::write(state.join("show.last"), ok_show()).unwrap();
        Self {
            dir,
            ctl,
            run,
            cache,
            state,
        }
    }

    fn put(&self, name: &str, body: &str) {
        fs::write(self.state.join(name), body).unwrap();
    }

    fn log(&self) -> Vec<String> {
        fs::read_to_string(self.state.join("log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn count(&self, verb: &str) -> usize {
        self.log()
            .iter()
            .filter(|line| line.split(' ').next() == Some(verb))
            .count()
    }

    async fn wait_for(&self, verb: &str, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.count(verb) < want {
            assert!(
                Instant::now() < deadline,
                "no {verb} logged: {:?}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn installer(&self) -> SystemdToolInstaller {
        SystemdToolInstaller::new(&self.ctl, covering(&[ToolName::Jq, ToolName::Node]))
            .with_run_dir(&self.run)
            .with_poll_interval(Duration::from_millis(10))
            .with_start_deadline(Duration::from_secs(30))
            .with_run_deadline(Duration::from_secs(30))
            .with_job_socket(JobSocketSetup::new(Services::new()))
    }

    fn run_dir_gone(&self) -> bool {
        !self.run.join(ID).exists()
    }
}

fn covering(tools: &[ToolName]) -> Vec<String> {
    tool_hosts(tools).iter().map(|h| (*h).to_owned()).collect()
}

fn jq() -> ToolSpec {
    ToolSpec::new("jq", "1.7.1").unwrap()
}

async fn install(installer: &SystemdToolInstaller, tools: &[ToolSpec]) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(60), installer.install(ID, tools))
        .await
        .unwrap()
}

#[tokio::test]
async fn one_missing_tool_starts_exactly_one_unit_with_the_expected_argv() {
    let fx = Fx::new();
    install(&fx.installer(), &[jq()]).await.unwrap();
    let unit = format!("fleet-tool-install@{ID}.service");
    let log = fx.log();
    assert_eq!(fx.count("start"), 1, "{log:?}");
    assert_eq!(log[0], format!("start --no-block {unit}"));
    assert!(log.contains(&format!("stop {unit}")), "{log:?}");
    assert!(log.contains(&format!("reset-failed {unit}")), "{log:?}");
    assert_eq!(
        fs::read_to_string(fx.state.join("seen-mise.toml")).unwrap(),
        "[tools]\njq = \"1.7.1\"\n"
    );
    let env = fs::read_to_string(fx.state.join("seen-tool-env")).unwrap();
    assert!(env.starts_with("HTTPS_PROXY=http://127.0.0.1:"), "{env}");
    assert_eq!(
        fs::read_to_string(fx.state.join("seen-sock"))
            .unwrap()
            .trim(),
        "sock"
    );
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn two_missing_tools_share_one_unit_start_and_one_mise_toml() {
    let fx = Fx::new();
    let tools = [jq(), ToolSpec::new("node", "20.11.1").unwrap()];
    install(&fx.installer(), &tools).await.unwrap();
    assert_eq!(fx.count("start"), 1);
    assert_eq!(
        fs::read_to_string(fx.state.join("seen-mise.toml")).unwrap(),
        "[tools]\njq = \"1.7.1\"\nnode = \"20.11.1\"\n"
    );
}

#[tokio::test]
async fn mise_toml_belongs_to_the_job_group_with_mode_0640() {
    let fx = Fx::new();
    let gid = fs::metadata(fx.dir.path()).unwrap().gid();
    let installer = fx.installer().with_job_gid(Some(gid));
    install(&installer, &[jq()]).await.unwrap();
    let listing = fs::read_to_string(fx.state.join("seen-mise-ls")).unwrap();
    let mut fields = listing.split_whitespace();
    assert_eq!(fields.next(), Some("-rw-r-----"));
    assert_eq!(fields.nth(2), Some(gid.to_string().as_str()), "{listing}");
}

type HookCall = (String, Vec<String>, usize);
type InstallerCase = Box<dyn Fn(&Fx) -> SystemdToolInstaller>;

#[tokio::test]
async fn the_hosts_hook_gets_the_install_hosts_before_the_unit_starts() {
    let fx = Fx::new();
    let seen: Arc<Mutex<Vec<HookCall>>> = Arc::default();
    let log_path = fx.state.join("log");
    let sink = Arc::clone(&seen);
    let installer = fx.installer().with_hosts_hook(Arc::new(move |id, hosts| {
        let starts = fs::read_to_string(&log_path).unwrap_or_default().len();
        sink.lock().unwrap_or_else(PoisonError::into_inner).push((
            id.to_owned(),
            hosts.iter().map(|h| (*h).to_owned()).collect(),
            starts,
        ));
    }));
    install(&installer, &[jq()]).await.unwrap();
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, ID);
    assert_eq!(seen[0].1, covering(&[ToolName::Jq]));
    assert_eq!(seen[0].2, 0);
}

#[tokio::test]
async fn a_failed_unit_is_an_error_and_is_cleaned_up() {
    let fx = Fx::new();
    fx.put("show.last", &show("failed", "failed", "exit-code", 1, 1));
    let err = install(&fx.installer(), &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(fx.count("stop"), 1);
    assert_eq!(fx.count("reset-failed"), 1);
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn a_refused_start_is_an_error_and_is_cleaned_up() {
    let fx = Fx::new();
    fx.put("start.rc", "1");
    let err = install(&fx.installer(), &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(fx.count("show"), 0);
    assert_eq!(fx.count("reset-failed"), 1);
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn a_unit_past_the_run_deadline_is_killed_and_counts_as_ended() {
    let fx = Fx::new();
    fx.put("show.last", &show("active", "running", "success", 0, 0));
    let installer = fx.installer().with_run_deadline(Duration::from_millis(200));
    let began = Instant::now();
    let err = install(&installer, &[jq()]).await.unwrap_err();
    assert!(began.elapsed() < Duration::from_secs(15));
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    let unit = format!("fleet-tool-install@{ID}.service");
    assert!(
        fx.log()
            .contains(&format!("kill --kill-whom=all --signal=SIGKILL {unit}")),
        "{:?}",
        fx.log()
    );
    assert_eq!(fx.count("stop"), 1);
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn a_unit_that_never_ran_is_killed_after_the_start_deadline() {
    let fx = Fx::new();
    fx.put("show.last", &show("inactive", "dead", "success", 0, 0));
    let installer = fx
        .installer()
        .with_start_deadline(Duration::from_millis(200));
    let began = Instant::now();
    let err = install(&installer, &[jq()]).await.unwrap_err();
    assert!(began.elapsed() < Duration::from_secs(15));
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert_eq!(fx.count("kill"), 1);
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn an_unreadable_state_is_killed_and_counts_as_ended() {
    let fx = Fx::new();
    fx.put("show.last", "");
    fx.put("show.rc", "1");
    let err = install(&fx.installer(), &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(fx.count("kill"), 1);
    assert_eq!(fx.count("reset-failed"), 1);
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn hostile_unit_output_is_an_error_and_never_an_install() {
    let hostile = [
        format!("{}Extra=1\n", ok_show()),
        format!("{}{}", ok_show(), ok_show()),
        "ActiveState=active\nSubState=exited\n".to_owned(),
        ok_show().replace("ExecMainStatus=0", "ExecMainStatus=zero"),
        ok_show().replace("active", "evil\rstate"),
        "x".repeat(8192),
        "secret-token /home/leak\n".to_owned(),
    ];
    for body in hostile {
        let fx = Fx::new();
        fx.put("show.last", &body);
        let err = install(&fx.installer(), &[jq()]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{body:?}");
        assert!(!err.to_string().contains("secret"), "{err}");
        assert_eq!(fx.count("kill"), 1, "{body:?}");
        assert!(fx.run_dir_gone());
    }
}

#[tokio::test]
async fn a_host_list_that_misses_a_tool_host_starts_nothing() {
    let fx = Fx::new();
    let installer =
        SystemdToolInstaller::new(&fx.ctl, vec!["api.github.com".to_owned()]).with_run_dir(&fx.run);
    let err = install(&installer, &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fx.log(), Vec::<String>::new());
    assert!(fx.run_dir_gone());
}

#[tokio::test]
async fn bad_input_starts_nothing() {
    let fx = Fx::new();
    let installer = fx.installer();
    let err = installer.install("../x", &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let err = installer.install(ID, &[]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let relative =
        SystemdToolInstaller::new("systemctl", covering(&[ToolName::Jq])).with_run_dir(&fx.run);
    let err = relative.install(ID, &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(fx.log(), Vec::<String>::new());
}

#[tokio::test]
async fn an_existing_run_dir_is_refused_and_left_alone() {
    let fx = Fx::new();
    fs::create_dir(fx.run.join(ID)).unwrap();
    let err = install(&fx.installer(), &[jq()]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert!(fx.run.join(ID).exists());
    assert_eq!(fx.log(), Vec::<String>::new());
}

#[tokio::test]
async fn a_dropped_install_kills_the_unit_and_removes_the_run_dir() {
    let fx = Fx::new();
    fx.put("show.last", &show("active", "running", "success", 0, 0));
    let installer = fx.installer();
    let tools = [jq()];
    let pending = installer.install(ID, &tools);
    tokio::select! {
        _ = pending => panic!("install finished before it was dropped"),
        () = fx.wait_for("start", 1) => {}
    }
    assert_eq!(fx.count("start"), 1);
    assert_eq!(fx.count("kill"), 1, "{:?}", fx.log());
    assert_eq!(fx.count("reset-failed"), 1);
    assert!(fx.run_dir_gone());
}

struct Server {
    reports: Mutex<Vec<ReportJobRequest>>,
    profile: Profile,
}

#[derive(Clone)]
struct Handle(Arc<Server>);

impl Reporter for Handle {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        self.0
            .reports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        ready(Ok(ReportJobReply::default()))
    }

    fn profile_blob(
        &self,
        request: GetProfileBlobRequest,
    ) -> impl Future<Output = Result<GetProfileBlobReply, Status>> + Send {
        let _ = request;
        ready(Ok(GetProfileBlobReply {
            profile: Some(reference(&self.0.profile)),
            content: self.0.profile.canonical_json(),
        }))
    }
}

fn reference(profile: &Profile) -> ProfileRef {
    ProfileRef {
        name: "p".into(),
        version: 1,
        hash: profile.hash().to_string(),
    }
}

fn job(profile: &Profile) -> Job {
    Job {
        job_id: ID.into(),
        attempt: 1,
        r#box: "boxa".into(),
        prompt: "go".into(),
        profile: Some(reference(profile)),
        profile_tools_granted: true,
        ..Job::default()
    }
}

fn runner(fx: &Fx, installer: SystemdToolInstaller) -> (AgentRunner<Handle>, Profile) {
    let profile = Profile {
        model: Some("opus".into()),
        tools: vec![jq()],
        ..Profile::default()
    };
    let agent = fx.dir.path().join("claude");
    fs::write(&agent, AGENT).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    let server = Arc::new(Server {
        reports: Mutex::new(Vec::new()),
        profile: profile.clone(),
    });
    let mut config = RunConfig::new(agent, true);
    config.base_env = vec![("PATH".into(), OsString::from("/inherited/bin"))];
    config.jobs_dir = Some(fx.dir.path().join("jobs"));
    let owner = fs::metadata(&fx.cache).unwrap().uid();
    let installer: Arc<dyn ToolInstaller> = Arc::new(installer);
    let runner = AgentRunner::new(config, Handle(server), Redactor::default()).with_tool_preflight(
        ToolPreflight::new(ToolCache::new(&fx.cache, owner)).with_installer(installer),
    );
    (runner, profile)
}

#[tokio::test]
async fn a_missing_tool_installs_through_the_unit_and_the_job_runs_with_it_on_path() {
    let fx = Fx::new();
    let (runner, profile) = runner(&fx, fx.installer());
    let job = job(&profile);
    let cwd = fx.dir.path().join("work");
    fs::create_dir_all(&cwd).unwrap();
    let (_trigger, shutdown) = Shutdown::channel();
    runner.load_profile(&job, "boxa").await.unwrap();
    runner.preflight_tools(&job).await.unwrap();
    let outcome = runner.run(&job, &cwd, shutdown).await.unwrap();
    assert!(matches!(outcome, AgentOutcome::Succeeded), "{outcome:?}");
    assert_eq!(fx.count("start"), 1);
    let path = fs::read_to_string(cwd.join("seen-path")).unwrap();
    let bin = fx.cache.join("jq").join("1.7.1").join("bin");
    assert_eq!(
        path,
        format!("{}:/usr/local/bin:/usr/bin:/bin", bin.display())
    );
}

#[tokio::test]
async fn a_cache_hit_starts_no_unit() {
    let fx = Fx::new();
    let bin = fx.cache.join("jq").join("1.7.1").join("bin");
    fs::create_dir_all(&bin).unwrap();
    for dir in [fx.cache.join("jq"), fx.cache.join("jq").join("1.7.1"), bin] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (runner, profile) = runner(&fx, fx.installer());
    let job = job(&profile);
    runner.load_profile(&job, "boxa").await.unwrap();
    runner.preflight_tools(&job).await.unwrap();
    assert_eq!(fx.log(), Vec::<String>::new());
}

#[tokio::test]
async fn every_installer_failure_gives_the_fixed_message_without_detail() {
    let cases: Vec<(&str, InstallerCase)> = vec![
        (
            "unit failed",
            Box::new(|fx| {
                fx.put("show.last", &show("failed", "failed", "exit-code", 1, 1));
                fx.installer()
            }),
        ),
        (
            "start refused",
            Box::new(|fx| {
                fx.put("start.rc", "1");
                fx.installer()
            }),
        ),
        (
            "deadline",
            Box::new(|fx| {
                fx.put("show.last", &show("active", "running", "success", 0, 0));
                fx.installer().with_run_deadline(Duration::from_millis(100))
            }),
        ),
        (
            "ambiguous",
            Box::new(|fx| {
                fx.put("show.last", "secret-stderr /home/leak\n");
                fx.installer()
            }),
        ),
        (
            "hosts",
            Box::new(|fx| SystemdToolInstaller::new(&fx.ctl, Vec::new()).with_run_dir(&fx.run)),
        ),
        (
            "unit ran but cache stayed empty",
            Box::new(|fx| {
                fs::remove_file(fx.state.join("cache")).unwrap();
                fx.installer()
            }),
        ),
    ];
    for (name, make) in cases {
        let fx = Fx::new();
        let installer = make(&fx);
        let (runner, profile) = runner(&fx, installer);
        let job = job(&profile);
        runner.load_profile(&job, "boxa").await.unwrap();
        let err = runner.preflight_tools(&job).await.unwrap_err();
        assert_eq!(err, TOOL_PREFLIGHT_FAILED, "{name}");
        assert_eq!(TOOL_PREFLIGHT_FAILED, "tool preflight failed");
        assert!(fx.run_dir_gone(), "{name}");
    }
}

const MISE: &str = "[mise]\nversion = \"2024.11.3\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nsignature_path = \"/etc/mise.minisig\"\npublic_key_path = \"/etc/mise.pub\"\n";

fn config(text: &str) -> Config {
    Config::resolve(Some(text), &|_| None).unwrap()
}

#[test]
fn the_production_installer_exists_only_for_systemd_with_mise() {
    let systemd = format!("agent_launcher = \"systemd\"\n{MISE}");
    let direct = format!("agent_launcher = \"direct\"\n{MISE}");
    let plain = "agent_launcher = \"systemd\"\n";
    let pick = |text: &str| select_tool_installer(&config(text), None, Services::new(), None);
    assert!(pick(&systemd).is_some());
    assert!(pick(&direct).is_none());
    assert!(pick(plain).is_none());
}

#[test]
fn the_production_launcher_sets_tool_install_when_mise_is_configured() {
    let with = config(&format!("agent_launcher = \"systemd\"\n{MISE}"));
    let without = config("agent_launcher = \"systemd\"\n");
    let shown = |config: &Config| format!("{:?}", select_launcher(config, None, Services::new()));
    assert!(
        shown(&with).contains("tool_install: Some"),
        "{}",
        shown(&with)
    );
    assert!(shown(&without).contains("tool_install: None"));
}

#[test]
fn write_mise_toml_refuses_hostile_targets() {
    let dir = TempDir::new().unwrap();
    let run = dir.path().join("run");
    fs::create_dir(&run).unwrap();
    let tools = [jq()];
    for id in ["", "a/b", "..", "a b", "j\nk"] {
        assert!(
            fleetd::tools::write_mise_toml(&run, id, &tools, None).is_err(),
            "{id:?}"
        );
    }
    fs::create_dir(run.join("j3")).unwrap();
    assert!(fleetd::tools::write_mise_toml(&run, "j3", &[], None).is_err());
    assert!(!run.join("j3").join("mise.toml").exists());
    assert!(fleetd::tools::write_mise_toml(&run, "j1", &tools, None).is_err());
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, run.join("j1")).unwrap();
    assert!(fleetd::tools::write_mise_toml(&run, "j1", &tools, None).is_err());
    assert!(!elsewhere.join("mise.toml").exists());
    fs::create_dir(run.join("j2")).unwrap();
    let path = fleetd::tools::write_mise_toml(&run, "j2", &tools, None).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(fleetd::tools::write_mise_toml(&run, "j2", &tools, None).is_err());
}

#[test]
fn render_mise_toml_lists_each_tool_once_in_order() {
    let tools = [jq(), ToolSpec::new("uv", "0.5.1").unwrap()];
    assert_eq!(
        fleetd::tools::render_mise_toml(&tools),
        "[tools]\njq = \"1.7.1\"\nuv = \"0.5.1\"\n"
    );
    assert_eq!(fleetd::tools::render_mise_toml(&[]), "[tools]\n");
}

#[tokio::test]
async fn the_job_socket_is_closed_before_the_unit_is_stopped() {
    let fx = Fx::new();
    install(&fx.installer(), &[jq()]).await.unwrap();
    assert!(fx.state.join("seen-sock").exists());
    assert!(!fx.state.join("stop-sock").exists());
}

#[tokio::test]
async fn the_tool_count_is_capped_at_the_cache_entry_limit() {
    let fx = Fx::new();
    let at_cap = vec![jq(); fleetd::tools::MAX_CACHE_ENTRIES];
    install(&fx.installer(), &at_cap).await.unwrap();
    let fx = Fx::new();
    let over = vec![jq(); fleetd::tools::MAX_CACHE_ENTRIES + 1];
    let err = install(&fx.installer(), &over).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(fx.log(), Vec::<String>::new());
}

#[test]
fn only_exact_egress_hosts_count_toward_the_install_check() {
    let text = format!(
        "agent_launcher = \"systemd\"\negress_allow = [\"a.example.com\", \"*.example.org\", \"b.example.net\"]\n{MISE}"
    );
    let installer = select_tool_installer(&config(&text), None, Services::new(), None).unwrap();
    assert!(
        format!("{installer:?}").contains("egress_allow: 2"),
        "{installer:?}"
    );
    let launcher = select_launcher(&config(&text), None, Services::new());
    assert!(
        format!("{launcher:?}").contains("egress_allow: 2"),
        "{launcher:?}"
    );
}

#[test]
fn the_hosts_hook_reaches_the_production_installer() {
    let text = format!("agent_launcher = \"systemd\"\n{MISE}");
    let hook: fleetd::systemd::HostsHook = Arc::new(|_, _| {});
    let with = select_tool_installer(&config(&text), None, Services::new(), Some(hook)).unwrap();
    assert!(format!("{with:?}").contains("hosts_hook: true"), "{with:?}");
    let without = select_tool_installer(&config(&text), None, Services::new(), None).unwrap();
    assert!(
        format!("{without:?}").contains("hosts_hook: false"),
        "{without:?}"
    );
}
