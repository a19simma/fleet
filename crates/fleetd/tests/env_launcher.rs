//! The production Setup launcher (ADR-0067 decision 6) against a fake `systemctl` that runs the
//! real `fleetd env-setup-exec` shim, and the shim on its own. Own test binary: it spawns
//! children and binds sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{
    EnvironmentOnFail, EnvironmentScriptSpec, GetJobEnvironmentReply, JobEnvironmentSecret,
};
use fleetd::env_launcher::{EnvExecError, SystemdSetupLauncher, env_unit_name, run_env_step};
use fleetd::env_setup::EnvSetup;
use fleetd::envd::{EnvDelivery, MountCheck, Owner, ReleasedEnvironment};
use tempfile::TempDir;

#[path = "common/bounded.rs"]
mod bounded;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const JOB: &str = "job1";
const TOKEN: &str = "setup-only-token-value-9921";

const SCRIPT: &str = r#"#!/bin/sh
root=$(dirname "$0")
unit=
for a in "$@"; do
  case "$a" in fleet-env@*) unit=$a;; esac
done
id=${unit#fleet-env@}
id=${id%.service}
echo "$*" >> "$root/log"
down() {
  p=$(cat "$root/pid" 2>/dev/null)
  if [ -n "$p" ]; then
    pkill -KILL -P "$p" 2>/dev/null
    kill -KILL "$p" 2>/dev/null
  fi
}
case "$1" in
  start)
    if [ -f "$root/start.rc" ]; then exit "$(cat "$root/start.rc")"; fi
    rm -f "$root/rc"
    (
      sh -c 'echo $$ > "$1/pid"; exec "$2" env-setup-exec "$3" --run-dir "$4"' sh "$root" "$(cat "$root/bin")" "$id" "$(cat "$root/runroot")" >/dev/null 2>>"$root/shim.err"
      echo $? > "$root/rc"
    ) &
    exit 0
    ;;
  show)
    case "$*" in
      *ControlGroup*) printf 'ControlGroup=%s\n' "$(cat "$root/cgroup")"; exit 0;;
    esac
    if [ ! -f "$root/pid" ]; then
      printf 'ActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n'
    elif [ ! -f "$root/rc" ]; then
      printf 'ActiveState=activating\nSubState=start\nResult=success\nExecMainCode=0\nExecMainStatus=0\n'
    else
      rc=$(cat "$root/rc")
      if [ "$rc" = 0 ]; then
        printf 'ActiveState=active\nSubState=exited\nResult=success\nExecMainCode=1\nExecMainStatus=0\n'
      else
        printf 'ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=%s\n' "$rc"
      fi
    fi
    ;;
  kill|stop)
    down
    if [ "$1" = stop ]; then rm -f "$root/pid"; fi
    ;;
  list-units)
    cat "$root/units" 2>/dev/null
    ;;
esac
exit 0
"#;

#[derive(Debug)]
struct Tmpfs;

impl MountCheck for Tmpfs {
    fn is_tmpfs(&self, _: std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool> {
        Ok(true)
    }
}

struct Fix {
    dir: TempDir,
    run_root: PathBuf,
}

impl Fix {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let run_root = dir.path().join("env");
        fs::create_dir(&run_root).unwrap();
        let path = dir.path().join("systemctl");
        fs::write(&path, SCRIPT).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.path().join("bin"), env!("CARGO_BIN_EXE_fleetd")).unwrap();
        fs::write(dir.path().join("runroot"), run_root.to_str().unwrap()).unwrap();
        Self { dir, run_root }
    }

    fn systemctl(&self) -> PathBuf {
        self.dir.path().join("systemctl")
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("log")).unwrap_or_default()
    }

    fn launcher(&self) -> SystemdSetupLauncher {
        SystemdSetupLauncher::new(self.systemctl(), &self.run_root)
            .with_poll_interval(Duration::from_millis(20))
    }

    fn setup(&self, scripts: Vec<EnvironmentScriptSpec>) -> EnvSetup {
        let delivery_root = self.dir.path().join("run");
        fs::create_dir_all(&delivery_root).unwrap();
        let delivery = Arc::new(
            EnvDelivery::new(
                &delivery_root,
                Owner {
                    uid: None,
                    gid: None,
                },
                Arc::new(Tmpfs),
            )
            .unwrap(),
        );
        delivery.hold(
            JOB,
            ReleasedEnvironment::from_reply(GetJobEnvironmentReply {
                scripts,
                secrets: vec![JobEnvironmentSecret {
                    name: "TOKEN".to_owned(),
                    value: TOKEN.to_owned(),
                    agent_visible: false,
                    ..JobEnvironmentSecret::default()
                }],
                ..GetJobEnvironmentReply::default()
            }),
        );
        EnvSetup::new(Arc::new(self.launcher()), delivery, &self.run_root)
            .with_drain_grace(Duration::from_millis(500))
    }
}

fn script(name: &str, body: &str, secs: u32) -> EnvironmentScriptSpec {
    EnvironmentScriptSpec {
        name: name.to_owned(),
        body: format!("#!/bin/sh\n{body}\n"),
        on_fail: EnvironmentOnFail::Abort.into(),
        timeout_s: Some(secs),
    }
}

fn redactor() -> Redactor {
    Redactor::new([TOKEN])
}

#[tokio::test]
async fn a_step_runs_in_the_unit_and_its_output_comes_back() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        let setup = fix.setup(vec![script(
            "one",
            "echo hello-from-the-unit; echo err >&2",
            20,
        )]);
        let report = setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed, None, "{:?}", report.notes);
        let notes = report.notes.join("\n");
        assert!(notes.contains("hello-from-the-unit"), "{notes}");
        assert!(notes.contains("err"), "{notes}");
        let log = fix.log();
        assert!(
            log.contains("start --no-block fleet-env@job1.service"),
            "{log}"
        );
        assert!(log.contains("stop fleet-env@job1.service"), "{log}");
        assert!(!fix.run_root.join(JOB).exists());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn the_exit_status_comes_from_the_unit_not_the_output() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        let setup = fix.setup(vec![script("one", "echo exit 0; exit 3", 20)]);
        let report = setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed.as_deref(), Some("one"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn the_step_sees_a_writable_out_dir_and_the_setup_only_secret() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        let body = format!(
            "echo product > \"$FLEET_ENV_OUT/p\" || exit 4\ncat \"$FLEET_ENV_OUT/p\"\ntest \"$(cat \"$FLEET_ENV_SECRETS/TOKEN\")\" = {TOKEN} || exit 5\necho out=$FLEET_ENV_OUT"
        );
        let setup = fix.setup(vec![script("one", &body, 20)]);
        let report = setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed, None, "{:?}", report.notes);
        let notes = report.notes.join("\n");
        assert!(notes.contains("product"), "{notes}");
        let out = format!("out={}", fix.run_root.join(JOB).join("out").display());
        assert!(notes.contains(&out), "{notes} / {out}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_unit_that_cannot_start_fails_the_job_even_for_a_continue_step() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        fs::write(fix.dir.path().join("start.rc"), "1").unwrap();
        let mut one = script("one", "true", 20);
        one.on_fail = EnvironmentOnFail::Continue.into();
        let setup = fix.setup(vec![one, script("two", "true", 20)]);
        let report = setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed.as_deref(), Some("one"));
        assert!(report.notes.join("\n").contains("could not start"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_missing_systemctl_fails_the_job_closed() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        let delivery_root = fix.dir.path().join("run");
        fs::create_dir_all(&delivery_root).unwrap();
        let setup = fix.setup(vec![script("one", "true", 20)]);
        drop(setup);
        let launcher = SystemdSetupLauncher::new(fix.dir.path().join("absent"), &fix.run_root);
        let delivery = Arc::new(
            EnvDelivery::new(
                &delivery_root,
                Owner {
                    uid: None,
                    gid: None,
                },
                Arc::new(Tmpfs),
            )
            .unwrap(),
        );
        delivery.hold(
            JOB,
            ReleasedEnvironment::from_reply(GetJobEnvironmentReply {
                scripts: vec![script("one", "true", 20)],
                ..GetJobEnvironmentReply::default()
            }),
        );
        let report = EnvSetup::new(Arc::new(launcher), delivery, &fix.run_root)
            .run(JOB, &redactor())
            .await;
        assert_eq!(report.failed.as_deref(), Some("one"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_timed_out_step_is_stopped_through_the_unit() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        let setup = fix.setup(vec![script("one", "sleep 30", 1)]);
        let report = setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed.as_deref(), Some("one"));
        assert!(report.notes.join("\n").contains("timed out"));
        let log = fix.log();
        assert!(log.contains("stop fleet-env@job1.service"), "{log}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn two_steps_start_the_unit_twice_and_stop_it_after_each() -> TestResult {
    bounded::bounded(async {
        let fix = Fix::new();
        let setup = fix.setup(vec![
            script("one", "echo a", 20),
            script("two", "echo b", 20),
        ]);
        let report = setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed, None, "{:?}", report.notes);
        let log = fix.log();
        let starts = log
            .matches("start --no-block fleet-env@job1.service")
            .count();
        let stops = log.matches("stop fleet-env@job1.service").count();
        assert_eq!((starts, stops), (2, 2), "{log}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn the_cgroup_of_the_unit_is_checked_against_the_env_slice() {
    let fix = Fix::new();
    let launcher = fix.launcher();
    let cgroup = fix.dir.path().join("cgroup");
    fs::write(
        &cgroup,
        format!("/{}/fleet-env@job1.service", fleetd::jobsock::ENV_SLICE),
    )
    .unwrap();
    assert!(launcher.confirm_slice(JOB).await.unwrap());
    fs::write(&cgroup, "/system.slice/fleet-env@job1.service").unwrap();
    assert!(!launcher.confirm_slice(JOB).await.unwrap());
    assert!(launcher.confirm_slice("a/b").await.is_err());
}

#[tokio::test]
async fn the_startup_sweep_stops_dead_units_and_shreds_dead_dirs() {
    let fix = Fix::new();
    fs::write(
        fix.dir.path().join("units"),
        "fleet-env@dead1.service loaded active exited Fleet environment setup for job dead1\nfleet-env@live1.service loaded active exited x\nfleet-env@bad$id.service loaded failed failed x\nother.service loaded active running x\n",
    )
    .unwrap();
    for id in ["dead1", "live1"] {
        fs::create_dir_all(fix.run_root.join(id).join("secrets")).unwrap();
        fs::write(fix.run_root.join(id).join("secrets/TOKEN"), TOKEN).unwrap();
    }
    fix.launcher().sweep_stale(&|id| id == "live1").await;
    let log = fix.log();
    assert!(log.contains("stop fleet-env@dead1.service"), "{log}");
    assert!(
        log.contains("reset-failed fleet-env@dead1.service"),
        "{log}"
    );
    assert!(
        !log.contains("live1.service\n") || !log.contains("stop fleet-env@live1"),
        "{log}"
    );
    assert!(
        !log.contains("other.service") || !log.contains("stop other"),
        "{log}"
    );
    assert!(!log.contains("bad$id"), "{log}");
    assert!(!fix.run_root.join("dead1").exists());
    assert!(fix.run_root.join("live1/secrets/TOKEN").exists());
}

#[test]
fn the_unit_name_is_the_template_instance_of_the_job() {
    assert_eq!(env_unit_name("job_1"), "fleet-env@job_1.service");
}

struct Shim {
    dir: TempDir,
    root: PathBuf,
    _held: Option<UnixListener>,
}

fn shim(body: &str, with_socket: bool) -> (Shim, std::thread::JoinHandle<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let job = root.join(JOB);
    fs::create_dir_all(job.join("a1")).unwrap();
    fs::create_dir(job.join("out")).unwrap();
    fs::write(job.join("a1/step"), body).unwrap();
    fs::write(job.join("attempt"), "a1").unwrap();
    let listener = UnixListener::bind(job.join("step.sock")).unwrap();
    let held = with_socket.then(|| UnixListener::bind(job.join("job.sock")).unwrap());
    let reader = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let _ = conn.read_to_end(&mut got);
        got
    });
    (
        Shim {
            dir,
            root,
            _held: held,
        },
        reader,
    )
}

fn ephemeral() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

#[test]
fn the_shim_runs_the_script_with_a_clean_env_out_dir_and_proxy_and_returns_its_code() {
    let (shim, reader) = shim(
        "#!/bin/sh\necho \"out=$FLEET_ENV_OUT secrets=$FLEET_ENV_SECRETS proxy=$HTTPS_PROXY\"\npwd\nexit 7\n",
        true,
    );
    let code = temp_env_run(&shim.root);
    assert_eq!(code, 7);
    let text = String::from_utf8(reader.join().unwrap()).unwrap();
    let job = shim.root.join(JOB);
    assert!(
        text.contains(&format!("out={}", job.join("out").display())),
        "{text}"
    );
    assert!(
        text.contains(&format!("secrets={}", job.join("secrets").display())),
        "{text}"
    );
    assert!(text.contains("proxy=http://127.0.0.1:"), "{text}");
    drop(shim.dir);
}

fn temp_env_run(root: &Path) -> i32 {
    run_env_step(root, JOB, ephemeral()).unwrap()
}

#[test]
fn the_shim_refuses_a_bad_id_attempt_or_shebang_before_running_anything() {
    for id in ["", "..", "a/b", "a b", "job\n1"] {
        let (shim, _reader) = shim("#!/bin/sh\ntrue\n", false);
        assert_eq!(
            run_env_step(&shim.root, id, ephemeral()).unwrap_err(),
            EnvExecError::InvalidId,
            "{id:?}"
        );
    }
    for attempt in [
        "",
        "../a1",
        "a",
        "a1/x",
        "b1",
        "a1\n",
        "a99999999999999999999999",
    ] {
        let (shim, _reader) = shim("#!/bin/sh\ntrue\n", false);
        fs::write(shim.root.join(JOB).join("attempt"), attempt).unwrap();
        assert_eq!(
            run_env_step(&shim.root, JOB, ephemeral()).unwrap_err(),
            EnvExecError::BadAttempt,
            "{attempt:?}"
        );
    }
    for body in ["true\n", "#!sh\ntrue\n", "#!/bin/sh\0x\ntrue\n", ""] {
        let (shim, _reader) = shim(body, false);
        assert_eq!(
            run_env_step(&shim.root, JOB, ephemeral()).unwrap_err(),
            EnvExecError::BadScript,
            "{body:?}"
        );
    }
}

#[test]
fn the_shim_binary_exits_two_with_a_fixed_message_for_a_bad_id() {
    let out = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .args([
            "env-setup-exec",
            "a b",
            "--run-dir",
            "/nonexistent-env-root",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("job id is not valid"), "{err}");
    assert!(!err.contains("nonexistent-env-root"), "{err}");
}
