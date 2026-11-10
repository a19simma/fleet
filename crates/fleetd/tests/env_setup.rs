//! The Environment script runner (ADR-0067 decision 6). Own test binary because it spawns
//! children: a shell stands in for the Setup unit.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{EnvironmentOnFail, EnvironmentScriptSpec, GetJobEnvironmentReply};
use fleetd::env_setup::{
    EnvSetup, OUTPUT_CAP, SetupLauncher, StepProc, StepRun, UnavailableLauncher,
};
use fleetd::envd::{EnvDelivery, MountCheck, Owner, ReleasedEnvironment};

#[path = "common/bounded.rs"]
mod bounded;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const JOB: &str = "job1";
const SECRET: &str = "supersecretvalue-4471-zq";

#[derive(Debug)]
struct Tmpfs;

impl MountCheck for Tmpfs {
    fn is_tmpfs(&self, _: std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool> {
        Ok(true)
    }
}

#[derive(Debug, Default)]
struct ShLauncher {
    kill_group: bool,
    killed: Arc<AtomicUsize>,
    pids: Mutex<Vec<u32>>,
    panic_on: Option<&'static str>,
    started: AtomicBool,
}

impl ShLauncher {
    fn killing() -> Arc<Self> {
        Arc::new(Self {
            kill_group: true,
            ..Self::default()
        })
    }

    fn lenient() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn panicking(step: &'static str) -> Arc<Self> {
        Arc::new(Self {
            kill_group: true,
            panic_on: Some(step),
            ..Self::default()
        })
    }
}

fn group_kill(pid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .status();
}

impl SetupLauncher for ShLauncher {
    fn start(&self, run: &StepRun<'_>) -> std::io::Result<StepProc> {
        assert_ne!(self.panic_on, Some(run.step), "launcher panic");
        self.started.store(true, Ordering::SeqCst);
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exec /bin/sh \"$0\" 2>&1")
            .arg(run.script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .process_group(0)
            .kill_on_drop(false)
            .spawn()?;
        let pid = child.id().unwrap_or(0);
        self.pids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(pid);
        let output = child.stdout.take().unwrap();
        let kill_group = self.kill_group;
        let seen = Arc::clone(&self.killed);
        Ok(StepProc {
            output: Box::pin(output),
            exit: Box::pin(async move {
                let status = child.wait().await?;
                Ok(status.success())
            }),
            kill: Box::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                if kill_group {
                    group_kill(pid);
                }
            }),
        })
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

struct Rig {
    _dir: tempfile::TempDir,
    root: PathBuf,
    setup: EnvSetup,
}

fn rig(launcher: Arc<dyn SetupLauncher>, scripts: Vec<EnvironmentScriptSpec>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let delivery_root = dir.path().join("run");
    fs::create_dir(&delivery_root).unwrap();
    let root = dir.path().join("env");
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
            ..GetJobEnvironmentReply::default()
        }),
    );
    let setup =
        EnvSetup::new(launcher, delivery, &root).with_drain_grace(Duration::from_millis(300));
    Rig {
        _dir: dir,
        root,
        setup,
    }
}

fn redactor() -> Redactor {
    Redactor::new([SECRET])
}

fn joined(notes: &[String]) -> String {
    notes.join("\n")
}

fn gone(path: &Path) -> bool {
    !path.exists()
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}

async fn dead_soon(pid: u32) -> bool {
    for _ in 0..100 {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn kill_pid(pid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

#[tokio::test]
async fn steps_run_in_order_and_each_gets_a_fresh_scratch_removed_afterwards() -> TestResult {
    bounded::bounded(async {
        let launcher = ShLauncher::killing();
        let scripts = vec![
            script(
                "first",
                "echo first-ran; echo \"$(dirname \"$0\")\" > \"$(dirname \"$0\")/where\"; touch \"$(dirname \"$0\")/leftover\"; cat \"$(dirname \"$0\")/where\"",
                5,
            ),
            script(
                "second",
                "echo second-ran; echo \"dir=$(dirname \"$0\")\"; ls \"$(dirname \"$0\")\" | tr '\\n' ','",
                5,
            ),
        ];
        let rig = rig(launcher, scripts);
        let report = rig.setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed, None);
        assert!(report.ran);
        let text = joined(&report.notes);
        let first = text.find("first-ran").unwrap();
        let second = text.find("second-ran").unwrap();
        assert!(first < second, "{text}");
        assert!(text.contains("setup step first ok"), "{text}");
        assert!(text.contains("setup step second ok"), "{text}");
        assert!(!text.contains("leftover"), "{text}");
        assert!(text.contains("step,"), "{text}");
        assert_eq!(
            text.lines()
                .filter_map(|l| l.split("dir=").nth(1))
                .count(),
            1
        );
        assert!(gone(&rig.root.join(JOB)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_failing_step_stops_later_steps_and_names_itself() -> TestResult {
    bounded::bounded(async {
        let scripts = vec![
            script("one", "echo one-ok", 5),
            script("two", "echo two-bad; exit 3", 5),
            script("three", "echo three-must-not-run", 5),
        ];
        let rig = rig(ShLauncher::killing(), scripts);
        let report = rig.setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed.as_deref(), Some("two"));
        let text = joined(&report.notes);
        assert!(text.contains("setup step two failed"), "{text}");
        assert!(!text.contains("three-must-not-run"), "{text}");
        assert!(gone(&rig.root.join(JOB)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_step_past_its_timeout_is_killed_and_fails() -> TestResult {
    bounded::bounded(async {
        let launcher = ShLauncher::killing();
        let rig = rig(launcher.clone(), vec![script("slow", "sleep 120", 1)]);
        let report = rig.setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed.as_deref(), Some("slow"));
        assert!(joined(&report.notes).contains("setup step slow timed out"));
        assert!(report.elapsed < Duration::from_secs(20));
        let pids = launcher.pids.lock().unwrap().clone();
        assert_eq!(pids.len(), 1);
        for pid in pids {
            assert!(dead_soon(pid).await, "step process {pid} still alive");
        }
        assert!(gone(&rig.root.join(JOB)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_the_run_removes_the_scratch_and_ends_the_step() -> TestResult {
    bounded::bounded(async {
        let launcher = ShLauncher::killing();
        let rig = rig(launcher.clone(), vec![script("hang", "sleep 120", 300)]);
        let redactor = redactor();
        let outcome =
            tokio::time::timeout(Duration::from_millis(500), rig.setup.run(JOB, &redactor)).await;
        assert!(outcome.is_err());
        assert!(gone(&rig.root.join(JOB)));
        let pids = launcher.pids.lock().unwrap().clone();
        assert_eq!(pids.len(), 1);
        for pid in pids {
            assert!(dead_soon(pid).await, "step process {pid} still alive");
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_panic_while_starting_a_step_removes_the_scratch() -> TestResult {
    bounded::bounded(async {
        let rig = rig(
            ShLauncher::panicking("boom"),
            vec![script("boom", "true", 5)],
        );
        let root = rig.root.clone();
        let redactor = redactor();
        let joined = tokio::task::spawn(async move {
            let rig = rig;
            rig.setup.run(JOB, &redactor).await
        })
        .await;
        assert!(joined.is_err());
        assert!(gone(&root.join(JOB)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_launcher_that_cannot_start_fails_the_step_and_leaves_nothing() -> TestResult {
    bounded::bounded(async {
        let rig = rig(
            Arc::new(UnavailableLauncher),
            vec![script("only", "true", 5)],
        );
        let report = rig.setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed.as_deref(), Some("only"));
        assert!(joined(&report.notes).contains("setup step only could not start"));
        assert!(gone(&rig.root.join(JOB)));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_job_with_no_script_runs_nothing() -> TestResult {
    bounded::bounded(async {
        let launcher = ShLauncher::killing();
        let rig = rig(launcher.clone(), Vec::new());
        let report = rig.setup.run(JOB, &redactor()).await;
        assert!(!report.ran);
        assert_eq!(report.notes, Vec::<String>::new());
        assert!(!launcher.started.load(Ordering::SeqCst));
        assert!(gone(&rig.root));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_zero_width_split_secret_is_masked_in_the_notes() -> TestResult {
    bounded::bounded(async {
        let split = "supersecretvalue\\342\\200\\213-4471-zq";
        let rig = rig(
            ShLauncher::killing(),
            vec![script(
                "leak",
                &format!("printf 'pre %s post\\n' \"$(printf '{split}')\"; echo {SECRET}"),
                5,
            )],
        );
        let report = rig.setup.run(JOB, &redactor()).await;
        let text = joined(&report.notes);
        assert!(text.contains("pre "), "{text}");
        assert!(!text.contains("supersecretvalue"), "{text}");
        assert!(text.contains("[REDACTED]"), "{text}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_secret_straddling_the_output_cap_is_masked_whole() -> TestResult {
    bounded::bounded(async {
        let lead = OUTPUT_CAP - 10;
        let rig = rig(
            ShLauncher::killing(),
            vec![script(
                "edge",
                &format!(
                    "head -c {lead} /dev/zero | tr '\\0' a; printf %s {SECRET}; head -c 4000 /dev/zero | tr '\\0' b; echo"
                ),
                5,
            )],
        );
        let report = rig.setup.run(JOB, &redactor()).await;
        let text = joined(&report.notes);
        assert!(text.contains("[output cut]"), "cut marker missing");
        assert!(!text.contains(&SECRET[..10]), "secret prefix leaked");
        assert!(text.contains("[REDACTED]"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn output_is_bounded_to_the_cap() -> TestResult {
    bounded::bounded(async {
        let rig = rig(
            ShLauncher::killing(),
            vec![script(
                "flood",
                "head -c 400000 /dev/zero | tr '\\0' x; echo",
                5,
            )],
        );
        let report = rig.setup.run(JOB, &redactor()).await;
        assert_eq!(report.failed, None);
        let output = report.notes.iter().find(|n| n.contains("output")).unwrap();
        assert!(output.len() <= OUTPUT_CAP + 200, "{}", output.len());
        assert!(output.contains("[output cut]"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_detached_descendant_holding_the_pipe_does_not_hang_the_step() -> TestResult {
    bounded::bounded(async {
        let dir = tempfile::tempdir()?;
        let pid_file = dir.path().join("descendant.pid");
        let launcher = ShLauncher::lenient();
        let rig = rig(
            launcher,
            vec![script(
                "detach",
                &format!(
                    "sleep 300 &\necho $! > {}\necho parent-done",
                    pid_file.display()
                ),
                5,
            )],
        );
        let redactor = redactor();
        let run =
            tokio::time::timeout(Duration::from_secs(20), rig.setup.run(JOB, &redactor)).await;
        let leftover: Option<u32> = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|t| t.trim().parse().ok());
        let report = run.map_err(|_| "setup hung on a detached descendant");
        if let Some(pid) = leftover {
            kill_pid(pid);
        }
        let report = report?;
        assert_eq!(report.failed, None);
        assert!(joined(&report.notes).contains("parent-done"));
        assert!(
            leftover.is_some(),
            "positive control: the descendant started"
        );
        assert!(report.elapsed < Duration::from_secs(10));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn end_removes_a_leftover_tree_and_is_idempotent() -> TestResult {
    bounded::bounded(async {
        let rig = rig(ShLauncher::killing(), vec![script("s", "true", 5)]);
        fs::create_dir_all(rig.root.join(JOB).join("a9"))?;
        rig.setup.end(JOB);
        assert!(gone(&rig.root.join(JOB)));
        rig.setup.end(JOB);
        rig.setup.end("../x");
        Ok(())
    })
    .await
}

#[derive(Debug)]
struct GatedLauncher {
    killed: Arc<AtomicBool>,
}

impl SetupLauncher for GatedLauncher {
    fn start(&self, _: &StepRun<'_>) -> std::io::Result<StepProc> {
        use tokio::io::AsyncWriteExt;
        let (mut tx, rx) = tokio::io::duplex(1024);
        let flag = Arc::clone(&self.killed);
        let seen = Arc::clone(&self.killed);
        tokio::spawn(async move {
            while !seen.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let _ = tx.write_all(b"after-kill\n").await;
        });
        Ok(StepProc {
            output: Box::pin(rx),
            exit: Box::pin(std::future::ready(Ok(true))),
            kill: Box::new(move || flag.store(true, Ordering::SeqCst)),
        })
    }
}

#[tokio::test]
async fn the_step_is_killed_before_the_output_drain_wait_begins() -> TestResult {
    bounded::bounded(async {
        let launcher = Arc::new(GatedLauncher {
            killed: Arc::new(AtomicBool::new(false)),
        });
        let rig = rig(launcher, vec![script("gated", "true", 5)]);
        let setup = rig.setup.with_drain_grace(Duration::from_secs(3));
        let report = setup.run(JOB, &redactor()).await;
        let text = joined(&report.notes);
        assert!(text.contains("after-kill"), "{text}");
        Ok(())
    })
    .await
}
