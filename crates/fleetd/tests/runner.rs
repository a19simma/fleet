//! Runs a fake agent script. Own test binary because it spawns children.

use std::ffi::OsString;
use std::future::{Future, ready};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::MAX_CHUNKS_PER_REPORT;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest};
use fleetd::poller::{RunError, Shutdown};
use fleetd::runner::{AgentOutcome, AgentRunner, Interrupt, Reporter, RunConfig};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

#[path = "common/bounded.rs"]
mod common;
#[path = "common/reader.rs"]
mod reader;

use reader::{Reader, hold_reader};

const SECRET_NAMES: [&str; 9] = [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_PAT",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
    "FLEET_TOKEN",
    "FLEET_CLIENT_TOKEN",
];

type TestResult = Result<(), Box<dyn std::error::Error>>;

const START_BAND: Duration = Duration::from_secs(5);
const REAP_ATTEMPTS: usize = 10;

const SCRIPT: &str = r#"#!/bin/sh
mode=${2%%:*}
path=${2#*:}
case "$mode" in
stream)
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"working on it"}]}}'
  echo 'token hunter2-hunter2 end'
  exit 0 ;;
exit3) echo out; exit 3 ;;
env) env; exit 0 ;;
args) printf 'arg=%s\n' "$@"; exit 0 ;;
quiet) read x < "$path"; exit 0 ;;
hold) sleep 300 > "$path" & wait ;;
bg) sleep 300 > "$path" & read x < "$path.ready"; exit 0 ;;
badutf8) printf 'a\377b\nnext\n'; exit 0 ;;
stubborn) trap '' TERM; sleep 300 > "$path" & wait ;;
term) trap 'echo t > "$path.marker"; exit 0' TERM; sleep 300 > "$path" & wait ;;
closed) exec 1>&-; : > "$path.closed"; read x < "$path"; exit 0 ;;
burst) i=0; while [ $i -lt 700 ]; do echo x; i=$((i+1)); done; exit 0 ;;
huge) head -c 3000000 /dev/zero | tr '\0' a; echo; echo next; exit 0 ;;
reap) echo $$ > "$path"; read x < "$path.go"; exit 0 ;;
big) i=0; while [ $i -lt 200 ]; do printf '%01000d\n' 0; i=$((i+1)); done; : > "$path.done"; read x < "$path"; exit 0 ;;
flood) i=0; while [ $i -lt 100 ]; do printf '%01000d\n' 0; i=$((i+1)); done; exit 0 ;;
orphan) perl -e 'use POSIX; POSIX::setsid(); open(F, ">", $ARGV[0]); print F $$; close F; exec "sleep", "300"' "$path" &
  while [ ! -s "$path" ]; do sleep 0.05; done; exit 0 ;;
esac
"#;

struct Hung {
    called: mpsc::UnboundedSender<()>,
}

impl Reporter for Hung {
    fn report(
        &self,
        _request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let _ = self.called.send(());
        std::future::pending()
    }
}

#[derive(Default)]
struct Switch {
    cancel: AtomicBool,
    lost: AtomicBool,
    stale_terminal: AtomicBool,
}

struct Fake {
    tx: mpsc::UnboundedSender<ReportJobRequest>,
    fail_first: AtomicUsize,
    switch: Arc<Switch>,
}

impl Reporter for Fake {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let failing = self
            .fail_first
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if failing {
            return ready(Err(Status::unavailable("down")));
        }
        let terminal = request.terminal_state.is_some();
        let _ = self.tx.send(request);
        let lost = self.switch.lost.load(Ordering::SeqCst)
            || (terminal && self.switch.stale_terminal.load(Ordering::SeqCst));
        if lost {
            return ready(Err(Status::failed_precondition("stale")));
        }
        ready(Ok(ReportJobReply {
            cancel_requested: self.switch.cancel.load(Ordering::SeqCst),
            ..ReportJobReply::default()
        }))
    }
}

fn script() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("claude");
        std::fs::write(&path, SCRIPT).unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        (dir, path)
    });
    path
}

fn base_env() -> Vec<(OsString, OsString)> {
    let mut env = vec![
        ("GH_TOKEN".into(), "not-a-real-gh-value".into()),
        ("FLEET_TOKEN".into(), "not-a-real-fleet-value".into()),
        ("KEPT_VALUE".into(), "kept".into()),
    ];
    env.extend(
        SECRET_NAMES
            .iter()
            .map(|name| ((*name).into(), "not-a-real-value".into())),
    );
    env.extend(std::env::var_os("PATH").map(|path| ("PATH".into(), path)));
    env
}

fn config(disposable: bool) -> RunConfig {
    let mut config = RunConfig::new(script(), disposable);
    config.base_env = base_env();
    config.flush_interval = Duration::from_millis(20);
    config
}

fn job(prompt: &str) -> Job {
    Job {
        job_id: "job1".into(),
        attempt: 2,
        r#box: "boxa".into(),
        prompt: prompt.into(),
        ..Job::default()
    }
}

fn runner(
    config: RunConfig,
    fail_first: usize,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    let (agent, rx, _) = switched(config, fail_first);
    (agent, rx)
}

type Switched = (
    AgentRunner<Fake>,
    mpsc::UnboundedReceiver<ReportJobRequest>,
    Arc<Switch>,
);

fn switched(config: RunConfig, fail_first: usize) -> Switched {
    let (tx, rx) = mpsc::unbounded_channel();
    let switch = Arc::new(Switch::default());
    let fake = Fake {
        tx,
        fail_first: AtomicUsize::new(fail_first),
        switch: Arc::clone(&switch),
    };
    (
        AgentRunner::new(config, fake, Redactor::new(["hunter2-hunter2"])),
        rx,
        switch,
    )
}

fn drain(rx: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> Vec<ReportJobRequest> {
    let mut all = Vec::new();
    while let Ok(request) = rx.try_recv() {
        all.push(request);
    }
    all
}

fn text(requests: &[ReportJobRequest]) -> String {
    requests
        .iter()
        .flat_map(|r| r.chunks.iter().map(|c| c.text.as_str()))
        .collect()
}

fn fifo(dir: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    assert!(Command::new("mkfifo").arg(&path).status()?.success());
    Ok(path)
}

async fn release(path: &Path) -> TestResult {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new().write(true).open(path).await?;
    file.write_all(b"go\n").await?;
    Ok(())
}

async fn first_heartbeat(rx: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> TestResult {
    let seen = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(request) = rx.recv().await {
            if request.chunks.is_empty() && request.terminal_state.is_none() {
                return true;
            }
        }
        false
    })
    .await?;
    assert!(seen);
    Ok(())
}

#[tokio::test]
async fn runner_streams_and_maps_exit() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();

        let (ok, mut rx) = runner(config(false), 0);
        let outcome = ok
            .run(&job("stream:"), dir.path(), shutdown.clone())
            .await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        let requests = drain(&mut rx);
        assert!(requests.iter().all(|r| r.terminal_state.is_none()));
        assert!(
            requests
                .iter()
                .all(|r| r.job_id == "job1" && r.attempt == 2)
        );
        assert!(requests.iter().all(|r| r.r#box == "boxa"));
        let chunks: Vec<_> = requests.iter().flat_map(|r| r.chunks.clone()).collect();
        assert_eq!(chunks.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![1, 2]);
        let all = text(&requests);
        assert!(all.contains("working on it"));
        assert!(all.contains("token [REDACTED] end"));
        assert!(!all.contains("hunter2"));
        assert_eq!(
            requests.last().map(|r| r.progress.as_str()),
            Some("working on it")
        );

        let (bad, mut rx) = runner(config(false), 0);
        let outcome = bad.run(&job("exit3:"), dir.path(), shutdown).await?;
        assert!(matches!(
            outcome,
            AgentOutcome::Failed {
                exit_code: Some(3),
                ..
            }
        ));
        let requests = drain(&mut rx);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert_eq!(last.exit_code, Some(3));
        assert!(last.error.is_some());
        assert!(text(&requests).contains("out"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_env_has_no_gh_token() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();
        let (agent, mut rx) = runner(config(false), 0);
        agent.run(&job("env:"), dir.path(), shutdown).await?;
        let all = text(&drain(&mut rx));
        for name in SECRET_NAMES {
            assert!(!all.contains(&format!("{name}=")), "{name} leaked");
        }
        assert!(!all.contains("not-a-real"));
        assert!(all.contains("KEPT_VALUE=kept"));
        assert!(all.contains("FLEET_JOB_ID=job1"));
        assert!(all.contains("SWARM_BOX=1"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_skips_permissions_only_on_a_disposable_box() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();
        for (disposable, expected) in [(false, false), (true, true)] {
            let (agent, mut rx) = runner(config(disposable), 0);
            agent
                .run(&job("args:"), dir.path(), shutdown.clone())
                .await?;
            let all = text(&drain(&mut rx));
            assert!(all.contains("arg=-p\narg=args:\n"));
            assert!(all.contains("arg=--output-format\narg=stream-json\narg=--verbose\n"));
            assert_eq!(all.contains("--dangerously-skip-permissions"), expected);
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_reports_while_the_agent_is_quiet() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let gate = fifo(dir.path(), "gate")?;
        let mut cfg = config(false);
        cfg.report_interval = Duration::from_millis(100);
        let (agent, mut rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("quiet:{}", gate.display());
        let job = job(&prompt);
        let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
            first_heartbeat(&mut rx).await?;
            release(&gate).await
        });
        driven?;
        assert_eq!(outcome?, AgentOutcome::Succeeded);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_resends_chunks_after_a_failed_report() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let mut cfg = config(false);
        cfg.report_interval = Duration::from_millis(50);
        let (agent, mut rx) = runner(cfg, 1);
        let (_trigger, shutdown) = Shutdown::channel();
        agent.run(&job("stream:"), dir.path(), shutdown).await?;
        agent.fail_job(&job("stream:"), "boom").await;
        let chunks: Vec<_> = drain(&mut rx)
            .iter()
            .flat_map(|r| r.chunks.iter().map(|c| c.seq))
            .collect();
        assert_eq!(chunks, vec![1, 2]);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_caps_a_report_by_chunk_count() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let mut cfg = config(false);
        cfg.report_interval = Duration::from_millis(50);
        let (agent, mut rx) = runner(cfg, 2);
        let (_trigger, shutdown) = Shutdown::channel();
        agent.run(&job("burst:"), dir.path(), shutdown).await?;
        let requests = drain(&mut rx);
        assert!(
            requests
                .iter()
                .all(|r| r.chunks.len() <= MAX_CHUNKS_PER_REPORT)
        );
        let seqs: Vec<_> = requests
            .iter()
            .flat_map(|r| r.chunks.iter().map(|c| c.seq))
            .collect();
        assert_eq!(seqs, (1..=700).collect::<Vec<u64>>());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_timeout_kills_the_process_group() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hold = fifo(dir.path(), "hold")?;
        let reader = hold_reader(&hold);
        let mut cfg = config(false);
        cfg.timeout = START_BAND;
        let (agent, mut rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("hold:{}", hold.display());
        let outcome = agent.run(&job(&prompt), dir.path(), shutdown).await?;
        assert!(matches!(
            outcome,
            AgentOutcome::Failed {
                exit_code: None,
                error: "agent timed out"
            }
        ));
        let requests = drain(&mut rx);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_shutdown_kills_the_process_group() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hold = fifo(dir.path(), "hold")?;
        let mut reader = hold_reader(&hold);
        let (agent, mut rx) = runner(config(false), 0);
        let (trigger, shutdown) = Shutdown::channel();
        let prompt = format!("hold:{}", hold.display());
        let job = job(&prompt);
        let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
            reader.wait_opened().await?;
            let _ = trigger.send(true);
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        driven?;
        assert!(matches!(outcome, Err(RunError)));
        let requests = drain(&mut rx);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert_eq!(
            last.error.as_deref(),
            Some("agent stopped by daemon shutdown")
        );
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_reports_a_missing_binary_as_failed() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let mut cfg = config(false);
        cfg.claude_bin = dir.path().join("absent");
        let (agent, mut rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("stream:"), dir.path(), shutdown).await?;
        assert!(matches!(
            outcome,
            AgentOutcome::Failed {
                exit_code: None,
                ..
            }
        ));
        let requests = drain(&mut rx);
        assert_eq!(
            requests.last().and_then(|r| r.terminal_state),
            Some(JobState::Failed.into())
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_kills_background_descendants_after_a_clean_exit() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let bg = fifo(dir.path(), "bg")?;
        let ready = fifo(dir.path(), "bg.ready")?;
        let mut reader = hold_reader(&bg);
        let (agent, _rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("bg:{}", bg.display());
        let job = job(&prompt);
        let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
            reader.wait_opened().await?;
            release(&ready).await
        });
        driven?;
        assert_eq!(outcome?, AgentOutcome::Succeeded);
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_reports_after_the_agent_closes_stdout() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let gate = fifo(dir.path(), "gate")?;
        let closed = fifo(dir.path(), "gate.closed")?;
        let mut reader = hold_reader(&closed);
        let mut cfg = config(false);
        cfg.report_interval = Duration::from_millis(20);
        let (agent, mut rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("closed:{}", gate.display());
        let job = job(&prompt);
        let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
            reader.wait_opened().await?;
            drain(&mut rx);
            let beats = async {
                first_heartbeat(&mut rx).await?;
                first_heartbeat(&mut rx).await
            }
            .await;
            release(&gate).await?;
            beats
        });
        driven?;
        assert_eq!(outcome?, AgentOutcome::Succeeded);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_caps_a_huge_stdout_line() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("huge:"), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        let requests = drain(&mut rx);
        let chunks: Vec<_> = requests.iter().flat_map(|r| r.chunks.clone()).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].text.len(), fleetd::runner::MAX_CHUNK_BYTES);
        assert!(chunks[0].truncated);
        assert_eq!(chunks[1].text, "next\n");
        assert!(!chunks[1].truncated);
        Ok(())
    }))
    .await
}

struct Down(Arc<AtomicUsize>);

impl Reporter for Down {
    fn report(
        &self,
        _request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        ready(Err(Status::unavailable("down")))
    }
}

#[tokio::test]
async fn a_failing_flush_does_not_block_the_pipe_on_every_line() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut cfg = config(false);
        cfg.flush_interval = Duration::from_secs(5);
        let agent = AgentRunner::new(cfg, Down(Arc::clone(&calls)), Redactor::default());
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("flood:"), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        let made = calls.load(Ordering::SeqCst);
        assert!((1..=4).contains(&made), "report calls: {made}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_setsid_descendant_holding_stdout_does_not_turn_success_into_timeout() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let pid_file = dir.path().join("orphan.pid");
        let mut cfg = config(false);
        cfg.timeout = Duration::from_secs(30);
        let (agent, _rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let started = std::time::Instant::now();
        let outcome = agent
            .run(
                &job(&format!("orphan:{}", pid_file.display())),
                dir.path(),
                shutdown,
            )
            .await;
        let elapsed = started.elapsed();
        let pid = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(text) = tokio::fs::read_to_string(&pid_file).await
                    && !text.is_empty()
                {
                    return text;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?;
        assert!(Command::new("kill").arg(pid.trim()).status()?.success());
        assert_eq!(outcome?, AgentOutcome::Succeeded);
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        Ok(())
    }))
    .await
}

#[tokio::test(start_paused = true)]
async fn keep_alive_renews_the_lease_while_the_work_runs() -> TestResult {
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_secs(30);
    let (agent, mut rx) = runner(cfg, 0);
    let out = agent
        .keep_alive(&job("x"), async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            7
        })
        .await;
    assert_eq!(out, Ok(7));
    let reports = drain(&mut rx);
    assert_eq!(reports.len(), 3);
    assert!(
        reports
            .iter()
            .all(|r| r.job_id == "job1" && r.chunks.is_empty() && r.terminal_state.is_none())
    );
    Ok(())
}

#[tokio::test]
async fn fail_job_after_a_run_keeps_the_progress() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("stream:"), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        agent.fail_job(&job("stream:"), "boom").await;
        let requests = drain(&mut rx);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert_eq!(last.progress, "working on it");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn runner_reports_failed_when_the_child_cannot_be_awaited() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        for attempt in 0..REAP_ATTEMPTS {
            let pid_path = fifo(dir.path(), &format!("reap{attempt}"))?;
            let go = fifo(dir.path(), &format!("reap{attempt}.go"))?;
            let (agent, mut rx) = runner(config(false), 0);
            let (_trigger, shutdown) = Shutdown::channel();
            let prompt = format!("reap:{}", pid_path.display());
            let job = job(&prompt);
            let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
                let raw = tokio::fs::read_to_string(&pid_path).await?;
                let pid = rustix::process::Pid::from_raw(raw.trim().parse()?).ok_or("bad pid")?;
                let (entering, entered) = oneshot::channel();
                let reaper = std::thread::spawn(move || {
                    let _ = entering.send(());
                    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
                    {
                        Ok(_) => Ok(true),
                        Err(rustix::io::Errno::CHILD) => Ok(false),
                        Err(errno) => Err(errno),
                    }
                });
                entered.await?;
                release(&go).await?;
                let joined = tokio::task::spawn_blocking(move || reaper.join()).await?;
                let won = joined.map_err(|_| "reaper panicked")??;
                Ok::<bool, Box<dyn std::error::Error>>(won)
            });
            if !driven? {
                continue;
            }
            assert!(matches!(outcome, Err(RunError)));
            let requests = drain(&mut rx);
            let last = requests.last().ok_or("no report")?;
            assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
            assert_eq!(last.error.as_deref(), Some("agent could not be awaited"));
            return Ok(());
        }
        Err("the runner reaped the child before the test in every attempt".into())
    }))
    .await
}

#[tokio::test]
async fn runner_keeps_lines_after_invalid_utf8() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("badutf8:"), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        assert_eq!(text(&drain(&mut rx)), "a\u{FFFD}b\nnext\n");
        Ok(())
    }))
    .await
}

fn hung_runner(config: RunConfig) -> (AgentRunner<Hung>, mpsc::UnboundedReceiver<()>) {
    let (called, rx) = mpsc::unbounded_channel();
    (
        AgentRunner::new(config, Hung { called }, Redactor::new(["hunter2-hunter2"])),
        rx,
    )
}

fn hung_config() -> RunConfig {
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_millis(10);
    cfg.terminal_report_timeout = Duration::from_millis(200);
    cfg
}

#[tokio::test]
async fn a_hung_reporter_does_not_delay_the_timeout_kill() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hold = fifo(dir.path(), "hold")?;
        let reader = hold_reader(&hold);
        let mut cfg = hung_config();
        cfg.timeout = START_BAND;
        let (agent, _called) = hung_runner(cfg);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("hold:{}", hold.display());
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            agent.run(&job(&prompt), dir.path(), shutdown),
        )
        .await??;
        assert!(matches!(
            outcome,
            AgentOutcome::Failed {
                error: "agent timed out",
                ..
            }
        ));
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_hung_reporter_does_not_delay_shutdown() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hold = fifo(dir.path(), "hold")?;
        let mut reader = hold_reader(&hold);
        let (agent, mut called) = hung_runner(hung_config());
        let (trigger, shutdown) = Shutdown::channel();
        let prompt = format!("hold:{}", hold.display());
        let job = job(&prompt);
        let run = tokio::time::timeout(
            Duration::from_secs(20),
            agent.run(&job, dir.path(), shutdown),
        );
        let (outcome, driven) = tokio::join!(run, async {
            reader.wait_opened().await?;
            tokio::time::timeout(Duration::from_secs(20), called.recv())
                .await?
                .ok_or("no report")?;
            let _ = trigger.send(true);
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        driven?;
        assert!(matches!(outcome?, Err(RunError)));
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

type SendError = Box<dyn std::error::Error + Send + Sync>;

fn fast_beat() -> RunConfig {
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_millis(50);
    cfg.cancel_grace = Duration::from_millis(300);
    cfg
}

async fn cancel_run(
    mode: &str,
    dir: &Path,
) -> Result<(AgentOutcome, Vec<ReportJobRequest>, Reader), SendError> {
    let hold = fifo(dir, mode).map_err(|e| e.to_string())?;
    let mut reader = hold_reader(&hold);
    let (agent, mut rx, switch) = switched(fast_beat(), 0);
    let (_trigger, shutdown) = Shutdown::channel();
    let prompt = format!("{mode}:{}", hold.display());
    let job = job(&prompt);
    let (outcome, driven) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(20), agent.run(&job, dir, shutdown)),
        async {
            reader.wait_opened().await?;
            switch.cancel.store(true, Ordering::SeqCst);
            Ok::<(), SendError>(())
        }
    );
    driven?;
    Ok((outcome??, drain(&mut rx), reader))
}

#[tokio::test]
async fn cancel_kills_group() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (outcome, requests, reader) = cancel_run("stubborn", dir.path())
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(outcome, AgentOutcome::Cancelled);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Cancelled.into()));
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn cancel_sends_term_before_kill() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (outcome, _, reader) = cancel_run("term", dir.path())
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(outcome, AgentOutcome::Cancelled);
        reader.wait_eof().await?;
        assert!(dir.path().join("term.marker").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn precondition_failed_kills() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hold = fifo(dir.path(), "hold")?;
        let mut reader = hold_reader(&hold);
        let (agent, mut rx, switch) = switched(fast_beat(), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("hold:{}", hold.display());
        let job = job(&prompt);
        let (outcome, driven) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(20),
                agent.run(&job, dir.path(), shutdown)
            ),
            async {
                reader.wait_opened().await?;
                switch.lost.store(true, Ordering::SeqCst);
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        );
        driven?;
        assert_eq!(outcome??, AgentOutcome::Lost);
        let requests = drain(&mut rx);
        assert!(requests.iter().all(|r| r.terminal_state.is_none()));
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_stale_terminal_report_leaves_the_outcome_unchanged() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx, switch) = switched(config(false), 0);
        switch.stale_terminal.store(true, Ordering::SeqCst);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("exit3:"), dir.path(), shutdown).await?;
        assert!(matches!(
            outcome,
            AgentOutcome::Failed {
                exit_code: Some(3),
                ..
            }
        ));
        let sent = drain(&mut rx);
        assert_eq!(
            sent.iter().filter(|r| r.terminal_state.is_some()).count(),
            1
        );
        Ok(())
    }))
    .await
}

fn slow_flush(fail_first: usize) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    let mut cfg = config(false);
    cfg.flush_interval = Duration::from_secs(3600);
    cfg.report_interval = Duration::from_secs(3600);
    runner(cfg, fail_first)
}

fn seqs(requests: &[ReportJobRequest]) -> Vec<u64> {
    requests
        .iter()
        .flat_map(|r| r.chunks.iter().map(|c| c.seq))
        .collect()
}

#[tokio::test]
async fn chunks_left_by_a_failed_final_flush_reach_the_server_before_the_terminal() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx) = slow_flush(1);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent.run(&job("stream:"), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        assert!(drain(&mut rx).is_empty());
        agent.fail_job(&job("stream:"), "boom").await;
        let requests = drain(&mut rx);
        assert_eq!(seqs(&requests), vec![1, 2]);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert!(last.chunks.is_empty());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_terminal_report_retries_queued_chunks_until_they_are_delivered() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx) = slow_flush(2);
        let (_trigger, shutdown) = Shutdown::channel();
        agent.run(&job("stream:"), dir.path(), shutdown).await?;
        agent.fail_job(&job("stream:"), "boom").await;
        let requests = drain(&mut rx);
        assert_eq!(seqs(&requests), vec![1, 2]);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        Ok(())
    }))
    .await
}

#[tokio::test(start_paused = true)]
async fn a_lost_lease_stops_the_guarded_work() -> TestResult {
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_secs(30);
    let (agent, mut rx, switch) = switched(cfg, 0);
    switch.lost.store(true, Ordering::SeqCst);
    let out = agent
        .keep_alive(&job("x"), async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            7
        })
        .await;
    assert_eq!(out, Err(Interrupt::Lost));
    assert!(drain(&mut rx).iter().all(|r| r.terminal_state.is_none()));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_cancel_reply_stops_the_guarded_work() -> TestResult {
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_secs(30);
    let (agent, _rx, switch) = switched(cfg, 0);
    switch.cancel.store(true, Ordering::SeqCst);
    let out = agent
        .keep_alive(&job("x"), async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            7
        })
        .await;
    assert_eq!(out, Err(Interrupt::Cancelled));
    Ok(())
}

struct Gate {
    first: Mutex<Option<oneshot::Receiver<()>>>,
}

impl Reporter for Gate {
    fn report(
        &self,
        _request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let gate = self
            .first
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        async move {
            Ok(ReportJobReply {
                cancel_requested: match gate {
                    Some(release) => release.await.is_ok(),
                    None => false,
                },
                ..ReportJobReply::default()
            })
        }
    }
}

#[tokio::test]
async fn a_report_in_flight_does_not_stop_stdout_reads_or_delay_a_cancel() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hold = fifo(dir.path(), "hold")?;
        let (release, gate) = oneshot::channel();
        let agent = AgentRunner::new(
            config(false),
            Gate {
                first: Mutex::new(Some(gate)),
            },
            Redactor::default(),
        );
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("big:{}", hold.display());
        let job = job(&prompt);
        let marker = dir.path().join("hold.done");
        let (outcome, driven) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(30),
                agent.run(&job, dir.path(), shutdown)
            ),
            async {
                tokio::time::timeout(Duration::from_secs(10), async {
                    while !marker.exists() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await?;
                let _ = release.send(());
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        );
        driven?;
        assert_eq!(outcome??, AgentOutcome::Cancelled);
        Ok(())
    }))
    .await
}
