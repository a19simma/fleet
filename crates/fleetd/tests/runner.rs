//! Runs a fake agent script. Own test binary because it spawns children.

use std::ffi::OsString;
use std::future::{Future, ready};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::MAX_CHUNKS_PER_REPORT;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest};
use fleetd::poller::{RunError, Shutdown};
use fleetd::runner::{AgentOutcome, AgentRunner, Reporter, RunConfig};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

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

struct Reader {
    opened: oneshot::Receiver<()>,
    eof: tokio::task::JoinHandle<std::io::Result<usize>>,
}

fn hold_reader(path: &Path) -> Reader {
    let path = path.to_owned();
    let (tx, opened) = oneshot::channel();
    let eof = tokio::spawn(async move {
        let mut file = tokio::fs::File::open(path).await?;
        let _ = tx.send(());
        let mut sink = Vec::new();
        file.read_to_end(&mut sink).await
    });
    Reader { opened, eof }
}

#[tokio::test]
async fn runner_streams_and_maps_exit() -> TestResult {
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
}

#[tokio::test]
async fn runner_env_has_no_gh_token() -> TestResult {
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
}

#[tokio::test]
async fn runner_skips_permissions_only_on_a_disposable_box() -> TestResult {
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
}

#[tokio::test]
async fn runner_reports_while_the_agent_is_quiet() -> TestResult {
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
}

#[tokio::test]
async fn runner_resends_chunks_after_a_failed_report() -> TestResult {
    let dir = TempDir::new()?;
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_millis(50);
    let (agent, mut rx) = runner(cfg, 1);
    let (_trigger, shutdown) = Shutdown::channel();
    agent.run(&job("stream:"), dir.path(), shutdown).await?;
    let chunks: Vec<_> = drain(&mut rx)
        .iter()
        .flat_map(|r| r.chunks.iter().map(|c| c.seq))
        .collect();
    assert_eq!(chunks, vec![1, 2]);
    Ok(())
}

#[tokio::test]
async fn runner_caps_a_report_by_chunk_count() -> TestResult {
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
}

#[tokio::test]
async fn runner_timeout_kills_the_process_group() -> TestResult {
    let dir = TempDir::new()?;
    let hold = fifo(dir.path(), "hold")?;
    let reader = hold_reader(&hold);
    let mut cfg = config(false);
    cfg.timeout = Duration::from_millis(1500);
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
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
}

#[tokio::test]
async fn runner_shutdown_kills_the_process_group() -> TestResult {
    let dir = TempDir::new()?;
    let hold = fifo(dir.path(), "hold")?;
    let mut reader = hold_reader(&hold);
    let (agent, mut rx) = runner(config(false), 0);
    let (trigger, shutdown) = Shutdown::channel();
    let prompt = format!("hold:{}", hold.display());
    let job = job(&prompt);
    let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
        tokio::time::timeout(Duration::from_secs(20), &mut reader.opened).await??;
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
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
}

#[tokio::test]
async fn runner_reports_a_missing_binary_as_failed() -> TestResult {
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
}

#[tokio::test]
async fn runner_kills_background_descendants_after_a_clean_exit() -> TestResult {
    let dir = TempDir::new()?;
    let bg = fifo(dir.path(), "bg")?;
    let ready = fifo(dir.path(), "bg.ready")?;
    let mut reader = hold_reader(&bg);
    let (agent, _rx) = runner(config(false), 0);
    let (_trigger, shutdown) = Shutdown::channel();
    let prompt = format!("bg:{}", bg.display());
    let job = job(&prompt);
    let (outcome, driven) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
        tokio::time::timeout(Duration::from_secs(20), &mut reader.opened).await??;
        release(&ready).await
    });
    driven?;
    assert_eq!(outcome?, AgentOutcome::Succeeded);
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
}

#[tokio::test]
async fn runner_reports_after_the_agent_closes_stdout() -> TestResult {
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
        tokio::time::timeout(Duration::from_secs(20), &mut reader.opened).await??;
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
}

#[tokio::test]
async fn runner_caps_a_huge_stdout_line() -> TestResult {
    let dir = TempDir::new()?;
    let (agent, mut rx) = runner(config(false), 0);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent.run(&job("huge:"), dir.path(), shutdown).await?;
    assert_eq!(outcome, AgentOutcome::Succeeded);
    let requests = drain(&mut rx);
    let chunks: Vec<_> = requests.iter().flat_map(|r| r.chunks.clone()).collect();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].text.len(), fleetd::runner::MAX_CHUNK_BYTES);
    assert_eq!(chunks[1].text, "next\n");
    Ok(())
}

#[tokio::test]
async fn runner_reports_failed_when_the_child_cannot_be_awaited() -> TestResult {
    let dir = TempDir::new()?;
    let pid_path = fifo(dir.path(), "reap")?;
    let go = fifo(dir.path(), "reap.go")?;
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
            loop {
                let status =
                    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)?;
                if status.is_some() {
                    return Ok::<(), rustix::io::Errno>(());
                }
                std::hint::spin_loop();
            }
        });
        entered.await?;
        release(&go).await?;
        let joined = tokio::task::spawn_blocking(move || reaper.join()).await?;
        joined.map_err(|_| "reaper panicked")??;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    driven?;
    assert!(matches!(outcome, Err(RunError)));
    let requests = drain(&mut rx);
    let last = requests.last().ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
    assert_eq!(last.error.as_deref(), Some("agent could not be awaited"));
    Ok(())
}

#[tokio::test]
async fn runner_keeps_lines_after_invalid_utf8() -> TestResult {
    let dir = TempDir::new()?;
    let (agent, mut rx) = runner(config(false), 0);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent.run(&job("badutf8:"), dir.path(), shutdown).await?;
    assert_eq!(outcome, AgentOutcome::Succeeded);
    assert_eq!(text(&drain(&mut rx)), "a\u{FFFD}b\nnext\n");
    Ok(())
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
    let dir = TempDir::new()?;
    let hold = fifo(dir.path(), "hold")?;
    let reader = hold_reader(&hold);
    let mut cfg = hung_config();
    cfg.timeout = Duration::from_millis(1500);
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
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
}

#[tokio::test]
async fn a_hung_reporter_does_not_delay_shutdown() -> TestResult {
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
        tokio::time::timeout(Duration::from_secs(20), &mut reader.opened).await??;
        tokio::time::timeout(Duration::from_secs(20), called.recv())
            .await?
            .ok_or("no report")?;
        let _ = trigger.send(true);
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    driven?;
    assert!(matches!(outcome?, Err(RunError)));
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
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
            tokio::time::timeout(Duration::from_secs(20), &mut reader.opened).await??;
            switch.cancel.store(true, Ordering::SeqCst);
            Ok::<(), SendError>(())
        }
    );
    driven?;
    Ok((outcome??, drain(&mut rx), reader))
}

#[tokio::test]
async fn cancel_kills_group() -> TestResult {
    let dir = TempDir::new()?;
    let (outcome, requests, reader) = cancel_run("stubborn", dir.path())
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(outcome, AgentOutcome::Cancelled);
    let last = requests.last().ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Cancelled.into()));
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
}

#[tokio::test]
async fn cancel_sends_term_before_kill() -> TestResult {
    let dir = TempDir::new()?;
    let (outcome, _, reader) = cancel_run("term", dir.path())
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(outcome, AgentOutcome::Cancelled);
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    assert!(dir.path().join("term.marker").exists());
    Ok(())
}

#[tokio::test]
async fn precondition_failed_kills() -> TestResult {
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
            tokio::time::timeout(Duration::from_secs(20), &mut reader.opened).await??;
            switch.lost.store(true, Ordering::SeqCst);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
    );
    driven?;
    assert_eq!(outcome??, AgentOutcome::Lost);
    let requests = drain(&mut rx);
    assert!(requests.iter().all(|r| r.terminal_state.is_none()));
    tokio::time::timeout(Duration::from_secs(20), reader.eof).await???;
    Ok(())
}

#[tokio::test]
async fn a_stale_terminal_report_leaves_the_outcome_unchanged() -> TestResult {
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
}
