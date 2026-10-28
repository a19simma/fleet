//! Runs a fake agent script. Own test binary because it spawns children.

use std::ffi::OsString;
use std::future::{Future, ready};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::MAX_CHUNKS_PER_REPORT;
use fleet_proto::v1::{
    Job, JobEvent, JobEventKind, JobState, ReportJobReply, ReportJobRequest, TranscriptChunk,
};
use fleetd::HookHub;
use fleetd::agent_config::{AGENT_PROTOCOL, Bundle, JOB_EMAIL, JOB_NAME};
use fleetd::poller::{RunError, Shutdown};
use fleetd::runner::{
    AgentOutcome, AgentRunner, ChildWait, Interrupt, Reporter, RunConfig, STRIPPED_ENV,
};
use fleetd::toolhook::ToolReport;
use serde_json::json;
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

#[path = "common/bounded.rs"]
mod common;
#[path = "common/logs.rs"]
mod logs;
#[path = "common/reader.rs"]
mod reader;

use logs::capture_logs;
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

const SCRIPT: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo '2.1.289 (Claude Code)'; exit 0; fi
mode=${2%%:*}
path=${2#*:}
case "$mode" in
stream)
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"working on it"}]}}'
  echo 'token hunter2-hunter2 end'
  exit 0 ;;
exit3) echo out; exit 3 ;;
cat) cat "$path"; exit 0 ;;
catfail) cat "$path"; exit 3 ;;
cathold) cat "${path%%|*}"; sleep 300 > "${path#*|}" & wait ;;
sleepy) cat "$path"; sleep 0.4; cat "$path.second"; exit 0 ;;
env) env; exit 0 ;;
dir) printf 'dir=%s\n' "$HOME"; cat "$HOME/.claude/CLAUDE.md" "$HOME/.claude/settings.json" "$HOME/.gitconfig"; ls -d "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$XDG_DATA_HOME"; exit "${path:-0}" ;;
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
    fail_mask: AtomicU64,
    calls: AtomicUsize,
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
        let call = self.switch.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let masked = (self.switch.fail_mask.load(Ordering::SeqCst) >> call) & 1 == 1;
        #[expect(
            deprecated,
            reason = "try_update needs rust 1.95, above the workspace MSRV"
        )]
        let failing = masked
            || self
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

fn jobs_dir() -> PathBuf {
    static ROOT: OnceLock<TempDir> = OnceLock::new();
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = ROOT.get_or_init(|| TempDir::new().unwrap_or_else(|_| std::process::abort()));
    root.path()
        .join(NEXT.fetch_add(1, Ordering::SeqCst).to_string())
}

fn base_env() -> Vec<(OsString, OsString)> {
    let mut env = vec![
        ("GH_TOKEN".into(), "not-a-real-gh-value".into()),
        ("FLEET_TOKEN".into(), "not-a-real-fleet-value".into()),
        ("KEPT_VALUE".into(), "kept".into()),
        ("HOME".into(), "/real/operator/home".into()),
        ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
        ("XDG_CONFIG_HOME".into(), "/real/operator/config".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("TERM".into(), "dumb".into()),
        ("CLAUDE_CODE_OAUTH_TOKEN".into(), "oauth-pass".into()),
        ("HTTPS_PROXY".into(), "http://proxy.invalid:3128".into()),
        ("NO_PROXY".into(), "localhost".into()),
        ("DISABLE_TELEMETRY".into(), "1".into()),
        ("EXTRA_PASS".into(), "extra".into()),
        ("FLEETD_ASKPASS".into(), "1".into()),
        ("FLEETD_ASKPASS_HOST".into(), "github.com".into()),
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
    config.jobs_dir = Some(jobs_dir());
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

fn env_map(all: &str) -> std::collections::BTreeMap<&str, &str> {
    all.lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}

#[tokio::test]
async fn runner_env_is_an_allowlist_with_a_home_under_the_job_dir() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();
        let mut cfg = config(false);
        cfg.env_passthrough = vec![
            "EXTRA_PASS".into(),
            "GH_TOKEN".into(),
            "FLEETD_ASKPASS".into(),
        ];
        let jobs = cfg.jobs_dir.clone().ok_or("jobs dir")?;
        let (agent, mut rx) = runner(cfg, 0);
        agent.run(&job("env:"), dir.path(), shutdown).await?;
        let all = text(&drain(&mut rx));
        let env = env_map(&all);
        let home = jobs.join(".agent").join("job1").join("home");
        let home = home.to_string_lossy();
        assert_eq!(env.get("HOME"), Some(&&*home));
        assert!(!all.contains("/real/operator"));
        assert!(!env.contains_key("XDG_RUNTIME_DIR"));
        assert!(!all.contains("not-a-real"));
        for name in STRIPPED_ENV {
            assert!(!env.contains_key(name), "{name} leaked");
        }
        assert!(env.keys().all(|name| !name.starts_with("FLEETD_ASKPASS")));
        assert!(!env.contains_key("KEPT_VALUE"));
        for (name, value) in [
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C.UTF-8"),
            ("TERM", "dumb"),
            ("CLAUDE_CODE_OAUTH_TOKEN", "oauth-pass"),
            ("HTTPS_PROXY", "http://proxy.invalid:3128"),
            ("NO_PROXY", "localhost"),
            ("DISABLE_TELEMETRY", "1"),
            ("EXTRA_PASS", "extra"),
            ("FLEET_JOB_ID", "job1"),
            ("SWARM_BOX", "1"),
            ("DISABLE_AUTOUPDATER", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_AUTHOR_NAME", JOB_NAME),
            ("GIT_AUTHOR_EMAIL", JOB_EMAIL),
            ("GIT_COMMITTER_NAME", JOB_NAME),
            ("GIT_COMMITTER_EMAIL", JOB_EMAIL),
        ] {
            assert_eq!(env.get(name), Some(&value), "{name}");
        }
        for (name, tail) in [
            ("CLAUDE_CONFIG_DIR", "home/.claude"),
            ("XDG_CONFIG_HOME", "home/.config"),
            ("XDG_CACHE_HOME", "home/.cache"),
            ("XDG_STATE_HOME", "home/.local/state"),
            ("XDG_DATA_HOME", "home/.local/share"),
            ("GIT_CONFIG_GLOBAL", "home/.gitconfig"),
        ] {
            let want = jobs.join(".agent").join("job1").join(tail);
            assert_eq!(env.get(name), Some(&&*want.to_string_lossy()), "{name}");
        }
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
            assert!(all.contains("arg=--setting-sources\narg=user\n"));
            assert!(all.contains(&format!(
                "arg=--append-system-prompt\narg={AGENT_PROTOCOL}\n"
            )));
            assert!(all.contains("arg=--disallowedTools\narg=Bash(git push *)\narg=Bash(gh *)\n"));
            assert!(!all.contains("--bare"));
            assert!(!all.contains("disableBypassPermissionsMode"));
            assert_eq!(all.contains("--dangerously-skip-permissions"), expected);
            assert_eq!(
                all.contains("arg=--permission-mode\narg=dontAsk\n"),
                !expected
            );
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn every_job_gets_both_caps_with_the_configured_values() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();
        for disposable in [false, true] {
            let mut cfg = config(disposable);
            cfg.max_turns = 7;
            cfg.max_budget_usd = 1.25;
            let (agent, mut rx) = runner(cfg, 0);
            agent
                .run(&job("args:"), dir.path(), shutdown.clone())
                .await?;
            let all = text(&drain(&mut rx));
            assert!(all.contains("arg=--max-turns\narg=7\n"));
            assert!(all.contains("arg=--max-budget-usd\narg=1.25\n"));
        }
        let (agent, mut rx) = runner(config(false), 0);
        agent.run(&job("args:"), dir.path(), shutdown).await?;
        let all = text(&drain(&mut rx));
        assert!(all.contains("arg=--max-turns\narg=100\n"));
        assert!(all.contains("arg=--max-budget-usd\narg=5\n"));
        assert_eq!(all.matches("--max-turns").count(), 1);
        assert_eq!(all.matches("--max-budget-usd").count(), 1);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_bundle_cannot_override_or_remove_the_caps() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let hostile = TempDir::new()?;
        std::fs::write(
            hostile.path().join("settings.json"),
            r#"{"maxTurns":100000,"max_turns":100000,"maxBudgetUsd":9999,"env":{"MAX_TURNS":"9"}}"#,
        )?;
        assert!(Bundle::from_dir(hostile.path()).is_err());
        let bundle = TempDir::new()?;
        std::fs::write(
            bundle.path().join("settings.json"),
            r#"{"model":"sonnet","permissions":{"allow":["Bash"]}}"#,
        )?;
        let (_trigger, shutdown) = Shutdown::channel();
        let mut cfg = config(false);
        cfg.max_turns = 9;
        cfg.max_budget_usd = 2.0;
        cfg.bundle = Bundle::from_dir(bundle.path())?;
        let (agent, mut rx) = runner(cfg, 0);
        agent.run(&job("args:"), dir.path(), shutdown).await?;
        let all = text(&drain(&mut rx));
        assert!(all.contains("arg=--max-turns\narg=9\n"));
        assert!(all.contains("arg=--max-budget-usd\narg=2\n"));
        Ok(())
    }))
    .await
}

fn capped_result(subtype: &str, is_error: bool) -> String {
    json!({"type":"result","subtype":subtype,"is_error":is_error,"num_turns":30,
        "duration_ms":10,"duration_api_ms":5,"stop_reason":"tool_use","total_cost_usd":1.5,
        "usage":{"input_tokens":7,"output_tokens":8}})
    .to_string()
}

#[tokio::test]
async fn a_cap_hit_is_a_distinct_failure_and_other_endings_are_not() -> TestResult {
    common::bounded(Box::pin(async {
        let table: [(&str, bool, &str, Option<&str>); 7] = [
            (
                "error_max_turns",
                true,
                "catfail",
                Some("max turns reached"),
            ),
            ("error_max_turns", true, "cat", Some("max turns reached")),
            (
                "error_max_budget_usd",
                true,
                "catfail",
                Some("budget exceeded"),
            ),
            ("error_max_budget_usd", true, "cat", Some("budget exceeded")),
            (
                "error_during_execution",
                true,
                "catfail",
                Some("agent exited with a failure status"),
            ),
            (
                "success",
                false,
                "catfail",
                Some("agent exited with a failure status"),
            ),
            ("success", false, "cat", None),
        ];
        for (subtype, is_error, mode, expected) in table {
            let dir = TempDir::new()?;
            let lines = [
                json!({"type":"system","subtype":"init"}).to_string(),
                capped_result(subtype, is_error),
            ];
            let file = fixture(dir.path(), "run.jsonl", &lines)?;
            let (agent, mut rx) = runner(config(false), 0);
            let (_trigger, shutdown) = Shutdown::channel();
            let prompt = format!("{mode}:{}", file.display());
            let outcome = agent.run(&job(&prompt), dir.path(), shutdown).await?;
            let requests = drain(&mut rx);
            let Some(error) = expected else {
                assert_eq!(outcome, AgentOutcome::Succeeded, "{subtype} {mode}");
                assert!(requests.iter().all(|r| r.terminal_state.is_none()));
                continue;
            };
            let last = terminal(&requests)?;
            let exit_code = if mode == "cat" { Some(0) } else { Some(3) };
            assert_eq!(
                outcome,
                AgentOutcome::Failed { exit_code, error },
                "{subtype} {mode}"
            );
            assert_eq!(last.terminal_state, Some(i32::from(JobState::Failed)));
            assert_eq!(last.error.as_deref(), Some(error));
            assert_eq!(last.exit_code, exit_code);
            assert_eq!(
                last.summary
                    .as_ref()
                    .and_then(|s| s.result_subtype.as_deref()),
                Some(subtype)
            );
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
        let (agent, mut rx) = slow_flush(0);
        let (_trigger, shutdown) = Shutdown::channel();
        agent.run(&job("burst:"), dir.path(), shutdown).await?;
        let requests = drain(&mut rx);
        let sizes: Vec<_> = requests.iter().map(|r| r.chunks.len()).collect();
        assert_eq!(
            sizes,
            [
                MAX_CHUNKS_PER_REPORT,
                MAX_CHUNKS_PER_REPORT,
                700 - 2 * MAX_CHUNKS_PER_REPORT
            ]
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

struct Unawaitable(tokio::process::Child);

impl ChildWait for Unawaitable {
    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.wait().await?;
        Err(std::io::Error::from_raw_os_error(
            rustix::io::Errno::CHILD.raw_os_error(),
        ))
    }
}

#[tokio::test]
async fn runner_reports_failed_when_the_child_cannot_be_awaited() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let job = job("stream:");
        let outcome = agent
            .run_with(&job, dir.path(), shutdown, Unawaitable)
            .await;
        assert!(matches!(outcome, Err(RunError)));
        let requests = drain(&mut rx);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert_eq!(last.error.as_deref(), Some("agent could not be awaited"));
        Ok(())
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

fn slow_cfg() -> RunConfig {
    let mut cfg = config(false);
    cfg.flush_interval = Duration::from_secs(3600);
    cfg.report_interval = Duration::from_secs(3600);
    cfg
}

fn slow_report() -> RunConfig {
    let mut cfg = config(false);
    cfg.report_interval = Duration::from_secs(3600);
    cfg
}

fn slow_flush(fail_first: usize) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    runner(slow_cfg(), fail_first)
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
        assert_eq!(drain(&mut rx), Vec::<ReportJobRequest>::new());
        agent.fail_job(&job("stream:"), "boom").await;
        let requests = drain(&mut rx);
        assert_eq!(seqs(&requests), vec![1, 2]);
        let last = requests.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert_eq!(last.chunks, Vec::<TranscriptChunk>::new());
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

#[tokio::test]
async fn the_job_dir_holds_the_bundle_during_the_run_and_is_gone_after() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();
        let cfg = config(false);
        let jobs = cfg.jobs_dir.clone().ok_or("jobs dir")?;
        let (agent, mut rx) = runner(cfg, 0);
        let outcome = agent.run(&job("dir:"), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        let all = text(&drain(&mut rx));
        assert!(all.contains("Commit finished work"));
        assert!(all.contains("\"Edit\""));
        assert!(all.contains("\"Bash(git push *)\""));
        assert!(all.contains("\"Bash(gh *)\""));
        assert!(all.contains("\"attribution\""));
        assert!(all.contains(&format!("name = {JOB_NAME}")));
        assert!(all.contains(&format!("email = {JOB_EMAIL}")));
        assert!(all.contains("gpgsign = false"));
        assert!(all.contains("/home/.config"));
        assert!(all.contains("/home/.local/share"));
        assert!(!jobs.join(".agent").join("job1").exists());
        assert!(!jobs.join(".agent").join("job1.tmp").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_job_dir_is_gone_after_a_failed_run_and_a_failed_start() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (_trigger, shutdown) = Shutdown::channel();
        let cfg = config(false);
        let jobs = cfg.jobs_dir.clone().ok_or("jobs dir")?;
        let (agent, _rx) = runner(cfg, 0);
        let outcome = agent
            .run(&job("dir:3"), dir.path(), shutdown.clone())
            .await?;
        assert!(matches!(
            outcome,
            AgentOutcome::Failed {
                exit_code: Some(3),
                ..
            }
        ));
        assert!(!jobs.join(".agent").join("job1").exists());
        let mut missing = config(false);
        missing.claude_bin = dir.path().join("absent");
        let jobs = missing.jobs_dir.clone().ok_or("jobs dir")?;
        let (agent, _rx) = runner(missing, 0);
        agent.run(&job("dir:"), dir.path(), shutdown).await?;
        assert!(!jobs.join(".agent").join("job1").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_bundle_override_reaches_the_job_home() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let bundle = TempDir::new()?;
        std::fs::write(bundle.path().join("CLAUDE.md"), "operator persona")?;
        let (_trigger, shutdown) = Shutdown::channel();
        let mut cfg = config(false);
        cfg.bundle = Bundle::from_dir(bundle.path())?;
        let (agent, mut rx) = runner(cfg, 0);
        agent.run(&job("dir:"), dir.path(), shutdown).await?;
        let all = text(&drain(&mut rx));
        assert!(all.contains("operator persona"));
        assert!(all.contains("\"Edit\""));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_spawn_failure_logs_the_program_and_error_kind_but_not_the_prompt() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let (logs, _guard) = capture_logs();
        let mut cfg = config(false);
        cfg.claude_bin = dir.path().join("absent-claude");
        let (agent, _rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .run(&job("prompt-with-private-words"), dir.path(), shutdown)
            .await?;
        let out = logs.text();
        assert!(out.contains("agent could not be spawned"), "{out}");
        assert!(out.contains("absent-claude"), "{out}");
        assert!(out.contains("NotFound"), "{out}");
        assert!(!out.contains("prompt-with-private-words"), "{out}");
        Ok(())
    }))
    .await
}

fn bash_use(id: &str, command: &str) -> String {
    json!({"type":"assistant","message":{"id":format!("m{id}"),"content":[
        {"type":"tool_use","id":id,"name":"Bash","input":{"command":command}}]}})
    .to_string()
}

fn tool_ok(id: &str) -> String {
    json!({"type":"user","message":{"content":[
        {"type":"tool_result","tool_use_id":id,"content":"out"}]}})
    .to_string()
}

fn denied(id: &str, message: &str) -> String {
    json!({"type":"system","subtype":"permission_denied","tool_name":"Bash",
        "tool_use_id":id,"message":message})
    .to_string()
}

fn result_line() -> String {
    json!({"type":"result","subtype":"success","num_turns":3,"duration_ms":10,
        "duration_api_ms":5,"total_cost_usd":0.5,
        "usage":{"input_tokens":7,"output_tokens":8}})
    .to_string()
}

fn secret_run() -> Vec<String> {
    vec![
        json!({"type":"system","subtype":"init"}).to_string(),
        bash_use("t1", "echo hunter2-hunter2 done"),
        tool_ok("t1"),
        denied("t2", "denied hunter2-hunter2 here"),
        "not json {{{".to_owned(),
        result_line(),
    ]
}

fn fixture(dir: &Path, name: &str, lines: &[String]) -> Result<PathBuf, std::io::Error> {
    let path = dir.join(name);
    std::fs::write(&path, format!("{}\n", lines.join("\n")))?;
    Ok(path)
}

fn events(requests: &[ReportJobRequest]) -> Vec<JobEvent> {
    requests.iter().flat_map(|r| r.events.clone()).collect()
}

fn terminal(requests: &[ReportJobRequest]) -> Result<&ReportJobRequest, &'static str> {
    requests
        .iter()
        .find(|r| r.terminal_state.is_some())
        .ok_or("no terminal report")
}

#[tokio::test]
async fn telemetry_events_and_summary_reach_a_failed_run_redacted() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let file = fixture(dir.path(), "run.jsonl", &secret_run())?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("catfail:{}", file.display());
        let outcome = agent.run(&job(&prompt), dir.path(), shutdown).await?;
        assert!(matches!(outcome, AgentOutcome::Failed { .. }));
        let requests = drain(&mut rx);
        let sent = events(&requests);
        assert_eq!(sent.iter().map(|e| e.seq).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(sent[0].kind, i32::from(JobEventKind::Tool));
        assert_eq!(sent[1].kind, i32::from(JobEventKind::Denial));
        assert!(
            sent[0]
                .cmd
                .as_deref()
                .is_some_and(|c| c.contains("[REDACTED]"))
        );
        assert!(
            sent[1]
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("[REDACTED]"))
        );
        assert!(!format!("{requests:?}").contains("hunter2"));
        let summary = terminal(&requests)?.summary.clone().ok_or("no summary")?;
        assert!(summary.complete);
        assert_eq!(summary.turns, Some(3));
        assert_eq!(summary.tool_calls, Some(1));
        assert_eq!(summary.denials, Some(1));
        assert_eq!(summary.model, None);
        assert!(
            requests
                .iter()
                .filter(|r| r.terminal_state.is_none())
                .all(|r| r.summary.is_none())
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_version_stamp_reaches_the_terminal_summary() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let init = json!({"type":"system","subtype":"init","model":"claude-opus-4"}).to_string();
        let file = fixture(dir.path(), "run.jsonl", &[init, result_line()])?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("catfail:{}", file.display());
        let outcome = agent.run(&job(&prompt), dir.path(), shutdown).await?;
        assert!(matches!(outcome, AgentOutcome::Failed { .. }));
        let requests = drain(&mut rx);
        let summary = terminal(&requests)?.summary.clone().ok_or("no summary")?;
        assert_eq!(summary.model.as_deref(), Some("claude-opus-4"));
        assert_eq!(
            summary.claude_version.as_deref(),
            Some("2.1.289 (Claude Code)")
        );
        let sha = summary.bundle_sha.ok_or("no bundle sha")?;
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_timed_out_run_sends_its_events_and_a_summary() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let file = fixture(dir.path(), "run.jsonl", &secret_run())?;
        let hold = fifo(dir.path(), "hold")?;
        let reader = hold_reader(&hold);
        let mut cfg = config(false);
        cfg.timeout = START_BAND;
        let (agent, mut rx) = runner(cfg, 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cathold:{}|{}", file.display(), hold.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        let requests = drain(&mut rx);
        assert_eq!(events(&requests).len(), 2);
        let summary = terminal(&requests)?.summary.clone().ok_or("no summary")?;
        assert!(summary.complete);
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_cancelled_run_sends_its_events_and_a_summary() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let file = fixture(dir.path(), "run.jsonl", &secret_run())?;
        let hold = fifo(dir.path(), "hold")?;
        let mut reader = hold_reader(&hold);
        let (agent, mut rx, switch) = switched(fast_beat(), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cathold:{}|{}", file.display(), hold.display());
        let job = job(&prompt);
        let (outcome, driven) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(20),
                agent.run(&job, dir.path(), shutdown)
            ),
            async {
                reader.wait_opened().await?;
                switch.cancel.store(true, Ordering::SeqCst);
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        );
        driven?;
        assert_eq!(outcome??, AgentOutcome::Cancelled);
        let requests = drain(&mut rx);
        assert_eq!(events(&requests).len(), 2);
        let last = terminal(&requests)?;
        assert_eq!(last.terminal_state, Some(JobState::Cancelled.into()));
        assert!(last.summary.is_some());
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_failed_report_resends_the_same_events_once() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let file = fixture(dir.path(), "run.jsonl", &secret_run())?;
        let (agent, mut rx) = slow_flush(2);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        let outcome = agent.run(&job(&prompt), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        assert_eq!(drain(&mut rx), Vec::<ReportJobRequest>::new());
        agent.fail_job(&job(&prompt), "boom").await;
        let requests = drain(&mut rx);
        assert_eq!(
            events(&requests).iter().map(|e| e.seq).collect::<Vec<_>>(),
            [0, 1]
        );
        assert!(terminal(&requests)?.summary.is_some());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_backlog_over_256_events_splits_across_reports_with_ascending_seq() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let uses: Vec<_> = (0..300)
            .map(|i| json!({"type":"tool_use","id":format!("t{i}"),"name":"Bash","input":{"command":"ls"}}))
            .collect();
        let results: Vec<_> = (0..300)
            .map(|i| json!({"type":"tool_result","tool_use_id":format!("t{i}"),"content":"o"}))
            .collect();
        let lines = [
            json!({"type":"assistant","message":{"id":"m","content":uses}}).to_string(),
            json!({"type":"user","message":{"content":results}}).to_string(),
        ];
        let file = fixture(dir.path(), "run.jsonl", &lines)?;
        let (agent, mut rx) = slow_flush(0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        let requests = drain(&mut rx);
        let sizes: Vec<_> = requests
            .iter()
            .map(|r| r.events.len())
            .filter(|n| *n > 0)
            .collect();
        assert_eq!(sizes, [256, 44]);
        let seqs: Vec<_> = events(&requests).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, (0..300).collect::<Vec<u32>>());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn an_events_only_backlog_survives_failed_reports_until_sent() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let uses: Vec<_> = (0..300)
            .map(|i| json!({"type":"tool_use","id":format!("t{i}"),"name":"Bash","input":{"command":"ls"}}))
            .collect();
        let results: Vec<_> = (0..300)
            .map(|i| json!({"type":"tool_result","tool_use_id":format!("t{i}"),"content":"o"}))
            .collect();
        let lines = [
            json!({"type":"assistant","message":{"id":"m","content":uses}}).to_string(),
            json!({"type":"user","message":{"content":results}}).to_string(),
        ];
        let file = fixture(dir.path(), "run.jsonl", &lines)?;
        let (agent, mut rx, switch) = switched(slow_cfg(), 0);
        switch.fail_mask.store(0b1100, Ordering::SeqCst);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        agent.fail_job(&job(&prompt), "boom").await;
        let requests = drain(&mut rx);
        let seqs: Vec<_> = events(&requests).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, (0..300).collect::<Vec<u32>>());
        assert!(terminal(&requests)?.summary.is_some());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_running_job_sends_an_events_only_backlog_without_waiting_for_the_report_interval()
-> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let uses: Vec<_> = (0..300)
            .map(|i| json!({"type":"tool_use","id":format!("t{i}"),"name":"Bash","input":{"command":"ls"}}))
            .collect();
        let results: Vec<_> = (0..300)
            .map(|i| json!({"type":"tool_result","tool_use_id":format!("t{i}"),"content":"o"}))
            .collect();
        let lines = [
            json!({"type":"assistant","message":{"id":"m","content":uses}}).to_string(),
            json!({"type":"user","message":{"content":results}}).to_string(),
        ];
        let file = fixture(dir.path(), "run.jsonl", &lines)?;
        let hold = fifo(dir.path(), "hold")?;
        let mut reader = hold_reader(&hold);
        let (agent, mut rx) = runner(slow_report(), 0);
        let (trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cathold:{}|{}", file.display(), hold.display());
        let job = job(&prompt);
        let (outcome, seen) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(30),
                agent.run(&job, dir.path(), shutdown)
            ),
            async {
                reader.wait_opened().await?;
                let mut count = 0;
                while count < 300 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    count += events(&drain(&mut rx)).len();
                }
                let _ = trigger.send(true);
                Ok::<usize, Box<dyn std::error::Error>>(count)
            }
        );
        assert_eq!(seen?, 300);
        assert!(matches!(outcome?, Err(RunError)));
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn event_time_is_measured_from_job_start() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let first = fixture(
            dir.path(),
            "run.jsonl",
            &[bash_use("a", "ls"), tool_ok("a")],
        )?;
        fixture(
            dir.path(),
            "run.jsonl.second",
            &[bash_use("b", "ls"), tool_ok("b")],
        )?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("sleepy:{}", first.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        let sent = events(&drain(&mut rx));
        assert_eq!(sent.len(), 2);
        assert!(sent[1].ts_ms >= sent[0].ts_ms + 300);
        assert!(sent[1].ts_ms < 20_000);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn garbage_lines_leave_the_transcript_byte_identical() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let lines = vec![
            json!({"type":"system","subtype":"init"}).to_string(),
            "not json".to_owned(),
            String::new(),
            "[1,2,3]".to_owned(),
            "null".to_owned(),
            "\"str\"".to_owned(),
            "[".repeat(5000),
            json!({"type":"user","message":{"content":"x"}}).to_string(),
            json!({"type":"user","message":{"content":[{"type":"tool_result"}]}}).to_string(),
            json!({"type":"assistant","message":{"content":[{"type":"tool_use"}]}}).to_string(),
            "x".repeat(200_000),
            bash_use("t1", "ls"),
        ];
        let file = fixture(dir.path(), "run.jsonl", &lines)?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        let outcome = agent.run(&job(&prompt), dir.path(), shutdown).await?;
        assert_eq!(outcome, AgentOutcome::Succeeded);
        agent.fail_job(&job(&prompt), "boom").await;
        let requests = drain(&mut rx);
        assert_eq!(text(&requests), std::fs::read_to_string(&file)?);
        assert_eq!(events(&requests), Vec::<JobEvent>::new());
        let summary = terminal(&requests)?.summary.clone().ok_or("no summary")?;
        assert!(!summary.complete);
        assert!(summary.missing.contains(&"result".to_owned()));
        Ok(())
    }))
    .await
}

const ESCAPED: &str = "ab\"cd\\ef\ngh-zzTAIL";

fn unicode_escaped(text: &str) -> String {
    text.replace('\\', "\\u005c")
        .replace('"', "\\u0022")
        .replace('\n', "\\u000a")
}

#[tokio::test]
async fn an_escaped_secret_at_the_command_and_detail_caps_leaves_no_prefix() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let command = format!("{}{ESCAPED}", "a".repeat(500));
        let message = format!("{}{ESCAPED}", "b".repeat(1010));
        let raw_use = format!(
            "{{\"type\":\"assistant\",\"message\":{{\"id\":\"m2\",\"content\":[{{\"type\":\"tool_use\",\"id\":\"t2\",\"name\":\"Bash\",\"input\":{{\"command\":\"{}\"}}}}]}}}}",
            unicode_escaped(&command)
        );
        let raw_denial = format!(
            "{{\"type\":\"system\",\"subtype\":\"permission_denied\",\"tool_name\":\"Bash\",\"tool_use_id\":\"d2\",\"message\":\"{}\"}}",
            unicode_escaped(&message)
        );
        let lines = [
            bash_use("t1", &command),
            tool_ok("t1"),
            denied("d1", &message),
            raw_use,
            tool_ok("t2"),
            raw_denial,
        ];
        let file = fixture(dir.path(), "run.jsonl", &lines)?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let fake = Fake {
            tx,
            fail_first: AtomicUsize::new(0),
            switch: Arc::new(Switch::default()),
        };
        let agent = AgentRunner::new(config(false), fake, Redactor::new([ESCAPED]));
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        let sent = events(&drain(&mut rx));
        assert_eq!(sent.len(), 4);
        for event in &sent {
            let fields = [&event.tool_use_id, &event.tool, &event.cmd, &event.detail];
            for field in fields.into_iter().flatten() {
                for end in 6..=ESCAPED.len() {
                    assert!(!field.contains(&ESCAPED[..end]), "prefix of {end} bytes leaked");
                }
            }
        }
        for event in sent.iter().filter(|e| e.kind == i32::from(JobEventKind::Tool)) {
            let cmd = event.cmd.as_deref().ok_or("no cmd")?;
            assert_eq!(cmd.len(), 510);
            assert!(cmd.ends_with("[REDACTED]"));
        }
        for event in sent.iter().filter(|e| e.kind == i32::from(JobEventKind::Denial)) {
            let detail = event.detail.as_deref().ok_or("no detail")?;
            assert_eq!(detail.len(), 1020);
            assert!(detail.ends_with("[REDACTED]"));
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_secret_at_the_command_cap_is_redacted_before_the_cut() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let command = format!("{} hunter2-hunter2 tail", "a".repeat(505));
        let lines = [bash_use("t1", &command), tool_ok("t1")];
        let file = fixture(dir.path(), "run.jsonl", &lines)?;
        let (agent, mut rx) = runner(config(false), 0);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        let sent = events(&drain(&mut rx));
        let cmd = sent.first().and_then(|e| e.cmd.clone()).ok_or("no cmd")?;
        assert_eq!(cmd.len(), 512);
        assert!(cmd.ends_with(" [REDAC"));
        assert!(!cmd.contains("hunt"));
        Ok(())
    }))
    .await
}

fn hook_report(exit: i32, dur: u64) -> ToolReport {
    ToolReport {
        tool_use_id: "a".into(),
        tool_name: "Bash".into(),
        exit_code: Some(exit),
        dur_ms: Some(dur),
    }
}

#[tokio::test]
async fn a_tool_hook_fills_the_event_exit_code_and_the_summary_bash_nonzero() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        fixture(dir.path(), "run.jsonl", &[bash_use("a", "false")])?;
        let first = dir.path().join("run.jsonl");
        fixture(dir.path(), "run.jsonl.second", &[tool_ok("a")])?;
        let hub = HookHub::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let fake = Fake {
            tx,
            fail_first: AtomicUsize::new(0),
            switch: Arc::new(Switch::default()),
        };
        let agent =
            AgentRunner::new(config(false), fake, Redactor::default()).with_hook_hub(hub.clone());
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("sleepy:{}", first.display());
        let job = job(&prompt);
        let (outcome, delivered) = tokio::join!(agent.run(&job, dir.path(), shutdown), async {
            assert!(!hub.deliver("other-job", hook_report(5, 5)));
            for _ in 0..800 {
                if hub.deliver("job1", hook_report(2, 123)) {
                    assert!(hub.deliver("job1", hook_report(9, 999)));
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            false
        });
        assert_eq!(outcome?, AgentOutcome::Succeeded);
        assert!(delivered, "job never registered with the hub");
        agent.fail_job(&job, "boom").await;
        let requests = drain(&mut rx);
        let sent = events(&requests);
        assert_eq!(sent.len(), 1);
        let event = sent.first().ok_or("no event")?;
        assert_eq!(event.exit_code, Some(2));
        assert_eq!(event.dur_ms, Some(123));
        let summary = terminal(&requests)?.summary.clone().ok_or("no summary")?;
        assert_eq!(summary.bash_nonzero, Some(1));
        assert!(!summary.missing.contains(&"exit_codes".to_owned()));
        assert!(hub.dropped() >= 1);
        assert!(!hub.deliver("job1", hook_report(1, 1)));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn without_a_hook_the_summary_keeps_exit_codes_missing() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let file = fixture(
            dir.path(),
            "run.jsonl",
            &[bash_use("a", "ls"), tool_ok("a")],
        )?;
        let hub = HookHub::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let fake = Fake {
            tx,
            fail_first: AtomicUsize::new(0),
            switch: Arc::new(Switch::default()),
        };
        let agent = AgentRunner::new(config(false), fake, Redactor::default()).with_hook_hub(hub);
        let (_trigger, shutdown) = Shutdown::channel();
        let prompt = format!("cat:{}", file.display());
        agent.run(&job(&prompt), dir.path(), shutdown).await?;
        agent.fail_job(&job(&prompt), "boom").await;
        let requests = drain(&mut rx);
        assert_eq!(events(&requests).first().map(|e| e.exit_code), Some(None));
        let summary = terminal(&requests)?.summary.clone().ok_or("no summary")?;
        assert!(summary.missing.contains(&"exit_codes".to_owned()));
        Ok(())
    }))
    .await
}
