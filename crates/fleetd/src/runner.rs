//! Runs `claude -p` for a claimed job and streams its output through `ReportJob`.
//!
//! The agent runs as a child in its own process group with a scrubbed environment. Every
//! stdout line is redacted, then sent as a transcript chunk. A report goes out when 64 KiB
//! of chunks are pending, every flush interval while chunks wait, and at least every
//! report interval even when the agent is silent, so the server lease cannot lapse on a
//! quiet agent. A reply with `cancel_requested` sends `SIGTERM` to the group, and after the
//! cancel grace `SIGKILL`, then reports `CANCELLED`. A `FAILED_PRECONDITION` reply means the
//! lease is gone: the group is killed, pending chunks are dropped and nothing more is sent.
//!
//! A report runs as an in-flight future inside the read loop, so a slow or hung server never
//! stops stdout reads, cancel or the child's exit from being seen. At most one report is in
//! flight. After a failure only the flush tick retries, so a dead server costs one timeout
//! per tick, not one per line. Chunks that no report delivered stay queued and travel with
//! the carry into [`AgentRunner::finish`], and the terminal report retries until they are
//! delivered or [`RunConfig::terminal_report_timeout`] passes. After the agent exits,
//! stdout is drained for at most [`STDOUT_DRAIN`], so a descendant that left the process
//! group cannot hold the run open. A chunk cut to [`MAX_CHUNK_BYTES`] has `truncated` set.
//!
//! Each redacted line also feeds a per-job parser ([`crate::telemetry`], wrapped in a private
//! `feed` module). Its events ride the same reports in batches of at most 256, keep their
//! `seq`, and stay queued until a report succeeds, so a retry resends the same events. At
//! most 4096 events wait: the oldest drop first and are counted. A parser fault only bumps a
//! counter and never touches the transcript. The terminal report carries the summary. A lost
//! lease sends no terminal report, so it sends no summary.
//! Chunk numbers and progress carry from [`AgentRunner::run`] into [`AgentRunner::finish`]
//! and [`AgentRunner::fail_job`] for the same job, so the server keeps their chunks.
//! [`AgentRunner::keep_alive`] and `finish` renew the lease while git steps run, and stop the
//! work when a renewal shows the lease gone or the job cancelled.
//!
//! After a successful run, [`AgentRunner::finish`] fetches `swarm/<job_id>` from the worktree
//! into a throwaway bare repo, counts the commits, pushes the branch and opens the pull
//! request with `gh` from that repo, then sends the terminal report. Every helper runs in
//! its own process group with an allowlisted environment and a scratch `HOME` and config
//! dirs, so no agent-writable config is read. The push carries only `GIT_ASKPASS`, which
//! names `fleetd askpass`, and the `GH_TOKEN` that helper prints, and `gh` only its own
//! token. Push is limited to `https` remotes on the [`RepoPolicy`] hosts.
//!
//! The agent runs with `HOME` and `CLAUDE_CONFIG_DIR` in a per-job directory
//! ([`crate::agent_config`]) and an allowlisted environment, never the operator's home. Before
//! the fetch, [`AgentRunner::finish`] commits whatever the agent left uncommitted in the
//! worktree, unless the staged diff holds a value the redactor knows.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::MAX_CHUNKS_PER_REPORT;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest, TranscriptChunk};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Instant, MissedTickBehavior, Sleep};
use tonic::{Code, Status};

use crate::agent_config::{Bundle, JOB_EMAIL, JOB_NAME, JobDir};
use crate::askpass;
use crate::feed::Feed;
use crate::group::GroupGuard;
use crate::now_ms;
use crate::poller::{RunError, Shutdown};
use crate::proc::{CAPTURE_BYTES, CaptureError, Captured, capture};
use crate::telemetry::Terminal as Ending;
use crate::toolhook::HookHub;
use crate::workspace::{RepoPolicy, validate_job_id, validate_ref, validate_repo};

/// Variables that never reach the agent's environment block, however it is configured.
///
/// The agent environment is an allowlist, so this list is the test oracle and the check for
/// `agent_env_passthrough`. The agent runs as fleetd's uid and can still read the fleetd
/// environment through `/proc` (ADR-0024 Known limit). The push child keeps `GH_TOKEN` and
/// `GIT_ASKPASS`.
pub const STRIPPED_ENV: [&str; 9] = [
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

const AGENT_ENV: [&str; 12] = [
    "PATH",
    "LANG",
    "TERM",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "DISABLE_TELEMETRY",
];
const AGENT_ENV_PREFIX: &str = "LC_";
pub(crate) const DENIED_TOOLS: [&str; 6] = [
    "Bash(git push *)",
    "Bash(gh *)",
    "Edit",
    "Write",
    "NotebookEdit",
    "MultiEdit",
];

/// Appended to the agent's system prompt.
pub const AGENT_PROTOCOL: &str = "You run as an unattended fleet job. Commit finished work on the current branch with a semantic message (type(scope): subject). Never push and never run gh: the daemon publishes the branch. Add no attribution lines to commits or pull requests. The Edit and Write tools are denied: change files with Bash, using a quoted python3 heredoc.";

const CLEAN_ENV: [&str; 1] = ["PATH"];
const PUSH_ENV: [&str; 2] = ["PATH", "GH_TOKEN"];
const GH_ENV: [&str; 4] = ["PATH", "GH_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN"];
const MAX_TITLE_CHARS: usize = 256;

/// Default longest time for the whole finish step, and for each helper in it.
pub const DEFAULT_FINISH_TIMEOUT: Duration = Duration::from_secs(300);

/// Default longest time for preparing the workspace.
pub const DEFAULT_PREPARE_TIMEOUT: Duration = Duration::from_secs(300);

const TAIL_BYTES: usize = 2048;
const MAX_PR_URL_BYTES: usize = 2048;

/// Default for `max_turns`, passed to every job as `--max-turns`.
///
/// Read from `claude --help` and the option table of the installed binary, Claude Code
/// 2.1.289: `--max-turns <turns>` is "Maximum number of agentic turns in non-interactive mode.
/// This will early exit the conversation after the specified number of turns. (only works with
/// --print)". At that version `claude --help` does not list it, but the binary registers it.
/// `--max-budget-usd <amount>` is "Maximum dollar amount to spend on API calls (only works
/// with --print)". When a limit hits, the binary ends the run with a stream-json `result` line
/// whose `subtype` is `error_max_turns` or `error_max_budget_usd` (both strings are in the
/// binary and its text-mode handler prints "Reached max turns" and "Exceeded USD budget").
/// Not observed, so unverified: the process exit code on a cap hit and the `is_error` value
/// of those lines, and whether the budget is checked before or after the call that crosses it.
pub const DEFAULT_MAX_TURNS: u32 = 100;
/// Default for `max_budget_usd`, passed to every job as `--max-budget-usd`. See
/// [`DEFAULT_MAX_TURNS`] for what the flag does.
pub const DEFAULT_MAX_BUDGET_USD: f64 = 5.0;

/// Default hard limit on one agent run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Default time between report attempts while chunks are pending.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Default longest gap between reports, silent agent or not.
pub const DEFAULT_REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// Default longest wait for the terminal report after a run ends.
pub const DEFAULT_TERMINAL_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default time a cancelled agent gets after `SIGTERM` before `SIGKILL`.
pub const DEFAULT_CANCEL_GRACE: Duration = Duration::from_secs(10);

/// Longest wait for stdout to close after the agent exits. A descendant that escaped the
/// process group and holds the pipe cannot stretch the run past it.
pub const STDOUT_DRAIN: Duration = Duration::from_secs(1);

/// Pending chunk bytes that trigger an immediate report.
pub const FLUSH_BYTES: usize = 64 * 1024;

/// Most chunk bytes held while the server is unreachable. The oldest chunks go first.
pub const MAX_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Most chunk bytes in one report, kept under the 1 MiB server decode limit.
pub const MAX_REQUEST_BYTES: usize = 512 * 1024;

/// Longest chunk text. A longer stdout line is cut at a character boundary.
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;

/// Longest progress text, in characters.
pub const MAX_PROGRESS_CHARS: usize = 200;

const RETRY_PAUSE: Duration = Duration::from_millis(200);

const PHASE: &str = "agent";
const ERR_START: &str = "agent could not start";
const ERR_EXIT: &str = "agent exited with a failure status";
const ERR_SIGNAL: &str = "agent was killed by a signal";
const ERR_TIMEOUT: &str = "agent timed out";
const ERR_SHUTDOWN: &str = "agent stopped by daemon shutdown";
const ERR_WAIT: &str = "agent could not be awaited";
const ERR_MAX_TURNS: &str = "max turns reached";
const ERR_BUDGET: &str = "budget exceeded";
const SUBTYPE_MAX_TURNS: &str = "error_max_turns";
const SUBTYPE_BUDGET: &str = "error_max_budget_usd";
const ERR_COMMITS: &str = "job commits could not be inspected";
const ERR_PUSH: &str = "git push failed";
const ERR_PR: &str = "pull request could not be opened";
const ERR_PR_URL: &str = "pull request url was not returned";
const ERR_FINISH_TIMEOUT: &str = "finish step timed out";
const ERR_SECRET: &str = "uncommitted changes held a secret value";
const MAX_DIFF_BYTES: u64 = 32 * 1024 * 1024;
const LOG_TAIL_BYTES: usize = 512;
const NO_CHANGES_NOTE: &str = "fleet: no_changes";
const FALLBACK_GUARDS: [&str; 16] = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "core.sshCommand=",
    "-c",
    "credential.helper=",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
    "-c",
    "core.pager=cat",
];

/// True when `name` may not reach the agent: a [`STRIPPED_ENV`] name or a `FLEETD_` one.
#[must_use]
pub fn env_forbidden(name: &str) -> bool {
    STRIPPED_ENV.contains(&name) || name.starts_with("FLEETD_")
}

/// Sends one `ReportJob` call. The seam lets tests run without a server.
pub trait Reporter: Send + Sync {
    /// Delivers `request`.
    ///
    /// # Errors
    ///
    /// Returns the gRPC status when the call fails.
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send;
}

/// How the agent is started and paced.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunConfig {
    /// Agent binary, `claude` by default.
    pub claude_bin: PathBuf,
    /// GitHub CLI binary that opens the pull request, `gh` by default.
    pub gh_bin: PathBuf,
    /// The fleetd executable the push runs as `<path> askpass`, the current executable by
    /// default.
    pub askpass_bin: PathBuf,
    /// Repos a job may push to. The push runs with only these hosts, and the askpass helper
    /// answers only for the token host.
    pub repo_policy: RepoPolicy,
    /// Git binary used to fetch, count, log and push commits, `git` by default.
    pub git_bin: PathBuf,
    /// Longest time for the finish step and for each helper command in it.
    pub finish_timeout: Duration,
    /// True when the box is disposable. Only then the agent runs with permission checks off.
    pub disposable: bool,
    /// Hard limit on the run. The process group is killed when it passes.
    pub timeout: Duration,
    /// Agentic turns one job may take, always passed as `--max-turns`.
    pub max_turns: u32,
    /// Dollars one job may spend, always passed as `--max-budget-usd`.
    pub max_budget_usd: f64,
    /// Time between report attempts while chunks wait.
    pub flush_interval: Duration,
    /// Longest gap between reports.
    pub report_interval: Duration,
    /// Time between `SIGTERM` and `SIGKILL` when the server asks to cancel.
    pub cancel_grace: Duration,
    /// Longest time for preparing the workspace, lease renewals included.
    pub prepare_timeout: Duration,
    /// Longest wait for the terminal report. Past it the report is dropped, so a hung
    /// server cannot hold the runner after the process group is dead.
    pub terminal_report_timeout: Duration,
    /// Environment the agent inherits from, filtered by the allowlist and
    /// [`RunConfig::env_passthrough`].
    pub base_env: Vec<(OsString, OsString)>,
    /// Extra names the agent inherits from [`RunConfig::base_env`]. A [`STRIPPED_ENV`] or
    /// `FLEETD_` name is ignored here.
    pub env_passthrough: Vec<String>,
    /// Files for the per-job `home/.claude`, the embedded bundle by default.
    pub bundle: Bundle,
    /// Directory that holds `.agent/<job id>`, the parent of the worktree when absent.
    pub jobs_dir: Option<PathBuf>,
    /// Group that owns the per-job agent directory, group-writable. Unset keeps the 0700 modes.
    pub job_gid: Option<u32>,
}

impl RunConfig {
    /// A config for `claude_bin` that inherits the current process environment.
    pub fn new(claude_bin: impl Into<PathBuf>, disposable: bool) -> Self {
        Self {
            claude_bin: claude_bin.into(),
            gh_bin: PathBuf::from("gh"),
            git_bin: PathBuf::from("git"),
            askpass_bin: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("fleetd")),
            repo_policy: RepoPolicy::default(),
            finish_timeout: DEFAULT_FINISH_TIMEOUT,
            prepare_timeout: DEFAULT_PREPARE_TIMEOUT,
            disposable,
            timeout: DEFAULT_TIMEOUT,
            max_turns: DEFAULT_MAX_TURNS,
            max_budget_usd: DEFAULT_MAX_BUDGET_USD,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            report_interval: DEFAULT_REPORT_INTERVAL,
            cancel_grace: DEFAULT_CANCEL_GRACE,
            terminal_report_timeout: DEFAULT_TERMINAL_REPORT_TIMEOUT,
            base_env: std::env::vars_os().collect(),
            env_passthrough: Vec::new(),
            bundle: Bundle::default(),
            jobs_dir: None,
            job_gid: None,
        }
    }
}

/// How an agent run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentOutcome {
    /// The agent exited with status 0. The caller then runs [`AgentRunner::finish`].
    Succeeded,
    /// The server asked to cancel. The group was terminated and a `CANCELLED` report attempted.
    Cancelled,
    /// The server rejected a report as stale, so the lease is gone. The group was killed and
    /// nothing more was sent.
    Lost,
    /// The run failed and a terminal `FAILED` report was attempted.
    Failed {
        /// The exit status, absent when the agent was killed or never started.
        exit_code: Option<i32>,
        /// A fixed description of the failure.
        error: &'static str,
    },
}

/// How the finish step ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FinishOutcome {
    /// A terminal `SUCCEEDED` report was attempted.
    Succeeded {
        /// The pushed branch, absent when the agent made no commits.
        branch: Option<String>,
        /// The pull request url, absent when there is no branch or the job opts out of a PR.
        pr_url: Option<String>,
    },
    /// The push or the pull request failed and a terminal `FAILED` report was attempted.
    Failed {
        /// A fixed description of the failure.
        error: &'static str,
    },
    /// A lease renewal showed the lease gone. The work was dropped and nothing more was sent.
    Lost,
    /// A lease renewal asked to cancel. The work was dropped and a `CANCELLED` report attempted.
    Cancelled,
}

/// Why guarded work stopped before it finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Interrupt {
    /// A renewal was rejected as stale, so the lease is gone.
    Lost,
    /// A renewal carried `cancel_requested`.
    Cancelled,
}

/// Awaits the exit of a spawned agent process.
///
/// Production uses the [`Child`] itself. Tests inject a stand-in to force a wait error.
pub trait ChildWait: Send {
    /// Resolves with the exit status once the process has ended.
    fn wait(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send;
}

impl ChildWait for Child {
    fn wait(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send {
        Self::wait(self)
    }
}

const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const VERSION_BYTES: u64 = 1024;
const VERSION_CHARS: usize = 64;

/// The value of a [`VersionStamp`] field that is not known.
pub const UNKNOWN_STAMP: &str = "unknown";

/// What produced a job: the config bundle, the `claude` build and the model.
///
/// A field that is not known holds [`UNKNOWN_STAMP`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionStamp {
    /// Hex SHA-256 of the agent config bundle, see [`Bundle::sha256`].
    pub bundle_sha: String,
    /// The `claude` version string.
    pub claude_version: String,
    /// The model name.
    pub model: String,
}

impl VersionStamp {
    /// This stamp with the model the agent reported, or [`UNKNOWN_STAMP`] when it reported none.
    #[must_use]
    pub fn with_model(mut self, model: Option<&str>) -> Self {
        if let Some(model) = model {
            model.clone_into(&mut self.model);
        }
        self
    }
}

impl Default for VersionStamp {
    fn default() -> Self {
        Self {
            bundle_sha: UNKNOWN_STAMP.to_owned(),
            claude_version: UNKNOWN_STAMP.to_owned(),
            model: UNKNOWN_STAMP.to_owned(),
        }
    }
}

/// Everything a launcher needs to start the agent: the command line, the full environment
/// block and the working directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentSpec {
    /// The program followed by its arguments.
    pub argv: Vec<OsString>,
    /// The complete environment. Nothing else is inherited.
    pub env: BTreeMap<OsString, OsString>,
    /// The agent's working directory.
    pub cwd: PathBuf,
    /// The version stamp every job carries.
    pub stamp: VersionStamp,
}

/// A running agent process behind a [`Launcher`].
///
/// The runner awaits [`AgentProc::wait`] and sends [`AgentProc::terminate`] on a cancel and
/// [`AgentProc::kill`] to end the run. Both are synchronous so the read loop never awaits
/// them. Dropping the value must kill everything the agent started.
pub trait AgentProc: Send {
    /// Resolves with the exit status once the process has ended.
    fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + '_>>;

    /// Asks the agent and its descendants to stop, as `SIGTERM` to the process group does.
    fn terminate(&mut self);

    /// Ends the agent and its descendants at once. Safe to call more than once.
    fn kill(&mut self);

    /// Whether the process ended by a signal after the run deadline the launcher was given.
    /// A launcher whose sandbox enforces its own timeout reports it here; the default is no.
    fn timed_out(&self) -> bool {
        false
    }
}

/// A started agent: its stdout and the handle that ends it.
pub struct Launched {
    /// The agent's stdout, read line by line.
    pub stdout: Box<dyn AsyncRead + Send + Unpin>,
    /// The process handle.
    pub proc: Box<dyn AgentProc>,
}

/// Starts the agent for [`AgentRunner`]. The seam lets a different sandbox replace the
/// direct spawn.
///
/// [`DirectLauncher`] puts the agent in its own process group, so a signal reaches every
/// descendant. Another launcher must give `terminate` and `kill` the same reach, for example
/// the whole cgroup of a unit.
pub trait Launcher: Send + Sync + std::fmt::Debug {
    /// Starts the agent described by `spec`.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the agent cannot be started.
    fn launch(&self, spec: AgentSpec) -> io::Result<Launched>;
}

/// Spawns the agent as a child in its own process group, killed with the group on drop.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectLauncher;

impl Launcher for DirectLauncher {
    fn launch(&self, spec: AgentSpec) -> io::Result<Launched> {
        spawn_direct(&spec, |child| child)
    }
}

struct Grouped<W> {
    inner: W,
    guard: GroupGuard,
}

impl<W: ChildWait> AgentProc for Grouped<W> {
    fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + '_>> {
        Box::pin(self.inner.wait())
    }

    fn terminate(&mut self) {
        self.guard.terminate();
    }

    fn kill(&mut self) {
        self.guard.kill();
    }
}

fn spawn_direct<W: ChildWait + 'static>(
    spec: &AgentSpec,
    wrap: impl FnOnce(Child) -> W,
) -> io::Result<Launched> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty agent argv"))?;
    let mut child = Command::new(program)
        .args(args)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let guard = GroupGuard::new(child.id());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("agent stdout missing"))?;
    Ok(Launched {
        stdout: Box::new(stdout),
        proc: Box::new(Grouped {
            inner: wrap(child),
            guard,
        }),
    })
}

/// Runs the agent for claimed jobs.
#[derive(Debug)]
pub struct AgentRunner<R> {
    config: RunConfig,
    launcher: Arc<dyn Launcher>,
    reporter: R,
    redactor: Redactor,
    carries: Mutex<HashMap<String, Carry>>,
    hub: Option<Arc<HookHub>>,
    claude_version: Mutex<Option<String>>,
}

#[derive(Debug, Default)]
struct Carry {
    next_seq: u64,
    progress: String,
    pending: VecDeque<TranscriptChunk>,
    pending_bytes: usize,
    feed: Option<Feed>,
}

impl<R: Reporter> AgentRunner<R> {
    /// A runner that reports through `reporter` and redacts with `redactor`.
    pub fn new(config: RunConfig, reporter: R, redactor: Redactor) -> Self {
        Self {
            config,
            launcher: Arc::new(DirectLauncher),
            reporter,
            redactor,
            carries: Mutex::new(HashMap::new()),
            hub: None,
            claude_version: Mutex::new(None),
        }
    }

    /// Starts agents through `launcher` instead of [`DirectLauncher`].
    #[must_use]
    pub fn with_launcher(mut self, launcher: Arc<dyn Launcher>) -> Self {
        self.launcher = launcher;
        self
    }

    /// Takes tool hook reports for running jobs from `hub`.
    ///
    /// A job registers its id in the hub while its agent runs. Each report fills the exit code
    /// and duration of the matching tool event, and the summary counts it once per tool use id.
    #[must_use]
    pub fn with_hook_hub(mut self, hub: Arc<HookHub>) -> Self {
        self.hub = Some(hub);
        self
    }

    fn carry_key(job: &Job) -> String {
        format!("{}#{}", job.job_id, job.attempt)
    }

    fn stash(&self, job: &Job, carry: Carry) {
        self.carries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(Self::carry_key(job), carry);
    }

    fn resume<'a>(&'a self, job: &'a Job) -> Stream<'a, R> {
        let carry = self
            .carries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&Self::carry_key(job))
            .unwrap_or_default();
        Stream::new(
            &self.reporter,
            job,
            self.config.terminal_report_timeout,
            carry,
            self.hub.clone(),
        )
    }

    /// The longest time the caller should let the workspace step run.
    #[must_use]
    pub const fn prepare_timeout(&self) -> Duration {
        self.config.prepare_timeout
    }

    /// Runs `work` and renews the job lease while it runs.
    ///
    /// An empty `ReportJob` goes out every [`RunConfig::report_interval`] until `work`
    /// completes. A `FAILED_PRECONDITION` reply drops `work` and gives
    /// [`Interrupt::Lost`], a reply with `cancel_requested` gives [`Interrupt::Cancelled`].
    /// Other report errors are ignored: the terminal report decides the outcome.
    ///
    /// # Errors
    ///
    /// Returns the [`Interrupt`] that stopped `work`.
    pub async fn keep_alive<T>(
        &self,
        job: &Job,
        work: impl Future<Output = T>,
    ) -> Result<T, Interrupt> {
        self.alive(job, "", work).await
    }

    async fn alive<T>(
        &self,
        job: &Job,
        progress: &str,
        work: impl Future<Output = T>,
    ) -> Result<T, Interrupt> {
        tokio::select! {
            out = work => Ok(out),
            stop = self.renew(job, progress) => Err(stop),
        }
    }

    async fn renew(&self, job: &Job, progress: &str) -> Interrupt {
        loop {
            tokio::time::sleep(self.config.report_interval).await;
            match self
                .reporter
                .report(report_request(job, progress, Vec::new()))
                .await
            {
                Err(status) if status.code() == Code::FailedPrecondition => {
                    tracing::warn!("job lease lost");
                    return Interrupt::Lost;
                }
                Ok(reply) if reply.cancel_requested => return Interrupt::Cancelled,
                _ => {}
            }
        }
    }

    /// Sends a terminal `CANCELLED` report, for a job cancelled before the agent started.
    /// The report waits at most [`RunConfig::terminal_report_timeout`].
    pub async fn cancel_job(&self, job: &Job) {
        let mut stream = self.resume(job);
        stream.cancelled().await;
    }

    /// Runs `claude -p <prompt> --output-format stream-json --verbose` in `cwd`.
    ///
    /// The child gets no stdin, its own process group, `FLEET_JOB_ID` and `SWARM_BOX=1`.
    /// It gets `--dangerously-skip-permissions` only when the config marks the box
    /// disposable. Exit 0 is [`AgentOutcome::Succeeded`]. A nonzero exit, a signal, a
    /// start failure or the timeout sends a terminal `FAILED` report and returns
    /// [`AgentOutcome::Failed`]. A report reply with `cancel_requested` gives
    /// [`AgentOutcome::Cancelled`] after `SIGTERM`, the cancel grace and `SIGKILL`. A
    /// `FAILED_PRECONDITION` reply gives [`AgentOutcome::Lost`]. The whole process group is
    /// killed on every exit path, so no background descendant outlives the run. Every report
    /// is raced against the deadline and shutdown, and the terminal report waits at most
    /// [`RunConfig::terminal_report_timeout`], so a hung server never delays the kill.
    ///
    /// # Errors
    ///
    /// Returns [`RunError`] when `shutdown` fires or the child cannot be awaited. The
    /// process group is killed and a best-effort terminal `FAILED` report is sent first.
    pub async fn run(
        &self,
        job: &Job,
        cwd: &Path,
        shutdown: Shutdown,
    ) -> Result<AgentOutcome, RunError> {
        self.run_launched(job, cwd, shutdown, |spec| self.launcher.launch(spec))
            .await
    }

    /// Like [`Self::run`], but `wrap` turns the spawned child into the value the runner
    /// awaits for its exit.
    ///
    /// # Errors
    ///
    /// Same as [`Self::run`].
    pub async fn run_with<W: ChildWait + 'static>(
        &self,
        job: &Job,
        cwd: &Path,
        shutdown: Shutdown,
        wrap: impl FnOnce(Child) -> W + Send,
    ) -> Result<AgentOutcome, RunError> {
        self.run_launched(job, cwd, shutdown, move |spec| spawn_direct(&spec, wrap))
            .await
    }

    async fn run_launched(
        &self,
        job: &Job,
        cwd: &Path,
        shutdown: Shutdown,
        launch: impl FnOnce(AgentSpec) -> io::Result<Launched> + Send,
    ) -> Result<AgentOutcome, RunError> {
        let mut stream = Stream::new(
            &self.reporter,
            job,
            self.config.terminal_report_timeout,
            Carry::default(),
            self.hub.clone(),
        );
        let result = self
            .run_stream(job, cwd, shutdown, &mut stream, launch)
            .await;
        if matches!(result, Ok(AgentOutcome::Succeeded)) {
            self.stash(job, stream.carry());
        }
        result
    }

    async fn run_stream(
        &self,
        job: &Job,
        cwd: &Path,
        shutdown: Shutdown,
        stream: &mut Stream<'_, R>,
        launch: impl FnOnce(AgentSpec) -> io::Result<Launched> + Send,
    ) -> Result<AgentOutcome, RunError> {
        let root = self
            .config
            .jobs_dir
            .as_deref()
            .or_else(|| cwd.parent())
            .unwrap_or(cwd);
        let job_dir = match JobDir::create_shared(
            root,
            &job.job_id,
            &self.config.bundle,
            self.config.job_gid,
        ) {
            Ok(dir) => dir,
            Err(err) => {
                tracing::warn!(kind = ?err.kind(), "agent config dir could not be created");
                return Ok(stream.fail(None, ERR_START).await);
            }
        };
        let mut spec = self.agent_spec(job, cwd, &job_dir.home());
        if let Some(version) = self.claude_version(cwd, &job_dir.home()).await {
            spec.stamp.claude_version = version;
        }
        let Launched { stdout, mut proc } = match launch(spec) {
            Ok(launched) => launched,
            Err(err) => {
                tracing::warn!(
                    program = %self.config.claude_bin.display(),
                    kind = ?err.kind(),
                    "agent could not be spawned"
                );
                return Ok(stream.fail(None, ERR_START).await);
            }
        };
        let mut ctl = Ctl {
            deadline: Box::pin(tokio::time::sleep(self.config.timeout)),
            shutdown,
        };
        let end = self.drive(proc.as_mut(), stdout, stream, &mut ctl).await;
        if matches!(end, Err(End::Cancel)) {
            proc.terminate();
            let _ = tokio::time::timeout(self.config.cancel_grace, proc.wait()).await;
        }
        proc.kill();
        let _ = proc.wait().await;
        match end {
            Ok(status) => {
                if let Some(error) = stream.feed.result_subtype().and_then(cap_error) {
                    return Ok(stream.fail(status.code(), error).await);
                }
                match status.code() {
                    Some(0) => Ok(AgentOutcome::Succeeded),
                    Some(code) => Ok(stream.fail(Some(code), ERR_EXIT).await),
                    None if proc.timed_out() => Ok(stream.fail(None, ERR_TIMEOUT).await),
                    None => Ok(stream.fail(None, ERR_SIGNAL).await),
                }
            }
            Err(End::Timeout) => Ok(stream.fail(None, ERR_TIMEOUT).await),
            Err(End::Cancel) => {
                stream.cancelled().await;
                Ok(AgentOutcome::Cancelled)
            }
            Err(End::Lost) => Ok(AgentOutcome::Lost),
            Err(End::Shutdown) => {
                stream.fail(None, ERR_SHUTDOWN).await;
                Err(RunError)
            }
            Err(End::Wait) => {
                stream.fail(None, ERR_WAIT).await;
                Err(RunError)
            }
        }
    }

    /// Publishes the agent's work and sends the terminal report.
    ///
    /// Commits on `swarm/<job_id>` beyond `origin/<base_ref>` are pushed to the job's repo
    /// url. None gives a `SUCCEEDED` report with no branch and no pull request. Otherwise,
    /// unless the job has `open_pr` off, `gh pr create` runs and the last stdout line that
    /// is an `https` url becomes `pr_url`.
    ///
    /// No credentialed command runs in the agent's repo. A throwaway bare repo under the
    /// jobs directory fetches the branch from the worktree with no tokens in the
    /// environment. The push (`--no-verify`, no hooks path, no stored credential helper, no
    /// global or system git config) and `gh` run from that repo with an allowlisted
    /// environment, a scratch `HOME` and scratch config dirs. The push holds only
    /// `GIT_ASKPASS` (`fleetd askpass`) and the `GH_TOKEN` it prints, and `gh` only its own
    /// token, so config the agent planted cannot capture a token. The push allows `https`
    /// remotes on the policy hosts only, and the helper answers only for those hosts. A
    /// failure sends a `FAILED` report with a fixed error and the redacted, bounded tail of
    /// the helper's stderr as one transcript chunk. The raw output goes nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`RunError`] when `shutdown` fires. A best-effort `FAILED` report is sent
    /// first and the helper's process group is killed.
    pub async fn finish(
        &self,
        job: &Job,
        cwd: &Path,
        shutdown: Shutdown,
    ) -> Result<FinishOutcome, RunError> {
        let mut stream = self.resume(job);
        let mut ctl = Ctl {
            deadline: Box::pin(tokio::time::sleep(self.config.finish_timeout)),
            shutdown,
        };
        let progress = stream.progress.clone();
        match ctl
            .race(self.alive(job, &progress, self.publish(job, cwd)))
            .await
        {
            Ok(Err(Interrupt::Lost)) => Ok(FinishOutcome::Lost),
            Ok(Err(Interrupt::Cancelled)) => {
                stream.cancelled().await;
                Ok(FinishOutcome::Cancelled)
            }
            Ok(Ok(Ok(published))) => {
                if published.branch.is_none() {
                    tracing::info!("job ended with no changes");
                    stream.push(&self.redactor, NO_CHANGES_NOTE);
                }
                stream
                    .terminal(Terminal {
                        state: JobState::Succeeded,
                        exit_code: Some(0),
                        error: None,
                        branch: published.branch.clone(),
                        pr_url: published.pr_url.clone(),
                    })
                    .await;
                Ok(FinishOutcome::Succeeded {
                    branch: published.branch,
                    pr_url: published.pr_url,
                })
            }
            Ok(Ok(Err(failure))) => {
                tracing::warn!(
                    error = failure.error,
                    stderr_tail = %self.log_tail(&failure.tail),
                    "job publish step failed"
                );
                for line in failure.tail.lines() {
                    stream.push(&self.redactor, line);
                }
                stream.fail(None, failure.error).await;
                Ok(FinishOutcome::Failed {
                    error: failure.error,
                })
            }
            Err(Stop::Timeout) => {
                stream.fail(None, ERR_FINISH_TIMEOUT).await;
                Ok(FinishOutcome::Failed {
                    error: ERR_FINISH_TIMEOUT,
                })
            }
            Err(Stop::Shutdown) => {
                stream.fail(None, ERR_SHUTDOWN).await;
                Err(RunError)
            }
        }
    }

    /// Sends a terminal `FAILED` report with a fixed `error`, for a job that failed before
    /// the agent started. The report waits at most [`RunConfig::terminal_report_timeout`].
    pub async fn fail_job(&self, job: &Job, error: &'static str) {
        let mut stream = self.resume(job);
        stream.fail(None, error).await;
    }

    async fn publish(&self, job: &Job, cwd: &Path) -> Result<Published, Failure> {
        validate_job_id(&job.job_id).map_err(|_| Failure::bare(ERR_COMMITS))?;
        validate_repo(&job.repo, &self.config.repo_policy).map_err(|_| Failure::bare(ERR_PUSH))?;
        validate_ref(&job.base_ref).map_err(|_| Failure::bare(ERR_COMMITS))?;
        let branch = format!("swarm/{}", job.job_id);
        let scratch = Scratch::create(cwd, &job.job_id).map_err(|()| Failure::bare(ERR_COMMITS))?;
        let dir = scratch.path();
        self.commit_leftovers(job, cwd, dir).await?;
        if !self.ahead(job, &branch, cwd, dir).await? {
            return Ok(Published {
                branch: None,
                pr_url: None,
            });
        }
        let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
        let pushed = self
            .helper(
                &self.config.git_bin,
                dir,
                &[
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "credential.helper=",
                    "push",
                    "--quiet",
                    "--no-verify",
                    "--",
                    &job.repo,
                    &refspec,
                ],
                Scope::Push,
            )
            .await
            .map_err(|e| e.failure(ERR_PUSH))?;
        if !pushed.success {
            return Err(Failure::tail(ERR_PUSH, &pushed.stderr));
        }
        if !job.open_pr {
            return Ok(Published {
                branch: Some(branch),
                pr_url: None,
            });
        }
        let pr_url = self.open_pr(job, &branch, dir).await?;
        Ok(Published {
            branch: Some(branch),
            pr_url: Some(pr_url),
        })
    }

    fn log_tail(&self, stderr: &str) -> String {
        let redacted = self.redactor.redact_str(stderr);
        let mut start = redacted.len().saturating_sub(LOG_TAIL_BYTES);
        while !redacted.is_char_boundary(start) {
            start += 1;
        }
        redacted.get(start..).unwrap_or_default().to_owned()
    }

    async fn commit_leftovers(&self, job: &Job, cwd: &Path, dir: &Path) -> Result<(), Failure> {
        let tree = Scope::Tree(cwd);
        let listed = self
            .helper(
                &self.config.git_bin,
                dir,
                &["config", "--list", "--name-only"],
                tree,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !listed.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        let mut guards: Vec<String> = FALLBACK_GUARDS.map(str::to_owned).to_vec();
        for name in filter_drivers(&listed.stdout).ok_or_else(|| Failure::bare(ERR_COMMITS))? {
            for (key, value) in [
                ("clean", ""),
                ("smudge", ""),
                ("process", ""),
                ("required", "false"),
            ] {
                guards.push("-c".to_owned());
                guards.push(format!("filter.{name}.{key}={value}"));
            }
        }
        let status = self
            .guarded(
                dir,
                &guards,
                tree,
                &["status", "--porcelain"],
                CAPTURE_BYTES,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !status.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        if status.stdout.trim().is_empty() {
            return Ok(());
        }
        let added = self
            .guarded(dir, &guards, tree, &["add", "-A"], CAPTURE_BYTES)
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !added.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        let staged = self
            .guarded(
                dir,
                &guards,
                tree,
                &[
                    "diff",
                    "--cached",
                    "--text",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-color",
                ],
                MAX_DIFF_BYTES,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !staged.success || staged.truncated {
            return Err(Failure::bare(ERR_COMMITS));
        }
        if matches!(self.redactor.redact_str(&staged.stdout), Cow::Owned(_)) {
            return Err(Failure::bare(ERR_SECRET));
        }
        if staged.stdout.is_empty() {
            return Ok(());
        }
        let message = format!("chore: uncommitted job changes (fleet job {})", job.job_id);
        let committed = self
            .guarded(
                dir,
                &guards,
                tree,
                &[
                    "commit",
                    "--quiet",
                    "--no-verify",
                    "--no-gpg-sign",
                    "-m",
                    &message,
                ],
                CAPTURE_BYTES,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if committed.success {
            Ok(())
        } else {
            Err(Failure::bare(ERR_COMMITS))
        }
    }

    async fn guarded(
        &self,
        dir: &Path,
        guards: &[String],
        tree: Scope<'_>,
        rest: &[&str],
        limit: u64,
    ) -> Result<Captured, CaptureError> {
        let mut args: Vec<&str> = guards.iter().map(String::as_str).collect();
        args.extend_from_slice(rest);
        self.helper_limited(&self.config.git_bin, dir, &args, tree, limit)
            .await
    }

    async fn ahead(
        &self,
        job: &Job,
        branch: &str,
        cwd: &Path,
        dir: &Path,
    ) -> Result<bool, Failure> {
        self.helper(
            &self.config.git_bin,
            dir,
            &["init", "--bare", "--quiet"],
            Scope::Clean,
        )
        .await
        .map_err(|e| e.failure(ERR_COMMITS))?;
        let worktree = cwd.to_str().ok_or_else(|| Failure::bare(ERR_COMMITS))?;
        let head = format!("+refs/heads/{branch}:refs/heads/{branch}");
        let base = format!(
            "+refs/remotes/origin/{base}:refs/remotes/origin/{base}",
            base = job.base_ref
        );
        let fetched = self
            .helper(
                &self.config.git_bin,
                dir,
                &[
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=",
                    "-c",
                    "core.sshCommand=",
                    "-c",
                    "credential.helper=",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--",
                    worktree,
                    &head,
                    &base,
                ],
                Scope::Clean,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !fetched.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        let range = format!("refs/remotes/origin/{}..refs/heads/{branch}", job.base_ref);
        let counted = self
            .helper(
                &self.config.git_bin,
                dir,
                &["rev-list", "--count", &range],
                Scope::Clean,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        let count = counted.stdout.trim();
        if !counted.success || count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::bare(ERR_COMMITS));
        }
        Ok(!count.bytes().all(|b| b == b'0'))
    }

    async fn open_pr(&self, job: &Job, branch: &str, dir: &Path) -> Result<String, Failure> {
        let subject = self
            .helper(
                &self.config.git_bin,
                dir,
                &["log", "-1", "--format=%s", &format!("refs/heads/{branch}")],
                Scope::Clean,
            )
            .await
            .map_err(|e| e.failure(ERR_PR))?;
        let title: String = match subject.stdout.trim() {
            "" => branch,
            line => line,
        }
        .chars()
        .take(MAX_TITLE_CHARS)
        .collect();
        let created = self
            .helper(
                &self.config.gh_bin,
                dir,
                &[
                    "pr",
                    "create",
                    "--repo",
                    &job.repo,
                    "--head",
                    branch,
                    "--base",
                    &job.base_ref,
                    "--title",
                    &title,
                    "--body",
                    &format!("Fleet job {}", job.job_id),
                ],
                Scope::Gh,
            )
            .await
            .map_err(|e| e.failure(ERR_PR))?;
        if !created.success {
            return Err(Failure::tail(ERR_PR, &created.stderr));
        }
        pr_url(&created.stdout).ok_or_else(|| Failure::bare(ERR_PR_URL))
    }

    async fn helper(
        &self,
        bin: &Path,
        dir: &Path,
        args: &[&str],
        scope: Scope<'_>,
    ) -> Result<Captured, CaptureError> {
        self.helper_limited(bin, dir, args, scope, CAPTURE_BYTES)
            .await
    }

    async fn helper_limited(
        &self,
        bin: &Path,
        dir: &Path,
        args: &[&str],
        scope: Scope<'_>,
        limit: u64,
    ) -> Result<Captured, CaptureError> {
        let home = dir.join(HOME_DIR);
        let mut command = Command::new(bin);
        command
            .current_dir(dir)
            .args(args)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_DATA_HOME", home.join(".local"))
            .env("XDG_STATE_HOME", home.join(".state"))
            .env("GIT_DIR", dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GH_PROMPT_DISABLED", "1");
        let allowed: &[&str] = match scope {
            Scope::Clean | Scope::Tree(_) => &CLEAN_ENV,
            Scope::Push => &PUSH_ENV,
            Scope::Gh => &GH_ENV,
        };
        let kept = |name: &OsString| allowed.iter().any(|keep| name == keep);
        command.envs(
            self.config
                .base_env
                .iter()
                .filter(|(name, _)| kept(name))
                .map(|(name, value)| (name, value)),
        );
        match scope {
            Scope::Clean | Scope::Tree(_) => command.env("GIT_ALLOW_PROTOCOL", "file"),
            Scope::Push => command
                .env("GIT_ALLOW_PROTOCOL", self.config.repo_policy.protocols())
                .envs(askpass::env(&self.config.askpass_bin))
                .env(
                    askpass::HOST_ENV,
                    self.config.repo_policy.token_host().unwrap_or_default(),
                ),
            Scope::Gh => command
                .env("GH_CONFIG_DIR", dir.join(GH_CONFIG_DIR))
                .env("GH_NO_UPDATE_NOTIFIER", "1")
                .env("GH_BROWSER", "true")
                .env("GH_EDITOR", "true")
                .env("GH_PAGER", "cat")
                .env("PAGER", "cat"),
        };
        if let Scope::Tree(work) = scope {
            command
                .current_dir(work)
                .env_remove("GIT_DIR")
                .env("GIT_AUTHOR_NAME", JOB_NAME)
                .env("GIT_AUTHOR_EMAIL", JOB_EMAIL)
                .env("GIT_COMMITTER_NAME", JOB_NAME)
                .env("GIT_COMMITTER_EMAIL", JOB_EMAIL);
        }
        capture(command, self.config.finish_timeout, limit).await
    }

    async fn drive(
        &self,
        child: &mut dyn AgentProc,
        stdout: Box<dyn AsyncRead + Send + Unpin>,
        stream: &mut Stream<'_, R>,
        ctl: &mut Ctl,
    ) -> Result<ExitStatus, End> {
        let mut lines = LineReader::new(BufReader::new(stdout), MAX_CHUNK_BYTES);
        let mut open = true;
        let mut status = None;
        let mut drain: Option<Pin<Box<Sleep>>> = None;
        let mut tick = tokio::time::interval_at(
            Instant::now() + self.config.flush_interval,
            self.config.flush_interval,
        );
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let status = loop {
            if !open && let Some(done) = status.take() {
                break done;
            }
            tokio::select! {
                read = lines.next_line(), if open => {
                    if !lines.line.is_empty() {
                        let line = lines.line.strip_suffix(b"\n").unwrap_or(&lines.line);
                        let line = line.strip_suffix(b"\r").unwrap_or(line);
                        stream.push(&self.redactor, &String::from_utf8_lossy(line));
                        lines.line.clear();
                    }
                    if !matches!(read, Ok(true)) {
                        open = false;
                    } else if stream.pending_bytes >= FLUSH_BYTES && !stream.failing {
                        stream.start();
                    }
                }
                waited = child.wait(), if status.is_none() => {
                    child.kill();
                    status = Some(waited);
                    drain = Some(Box::pin(tokio::time::sleep(STDOUT_DRAIN)));
                }
                () = drain_expired(&mut drain) => open = false,
                reply = stream.reply(), if stream.in_flight() => stream.settle(reply)?,
                _ = tick.tick() => stream.beat(self.config.report_interval),
                () = &mut ctl.deadline => return Err(End::Timeout),
                () = ctl.shutdown.requested() => return Err(End::Shutdown),
            }
        };
        let status = status.map_err(|_| End::Wait)?;
        stream.flush(ctl).await?;
        Ok(status)
    }

    fn agent_env_kept(&self, name: &OsString) -> bool {
        let Some(name) = name.to_str() else {
            return false;
        };
        !env_forbidden(name)
            && (AGENT_ENV.contains(&name)
                || name.starts_with(AGENT_ENV_PREFIX)
                || self
                    .config
                    .env_passthrough
                    .iter()
                    .any(|extra| extra == name))
    }

    async fn claude_version(&self, cwd: &Path, home: &Path) -> Option<String> {
        let cached = self
            .claude_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if cached.is_some() {
            return cached;
        }
        let mut command = Command::new(&self.config.claude_bin);
        command
            .arg("--version")
            .current_dir(cwd)
            .env_clear()
            .env("HOME", home)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("DISABLE_AUTOUPDATER", "1");
        command.envs(
            self.config
                .base_env
                .iter()
                .filter(|(name, _)| name == "PATH")
                .map(|(name, value)| (name, value)),
        );
        let output = capture(command, VERSION_TIMEOUT, VERSION_BYTES)
            .await
            .ok()?;
        let version = parse_version(&output.stdout).filter(|_| output.success)?;
        *self
            .claude_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(version.clone());
        Some(version)
    }

    /// The command line, environment and working directory for `job`'s agent.
    ///
    /// The environment is the allowlisted part of [`RunConfig::base_env`] plus the per-job
    /// values, with `home` as `HOME` and `home/.claude` as `CLAUDE_CONFIG_DIR`.
    pub fn agent_spec(&self, job: &Job, cwd: &Path, home: &Path) -> AgentSpec {
        let turns = self.config.max_turns.to_string();
        let budget = self.config.max_budget_usd.to_string();
        let mut argv: Vec<OsString> = vec![self.config.claude_bin.clone().into_os_string()];
        argv.extend(
            [
                "-p",
                job.prompt.as_str(),
                "--output-format",
                "stream-json",
                "--verbose",
                "--setting-sources",
                "user",
                "--append-system-prompt",
                AGENT_PROTOCOL,
                "--max-turns",
                turns.as_str(),
                "--max-budget-usd",
                budget.as_str(),
            ]
            .map(OsString::from),
        );
        if self.config.disposable {
            argv.push("--dangerously-skip-permissions".into());
        } else {
            argv.extend(["--permission-mode", "dontAsk"].map(OsString::from));
        }
        argv.push("--disallowedTools".into());
        argv.extend(DENIED_TOOLS.map(OsString::from));
        let mut env: BTreeMap<OsString, OsString> = self
            .config
            .base_env
            .iter()
            .filter(|(name, _)| self.agent_env_kept(name))
            .cloned()
            .collect();
        let fixed: [(&str, OsString); 15] = [
            ("FLEET_JOB_ID", job.job_id.clone().into()),
            ("SWARM_BOX", "1".into()),
            ("HOME", home.into()),
            ("CLAUDE_CONFIG_DIR", home.join(".claude").into()),
            ("XDG_CONFIG_HOME", home.join(".config").into()),
            ("XDG_CACHE_HOME", home.join(".cache").into()),
            ("XDG_STATE_HOME", home.join(".local").join("state").into()),
            ("XDG_DATA_HOME", home.join(".local").join("share").into()),
            ("DISABLE_AUTOUPDATER", "1".into()),
            ("GIT_CONFIG_GLOBAL", home.join(".gitconfig").into()),
            ("GIT_TERMINAL_PROMPT", "0".into()),
            ("GIT_AUTHOR_NAME", JOB_NAME.into()),
            ("GIT_AUTHOR_EMAIL", JOB_EMAIL.into()),
            ("GIT_COMMITTER_NAME", JOB_NAME.into()),
            ("GIT_COMMITTER_EMAIL", JOB_EMAIL.into()),
        ];
        env.extend(fixed.map(|(name, value)| (OsString::from(name), value)));
        AgentSpec {
            argv,
            env,
            cwd: cwd.to_path_buf(),
            stamp: VersionStamp {
                bundle_sha: self.config.bundle.sha256(),
                ..VersionStamp::default()
            },
        }
    }
}

fn parse_version(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?.trim();
    if !crate::telemetry::is_plain_text(line) {
        return None;
    }
    Some(line.chars().take(VERSION_CHARS).collect())
}

struct LineReader<R> {
    reader: R,
    line: Vec<u8>,
    max: usize,
    skipping: bool,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    fn new(reader: R, max: usize) -> Self {
        Self {
            reader,
            line: Vec::new(),
            max,
            skipping: false,
        }
    }

    async fn next_line(&mut self) -> io::Result<bool> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(false);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let used = newline.map_or(available.len(), |at| at + 1);
            if !self.skipping {
                let room = self.max.saturating_sub(self.line.len());
                self.line.extend(available.iter().take(used.min(room)));
                self.skipping = used > room;
            }
            self.reader.consume(used);
            if newline.is_some() {
                self.skipping = false;
                return Ok(true);
            }
        }
    }
}

async fn drain_expired(drain: &mut Option<Pin<Box<Sleep>>>) {
    match drain {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending().await,
    }
}

enum End {
    Timeout,
    Shutdown,
    Wait,
    Cancel,
    Lost,
}

impl From<Stop> for End {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::Timeout => Self::Timeout,
            Stop::Shutdown => Self::Shutdown,
        }
    }
}

enum Stop {
    Timeout,
    Shutdown,
}

struct Ctl {
    deadline: Pin<Box<Sleep>>,
    shutdown: Shutdown,
}

impl Ctl {
    async fn race<T>(&mut self, work: impl Future<Output = T>) -> Result<T, Stop> {
        tokio::select! {
            value = work => Ok(value),
            () = &mut self.deadline => Err(Stop::Timeout),
            () = self.shutdown.requested() => Err(Stop::Shutdown),
        }
    }
}

type ReportFuture<'a> = Pin<Box<dyn Future<Output = Result<ReportJobReply, Status>> + Send + 'a>>;

struct InFlight<'a> {
    upto: u64,
    events_upto: Option<u32>,
    future: ReportFuture<'a>,
}

struct Reply {
    upto: u64,
    events_upto: Option<u32>,
    result: Result<ReportJobReply, Status>,
}

struct Stream<'a, R> {
    reporter: &'a R,
    job: &'a Job,
    pending: VecDeque<TranscriptChunk>,
    pending_bytes: usize,
    feed: Feed,
    in_flight: Option<InFlight<'a>>,
    next_seq: u64,
    progress: String,
    last_report: Instant,
    terminal_timeout: Duration,
    cancel: bool,
    lost: bool,
    failing: bool,
    hub: Option<Arc<HookHub>>,
}

impl<R> Drop for Stream<'_, R> {
    fn drop(&mut self) {
        if let Some(hub) = &self.hub {
            hub.unregister(&self.job.job_id);
        }
    }
}

impl<'a, R: Reporter> Stream<'a, R> {
    fn new(
        reporter: &'a R,
        job: &'a Job,
        terminal_timeout: Duration,
        carry: Carry,
        hub: Option<Arc<HookHub>>,
    ) -> Self {
        if let Some(hub) = &hub {
            hub.register(&job.job_id);
        }
        Self {
            reporter,
            job,
            pending: carry.pending,
            pending_bytes: carry.pending_bytes,
            feed: carry.feed.unwrap_or_else(|| Feed::new(Instant::now())),
            in_flight: None,
            next_seq: carry.next_seq.max(1),
            progress: carry.progress,
            last_report: Instant::now(),
            terminal_timeout,
            cancel: false,
            lost: false,
            failing: false,
            hub,
        }
    }

    fn pull_hooks(&mut self) {
        let Some(hub) = &self.hub else { return };
        for report in hub.drain(&self.job.job_id) {
            self.feed.hook(report);
        }
    }

    fn carry(&mut self) -> Carry {
        Carry {
            next_seq: self.next_seq,
            progress: self.progress.clone(),
            pending: std::mem::take(&mut self.pending),
            pending_bytes: std::mem::take(&mut self.pending_bytes),
            feed: Some(std::mem::replace(&mut self.feed, Feed::new(Instant::now()))),
        }
    }

    fn push(&mut self, redactor: &Redactor, line: &str) {
        if self.lost {
            return;
        }
        let clean = redactor.redact_str(line);
        self.feed.line(redactor, &clean, Instant::now());
        self.pull_hooks();
        if let Some(text) = assistant_text(&clean) {
            self.progress = text.chars().take(MAX_PROGRESS_CHARS).collect();
        }
        let mut text = clean.into_owned();
        text.push('\n');
        let truncated = cut(&mut text, MAX_CHUNK_BYTES);
        self.pending_bytes += text.len();
        self.pending.push_back(TranscriptChunk {
            seq: self.next_seq,
            ts_ms: now_ms(),
            text,
            truncated,
        });
        self.next_seq += 1;
        while self.pending_bytes > MAX_BUFFER_BYTES {
            match self.pending.pop_front() {
                Some(dropped) => self.pending_bytes -= dropped.text.len(),
                None => break,
            }
        }
    }

    fn beat(&mut self, report_interval: Duration) {
        self.pull_hooks();
        if !self.pending.is_empty()
            || !self.feed.backlog_empty()
            || self.last_report.elapsed() >= report_interval
        {
            self.start();
        }
    }

    fn drained(&self) -> bool {
        self.pending.is_empty() && self.feed.backlog_empty()
    }

    fn in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    fn start(&mut self) {
        if self.in_flight.is_some() || self.lost {
            return;
        }
        let count = self.batch_len();
        let chunks: Vec<_> = self.pending.iter().take(count).cloned().collect();
        let upto = chunks.last().map_or(0, |chunk| chunk.seq);
        let events = self.feed.batch();
        let events_upto = events.last().map(|event| event.seq);
        let mut request = self.request(chunks);
        request.events = events;
        self.in_flight = Some(InFlight {
            upto,
            events_upto,
            future: Box::pin(self.reporter.report(request)),
        });
    }

    async fn reply(&mut self) -> Reply {
        let Some(flying) = self.in_flight.as_mut() else {
            return std::future::pending().await;
        };
        let result = flying.future.as_mut().await;
        let upto = flying.upto;
        let events_upto = flying.events_upto;
        self.in_flight = None;
        Reply {
            upto,
            events_upto,
            result,
        }
    }

    fn settle(&mut self, reply: Reply) -> Result<(), End> {
        match reply.result {
            Ok(reply_ok) => {
                self.cancel |= reply_ok.cancel_requested;
                while self.pending.front().is_some_and(|c| c.seq <= reply.upto) {
                    if let Some(sent) = self.pending.pop_front() {
                        self.pending_bytes -= sent.text.len();
                    }
                }
                if let Some(upto) = reply.events_upto {
                    self.feed.ack(upto);
                }
                self.last_report = Instant::now();
                self.failing = false;
            }
            Err(status) if status.code() == Code::FailedPrecondition => {
                tracing::warn!("job lease lost");
                self.lost = true;
                self.pending.clear();
                self.pending_bytes = 0;
            }
            Err(status) => {
                tracing::warn!(code = ?status.code(), "job report failed");
                self.failing = true;
            }
        }
        if self.lost {
            Err(End::Lost)
        } else if self.cancel {
            Err(End::Cancel)
        } else {
            Ok(())
        }
    }

    async fn flush(&mut self, ctl: &mut Ctl) -> Result<(), End> {
        ctl.race(self.send_pending()).await?;
        if self.lost {
            Err(End::Lost)
        } else if self.cancel {
            Err(End::Cancel)
        } else {
            Ok(())
        }
    }

    async fn send_pending(&mut self) {
        loop {
            self.start();
            if self.in_flight.is_none() {
                return;
            }
            let reply = self.reply().await;
            let _ = self.settle(reply);
            if self.lost || self.failing || self.drained() {
                return;
            }
        }
    }

    fn batch_len(&self) -> usize {
        let mut bytes = 0;
        let mut count = 0;
        for chunk in &self.pending {
            if count >= MAX_CHUNKS_PER_REPORT
                || (count > 0 && bytes + chunk.text.len() > MAX_REQUEST_BYTES)
            {
                break;
            }
            bytes += chunk.text.len();
            count += 1;
        }
        count
    }

    fn request(&self, chunks: Vec<TranscriptChunk>) -> ReportJobRequest {
        report_request(self.job, &self.progress, chunks)
    }

    async fn fail(&mut self, exit_code: Option<i32>, error: &'static str) -> AgentOutcome {
        self.terminal(Terminal {
            state: JobState::Failed,
            exit_code,
            error: Some(error),
            branch: None,
            pr_url: None,
        })
        .await;
        AgentOutcome::Failed { exit_code, error }
    }

    async fn terminal(&mut self, end: Terminal) {
        let bound = self.terminal_timeout;
        if tokio::time::timeout(bound, self.send_terminal(end))
            .await
            .is_err()
        {
            tracing::warn!("job terminal report timed out");
        }
    }

    async fn cancelled(&mut self) {
        self.terminal(Terminal {
            state: JobState::Cancelled,
            exit_code: None,
            error: None,
            branch: None,
            pr_url: None,
        })
        .await;
    }

    async fn send_terminal(&mut self, end: Terminal) {
        loop {
            self.send_pending().await;
            if self.lost {
                return;
            }
            if self.drained() {
                break;
            }
            tokio::time::sleep(RETRY_PAUSE).await;
        }
        let mut request = self.request(Vec::new());
        request.terminal_state = Some(end.state.into());
        request.error = end.error.map(str::to_owned);
        request.exit_code = end.exit_code;
        request.branch = end.branch;
        request.pr_url = end.pr_url;
        self.pull_hooks();
        request.summary = Some(self.feed.finish(ending(end.state, end.error)));
        match self.reporter.report(request).await {
            Err(status) if status.code() == Code::FailedPrecondition => {
                tracing::info!("job already ended");
            }
            Err(status) => {
                tracing::warn!(code = ?status.code(), "job terminal report failed");
            }
            Ok(_) => {}
        }
    }
}

fn report_request(job: &Job, progress: &str, chunks: Vec<TranscriptChunk>) -> ReportJobRequest {
    ReportJobRequest {
        job_id: job.job_id.clone(),
        attempt: job.attempt,
        r#box: job.r#box.clone(),
        phase: PHASE.to_owned(),
        progress: progress.to_owned(),
        chunks,
        ..ReportJobRequest::default()
    }
}

/// Maps a final `result` subtype to the cap failure it means, if any. A cap hit is a failure
/// whatever the exit status, so it takes precedence over the status. It ends as
/// [`Ending::Failed`] and never reaches [`AgentRunner::finish`], so no branch is published.
fn cap_error(subtype: &str) -> Option<&'static str> {
    match subtype {
        SUBTYPE_MAX_TURNS => Some(ERR_MAX_TURNS),
        SUBTYPE_BUDGET => Some(ERR_BUDGET),
        _ => None,
    }
}

fn ending(state: JobState, error: Option<&str>) -> Ending {
    match (state, error) {
        (JobState::Succeeded, _) => Ending::Succeeded,
        (JobState::Cancelled, _) => Ending::Cancelled,
        (_, Some(ERR_TIMEOUT | ERR_FINISH_TIMEOUT)) => Ending::TimedOut,
        _ => Ending::Failed,
    }
}

struct Terminal {
    state: JobState,
    exit_code: Option<i32>,
    error: Option<&'static str>,
    branch: Option<String>,
    pr_url: Option<String>,
}

struct Published {
    branch: Option<String>,
    pr_url: Option<String>,
}

#[derive(Clone, Copy)]
enum Scope<'a> {
    Clean,
    Push,
    Gh,
    Tree(&'a Path),
}

trait IntoFailure {
    fn failure(self, start: &'static str) -> Failure;
}

impl IntoFailure for CaptureError {
    fn failure(self, start: &'static str) -> Failure {
        match self {
            Self::Start => Failure::bare(start),
            Self::Timeout => Failure::bare(ERR_FINISH_TIMEOUT),
        }
    }
}

const HOME_DIR: &str = "home";
const GH_CONFIG_DIR: &str = "gh";

struct Scratch(PathBuf);

impl Scratch {
    fn create(cwd: &Path, job_id: &str) -> Result<Self, ()> {
        let parent = cwd.parent().ok_or(())?;
        let path = parent.join(format!(".finish-{job_id}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).map_err(|_| ())?;
        for sub in [HOME_DIR, GH_CONFIG_DIR] {
            std::fs::create_dir(path.join(sub)).map_err(|_| ())?;
        }
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Failure {
    error: &'static str,
    tail: String,
}

impl Failure {
    fn bare(error: &'static str) -> Self {
        Self {
            error,
            tail: String::new(),
        }
    }

    fn tail(error: &'static str, stderr: &str) -> Self {
        let mut start = stderr.len().saturating_sub(TAIL_BYTES);
        while !stderr.is_char_boundary(start) {
            start += 1;
        }
        Self {
            error,
            tail: stderr[start..].to_owned(),
        }
    }
}

fn filter_drivers(listing: &str) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for line in listing.lines() {
        let Some(rest) = line.strip_prefix("filter.") else {
            continue;
        };
        let Some((name, _)) = rest.rsplit_once('.') else {
            continue;
        };
        if name.contains('=') {
            return None;
        }
        names.insert(name.to_owned());
    }
    Some(names)
}

fn pr_url(stdout: &str) -> Option<String> {
    let line = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())?;
    let plain = line.len() <= MAX_PR_URL_BYTES
        && line.starts_with("https://")
        && !line.chars().any(|c| c.is_control() || c.is_whitespace());
    plain.then(|| line.to_owned())
}

fn assistant_text(line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("type")?.as_str()? != "assistant" {
        return None;
    }
    value
        .get("message")?
        .get("content")?
        .as_array()?
        .iter()
        .rev()
        .find_map(|block| {
            if block.get("type")?.as_str()? == "text" {
                block.get("text")?.as_str().map(str::to_owned)
            } else {
                None
            }
        })
}

fn cut(text: &mut String, max: usize) -> bool {
    if text.len() <= max {
        return false;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}

#[cfg(test)]
mod tests {
    use super::{
        AgentOutcome, AgentProc, AgentRunner, AgentSpec, DirectLauncher, ERR_EXIT,
        ERR_FINISH_TIMEOUT, ERR_SIGNAL, ERR_TIMEOUT, Ending, Job, JobState, Launched, Launcher,
        LineReader, Reporter, RunConfig, STRIPPED_ENV, UNKNOWN_STAMP, VERSION_CHARS, VersionStamp,
        ending, parse_version,
    };
    use crate::poller::Shutdown;
    use fleet_core::Redactor;
    use fleet_proto::v1::{ReportJobReply, ReportJobRequest};
    use std::ffi::OsString;
    use std::future::Future;
    use std::io;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::process::ExitStatus;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;
    use tokio::io::BufReader;
    use tonic::Status;

    struct Replies {
        cancel: bool,
    }

    impl Reporter for Replies {
        fn report(
            &self,
            _request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            let reply = ReportJobReply {
                cancel_requested: self.cancel,
                ..ReportJobReply::default()
            };
            async move { Ok(reply) }
        }
    }

    #[derive(Debug)]
    struct FakeProc {
        status: ExitStatus,
        hold: bool,
        stopped: Arc<AtomicBool>,
        calls: Arc<Mutex<Vec<&'static str>>>,
        timed_out: bool,
    }

    impl AgentProc for FakeProc {
        fn timed_out(&self) -> bool {
            self.timed_out
        }

        fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + '_>> {
            Box::pin(async move {
                while self.hold && !self.stopped.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok(self.status)
            })
        }

        fn terminate(&mut self) {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push("terminate");
        }

        fn kill(&mut self) {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push("kill");
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct FakeLauncher {
        status: ExitStatus,
        hold: bool,
        specs: Arc<Mutex<Vec<AgentSpec>>>,
        calls: Arc<Mutex<Vec<&'static str>>>,
        timed_out: bool,
    }

    impl FakeLauncher {
        fn new(status: ExitStatus, hold: bool) -> Self {
            Self {
                status,
                hold,
                specs: Arc::default(),
                calls: Arc::default(),
                timed_out: false,
            }
        }
    }

    impl Launcher for FakeLauncher {
        fn launch(&self, spec: AgentSpec) -> io::Result<Launched> {
            self.specs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(spec);
            Ok(Launched {
                stdout: Box::new(tokio::io::empty()),
                proc: Box::new(FakeProc {
                    status: self.status,
                    hold: self.hold,
                    stopped: Arc::default(),
                    calls: Arc::clone(&self.calls),
                    timed_out: self.timed_out,
                }),
            })
        }
    }

    fn test_config(jobs: &Path) -> RunConfig {
        let mut config = RunConfig::new("claude-fake", false);
        config.jobs_dir = Some(jobs.to_path_buf());
        config.max_turns = 7;
        config.max_budget_usd = 1.5;
        config.flush_interval = Duration::from_millis(10);
        config.report_interval = Duration::from_millis(10);
        config.cancel_grace = Duration::from_millis(20);
        config.base_env = STRIPPED_ENV
            .iter()
            .map(|name| (OsString::from(name), OsString::from("secret")))
            .chain([
                (OsString::from("PATH"), OsString::from("/bin")),
                (OsString::from("HTTPS_PROXY"), OsString::from("http://p:1")),
                (OsString::from("HOME"), OsString::from("/real/operator")),
            ])
            .collect();
        config.env_passthrough = STRIPPED_ENV.iter().map(|name| (*name).to_owned()).collect();
        config
    }

    fn test_job() -> Job {
        Job {
            job_id: "job1".into(),
            prompt: "do it".into(),
            ..Job::default()
        }
    }

    #[test]
    fn agent_spec_holds_the_scrubbed_env_the_caps_and_the_cwd() {
        let jobs = Path::new("/jobs");
        let runner = AgentRunner::new(
            test_config(jobs),
            Replies { cancel: false },
            Redactor::default(),
        );
        let home = Path::new("/jobs/home");
        let spec = runner.agent_spec(&test_job(), Path::new("/work"), home);
        for name in STRIPPED_ENV {
            assert!(
                !spec.env.contains_key(&OsString::from(name)),
                "{name} leaked"
            );
        }
        assert_eq!(spec.env.get(&OsString::from("HOME")), Some(&home.into()));
        assert_eq!(
            spec.env.get(&OsString::from("CLAUDE_CONFIG_DIR")),
            Some(&home.join(".claude").into_os_string())
        );
        assert_eq!(
            spec.env.get(&OsString::from("HTTPS_PROXY")),
            Some(&OsString::from("http://p:1"))
        );
        assert_eq!(spec.cwd, Path::new("/work"));
        assert_eq!(spec.argv.first(), Some(&OsString::from("claude-fake")));
        let flag = |name: &str| {
            let at = spec.argv.iter().position(|arg| arg == name)?;
            spec.argv.get(at + 1).cloned()
        };
        assert_eq!(flag("--max-turns"), Some(OsString::from("7")));
        assert_eq!(flag("--max-budget-usd"), Some(OsString::from("1.5")));
        assert_eq!(flag("-p"), Some(OsString::from("do it")));
        assert_eq!(flag("--permission-mode"), Some(OsString::from("dontAsk")));
    }

    #[test]
    fn every_agent_spec_carries_a_stamp_with_unknown_defaults() {
        let runner = AgentRunner::new(
            test_config(Path::new("/jobs")),
            Replies { cancel: false },
            Redactor::default(),
        );
        let spec = runner.agent_spec(&test_job(), Path::new("/w"), Path::new("/h"));
        assert_eq!(spec.stamp.bundle_sha, runner.config.bundle.sha256());
        assert_eq!(spec.stamp.bundle_sha.len(), 64);
        assert_eq!(spec.stamp.claude_version, UNKNOWN_STAMP);
        assert_eq!(spec.stamp.model, UNKNOWN_STAMP);
        let blank = VersionStamp::default();
        assert_eq!(
            [&blank.bundle_sha, &blank.claude_version, &blank.model],
            ["unknown"; 3]
        );
    }

    #[test]
    fn agent_spec_denies_the_file_edit_tools_in_either_mode() {
        for disposable in [false, true] {
            let mut config = test_config(Path::new("/jobs"));
            config.disposable = disposable;
            let runner = AgentRunner::new(config, Replies { cancel: false }, Redactor::default());
            let spec = runner.agent_spec(&test_job(), Path::new("/work"), Path::new("/h"));
            let at = spec
                .argv
                .iter()
                .position(|arg| arg == "--disallowedTools")
                .unwrap_or(usize::MAX);
            let denied: Vec<&OsString> = spec.argv.iter().skip(at.saturating_add(1)).collect();
            for tool in ["Edit", "Write", "NotebookEdit", "MultiEdit"] {
                assert!(denied.contains(&&OsString::from(tool)), "missing {tool}");
            }
        }
    }

    #[test]
    fn managed_settings_deny_the_file_edit_tools() {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("../../../deploy/managed-settings.json"))
                .unwrap_or_default();
        let deny: Vec<&str> = value["permissions"]["deny"]
            .as_array()
            .map(|list| list.iter().filter_map(|item| item.as_str()).collect())
            .unwrap_or_default();
        for tool in ["Edit", "Write", "NotebookEdit", "MultiEdit"] {
            assert!(deny.contains(&tool), "missing {tool}");
        }
    }

    #[test]
    fn agent_spec_skips_permissions_only_on_a_disposable_box() {
        let mut config = test_config(Path::new("/jobs"));
        config.disposable = true;
        let runner = AgentRunner::new(config, Replies { cancel: false }, Redactor::default());
        let spec = runner.agent_spec(&test_job(), Path::new("/work"), Path::new("/h"));
        assert!(
            spec.argv
                .contains(&OsString::from("--dangerously-skip-permissions"))
        );
        assert!(!spec.argv.contains(&OsString::from("--permission-mode")));
    }

    #[test]
    fn the_direct_launcher_rejects_an_empty_argv() {
        let spec = AgentSpec {
            argv: Vec::new(),
            env: std::collections::BTreeMap::new(),
            cwd: "/".into(),
            stamp: VersionStamp::default(),
        };
        let err = DirectLauncher.launch(spec).err().map(|err| err.kind());
        assert_eq!(err, Some(io::ErrorKind::InvalidInput));
    }

    #[tokio::test]
    async fn the_runner_launches_once_and_maps_the_proc_status() {
        let cases = [
            (ExitStatus::from_raw(0), AgentOutcome::Succeeded),
            (
                ExitStatus::from_raw(3 << 8),
                AgentOutcome::Failed {
                    exit_code: Some(3),
                    error: ERR_EXIT,
                },
            ),
        ];
        for (status, expected) in cases {
            let dir = tempfile::tempdir().expect("tempdir");
            let launcher = Arc::new(FakeLauncher::new(status, false));
            let runner = AgentRunner::new(
                test_config(dir.path()),
                Replies { cancel: false },
                Redactor::default(),
            )
            .with_launcher(launcher.clone());
            let (_trigger, shutdown) = Shutdown::channel();
            let job = test_job();
            let outcome = runner.run(&job, dir.path(), shutdown).await;
            assert_eq!(outcome.ok(), Some(expected));
            let specs = launcher
                .specs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let home = dir.path().join(".agent").join("job1").join("home");
            assert_eq!(*specs, vec![runner.agent_spec(&job, dir.path(), &home)]);
        }
    }

    fn version_script(mode: &str) -> PathBuf {
        static DIR: std::sync::OnceLock<(tempfile::TempDir, PathBuf, PathBuf)> =
            std::sync::OnceLock::new();
        let (_, ok, bad) = DIR.get_or_init(|| {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
            let write = |name: &str, body: &str| {
                let path = dir.path().join(name);
                std::fs::write(&path, body).unwrap_or_else(|_| std::process::abort());
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .unwrap_or_else(|_| std::process::abort());
                path
            };
            let ok = write("ok", "#!/bin/sh\necho '2.3.4 (Claude Code)'\n");
            let bad = write("bad", "#!/bin/sh\necho '9.9.9'\nexit 1\n");
            (dir, ok, bad)
        });
        if mode == "ok" {
            ok.clone()
        } else {
            bad.clone()
        }
    }

    #[tokio::test]
    async fn the_stamp_carries_the_version_claude_prints_and_unknown_when_it_cannot() {
        for (bin, expected) in [
            (version_script("ok"), "2.3.4 (Claude Code)"),
            (version_script("bad"), UNKNOWN_STAMP),
            (PathBuf::from("/nonexistent/claude"), UNKNOWN_STAMP),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let launcher = Arc::new(FakeLauncher::new(ExitStatus::from_raw(0), false));
            let mut config = test_config(dir.path());
            config.claude_bin = bin;
            let runner = AgentRunner::new(config, Replies { cancel: false }, Redactor::default())
                .with_launcher(launcher.clone());
            let (_trigger, shutdown) = Shutdown::channel();
            let outcome = runner.run(&test_job(), dir.path(), shutdown).await;
            assert_eq!(outcome.ok(), Some(AgentOutcome::Succeeded));
            let specs = launcher
                .specs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            assert_eq!(specs[0].stamp.claude_version, expected);
            assert_eq!(specs[0].stamp.model, UNKNOWN_STAMP);
        }
    }

    #[test]
    fn a_version_line_is_the_first_clean_line_cut_at_the_cap() {
        assert_eq!(parse_version("1.0 (x)\nmore"), Some("1.0 (x)".to_owned()));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("  \n"), None);
        assert_eq!(parse_version("a\u{1b}[0m"), None);
        assert_eq!(
            parse_version(&"v".repeat(200)).map(|v| v.len()),
            Some(VERSION_CHARS)
        );
    }

    #[test]
    fn a_stamp_takes_the_reported_model_and_keeps_unknown_without_one() {
        let named = VersionStamp::default().with_model(Some("claude-opus-4"));
        assert_eq!(named.model, "claude-opus-4");
        assert_eq!(named.claude_version, UNKNOWN_STAMP);
        assert_eq!(
            VersionStamp::default().with_model(None).model,
            UNKNOWN_STAMP
        );
    }

    #[tokio::test]
    async fn a_signal_end_past_the_launcher_deadline_reports_timed_out() {
        for (timed_out, expected) in [(true, ERR_TIMEOUT), (false, ERR_SIGNAL)] {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut launcher = FakeLauncher::new(ExitStatus::from_raw(9), false);
            launcher.timed_out = timed_out;
            let runner = AgentRunner::new(
                test_config(dir.path()),
                Replies { cancel: false },
                Redactor::default(),
            )
            .with_launcher(Arc::new(launcher));
            let (_trigger, shutdown) = Shutdown::channel();
            let outcome = runner.run(&test_job(), dir.path(), shutdown).await;
            assert_eq!(
                outcome.ok(),
                Some(AgentOutcome::Failed {
                    exit_code: None,
                    error: expected,
                })
            );
        }
    }

    #[tokio::test]
    async fn a_cancel_reply_terminates_then_kills_the_proc() {
        let dir = tempfile::tempdir().expect("tempdir");
        let launcher = Arc::new(FakeLauncher::new(ExitStatus::from_raw(0), true));
        let runner = AgentRunner::new(
            test_config(dir.path()),
            Replies { cancel: true },
            Redactor::default(),
        )
        .with_launcher(launcher.clone());
        let (_trigger, shutdown) = Shutdown::channel();
        let job = test_job();
        let run = runner.run(&job, dir.path(), shutdown);
        let outcome = tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("run bounded");
        assert_eq!(outcome.ok(), Some(AgentOutcome::Cancelled));
        let calls = launcher
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(calls.first(), Some(&"terminate"));
        assert!(calls.contains(&"kill"));
    }

    #[test]
    fn the_terminal_state_and_error_pick_the_telemetry_ending() {
        let cases = [
            (JobState::Succeeded, None, Ending::Succeeded),
            (JobState::Cancelled, None, Ending::Cancelled),
            (JobState::Failed, None, Ending::Failed),
            (JobState::Failed, Some("boom"), Ending::Failed),
            (JobState::Failed, Some(ERR_TIMEOUT), Ending::TimedOut),
            (JobState::Failed, Some(ERR_FINISH_TIMEOUT), Ending::TimedOut),
        ];
        for (state, error, expected) in cases {
            assert_eq!(ending(state, error), expected);
        }
    }

    #[tokio::test]
    async fn a_huge_line_is_capped_before_it_is_buffered() {
        let mut input = vec![b'a'; 1024 * 1024];
        input.extend_from_slice(b"\nnext\nlast");
        let reader = BufReader::with_capacity(4096, input.as_slice());
        let mut lines = LineReader::new(reader, 1000);
        let mut seen = Vec::new();
        while matches!(lines.next_line().await, Ok(true)) {
            assert!(lines.line.len() <= 1000);
            seen.push(std::mem::take(&mut lines.line));
        }
        seen.push(std::mem::take(&mut lines.line));
        assert_eq!(seen[0].len(), 1000);
        assert_eq!(seen[1], b"next\n");
        assert_eq!(seen[2], b"last");
    }
}
