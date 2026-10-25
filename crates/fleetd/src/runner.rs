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

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::MAX_CHUNKS_PER_REPORT;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest, TranscriptChunk};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::{Instant, MissedTickBehavior, Sleep};
use tonic::{Code, Status};

use crate::askpass;
use crate::group::GroupGuard;
use crate::now_ms;
use crate::poller::{RunError, Shutdown};
use crate::proc::{CaptureError, Captured, capture};
use crate::workspace::{RepoPolicy, validate_job_id, validate_ref, validate_repo};

/// Variables removed from the agent's own environment block.
///
/// The agent runs as fleetd's uid and can still read the fleetd environment through
/// `/proc` (ADR-0024 Known limit). The push child keeps `GH_TOKEN` and `GIT_ASKPASS`.
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
const ERR_COMMITS: &str = "job commits could not be inspected";
const ERR_PUSH: &str = "git push failed";
const ERR_PR: &str = "pull request could not be opened";
const ERR_PR_URL: &str = "pull request url was not returned";
const ERR_FINISH_TIMEOUT: &str = "finish step timed out";

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
    /// answers only for them.
    pub repo_policy: RepoPolicy,
    /// Git binary used to fetch, count, log and push commits, `git` by default.
    pub git_bin: PathBuf,
    /// Longest time for the finish step and for each helper command in it.
    pub finish_timeout: Duration,
    /// True when the box is disposable. Only then the agent runs with permission checks off.
    pub disposable: bool,
    /// Hard limit on the run. The process group is killed when it passes.
    pub timeout: Duration,
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
    /// Environment the agent inherits, before [`STRIPPED_ENV`] is removed.
    pub base_env: Vec<(OsString, OsString)>,
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
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            report_interval: DEFAULT_REPORT_INTERVAL,
            cancel_grace: DEFAULT_CANCEL_GRACE,
            terminal_report_timeout: DEFAULT_TERMINAL_REPORT_TIMEOUT,
            base_env: std::env::vars_os().collect(),
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

/// Runs the agent for claimed jobs.
#[derive(Debug)]
pub struct AgentRunner<R> {
    config: RunConfig,
    reporter: R,
    redactor: Redactor,
    carries: Mutex<HashMap<String, Carry>>,
}

#[derive(Debug, Default)]
struct Carry {
    next_seq: u64,
    progress: String,
    pending: VecDeque<TranscriptChunk>,
    pending_bytes: usize,
}

impl<R: Reporter> AgentRunner<R> {
    /// A runner that reports through `reporter` and redacts with `redactor`.
    pub fn new(config: RunConfig, reporter: R, redactor: Redactor) -> Self {
        Self {
            config,
            reporter,
            redactor,
            carries: Mutex::new(HashMap::new()),
        }
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
        let mut stream = Stream::new(
            &self.reporter,
            job,
            self.config.terminal_report_timeout,
            Carry::default(),
        );
        let result = self.run_stream(job, cwd, shutdown, &mut stream).await;
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
    ) -> Result<AgentOutcome, RunError> {
        let Ok(mut child) = self.command(job, cwd).spawn() else {
            return Ok(stream.fail(None, ERR_START).await);
        };
        let mut guard = GroupGuard::new(child.id());
        let Some(stdout) = child.stdout.take() else {
            guard.kill();
            let _ = child.wait().await;
            return Ok(stream.fail(None, ERR_START).await);
        };
        let mut ctl = Ctl {
            deadline: Box::pin(tokio::time::sleep(self.config.timeout)),
            shutdown,
        };
        let end = self
            .drive(&mut child, stdout, &mut guard, stream, &mut ctl)
            .await;
        if matches!(end, Err(End::Cancel)) {
            guard.terminate();
            let _ = tokio::time::timeout(self.config.cancel_grace, child.wait()).await;
        }
        guard.kill();
        let _ = child.wait().await;
        match end {
            Ok(status) => match status.code() {
                Some(0) => Ok(AgentOutcome::Succeeded),
                Some(code) => Ok(stream.fail(Some(code), ERR_EXIT).await),
                None => Ok(stream.fail(None, ERR_SIGNAL).await),
            },
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
        scope: Scope,
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
            Scope::Clean => &CLEAN_ENV,
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
            Scope::Clean => command.env("GIT_ALLOW_PROTOCOL", "file"),
            Scope::Push => command
                .env("GIT_ALLOW_PROTOCOL", self.config.repo_policy.protocols())
                .env("GIT_ASKPASS", askpass_command(&self.config.askpass_bin))
                .env(
                    askpass::HOSTS_ENV,
                    self.config.repo_policy.hosts().join(","),
                ),
            Scope::Gh => command
                .env("GH_CONFIG_DIR", dir.join(GH_CONFIG_DIR))
                .env("GH_NO_UPDATE_NOTIFIER", "1")
                .env("GH_BROWSER", "true")
                .env("GH_EDITOR", "true")
                .env("GH_PAGER", "cat")
                .env("PAGER", "cat"),
        };
        capture(command, self.config.finish_timeout).await
    }

    async fn drive(
        &self,
        child: &mut Child,
        stdout: ChildStdout,
        guard: &mut GroupGuard,
        stream: &mut Stream<'_, R>,
        ctl: &mut Ctl,
    ) -> Result<ExitStatus, End> {
        let mut lines = LineReader::new(BufReader::new(stdout), MAX_CHUNK_BYTES);
        let mut open = true;
        let mut status = None;
        let mut drain: Option<Pin<Box<Sleep>>> = None;
        let mut tick = tokio::time::interval(self.config.flush_interval);
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
                    guard.kill();
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

    fn command(&self, job: &Job, cwd: &Path) -> Command {
        let mut command = Command::new(&self.config.claude_bin);
        command
            .args([
                "-p",
                &job.prompt,
                "--output-format",
                "stream-json",
                "--verbose",
            ])
            .current_dir(cwd)
            .env_clear()
            .envs(
                self.config
                    .base_env
                    .iter()
                    .filter(|(name, _)| !STRIPPED_ENV.iter().any(|bad| name == bad))
                    .map(|(name, value)| (name, value)),
            )
            .env("FLEET_JOB_ID", &job.job_id)
            .env("SWARM_BOX", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        if self.config.disposable {
            command.arg("--dangerously-skip-permissions");
        }
        command
    }
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

    async fn next_line(&mut self) -> std::io::Result<bool> {
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
    future: ReportFuture<'a>,
}

struct Reply {
    upto: u64,
    result: Result<ReportJobReply, Status>,
}

struct Stream<'a, R> {
    reporter: &'a R,
    job: &'a Job,
    pending: VecDeque<TranscriptChunk>,
    pending_bytes: usize,
    in_flight: Option<InFlight<'a>>,
    next_seq: u64,
    progress: String,
    last_report: Instant,
    terminal_timeout: Duration,
    cancel: bool,
    lost: bool,
    failing: bool,
}

impl<'a, R: Reporter> Stream<'a, R> {
    fn new(reporter: &'a R, job: &'a Job, terminal_timeout: Duration, carry: Carry) -> Self {
        Self {
            reporter,
            job,
            pending: carry.pending,
            pending_bytes: carry.pending_bytes,
            in_flight: None,
            next_seq: carry.next_seq.max(1),
            progress: carry.progress,
            last_report: Instant::now(),
            terminal_timeout,
            cancel: false,
            lost: false,
            failing: false,
        }
    }

    fn carry(&mut self) -> Carry {
        Carry {
            next_seq: self.next_seq,
            progress: self.progress.clone(),
            pending: std::mem::take(&mut self.pending),
            pending_bytes: std::mem::take(&mut self.pending_bytes),
        }
    }

    fn push(&mut self, redactor: &Redactor, line: &str) {
        if self.lost {
            return;
        }
        let clean = redactor.redact_str(line);
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
        if !self.pending.is_empty() || self.last_report.elapsed() >= report_interval {
            self.start();
        }
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
        let request = self.request(chunks);
        self.in_flight = Some(InFlight {
            upto,
            future: Box::pin(self.reporter.report(request)),
        });
    }

    async fn reply(&mut self) -> Reply {
        let Some(flying) = self.in_flight.as_mut() else {
            return std::future::pending().await;
        };
        let result = flying.future.as_mut().await;
        let upto = flying.upto;
        self.in_flight = None;
        Reply { upto, result }
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
            if !self.failing && !self.pending.is_empty() {
                self.start();
            }
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
            if self.lost || self.failing || self.pending.is_empty() {
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
            if self.pending.is_empty() {
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
enum Scope {
    Clean,
    Push,
    Gh,
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

fn askpass_command(bin: &Path) -> String {
    format!("'{}' askpass", bin.to_string_lossy().replace('\'', "'\\''"))
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
    use super::LineReader;
    use tokio::io::BufReader;

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
