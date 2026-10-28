//! The credential broker core of ADR-0037.
//!
//! The agent asks fleetd to push, open a pull request, read check results or fetch. A
//! [`Request`] carries no branch, repo, URL or job id: `deny_unknown_fields` rejects any such
//! key. The remote branch comes from the [`PushTarget`] that [`Broker::new`] derives from the
//! claimed Job, and the executors ([`GitExecutor`], [`GhExecutor`]) receive that target, never
//! a client value.
//!
//! `pr_checks` reads the checks of the pull request URL the broker itself recorded from the
//! Job's `pr_create` reply, never one from a request, and is refused until one is recorded.
//! `fetch` refreshes the mirror of the Job's own repo. Both are paced: at most
//! [`MAX_PR_CHECKS_PER_JOB`] and [`MAX_FETCHES_PER_JOB`] attempts per Job, no closer together
//! than [`MIN_PR_CHECKS_INTERVAL`] and [`MIN_FETCH_INTERVAL`] ([`Limits`]), and one `fetch`
//! at a time per Job. [`GhCli`] and [`MirrorGit`] are the real executors of these two reads.
//!
//! Per Job the broker allows [`MAX_PUSHES_PER_JOB`] pushes and [`MAX_PRS_PER_JOB`] pull request,
//! a title of at most [`MAX_TITLE_CHARS`] characters and a body of at most [`MAX_BODY_BYTES`]
//! bytes, and refuses attribution lines. Title and body are redacted before an executor sees
//! them and every output is redacted and cut to [`MAX_OUTPUT_BYTES`]. A capped operation counts
//! when it is attempted, so a failed push or a failed pull request still spends its slot.
//! Errors are fixed messages: no executor text and no client value reaches the reply. Every
//! operation has a timeout.
//!
//! The direct launcher gets no broker: [`Broker::new`] refuses it, as the job socket does
//! (ADR-0036), because the agent there shares fleetd's uid.
//!
//! The decision logic is pure. The executors for `push` and `pr_create` are not written yet:
//! [`MirrorGit`] and [`GhCli`] refuse those two, and ADR-0031 P3 gates the real `push`.

use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::Job;
use fleet_proto::{is_ci_url, is_swarm_branch};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::Instant;

use crate::AgentLauncher;
use crate::group::GroupGuard;
use crate::jobsock::MAX_FRAME_BYTES;
use crate::workspace::Workspace;

/// Most `push` calls one Job may attempt.
pub const MAX_PUSHES_PER_JOB: u32 = 10;
/// Most `pr_create` calls one Job may attempt.
pub const MAX_PRS_PER_JOB: u32 = 1;
/// Most characters in a pull request title.
pub const MAX_TITLE_CHARS: usize = 256;
/// Most bytes in a pull request body.
pub const MAX_BODY_BYTES: usize = 8 * 1024;
/// Most bytes in the output of one operation.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024;
/// Most `pr_checks` calls one Job may attempt.
pub const MAX_PR_CHECKS_PER_JOB: u32 = 240;
/// Most `fetch` calls one Job may attempt.
pub const MAX_FETCHES_PER_JOB: u32 = 10;
/// Shortest time between two `pr_checks` attempts of one Job.
pub const MIN_PR_CHECKS_INTERVAL: Duration = Duration::from_secs(5);
/// Shortest time between two `fetch` attempts of one Job.
pub const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(30);
/// Most bytes in a recorded pull request URL.
pub const MAX_PR_URL_BYTES: usize = 2048;
/// Most checks `pr_checks` returns.
pub const MAX_CHECKS: usize = 50;
/// Most characters of a check name `pr_checks` returns.
pub const MAX_CHECK_NAME_CHARS: usize = 120;
const MAX_GH_STDOUT_BYTES: usize = 256 * 1024;
/// Timeout of `push`.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(120);
/// Timeout of `pr_create`.
pub const PR_CREATE_TIMEOUT: Duration = Duration::from_secs(60);
/// Timeout of `pr_checks`.
pub const PR_CHECKS_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of `fetch`.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);

/// An operation the agent may request. No variant has a field for a branch, repo, URL or id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Pushes the Job's own branch to the target.
    Push {},
    /// Opens the one pull request of the Job.
    PrCreate {
        /// The title.
        title: String,
        /// The body.
        body: String,
    },
    /// Reads the check results of the Job's pull request.
    PrChecks {},
    /// Fetches the Job's own repo.
    Fetch {},
}

impl Request {
    /// Parses one frame. An oversize frame, a frame that is not a JSON object (serde also reads
    /// `["fetch"]` as a tagged enum), an unknown op and any extra key yield
    /// [`Denial::InvalidRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`Denial::InvalidRequest`] when the frame is not exactly one known request.
    pub fn parse(frame: &[u8]) -> Result<Self, Denial> {
        let object = frame.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
        if frame.len() > MAX_FRAME_BYTES || !object {
            return Err(Denial::InvalidRequest);
        }
        serde_json::from_slice(frame).map_err(|_| Denial::InvalidRequest)
    }

    const fn timeout(&self) -> Duration {
        match self {
            Self::Push {} => PUSH_TIMEOUT,
            Self::PrCreate { .. } => PR_CREATE_TIMEOUT,
            Self::PrChecks {} => PR_CHECKS_TIMEOUT,
            Self::Fetch {} => FETCH_TIMEOUT,
        }
    }
}

/// The remote branch a Job's pushes go to, derived from the claimed Job.
///
/// A normal Job pushes to `swarm/<job id>`. A fix Job (`parent_job_id` set, ADR-0028) pushes to
/// the chain root's branch `swarm/<root id>`, named by its `base_ref`. Either id must match
/// `^[A-Za-z0-9]{1,64}$`, so the branch matches `^swarm/[A-Za-z0-9]{1,64}$`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushTarget {
    /// The Job's own id.
    Own(String),
    /// The root Job's id of the fix chain.
    Chain(String),
}

impl PushTarget {
    /// Derives the target from the claimed Job.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Target`] when the Job id, or for a fix Job the `base_ref`, does
    /// not name a valid `swarm/` branch.
    pub fn from_job(job: &Job) -> Result<Self, BrokerError> {
        if job.parent_job_id.is_none() {
            if is_swarm_branch(&format!("swarm/{}", job.job_id)) {
                Ok(Self::Own(job.job_id.clone()))
            } else {
                Err(BrokerError::Target)
            }
        } else if is_swarm_branch(&job.base_ref) {
            job.base_ref
                .strip_prefix("swarm/")
                .map(|root| Self::Chain(root.to_owned()))
                .ok_or(BrokerError::Target)
        } else {
            Err(BrokerError::Target)
        }
    }

    /// The remote branch name.
    #[must_use]
    pub fn branch(&self) -> String {
        match self {
            Self::Own(id) | Self::Chain(id) => format!("swarm/{id}"),
        }
    }
}

/// Why a [`Broker`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerError {
    /// The agent launcher is direct, which gets no job socket and no broker.
    DirectLauncher,
    /// The claimed Job names no valid push target.
    Target,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DirectLauncher => "broker refused: agent_launcher is direct",
            Self::Target => "broker refused: the job names no valid push target",
        })
    }
}

impl std::error::Error for BrokerError {}

/// A failed executor call. It carries nothing: the executor logs its own detail and the agent
/// sees only [`Denial::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecError;

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("executor failed")
    }
}

impl std::error::Error for ExecError {}

/// Runs the git operations. The target comes from the broker, never from the agent.
pub trait GitExecutor: Send + Sync {
    /// Pushes the Job's work to the target branch and returns a short status line.
    fn push(&self, target: &PushTarget) -> impl Future<Output = Result<String, ExecError>> + Send;

    /// Fetches the Job's own repo and returns a short status line.
    fn fetch(&self) -> impl Future<Output = Result<String, ExecError>> + Send;
}

/// Runs the `gh` operations. The target comes from the broker, never from the agent.
pub trait GhExecutor: Send + Sync {
    /// Opens a pull request from the target branch and returns its URL.
    fn pr_create(
        &self,
        target: &PushTarget,
        title: &str,
        body: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send;

    /// Returns the check results of the pull request at `pr_url`, the URL the broker recorded
    /// for this Job. The executor still validates it.
    fn pr_checks(
        &self,
        target: &PushTarget,
        pr_url: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send;
}

/// Why the broker refused or failed a request. The message of each is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Denial {
    /// The frame, title or body broke a rule.
    InvalidRequest,
    /// The per-Job cap of the operation is spent.
    CapReached,
    /// The operation was attempted again before its minimum interval passed. It spends no cap.
    RateLimited,
    /// `pr_checks` came before the broker recorded a pull request URL for the Job.
    NoPullRequest,
    /// The executor failed.
    Failed,
    /// The operation exceeded its timeout.
    TimedOut,
}

impl Denial {
    /// The fixed message sent to the agent.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid request",
            Self::CapReached => "per-job cap reached",
            Self::RateLimited => "rate limited",
            Self::NoPullRequest => "no pull request recorded",
            Self::Failed => "operation failed",
            Self::TimedOut => "operation timed out",
        }
    }
}

/// The reply to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// The operation ran. The output is redacted and cut to [`MAX_OUTPUT_BYTES`].
    Done {
        /// The output.
        output: String,
    },
    /// The operation did not run or failed.
    Denied {
        /// The reason code.
        error: Denial,
        /// The fixed message of the code.
        message: &'static str,
    },
}

impl Response {
    fn denied(error: Denial) -> Self {
        Self::Denied {
            error,
            message: error.message(),
        }
    }
}

/// The pacing of the two read operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most `pr_checks` attempts per Job.
    pub max_pr_checks: u32,
    /// Shortest time between two `pr_checks` attempts.
    pub pr_checks_interval: Duration,
    /// Most `fetch` attempts per Job.
    pub max_fetches: u32,
    /// Shortest time between two `fetch` attempts.
    pub fetch_interval: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pr_checks: MAX_PR_CHECKS_PER_JOB,
            pr_checks_interval: MIN_PR_CHECKS_INTERVAL,
            max_fetches: MAX_FETCHES_PER_JOB,
            fetch_interval: MIN_FETCH_INTERVAL,
        }
    }
}

#[derive(Debug, Default)]
struct Counts {
    pushes: u32,
    prs: u32,
    pr_url: Option<String>,
    checks: Paced,
    fetches: Paced,
}

#[derive(Debug, Default)]
struct Paced {
    count: u32,
    last: Option<Instant>,
}

impl Paced {
    fn spend(&mut self, cap: u32, interval: Duration) -> Result<(), Denial> {
        if self.count >= cap {
            return Err(Denial::CapReached);
        }
        let now = Instant::now();
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < interval)
        {
            return Err(Denial::RateLimited);
        }
        self.count += 1;
        self.last = Some(now);
        Ok(())
    }
}

/// The broker of one Job.
pub struct Broker<G, H> {
    target: PushTarget,
    git: G,
    gh: H,
    redactor: Redactor,
    limits: Limits,
    counts: Mutex<Counts>,
    fetch_gate: tokio::sync::Mutex<()>,
}

impl<G: GitExecutor, H: GhExecutor> Broker<G, H> {
    /// Builds the broker of a claimed Job.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::DirectLauncher`] under the direct launcher and
    /// [`BrokerError::Target`] when the Job names no valid push target.
    pub fn new(
        launcher: AgentLauncher,
        job: &Job,
        git: G,
        gh: H,
        redactor: Redactor,
    ) -> Result<Self, BrokerError> {
        if launcher != AgentLauncher::Systemd {
            return Err(BrokerError::DirectLauncher);
        }
        Ok(Self {
            target: PushTarget::from_job(job)?,
            git,
            gh,
            redactor,
            limits: Limits::default(),
            counts: Mutex::new(Counts::default()),
            fetch_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Replaces the pacing of the read operations.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The push target of the Job.
    #[must_use]
    pub const fn target(&self) -> &PushTarget {
        &self.target
    }

    /// Parses one frame and serves it.
    pub async fn handle_frame(&self, frame: &[u8]) -> Response {
        match Request::parse(frame) {
            Ok(request) => self.handle(request).await,
            Err(denial) => Response::denied(denial),
        }
    }

    /// Serves one request.
    pub async fn handle(&self, request: Request) -> Response {
        let timeout = request.timeout();
        let creating = matches!(request, Request::PrCreate { .. });
        let result = match request {
            Request::Push {} => {
                if !self.reserve(|c| spend(&mut c.pushes, MAX_PUSHES_PER_JOB)) {
                    return Response::denied(Denial::CapReached);
                }
                tokio::time::timeout(timeout, self.git.push(&self.target)).await
            }
            Request::PrCreate { title, body } => {
                let title = self.redactor.redact_str(&title);
                let body = self.redactor.redact_str(&body);
                if !valid_title(&title) || !valid_body(&body) {
                    return Response::denied(Denial::InvalidRequest);
                }
                if !self.reserve(|c| spend(&mut c.prs, MAX_PRS_PER_JOB)) {
                    return Response::denied(Denial::CapReached);
                }
                tokio::time::timeout(timeout, self.gh.pr_create(&self.target, &title, &body)).await
            }
            Request::PrChecks {} => {
                let Some(url) = self.recorded_pr_url() else {
                    return Response::denied(Denial::NoPullRequest);
                };
                let limits = self.limits;
                if let Err(denial) = self.paced(|c| {
                    c.checks
                        .spend(limits.max_pr_checks, limits.pr_checks_interval)
                }) {
                    return Response::denied(denial);
                }
                tokio::time::timeout(timeout, self.gh.pr_checks(&self.target, &url)).await
            }
            Request::Fetch {} => {
                let limits = self.limits;
                if let Err(denial) =
                    self.paced(|c| c.fetches.spend(limits.max_fetches, limits.fetch_interval))
                {
                    return Response::denied(denial);
                }
                tokio::time::timeout(timeout, async {
                    let _one_at_a_time = self.fetch_gate.lock().await;
                    self.git.fetch().await
                })
                .await
            }
        };
        match result {
            Ok(Ok(output)) => {
                let output = self.clean(&output);
                if creating {
                    self.record_pr_url(&output);
                }
                Response::Done { output }
            }
            Ok(Err(ExecError)) => Response::denied(Denial::Failed),
            Err(_) => Response::denied(Denial::TimedOut),
        }
    }

    fn paced(&self, spend: impl FnOnce(&mut Counts) -> Result<(), Denial>) -> Result<(), Denial> {
        spend(&mut self.counts.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn recorded_pr_url(&self) -> Option<String> {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pr_url
            .clone()
    }

    fn record_pr_url(&self, output: &str) {
        if let Some(url) = pr_url_of(output) {
            self.counts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pr_url = Some(url);
        }
    }

    fn reserve(&self, spend: impl FnOnce(&mut Counts) -> bool) -> bool {
        spend(&mut self.counts.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn clean(&self, output: &str) -> String {
        let redacted = self.redactor.redact_str(output);
        let mut end = redacted.len().min(MAX_OUTPUT_BYTES);
        while !redacted.is_char_boundary(end) {
            end -= 1;
        }
        redacted[..end].to_owned()
    }
}

impl<G, H> fmt::Debug for Broker<G, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Broker")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// Refreshes the mirror of the Job's own repo. `push` is refused until the push executor lands.
///
/// The repo comes from the claimed Job at construction, never from a request. `fetch` runs
/// [`Workspace::fetch_mirror`], so it uses the production repo policy, an https-only protocol
/// list, `core.hooksPath` and `core.fsmonitor` off, and the askpass helper bound to the token
/// host. Build it from a clone of the runner's [`Workspace`]: only clones share the lock that
/// serializes the refresh with `prepare`.
#[derive(Debug, Clone)]
pub struct MirrorGit {
    workspace: Workspace,
    repo: String,
}

impl MirrorGit {
    /// An executor that refreshes the mirror of `job.repo`.
    #[must_use]
    pub fn new(workspace: Workspace, job: &Job) -> Self {
        Self {
            workspace,
            repo: job.repo.clone(),
        }
    }
}

impl GitExecutor for MirrorGit {
    fn push(&self, _target: &PushTarget) -> impl Future<Output = Result<String, ExecError>> + Send {
        std::future::ready(Err(ExecError))
    }

    async fn fetch(&self) -> Result<String, ExecError> {
        match self.workspace.fetch_mirror(&self.repo).await {
            Ok(()) => Ok("fetched".to_owned()),
            Err(err) => {
                tracing::warn!(error = %err, detail = err.detail(), "broker fetch failed");
                Err(ExecError)
            }
        }
    }
}

/// Runs `gh pr checks` for the broker. `pr_create` is refused until its executor lands.
///
/// The child gets an empty environment plus `PATH`, a scratch `HOME`, `XDG_CONFIG_HOME` and
/// `GH_CONFIG_DIR`, `GH_TOKEN`, `GH_HOST` and, off `github.com`, `GH_ENTERPRISE_TOKEN`. The
/// token never reaches argv or fleetd's own environment. The agent shares fleetd's uid under
/// some launchers, so this hides the token from other uids only (ADR-0024 Known limit).
#[derive(Clone)]
pub struct GhCli {
    bin: PathBuf,
    host: String,
    token: String,
    scratch: PathBuf,
    path_env: Option<OsString>,
}

impl fmt::Debug for GhCli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GhCli")
            .field("bin", &self.bin)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct RawCheck {
    bucket: Option<String>,
    name: Option<String>,
    link: Option<String>,
}

#[derive(Debug, Serialize)]
struct Check {
    bucket: &'static str,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

#[derive(Debug, Serialize)]
struct Checks {
    checks: Vec<Check>,
    truncated: bool,
}

impl GhCli {
    /// A `gh` executor for the pull requests of `host`, with `token` as that host's credential
    /// and `scratch` as the child's home and working directory.
    #[must_use]
    pub fn new(
        bin: impl Into<PathBuf>,
        host: impl Into<String>,
        token: String,
        scratch: impl Into<PathBuf>,
    ) -> Self {
        Self {
            bin: bin.into(),
            host: host.into(),
            token,
            scratch: scratch.into(),
            path_env: std::env::var_os("PATH"),
        }
    }

    fn command(&self, pr_url: &str) -> Command {
        let home = &self.scratch;
        let mut command = Command::new(&self.bin);
        command.env_clear();
        if let Some(path) = &self.path_env {
            command.env("PATH", path);
        }
        command
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("GH_CONFIG_DIR", home.join("gh"))
            .env("GH_TOKEN", &self.token)
            .env("GH_HOST", &self.host)
            .env("GH_PROMPT_DISABLED", "1")
            .env("GH_NO_UPDATE_NOTIFIER", "1")
            .env("NO_COLOR", "1");
        if !self.host.eq_ignore_ascii_case("github.com") {
            command.env("GH_ENTERPRISE_TOKEN", &self.token);
        }
        command
            .args(["pr", "checks", pr_url, "--json", "bucket,link,name"])
            .current_dir(home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        command
    }

    async fn run(&self, pr_url: &str) -> Result<Vec<u8>, ExecError> {
        tokio::fs::create_dir_all(&self.scratch)
            .await
            .map_err(|_| ExecError)?;
        let mut child = self.command(pr_url).spawn().map_err(|_| ExecError)?;
        let _guard = GroupGuard::new(child.id());
        let mut stdout = child.stdout.take().ok_or(ExecError)?;
        let mut raw = Vec::new();
        (&mut stdout)
            .take(MAX_GH_STDOUT_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .await
            .map_err(|_| ExecError)?;
        if raw.len() > MAX_GH_STDOUT_BYTES {
            return Err(ExecError);
        }
        let _ = child.wait().await;
        Ok(raw)
    }

    fn subset(&self, raw: &[u8]) -> Result<String, ExecError> {
        let items: Vec<RawCheck> = serde_json::from_slice(raw).map_err(|_| ExecError)?;
        let mut shown = Checks {
            checks: Vec::new(),
            truncated: items.len() > MAX_CHECKS,
        };
        for item in items.into_iter().take(MAX_CHECKS) {
            shown.checks.push(Check {
                bucket: bucket_name(item.bucket.as_deref()),
                name: check_name(item.name.as_deref()),
                link: item.link.filter(|link| link_on_host(link, &self.host)),
            });
            if serde_json::to_string(&shown).map_err(|_| ExecError)?.len() > MAX_OUTPUT_BYTES {
                shown.checks.pop();
                shown.truncated = true;
                break;
            }
        }
        serde_json::to_string(&shown).map_err(|_| ExecError)
    }
}

impl GhExecutor for GhCli {
    fn pr_create(
        &self,
        _target: &PushTarget,
        _title: &str,
        _body: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        std::future::ready(Err(ExecError))
    }

    async fn pr_checks(&self, _target: &PushTarget, pr_url: &str) -> Result<String, ExecError> {
        if !is_pull_url(pr_url, &self.host) {
            return Err(ExecError);
        }
        let raw = self.run(pr_url).await?;
        self.subset(&raw)
    }
}

fn bucket_name(bucket: Option<&str>) -> &'static str {
    match bucket {
        Some("pass") => "pass",
        Some("fail") => "fail",
        Some("pending") => "pending",
        Some("skipping") => "skipping",
        Some("cancel") => "cancel",
        _ => "unknown",
    }
}

fn check_name(name: Option<&str>) -> String {
    name.unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() && !is_hidden_text(*c) && !is_line_separator(*c))
        .take(MAX_CHECK_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn host_of(url: &str) -> Option<&str> {
    url.strip_prefix("https://")?.split(['/', '?', '#']).next()
}

fn link_on_host(link: &str, host: &str) -> bool {
    is_ci_url(link) && host_of(link).is_some_and(|h| h.eq_ignore_ascii_case(host))
}

fn is_pull_url(url: &str, host: &str) -> bool {
    if url.len() > MAX_PR_URL_BYTES || !link_on_host(url, host) {
        return false;
    }
    let Some(path) = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, path)| path)
    else {
        return false;
    };
    let mut parts = path.split('/');
    let plain = |part: Option<&str>| {
        part.is_some_and(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    };
    plain(parts.next())
        && plain(parts.next())
        && parts.next() == Some("pull")
        && parts
            .next()
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

/// The pull request URL in the redacted `pr_create` output: the last non-empty line, when it
/// is one plain `https` URL of at most [`MAX_PR_URL_BYTES`] bytes.
fn pr_url_of(output: &str) -> Option<String> {
    let line = output
        .split(is_line_separator)
        .map(str::trim)
        .rfind(|l| !l.is_empty())?;
    (line.len() <= MAX_PR_URL_BYTES && is_ci_url(line)).then(|| line.to_owned())
}

fn spend(count: &mut u32, cap: u32) -> bool {
    if *count >= cap {
        return false;
    }
    *count += 1;
    true
}

fn valid_title(title: &str) -> bool {
    !title.trim().is_empty()
        && title.chars().count() <= MAX_TITLE_CHARS
        && !title.chars().any(|c| c.is_control() || is_hidden_text(c))
        && !has_attribution(title)
}

fn valid_body(body: &str) -> bool {
    body.len() <= MAX_BODY_BYTES
        && !body
            .chars()
            .any(|c| is_hidden_text(c) || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
        && !has_attribution(body)
}

const ATTRIBUTION_TRAILERS: [&str; 3] = ["coauthoredby", "signedoffby", "claudesession"];

const ATTRIBUTION_FRAGMENTS: [&str; 2] = ["claudeaicode", "generatedbyclaude"];

fn is_line_separator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Bidi overrides and isolates plus Unicode tag characters hide or smuggle text.
fn is_hidden_text(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{e0000}'..='\u{e007f}')
}

/// Lowercased ASCII alphanumerics only, so invisible and decorative characters vanish.
fn skeleton(text: &str) -> String {
    text.chars()
        .flat_map(char::to_lowercase)
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

fn is_trailer_line(line: &str) -> bool {
    let Some((key, _)) = line.split_once(':') else {
        return false;
    };
    let key = skeleton(key);
    let key = key.trim_start_matches(|c: char| c.is_ascii_digit());
    ATTRIBUTION_TRAILERS.contains(&key)
}

fn has_attribution(text: &str) -> bool {
    text.split(is_line_separator).any(|line| {
        let skeleton = skeleton(line);
        is_trailer_line(line)
            || ATTRIBUTION_FRAGMENTS
                .iter()
                .any(|fragment| skeleton.contains(fragment))
            || (skeleton.contains("generatedwith") && skeleton.contains("claude"))
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const SECRET: &str = "ghp_secretsecret1234";

    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<Mutex<Vec<String>>>,
        fail: bool,
        hang: bool,
        output: String,
    }

    impl Fake {
        fn record(&self, call: String) {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(call);
        }

        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn reply(&self, call: String) -> impl Future<Output = Result<String, ExecError>> + Send {
            self.record(call);
            let (fail, hang, output) = (self.fail, self.hang, self.output.clone());
            async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                if fail { Err(ExecError) } else { Ok(output) }
            }
        }
    }

    impl GitExecutor for Fake {
        fn push(
            &self,
            target: &PushTarget,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            self.reply(format!("push {}", target.branch()))
        }

        fn fetch(&self) -> impl Future<Output = Result<String, ExecError>> + Send {
            self.reply("fetch".to_owned())
        }
    }

    impl GhExecutor for Fake {
        fn pr_create(
            &self,
            target: &PushTarget,
            title: &str,
            body: &str,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            self.reply(format!("pr_create {} {title} {body}", target.branch()))
        }

        fn pr_checks(
            &self,
            target: &PushTarget,
            pr_url: &str,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            self.reply(format!("pr_checks {} {pr_url}", target.branch()))
        }
    }

    fn job(id: &str) -> Job {
        Job {
            job_id: id.to_owned(),
            ..Job::default()
        }
    }

    fn fix_job(id: &str, base_ref: &str) -> Job {
        Job {
            job_id: id.to_owned(),
            parent_job_id: Some("parentjob".to_owned()),
            base_ref: base_ref.to_owned(),
            ..Job::default()
        }
    }

    fn broker_for(job: &Job, fake: &Fake) -> Result<Broker<Fake, Fake>, BrokerError> {
        Broker::new(
            AgentLauncher::Systemd,
            job,
            fake.clone(),
            fake.clone(),
            Redactor::new([SECRET]),
        )
    }

    fn broker(fake: &Fake) -> Result<Broker<Fake, Fake>, BrokerError> {
        broker_for(&job("job1"), fake)
    }

    fn pr(title: &str, body: &str) -> Request {
        Request::PrCreate {
            title: title.to_owned(),
            body: body.to_owned(),
        }
    }

    fn denied(error: Denial) -> Response {
        Response::denied(error)
    }

    const PR_URL: &str = "https://github.com/o/r/pull/7";

    fn unpaced() -> Limits {
        Limits {
            max_pr_checks: u32::MAX,
            pr_checks_interval: Duration::ZERO,
            max_fetches: u32::MAX,
            fetch_interval: Duration::ZERO,
        }
    }

    fn with_url(b: Broker<Fake, Fake>) -> Broker<Fake, Fake> {
        b.record_pr_url(PR_URL);
        b
    }

    #[test]
    fn requests_parse_with_no_extra_keys() {
        assert_eq!(Request::parse(br#"{"op":"push"}"#), Ok(Request::Push {}));
        assert_eq!(
            Request::parse(br#"{"op":"pr_checks"}"#),
            Ok(Request::PrChecks {})
        );
        assert_eq!(Request::parse(br#"{"op":"fetch"}"#), Ok(Request::Fetch {}));
        assert_eq!(
            Request::parse(br#"{"op":"pr_create","title":"t","body":"b"}"#),
            Ok(pr("t", "b"))
        );
    }

    #[test]
    fn a_branch_repo_url_or_job_id_key_is_refused_on_every_op() {
        for op in [
            r#""op":"push""#,
            r#""op":"pr_checks""#,
            r#""op":"fetch""#,
            r#""op":"pr_create","title":"t","body":"b""#,
        ] {
            for key in ["branch", "repo", "url", "job_id", "base_ref", "remote"] {
                let frame = format!(r#"{{{op},"{key}":"x"}}"#);
                assert_eq!(
                    Request::parse(frame.as_bytes()),
                    Err(Denial::InvalidRequest),
                    "{frame}"
                );
            }
        }
    }

    #[test]
    fn the_hostile_input_table_never_reaches_a_read_op() {
        let keys = [
            "url",
            "pr",
            "pr_url",
            "pr_number",
            "number",
            "repo",
            "repository",
            "remote",
            "ref",
            "refspec",
            "refs",
            "branch",
            "job_id",
            "token",
            "host",
            "args",
            "argv",
            "flags",
            "json",
            "fields",
            "depth",
            "prune",
            "force",
            "all",
            "tags",
            "dir",
            "cwd",
            "env",
            "config",
            "-c",
            "--upload-pack",
            "",
            "OP",
            "Op",
            "\u{0}",
            "op ",
        ];
        for op in [r#""op":"pr_checks""#, r#""op":"fetch""#] {
            for key in keys {
                let key = key.replace('\u{0}', "\\u0000");
                for value in [r#""x""#, "1", "null", "[]", r#"{"a":1}"#, "true"] {
                    let frame = format!(r#"{{{op},"{key}":{value}}}"#);
                    assert_eq!(
                        Request::parse(frame.as_bytes()),
                        Err(Denial::InvalidRequest),
                        "{frame}"
                    );
                }
            }
        }
        for frame in [
            &br#"{"op":"PR_CHECKS"}"#[..],
            br#"{"op":"Fetch"}"#,
            br#"{"op":"fetch "}"#,
            br#"{"op":" fetch"}"#,
            br#"{"op":"fetch\u0000"}"#,
            br#"{"op":["fetch"]}"#,
            br#"{"op":null}"#,
            br#"["fetch"]"#,
            br#""fetch""#,
            b"null",
            br#"{"op":"fetch"}x"#,
            br#"{"op":"fetch"}{"op":"fetch"}"#,
            br#"{"op":"pr_checks","op":"pr_checks","url":"u"}"#,
            b"{\"op\":\"fetch\"}\xff",
            b"\xef\xbb\xbf{\"op\":\"fetch\"}",
        ] {
            assert_eq!(
                Request::parse(frame),
                Err(Denial::InvalidRequest),
                "{}",
                String::from_utf8_lossy(frame)
            );
        }
    }

    #[test]
    fn unknown_ops_malformed_and_oversize_frames_are_refused() {
        for frame in [
            &br#"{"op":"gh_api"}"#[..],
            br#"{"op":"merge"}"#,
            br#"{"op":"git","args":["push"]}"#,
            br#"{"op":"pr_create","title":"t"}"#,
            br"{}",
            b"push",
            b"",
        ] {
            assert_eq!(Request::parse(frame), Err(Denial::InvalidRequest));
        }
        let big = format!(
            r#"{{"op":"pr_create","title":"t","body":"{}"}}"#,
            "a".repeat(MAX_FRAME_BYTES)
        );
        assert_eq!(Request::parse(big.as_bytes()), Err(Denial::InvalidRequest));
    }

    #[test]
    fn a_normal_job_targets_its_own_branch() {
        assert_eq!(
            PushTarget::from_job(&job("job1")),
            Ok(PushTarget::Own("job1".to_owned()))
        );
        assert_eq!(PushTarget::Own("job1".to_owned()).branch(), "swarm/job1");
    }

    #[test]
    fn a_fix_job_targets_the_chain_root_branch() {
        let target = PushTarget::from_job(&fix_job("fixjob", "swarm/rootjob"));
        assert_eq!(target, Ok(PushTarget::Chain("rootjob".to_owned())));
        assert_eq!(target.map(|t| t.branch()), Ok("swarm/rootjob".to_owned()));
    }

    #[test]
    fn a_job_with_no_valid_target_is_refused() {
        let long = "a".repeat(65);
        for bad in [
            fix_job("fixjob", "main"),
            fix_job("fixjob", "swarm/"),
            fix_job("fixjob", "swarm/a/b"),
            fix_job("fixjob", "swarm/../x"),
            fix_job("fixjob", &format!("swarm/{long}")),
            fix_job("fixjob", "refs/heads/swarm/x"),
            job(""),
            job("a/b"),
            job("a b"),
            job(&long),
        ] {
            assert_eq!(PushTarget::from_job(&bad), Err(BrokerError::Target));
        }
    }

    #[test]
    fn the_direct_launcher_gets_no_broker() {
        let fake = Fake::default();
        let built = Broker::new(
            AgentLauncher::Direct,
            &job("job1"),
            fake.clone(),
            fake,
            Redactor::new([SECRET]),
        );
        assert_eq!(built.err(), Some(BrokerError::DirectLauncher));
    }

    #[test]
    fn a_bad_target_fails_construction_under_systemd() {
        let fake = Fake::default();
        assert_eq!(
            broker_for(&job("a/b"), &fake).err(),
            Some(BrokerError::Target)
        );
    }

    #[tokio::test]
    async fn push_and_pr_checks_use_the_target_of_the_job() -> TestResult {
        let fake = Fake {
            output: "ok".to_owned(),
            ..Fake::default()
        };
        let own = broker(&fake)?;
        assert_eq!(
            own.handle(Request::Push {}).await,
            Response::Done {
                output: "ok".to_owned()
            }
        );
        own.handle(pr("t", "b")).await;
        own.record_pr_url(PR_URL);
        own.handle(Request::PrChecks {}).await;
        assert_eq!(
            fake.calls(),
            [
                "push swarm/job1",
                "pr_create swarm/job1 t b",
                format!("pr_checks swarm/job1 {PR_URL}").as_str()
            ]
        );

        let chain_fake = Fake::default();
        let chain = broker_for(&fix_job("fixjob", "swarm/rootjob"), &chain_fake)?;
        chain.handle(Request::Push {}).await;
        chain.handle(pr("t", "b")).await;
        assert_eq!(
            chain_fake.calls(),
            ["push swarm/rootjob", "pr_create swarm/rootjob t b"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_frame_with_a_branch_never_reaches_an_executor() -> TestResult {
        let fake = Fake::default();
        let b = broker(&fake)?;
        let reply = b.handle_frame(br#"{"op":"push","branch":"main"}"#).await;
        assert_eq!(reply, denied(Denial::InvalidRequest));
        assert_eq!(fake.calls(), Vec::<String>::new());
        assert_eq!(
            b.handle_frame(br#"{"op":"fetch"}"#).await,
            Response::Done {
                output: String::new()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn pushes_are_capped_per_job_and_failures_count() -> TestResult {
        let fake = Fake {
            fail: true,
            ..Fake::default()
        };
        let b = broker(&fake)?;
        for _ in 0..MAX_PUSHES_PER_JOB {
            assert_eq!(b.handle(Request::Push {}).await, denied(Denial::Failed));
        }
        assert_eq!(b.handle(Request::Push {}).await, denied(Denial::CapReached));
        assert_eq!(fake.calls().len(), MAX_PUSHES_PER_JOB as usize);
        Ok(())
    }

    #[tokio::test]
    async fn one_pr_per_job_even_after_a_failure() -> TestResult {
        let fake = Fake {
            fail: true,
            ..Fake::default()
        };
        let b = broker(&fake)?;
        assert_eq!(b.handle(pr("t", "b")).await, denied(Denial::Failed));
        assert_eq!(b.handle(pr("t", "b")).await, denied(Denial::CapReached));
        assert_eq!(fake.calls().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_pr_creates_run_once() -> TestResult {
        let fake = Fake {
            output: "url".to_owned(),
            ..Fake::default()
        };
        let b = broker(&fake)?;
        let (a, c) = tokio::join!(b.handle(pr("t", "b")), b.handle(pr("t", "b")));
        let capped = usize::from(a == denied(Denial::CapReached))
            + usize::from(c == denied(Denial::CapReached));
        assert_eq!(capped, 1);
        assert_eq!(fake.calls().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn read_ops_run_up_to_their_own_cap_and_no_further() -> TestResult {
        let fake = Fake::default();
        let b = with_url(broker(&fake)?.with_limits(Limits {
            max_pr_checks: 3,
            max_fetches: 2,
            ..unpaced()
        }));
        for _ in 0..3 {
            assert!(matches!(
                b.handle(Request::PrChecks {}).await,
                Response::Done { .. }
            ));
        }
        for _ in 0..2 {
            assert!(matches!(
                b.handle(Request::Fetch {}).await,
                Response::Done { .. }
            ));
        }
        assert_eq!(
            b.handle(Request::PrChecks {}).await,
            denied(Denial::CapReached)
        );
        assert_eq!(
            b.handle(Request::Fetch {}).await,
            denied(Denial::CapReached)
        );
        assert_eq!(fake.calls().len(), 5);
        Ok(())
    }

    #[test]
    fn the_default_limits_are_the_documented_constants() {
        assert_eq!(
            Limits::default(),
            Limits {
                max_pr_checks: MAX_PR_CHECKS_PER_JOB,
                pr_checks_interval: MIN_PR_CHECKS_INTERVAL,
                max_fetches: MAX_FETCHES_PER_JOB,
                fetch_interval: MIN_FETCH_INTERVAL,
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_op_inside_its_interval_is_rate_limited_and_spends_no_cap() -> TestResult {
        let fake = Fake::default();
        let b = with_url(broker(&fake)?);
        assert!(matches!(
            b.handle(Request::Fetch {}).await,
            Response::Done { .. }
        ));
        for _ in 0..(MAX_FETCHES_PER_JOB + 3) {
            assert_eq!(
                b.handle(Request::Fetch {}).await,
                denied(Denial::RateLimited)
            );
        }
        tokio::time::advance(MIN_FETCH_INTERVAL.saturating_sub(Duration::from_millis(1))).await;
        assert_eq!(
            b.handle(Request::Fetch {}).await,
            denied(Denial::RateLimited)
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            b.handle(Request::Fetch {}).await,
            Response::Done { .. }
        ));
        assert!(matches!(
            b.handle(Request::PrChecks {}).await,
            Response::Done { .. }
        ));
        assert_eq!(
            b.handle(Request::PrChecks {}).await,
            denied(Denial::RateLimited)
        );
        tokio::time::advance(MIN_PR_CHECKS_INTERVAL).await;
        assert!(matches!(
            b.handle(Request::PrChecks {}).await,
            Response::Done { .. }
        ));
        assert_eq!(fake.calls().len(), 4);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_op_still_spends_its_slot_and_its_interval() -> TestResult {
        let fake = Fake {
            fail: true,
            ..Fake::default()
        };
        let b = broker(&fake)?;
        assert_eq!(b.handle(Request::Fetch {}).await, denied(Denial::Failed));
        assert_eq!(
            b.handle(Request::Fetch {}).await,
            denied(Denial::RateLimited)
        );
        Ok(())
    }

    #[tokio::test]
    async fn pr_checks_before_a_recorded_pull_request_is_refused_without_a_call() -> TestResult {
        let fake = Fake::default();
        let b = broker(&fake)?;
        for _ in 0..3 {
            assert_eq!(
                b.handle(Request::PrChecks {}).await,
                denied(Denial::NoPullRequest)
            );
        }
        assert_eq!(fake.calls(), Vec::<String>::new());
        assert_eq!(
            b.handle(Request::PrChecks {}).await,
            denied(Denial::NoPullRequest),
            "a refused call must not spend the interval"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pr_checks_uses_the_url_the_pr_create_reply_recorded() -> TestResult {
        let fake = Fake {
            output: format!("Creating pull request\n{PR_URL}\n"),
            ..Fake::default()
        };
        let b = broker(&fake)?;
        b.handle(pr("t", "b")).await;
        b.handle(Request::PrChecks {}).await;
        assert_eq!(
            fake.calls(),
            [
                "pr_create swarm/job1 t b".to_owned(),
                format!("pr_checks swarm/job1 {PR_URL}")
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_pr_create_reply_that_is_not_one_plain_https_url_records_nothing() -> TestResult {
        let long = format!(
            "https://github.com/o/r/pull/{}",
            "1".repeat(MAX_PR_URL_BYTES)
        );
        for output in [
            "ok",
            "",
            "http://github.com/o/r/pull/1",
            "https://github.com/o/r/pull/1 extra",
            "https://user@github.com/o/r/pull/1",
            "https://github.com/o\\r/pull/1",
            "javascript:alert(1)",
            long.as_str(),
        ] {
            let fake = Fake {
                output: output.to_owned(),
                ..Fake::default()
            };
            let b = broker(&fake)?;
            b.handle(pr("t", "b")).await;
            assert_eq!(
                b.handle(Request::PrChecks {}).await,
                denied(Denial::NoPullRequest),
                "{output}"
            );
        }
        Ok(())
    }

    #[derive(Clone, Default)]
    struct Overlap {
        running: Arc<Mutex<(u32, u32)>>,
    }

    impl GitExecutor for Overlap {
        fn push(
            &self,
            _target: &PushTarget,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            std::future::ready(Err(ExecError))
        }

        fn fetch(&self) -> impl Future<Output = Result<String, ExecError>> + Send {
            let running = Arc::clone(&self.running);
            async move {
                {
                    let mut state = running.lock().unwrap_or_else(PoisonError::into_inner);
                    state.0 += 1;
                    state.1 = state.1.max(state.0);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                running.lock().unwrap_or_else(PoisonError::into_inner).0 -= 1;
                Ok(String::new())
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_fetches_of_one_job_run_one_at_a_time() -> TestResult {
        let overlap = Overlap::default();
        let b = Broker::new(
            AgentLauncher::Systemd,
            &job("job1"),
            overlap.clone(),
            Fake::default(),
            Redactor::new([SECRET]),
        )?
        .with_limits(unpaced());
        let replies = tokio::join!(
            b.handle(Request::Fetch {}),
            b.handle(Request::Fetch {}),
            b.handle(Request::Fetch {})
        );
        for reply in [replies.0, replies.1, replies.2] {
            assert!(matches!(reply, Response::Done { .. }));
        }
        assert_eq!(overlap.running.lock().map(|s| s.1).ok(), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn title_and_body_limits_hold_and_invalid_input_spends_no_cap() -> TestResult {
        let fake = Fake::default();
        let b = broker(&fake)?;
        let bad = [
            pr(&"a".repeat(MAX_TITLE_CHARS + 1), "b"),
            pr(&"\u{e9}".repeat(MAX_TITLE_CHARS + 1), "b"),
            pr("", "b"),
            pr("   ", "b"),
            pr("two\nlines", "b"),
            pr("t", &"a".repeat(MAX_BODY_BYTES + 1)),
            pr("t", "bell\u{7}"),
        ];
        for request in bad {
            assert_eq!(b.handle(request).await, denied(Denial::InvalidRequest));
        }
        assert_eq!(fake.calls(), Vec::<String>::new());
        let edge = pr(
            &"\u{e9}".repeat(MAX_TITLE_CHARS),
            &"a".repeat(MAX_BODY_BYTES),
        );
        assert!(matches!(b.handle(edge).await, Response::Done { .. }));
        assert_eq!(fake.calls().len(), 1);
        Ok(())
    }

    #[test]
    fn attribution_detection_covers_separators_and_decorations() {
        let attributed = [
            "text\rCo-Authored-By: X",
            "text\r\nCo-Authored-By: X",
            "text\u{85}Co-Authored-By: X",
            "text\u{2028}Co-Authored-By: X",
            "text\u{2029}Signed-off-by: X",
            "> Co-authored-by: X",
            "- Signed-off-by: X",
            "* Claude-Session: https://x.test",
            "# Co-Authored-By: X",
            "fix\n\n>   - * # CO-AUTHORED-BY: X",
            "fix\r\r- signed-OFF-by: X",
            "fix\n  > # * Claude-Session: s",
        ];
        for text in attributed {
            assert!(has_attribution(text), "{text:?}");
        }
        let benign = [
            "fix the parser",
            "- bullet one\n- bullet two",
            "> quoted reply\r\n# heading\n* item",
            "add co-authored handling",
            "line one\rline two\u{2028}line three",
        ];
        for text in benign {
            assert!(!has_attribution(text), "{text:?}");
        }
        assert!(!valid_body("text\rCo-Authored-By: X"));
    }

    #[test]
    fn attribution_skeleton_ignores_hidden_and_decorative_characters() {
        let attributed = [
            "fix\n\u{200b}Co-Authored-By: X",
            "fix\n\u{feff}Signed-off-by: X",
            "fix\n\u{2060}Claude-Session: s",
            "fix\nCo\u{ad}-Authored-By: X",
            "fix\n+ Co-Authored-By: X",
            "fix\n1. Co-Authored-By: X",
            "fix\n\u{2022} Co-Authored-By: X",
            "fix\n`Co-Authored-By: X`",
            "fix\n_Co-Authored-By: X_",
            "fix\n[Co-Authored-By: X]",
            "fix\n(Co-Authored-By: X)",
            "fix\n| Co-Authored-By: X |",
            "fix\n~Co-Authored-By: X",
            "fix\n\"Signed-off-by: X\"",
            "fix\n<!-- Co-Authored-By: X",
            "fix\n\u{1f916} Co-Authored-By: X",
            "fix\nCO-aUtHoReD-bY: X",
            "fix\nGenerated  with Claude Code",
            "fix\ngenerated\u{200b} with claude",
            "fix\nsee claude.ai\u{200b}/code/s",
            "fix\nsee Claude.AI / Code",
            "fix\n\u{1f916} Generated by Claude",
            "fix\nGenerated with Claude\u{3164} Code",
            "fix\nGenerated with Claude\u{115f}\u{1160} Code",
            "fix\nsee claude.ai\u{3164}/code/s",
            "fix\nsee claude.ai\u{ffa0}/code/s",
            "fix\nCo\u{3164}-Authored-By: X",
            "fix\nSigned\u{115f}-off-by: X",
            "fix\nCo authored by: X",
            "fix\nco\u{200d}-authored-by: X",
        ];
        for text in attributed {
            assert!(has_attribution(text), "{text:?}");
            assert!(!valid_body(text), "{text:?}");
        }
        let benign = [
            "Refactor the parser and add tests.",
            "This was generated from the schema",
            "generated",
            "we mention co-authored work mid-sentence",
            "signed off later by the team",
            "1. first step\n2. second step",
            "Claude session timeout fix",
            "Signed off by default",
            "Co-authored handling: add tests",
            "Signed-off-by-default: true",
        ];
        for text in benign {
            assert!(!has_attribution(text), "{text:?}");
            assert!(valid_body(text), "{text:?}");
        }
    }

    #[test]
    fn skeleton_folds_kelvin_and_drops_non_ascii() {
        assert_eq!(skeleton("\u{212a}x\u{3164}-9"), "kx9");
    }

    #[test]
    fn hidden_text_characters_are_refused_in_title_and_body() {
        for c in [
            '\u{202a}',
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{e0000}',
            '\u{e0041}',
            '\u{e007f}',
        ] {
            assert!(!valid_title(&format!("a{c}b")), "{c:?}");
            assert!(!valid_body(&format!("a{c}b")), "{c:?}");
        }
        assert!(valid_title("plain title"));
    }

    #[test]
    fn legitimate_format_characters_are_accepted() {
        let texts = [
            "family \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467} emoji",
            "\u{645}\u{6cc}\u{200c}\u{62e}\u{648}\u{627}\u{647}\u{645} persian",
            "left\u{200e}right\u{200f}mark",
            "arabic\u{61c}letter",
        ];
        for text in texts {
            assert!(valid_title(text), "{text:?}");
            assert!(valid_body(text), "{text:?}");
        }
    }

    #[tokio::test]
    async fn attribution_lines_are_refused_in_title_and_body() -> TestResult {
        let fake = Fake::default();
        let b = broker(&fake)?;
        for text in [
            "Co-Authored-By: Someone <a@b.c>",
            "  co-authored-by: x",
            "Signed-off-by: x",
            "Claude-Session: https://example.test/s",
            "see https://claude.ai/code/session_1",
            "\u{1f916} Generated with [Claude Code](https://x.test)",
            "generated with Claude",
            "Generated by Claude",
        ] {
            assert_eq!(
                b.handle(pr("t", &format!("fix\n\n{text}"))).await,
                denied(Denial::InvalidRequest),
                "{text}"
            );
            if !text.contains('\u{1f916}') {
                assert_eq!(
                    b.handle(pr(text, "b")).await,
                    denied(Denial::InvalidRequest),
                    "{text}"
                );
            }
        }
        assert_eq!(fake.calls(), Vec::<String>::new());
        assert!(matches!(
            b.handle(pr("fix(x): add co-authored handling", "b")).await,
            Response::Done { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn secrets_are_redacted_going_in_and_coming_out() -> TestResult {
        let fake = Fake {
            output: format!("https://example.test/pr/1 {SECRET}"),
            ..Fake::default()
        };
        let b = broker(&fake)?;
        let reply = b
            .handle(pr(&format!("t {SECRET}"), &format!("b {SECRET}")))
            .await;
        assert_eq!(
            reply,
            Response::Done {
                output: "https://example.test/pr/1 [REDACTED]".to_owned()
            }
        );
        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(!calls.join(" ").contains(SECRET));
        Ok(())
    }

    #[tokio::test]
    async fn output_is_cut_on_a_char_boundary() -> TestResult {
        let fake = Fake {
            output: "\u{e9}".repeat(MAX_OUTPUT_BYTES),
            ..Fake::default()
        };
        let b = broker(&fake)?;
        let Response::Done { output } = b.handle(Request::Fetch {}).await else {
            return Err("not done".into());
        };
        assert_eq!(output.len(), MAX_OUTPUT_BYTES);
        assert!(output.chars().all(|c| c == '\u{e9}'));
        Ok(())
    }

    #[tokio::test]
    async fn executor_failures_reply_with_a_fixed_message() -> TestResult {
        let fake = Fake {
            fail: true,
            ..Fake::default()
        };
        let b = broker(&fake)?;
        let reply = b.handle(Request::Fetch {}).await;
        assert_eq!(
            serde_json::to_string(&reply)?,
            r#"{"status":"denied","error":"failed","message":"operation failed"}"#
        );
        Ok(())
    }

    #[tokio::test]
    async fn done_replies_serialize_with_status_and_output() -> TestResult {
        let reply = Response::Done {
            output: "x".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&reply)?,
            r#"{"status":"done","output":"x"}"#
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn every_op_times_out_with_a_fixed_error() -> TestResult {
        let fake = Fake {
            hang: true,
            ..Fake::default()
        };
        let b = with_url(broker(&fake)?.with_limits(unpaced()));
        for request in [
            Request::Push {},
            pr("t", "b"),
            Request::PrChecks {},
            Request::Fetch {},
        ] {
            assert_eq!(b.handle(request).await, denied(Denial::TimedOut));
        }
        Ok(())
    }

    #[test]
    fn timeouts_are_bounded() {
        for timeout in [
            PUSH_TIMEOUT,
            PR_CREATE_TIMEOUT,
            PR_CHECKS_TIMEOUT,
            FETCH_TIMEOUT,
        ] {
            assert!(timeout > Duration::ZERO && timeout <= Duration::from_secs(120));
        }
    }
}
