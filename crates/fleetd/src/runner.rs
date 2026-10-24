//! Runs `claude -p` for a claimed job and streams its output through `ReportJob`.
//!
//! The agent runs as a child in its own process group with a scrubbed environment. Every
//! stdout line is redacted, then sent as a transcript chunk. A report goes out when 64 KiB
//! of chunks are pending, every flush interval while chunks wait, and at least every
//! report interval even when the agent is silent, so the server lease cannot lapse on a
//! quiet agent. The reply of a report is not inspected here.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest, TranscriptChunk};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::{Instant, MissedTickBehavior, Sleep};
use tonic::Status;

use crate::group::GroupGuard;
use crate::now_ms;
use crate::poller::{RunError, Shutdown};

/// Variables that never reach the agent.
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

/// Default hard limit on one agent run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Default time between report attempts while chunks are pending.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Default longest gap between reports, silent agent or not.
pub const DEFAULT_REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// Default longest wait for the terminal report after a run ends.
pub const DEFAULT_TERMINAL_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

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

const PHASE: &str = "agent";
const ERR_START: &str = "agent could not start";
const ERR_EXIT: &str = "agent exited with a failure status";
const ERR_SIGNAL: &str = "agent was killed by a signal";
const ERR_TIMEOUT: &str = "agent timed out";
const ERR_SHUTDOWN: &str = "agent stopped by daemon shutdown";
const ERR_WAIT: &str = "agent could not be awaited";

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
    /// True when the box is disposable. Only then the agent runs with permission checks off.
    pub disposable: bool,
    /// Hard limit on the run. The process group is killed when it passes.
    pub timeout: Duration,
    /// Time between report attempts while chunks wait.
    pub flush_interval: Duration,
    /// Longest gap between reports.
    pub report_interval: Duration,
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
            disposable,
            timeout: DEFAULT_TIMEOUT,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            report_interval: DEFAULT_REPORT_INTERVAL,
            terminal_report_timeout: DEFAULT_TERMINAL_REPORT_TIMEOUT,
            base_env: std::env::vars_os().collect(),
        }
    }
}

/// How an agent run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentOutcome {
    /// The agent exited with status 0. The caller finishes the job.
    Succeeded,
    /// The run failed and a terminal `FAILED` report was attempted.
    Failed {
        /// The exit status, absent when the agent was killed or never started.
        exit_code: Option<i32>,
        /// A fixed description of the failure.
        error: &'static str,
    },
}

/// Runs the agent for claimed jobs.
#[derive(Debug)]
pub struct AgentRunner<R> {
    config: RunConfig,
    reporter: R,
    redactor: Redactor,
}

impl<R: Reporter> AgentRunner<R> {
    /// A runner that reports through `reporter` and redacts with `redactor`.
    pub fn new(config: RunConfig, reporter: R, redactor: Redactor) -> Self {
        Self {
            config,
            reporter,
            redactor,
        }
    }

    /// Runs `claude -p <prompt> --output-format stream-json --verbose` in `cwd`.
    ///
    /// The child gets no stdin, its own process group, `FLEET_JOB_ID` and `SWARM_BOX=1`.
    /// It gets `--dangerously-skip-permissions` only when the config marks the box
    /// disposable. Exit 0 is [`AgentOutcome::Succeeded`]. A nonzero exit, a signal, a
    /// start failure or the timeout sends a terminal `FAILED` report and returns
    /// [`AgentOutcome::Failed`]. The whole process group is killed on every exit path, so
    /// no background descendant outlives the run. Every report is raced against the
    /// deadline and shutdown, and the terminal report waits at most
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
        let mut stream = Stream::new(&self.reporter, job, self.config.terminal_report_timeout);
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
            .drive(&mut child, stdout, &mut guard, &mut stream, &mut ctl)
            .await;
        guard.kill();
        let _ = child.wait().await;
        match end {
            Ok(status) => match status.code() {
                Some(0) => Ok(AgentOutcome::Succeeded),
                Some(code) => Ok(stream.fail(Some(code), ERR_EXIT).await),
                None => Ok(stream.fail(None, ERR_SIGNAL).await),
            },
            Err(End::Timeout) => Ok(stream.fail(None, ERR_TIMEOUT).await),
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
                    } else if stream.pending_bytes >= FLUSH_BYTES {
                        stream.flush(ctl).await?;
                    }
                }
                waited = child.wait(), if status.is_none() => {
                    guard.kill();
                    status = Some(waited);
                }
                _ = tick.tick() => stream.beat(self.config.report_interval, ctl).await?,
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

enum End {
    Timeout,
    Shutdown,
    Wait,
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

struct Stream<'a, R> {
    reporter: &'a R,
    job: &'a Job,
    pending: VecDeque<TranscriptChunk>,
    pending_bytes: usize,
    next_seq: u64,
    progress: String,
    last_report: Instant,
    terminal_timeout: Duration,
}

impl<'a, R: Reporter> Stream<'a, R> {
    fn new(reporter: &'a R, job: &'a Job, terminal_timeout: Duration) -> Self {
        Self {
            reporter,
            job,
            pending: VecDeque::new(),
            pending_bytes: 0,
            next_seq: 1,
            progress: String::new(),
            last_report: Instant::now(),
            terminal_timeout,
        }
    }

    fn push(&mut self, redactor: &Redactor, line: &str) {
        let clean = redactor.redact_str(line);
        if let Some(text) = assistant_text(&clean) {
            self.progress = text.chars().take(MAX_PROGRESS_CHARS).collect();
        }
        let mut text = clean.into_owned();
        text.push('\n');
        cut(&mut text, MAX_CHUNK_BYTES);
        self.pending_bytes += text.len();
        self.pending.push_back(TranscriptChunk {
            seq: self.next_seq,
            ts_ms: now_ms(),
            text,
            truncated: false,
        });
        self.next_seq += 1;
        while self.pending_bytes > MAX_BUFFER_BYTES {
            match self.pending.pop_front() {
                Some(dropped) => self.pending_bytes -= dropped.text.len(),
                None => break,
            }
        }
    }

    async fn beat(&mut self, report_interval: Duration, ctl: &mut Ctl) -> Result<(), Stop> {
        if !self.pending.is_empty() || self.last_report.elapsed() >= report_interval {
            self.flush(ctl).await?;
        }
        Ok(())
    }

    async fn flush(&mut self, ctl: &mut Ctl) -> Result<(), Stop> {
        ctl.race(self.send_pending()).await
    }

    async fn send_pending(&mut self) {
        loop {
            let count = self.batch_len();
            let chunks: Vec<_> = self.pending.iter().take(count).cloned().collect();
            let request = self.request(chunks);
            match self.reporter.report(request).await {
                Ok(_) => {
                    for dropped in self.pending.drain(..count) {
                        self.pending_bytes -= dropped.text.len();
                    }
                    self.last_report = Instant::now();
                    if self.pending.is_empty() {
                        return;
                    }
                }
                Err(status) => {
                    tracing::warn!(code = ?status.code(), "job report failed");
                    return;
                }
            }
        }
    }

    fn batch_len(&self) -> usize {
        let mut bytes = 0;
        let mut count = 0;
        for chunk in &self.pending {
            if count > 0 && bytes + chunk.text.len() > MAX_REQUEST_BYTES {
                break;
            }
            bytes += chunk.text.len();
            count += 1;
        }
        count
    }

    fn request(&self, chunks: Vec<TranscriptChunk>) -> ReportJobRequest {
        ReportJobRequest {
            job_id: self.job.job_id.clone(),
            attempt: self.job.attempt,
            r#box: self.job.r#box.clone(),
            phase: PHASE.to_owned(),
            progress: self.progress.clone(),
            chunks,
            ..ReportJobRequest::default()
        }
    }

    async fn fail(&mut self, exit_code: Option<i32>, error: &'static str) -> AgentOutcome {
        let bound = self.terminal_timeout;
        if tokio::time::timeout(bound, self.send_terminal(exit_code, error))
            .await
            .is_err()
        {
            tracing::warn!("job failure report timed out");
        }
        AgentOutcome::Failed { exit_code, error }
    }

    async fn send_terminal(&mut self, exit_code: Option<i32>, error: &'static str) {
        self.send_pending().await;
        let mut request = self.request(Vec::new());
        request.terminal_state = Some(JobState::Failed.into());
        request.error = Some(error.to_owned());
        request.exit_code = exit_code;
        if let Err(status) = self.reporter.report(request).await {
            tracing::warn!(code = ?status.code(), "job failure report failed");
        }
    }
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

fn cut(text: &mut String, max: usize) {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
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
