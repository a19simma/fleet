//! Background command timing, measured from pueue.
//!
//! A [`BgWatcher`] never reads command text. It takes the highest pueue task id at job start
//! as a baseline, then polls `pueue status --json` through a [`PueueClient`] and tracks every
//! task whose id is above the baseline. Pueue's own timestamps give start and end. When they
//! are missing or contradict each other, the watcher falls back to its own monotonic clock,
//! anchored at the job start.
//!
//! Each pueue state has one rule, listed in [`rule`]. `Done` is terminal and closes the task
//! with its log. The other states are open: when the job exits, the deadline passes, polling
//! fails [`MAX_POLL_ERRORS`] times in a row or the task vanishes from the status, the task is
//! closed with the matching [`EndedBy`].
//!
//! Log text is untrusted. It is read with a byte cap larger than the output cap. The whole read
//! is redacted first, so a secret that straddles the output cap is replaced whole. A cut read
//! then loses its last [`LOG_TAIL_GUARD`] bytes, so a secret split by the read cap leaves no
//! fragment. The text is passed through the
//! [`ShellRecorder`](crate::shell_timing::ShellRecorder) (strip, redaction, strip again, then
//! cut). The strip drops NUL, control, format, line and paragraph separator and tag characters
//! other than newline and tab, so none can split a secret past the redactor.
//!
//! A [`LogPusher`] tails the same tasks live. Per task it reads the log, redacts the whole read
//! first, strips the same characters before and after redaction, and only then cuts chunks of at most
//! [`MAX_SHELL_LOG_CHUNK_BYTES`] bytes. Each cut lands on a `char` boundary at or below the
//! cap, so no chunk splits a UTF-8 character. While a task runs, the last [`LOG_TAIL_GUARD`]
//! bytes of the redacted text are held back, so a secret still being written is never sent as
//! a fragment; the guard has the same bound as above and a longer secret is a documented
//! residual. Chunks go out through a [`LogReporter`] under a token budget on an injected
//! `now`, and a task stops at [`MAX_SHELL_LOG_CHUNKS`] chunks with a final `Failed` report
//! because the wire has no truncation status.
//!
//! `pueue log --lines` returns a sliding window, so a reader cannot index a byte offset into a
//! read that may have lost its head, and a multi-line secret whose first lines fell out of the
//! window no longer matches the [`Redactor`]. Every caller reads through one checked fetch,
//! [`LogFetch`], which counts lines on the full pueue output before any byte truncation. Ways
//! the head can go missing and how each is covered:
//!
//! - Line cap: [`LOG_LINES`] or more lines sets `head_may_be_lost`, also when the byte cap
//!   then cuts the text below that count.
//! - Byte cap: the cap cuts the tail and keeps the head, so it loses no head; the tail guard
//!   covers a secret it splits.
//! - Rotation, `pueue clean` or `pueue reset` after bytes went out: the head hash of the sent
//!   bytes no longer matches, or the text is shorter than what was sent.
//! - The same events before any byte went out leave no line-count or hash signal: a log
//!   restarted below [`LOG_LINES`] lines is an undetectable residual.
//! - A shifted window whose text still starts with the bytes already sent passes the hash
//!   check, so identical repeated lines can hide the shift.
//!
//! The pusher fails the task closed on any of these: one empty `Failed` chunk, then no more
//! pushes. The watcher withholds the log and reports [`HEAD_LOST_MARKER`] instead.
//!
//! Limit: pueue reuses ids after `pueue reset`, so a task created after a reset with an id at or
//! below the baseline is not seen. The watcher polls as the uid of its [`PueueClient`]; the
//! caller chooses that uid when it builds the client.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_core::text::{Cap, sanitise_lines};
use fleet_proto::{
    MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SHELL_LOG_CHUNK_BYTES, MAX_SHELL_LOG_CHUNKS, v1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::time::Instant;

use crate::shell_timing::{ShellInput, ShellRecord, ShellRecorder};

/// Default pause between status polls.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Default longest a watch runs before it closes every open task.
pub const WATCH_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);
/// Longest one client call may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Consecutive failed polls after which the watch stops.
pub const MAX_POLL_ERRORS: u32 = 5;
/// Most tasks tracked at once.
pub const MAX_TRACKED_TASKS: usize = MAX_SHELL_COMMANDS;
/// Bytes dropped from the end of a cut read after redaction, so a secret split by the read cap
/// leaves no fragment.
///
/// The [`Redactor`] states no longest secret: [`fleet_core::MIN_SECRET_LEN`] is a floor and
/// its values come from an env file with no upper bound. The guard is therefore the bound this
/// module enforces: a secret of at most `LOG_TAIL_GUARD + 1` bytes that the read cap splits
/// leaves a fragment shorter than the guard, and the guard removes it. 4096 bytes holds a
/// 4096-bit RSA private key in PEM form (about 3.2 KiB). A longer secret is outside the bound.
pub const LOG_TAIL_GUARD: usize = 4096;
/// Most log bytes read for one task.
pub const LOG_READ_CAP: usize = MAX_SHELL_LOG_BYTES + 1 + LOG_TAIL_GUARD;
/// Most bytes read from `pueue status --json`.
pub const STATUS_READ_CAP: usize = 4 * 1024 * 1024;
/// Most bytes read from `pueue log --json` for one task, envelope included.
pub const LOG_JSON_CAP: usize = 1024 * 1024;
const MAX_WALL_MS: u64 = i64::MAX as u64;
/// Most trailing log lines requested from pueue.
pub const LOG_LINES: usize = 1000;

/// Why a pueue call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PueueError {
    /// The command could not be spawned.
    Spawn,
    /// The spawned command gave no stdout pipe.
    NoStdout,
    /// Reading the command's stdout failed before the cap was crossed.
    Read,
    /// The command exited with a failure.
    Status,
    /// The reply exceeded its byte cap.
    TooLarge,
    /// The reply was not the expected JSON.
    Parse,
    /// The call exceeded [`CALL_TIMEOUT`].
    Timeout,
}

impl fmt::Display for PueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Spawn => "pueue could not be spawned",
            Self::NoStdout => "pueue gave no stdout pipe",
            Self::Read => "reading pueue output failed",
            Self::Status => "pueue exited with a failure",
            Self::TooLarge => "pueue reply is too large",
            Self::Parse => "pueue reply is not valid",
            Self::Timeout => "pueue call timed out",
        })
    }
}

impl std::error::Error for PueueError {}

/// Text reported in place of a log whose head pueue's window may have dropped.
pub const HEAD_LOST_MARKER: &str = "[log withheld: pueue window may have dropped its start]";

/// One checked read of a task log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFetch {
    /// At most the requested number of bytes of the output.
    pub bytes: Vec<u8>,
    /// Whether pueue's line window may have dropped the start of the output.
    pub head_may_be_lost: bool,
}

impl LogFetch {
    /// Counts the lines of `full` before cutting it to `max_bytes` bytes.
    #[must_use]
    pub fn checked(mut full: Vec<u8>, max_bytes: usize) -> Self {
        let head_may_be_lost = line_count(&full) >= LOG_LINES;
        full.truncate(max_bytes);
        Self {
            bytes: full,
            head_may_be_lost,
        }
    }
}

async fn fetch_checked<C: PueueClient>(
    client: &C,
    id: u64,
    max_bytes: usize,
    timeout: Duration,
) -> Option<LogFetch> {
    tokio::time::timeout(timeout, client.log(id, max_bytes))
        .await
        .ok()?
        .ok()
}

/// The two pueue reads the watcher needs.
pub trait PueueClient: Send + Sync {
    /// The text of `pueue status --json`.
    fn status_json(&self) -> impl Future<Output = Result<String, PueueError>> + Send;

    /// At most `max_bytes` bytes of the output of task `id`, with the window check made on
    /// the full output; build it with [`LogFetch::checked`].
    fn log(
        &self,
        id: u64,
        max_bytes: usize,
    ) -> impl Future<Output = Result<LogFetch, PueueError>> + Send;
}

/// Runs the `pueue` binary with a fixed environment.
#[derive(Debug, Clone)]
pub struct PueueCli {
    bin: PathBuf,
    env: Vec<(String, String)>,
}

impl PueueCli {
    /// Builds a client for `bin`. The child gets only `env`.
    #[must_use]
    pub fn new(bin: impl Into<PathBuf>, env: Vec<(String, String)>) -> Self {
        Self {
            bin: bin.into(),
            env,
        }
    }

    async fn run(&self, args: &[String], cap: usize) -> Result<Vec<u8>, PueueError> {
        let mut child = Command::new(&self.bin)
            .args(args)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| PueueError::Spawn)?;
        let stdout = child.stdout.take().ok_or(PueueError::NoStdout)?;
        collect(&mut child, stdout, cap).await
    }
}

async fn collect<R: AsyncRead + Unpin>(
    child: &mut Child,
    stdout: R,
    cap: usize,
) -> Result<Vec<u8>, PueueError> {
    let mut out = Vec::new();
    let read_ok = read_capped(stdout, cap, &mut out).await;
    if out.len() > cap || !read_ok {
        let _ = child.start_kill();
    }
    let status = child.wait().await;
    verdict(out.len(), cap, read_ok, status.is_ok_and(|s| s.success()))?;
    Ok(out)
}

async fn read_capped<R: AsyncRead + Unpin>(reader: R, cap: usize, out: &mut Vec<u8>) -> bool {
    reader.take(cap as u64 + 1).read_to_end(out).await.is_ok()
}

fn verdict(len: usize, cap: usize, read_ok: bool, exited_ok: bool) -> Result<(), PueueError> {
    if len > cap {
        return Err(PueueError::TooLarge);
    }
    if !read_ok {
        return Err(PueueError::Read);
    }
    if !exited_ok {
        return Err(PueueError::Status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PueueCli, PueueError, STATUS_READ_CAP, collect, read_capped, verdict};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    struct FailAfter {
        left: usize,
    }

    impl AsyncRead for FailAfter {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.left == 0 {
                return Poll::Ready(Err(io::Error::other("boom")));
            }
            let n = self.left.min(buf.remaining());
            buf.put_slice(&vec![b'y'; n]);
            self.left -= n;
            Poll::Ready(Ok(()))
        }
    }

    async fn judge(fail_after: usize, cap: usize) -> Result<(), PueueError> {
        let mut out = Vec::new();
        let read_ok = read_capped(FailAfter { left: fail_after }, cap, &mut out).await;
        verdict(out.len(), cap, read_ok, true)
    }

    #[tokio::test]
    async fn a_read_failure_under_the_cap_is_a_read_error() {
        assert_eq!(judge(5, 10).await, Err(PueueError::Read));
    }

    #[tokio::test]
    async fn a_read_failure_after_the_cap_is_too_large() {
        assert_eq!(judge(11, 10).await, Err(PueueError::TooLarge));
        assert_eq!(judge(50, 10).await, Err(PueueError::TooLarge));
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["-c".to_owned(), script.to_owned()]
    }

    #[tokio::test]
    async fn a_child_that_floods_stdout_is_too_large() {
        let cli = PueueCli::new("/bin/sh", Vec::new());
        let got = cli.run(&sh("exec yes"), STATUS_READ_CAP).await;
        assert_eq!(got.err(), Some(PueueError::TooLarge));
    }

    #[tokio::test]
    async fn a_child_that_exits_with_a_failure_is_a_status_error() {
        let cli = PueueCli::new("/bin/sh", Vec::new());
        let got = cli.run(&sh("echo partial; exit 3"), STATUS_READ_CAP).await;
        assert_eq!(got.err(), Some(PueueError::Status));
    }

    #[tokio::test]
    async fn a_child_that_closes_stdout_and_exits_later_with_success_is_ok() {
        let cli = PueueCli::new("/bin/sh", Vec::new());
        let got = cli
            .run(&sh("echo ok; exec 1>&-; sleep 0.3"), STATUS_READ_CAP)
            .await;
        assert_eq!(got, Ok(b"ok\n".to_vec()));
    }

    #[tokio::test]
    async fn a_child_that_closes_stdout_and_fails_later_is_a_status_error() {
        let cli = PueueCli::new("/bin/sh", Vec::new());
        let got = cli
            .run(
                &sh("echo ok; exec 1>&-; sleep 0.3; exit 3"),
                STATUS_READ_CAP,
            )
            .await;
        assert_eq!(got, Err(PueueError::Status));
    }

    #[tokio::test]
    async fn a_child_over_the_cap_is_killed_and_reaped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("pid");
        let script = format!(
            "echo $$ > {}; head -c {} /dev/zero; exec sleep 30",
            pid_file.display(),
            STATUS_READ_CAP + 1
        );
        let cli = PueueCli::new("/bin/sh", Vec::new());
        let started = std::time::Instant::now();
        let got = cli.run(&sh(&script), STATUS_READ_CAP).await;
        assert_eq!(got, Err(PueueError::TooLarge));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert_gone(&pid_file);
    }

    #[tokio::test]
    async fn a_read_failure_kills_and_reaps_the_child() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("pid");
        let script = format!("echo $$ > {}; exec sleep 30", pid_file.display());
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(sh(&script))
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        while std::fs::read_to_string(&pid_file).map_or(true, |t| !t.ends_with('\n')) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let started = std::time::Instant::now();
        let got = collect(&mut child, FailAfter { left: 5 }, 10).await;
        assert_eq!(got, Err(PueueError::Read));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert_gone(&pid_file);
    }

    fn assert_gone(pid_file: &std::path::Path) {
        let pid = std::fs::read_to_string(pid_file).expect("pid file");
        let alive = std::process::Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("kill")
            .success();
        assert!(!alive, "child {} still alive", pid.trim());
    }

    #[test]
    fn output_over_the_cap_is_too_large_whatever_else_failed() {
        for read_ok in [true, false] {
            for exited_ok in [true, false] {
                assert_eq!(
                    verdict(11, 10, read_ok, exited_ok),
                    Err(PueueError::TooLarge)
                );
            }
        }
    }

    #[test]
    fn a_failure_within_the_cap_names_its_cause() {
        assert_eq!(verdict(10, 10, false, false), Err(PueueError::Read));
        assert_eq!(verdict(10, 10, true, false), Err(PueueError::Status));
        assert_eq!(verdict(10, 10, true, true), Ok(()));
    }

    #[test]
    fn each_variant_has_its_own_text() {
        let all = [
            PueueError::Spawn,
            PueueError::NoStdout,
            PueueError::Read,
            PueueError::Status,
            PueueError::TooLarge,
            PueueError::Parse,
            PueueError::Timeout,
        ];
        let texts: std::collections::BTreeSet<String> =
            all.iter().map(ToString::to_string).collect();
        assert_eq!(texts.len(), all.len());
    }
}

#[derive(Deserialize)]
struct LogEntry {
    output: String,
}

impl PueueClient for PueueCli {
    async fn status_json(&self) -> Result<String, PueueError> {
        let args = ["status".to_owned(), "--json".to_owned()];
        let out = self.run(&args, STATUS_READ_CAP).await?;
        String::from_utf8(out).map_err(|_| PueueError::Parse)
    }

    async fn log(&self, id: u64, max_bytes: usize) -> Result<LogFetch, PueueError> {
        let args = [
            "log".to_owned(),
            "--json".to_owned(),
            "--lines".to_owned(),
            LOG_LINES.to_string(),
            id.to_string(),
        ];
        let out = self.run(&args, LOG_JSON_CAP).await?;
        let mut map: BTreeMap<String, LogEntry> =
            serde_json::from_slice(&out).map_err(|_| PueueError::Parse)?;
        let entry = map.remove(&id.to_string()).ok_or(PueueError::Parse)?;
        Ok(LogFetch::checked(entry.output.into_bytes(), max_bytes))
    }
}

#[derive(Debug, Deserialize)]
enum RawResult {
    Success,
    Failed(i32),
    FailedToSpawn(serde::de::IgnoredAny),
    Killed,
    Errored,
    DependencyFailed,
}

#[derive(Debug, Deserialize)]
enum RawStatus {
    Locked {},
    Stashed {},
    Queued {},
    Running {
        start: String,
    },
    Paused {
        start: String,
    },
    Done {
        start: String,
        end: String,
        result: RawResult,
    },
}

#[derive(Debug, Deserialize)]
struct RawTask {
    id: u64,
    original_command: String,
    status: RawStatus,
}

#[derive(Debug, Deserialize)]
struct RawSnapshot {
    tasks: BTreeMap<String, RawTask>,
}

/// A pueue task state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgState {
    /// Waiting for a slot.
    Queued,
    /// Held back by the user.
    Stashed,
    /// Its command is being edited.
    Locked,
    /// Running.
    Running,
    /// Started, then paused.
    Paused,
    /// Finished.
    Done,
}

/// How a pueue task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgOutcome {
    /// Exit code 0.
    Success,
    /// A nonzero exit code.
    Failed(i32),
    /// The process never started.
    FailedToSpawn,
    /// Killed by the user or the pueue daemon.
    Killed,
    /// Pueue hit an IO error.
    Errored,
    /// A dependency failed.
    DependencyFailed,
}

impl BgOutcome {
    fn exit_code(self) -> Option<i32> {
        match self {
            Self::Success => Some(0),
            Self::Failed(code) => Some(code),
            _ => None,
        }
    }
}

impl From<RawResult> for BgOutcome {
    fn from(raw: RawResult) -> Self {
        match raw {
            RawResult::Success => Self::Success,
            RawResult::Failed(code) => Self::Failed(code),
            RawResult::FailedToSpawn(_) => Self::FailedToSpawn,
            RawResult::Killed => Self::Killed,
            RawResult::Errored => Self::Errored,
            RawResult::DependencyFailed => Self::DependencyFailed,
        }
    }
}

/// What closed a task record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndedBy {
    /// Pueue reported `Done`.
    Pueue,
    /// The job ended while the task was open.
    JobExit,
    /// The watch deadline passed while the task was open.
    Deadline,
    /// Polling failed [`MAX_POLL_ERRORS`] times in a row.
    PollFailed,
    /// The task left the pueue status while open.
    Removed,
}

/// What the watcher does with one pueue state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Keep polling; an end cause closes it.
    Open,
    /// Close the task now with its result and log.
    Close,
}

/// The rule for each state, one row per [`BgState`].
#[must_use]
pub const fn rule(state: BgState) -> Rule {
    match state {
        BgState::Queued
        | BgState::Stashed
        | BgState::Locked
        | BgState::Running
        | BgState::Paused => Rule::Open,
        BgState::Done => Rule::Close,
    }
}

/// One closed background task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgRecord {
    /// Pueue task id.
    pub id: u64,
    /// The redacted, bounded record. Its `background` flag is true.
    pub record: ShellRecord,
    /// What closed the record.
    pub ended_by: EndedBy,
    /// The state last seen before the close.
    pub last_state: BgState,
    /// The pueue result, only for [`EndedBy::Pueue`].
    pub outcome: Option<BgOutcome>,
    /// Whether the log was cut to its cap.
    pub log_cut: bool,
    /// Whether the log could not be read.
    pub log_failed: bool,
}

/// Wall and monotonic time at the job start.
#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    /// Wall clock at the job start, in milliseconds.
    pub wall_ms: u64,
    /// Monotonic clock at the job start.
    pub at: Instant,
}

/// Timing of one watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgConfig {
    /// Pause between polls.
    pub interval: Duration,
    /// Longest the watch runs.
    pub deadline: Duration,
    /// Longest one client call may take.
    pub call_timeout: Duration,
}

impl Default for BgConfig {
    fn default() -> Self {
        Self {
            interval: POLL_INTERVAL,
            deadline: WATCH_DEADLINE,
            call_timeout: CALL_TIMEOUT,
        }
    }
}

/// Why a watch could not start or a poll failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgError {
    /// A pueue call failed.
    Pueue(PueueError),
}

impl fmt::Display for BgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pueue(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BgError {}

impl From<PueueError> for BgError {
    fn from(e: PueueError) -> Self {
        Self::Pueue(e)
    }
}

/// Parses an RFC 3339 timestamp with a numeric or `Z` offset into Unix milliseconds.
///
/// Returns `None` for any other shape, a time before 1970 or an out-of-range field.
#[must_use]
pub fn parse_timestamp(text: &str) -> Option<u64> {
    if !text.is_ascii() {
        return None;
    }
    let field = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        if !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let is_at = |at: usize, want: u8| text.as_bytes().get(at) == Some(&want);
    let shaped =
        is_at(4, b'-') && is_at(7, b'-') && is_at(10, b'T') && is_at(13, b':') && is_at(16, b':');
    if !shaped {
        return None;
    }
    let (yr, mo, dy) = (field(0..4)?, field(5..7)?, field(8..10)?);
    let (hh, mm, ss) = (field(11..13)?, field(14..16)?, field(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&dy) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let mut at = 19;
    let mut frac_ms = 0_i64;
    if is_at(at, b'.') {
        let frac = text.get(at + 1..)?;
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        let head = frac.get(..digits.min(3)).filter(|h| !h.is_empty())?;
        let scale = 10_i64.pow(3 - u32::try_from(head.len()).ok()?);
        frac_ms = head.parse::<i64>().ok()? * scale;
        at += 1 + digits;
    }
    let tail = text.get(at..)?;
    let off = if tail == "Z" {
        0
    } else {
        let sign = match tail.as_bytes().first()? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        if tail.len() != 6 || !is_at(at + 3, b':') {
            return None;
        }
        let (oh, om) = (field(at + 1..at + 3)?, field(at + 4..at + 6)?);
        if oh > 23 || om > 59 {
            return None;
        }
        sign * (oh * 3600 + om * 60)
    };
    let y = if mo <= 2 { yr - 1 } else { yr };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + dy - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * 86_400 + hh * 3600 + mm * 60 + ss - off;
    let total = epoch.checked_mul(1000)?.checked_add(frac_ms)?;
    u64::try_from(total).ok()
}

#[derive(Debug)]
struct Done {
    start: Option<u64>,
    end: Option<u64>,
    outcome: BgOutcome,
}

#[derive(Debug)]
struct Tracked {
    command: String,
    state: BgState,
    first_seen: Instant,
    running_seen: Option<Instant>,
    pueue_start: Option<u64>,
    done: Option<Done>,
    closed: bool,
}

struct Seen {
    id: u64,
    command: String,
    state: BgState,
    start: Option<u64>,
    done: Option<Done>,
}

fn observe(raw: RawTask) -> Seen {
    let (state, start, done) = match raw.status {
        RawStatus::Locked {} => (BgState::Locked, None, None),
        RawStatus::Stashed {} => (BgState::Stashed, None, None),
        RawStatus::Queued {} => (BgState::Queued, None, None),
        RawStatus::Running { start } => (BgState::Running, parse_timestamp(&start), None),
        RawStatus::Paused { start } => (BgState::Paused, parse_timestamp(&start), None),
        RawStatus::Done { start, end, result } => {
            let done = Done {
                start: parse_timestamp(&start),
                end: parse_timestamp(&end),
                outcome: result.into(),
            };
            (BgState::Done, done.start, Some(done))
        }
    };
    Seen {
        id: raw.id,
        command: raw.original_command,
        state,
        start,
        done,
    }
}

/// Watches pueue for tasks that start after the job did.
#[derive(Debug)]
pub struct BgWatcher<C> {
    client: C,
    config: BgConfig,
    anchor: Anchor,
    baseline: u64,
    tracked: BTreeMap<u64, Tracked>,
    recorder: ShellRecorder,
    redactor: Redactor,
    records: Vec<BgRecord>,
    untracked: u64,
    errors: u32,
}

/// What a finished watch holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgReport {
    /// Closed tasks in close order.
    pub records: Vec<BgRecord>,
    /// Tasks seen past [`MAX_TRACKED_TASKS`] and not recorded.
    pub overflow: u64,
}

impl<C: PueueClient> BgWatcher<C> {
    /// Reads the status once and sets the baseline to its highest task id.
    ///
    /// # Errors
    ///
    /// Returns [`BgError`] when that read fails or times out. Without a baseline every old task
    /// would read as new, so the watch refuses to start.
    pub async fn start(
        client: C,
        redactor: Redactor,
        anchor: Anchor,
        config: BgConfig,
    ) -> Result<Self, BgError> {
        let snapshot = fetch_status(&client, config.call_timeout).await?;
        let baseline = snapshot
            .tasks
            .values()
            .map(|t| t.id)
            .max()
            .unwrap_or_default();
        Ok(Self {
            client,
            config,
            anchor,
            baseline,
            tracked: BTreeMap::new(),
            recorder: ShellRecorder::new(redactor.clone()),
            redactor,
            records: Vec::new(),
            untracked: 0,
            errors: 0,
        })
    }

    /// Highest task id at the start of the watch.
    #[must_use]
    pub fn baseline(&self) -> u64 {
        self.baseline
    }

    fn wall(&self, at: Instant) -> u64 {
        let ms = at.saturating_duration_since(self.anchor.at).as_millis();
        let ms = u64::try_from(ms).unwrap_or(u64::MAX);
        self.anchor.wall_ms.saturating_add(ms).min(MAX_WALL_MS)
    }

    fn apply(&mut self, seen: Seen, now: Instant) -> Option<u64> {
        let tracked = self.tracked.entry(seen.id).or_insert_with(|| Tracked {
            command: seen.command,
            state: seen.state,
            first_seen: now,
            running_seen: None,
            pueue_start: None,
            done: None,
            closed: false,
        });
        if tracked.closed {
            return None;
        }
        tracked.state = seen.state;
        if matches!(seen.state, BgState::Running | BgState::Paused)
            && tracked.running_seen.is_none()
        {
            tracked.running_seen = Some(now);
        }
        if seen.start.is_some() {
            tracked.pueue_start = seen.start;
        }
        tracked.done = seen.done;
        (rule(seen.state) == Rule::Close).then_some(seen.id)
    }

    /// Polls once, closing every task pueue reports `Done` and every open task that left the
    /// status.
    ///
    /// # Errors
    ///
    /// Returns [`BgError`] when the status read fails, times out or does not parse.
    pub async fn poll(&mut self, now: Instant) -> Result<(), BgError> {
        let snapshot = fetch_status(&self.client, self.config.call_timeout).await?;
        let mut present = BTreeSet::new();
        let mut untracked = 0_u64;
        let mut finished = Vec::new();
        for raw in snapshot.tasks.into_values() {
            if raw.id <= self.baseline {
                continue;
            }
            if !self.tracked.contains_key(&raw.id) && self.tracked.len() >= MAX_TRACKED_TASKS {
                untracked += 1;
                continue;
            }
            present.insert(raw.id);
            if let Some(id) = self.apply(observe(raw), now) {
                finished.push(id);
            }
        }
        self.untracked = self.untracked.max(untracked);
        for id in finished {
            self.close(id, EndedBy::Pueue, now).await;
        }
        let gone: Vec<u64> = self
            .tracked
            .iter()
            .filter(|(id, t)| !t.closed && !present.contains(id))
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            self.close(id, EndedBy::Removed, now).await;
        }
        Ok(())
    }

    /// Reads, sanitises and cuts one task log. When the read hit the cap, a second pass cuts the
    /// already-clean text by its own sanitised length, which is shorter than the raw length, so
    /// the last `LOG_TAIL_GUARD` bytes drop and a secret split by the cap leaves no prefix. The
    /// second pass redacts text that is already redacted and relies on the redactor being
    /// idempotent.
    async fn read_log(&self, id: u64) -> (String, bool, bool) {
        let Some(fetch) =
            fetch_checked(&self.client, id, LOG_READ_CAP + 1, self.config.call_timeout).await
        else {
            return (String::new(), false, true);
        };
        if fetch.head_may_be_lost {
            return (HEAD_LOST_MARKER.to_owned(), true, false);
        }
        let raw = fetch.bytes;
        let cut = raw.len() > LOG_READ_CAP;
        let text = String::from_utf8_lossy(&raw);
        let mut clean = sanitise_lines(&self.redactor, &text, Cap::Bytes(LOG_READ_CAP));
        if cut {
            let keep = clean.text.len().saturating_sub(LOG_TAIL_GUARD);
            clean = sanitise_lines(&self.redactor, &clean.text, Cap::Bytes(keep));
        }
        (clean.text, cut || clean.cut, false)
    }

    async fn close(&mut self, id: u64, ended_by: EndedBy, now: Instant) {
        let Some(t) = self.tracked.get_mut(&id) else {
            return;
        };
        if t.closed {
            return;
        }
        t.closed = true;
        let command = t.command.clone();
        let state = t.state;
        let pueue_start = t.pueue_start;
        let first_seen = t.running_seen.unwrap_or(t.first_seen);
        let done = t.done.take();
        let fallback = (self.wall(first_seen), self.wall(now));
        let (started, ended) = match &done {
            Some(Done {
                start: Some(s),
                end: Some(e),
                ..
            }) if e >= s => (*s, *e),
            Some(_) => fallback,
            None => match pueue_start {
                Some(s) if s <= fallback.1 => (s, fallback.1),
                _ => fallback,
            },
        };
        let has_log = matches!(state, BgState::Running | BgState::Paused | BgState::Done);
        let (output, log_cut, log_failed) = if has_log {
            self.read_log(id).await
        } else {
            (String::new(), false, false)
        };
        let outcome = done.as_ref().map(|d| d.outcome);
        let input = ShellInput {
            command,
            output,
            started,
            ended: Some(ended),
            exit_code: outcome.and_then(BgOutcome::exit_code),
            background: true,
        };
        let before = self.recorder.records().len();
        if self.recorder.record(&input).is_err() || self.recorder.records().len() == before {
            return;
        }
        let Some(record) = self.recorder.records().last().cloned() else {
            return;
        };
        self.records.push(BgRecord {
            id,
            record,
            ended_by,
            last_state: state,
            outcome,
            log_cut,
            log_failed,
        });
    }

    /// Closes every open task with `ended_by` and returns the report.
    ///
    /// For [`EndedBy::JobExit`] and [`EndedBy::Deadline`] it first polls once more, so a task
    /// that finished just before the end keeps its pueue result.
    pub async fn finish(mut self, ended_by: EndedBy, now: Instant) -> BgReport {
        if matches!(ended_by, EndedBy::JobExit | EndedBy::Deadline) {
            let _ = self.poll(now).await;
        }
        let open: Vec<u64> = self
            .tracked
            .iter()
            .filter(|(_, t)| !t.closed)
            .map(|(id, _)| *id)
            .collect();
        for id in open {
            self.close(id, ended_by, now).await;
        }
        BgReport {
            records: self.records,
            overflow: self.untracked,
        }
    }

    /// Polls every [`BgConfig::interval`] until `stop` resolves, the deadline passes or
    /// [`MAX_POLL_ERRORS`] polls fail in a row, then closes the open tasks.
    pub async fn watch(mut self, stop: impl Future<Output = ()>) -> BgReport {
        tokio::pin!(stop);
        let deadline = Instant::now() + self.config.deadline;
        let ended_by = loop {
            tokio::select! {
                () = &mut stop => break EndedBy::JobExit,
                () = tokio::time::sleep_until(deadline) => break EndedBy::Deadline,
                () = tokio::time::sleep(self.config.interval) => {}
            }
            if self.poll(Instant::now()).await.is_ok() {
                self.errors = 0;
            } else {
                self.errors += 1;
                if self.errors >= MAX_POLL_ERRORS {
                    break EndedBy::PollFailed;
                }
            }
        };
        self.finish(ended_by, Instant::now()).await
    }
}

async fn fetch_status<C: PueueClient>(
    client: &C,
    limit: Duration,
) -> Result<RawSnapshot, PueueError> {
    let text = tokio::time::timeout(limit, client.status_json())
        .await
        .map_err(|_| PueueError::Timeout)??;
    serde_json::from_str(&text).map_err(|_| PueueError::Parse)
}

/// Shortest pause between two log reads of one running task.
pub const LOG_READ_INTERVAL: Duration = Duration::from_secs(1);
/// Rate budget one reported chunk costs.
pub const LOG_CHUNK_COST: Duration = Duration::from_millis(250);
/// Most chunks reported back to back before the rate budget runs dry.
pub const LOG_BURST: u32 = 8;
/// Consecutive failed reads or reports after which a task is given up.
pub const MAX_LOG_ERRORS: u32 = 5;
/// Most log bytes read for one live task: the whole chunk budget plus the guard and one byte,
/// so a read that reaches it is known to be cut.
pub const LIVE_LOG_READ_CAP: usize =
    MAX_SHELL_LOG_CHUNKS * MAX_SHELL_LOG_CHUNK_BYTES + LOG_TAIL_GUARD + 1;

/// The live log command id of pueue task `task_id`: `bg-` and the decimal id, at most 23 bytes
/// of `[a-z0-9-]`, always valid for [`fleet_proto::validate_shell_log_command_id`].
#[must_use]
pub fn log_command_id(task_id: u64) -> String {
    format!("bg-{task_id}")
}

/// One chunk to report. The reporter adds the job, attempt and box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogChunk {
    /// The live log command id, valid on the wire.
    pub command_id: String,
    /// Chunk number from 0, below [`MAX_SHELL_LOG_CHUNKS`].
    pub seq: u32,
    /// Redacted UTF-8 text of at most [`MAX_SHELL_LOG_CHUNK_BYTES`] bytes. Empty for a status
    /// change alone.
    pub bytes: Vec<u8>,
    /// The task status after this chunk. Never `Unspecified`.
    pub status: v1::ShellStatus,
}

/// A chunk report that did not go through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportError;

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("log chunk report failed")
    }
}

impl std::error::Error for ReportError {}

/// Where chunks go. The gRPC client is wired behind this later.
pub trait LogReporter: Send + Sync {
    /// Sends one chunk. An error leaves the chunk unsent and it is offered again.
    fn report(&self, chunk: LogChunk) -> impl Future<Output = Result<(), ReportError>> + Send;
}

/// Timing of one [`LogPusher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogPushConfig {
    /// Pause between polls.
    pub interval: Duration,
    /// Longest the push runs.
    pub deadline: Duration,
    /// Longest one client or reporter call may take.
    pub call_timeout: Duration,
    /// Shortest pause between two log reads of one running task.
    pub read_interval: Duration,
}

impl Default for LogPushConfig {
    fn default() -> Self {
        Self {
            interval: POLL_INTERVAL,
            deadline: WATCH_DEADLINE,
            call_timeout: CALL_TIMEOUT,
            read_interval: LOG_READ_INTERVAL,
        }
    }
}

/// What a finished push holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPushReport {
    /// Tasks whose terminal status was reported, with that status.
    pub ended: Vec<(u64, v1::ShellStatus)>,
    /// Tasks that stopped without a reported terminal status.
    pub unreported: Vec<u64>,
    /// Tasks seen past [`MAX_TRACKED_TASKS`] and not pushed.
    pub overflow: u64,
}

#[derive(Debug, Default)]
struct LogRead {
    text: String,
    cut: bool,
    head_may_be_lost: bool,
}

fn line_count(raw: &[u8]) -> usize {
    let segments = raw.split(|b| *b == b'\n').count();
    segments - usize::from(raw.last().is_none_or(|b| *b == b'\n'))
}

impl LogTask {
    fn prefix_holds(&self, text: &str) -> bool {
        text.get(..self.sent)
            .is_some_and(|head| Sha256::digest(head.as_bytes()) == self.digest.clone().finalize())
    }
}

#[derive(Debug)]
struct LogTask {
    command_id: String,
    seq: u32,
    sent: usize,
    digest: Sha256,
    last: Option<v1::ShellStatus>,
    done: bool,
    errors: u32,
    next_read: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
struct Target {
    status: v1::ShellStatus,
    terminal: bool,
    readable: bool,
}

fn wire_status(state: BgState, outcome: Option<BgOutcome>) -> Target {
    match state {
        BgState::Queued | BgState::Stashed | BgState::Locked => Target {
            status: v1::ShellStatus::Queued,
            terminal: false,
            readable: false,
        },
        BgState::Running | BgState::Paused => Target {
            status: v1::ShellStatus::Running,
            terminal: false,
            readable: true,
        },
        BgState::Done => Target {
            status: if outcome == Some(BgOutcome::Success) {
                v1::ShellStatus::Done
            } else {
                v1::ShellStatus::Failed
            },
            terminal: true,
            readable: true,
        },
    }
}

fn is_terminal(status: v1::ShellStatus) -> bool {
    matches!(status, v1::ShellStatus::Done | v1::ShellStatus::Failed)
}

fn clean_log(redactor: &Redactor, raw: &[u8]) -> String {
    sanitise_lines(
        redactor,
        &String::from_utf8_lossy(raw),
        Cap::Bytes(LIVE_LOG_READ_CAP + 1),
    )
    .text
}

fn floor_boundary(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Tails every pueue task that starts after the watch did and pushes redacted chunks.
#[derive(Debug)]
pub struct LogPusher<C, R> {
    client: C,
    reporter: R,
    redactor: Redactor,
    config: LogPushConfig,
    baseline: u64,
    tasks: BTreeMap<u64, LogTask>,
    credit: Duration,
    credit_at: Instant,
    untracked: u64,
    errors: u32,
}

impl<C: PueueClient, R: LogReporter> LogPusher<C, R> {
    /// Reads the status once and sets the baseline to its highest task id.
    ///
    /// # Errors
    ///
    /// Returns [`BgError`] when that read fails, for the reason [`BgWatcher::start`] refuses.
    pub async fn start(
        client: C,
        reporter: R,
        redactor: Redactor,
        config: LogPushConfig,
        now: Instant,
    ) -> Result<Self, BgError> {
        let snapshot = fetch_status(&client, config.call_timeout).await?;
        let baseline = snapshot
            .tasks
            .values()
            .map(|t| t.id)
            .max()
            .unwrap_or_default();
        Ok(Self {
            client,
            reporter,
            redactor,
            config,
            baseline,
            tasks: BTreeMap::new(),
            credit: LOG_CHUNK_COST * LOG_BURST,
            credit_at: now,
            untracked: 0,
            errors: 0,
        })
    }

    fn refill(&mut self, now: Instant) {
        let gained = now.saturating_duration_since(self.credit_at);
        self.credit = (self.credit + gained).min(LOG_CHUNK_COST * LOG_BURST);
        self.credit_at = self.credit_at.max(now);
    }

    fn has_credit(&self) -> bool {
        self.credit >= LOG_CHUNK_COST
    }

    async fn read(&self, id: u64) -> Option<LogRead> {
        let fetch = fetch_checked(
            &self.client,
            id,
            LIVE_LOG_READ_CAP + 1,
            self.config.call_timeout,
        )
        .await?;
        Some(LogRead {
            text: clean_log(&self.redactor, &fetch.bytes),
            cut: fetch.bytes.len() > LIVE_LOG_READ_CAP,
            head_may_be_lost: fetch.head_may_be_lost,
        })
    }

    async fn send(&mut self, task: &mut LogTask, bytes: &str, status: v1::ShellStatus) -> bool {
        let chunk = LogChunk {
            command_id: task.command_id.clone(),
            seq: task.seq,
            bytes: bytes.as_bytes().to_vec(),
            status,
        };
        let call = self.reporter.report(chunk);
        let sent = matches!(
            tokio::time::timeout(self.config.call_timeout, call).await,
            Ok(Ok(()))
        );
        if sent {
            self.credit = self.credit.saturating_sub(LOG_CHUNK_COST);
            task.seq += 1;
            task.sent += bytes.len();
            task.digest.update(bytes.as_bytes());
            task.errors = 0;
            task.last = Some(status);
            task.done = is_terminal(status);
        } else {
            task.errors += 1;
            task.done = task.errors >= MAX_LOG_ERRORS;
        }
        sent
    }

    async fn advance(&mut self, id: u64, target: Target, now: Instant) {
        self.refill(now);
        let Some(mut task) = self.tasks.remove(&id) else {
            return;
        };
        if !task.done && self.has_credit() {
            self.push(&mut task, id, target, now).await;
        }
        self.tasks.insert(id, task);
    }

    async fn push(&mut self, task: &mut LogTask, id: u64, target: Target, now: Instant) {
        let due = task.next_read.is_none_or(|at| now >= at);
        let text = if target.readable && (target.terminal || due) {
            task.next_read = Some(now + self.config.read_interval);
            let read = self.read(id).await;
            if read.is_none() {
                task.errors += 1;
                if target.terminal && task.errors < MAX_LOG_ERRORS {
                    return;
                }
            }
            read
        } else {
            None
        };
        if let Some(read) = &text {
            let stable = !read.head_may_be_lost && task.prefix_holds(&read.text);
            if !stable {
                self.send(task, "", v1::ShellStatus::Failed).await;
                return;
            }
        }
        let LogRead { text, cut, .. } = text.unwrap_or_default();
        let hold = !target.terminal || cut;
        let end = if hold {
            floor_boundary(&text, text.len().saturating_sub(LOG_TAIL_GUARD))
        } else {
            text.len()
        };
        let ready = text.get(..end).unwrap_or_default();
        while !task.done && self.has_credit() {
            let rest = ready.get(task.sent..).unwrap_or_default();
            let take = floor_boundary(rest, MAX_SHELL_LOG_CHUNK_BYTES);
            let chunk = rest.get(..take).unwrap_or_default();
            let consumes = take == rest.len();
            let last_slot = task.seq as usize + 1 >= MAX_SHELL_LOG_CHUNKS;
            let truncated = (last_slot && !consumes) || (consumes && cut);
            let status = if truncated {
                v1::ShellStatus::Failed
            } else if last_slot && !target.terminal {
                break;
            } else if consumes {
                if rest.is_empty() && task.last == Some(target.status) {
                    break;
                }
                target.status
            } else if target.terminal {
                v1::ShellStatus::Running
            } else {
                target.status
            };
            if !self.send(task, chunk, status).await {
                break;
            }
        }
    }

    /// Polls once: starts tracking new tasks, reads the log of every running task and of
    /// every task that just ended, and reports what the rate budget allows.
    ///
    /// # Errors
    ///
    /// Returns [`BgError`] when the status read fails, times out or does not parse.
    pub async fn poll(&mut self, now: Instant) -> Result<(), BgError> {
        let snapshot = fetch_status(&self.client, self.config.call_timeout).await?;
        let mut present = BTreeSet::new();
        let mut targets = Vec::new();
        let mut untracked = 0_u64;
        for raw in snapshot.tasks.into_values() {
            if raw.id <= self.baseline {
                continue;
            }
            if !self.tasks.contains_key(&raw.id) && self.tasks.len() >= MAX_TRACKED_TASKS {
                untracked += 1;
                continue;
            }
            present.insert(raw.id);
            let seen = observe(raw);
            self.tasks.entry(seen.id).or_insert_with(|| LogTask {
                command_id: log_command_id(seen.id),
                seq: 0,
                sent: 0,
                digest: Sha256::new(),
                last: None,
                done: false,
                errors: 0,
                next_read: None,
            });
            let outcome = seen.done.as_ref().map(|d| d.outcome);
            targets.push((seen.id, wire_status(seen.state, outcome)));
        }
        self.untracked = self.untracked.max(untracked);
        for (id, task) in &self.tasks {
            if !task.done && !present.contains(id) {
                targets.push((*id, removed_target()));
            }
        }
        for (id, target) in targets {
            self.advance(id, target, now).await;
        }
        Ok(())
    }

    /// Polls once more, then reports `Failed` for every task still open and returns the
    /// report. A task the rate budget leaves no room for is listed as unreported.
    pub async fn finish(mut self, now: Instant) -> LogPushReport {
        let _ = self.poll(now).await;
        let open: Vec<u64> = self
            .tasks
            .iter()
            .filter(|(_, t)| !t.done)
            .map(|(id, _)| *id)
            .collect();
        for id in open {
            self.advance(id, removed_target(), now).await;
        }
        let mut ended = Vec::new();
        let mut unreported = Vec::new();
        for (id, task) in &self.tasks {
            match task.last {
                Some(status) if is_terminal(status) => ended.push((*id, status)),
                _ => unreported.push(*id),
            }
        }
        LogPushReport {
            ended,
            unreported,
            overflow: self.untracked,
        }
    }

    /// Polls every [`LogPushConfig::interval`] until `stop` resolves, the deadline passes or
    /// [`MAX_POLL_ERRORS`] polls fail in a row, then calls [`Self::finish`].
    pub async fn watch(mut self, stop: impl Future<Output = ()>) -> LogPushReport {
        tokio::pin!(stop);
        let deadline = Instant::now() + self.config.deadline;
        loop {
            tokio::select! {
                () = &mut stop => break,
                () = tokio::time::sleep_until(deadline) => break,
                () = tokio::time::sleep(self.config.interval) => {}
            }
            if self.poll(Instant::now()).await.is_ok() {
                self.errors = 0;
            } else {
                self.errors += 1;
                if self.errors >= MAX_POLL_ERRORS {
                    break;
                }
            }
        }
        self.finish(Instant::now()).await
    }
}

fn removed_target() -> Target {
    Target {
        status: v1::ShellStatus::Failed,
        terminal: true,
        readable: false,
    }
}
