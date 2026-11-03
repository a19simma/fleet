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
//! [`ShellRecorder`](crate::shell_timing::ShellRecorder) (NUL strip, redaction, then cut), and
//! has its control characters other than newline and tab replaced by `?` after redaction.
//!
//! Limit: pueue reuses ids after `pueue reset`, so a task created after a reset with an id at or
//! below the baseline is not seen. The watcher polls as the uid of its [`PueueClient`]; the
//! caller chooses that uid when it builds the client.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::{MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
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
    /// The command could not run or exited with a failure.
    Run,
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
            Self::Run => "pueue call failed",
            Self::TooLarge => "pueue reply is too large",
            Self::Parse => "pueue reply is not valid",
            Self::Timeout => "pueue call timed out",
        })
    }
}

impl std::error::Error for PueueError {}

/// The two pueue reads the watcher needs.
pub trait PueueClient: Send + Sync {
    /// The text of `pueue status --json`.
    fn status_json(&self) -> impl Future<Output = Result<String, PueueError>> + Send;

    /// At most `max_bytes` bytes of the output of task `id`.
    fn log(
        &self,
        id: u64,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, PueueError>> + Send;
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
            .map_err(|_| PueueError::Run)?;
        let mut out = Vec::new();
        let read = match child.stdout.take() {
            Some(stdout) => stdout.take(cap as u64 + 1).read_to_end(&mut out).await,
            None => return Err(PueueError::Run),
        };
        let _ = child.start_kill();
        let status = child.wait().await;
        read.map_err(|_| PueueError::Run)?;
        if out.len() > cap {
            return Err(PueueError::TooLarge);
        }
        match status {
            Ok(s) if s.success() => Ok(out),
            _ => Err(PueueError::Run),
        }
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

    async fn log(&self, id: u64, max_bytes: usize) -> Result<Vec<u8>, PueueError> {
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
        let mut bytes = entry.output.into_bytes();
        bytes.truncate(max_bytes);
        Ok(bytes)
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

fn scrub_controls(text: &mut String) {
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        *text = text
            .chars()
            .map(|c| {
                if c.is_control() && c != '\n' && c != '\t' {
                    '?'
                } else {
                    c
                }
            })
            .collect();
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

    async fn read_log(&self, id: u64) -> (String, bool, bool) {
        let call = self.client.log(id, LOG_READ_CAP + 1);
        let Ok(Ok(raw)) = tokio::time::timeout(self.config.call_timeout, call).await else {
            return (String::new(), false, true);
        };
        let cut = raw.len() > LOG_READ_CAP;
        let text = String::from_utf8_lossy(&raw).replace('\0', "");
        let mut text = self.redactor.redact_str(&text).into_owned();
        if cut {
            let mut end = text.len().saturating_sub(LOG_TAIL_GUARD);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        (text, cut, false)
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
        let Some(mut record) = self.recorder.records().last().cloned() else {
            return;
        };
        scrub_controls(&mut record.command);
        scrub_controls(&mut record.output);
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
