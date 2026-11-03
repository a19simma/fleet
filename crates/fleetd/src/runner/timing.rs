//! Timing capture for one job (ADR-0055).
//!
//! A [`Capture`] starts when the agent launches and ends when it exits. For a Claude job with a
//! receiver it drains the OTLP bodies the receiver queued, stamps each with its arrival time on
//! the job clock, parses it and maps the events to spans through a [`Collector`]. When a
//! [`BgFactory`] is set it also watches pueue for background tasks. For a Kimi job it reads the
//! session `wire.jsonl` under the job's `KIMI_CODE_HOME` after the agent exits. [`Gathered`]
//! holds everything; [`Gathered::request`] runs the core aggregate and builds the
//! `ReportTiming` request, which a [`TimingSink`] sends.
//!
//! Capture never fails a job. Every failure becomes a [`Note`] with fixed text that finish
//! pushes to the transcript, and the report goes out with what exists.
//!
//! The job clock counts milliseconds from the start of the run. The event timestamp is the
//! arrival time of its body, because the parser keeps no event time: it can trail the real end
//! of a tool by up to the exporter interval. The parser keeps no `run_in_background` flag
//! either, so a background `Bash` call from `OTel` maps as foreground shell time.
//!
//! The Kimi `wire.jsonl` field names are unverified (see [`crate::wire_timing`]), and its
//! timestamps are read as Unix milliseconds. A span that does not fall inside the job window
//! after that shift is dropped.
//!
//! No flush handle reaches this module: the receiver lives in the launcher's process handle.
//! The drain waits for a quiet period instead, and ends at a deadline.

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_core::timing::{Interval, Span, SpanKind, aggregate, clamp};
use fleet_proto::v1::{ReportTimingRequest, ShellCommand, TimingSpan, TimingSummary};
use fleet_proto::{
    MAX_SHELL_COMMANDS, MAX_SPANS, MAX_TIMING_NAME_BYTES, ShellCommandRecord, TimingSpanRecord,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::bg_command::{
    Anchor, BgConfig, BgError, BgRecord, BgReport, BgWatcher, EndedBy, PueueClient, log_command_id,
};
use crate::otel::{MAX_FLUSH_DEADLINE, QUIET_PERIOD};
use crate::otel_parse::{ClaudeEvent, MAX_DECISIONS, MAX_DURATION_MS, Observed, SpanMapper};
use crate::poller::{TimingOutcome, TimingReportError, TimingReporter, TimingTransport};
use crate::runner::TelemetryCapture;
use crate::shell_timing::{ShellInput, ShellRecord, ShellRecorder, strip_redact};
use crate::wire_timing::parse_wire;

/// Longest `Observed.id` the wiring passes to the mapper, in bytes. A longer id is dropped, so
/// the mapper's id set never holds a long key and the event is not deduplicated.
pub const MAX_OBSERVED_ID_BYTES: usize = 256;

/// Most decisions whose result is refused after the mapper's decision table overflowed. At the
/// cap every later result is refused.
pub const MAX_UNJUDGED: usize = MAX_DECISIONS;

/// Longest a timing report may take before finish stops waiting.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Most bodies one final drain takes after the stop signal.
pub const MAX_FINAL_DRAIN: usize = 1024;

/// Most bytes read from one Kimi `wire.jsonl`.
pub const MAX_WIRE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Most `wire.jsonl` files read for one job.
pub const MAX_WIRE_FILES: usize = 8;

/// Most directory entries the `wire.jsonl` search visits.
pub const MAX_WIRE_SCAN_ENTRIES: usize = 512;

/// Deepest directory the `wire.jsonl` search enters.
pub const MAX_WIRE_SCAN_DEPTH: usize = 6;

const WIRE_FILE_NAME: &str = "wire.jsonl";
const API_NAME: &str = "api_request";
const TOOL_FALLBACK_NAME: &str = "tool";
const BG_SPAN_NAME: &str = "pueue task";
const WIRE_SPAN_NAME: &str = "llm.request";

/// A fixed-text reason capture lost or cut something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Note {
    /// The flush deadline passed before the OTLP stream went quiet.
    FlushIncomplete,
    /// An OTLP body could not be parsed.
    BodyUnparsable,
    /// Spans past [`MAX_SPANS`] were dropped.
    SpansCapped,
    /// Shell commands past [`MAX_SHELL_COMMANDS`] were dropped.
    ShellsCapped,
    /// A result was dropped because its decision could not be kept.
    DecisionsOverflow,
    /// The pueue watch could not start.
    BgUnavailable,
    /// The pueue watch task failed.
    BgLost,
    /// The Kimi wire log could not be read.
    WireUnreadable,
    /// A record failed wire validation and was dropped.
    RecordRejected,
    /// The report was not stored: it failed, timed out or could not be attempted.
    ReportLost,
}

impl Note {
    /// The transcript text of the note.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::FlushIncomplete => {
                "timing note: telemetry flush deadline passed, spans may be missing"
            }
            Self::BodyUnparsable => "timing note: a telemetry body could not be parsed",
            Self::SpansCapped => "timing note: span cap reached, later spans dropped",
            Self::ShellsCapped => "timing note: shell command cap reached, later commands dropped",
            Self::DecisionsOverflow => {
                "timing note: tool decision table full, later tool spans dropped"
            }
            Self::BgUnavailable => "timing note: background task watch could not start",
            Self::BgLost => "timing note: background task watch failed",
            Self::WireUnreadable => "timing note: agent wire log could not be read",
            Self::RecordRejected => {
                "timing note: a timing record failed validation and was dropped"
            }
            Self::ReportLost => "timing note: the timing report was not stored",
        }
    }
}

/// A span with the labels the wire carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSpan {
    /// Kind and interval, in milliseconds on the job clock.
    pub span: Span,
    /// Redacted single-line name.
    pub name: String,
    /// Tool use id when the event had one.
    pub tool_use_id: Option<String>,
}

fn one_line(redactor: &Redactor, text: &str, fallback: &str) -> String {
    let redacted = strip_redact(redactor, text, false);
    let mut out = String::new();
    for c in redacted.chars() {
        if out.len() + c.len_utf8() > MAX_TIMING_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    if out.trim().is_empty() {
        fallback.to_owned()
    } else {
        out
    }
}

/// The id the wiring gives the mapper for `event`.
///
/// It is `None` for an event with no stable id or an id over [`MAX_OBSERVED_ID_BYTES`]. A result
/// and a decision of one call get different prefixes, so neither hides the other as a
/// duplicate.
#[must_use]
pub fn observed_id(event: &ClaudeEvent) -> Option<String> {
    let id = match event {
        ClaudeEvent::ToolResult(r) => format!("result:{}", r.tool_use_id),
        ClaudeEvent::ToolDecision(d) => format!("decision:{}", d.tool_use_id),
        ClaudeEvent::ApiRequest(_) => return None,
    };
    (id.len() <= MAX_OBSERVED_ID_BYTES).then_some(id)
}

/// Turns parsed events into named spans and foreground shell records.
///
/// The mapper is driven through [`SpanMapper::push_all`] only, one event per call, so the
/// wiring sees which call dropped a decision. A decision the mapper dropped at its table cap
/// would otherwise let its result map as a call with no decision. Here that result is refused:
/// the call's tool id joins a refused set capped at [`MAX_UNJUDGED`], and past that cap every
/// result is refused.
pub struct Collector {
    mapper: SpanMapper,
    spans: Vec<NamedSpan>,
    shells: ShellRecorder,
    redactor: Redactor,
    unjudged: HashSet<String>,
    refuse_results: bool,
    notes: HashSet<Note>,
}

impl fmt::Debug for Collector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Collector")
            .field("spans", &self.spans.len())
            .finish_non_exhaustive()
    }
}

impl Collector {
    /// A collector redacting with `redactor`.
    ///
    /// # Panics
    ///
    /// Never: the window is a fixed non-reversed interval.
    #[must_use]
    pub fn new(redactor: Redactor) -> Self {
        let window = Interval::new(0, MAX_DURATION_MS).unwrap_or_else(|_| unreachable!());
        Self {
            mapper: SpanMapper::new(window),
            spans: Vec::new(),
            shells: ShellRecorder::new(redactor.clone()),
            redactor,
            unjudged: HashSet::new(),
            refuse_results: false,
            notes: HashSet::new(),
        }
    }

    /// Records `note` once.
    pub fn note(&mut self, note: Note) {
        self.notes.insert(note);
    }

    /// Maps `events` that arrived at `ts_ms` on the job clock.
    pub fn ingest(&mut self, ts_ms: u64, events: Vec<ClaudeEvent>) {
        for event in events {
            self.ingest_one(ts_ms, &event);
        }
    }

    fn ingest_one(&mut self, ts_ms: u64, event: &ClaudeEvent) {
        if let ClaudeEvent::ToolResult(r) = event
            && (self.refuse_results || self.unjudged.contains(&r.tool_use_id))
        {
            self.note(Note::DecisionsOverflow);
            return;
        }
        let mut obs = Observed::new(ts_ms, event.clone());
        obs.id = observed_id(event);
        let dropped_before = self.mapper.stats().decisions_dropped;
        let mapped = self.mapper.push_all(vec![obs]);
        if let ClaudeEvent::ToolDecision(d) = event
            && self.mapper.stats().decisions_dropped > dropped_before
        {
            if self.unjudged.len() < MAX_UNJUDGED {
                self.unjudged.insert(d.tool_use_id.clone());
            } else {
                self.refuse_results = true;
            }
        }
        for span in mapped {
            self.keep(span, event);
        }
    }

    fn keep(&mut self, span: Span, event: &ClaudeEvent) {
        if self.spans.len() >= MAX_SPANS {
            self.note(Note::SpansCapped);
            return;
        }
        let (name, tool_use_id) = match event {
            ClaudeEvent::ToolResult(r) => (
                one_line(&self.redactor, &r.tool_name, TOOL_FALLBACK_NAME),
                Some(one_line(&self.redactor, &r.tool_use_id, "")).filter(|id| !id.is_empty()),
            ),
            _ => (API_NAME.to_owned(), None),
        };
        if let ClaudeEvent::ToolResult(r) = event
            && span.kind == SpanKind::Shell
            && let Some(command) = &r.command
        {
            let _ = self.shells.record(&ShellInput {
                command: command.clone(),
                output: String::new(),
                started: span.interval.start_ms(),
                ended: Some(span.interval.end_ms()),
                exit_code: r.success.then_some(0),
                background: false,
            });
        }
        self.spans.push(NamedSpan {
            span,
            name,
            tool_use_id,
        });
    }

    fn finish(self) -> (Vec<NamedSpan>, Vec<ShellRecord>, HashSet<Note>) {
        let mut notes = self.notes;
        if self.shells.overflow() > 0 {
            notes.insert(Note::ShellsCapped);
        }
        (self.spans, self.shells.records().to_vec(), notes)
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where a finished timing request goes. [`ReporterSink`] is the retrying one.
pub trait TimingSink: Send + Sync + fmt::Debug {
    /// Sends `request` until it is stored or refused.
    fn send(
        &self,
        request: ReportTimingRequest,
    ) -> BoxFuture<'_, Result<TimingOutcome, TimingReportError>>;
}

/// A [`TimingSink`] over a [`TimingReporter`]. One lock keeps the backoff shared by all jobs.
pub struct ReporterSink<T, C, R> {
    reporter: tokio::sync::Mutex<TimingReporter<T, C, R>>,
}

impl<T, C, R> ReporterSink<T, C, R> {
    /// Wraps `reporter`.
    #[must_use]
    pub fn new(reporter: TimingReporter<T, C, R>) -> Self {
        Self {
            reporter: tokio::sync::Mutex::new(reporter),
        }
    }
}

impl<T, C, R> fmt::Debug for ReporterSink<T, C, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReporterSink").finish_non_exhaustive()
    }
}

impl<T, C, R> TimingSink for ReporterSink<T, C, R>
where
    T: TimingTransport + 'static,
    C: crate::poller::RetryClock + 'static,
    R: crate::backoff::Random + Send + 'static,
{
    fn send(
        &self,
        request: ReportTimingRequest,
    ) -> BoxFuture<'_, Result<TimingOutcome, TimingReportError>> {
        Box::pin(async move { self.reporter.lock().await.report(request).await })
    }
}

/// A running pueue watch.
pub trait BgRun: Send {
    /// Polls until `stop` fires, then closes the open tasks.
    fn watch(self: Box<Self>, stop: oneshot::Receiver<()>) -> BoxFuture<'static, BgReport>;
}

/// Starts a pueue watch at job start.
pub trait BgFactory: Send + Sync + fmt::Debug {
    /// Reads the baseline and returns the watch.
    fn start(
        &self,
        redactor: Redactor,
        anchor: Anchor,
    ) -> BoxFuture<'_, Result<Box<dyn BgRun>, BgError>>;
}

/// A [`BgFactory`] over a cloneable [`PueueClient`].
#[derive(Clone)]
pub struct PueueBg<C> {
    client: C,
    config: BgConfig,
}

impl<C> PueueBg<C> {
    /// A factory watching through `client` with `config`.
    #[must_use]
    pub const fn new(client: C, config: BgConfig) -> Self {
        Self { client, config }
    }
}

impl<C> fmt::Debug for PueueBg<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PueueBg").finish_non_exhaustive()
    }
}

struct Watch<C>(BgWatcher<C>);

impl<C: PueueClient + 'static> BgRun for Watch<C> {
    fn watch(self: Box<Self>, stop: oneshot::Receiver<()>) -> BoxFuture<'static, BgReport> {
        Box::pin(self.0.watch(async move {
            let _ = stop.await;
        }))
    }
}

impl<C: PueueClient + Clone + 'static> BgFactory for PueueBg<C> {
    fn start(
        &self,
        redactor: Redactor,
        anchor: Anchor,
    ) -> BoxFuture<'_, Result<Box<dyn BgRun>, BgError>> {
        let client = self.client.clone();
        let config = self.config;
        Box::pin(async move {
            let watcher = BgWatcher::start(client, redactor, anchor, config).await?;
            let run: Box<dyn BgRun> = Box::new(Watch(watcher));
            Ok(run)
        })
    }
}

/// What the runner needs to capture and report timing.
#[derive(Clone)]
pub struct TimingWiring {
    pub(crate) sink: Arc<dyn TimingSink>,
    pub(crate) bg: Option<Arc<dyn BgFactory>>,
    pub(crate) quiet: Duration,
    pub(crate) deadline: Duration,
    pub(crate) send_timeout: Duration,
}

impl fmt::Debug for TimingWiring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimingWiring")
            .field("bg", &self.bg.is_some())
            .finish_non_exhaustive()
    }
}

impl TimingWiring {
    /// Wiring that reports through `sink`, with the receiver's quiet period and deadline.
    #[must_use]
    pub fn new(sink: Arc<dyn TimingSink>) -> Self {
        Self {
            sink,
            bg: None,
            quiet: QUIET_PERIOD,
            deadline: MAX_FLUSH_DEADLINE,
            send_timeout: SEND_TIMEOUT,
        }
    }

    /// Watches pueue through `factory`.
    #[must_use]
    pub fn with_bg(mut self, factory: Arc<dyn BgFactory>) -> Self {
        self.bg = Some(factory);
        self
    }

    /// Sets the drain quiet period and deadline. The deadline is capped at
    /// [`MAX_FLUSH_DEADLINE`].
    #[must_use]
    pub fn with_flush(mut self, quiet: Duration, deadline: Duration) -> Self {
        self.quiet = quiet;
        self.deadline = deadline.min(MAX_FLUSH_DEADLINE);
        self
    }

    /// Sets how long finish waits for the report.
    #[must_use]
    pub const fn with_send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }
}

fn ms_since(t0: Instant, at: Instant) -> u64 {
    let ms = at.saturating_duration_since(t0).as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX).min(MAX_DURATION_MS)
}

struct Shared {
    collector: Mutex<Collector>,
    last_body: Mutex<Option<Instant>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Capture in progress for one job.
pub struct Capture {
    t0: Instant,
    unix_start_ms: u64,
    agent_start_ms: u64,
    shared: Arc<Shared>,
    drain: Option<(oneshot::Sender<()>, JoinHandle<()>)>,
    bg: Option<(oneshot::Sender<()>, JoinHandle<BgReport>)>,
    redactor: Redactor,
    quiet: Duration,
    deadline: Duration,
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture").finish_non_exhaustive()
    }
}

async fn drain_bodies(
    shared: Arc<Shared>,
    t0: Instant,
    mut bodies: mpsc::Receiver<Vec<u8>>,
    mut stop: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            body = bodies.recv() => match body {
                Some(body) => take_body(&shared, t0, &body),
                None => return,
            },
        }
    }
    for _ in 0..MAX_FINAL_DRAIN {
        match bodies.try_recv() {
            Ok(body) => take_body(&shared, t0, &body),
            Err(_) => break,
        }
    }
}

fn take_body(shared: &Shared, t0: Instant, body: &[u8]) {
    let now = Instant::now();
    *lock(&shared.last_body) = Some(now);
    let ts = ms_since(t0, now);
    match crate::otel_parse::parse_logs(body) {
        Ok(parsed) => lock(&shared.collector).ingest(ts, parsed.events),
        Err(_) => lock(&shared.collector).note(Note::BodyUnparsable),
    }
}

async fn start_bg(
    factory: Option<&dyn BgFactory>,
    redactor: &Redactor,
    anchor: Anchor,
    shared: &Shared,
) -> Option<(oneshot::Sender<()>, JoinHandle<BgReport>)> {
    let factory = factory?;
    let Ok(run) = factory.start(redactor.clone(), anchor).await else {
        lock(&shared.collector).note(Note::BgUnavailable);
        return None;
    };
    let (stop_tx, stop_rx) = oneshot::channel();
    Some((stop_tx, tokio::spawn(run.watch(stop_rx))))
}

impl Capture {
    /// Starts capture. `t0` is the job clock origin. A missing `telemetry` or `bg` simply
    /// captures less.
    pub async fn start(
        wiring: &TimingWiring,
        t0: Instant,
        redactor: &Redactor,
        telemetry: Option<TelemetryCapture>,
    ) -> Self {
        let shared = Arc::new(Shared {
            collector: Mutex::new(Collector::new(redactor.clone())),
            last_body: Mutex::new(None),
        });
        let drain = telemetry.map(|capture| {
            let (stop_tx, stop_rx) = oneshot::channel();
            let task = tokio::spawn(drain_bodies(
                Arc::clone(&shared),
                t0,
                capture.bodies,
                stop_rx,
            ));
            (stop_tx, task)
        });
        let unix_start_ms = crate::now_ms().saturating_sub(ms_since(t0, Instant::now()));
        let anchor = Anchor {
            wall_ms: unix_start_ms,
            at: t0,
        };
        let bg = start_bg(wiring.bg.as_deref(), redactor, anchor, &shared).await;
        Self {
            t0,
            unix_start_ms,
            agent_start_ms: ms_since(t0, Instant::now()),
            shared,
            drain,
            bg,
            redactor: redactor.clone(),
            quiet: wiring.quiet,
            deadline: wiring.deadline.min(MAX_FLUSH_DEADLINE),
        }
    }

    async fn quiesce(&self) -> bool {
        let start = Instant::now();
        let end = start + self.deadline;
        loop {
            let last = *lock(&self.shared.last_body);
            let now = Instant::now();
            let quiet_at = last.map_or(start, |at| at.max(start)) + self.quiet;
            if now >= quiet_at {
                return false;
            }
            if now >= end {
                return true;
            }
            tokio::time::sleep_until(quiet_at.min(end)).await;
        }
    }

    /// Ends capture after the agent exits.
    ///
    /// Waits for the OTLP stream to go quiet or the deadline, stops the pueue watch with
    /// [`EndedBy::JobExit`], and reads the Kimi wire log under `kimi_home` when given.
    pub async fn stop(mut self, kimi_home: Option<&Path>) -> Gathered {
        let agent_end_ms = ms_since(self.t0, Instant::now());
        let incomplete = self.drain.is_some() && self.quiesce().await;
        let drained = self.drain.take();
        let bg_task = self.bg.take();
        if let Some((stop, task)) = drained {
            let _ = stop.send(());
            let _ = task.await;
        }
        let mut bg_records = Vec::new();
        let mut bg_overflow = false;
        let mut bg_lost = false;
        if let Some((stop, task)) = bg_task {
            let _ = stop.send(());
            match task.await {
                Ok(report) => {
                    bg_overflow = report.overflow > 0;
                    bg_records = report.records;
                }
                Err(_) => bg_lost = true,
            }
        }
        let wire = kimi_home.map(|home| read_wire(home, self.unix_start_ms, &self.redactor));
        let Self {
            shared,
            agent_start_ms,
            ..
        } = self;
        let collector = Arc::try_unwrap(shared).map_or_else(
            |shared| {
                let mut taken = lock(&shared.collector);
                std::mem::replace(&mut *taken, Collector::new(Redactor::default()))
            },
            |shared| {
                shared
                    .collector
                    .into_inner()
                    .unwrap_or_else(PoisonError::into_inner)
            },
        );
        let (mut spans, shells, mut notes) = collector.finish();
        if incomplete {
            notes.insert(Note::FlushIncomplete);
        }
        if bg_lost {
            notes.insert(Note::BgLost);
        }
        if bg_overflow {
            notes.insert(Note::ShellsCapped);
        }
        match wire {
            Some(Ok(extra)) => {
                for span in extra {
                    if spans.len() >= MAX_SPANS {
                        notes.insert(Note::SpansCapped);
                        break;
                    }
                    spans.push(span);
                }
            }
            Some(Err(())) => {
                notes.insert(Note::WireUnreadable);
            }
            None => {}
        }
        let mut notes: Vec<Note> = notes.into_iter().collect();
        notes.sort();
        Gathered {
            t0: self.t0,
            unix_start_ms: self.unix_start_ms,
            agent_start_ms,
            agent_end_ms,
            spans,
            foreground: shells,
            background: bg_records,
            notes,
        }
    }
}

fn find_wire_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0_usize)];
    let mut visited = 0_usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_WIRE_SCAN_ENTRIES || found.len() >= MAX_WIRE_FILES {
                return found;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() && depth < MAX_WIRE_SCAN_DEPTH {
                stack.push((entry.path(), depth + 1));
            } else if kind.is_file() && entry.file_name() == WIRE_FILE_NAME {
                found.push(entry.path());
            }
        }
    }
    found.sort();
    found
}

fn read_wire(home: &Path, unix_start_ms: u64, redactor: &Redactor) -> Result<Vec<NamedSpan>, ()> {
    let mut out = Vec::new();
    for path in find_wire_files(home) {
        let file = File::open(&path).map_err(|_| ())?;
        let parsed = parse_wire(BufReader::new(file.take(MAX_WIRE_FILE_BYTES))).map_err(|_| ())?;
        for span in parsed.spans {
            let start = span.interval.start_ms().saturating_sub(unix_start_ms);
            let end = span.interval.end_ms().saturating_sub(unix_start_ms);
            if span.interval.end_ms() <= unix_start_ms || end > MAX_DURATION_MS {
                continue;
            }
            if let Ok(interval) = Interval::new(start, end) {
                out.push(NamedSpan {
                    span: Span {
                        kind: span.kind,
                        interval,
                    },
                    name: one_line(redactor, WIRE_SPAN_NAME, WIRE_SPAN_NAME),
                    tool_use_id: None,
                });
            }
        }
    }
    Ok(out)
}

/// Everything capture collected, ready to become a request.
#[derive(Debug, Clone)]
pub struct Gathered {
    t0: Instant,
    unix_start_ms: u64,
    agent_start_ms: u64,
    agent_end_ms: u64,
    spans: Vec<NamedSpan>,
    foreground: Vec<ShellRecord>,
    background: Vec<BgRecord>,
    notes: Vec<Note>,
}

fn ended_by_text(by: EndedBy) -> Option<&'static str> {
    match by {
        EndedBy::Pueue => None,
        EndedBy::JobExit => Some("job_exit"),
        EndedBy::Deadline => Some("deadline"),
        EndedBy::PollFailed => Some("poll_failed"),
        EndedBy::Removed => Some("removed"),
    }
}

/// The request and the notes it carries.
#[derive(Debug, Clone)]
pub struct Built {
    /// The `ReportTiming` request.
    pub request: ReportTimingRequest,
    /// Notes from capture and from assembly.
    pub notes: Vec<Note>,
}

impl Gathered {
    /// Milliseconds from the start of capture to now.
    #[must_use]
    pub fn wall_ms(&self) -> u64 {
        ms_since(self.t0, Instant::now())
    }

    /// Notes recorded during capture.
    #[must_use]
    pub fn notes(&self) -> &[Note] {
        &self.notes
    }

    fn commands(
        &self,
        named: &mut Vec<NamedSpan>,
        wall_ms: u64,
        agent_end: u64,
    ) -> Vec<ShellCommand> {
        let mut commands: Vec<ShellCommand> = Vec::new();
        for bg in &self.background {
            let started = bg
                .record
                .started
                .saturating_sub(self.unix_start_ms)
                .min(wall_ms);
            let ended = bg
                .record
                .ended
                .map_or(agent_end, |e| e.saturating_sub(self.unix_start_ms))
                .clamp(started, wall_ms);
            let limit = Interval::new(started, ended).unwrap_or_else(|_| unreachable!());
            named.push(NamedSpan {
                span: Span {
                    kind: SpanKind::BgShell,
                    interval: limit,
                },
                name: BG_SPAN_NAME.to_owned(),
                tool_use_id: None,
            });
            commands.push(ShellCommand::from(&ShellCommandRecord {
                id: log_command_id(bg.id),
                command: bg.record.command.clone(),
                background: true,
                started_ms: started,
                ended_ms: Some(ended),
                duration_ms: ended - started,
                exit_code: bg.outcome.and_then(|o| match o {
                    crate::bg_command::BgOutcome::Success => Some(0),
                    crate::bg_command::BgOutcome::Failed(code) => Some(code),
                    _ => None,
                }),
                log: bg.record.output.clone(),
                log_truncated: bg.record.truncated || bg.log_cut,
                ended_by: ended_by_text(bg.ended_by).map(str::to_owned),
            }));
        }
        for (n, rec) in self.foreground.iter().enumerate() {
            let started = rec.started.min(wall_ms);
            let ended = rec.ended.unwrap_or(started).clamp(started, wall_ms);
            commands.push(ShellCommand::from(&ShellCommandRecord {
                id: format!("fg-{n}"),
                command: rec.command.clone(),
                background: false,
                started_ms: started,
                ended_ms: Some(ended),
                duration_ms: ended - started,
                exit_code: rec.exit_code,
                log: rec.output.clone(),
                log_truncated: rec.truncated,
                ended_by: None,
            }));
        }
        commands
    }

    /// Builds the request for a job whose window is `0..wall_ms` on the job clock.
    ///
    /// Spans from the receiver, the wire log and pueue are clamped to the job window, and the
    /// core aggregate fills the five parts, so the parts sum to `wall_ms` by construction. A
    /// record that would fail server validation is dropped and noted, so one bad record never
    /// costs the whole report. Background commands come first when the shell command cap cuts.
    ///
    /// # Panics
    ///
    /// Never: windows are built from a clamped start and end.
    #[must_use]
    pub fn request(&self, job_id: &str, attempt: u32, box_name: &str, wall_ms: u64) -> Built {
        let wall_ms = wall_ms.min(MAX_DURATION_MS);
        let job = Interval::new(0, wall_ms).unwrap_or_else(|_| unreachable!());
        let agent_end = self.agent_end_ms.min(wall_ms);
        let agent_start = self.agent_start_ms.min(agent_end);
        let agent = Interval::new(agent_start, agent_end).unwrap_or_else(|_| unreachable!());
        let mut notes = self.notes.clone();
        let mut named: Vec<NamedSpan> = Vec::new();
        for s in &self.spans {
            for interval in clamp(&[s.span.interval], job) {
                named.push(NamedSpan {
                    span: Span {
                        kind: s.span.kind,
                        interval,
                    },
                    ..s.clone()
                });
            }
        }
        let mut commands = self.commands(&mut named, wall_ms, agent_end);
        let core: Vec<Span> = named.iter().map(|s| s.span).collect();
        let summary = aggregate(&core, job, agent);
        let mut rejected = false;
        let mut spans: Vec<TimingSpan> = Vec::new();
        for s in &named {
            let record = TimingSpanRecord {
                span: s.span,
                name: s.name.clone(),
                tool_use_id: s.tool_use_id.clone(),
            };
            match TimingSpan::try_from(&record)
                .ok()
                .filter(|wire| TimingSpanRecord::try_from(wire.clone()).is_ok())
            {
                Some(wire) if spans.len() < MAX_SPANS => spans.push(wire),
                Some(_) => notes.push(Note::SpansCapped),
                None => rejected = true,
            }
        }
        let before = commands.len();
        commands.retain(|c| ShellCommandRecord::try_from(c.clone()).is_ok());
        rejected |= commands.len() != before;
        if commands.len() > MAX_SHELL_COMMANDS {
            commands.truncate(MAX_SHELL_COMMANDS);
            notes.push(Note::ShellsCapped);
        }
        if rejected {
            notes.push(Note::RecordRejected);
        }
        notes.sort();
        notes.dedup();
        Built {
            request: ReportTimingRequest {
                job_id: job_id.to_owned(),
                attempt,
                r#box: box_name.to_owned(),
                summary: Some(TimingSummary::from(&summary)),
                spans,
                shell_commands: commands,
            },
            notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use fleet_core::Redactor;
    use fleet_core::timing::SpanKind;
    use serde_json::json;
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    use super::{
        Capture, Collector, MAX_OBSERVED_ID_BYTES, MAX_UNJUDGED, Note, TimingSink, TimingWiring,
        observed_id, one_line,
    };
    use crate::otel_parse::{ApiRequest, ClaudeEvent, MAX_DECISIONS, ToolDecision, ToolResult};
    use crate::runner::TelemetryCapture;
    use fleet_proto::{MAX_SHELL_COMMANDS, MAX_SPANS, MAX_TIMING_NAME_BYTES};

    fn result(id: &str, tool: &str, ms: u64, command: Option<&str>) -> ClaudeEvent {
        ClaudeEvent::ToolResult(ToolResult {
            tool_use_id: id.to_owned(),
            tool_name: tool.to_owned(),
            duration_ms: ms,
            success: true,
            command: command.map(str::to_owned),
        })
    }

    fn decision(id: &str, tool: &str, verdict: &str) -> ClaudeEvent {
        ClaudeEvent::ToolDecision(ToolDecision {
            tool_use_id: id.to_owned(),
            tool_name: tool.to_owned(),
            decision: Some(verdict.to_owned()),
        })
    }

    fn api(ms: u64) -> ClaudeEvent {
        ClaudeEvent::ApiRequest(ApiRequest {
            duration_ms: ms,
            model: None,
        })
    }

    fn collector() -> Collector {
        Collector::new(Redactor::default())
    }

    #[test]
    fn an_observed_id_over_the_cap_is_dropped_and_one_at_the_cap_is_kept() {
        let fits = "x".repeat(MAX_OBSERVED_ID_BYTES - "result:".len());
        assert_eq!(
            observed_id(&result(&fits, "Bash", 1, None)).map(|id| id.len()),
            Some(MAX_OBSERVED_ID_BYTES)
        );
        let long = "x".repeat(MAX_OBSERVED_ID_BYTES - "result:".len() + 1);
        assert_eq!(observed_id(&result(&long, "Bash", 1, None)), None);
        assert_eq!(observed_id(&api(5)), None);
        assert_ne!(
            observed_id(&result("t1", "Bash", 1, None)),
            observed_id(&decision("t1", "Bash", "accept"))
        );
    }

    #[test]
    fn a_repeated_id_dedupes_and_an_over_cap_id_does_not() {
        let mut c = collector();
        c.ingest(
            1000,
            vec![
                result("t1", "Read", 100, None),
                result("t1", "Read", 100, None),
            ],
        );
        assert_eq!(c.spans.len(), 1);
        let long = "y".repeat(MAX_OBSERVED_ID_BYTES);
        c.ingest(
            2000,
            vec![
                result(&long, "Read", 100, None),
                result(&long, "Read", 100, None),
            ],
        );
        assert_eq!(c.spans.len(), 3);
        assert_eq!(c.mapper.stats().duplicates, 1);
    }

    #[test]
    fn a_reject_dropped_at_the_decision_cap_drops_its_result() {
        let mut c = collector();
        for n in 0..MAX_DECISIONS {
            c.ingest(10, vec![decision(&format!("d{n}"), "Bash", "accept")]);
        }
        c.ingest(20, vec![decision("late", "Bash", "reject")]);
        assert_eq!(c.mapper.stats().decisions_dropped, 1);
        c.ingest(1000, vec![result("late", "Bash", 500, Some("rm -rf x"))]);
        assert_eq!(c.spans.len(), 0);
        assert!(c.notes.contains(&Note::DecisionsOverflow));
        c.ingest(1000, vec![result("d0", "Bash", 500, Some("ls"))]);
        assert_eq!(c.spans.len(), 1);
        c.ingest(1100, vec![result("unseen", "Read", 50, None)]);
        assert_eq!(c.spans.len(), 2);
    }

    #[test]
    fn past_the_refused_set_cap_every_result_is_refused() {
        let mut c = collector();
        for n in 0..MAX_DECISIONS {
            c.ingest(10, vec![decision(&format!("d{n}"), "Bash", "accept")]);
        }
        for n in 0..=MAX_UNJUDGED {
            c.ingest(20, vec![decision(&format!("o{n}"), "Bash", "reject")]);
        }
        c.ingest(1000, vec![result("never-decided", "Read", 100, None)]);
        assert_eq!(c.spans.len(), 0);
    }

    #[test]
    fn the_span_vec_is_capped_and_noted() {
        let mut c = collector();
        for n in 0..=MAX_SPANS {
            c.ingest(10_000 + u64::try_from(n).expect("n"), vec![api(5)]);
        }
        assert_eq!(c.spans.len(), MAX_SPANS);
        assert!(c.notes.contains(&Note::SpansCapped));
    }

    #[test]
    fn the_wiring_drives_the_mapper_through_push_all_only() {
        let src = include_str!("timing.rs");
        let direct = format!("{}.push(", "mapper");
        let uses = src.matches(direct.as_str()).count();
        assert_eq!(uses, 0);
        assert!(src.contains(&format!("{}.push_all(", "mapper")));
    }

    #[test]
    fn foreground_bash_records_a_redacted_command_and_a_shell_span() {
        let mut c = Collector::new(Redactor::new(["hunter2-hunter2"]));
        c.ingest(
            1000,
            vec![result("t1", "Bash", 400, Some("echo hunter2-hunter2"))],
        );
        let (spans, shells, _) = c.finish();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans.first().map(|s| s.span.kind), Some(SpanKind::Shell));
        let rec = shells.first().expect("record");
        assert!(!rec.command.contains("hunter2"), "{}", rec.command);
        assert_eq!(rec.started, 600);
        assert_eq!(rec.ended, Some(1000));
    }

    #[test]
    fn a_name_is_redacted_before_it_is_cut() {
        let redactor = Redactor::new(["hunter2-hunter2"]);
        let name = format!(
            "{}hunter2-hunter2",
            "a".repeat(MAX_TIMING_NAME_BYTES - "hunter2-hu".len())
        );
        let out = one_line(&redactor, &name, "fallback");
        assert!(!out.contains("hunter"), "{out}");
        assert!(out.len() <= MAX_TIMING_NAME_BYTES);
        assert_eq!(one_line(&redactor, "a\nb\u{2028}c", "f"), "abc");
        assert_eq!(one_line(&redactor, "  ", "fallback"), "fallback");
    }

    const HIDDEN_SPLITTERS: [char; 3] = ['\u{1}', '\u{1b}', '\u{200b}'];
    const SPLIT_SECRET: &str = "hunter2-hunter2";

    fn split_secret(by: char) -> String {
        format!("{}{by}{}", &SPLIT_SECRET[..7], &SPLIT_SECRET[7..])
    }

    #[test]
    fn a_tool_name_split_by_a_hidden_char_is_redacted() {
        for by in HIDDEN_SPLITTERS {
            let mut c = Collector::new(Redactor::new([SPLIT_SECRET]));
            c.ingest(1000, vec![result("t1", &split_secret(by), 10, None)]);
            let (spans, _, _) = c.finish();
            let name = &spans.first().expect("span").name;
            assert!(!name.contains("hunter"), "{by:?}: {name}");
        }
    }

    #[test]
    fn a_tool_use_id_split_by_a_hidden_char_is_redacted() {
        for by in HIDDEN_SPLITTERS {
            let mut c = Collector::new(Redactor::new([SPLIT_SECRET]));
            c.ingest(1000, vec![result(&split_secret(by), "Bash", 10, None)]);
            let (spans, _, _) = c.finish();
            let id = spans
                .first()
                .and_then(|s| s.tool_use_id.clone())
                .expect("id");
            assert!(!id.contains("hunter"), "{by:?}: {id}");
        }
    }

    #[test]
    fn a_split_secret_straddling_the_name_cap_leaves_no_fragment() {
        let redactor = Redactor::new([SPLIT_SECRET]);
        for by in HIDDEN_SPLITTERS {
            let name = format!(
                "{}{}tail",
                "a".repeat(MAX_TIMING_NAME_BYTES - "hunter2-hu".len()),
                split_secret(by)
            );
            let out = one_line(&redactor, &name, "fallback");
            assert!(!out.contains("hunter"), "{by:?}: {out}");
            assert!(out.len() <= MAX_TIMING_NAME_BYTES);
        }
    }

    #[test]
    fn ordinary_names_and_ids_survive_the_strip() {
        let redactor = Redactor::new([SPLIT_SECRET]);
        assert_eq!(
            one_line(&redactor, "mcp__srv__Lookup", "f"),
            "mcp__srv__Lookup"
        );
        assert_eq!(
            one_line(&redactor, "L\u{e9}a \u{65e5}\u{672c}", "f"),
            "L\u{e9}a \u{65e5}\u{672c}"
        );
        assert_eq!(one_line(&redactor, "toolu_01AbC-9", ""), "toolu_01AbC-9");
        assert_eq!(one_line(&redactor, "\u{200b}\u{1}", "fallback"), "fallback");
    }

    #[test]
    fn the_request_parts_sum_to_wall_and_spans_stay_inside_the_job() {
        let mut c = collector();
        c.ingest(
            900,
            vec![
                api(300),
                result("t1", "Read", 200, None),
                result("t2", "Bash", 100, Some("ls")),
            ],
        );
        c.ingest(5000, vec![api(400)]);
        let (spans, foreground, notes) = c.finish();
        let gathered = super::Gathered {
            t0: Instant::now(),
            unix_start_ms: 0,
            agent_start_ms: 100,
            agent_end_ms: 2000,
            spans,
            foreground,
            background: Vec::new(),
            notes: notes.into_iter().collect(),
        };
        let built = gathered.request("job1", 3, "the-box", 2500);
        let summary = built.request.summary.expect("summary");
        assert_eq!(summary.wall_ms, 2500);
        assert_eq!(
            summary.api_wait_ms
                + summary.tool_ms
                + summary.shell_ms
                + summary.idle_ms
                + summary.overhead_ms,
            summary.wall_ms
        );
        assert_eq!(summary.overhead_ms, 100 + 500);
        assert!(built.request.spans.iter().all(|s| s.end_ms <= 2500));
        assert_eq!(built.request.attempt, 3);
        assert_eq!(built.request.r#box, "the-box");
        assert_eq!(built.request.shell_commands.len(), 1);
        assert!(built.request.shell_commands.len() <= MAX_SHELL_COMMANDS);
    }

    fn body(records: &[serde_json::Value]) -> Vec<u8> {
        json!({"resourceLogs": [{"resource": {"attributes": []},
            "scopeLogs": [{"scope": {"name": "x"}, "logRecords": records}]}]})
        .to_string()
        .into_bytes()
    }

    fn api_record(ms: u64) -> serde_json::Value {
        json!({"timeUnixNano": "1", "attributes": [
            {"key": "event.name", "value": {"stringValue": "claude_code.api_request"}},
            {"key": "duration_ms", "value": {"intValue": ms.to_string()}}
        ]})
    }

    fn wiring_for_test(quiet_ms: u64, deadline_ms: u64) -> TimingWiring {
        #[derive(Debug)]
        struct Never;
        impl TimingSink for Never {
            fn send(
                &self,
                _: fleet_proto::v1::ReportTimingRequest,
            ) -> super::BoxFuture<
                '_,
                Result<crate::poller::TimingOutcome, crate::poller::TimingReportError>,
            > {
                Box::pin(std::future::pending())
            }
        }
        TimingWiring::new(std::sync::Arc::new(Never)).with_flush(
            std::time::Duration::from_millis(quiet_ms),
            std::time::Duration::from_millis(deadline_ms),
        )
    }

    fn capture_of(rx: mpsc::Receiver<Vec<u8>>) -> TelemetryCapture {
        TelemetryCapture {
            port: NonZeroU16::new(4000).expect("port"),
            token: "tok".to_owned(),
            bodies: rx,
        }
    }

    #[tokio::test]
    async fn capture_collects_queued_bodies_and_waits_for_quiet() {
        let (tx, rx) = mpsc::channel(8);
        let wiring = wiring_for_test(40, 2000);
        let capture = Capture::start(
            &wiring,
            Instant::now(),
            &Redactor::default(),
            Some(capture_of(rx)),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        tx.send(body(&[api_record(5)])).await.expect("send");
        tx.send(b"not json".to_vec()).await.expect("send");
        let gathered = capture.stop(None).await;
        assert_eq!(gathered.spans.len(), 1);
        assert!(gathered.notes.contains(&Note::BodyUnparsable));
        assert!(!gathered.notes.contains(&Note::FlushIncomplete));
    }

    #[tokio::test]
    async fn a_stream_that_never_goes_quiet_ends_at_the_deadline_and_is_noted() {
        let (tx, rx) = mpsc::channel(64);
        let wiring = wiring_for_test(200, 150);
        let capture = Capture::start(
            &wiring,
            Instant::now(),
            &Redactor::default(),
            Some(capture_of(rx)),
        )
        .await;
        let pump = tokio::spawn(async move {
            for _ in 0..40 {
                if tx.send(body(&[api_record(5)])).await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        let gathered = capture.stop(None).await;
        pump.abort();
        assert!(gathered.notes.contains(&Note::FlushIncomplete));
    }

    #[tokio::test]
    async fn a_capture_with_no_receiver_still_stops_with_no_spans() {
        let wiring = wiring_for_test(10, 100);
        let capture = Capture::start(&wiring, Instant::now(), &Redactor::default(), None).await;
        let gathered = capture.stop(None).await;
        assert_eq!(gathered.spans.len(), 0);
        assert_eq!(gathered.notes.len(), 0);
    }

    #[test]
    fn the_wire_log_is_found_in_a_session_dir_and_shifted_to_the_job_clock() {
        let dir = tempfile::tempdir().expect("dir");
        let session = dir.path().join("sessions").join("s1");
        std::fs::create_dir_all(&session).expect("mkdir");
        std::fs::write(
            session.join("wire.jsonl"),
            include_str!("../../tests/fixtures/kimi-wire.synthetic.jsonl"),
        )
        .expect("write");
        let spans = super::read_wire(dir.path(), 1000, &Redactor::default()).expect("read");
        assert_ne!(spans.len(), 0);
        assert!(spans.iter().all(|s| s.span.kind == SpanKind::ApiWait));
        assert!(spans.iter().any(|s| s.span.interval.start_ms() == 100));
        let none = super::read_wire(dir.path(), u64::MAX / 2, &Redactor::default()).expect("read");
        assert_eq!(none.len(), 0);
        let missing = super::read_wire(&dir.path().join("absent"), 0, &Redactor::default());
        assert_eq!(missing.map(|v| v.len()), Ok(0));
    }
}
