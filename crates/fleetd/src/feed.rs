//! Feeds redacted transcript lines to the telemetry parser and queues the events for `ReportJob`.
//!
//! The feed sits beside the transcript path and never gates it. A line over [`MAX_LINE_BYTES`], a
//! line past the [`MAX_FED_BYTES`] budget and a parser panic only raise a counter. After a panic
//! the parser is dropped and the summary reports `parser` as missing. Event text is redacted
//! by the parser before it cuts a field at its cap, because a secret escaped inside the JSON string
//! only matches the redactor once decoded, and a cut would leave a prefix of it. A second pass in
//! `convert` covers the fields the parser does not cut.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};

use fleet_core::Redactor;
use fleet_proto::MAX_EVENTS_PER_REPORT;
use fleet_proto::v1 as pb;
use tokio::time::Instant;

use crate::phase::Phases;
use crate::runner::{UNKNOWN_STAMP, VersionStamp};
use crate::telemetry::{
    EventKind, FetchPhase, FetchRecordError, JobEvent, JobSummary, Limits, Telemetry, Terminal,
};
use crate::toolhook::ToolReport;

pub(crate) const MAX_LINE_BYTES: usize = 1 << 20;
pub(crate) const MAX_FED_BYTES: u64 = 32 << 20;
pub(crate) const MAX_PENDING_EVENTS: usize = 4096;
pub(crate) const MAX_HOOKED_IDS: usize = 4096;
pub(crate) const MAX_WAITING_HOOKS: usize = 256;
const PARSER_MISSING: &str = "parser";
const FETCH_OUTCOME_MISSING: &str = "fetch_outcome";

type Parse = fn(&mut Telemetry, &str, u64, &dyn Fn(&str) -> String) -> Vec<JobEvent>;

/// Lines and events the feed did not process, for the log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) oversize: u64,
    pub(crate) over_budget: u64,
    pub(crate) panics: u64,
    pub(crate) dropped: u64,
    pub(crate) hook_duplicates: u64,
    pub(crate) hook_dropped: u64,
}

/// Per-job telemetry state: the parser, the clock origin and the events no report has delivered.
#[derive(Debug)]
pub(crate) struct Feed {
    parser: Option<Telemetry>,
    parse: Parse,
    started: Instant,
    fed_bytes: u64,
    pending: VecDeque<pb::JobEvent>,
    counters: Counters,
    hooked: HashSet<String>,
    waiting: HashMap<String, ToolReport>,
    stamp: VersionStamp,
    phases: Phases,
    fetch_outcome_lost: bool,
}

impl Feed {
    pub(crate) fn new(started: Instant) -> Self {
        Self::with(started, Limits::default(), Telemetry::feed_line_with)
    }

    pub(crate) fn with(started: Instant, limits: Limits, parse: Parse) -> Self {
        Self {
            parser: Some(Telemetry::new(limits)),
            parse,
            started,
            fed_bytes: 0,
            pending: VecDeque::new(),
            counters: Counters::default(),
            hooked: HashSet::new(),
            waiting: HashMap::new(),
            stamp: VersionStamp::default(),
            phases: Phases::default(),
            fetch_outcome_lost: false,
        }
    }

    pub(crate) fn record(&mut self, phases: Phases) {
        self.phases.merge(phases);
    }

    pub(crate) fn set_stamp(&mut self, stamp: VersionStamp) {
        self.stamp = stamp;
    }

    #[cfg(test)]
    pub(crate) const fn counters(&self) -> Counters {
        self.counters
    }

    pub(crate) fn line(&mut self, redactor: &Redactor, clean: &str, now: Instant) {
        if clean.len() > MAX_LINE_BYTES {
            self.counters.oversize += 1;
            return;
        }
        let len = u64::try_from(clean.len()).unwrap_or(u64::MAX);
        if self.fed_bytes.saturating_add(len) > MAX_FED_BYTES {
            self.counters.over_budget += 1;
            return;
        }
        let Some(parser) = self.parser.as_mut() else {
            return;
        };
        self.fed_bytes += len;
        let ts_ms = u64::try_from(now.saturating_duration_since(self.started).as_millis())
            .unwrap_or(u64::MAX);
        let parse = self.parse;
        let redact = |text: &str| redactor.redact_str(text).into_owned();
        if let Ok(events) = catch_unwind(AssertUnwindSafe(|| parse(parser, clean, ts_ms, &redact)))
        {
            for event in events {
                self.queue(convert(redactor, event));
            }
        } else {
            self.counters.panics += 1;
            self.parser = None;
        }
        self.retry_waiting();
    }

    /// Records one fetch event, failing when the feed would not keep it.
    ///
    /// The feed refuses when it is closed, when the byte budget is spent (a line already skipped
    /// over budget counts, and so does a feed with no room left), when the event cap is already
    /// full (the event after the last stored one, the 2001st by default, becomes the truncation
    /// marker and fails; the one that reaches the cap is kept), and when the URL is over
    /// [`MAX_FETCH_URL_BYTES`] after redaction. An outcome phase carries the HTTP status into
    /// `exit_code` and the body length into `out_bytes`; an intent carries neither. A refused outcome record adds
    /// `fetch_outcome` to the summary `missing` list. The caller refuses the fetch when an
    /// intent record fails. "Recorded" means this feed accepted the event, not that the server
    /// confirmed it.
    pub(crate) fn record_fetch(
        &mut self,
        redactor: &Redactor,
        url: &str,
        phase: FetchPhase,
        now: Instant,
    ) -> Result<(), FetchRecordError> {
        let result = self.try_record_fetch(redactor, url, phase, now);
        if result.is_err() && !matches!(phase, FetchPhase::Intent) {
            self.fetch_outcome_lost = true;
        }
        result
    }

    fn try_record_fetch(
        &mut self,
        redactor: &Redactor,
        url: &str,
        phase: FetchPhase,
        now: Instant,
    ) -> Result<(), FetchRecordError> {
        if self.parser.is_none() {
            return Err(FetchRecordError::Closed);
        }
        if self.counters.over_budget > 0 || self.fed_bytes >= MAX_FED_BYTES {
            return Err(FetchRecordError::OverBudget);
        }
        let ts_ms = u64::try_from(now.saturating_duration_since(self.started).as_millis())
            .unwrap_or(u64::MAX);
        let redact = |text: &str| redactor.redact_str(text).into_owned();
        let mut stored = Vec::new();
        let parser = self.parser.as_mut().ok_or(FetchRecordError::Closed)?;
        let result = parser.record_fetch(url, phase, ts_ms, &redact, &mut stored);
        for event in stored {
            self.queue(convert(redactor, event));
        }
        result
    }

    /// Applies one tool hook report to the matching tool event.
    ///
    /// A `(job, tool_use_id)` pair applies once: a second report for an id already applied or
    /// waiting is counted and ignored, which also covers the `PostToolUse` and
    /// `PostToolUseFailure` pair a failing call fires. A report that arrives before its tool
    /// event waits, at most 256 at a time, and applies when the event appears. An event
    /// already acked keeps what it reported and only the summary changes.
    pub(crate) fn hook(&mut self, report: ToolReport) {
        if self.hooked.contains(&report.tool_use_id)
            || self.waiting.contains_key(&report.tool_use_id)
        {
            self.counters.hook_duplicates += 1;
            return;
        }
        if self.parser.is_none() {
            self.counters.hook_dropped += 1;
            return;
        }
        if self.apply(&report) {
            self.mark_hooked(report.tool_use_id);
        } else if self.waiting.len() >= MAX_WAITING_HOOKS {
            self.counters.hook_dropped += 1;
        } else {
            self.waiting.insert(report.tool_use_id.clone(), report);
        }
    }

    fn mark_hooked(&mut self, id: String) {
        if self.hooked.len() < MAX_HOOKED_IDS {
            self.hooked.insert(id);
        }
    }

    fn apply(&mut self, report: &ToolReport) -> bool {
        let Some(parser) = self.parser.as_mut() else {
            return false;
        };
        if !parser.apply_hook(&report.tool_use_id, report.exit_code, report.dur_ms) {
            return false;
        }
        let queued = self
            .pending
            .iter_mut()
            .find(|event| event.tool_use_id.as_deref() == Some(report.tool_use_id.as_str()));
        if let Some(event) = queued {
            if report.exit_code.is_some() {
                event.exit_code = report.exit_code;
            }
            if report.dur_ms.is_some() {
                event.dur_ms = report.dur_ms;
            }
        }
        true
    }

    fn retry_waiting(&mut self) {
        if self.waiting.is_empty() {
            return;
        }
        let ids: Vec<String> = self.waiting.keys().cloned().collect();
        for id in ids {
            let Some(report) = self.waiting.get(&id).cloned() else {
                continue;
            };
            if self.apply(&report) {
                self.waiting.remove(&id);
                self.mark_hooked(id);
            }
        }
    }

    fn queue(&mut self, event: pb::JobEvent) {
        self.pending.push_back(event);
        while self.pending.len() > MAX_PENDING_EVENTS {
            self.pending.pop_front();
            self.counters.dropped += 1;
        }
    }

    pub(crate) fn backlog_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(crate) fn batch(&self) -> Vec<pb::JobEvent> {
        self.pending
            .iter()
            .take(MAX_EVENTS_PER_REPORT)
            .cloned()
            .collect()
    }

    pub(crate) fn ack(&mut self, upto: u32) {
        while self.pending.front().is_some_and(|event| event.seq <= upto) {
            self.pending.pop_front();
        }
    }

    pub(crate) fn result_subtype(&self) -> Option<&str> {
        self.parser.as_ref().and_then(Telemetry::result_subtype)
    }

    pub(crate) fn finish(&mut self, terminal: Terminal) -> pb::JobSummary {
        let counters = self.counters;
        tracing::debug!(
            oversize = counters.oversize,
            over_budget = counters.over_budget,
            panics = counters.panics,
            dropped = counters.dropped,
            "job telemetry closed"
        );
        let stamp = self.stamp.clone();
        let phases = self.phases;
        let Some(parser) = self.parser.take() else {
            let mut missing = pb::JobSummary {
                missing: vec![PARSER_MISSING.to_owned()],
                ..pb::JobSummary::default()
            };
            if self.fetch_outcome_lost {
                missing.missing.push(FETCH_OUTCOME_MISSING.to_owned());
            }
            return phased(stamped(missing, &stamp), phases);
        };
        let stamp = stamp.with_model(parser.model());
        let mut summary = summary(parser.finish(terminal));
        if self.fetch_outcome_lost {
            summary.missing.push(FETCH_OUTCOME_MISSING.to_owned());
        }
        phased(stamped(summary, &stamp), phases)
    }
}

fn phased(mut summary: pb::JobSummary, phases: Phases) -> pb::JobSummary {
    summary.clone_ms = phases.checkout;
    summary.push_ms = phases.push;
    summary.pr_ms = phases.pr;
    summary
}

fn stamped(mut summary: pb::JobSummary, stamp: &VersionStamp) -> pb::JobSummary {
    let known = |value: &str| (value != UNKNOWN_STAMP).then(|| value.to_owned());
    summary.bundle_sha = known(&stamp.bundle_sha);
    summary.claude_version = known(&stamp.claude_version);
    summary.model = known(&stamp.model);
    summary
}

fn convert(redactor: &Redactor, event: JobEvent) -> pb::JobEvent {
    let clean = |text: Option<String>| text.map(|text| redactor.redact_str(&text).into_owned());
    let kind = match event.kind {
        EventKind::Tool => pb::JobEventKind::Tool,
        EventKind::Denial => pb::JobEventKind::Denial,
        EventKind::ApiRetry => pb::JobEventKind::ApiRetry,
        EventKind::Phase => pb::JobEventKind::Phase,
        EventKind::Stuck => pb::JobEventKind::Stuck,
        EventKind::Fetch => pb::JobEventKind::Fetch,
    };
    pb::JobEvent {
        seq: event.seq,
        ts_ms: event.ts_ms,
        kind: kind.into(),
        tool_use_id: clean(event.tool_use_id),
        tool: clean(event.tool),
        ok: event.ok,
        exit_code: event.exit_code,
        dur_ms: event.dur_ms,
        out_bytes: event.out_bytes,
        out_hash: event.out_hash,
        cmd: if event.kind == EventKind::Fetch {
            event.cmd
        } else {
            clean(event.cmd)
        },
        detail: clean(event.detail),
    }
}

fn summary(summary: JobSummary) -> pb::JobSummary {
    pb::JobSummary {
        turns: summary.turns,
        duration_ms: summary.duration_ms,
        duration_api_ms: summary.duration_api_ms,
        stop_reason: summary.stop_reason,
        result_subtype: summary.result_subtype,
        cost_est_usd: summary.cost_est_usd,
        tokens_in: summary.tokens_in,
        tokens_out: summary.tokens_out,
        tokens_cache_read: summary.tokens_cache_read,
        tokens_cache_write: summary.tokens_cache_write,
        tool_calls: summary.tool_calls,
        tool_errors: summary.tool_errors,
        bash_calls: summary.bash_calls,
        bash_nonzero: summary.bash_nonzero,
        denials: summary.denials,
        api_retries: summary.api_retries,
        first_edit_ms: summary.first_edit_ms,
        complete: summary.complete,
        missing: summary.missing,
        stuck_rule: summary.stuck.map(|stuck| stuck.rule.name().to_owned()),
        stuck_at_seq: summary.stuck.map(|stuck| stuck.seq),
        stuck_at_ms: summary.stuck.map(|stuck| stuck.ts_ms),
        bundle_sha: None,
        claude_version: None,
        model: None,
        clone_ms: None,
        push_ms: None,
        pr_ms: None,
        queue_wait_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::stuck::{Stuck, StuckRule};
    use crate::telemetry::MAX_FETCH_URL_BYTES;

    const SECRET: &str = "pa\"ss-word-xyz";

    fn fresh() -> (Feed, Instant) {
        let start = Instant::now();
        (Feed::new(start), start)
    }

    fn redactor() -> Redactor {
        Redactor::new([SECRET])
    }

    fn bash(id: &str, command: &str) -> String {
        json!({"type":"assistant","message":{"id":id,"content":[
            {"type":"tool_use","id":id,"name":"Bash","input":{"command":command}}]}})
        .to_string()
    }

    fn done(id: &str) -> String {
        json!({"type":"user","message":{"content":[
            {"type":"tool_result","tool_use_id":id,"content":"out"}]}})
        .to_string()
    }

    fn many(count: usize) -> (String, String) {
        let uses: Vec<_> = (0..count)
            .map(|i| json!({"type":"tool_use","id":format!("t{i}"),"name":"Bash","input":{"command":"ls"}}))
            .collect();
        let results: Vec<_> = (0..count)
            .map(|i| json!({"type":"tool_result","tool_use_id":format!("t{i}"),"content":"o"}))
            .collect();
        (
            json!({"type":"assistant","message":{"id":"m","content":uses}}).to_string(),
            json!({"type":"user","message":{"content":results}}).to_string(),
        )
    }

    fn seqs(events: &[pb::JobEvent]) -> Vec<u32> {
        events.iter().map(|event| event.seq).collect()
    }

    #[test]
    fn a_line_over_the_cap_is_skipped_and_counted_and_one_at_the_cap_is_fed() {
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &"x".repeat(MAX_LINE_BYTES + 1), start);
        assert_eq!(feed.counters().oversize, 1);
        assert_eq!(feed.fed_bytes, 0);
        feed.line(&redactor(), &"x".repeat(MAX_LINE_BYTES), start);
        assert_eq!(feed.counters().oversize, 1);
        assert_eq!(feed.fed_bytes, MAX_LINE_BYTES as u64);
    }

    #[test]
    fn lines_past_the_byte_budget_are_skipped_and_counted() {
        let (mut feed, start) = fresh();
        let line = "x".repeat(MAX_LINE_BYTES);
        for _ in 0..32 {
            feed.line(&redactor(), &line, start);
        }
        assert_eq!(feed.counters().over_budget, 0);
        assert_eq!(feed.fed_bytes, MAX_FED_BYTES);
        feed.line(&redactor(), "x", start);
        assert_eq!(feed.counters().over_budget, 1);
        assert_eq!(feed.fed_bytes, MAX_FED_BYTES);
    }

    fn boom(_: &mut Telemetry, _: &str, _: u64, _: &dyn Fn(&str) -> String) -> Vec<JobEvent> {
        panic!("boom");
    }

    #[test]
    fn a_parser_panic_is_counted_once_and_the_summary_names_the_parser() {
        let (_, start) = fresh();
        let mut feed = Feed::with(start, Limits::default(), boom);
        feed.line(&redactor(), "a", start);
        feed.line(&redactor(), "b", start);
        assert_eq!(feed.counters().panics, 1);
        assert!(feed.backlog_empty());
        let summary = feed.finish(Terminal::Failed);
        assert_eq!(summary.missing, ["parser"]);
        assert!(!summary.complete);
    }

    #[test]
    fn pending_events_are_bounded_and_the_oldest_are_dropped() {
        let start = Instant::now();
        let limits = Limits {
            max_events: 100_000,
            max_event_bytes: 1 << 30,
            ..Limits::default()
        };
        let mut feed = Feed::with(start, limits, Telemetry::feed_line_with);
        let (uses, results) = many(5000);
        feed.line(&redactor(), &uses, start);
        feed.line(&redactor(), &results, start);
        assert_eq!(feed.pending.len(), MAX_PENDING_EVENTS);
        assert_eq!(feed.counters().dropped, 5000 - MAX_PENDING_EVENTS as u64);
        assert_eq!(feed.pending.front().map(|e| e.seq), Some(904));
        assert_eq!(feed.pending.back().map(|e| e.seq), Some(4999));
    }

    #[test]
    fn a_batch_holds_256_events_and_an_ack_removes_through_its_seq() {
        let (mut feed, start) = fresh();
        let (uses, results) = many(300);
        feed.line(&redactor(), &uses, start);
        feed.line(&redactor(), &results, start);
        assert_eq!(seqs(&feed.batch()), (0..256).collect::<Vec<_>>());
        assert_eq!(feed.pending.len(), 300);
        feed.ack(0);
        assert_eq!(feed.pending.front().map(|e| e.seq), Some(1));
        feed.ack(255);
        assert_eq!(seqs(&feed.batch()), (256..300).collect::<Vec<_>>());
        feed.ack(299);
        assert!(feed.backlog_empty());
    }

    #[test]
    fn event_time_is_the_elapsed_ms_since_start_and_never_negative() {
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &bash("a", "ls"), start);
        feed.line(&redactor(), &done("a"), start + Duration::from_millis(1500));
        assert_eq!(feed.batch().first().map(|e| e.ts_ms), Some(1500));
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &bash("a", "ls"), start);
        feed.line(&redactor(), &done("a"), start - Duration::from_millis(5));
        assert_eq!(feed.batch().first().map(|e| e.ts_ms), Some(0));
    }

    #[test]
    fn decoded_event_text_is_redacted_in_every_field() {
        let (mut feed, start) = fresh();
        let escaped = json!(SECRET).to_string();
        let tool = format!(
            "{{\"type\":\"assistant\",\"message\":{{\"id\":\"m\",\"content\":[{{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"Bash\",\"input\":{{\"command\":{escaped}}}}}]}}}}"
        );
        feed.line(&redactor(), &tool, start);
        feed.line(&redactor(), &done("t1"), start);
        let denial = json!({"type":"system","subtype":"permission_denied","tool_name":SECRET,
            "tool_use_id":SECRET,"message":SECRET})
        .to_string();
        feed.line(&redactor(), &denial, start);
        let events = feed.batch();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].cmd.as_deref(), Some("[REDACTED]"));
        assert_eq!(events[1].tool_use_id.as_deref(), Some("[REDACTED]"));
        assert_eq!(events[1].tool.as_deref(), Some("[REDACTED]"));
        assert_eq!(events[1].detail.as_deref(), Some("[REDACTED]"));
    }

    const ESCAPED: &str = "ab\"cd\\ef\ngh-zzTAIL";

    fn unicode_escaped(text: &str) -> String {
        text.replace('\\', "\\u005c")
            .replace('"', "\\u0022")
            .replace('\n', "\\u000a")
    }

    fn bash_raw(id: &str, encoded: &str) -> String {
        format!(
            "{{\"type\":\"assistant\",\"message\":{{\"id\":\"m\",\"content\":[{{\"type\":\"tool_use\",\"id\":\"{id}\",\"name\":\"Bash\",\"input\":{{\"command\":\"{encoded}\"}}}}]}}}}"
        )
    }

    fn denial_raw(encoded: &str) -> String {
        format!(
            "{{\"type\":\"system\",\"subtype\":\"permission_denied\",\"tool_name\":\"Bash\",\"tool_use_id\":\"d\",\"message\":\"{encoded}\"}}"
        )
    }

    fn assert_no_prefix(events: &[pb::JobEvent], secret: &str) {
        let fields = events.iter().flat_map(|event| {
            [&event.tool_use_id, &event.tool, &event.cmd, &event.detail]
                .into_iter()
                .flatten()
        });
        for field in fields {
            for end in 6..=secret.len() {
                assert!(
                    !field.contains(&secret[..end]),
                    "prefix of {end} bytes leaked"
                );
            }
        }
    }

    #[test]
    fn an_escaped_secret_straddling_a_cap_leaves_no_prefix_in_any_field() {
        let redactor = Redactor::new([ESCAPED]);
        let serde_cmd = json!(format!("{}{ESCAPED}", "a".repeat(500))).to_string();
        let serde_detail = json!(format!("{}{ESCAPED}", "b".repeat(1010))).to_string();
        let forms = [
            (
                bash_raw(
                    "t1",
                    &unicode_escaped(&format!("{}{ESCAPED}", "a".repeat(500))),
                ),
                denial_raw(&unicode_escaped(&format!("{}{ESCAPED}", "b".repeat(1010)))),
            ),
            (
                bash_raw("t1", &serde_cmd[1..serde_cmd.len() - 1]),
                denial_raw(&serde_detail[1..serde_detail.len() - 1]),
            ),
        ];
        for (tool, denial) in forms {
            let (mut feed, start) = fresh();
            feed.line(&redactor, &tool, start);
            feed.line(&redactor, &done("t1"), start);
            feed.line(&redactor, &denial, start);
            let events = feed.batch();
            assert_eq!(events.len(), 2);
            assert_no_prefix(&events, ESCAPED);
            assert_eq!(events[0].cmd.as_deref().map(str::len), Some(510));
            assert!(
                events[0]
                    .cmd
                    .as_deref()
                    .is_some_and(|c| c.ends_with("[REDACTED]"))
            );
            assert_eq!(events[1].detail.as_deref().map(str::len), Some(1020));
            assert!(
                events[1]
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.ends_with("[REDACTED]"))
            );
        }
    }

    #[test]
    fn an_event_converts_field_for_field() {
        let event = JobEvent {
            seq: 3,
            ts_ms: 4,
            kind: EventKind::Phase,
            tool_use_id: Some("id".into()),
            tool: Some("Bash".into()),
            ok: Some(false),
            exit_code: Some(-2),
            dur_ms: Some(5),
            out_bytes: Some(6),
            out_hash: Some("abcd".into()),
            cmd: Some("ls".into()),
            detail: Some("why".into()),
        };
        assert_eq!(
            convert(&redactor(), event),
            pb::JobEvent {
                seq: 3,
                ts_ms: 4,
                kind: pb::JobEventKind::Phase.into(),
                tool_use_id: Some("id".into()),
                tool: Some("Bash".into()),
                ok: Some(false),
                exit_code: Some(-2),
                dur_ms: Some(5),
                out_bytes: Some(6),
                out_hash: Some("abcd".into()),
                cmd: Some("ls".into()),
                detail: Some("why".into()),
            }
        );
    }

    #[test]
    fn every_event_kind_converts_to_its_own_proto_kind() {
        let kinds = [
            (EventKind::Tool, pb::JobEventKind::Tool),
            (EventKind::Denial, pb::JobEventKind::Denial),
            (EventKind::ApiRetry, pb::JobEventKind::ApiRetry),
            (EventKind::Phase, pb::JobEventKind::Phase),
            (EventKind::Stuck, pb::JobEventKind::Stuck),
            (EventKind::Fetch, pb::JobEventKind::Fetch),
        ];
        for (kind, expected) in kinds {
            let event = JobEvent {
                kind,
                ..JobEvent::default()
            };
            assert_eq!(convert(&redactor(), event).kind, i32::from(expected));
        }
    }

    #[test]
    fn a_summary_converts_field_for_field() {
        let source = JobSummary {
            turns: Some(1),
            duration_ms: Some(2),
            duration_api_ms: Some(3),
            stop_reason: Some("end".into()),
            result_subtype: Some("success".into()),
            cost_est_usd: Some(0.25),
            tokens_in: Some(4),
            tokens_out: Some(5),
            tokens_cache_read: Some(6),
            tokens_cache_write: Some(7),
            tool_calls: Some(8),
            tool_errors: Some(9),
            bash_calls: Some(10),
            bash_nonzero: Some(11),
            denials: Some(12),
            api_retries: Some(13),
            first_edit_ms: Some(14),
            complete: true,
            missing: vec!["exit_codes".into()],
            terminal: None,
            stuck: Some(Stuck {
                rule: StuckRule::Alternating,
                seq: 15,
                ts_ms: 16,
            }),
        };
        assert_eq!(
            summary(source),
            pb::JobSummary {
                turns: Some(1),
                duration_ms: Some(2),
                duration_api_ms: Some(3),
                stop_reason: Some("end".into()),
                result_subtype: Some("success".into()),
                cost_est_usd: Some(0.25),
                tokens_in: Some(4),
                tokens_out: Some(5),
                tokens_cache_read: Some(6),
                tokens_cache_write: Some(7),
                tool_calls: Some(8),
                tool_errors: Some(9),
                bash_calls: Some(10),
                bash_nonzero: Some(11),
                denials: Some(12),
                api_retries: Some(13),
                first_edit_ms: Some(14),
                complete: true,
                missing: vec!["exit_codes".into()],
                stuck_rule: Some("alternating".into()),
                stuck_at_seq: Some(15),
                stuck_at_ms: Some(16),
                bundle_sha: None,
                claude_version: None,
                model: None,
                clone_ms: None,
                push_ms: None,
                pr_ms: None,
                queue_wait_ms: None,
            }
        );
    }

    #[test]
    fn an_unset_stuck_rule_converts_to_unset_fields() {
        let converted = summary(JobSummary::default());
        assert_eq!(converted.stuck_rule, None);
        assert_eq!(converted.stuck_at_seq, None);
        assert_eq!(converted.stuck_at_ms, None);
    }
    fn report(id: &str, exit: Option<i32>, dur: Option<u64>) -> ToolReport {
        ToolReport {
            tool_use_id: id.to_owned(),
            tool_name: "Bash".to_owned(),
            exit_code: exit,
            dur_ms: dur,
        }
    }

    fn stamp(model: &str) -> VersionStamp {
        VersionStamp {
            bundle_sha: "a".repeat(64),
            claude_version: "2.1.289".to_owned(),
            model: model.to_owned(),
        }
    }

    fn init(model: &str) -> String {
        json!({"type":"system","subtype":"init","model":model}).to_string()
    }

    #[test]
    fn the_stamp_and_the_init_model_reach_the_summary() {
        let (mut feed, start) = fresh();
        feed.set_stamp(stamp(UNKNOWN_STAMP));
        feed.line(&redactor(), &init("claude-opus-4"), start);
        let summary = feed.finish(Terminal::Succeeded);
        assert_eq!(summary.bundle_sha, Some("a".repeat(64)));
        assert_eq!(summary.claude_version.as_deref(), Some("2.1.289"));
        assert_eq!(summary.model.as_deref(), Some("claude-opus-4"));
    }

    #[test]
    fn an_unknown_stamp_field_is_unset_never_the_word_unknown() {
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &init("bad\u{7}model"), start);
        let summary = feed.finish(Terminal::Succeeded);
        assert_eq!(summary.bundle_sha, None);
        assert_eq!(summary.claude_version, None);
        assert_eq!(summary.model, None);
    }

    #[test]
    fn a_dead_parser_still_sends_the_known_stamp_fields() {
        let (_, start) = fresh();
        let mut feed = Feed::with(start, Limits::default(), boom);
        feed.set_stamp(stamp(UNKNOWN_STAMP));
        feed.line(&redactor(), "a", start);
        let summary = feed.finish(Terminal::Failed);
        assert_eq!(summary.bundle_sha, Some("a".repeat(64)));
        assert_eq!(summary.claude_version.as_deref(), Some("2.1.289"));
        assert_eq!(summary.model, None);
    }

    #[test]
    fn the_hook_caps_are_pinned() {
        assert_eq!(MAX_HOOKED_IDS, 4096);
        assert_eq!(MAX_WAITING_HOOKS, 256);
    }

    #[test]
    fn a_hook_after_its_event_fills_the_queued_event_and_the_summary() {
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &bash("a", "ls"), start);
        feed.line(&redactor(), &done("a"), start);
        assert_eq!(feed.batch().first().map(|e| e.exit_code), Some(None));
        feed.hook(report("a", Some(2), Some(50)));
        let event = feed.batch().into_iter().next().unwrap();
        assert_eq!((event.exit_code, event.dur_ms), (Some(2), Some(50)));
        let summary = feed.finish(Terminal::Succeeded);
        assert_eq!(summary.bash_nonzero, Some(1));
        assert!(!summary.missing.contains(&"exit_codes".to_owned()));
    }

    #[test]
    fn a_hook_for_an_acked_event_still_counts_in_the_summary() {
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &bash("a", "ls"), start);
        feed.line(&redactor(), &done("a"), start);
        feed.ack(0);
        feed.hook(report("a", Some(1), None));
        assert!(feed.backlog_empty());
        assert_eq!(feed.finish(Terminal::Succeeded).bash_nonzero, Some(1));
    }

    #[test]
    fn a_hook_before_its_event_waits_and_applies_when_the_event_appears() {
        let (mut feed, start) = fresh();
        feed.hook(report("a", Some(3), Some(9)));
        assert_eq!(feed.waiting.len(), 1);
        feed.line(&redactor(), &bash("a", "ls"), start);
        assert_eq!(feed.waiting.len(), 1);
        feed.line(&redactor(), &done("a"), start);
        assert_eq!(feed.waiting.len(), 0);
        let event = feed.batch().into_iter().next().unwrap();
        assert_eq!((event.exit_code, event.dur_ms), (Some(3), Some(9)));
        assert_eq!(feed.finish(Terminal::Succeeded).bash_nonzero, Some(1));
    }

    #[test]
    fn a_second_report_for_one_tool_use_applies_once() {
        let (mut feed, start) = fresh();
        feed.line(&redactor(), &bash("a", "ls"), start);
        feed.line(&redactor(), &done("a"), start);
        feed.hook(report("a", Some(2), Some(5)));
        feed.hook(report("a", Some(7), Some(6)));
        assert_eq!(feed.counters().hook_duplicates, 1);
        let event = feed.batch().into_iter().next().unwrap();
        assert_eq!((event.exit_code, event.dur_ms), (Some(2), Some(5)));
        let (mut waiting, _) = fresh();
        waiting.hook(report("w", Some(1), None));
        waiting.hook(report("w", Some(9), None));
        assert_eq!(waiting.counters().hook_duplicates, 1);
        assert_eq!(waiting.waiting.get("w").map(|r| r.exit_code), Some(Some(1)));
    }

    #[test]
    fn waiting_hooks_are_capped_and_the_overflow_is_counted() {
        let (mut feed, _) = fresh();
        for n in 0..MAX_WAITING_HOOKS {
            feed.hook(report(&format!("t{n}"), Some(1), None));
        }
        assert_eq!(feed.counters().hook_dropped, 0);
        feed.hook(report("extra", Some(1), None));
        assert_eq!(feed.waiting.len(), MAX_WAITING_HOOKS);
        assert_eq!(feed.counters().hook_dropped, 1);
    }

    #[test]
    fn applied_ids_are_remembered_up_to_the_cap() {
        let start = Instant::now();
        let limits = Limits {
            max_events: 100_000,
            max_event_bytes: 1 << 30,
            ..Limits::default()
        };
        let mut feed = Feed::with(start, limits, Telemetry::feed_line_with);
        let (uses, results) = many(MAX_HOOKED_IDS + 1);
        feed.line(&redactor(), &uses, start);
        feed.line(&redactor(), &results, start);
        for n in 0..=MAX_HOOKED_IDS {
            feed.hook(report(&format!("t{n}"), Some(0), None));
        }
        assert_eq!(feed.hooked.len(), MAX_HOOKED_IDS);
        assert_eq!(feed.counters().hook_duplicates, 0);
        feed.hook(report("t0", Some(0), None));
        assert_eq!(feed.counters().hook_duplicates, 1);
        feed.hook(report(&format!("t{MAX_HOOKED_IDS}"), Some(0), None));
        assert_eq!(feed.counters().hook_duplicates, 1);
    }

    #[test]
    fn a_hook_after_the_parser_is_gone_is_counted_as_dropped() {
        let (_, start) = fresh();
        let mut feed = Feed::with(start, Limits::default(), boom);
        feed.line(&redactor(), "a", start);
        feed.hook(report("a", Some(1), None));
        assert_eq!(feed.counters().hook_dropped, 1);
        assert_eq!(feed.waiting.len(), 0);
    }

    const URL: &str = "https://docs.example.org/a?q=1";

    fn fetch_feed(max_events: usize) -> (Feed, Instant) {
        let start = Instant::now();
        let limits = Limits {
            max_events,
            ..Limits::default()
        };
        (Feed::with(start, limits, Telemetry::feed_line_with), start)
    }

    #[test]
    fn an_intent_and_an_outcome_queue_as_fetch_events_in_order() {
        let (mut feed, start) = fresh();
        let at = start + Duration::from_millis(40);
        feed.record_fetch(&redactor(), URL, FetchPhase::Intent, at)
            .unwrap();
        feed.record_fetch(
            &redactor(),
            URL,
            FetchPhase::Succeeded {
                status: 200,
                bytes: 1,
            },
            at,
        )
        .unwrap();
        feed.record_fetch(&redactor(), URL, FetchPhase::Failed { status: None }, at)
            .unwrap();
        let events = feed.batch();
        assert_eq!(seqs(&events), [0, 1, 2]);
        for event in &events {
            assert_eq!(event.kind, i32::from(pb::JobEventKind::Fetch));
            assert_eq!(event.cmd.as_deref(), Some(URL));
            assert_eq!(event.ts_ms, 40);
        }
        assert_eq!(events[0].detail.as_deref(), Some("intent"));
        assert_eq!(events[0].ok, None);
        assert_eq!(events[1].ok, Some(true));
        assert_eq!(events[2].ok, Some(false));
        let summary = feed.finish(Terminal::Succeeded);
        assert!(!summary.missing.iter().any(|m| m == "fetch_outcome"));
    }

    #[test]
    fn a_secret_in_the_url_is_redacted() {
        let (mut feed, start) = fresh();
        let url = format!("https://docs.example.org/?k={SECRET}");
        feed.record_fetch(&redactor(), &url, FetchPhase::Intent, start)
            .unwrap();
        let event = &feed.batch()[0];
        assert_eq!(
            event.cmd.as_deref(),
            Some("https://docs.example.org/?k=[REDACTED]")
        );
    }

    #[test]
    fn a_url_over_the_cap_is_refused_and_one_at_the_cap_is_kept_whole() {
        let (mut feed, start) = fresh();
        let long = format!("https://h.example/{}", "a".repeat(MAX_FETCH_URL_BYTES));
        assert!(long.len() > MAX_FETCH_URL_BYTES);
        assert_eq!(
            feed.record_fetch(&redactor(), &long, FetchPhase::Intent, start),
            Err(FetchRecordError::UrlTooLong)
        );
        assert!(feed.backlog_empty());
        let exact = format!("https://h.example/{}", "a".repeat(MAX_FETCH_URL_BYTES - 18));
        assert_eq!(exact.len(), MAX_FETCH_URL_BYTES);
        feed.record_fetch(&redactor(), &exact, FetchPhase::Intent, start)
            .unwrap();
        assert_eq!(feed.batch()[0].cmd.as_deref(), Some(exact.as_str()));
    }

    #[test]
    fn a_closed_feed_refuses_and_a_lost_outcome_is_named_in_missing() {
        let (_, start) = fresh();
        let mut feed = Feed::with(start, Limits::default(), boom);
        feed.line(&redactor(), "a", start);
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start),
            Err(FetchRecordError::Closed)
        );
        assert_eq!(
            feed.record_fetch(
                &redactor(),
                URL,
                FetchPhase::Succeeded {
                    status: 200,
                    bytes: 1
                },
                start
            ),
            Err(FetchRecordError::Closed)
        );
        let summary = feed.finish(Terminal::Failed);
        assert_eq!(summary.missing, ["parser", "fetch_outcome"]);
    }

    #[test]
    fn a_refused_intent_alone_leaves_fetch_outcome_out_of_missing() {
        let (mut feed, start) = fetch_feed(1);
        feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start)
            .unwrap();
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start),
            Err(FetchRecordError::Truncated)
        );
        let summary = feed.finish(Terminal::Failed);
        assert!(summary.missing.iter().any(|m| m == "events_truncated"));
        assert!(!summary.missing.iter().any(|m| m == "fetch_outcome"));
    }

    #[test]
    fn fetch_events_count_toward_the_cap_and_a_truncated_feed_refuses() {
        let (mut feed, start) = fetch_feed(2);
        feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start)
            .unwrap();
        feed.record_fetch(
            &redactor(),
            URL,
            FetchPhase::Succeeded {
                status: 200,
                bytes: 1,
            },
            start,
        )
        .unwrap();
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start),
            Err(FetchRecordError::Truncated)
        );
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start),
            Err(FetchRecordError::Truncated)
        );
        let events = feed.batch();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].kind, i32::from(pb::JobEventKind::Phase));
        assert_eq!(events[2].detail.as_deref(), Some("truncated"));
    }

    #[test]
    fn a_failed_outcome_record_adds_fetch_outcome_to_missing() {
        let (mut feed, start) = fetch_feed(1);
        feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start)
            .unwrap();
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Failed { status: None }, start),
            Err(FetchRecordError::Truncated)
        );
        let summary = feed.finish(Terminal::Failed);
        assert!(summary.missing.iter().any(|m| m == "fetch_outcome"));
        assert!(summary.missing.iter().any(|m| m == "events_truncated"));
    }

    #[test]
    fn outcome_events_carry_status_and_bytes_and_intents_carry_neither() {
        let (mut feed, start) = fresh();
        feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start)
            .unwrap();
        feed.record_fetch(
            &redactor(),
            URL,
            FetchPhase::Succeeded {
                status: 200,
                bytes: 4096,
            },
            start,
        )
        .unwrap();
        feed.record_fetch(
            &redactor(),
            URL,
            FetchPhase::Failed { status: Some(503) },
            start,
        )
        .unwrap();
        feed.record_fetch(&redactor(), URL, FetchPhase::Failed { status: None }, start)
            .unwrap();
        let events = feed.batch();
        let pairs: Vec<_> = events.iter().map(|e| (e.exit_code, e.out_bytes)).collect();
        assert_eq!(
            pairs,
            [
                (None, None),
                (Some(200), Some(4096)),
                (Some(503), None),
                (None, None)
            ]
        );
    }

    #[test]
    fn the_url_cap_holds_on_the_wire_form_after_the_final_redaction() {
        let (mut feed, start) = fresh();
        let redactor = Redactor::new(["REDACTED"]);
        let tail = "a".repeat(MAX_FETCH_URL_BYTES - 28);
        let url = format!("https://h.example/REDACTED{tail}");
        assert_eq!(url.len(), MAX_FETCH_URL_BYTES - 2);
        feed.record_fetch(&redactor, &url, FetchPhase::Intent, start)
            .unwrap();
        let cmd = feed.batch()[0].cmd.clone().unwrap();
        assert_eq!(cmd, format!("https://h.example/[REDACTED]{tail}"));
        assert!(cmd.len() <= MAX_FETCH_URL_BYTES);
    }

    #[test]
    fn a_spent_byte_budget_refuses_the_record() {
        let (mut feed, start) = fresh();
        let line = "x".repeat(MAX_LINE_BYTES);
        for _ in 0..32 {
            feed.line(&redactor(), &line, start);
        }
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start),
            Err(FetchRecordError::OverBudget)
        );
        assert!(feed.backlog_empty());
        let (mut feed, start) = fresh();
        for _ in 0..31 {
            feed.line(&redactor(), &line, start);
        }
        feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start)
            .unwrap();
    }

    #[test]
    fn a_skipped_line_over_budget_also_refuses_the_record() {
        let (mut feed, start) = fresh();
        let line = "x".repeat(MAX_LINE_BYTES);
        for _ in 0..31 {
            feed.line(&redactor(), &line, start);
        }
        feed.line(&redactor(), &"y".repeat(MAX_LINE_BYTES - 1), start);
        feed.line(&redactor(), "zz", start);
        assert_eq!(feed.counters().over_budget, 1);
        assert_eq!(
            feed.record_fetch(&redactor(), URL, FetchPhase::Intent, start),
            Err(FetchRecordError::OverBudget)
        );
    }
}
