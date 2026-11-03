//! Background command timing from pueue: state table, baseline, timestamps, fallback, caps and
//! hostile log content.

#![expect(clippy::expect_used, reason = "test code asserts by panicking")]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Duration;

use fleet_core::{PLACEHOLDER, Redactor};
use fleet_proto::{
    MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SHELL_LOG_CHUNK_BYTES, MAX_SHELL_LOG_CHUNKS, v1,
    validate_shell_log_bytes, validate_shell_log_command_id, validate_shell_log_seq,
    validate_shell_log_status,
};
use fleetd::bg_command::{
    Anchor, BgConfig, BgOutcome, BgState, BgWatcher, EndedBy, LIVE_LOG_READ_CAP, LOG_BURST,
    LOG_CHUNK_COST, LOG_READ_CAP, LOG_TAIL_GUARD, LogChunk, LogPushConfig, LogPusher, LogReporter,
    MAX_LOG_ERRORS, MAX_POLL_ERRORS, MAX_TRACKED_TASKS, PueueCli, PueueClient, PueueError,
    ReportError, Rule, log_command_id, parse_timestamp, rule,
};
use tokio::time::Instant;

const SECRET: &str = "s3cr3t-token-value-xyz";
const WALL: u64 = 1_793_529_377_000;
const START: &str = "2026-11-01T11:36:17.379782+01:00";
const END: &str = "2026-11-01T11:39:48.902292+01:00";

#[derive(Default)]
struct Fake {
    statuses: Mutex<Vec<Result<String, PueueError>>>,
    logs: Mutex<BTreeMap<u64, Result<Vec<u8>, PueueError>>>,
    log_calls: Mutex<Vec<(u64, usize)>>,
    hang: bool,
}

impl Fake {
    fn with(statuses: Vec<String>) -> Self {
        Self::scripted(statuses.into_iter().map(Ok).collect())
    }

    fn scripted(statuses: Vec<Result<String, PueueError>>) -> Self {
        Self {
            statuses: Mutex::new(statuses),
            ..Self::default()
        }
    }

    fn log(self, id: u64, bytes: Vec<u8>) -> Self {
        self.logs.lock().expect("lock").insert(id, Ok(bytes));
        self
    }
}

impl PueueClient for &Fake {
    fn status_json(&self) -> impl Future<Output = Result<String, PueueError>> + Send {
        let next = {
            let mut all = self.statuses.lock().expect("lock");
            if all.len() > 1 {
                all.remove(0)
            } else {
                all.first().cloned().unwrap_or(Err(PueueError::Run))
            }
        };
        let hang = self.hang;
        async move {
            if hang {
                std::future::pending::<()>().await;
            }
            next
        }
    }

    fn log(
        &self,
        id: u64,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, PueueError>> + Send {
        self.log_calls.lock().expect("lock").push((id, max_bytes));
        let out = self
            .logs
            .lock()
            .expect("lock")
            .get(&id)
            .cloned()
            .unwrap_or(Ok(Vec::new()))
            .map(|mut bytes| {
                bytes.truncate(max_bytes);
                bytes
            });
        std::future::ready(out)
    }
}

fn task(id: u64, status: &str) -> String {
    format!(
        r#""{id}":{{"id":{id},"created_at":"{START}","original_command":"cmd {id}","command":"cmd {id}","path":"/w","envs":{{"K":"V"}},"group":"default","dependencies":[],"priority":0,"label":null,"status":{status}}}"#
    )
}

fn status(tasks: &[String]) -> String {
    format!(r#"{{"tasks":{{{}}},"groups":{{}}}}"#, tasks.join(","))
}

fn queued() -> String {
    format!(r#"{{"Queued":{{"enqueued_at":"{START}"}}}}"#)
}

fn running() -> String {
    format!(r#"{{"Running":{{"enqueued_at":"{START}","start":"{START}"}}}}"#)
}

fn done(result: &str) -> String {
    format!(
        r#"{{"Done":{{"enqueued_at":"{START}","start":"{START}","end":"{END}","result":{result}}}}}"#
    )
}

fn anchor() -> Anchor {
    Anchor {
        wall_ms: WALL,
        at: Instant::now(),
    }
}

fn config() -> BgConfig {
    BgConfig {
        interval: Duration::from_millis(100),
        deadline: Duration::from_secs(60),
        call_timeout: Duration::from_secs(1),
    }
}

async fn watcher(fake: &Fake) -> BgWatcher<&Fake> {
    BgWatcher::start(fake, Redactor::new([SECRET]), anchor(), config())
        .await
        .expect("start")
}

#[test]
fn the_state_table_has_one_rule_per_state() {
    let table = [
        (BgState::Queued, Rule::Open),
        (BgState::Stashed, Rule::Open),
        (BgState::Locked, Rule::Open),
        (BgState::Running, Rule::Open),
        (BgState::Paused, Rule::Open),
        (BgState::Done, Rule::Close),
    ];
    for (state, expected) in table {
        assert_eq!(rule(state), expected, "{state:?}");
    }
}

type Row = (
    &'static str,
    String,
    BgState,
    EndedBy,
    Option<BgOutcome>,
    Option<i32>,
);

#[tokio::test(start_paused = true)]
#[expect(clippy::too_many_lines, reason = "one table row per pueue state")]
async fn every_pueue_state_closes_by_its_rule() {
    let paused = format!(r#"{{"Paused":{{"enqueued_at":"{START}","start":"{START}"}}}}"#);
    let stashed = r#"{"Stashed":{"enqueue_at":null}}"#.to_owned();
    let locked = format!(r#"{{"Locked":{{"previous_status":{}}}}}"#, queued());
    let table: Vec<Row> = vec![
        (
            "queued",
            queued(),
            BgState::Queued,
            EndedBy::JobExit,
            None,
            None,
        ),
        (
            "stashed",
            stashed,
            BgState::Stashed,
            EndedBy::JobExit,
            None,
            None,
        ),
        (
            "locked",
            locked,
            BgState::Locked,
            EndedBy::JobExit,
            None,
            None,
        ),
        (
            "running",
            running(),
            BgState::Running,
            EndedBy::JobExit,
            None,
            None,
        ),
        (
            "paused",
            paused,
            BgState::Paused,
            EndedBy::JobExit,
            None,
            None,
        ),
        (
            "success",
            done(r#""Success""#),
            BgState::Done,
            EndedBy::Pueue,
            Some(BgOutcome::Success),
            Some(0),
        ),
        (
            "failed",
            done(r#"{"Failed":3}"#),
            BgState::Done,
            EndedBy::Pueue,
            Some(BgOutcome::Failed(3)),
            Some(3),
        ),
        (
            "spawn",
            done(r#"{"FailedToSpawn":"no such file"}"#),
            BgState::Done,
            EndedBy::Pueue,
            Some(BgOutcome::FailedToSpawn),
            None,
        ),
        (
            "killed",
            done(r#""Killed""#),
            BgState::Done,
            EndedBy::Pueue,
            Some(BgOutcome::Killed),
            None,
        ),
        (
            "errored",
            done(r#""Errored""#),
            BgState::Done,
            EndedBy::Pueue,
            Some(BgOutcome::Errored),
            None,
        ),
        (
            "dependency",
            done(r#""DependencyFailed""#),
            BgState::Done,
            EndedBy::Pueue,
            Some(BgOutcome::DependencyFailed),
            None,
        ),
    ];
    for (name, state_json, state, ended_by, outcome, exit) in table {
        let fake = Fake::with(vec![
            status(&[task(1, &queued())]),
            status(&[task(1, &queued()), task(2, &state_json)]),
        ]);
        let mut w = watcher(&fake).await;
        assert_eq!(w.baseline(), 1, "{name}");
        w.poll(Instant::now()).await.expect("poll");
        let report = w.finish(EndedBy::JobExit, Instant::now()).await;
        assert_eq!(report.records.len(), 1, "{name}");
        let r = &report.records[0];
        assert_eq!(r.id, 2, "{name}");
        assert_eq!(r.last_state, state, "{name}");
        assert_eq!(r.ended_by, ended_by, "{name}");
        assert_eq!(r.outcome, outcome, "{name}");
        assert_eq!(r.record.exit_code, exit, "{name}");
        assert!(r.record.background, "{name}");
        assert_eq!(r.record.command, "cmd 2", "{name}");
    }
}

#[tokio::test(start_paused = true)]
async fn only_ids_above_the_baseline_are_tracked() {
    let fake = Fake::with(vec![
        status(&[task(4, &queued()), task(9, &queued())]),
        status(&[
            task(4, &done(r#""Success""#)),
            task(9, &done(r#""Success""#)),
            task(10, &done(r#""Success""#)),
        ]),
    ]);
    let mut w = watcher(&fake).await;
    assert_eq!(w.baseline(), 9);
    w.poll(Instant::now()).await.expect("poll");
    let report = w.finish(EndedBy::JobExit, Instant::now()).await;
    let ids: Vec<u64> = report.records.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![10]);
}

#[tokio::test(start_paused = true)]
async fn an_empty_status_gives_baseline_zero() {
    let fake = Fake::with(vec![status(&[]), status(&[task(1, &done(r#""Success""#))])]);
    let mut w = watcher(&fake).await;
    assert_eq!(w.baseline(), 0);
    w.poll(Instant::now()).await.expect("poll");
    assert_eq!(
        w.finish(EndedBy::JobExit, Instant::now())
            .await
            .records
            .len(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn pueue_timestamps_give_start_end_and_duration() {
    let fake = Fake::with(vec![status(&[]), status(&[task(1, &done(r#""Success""#))])]);
    let mut w = watcher(&fake).await;
    w.poll(Instant::now()).await.expect("poll");
    let r = w
        .finish(EndedBy::JobExit, Instant::now())
        .await
        .records
        .remove(0);
    assert_eq!(r.record.started, 1_793_529_377_379);
    assert_eq!(r.record.ended, Some(1_793_529_588_902));
    assert_eq!(r.record.duration, 211_523);
}

#[tokio::test(start_paused = true)]
async fn missing_or_contradicting_timestamps_fall_back_to_the_monotonic_clock() {
    let bad_end = format!(
        r#"{{"Done":{{"enqueued_at":"{START}","start":"{END}","end":"{START}","result":"Success"}}}}"#
    );
    let garbage = format!(
        r#"{{"Done":{{"enqueued_at":"{START}","start":"x","end":"","result":"Success"}}}}"#
    );
    for (name, state) in [("end before start", bad_end), ("unparseable", garbage)] {
        let fake = Fake::with(vec![status(&[]), status(&[task(1, &state)])]);
        let mut w = watcher(&fake).await;
        tokio::time::advance(Duration::from_millis(700)).await;
        w.poll(Instant::now()).await.expect("poll");
        let r = w
            .finish(EndedBy::JobExit, Instant::now())
            .await
            .records
            .remove(0);
        assert_eq!(r.record.started, WALL + 700, "{name}");
        assert_eq!(r.record.ended, Some(WALL + 700), "{name}");
        assert_eq!(r.record.duration, 0, "{name}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_running_task_gets_a_monotonic_end_at_job_exit_and_its_log() {
    let fake =
        Fake::with(vec![status(&[]), status(&[task(1, &running())])]).log(1, b"partial".to_vec());
    let mut w = watcher(&fake).await;
    w.poll(Instant::now()).await.expect("poll");
    tokio::time::advance(Duration::from_secs(5)).await;
    let r = w
        .finish(EndedBy::JobExit, Instant::now())
        .await
        .records
        .remove(0);
    assert_eq!(r.ended_by, EndedBy::JobExit);
    assert_eq!(r.record.started, 1_793_529_377_379);
    assert_eq!(r.record.ended, Some(WALL + 5000));
    assert_eq!(r.record.output, "partial");
    assert!(r.record.ended.expect("end") >= r.record.started || r.record.duration == 0);
}

#[tokio::test(start_paused = true)]
async fn a_task_that_never_started_reads_no_log() {
    let fake = Fake::with(vec![status(&[]), status(&[task(1, &queued())])]);
    let mut w = watcher(&fake).await;
    w.poll(Instant::now()).await.expect("poll");
    w.finish(EndedBy::JobExit, Instant::now()).await;
    assert!(fake.log_calls.lock().expect("lock").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_task_that_leaves_the_status_closes_as_removed() {
    let fake = Fake::with(vec![
        status(&[]),
        status(&[task(1, &running())]),
        status(&[]),
    ]);
    let mut w = watcher(&fake).await;
    w.poll(Instant::now()).await.expect("poll");
    w.poll(Instant::now()).await.expect("poll");
    let report = w.finish(EndedBy::JobExit, Instant::now()).await;
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].ended_by, EndedBy::Removed);
}

#[tokio::test(start_paused = true)]
async fn a_closed_task_is_recorded_once() {
    let fake = Fake::with(vec![status(&[]), status(&[task(1, &done(r#""Success""#))])]);
    let mut w = watcher(&fake).await;
    for _ in 0..3 {
        w.poll(Instant::now()).await.expect("poll");
    }
    let report = w.finish(EndedBy::JobExit, Instant::now()).await;
    assert_eq!(report.records.len(), 1);
    assert_eq!(fake.log_calls.lock().expect("lock").len(), 1);
}

#[tokio::test(start_paused = true)]
async fn tracking_stops_at_the_cap_and_counts_the_rest() {
    let extra = 5;
    let all: Vec<String> = (1..=(MAX_TRACKED_TASKS + extra) as u64)
        .map(|id| task(id, &done(r#""Success""#)))
        .collect();
    let fake = Fake::with(vec![status(&[]), status(&all)]);
    let mut w = watcher(&fake).await;
    w.poll(Instant::now()).await.expect("poll");
    let report = w.finish(EndedBy::JobExit, Instant::now()).await;
    assert_eq!(MAX_TRACKED_TASKS, MAX_SHELL_COMMANDS);
    assert_eq!(report.records.len(), MAX_TRACKED_TASKS);
    assert_eq!(report.overflow, extra as u64);
    assert_eq!(report.records[0].id, 1);
}

#[tokio::test(start_paused = true)]
async fn start_fails_when_the_status_cannot_be_read() {
    let fake = Fake::scripted(vec![Err(PueueError::Run)]);
    let result = BgWatcher::start(&fake, Redactor::new([SECRET]), anchor(), config()).await;
    assert_eq!(
        result.err().map(|e| e.to_string()),
        Some("pueue call failed".into())
    );
    let fake = Fake::scripted(vec![Ok("not json".into())]);
    assert!(
        BgWatcher::start(&fake, Redactor::new([SECRET]), anchor(), config())
            .await
            .is_err()
    );
    let unknown =
        Ok(r#"{"tasks":{"1":{"id":1,"original_command":"c","status":{"Mystery":{}}}}}"#.into());
    let fake = Fake::scripted(vec![unknown]);
    assert!(
        BgWatcher::start(&fake, Redactor::new([SECRET]), anchor(), config())
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn a_hung_client_call_times_out() {
    let mut fake = Fake::with(vec![status(&[])]);
    fake.hang = true;
    let result = BgWatcher::start(&fake, Redactor::new([SECRET]), anchor(), config()).await;
    assert_eq!(
        result.err().map(|e| e.to_string()),
        Some("pueue call timed out".into())
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_poll_errors_end_the_watch_as_poll_failed() {
    let script = vec![
        Ok(status(&[])),
        Ok(status(&[task(1, &running())])),
        Err(PueueError::Run),
    ];
    let fake = Fake::scripted(script);
    let w = watcher(&fake).await;
    let report = w.watch(std::future::pending::<()>()).await;
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].ended_by, EndedBy::PollFailed);
    assert_eq!(MAX_POLL_ERRORS, 5);
}

#[tokio::test(start_paused = true)]
async fn the_deadline_closes_open_tasks() {
    let fake = Fake::with(vec![status(&[]), status(&[task(1, &running())])]);
    let mut cfg = config();
    cfg.deadline = Duration::from_secs(3);
    let w = BgWatcher::start(&fake, Redactor::new([SECRET]), anchor(), cfg)
        .await
        .expect("start");
    let report = w.watch(std::future::pending::<()>()).await;
    assert_eq!(report.records[0].ended_by, EndedBy::Deadline);
    assert_eq!(report.records[0].record.ended, Some(WALL + 3000));
}

#[tokio::test(start_paused = true)]
async fn the_job_exit_signal_closes_open_tasks_and_catches_a_last_done() {
    let fake = Fake::with(vec![
        status(&[]),
        status(&[task(1, &running()), task(2, &running())]),
        status(&[task(1, &running()), task(2, &done(r#""Success""#))]),
    ]);
    let w = watcher(&fake).await;
    let report = w
        .watch(tokio::time::sleep(Duration::from_millis(150)))
        .await;
    let by: Vec<(u64, EndedBy)> = report.records.iter().map(|r| (r.id, r.ended_by)).collect();
    assert_eq!(by, vec![(2, EndedBy::Pueue), (1, EndedBy::JobExit)]);
}

fn hostile_log(bytes: Vec<u8>) -> Fake {
    Fake::with(vec![status(&[]), status(&[task(1, &done(r#""Success""#))])]).log(1, bytes)
}

async fn output_of(fake: &Fake) -> (String, bool, bool) {
    let mut w = watcher(fake).await;
    w.poll(Instant::now()).await.expect("poll");
    let r = w
        .finish(EndedBy::JobExit, Instant::now())
        .await
        .records
        .remove(0);
    (
        r.record.output,
        r.log_cut || r.record.truncated,
        r.log_failed,
    )
}

#[tokio::test(start_paused = true)]
async fn hostile_log_content_table() {
    let table: Vec<(&str, Vec<u8>, &str)> = vec![
        ("nul", b"a\0b\0c".to_vec(), "abc"),
        ("cr", b"one\rtwo\r\nthree".to_vec(), "one?two?\nthree"),
        (
            "esc",
            b"\x1b[31mred\x1b]0;title\x07".to_vec(),
            "?[31mred?]0;title?",
        ),
        ("tab and newline kept", b"a\tb\nc".to_vec(), "a\tb\nc"),
        (
            "nul split secret",
            b"x s3cr3t-token\0-value-xyz y".to_vec(),
            "x [REDACTED] y",
        ),
        ("invalid utf8", vec![b'a', 0xff, b'b'], "a\u{fffd}b"),
        (
            "c1 control",
            "a\u{85}b\u{2028}c".as_bytes().to_vec(),
            "a?b\u{2028}c",
        ),
    ];
    for (name, bytes, expected) in table {
        let (out, cut, failed) = output_of(&hostile_log(bytes)).await;
        assert_eq!(out, expected, "{name}");
        assert!(!cut && !failed, "{name}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_secret_straddling_the_output_cap_leaves_no_fragment() {
    for back in 1..SECRET.len() {
        let mut text = "a".repeat(MAX_SHELL_LOG_BYTES - back);
        text.push_str(SECRET);
        text.push_str("tail");
        let (out, cut, _) = output_of(&hostile_log(text.into_bytes())).await;
        assert!(out.len() <= MAX_SHELL_LOG_BYTES, "{back}");
        assert!(!out.contains("s3cr3t"), "{back}");
        assert!(!out.ends_with("s3cr"), "{back}");
        assert!(cut || out.ends_with("tail"), "{back}");
        assert!(
            out.contains(&PLACEHOLDER[..back.min(PLACEHOLDER.len())]),
            "{back}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_secret_straddling_the_read_cap_leaves_no_fragment() {
    let fake_cap = LOG_READ_CAP;
    for back in 1..SECRET.len() {
        let mut text = "a ".repeat((fake_cap - back) / 2);
        while text.len() < fake_cap - back {
            text.push('a');
        }
        text.push_str(SECRET);
        text.push_str(&"b".repeat(100));
        let fake = hostile_log(text.into_bytes());
        let (out, cut, _) = output_of(&fake).await;
        assert!(!out.contains("s3cr"), "{back}");
        assert!(out.len() <= MAX_SHELL_LOG_BYTES, "{back}");
        assert!(cut, "{back}");
        let calls = fake.log_calls.lock().expect("lock");
        assert_eq!(calls[0], (1, LOG_READ_CAP + 1), "{back}");
    }
}

fn assert_no_secret_fragment(out: &str, label: &str) {
    for k in 4..=SECRET.len() {
        assert!(!out.contains(&SECRET[..k]), "{label}: prefix {k}");
        assert!(
            !out.contains(&SECRET[SECRET.len() - k..]),
            "{label}: suffix {k}"
        );
    }
}

fn filler(len: usize) -> String {
    let mut text = ". ".repeat(len / 2);
    while text.len() < len {
        text.push('.');
    }
    text
}

#[tokio::test(start_paused = true)]
async fn a_cut_read_hides_a_secret_straddling_the_output_cap_at_every_offset() {
    for back in 1..SECRET.len() {
        let mut text = filler(MAX_SHELL_LOG_BYTES - back);
        text.push_str(SECRET);
        let pad = LOG_READ_CAP + 200 - text.len();
        text.push_str(&filler(pad));
        assert!(text.len() > LOG_READ_CAP);
        let (out, cut, _) = output_of(&hostile_log(text.into_bytes())).await;
        assert!(cut, "{back}");
        assert!(out.len() <= MAX_SHELL_LOG_BYTES, "{back}");
        assert_no_secret_fragment(&out, &format!("cap {back}"));
    }
}

#[tokio::test(start_paused = true)]
async fn a_cut_read_hides_a_secret_straddling_the_read_cap_at_every_offset() {
    let copies = 400;
    for back in 0..=SECRET.len() + 1 {
        let mut text = String::new();
        for _ in 0..copies {
            text.push_str(SECRET);
            text.push('.');
        }
        let start = LOG_READ_CAP + 1 - back;
        text.push_str(&filler(start - text.len()));
        text.push_str(SECRET);
        text.push_str(&filler(200));
        assert!(text.len() > LOG_READ_CAP + 1);
        let (out, cut, _) = output_of(&hostile_log(text.into_bytes())).await;
        assert!(cut, "{back}");
        assert!(out.len() <= MAX_SHELL_LOG_BYTES, "{back}");
        assert!(out.len() > 10_000, "{back}: {}", out.len());
        assert_no_secret_fragment(&out, &format!("read {back}"));
    }
}

#[tokio::test(start_paused = true)]
async fn a_failed_log_read_still_records_the_task() {
    let fake = Fake::with(vec![status(&[]), status(&[task(1, &done(r#""Success""#))])]);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Err(PueueError::Run));
    let (out, cut, failed) = output_of(&fake).await;
    assert_eq!((out.as_str(), cut, failed), ("", false, true));
}

#[tokio::test(start_paused = true)]
async fn a_secret_in_the_command_is_redacted() {
    let secret_task = format!(
        r#""1":{{"id":1,"original_command":"curl -H {SECRET}\u001b","status":{}}}"#,
        done(r#""Success""#)
    );
    let fake = Fake::with(vec![
        status(&[]),
        format!(r#"{{"tasks":{{{secret_task}}}}}"#),
    ]);
    let mut w = watcher(&fake).await;
    w.poll(Instant::now()).await.expect("poll");
    let r = w
        .finish(EndedBy::JobExit, Instant::now())
        .await
        .records
        .remove(0);
    assert_eq!(r.record.command, "curl -H [REDACTED]?");
}

#[test]
fn timestamps_parse_by_a_fixed_grammar() {
    let table: Vec<(&str, Option<u64>)> = vec![
        ("1970-01-01T00:00:00Z", Some(0)),
        ("2026-11-01T10:36:17Z", Some(1_793_529_377_000)),
        ("2026-11-01T11:36:17.379782+01:00", Some(1_793_529_377_379)),
        ("2026-11-01T11:39:48.902292+01:00", Some(1_793_529_588_902)),
        ("2026-11-01T04:36:17.5-06:00", Some(1_793_529_377_500)),
        ("2026-11-01T10:36:17.37Z", Some(1_793_529_377_370)),
        ("2024-02-29T00:00:00Z", Some(1_709_164_800_000)),
        ("1969-12-31T23:59:59Z", None),
        ("2026-11-01T10:36:17", None),
        ("2026-11-01 10:36:17Z", None),
        ("2026-13-01T10:36:17Z", None),
        ("2026-11-32T10:36:17Z", None),
        ("2026-11-01T24:00:00Z", None),
        ("2026-11-01T10:36:17.Z", None),
        ("2026-11-01T10:36:17+0100", None),
        ("2026-11-01T10:36:17+24:00", None),
        ("2026-11-01T10:36:17Zjunk", None),
        ("2026-11-01T10:36:1\u{e9}Z", None),
        ("+026-11-01T10:36:17Z", None),
        ("", None),
        ("99999999999-11-01T10:36:17Z", None),
    ];
    for (text, expected) in table {
        assert_eq!(parse_timestamp(text), expected, "{text:?}");
    }
}

#[tokio::test]
async fn the_cli_client_caps_and_fails_closed() {
    let echo = PueueCli::new("/bin/echo", Vec::new());
    assert_eq!(echo.status_json().await.expect("echo"), "status --json\n");
    assert_eq!(echo.log(1, 10).await.err(), Some(PueueError::Parse));
    let yes = PueueCli::new("/usr/bin/yes", Vec::new());
    assert_eq!(yes.status_json().await.err(), Some(PueueError::TooLarge));
    let no = PueueCli::new("/usr/bin/false", Vec::new());
    assert_eq!(no.status_json().await.err(), Some(PueueError::Run));
    let missing = PueueCli::new("/nonexistent/pueue", Vec::new());
    assert_eq!(missing.status_json().await.err(), Some(PueueError::Run));
}

#[derive(Default)]
struct Rec {
    chunks: Mutex<Vec<LogChunk>>,
    fail: Mutex<u32>,
}

impl LogReporter for &Rec {
    fn report(&self, chunk: LogChunk) -> impl Future<Output = Result<(), ReportError>> + Send {
        let mut fail = self.fail.lock().expect("lock");
        let failing = *fail > 0;
        if failing {
            *fail -= 1;
        }
        drop(fail);
        let out = if failing {
            Err(ReportError)
        } else {
            self.chunks.lock().expect("lock").push(chunk);
            Ok(())
        };
        std::future::ready(out)
    }
}

impl Rec {
    fn all(&self) -> Vec<LogChunk> {
        self.chunks.lock().expect("lock").clone()
    }

    fn text(&self) -> String {
        let bytes: Vec<u8> = self.all().into_iter().flat_map(|c| c.bytes).collect();
        String::from_utf8(bytes).expect("chunks are utf-8")
    }

    fn statuses(&self) -> Vec<v1::ShellStatus> {
        self.all().into_iter().map(|c| c.status).collect()
    }
}

fn push_config() -> LogPushConfig {
    LogPushConfig {
        interval: Duration::from_millis(100),
        deadline: Duration::from_secs(60),
        call_timeout: Duration::from_secs(1),
        read_interval: Duration::from_secs(1),
    }
}

async fn drain(p: &mut LogPusher<&Fake, &Rec>, t0: Instant) {
    for i in 1..=12_u32 {
        p.poll(t0 + Duration::from_secs(10_000) * i)
            .await
            .expect("poll");
    }
}

fn set_tasks(fake: &Fake, tasks: &[String]) {
    *fake.statuses.lock().expect("lock") = vec![Ok(status(tasks))];
}

async fn pusher<'a>(
    fake: &'a Fake,
    rec: &'a Rec,
    redactor: Redactor,
    now: Instant,
) -> LogPusher<&'a Fake, &'a Rec> {
    set_tasks(fake, &[]);
    LogPusher::start(fake, rec, redactor, push_config(), now)
        .await
        .expect("start")
}

fn finished_task(id: u64) -> String {
    task(id, &done(r#""Success""#))
}

fn pad(len: usize) -> String {
    "a".repeat(len)
}

fn long_secret(len: usize) -> String {
    let mut out = String::new();
    let mut n = 0_u32;
    while out.len() < len {
        let _ = write!(out, "{:04}", n % 10_000);
        n += 1;
    }
    out.truncate(len);
    out
}

#[tokio::test]
async fn a_secret_straddling_a_chunk_boundary_is_replaced_whole() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = format!("{}{SECRET}tail", pad(MAX_SHELL_LOG_CHUNK_BYTES - 5));
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.clone().into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0).await.expect("poll");
    let chunks = rec.all();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].bytes.len(), MAX_SHELL_LOG_CHUNK_BYTES);
    assert!(
        chunks[0].bytes.ends_with(b"[REDA"),
        "really cut inside the placeholder"
    );
    assert!(chunks[1].bytes.starts_with(b"CTED]"));
    assert!(!rec.text().contains("s3cr3t"));
    assert!(rec.text().contains(PLACEHOLDER));
}

#[tokio::test]
async fn redaction_runs_before_the_chunks_are_cut() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = format!("{SECRET}{}", pad(MAX_SHELL_LOG_CHUNK_BYTES - 10));
    assert!(raw.len() > MAX_SHELL_LOG_CHUNK_BYTES);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0).await.expect("poll");
    let chunks = rec.all();
    assert_eq!(chunks.len(), 1, "the redacted text fits one chunk");
    assert!(rec.text().starts_with(PLACEHOLDER));
}

#[tokio::test]
async fn a_running_task_holds_back_the_guard_tail() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let first = format!("{}{SECRET}", pad(100));
    let raw = format!("{first}{}", pad(LOG_TAIL_GUARD - 3));
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[task(1, &running())]);
    p.poll(t0).await.expect("poll");
    let sent = rec.text();
    assert!(sent.len() <= 100 + PLACEHOLDER.len());
    assert!(!sent.contains("s3cr3t"));
    assert_eq!(rec.statuses().last(), Some(&v1::ShellStatus::Running));
}

#[tokio::test]
async fn a_secret_split_by_the_read_cap_leaves_no_fragment_up_to_the_guard() {
    let secret = long_secret(LOG_TAIL_GUARD + 1);
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([secret.clone()]), t0).await;
    let head = pad(LIVE_LOG_READ_CAP - 100);
    let raw = format!("{head}{secret}");
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    drain(&mut p, t0).await;
    assert!(rec.text().len() > head.len() - 2 * LOG_TAIL_GUARD);
    assert!(!rec.text().contains(&secret[..8]));
}

#[tokio::test]
async fn a_secret_longer_than_the_guard_split_by_the_read_cap_leaks_a_fragment() {
    let secret = long_secret(3 * LOG_TAIL_GUARD);
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([secret.clone()]), t0).await;
    let head = pad(LIVE_LOG_READ_CAP - 2 * LOG_TAIL_GUARD - 100);
    let raw = format!("{head}{secret}");
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    drain(&mut p, t0).await;
    assert!(rec.text().contains(&secret[..8]), "the documented residual");
}

#[tokio::test]
async fn the_rate_budget_bounds_chunks_per_instant() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = pad(40 * MAX_SHELL_LOG_CHUNK_BYTES);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0).await.expect("poll");
    assert_eq!(rec.all().len(), LOG_BURST as usize);
    p.poll(t0).await.expect("poll");
    assert_eq!(rec.all().len(), LOG_BURST as usize, "no time passed");
    let step = LOG_CHUNK_COST * 4;
    p.poll(t0 + step).await.expect("poll");
    assert_eq!(rec.all().len(), LOG_BURST as usize + 4);
    p.poll(t0 + step * 1000).await.expect("poll");
    assert_eq!(rec.all().len(), LOG_BURST as usize + 4 + LOG_BURST as usize);
    drain(&mut p, t0 + step * 1000).await;
    assert_eq!(rec.all().len(), 40);
    assert_eq!(rec.text().len(), 40 * MAX_SHELL_LOG_CHUNK_BYTES);
}

#[tokio::test]
async fn a_long_log_stops_at_the_chunk_cap_with_a_failed_status() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = pad(MAX_SHELL_LOG_CHUNKS * MAX_SHELL_LOG_CHUNK_BYTES + 1000);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    let far = Duration::from_secs(10_000);
    for i in 0..10 {
        p.poll(t0 + far * (i + 1)).await.expect("poll");
    }
    let chunks = rec.all();
    assert_eq!(chunks.len(), MAX_SHELL_LOG_CHUNKS);
    let seqs: Vec<u32> = chunks.iter().map(|c| c.seq).collect();
    assert_eq!(seqs, (0..64).collect::<Vec<u32>>());
    assert_eq!(chunks[63].status, v1::ShellStatus::Failed);
    assert!(
        chunks[..63]
            .iter()
            .all(|c| c.status == v1::ShellStatus::Running)
    );
    assert_eq!(
        rec.text().len(),
        MAX_SHELL_LOG_CHUNKS * MAX_SHELL_LOG_CHUNK_BYTES
    );
}

#[tokio::test]
async fn a_log_that_exactly_fills_the_chunk_cap_ends_done() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = pad(MAX_SHELL_LOG_CHUNKS * MAX_SHELL_LOG_CHUNK_BYTES);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    drain(&mut p, t0).await;
    let chunks = rec.all();
    assert_eq!(chunks.len(), MAX_SHELL_LOG_CHUNKS);
    assert_eq!(chunks[63].status, v1::ShellStatus::Done);
}

#[tokio::test]
async fn a_cut_read_that_redaction_shrinks_under_the_cap_still_reports_truncation() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = format!("{SECRET}\n").repeat(LIVE_LOG_READ_CAP / SECRET.len() + 10);
    assert!(raw.len() > LIVE_LOG_READ_CAP);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[finished_task(1)]);
    drain(&mut p, t0).await;
    let chunks = rec.all();
    assert!(chunks.len() < MAX_SHELL_LOG_CHUNKS);
    assert_eq!(
        chunks.last().map(|c| c.status),
        Some(v1::ShellStatus::Failed)
    );
}

#[tokio::test]
async fn a_task_stops_being_read_once_its_end_is_reported() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(b"out\n".to_vec()));
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0).await.expect("poll");
    let reports = rec.all().len();
    let reads = fake.log_calls.lock().expect("lock").len();
    assert_eq!(reports, 1);
    for i in 1..5 {
        p.poll(t0 + Duration::from_secs(100 * i))
            .await
            .expect("poll");
    }
    assert_eq!(rec.all().len(), reports);
    assert_eq!(fake.log_calls.lock().expect("lock").len(), reads);
    set_tasks(&fake, &[]);
    p.poll(t0 + Duration::from_secs(1000)).await.expect("poll");
    assert_eq!(
        rec.all().len(),
        reports,
        "a vanished finished task is not reported again"
    );
}

#[tokio::test]
async fn every_pueue_state_reports_its_wire_status() {
    let paused = format!(r#"{{"Paused":{{"enqueued_at":"{START}","start":"{START}"}}}}"#);
    let stashed = r#"{"Stashed":{"enqueue_at":null}}"#.to_owned();
    let locked = format!(r#"{{"Locked":{{"previous_status":{}}}}}"#, queued());
    let table = [
        ("queued", queued(), v1::ShellStatus::Queued),
        ("stashed", stashed, v1::ShellStatus::Queued),
        ("locked", locked, v1::ShellStatus::Queued),
        ("running", running(), v1::ShellStatus::Running),
        ("paused", paused, v1::ShellStatus::Running),
        ("success", done(r#""Success""#), v1::ShellStatus::Done),
        ("failed", done(r#"{"Failed":2}"#), v1::ShellStatus::Failed),
        ("killed", done(r#""Killed""#), v1::ShellStatus::Failed),
        ("errored", done(r#""Errored""#), v1::ShellStatus::Failed),
        (
            "spawn",
            done(r#"{"FailedToSpawn":"x"}"#),
            v1::ShellStatus::Failed,
        ),
        (
            "dependency",
            done(r#""DependencyFailed""#),
            v1::ShellStatus::Failed,
        ),
    ];
    for (name, state, expected) in table {
        let fake = Fake::with(vec![]);
        let rec = Rec::default();
        let t0 = Instant::now();
        let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
        set_tasks(&fake, &[task(1, &state)]);
        p.poll(t0).await.expect("poll");
        assert_eq!(rec.statuses(), vec![expected], "{name}");
        assert_eq!(rec.all()[0].bytes.len(), 0, "{name}");
    }
}

#[tokio::test]
async fn a_task_walks_queued_running_done_and_a_vanished_one_fails() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(b"hi\n".to_vec()));
    set_tasks(&fake, &[task(1, &queued()), task(2, &running())]);
    p.poll(t0).await.expect("poll");
    p.poll(t0 + Duration::from_millis(10)).await.expect("poll");
    set_tasks(&fake, &[task(1, &running())]);
    p.poll(t0 + Duration::from_secs(5)).await.expect("poll");
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0 + Duration::from_secs(10)).await.expect("poll");
    let one: Vec<v1::ShellStatus> = rec
        .all()
        .into_iter()
        .filter(|c| c.command_id == log_command_id(1))
        .map(|c| c.status)
        .collect();
    assert_eq!(
        one,
        [
            v1::ShellStatus::Queued,
            v1::ShellStatus::Running,
            v1::ShellStatus::Done
        ]
    );
    let two: Vec<v1::ShellStatus> = rec
        .all()
        .into_iter()
        .filter(|c| c.command_id == log_command_id(2))
        .map(|c| c.status)
        .collect();
    assert_eq!(two, [v1::ShellStatus::Running, v1::ShellStatus::Failed]);
}

#[tokio::test]
async fn a_task_at_or_below_the_baseline_is_not_pushed() {
    let fake = Fake::with(vec![status(&[finished_task(3)])]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = LogPusher::start(&fake, &rec, Redactor::new([SECRET]), push_config(), t0)
        .await
        .expect("start");
    p.poll(t0).await.expect("poll");
    assert_eq!(rec.all().len(), 0);
    assert_eq!(fake.log_calls.lock().expect("lock").len(), 0);
}

#[test]
fn the_command_id_always_validates() {
    for id in [0, 1, 7, 255, u64::MAX] {
        assert!(validate_shell_log_command_id(&log_command_id(id)), "{id}");
    }
}

#[tokio::test]
async fn every_chunk_passes_the_proto_validators_for_hostile_input() {
    let raw: Vec<u8> = [
        b"a\xffb\0c\r\n".as_slice(),
        "\u{85}d\u{2028}e\u{2029}f\t".as_bytes(),
        SECRET.as_bytes(),
        &[0xC3],
        pad(MAX_SHELL_LOG_CHUNK_BYTES * 2).as_bytes(),
        "\u{1F600}".repeat(2000).as_bytes(),
    ]
    .concat();
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    fake.logs.lock().expect("lock").insert(u64::MAX, Ok(raw));
    let hostile = format!(
        r#""{id}":{{"id":{id},"created_at":"{START}","original_command":"x\r\n\u0085\u2028 {SECRET}","command":"x","path":"/w","envs":{{}},"group":"default","dependencies":[],"priority":0,"label":null,"status":{state}}}"#,
        id = u64::MAX,
        state = done(r#""Success""#),
    );
    set_tasks(
        &fake,
        &[format!(r#"{{"tasks":{{{hostile}}},"groups":{{}}}}"#)],
    );
    *fake.statuses.lock().expect("lock") =
        vec![Ok(format!(r#"{{"tasks":{{{hostile}}},"groups":{{}}}}"#))];
    drain(&mut p, t0).await;
    let chunks = rec.all();
    assert!(chunks.len() > 2);
    for chunk in &chunks {
        assert!(validate_shell_log_command_id(&chunk.command_id));
        assert!(validate_shell_log_seq(chunk.seq));
        assert!(validate_shell_log_bytes(&chunk.bytes));
        assert!(validate_shell_log_status(chunk.status as i32).is_some());
        let text = std::str::from_utf8(&chunk.bytes).expect("utf-8, no split char");
        for bad in ['\0', '\r', '\u{85}', '\u{2028}', '\u{2029}'] {
            assert!(!text.contains(bad), "{bad:?}");
        }
        assert!(!text.contains("s3cr3t"));
    }
    assert!(rec.text().contains("a\u{fffd}bc"));
    assert!(rec.text().contains('\u{1F600}'));
}

#[tokio::test]
async fn a_failed_report_is_offered_again_with_the_same_seq() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(b"out\n".to_vec()));
    set_tasks(&fake, &[finished_task(1)]);
    *rec.fail.lock().expect("lock") = 2;
    p.poll(t0).await.expect("poll");
    assert_eq!(rec.all().len(), 0);
    p.poll(t0 + Duration::from_secs(1)).await.expect("poll");
    p.poll(t0 + Duration::from_secs(2)).await.expect("poll");
    let chunks = rec.all();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].seq, 0);
    assert_eq!(chunks[0].bytes, b"out\n");
}

#[tokio::test]
async fn a_task_is_given_up_after_repeated_report_failures() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    set_tasks(&fake, &[finished_task(1)]);
    *rec.fail.lock().expect("lock") = u32::MAX;
    for i in 0..(MAX_LOG_ERRORS + 3) {
        p.poll(t0 + Duration::from_secs(u64::from(i)))
            .await
            .expect("poll");
    }
    let tries = u32::MAX - *rec.fail.lock().expect("lock");
    assert_eq!(tries, MAX_LOG_ERRORS);
}

#[tokio::test]
async fn a_failed_log_read_of_a_finished_task_is_retried_then_ends_without_data() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Err(PueueError::Run));
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0).await.expect("poll");
    assert_eq!(rec.all().len(), 0, "retry before giving up");
    for i in 1..=MAX_LOG_ERRORS {
        p.poll(t0 + Duration::from_secs(u64::from(i)))
            .await
            .expect("poll");
    }
    assert_eq!(rec.statuses(), vec![v1::ShellStatus::Done]);
}

#[tokio::test]
async fn finish_fails_every_open_task() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    set_tasks(
        &fake,
        &[task(1, &running()), finished_task(2), task(3, &queued())],
    );
    p.poll(t0).await.expect("poll");
    let report = p.finish(t0 + Duration::from_secs(1)).await;
    assert_eq!(report.unreported.len(), 0);
    assert_eq!(
        report.ended,
        vec![
            (1, v1::ShellStatus::Failed),
            (2, v1::ShellStatus::Done),
            (3, v1::ShellStatus::Failed)
        ]
    );
}

#[tokio::test]
async fn tasks_past_the_tracking_cap_are_counted_not_pushed() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let tasks: Vec<String> = (1..=MAX_TRACKED_TASKS as u64 + 3)
        .map(|id| task(id, &queued()))
        .collect();
    set_tasks(&fake, &tasks);
    p.poll(t0).await.expect("poll");
    let report = p.finish(t0).await;
    assert_eq!(report.overflow, 3);
}

#[tokio::test]
async fn a_running_task_is_read_at_most_once_per_read_interval() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    set_tasks(&fake, &[task(1, &running())]);
    for ms in [0, 100, 200, 900] {
        p.poll(t0 + Duration::from_millis(ms)).await.expect("poll");
    }
    assert_eq!(fake.log_calls.lock().expect("lock").len(), 1);
    p.poll(t0 + Duration::from_secs(10)).await.expect("poll");
    assert_eq!(fake.log_calls.lock().expect("lock").len(), 2);
}

#[tokio::test]
async fn a_chunk_cut_never_splits_a_multibyte_character() {
    for (glyph, pad_len) in [("\u{e9}", 4095), ("\u{20ac}", 4094), ("\u{1F600}", 4093)] {
        let fake = Fake::with(vec![]);
        let rec = Rec::default();
        let t0 = Instant::now();
        let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
        let raw = format!("{}{glyph}{glyph}", pad(pad_len));
        fake.logs
            .lock()
            .expect("lock")
            .insert(1, Ok(raw.into_bytes()));
        set_tasks(&fake, &[finished_task(1)]);
        p.poll(t0).await.expect("poll");
        let chunks = rec.all();
        assert_eq!(chunks.len(), 2, "{glyph}");
        assert_eq!(chunks[0].bytes.len(), pad_len, "{glyph}");
        assert!(std::str::from_utf8(&chunks[0].bytes).is_ok());
        assert!(chunks[1].bytes.starts_with(glyph.as_bytes()));
        assert_eq!(rec.text(), format!("{}{glyph}{glyph}", pad(pad_len)));
    }
}

#[tokio::test]
async fn the_last_chunk_slot_is_kept_for_the_terminal_status() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    let raw = pad(63 * MAX_SHELL_LOG_CHUNK_BYTES + 500 + LOG_TAIL_GUARD);
    fake.logs
        .lock()
        .expect("lock")
        .insert(1, Ok(raw.into_bytes()));
    set_tasks(&fake, &[task(1, &running())]);
    for i in 1..=12_u32 {
        p.poll(t0 + Duration::from_secs(10_000) * i)
            .await
            .expect("poll");
    }
    assert_eq!(rec.all().len(), MAX_SHELL_LOG_CHUNKS - 1);
    set_tasks(&fake, &[finished_task(1)]);
    p.poll(t0 + Duration::from_secs(200_000))
        .await
        .expect("poll");
    let chunks = rec.all();
    assert_eq!(chunks.len(), MAX_SHELL_LOG_CHUNKS);
    assert!(chunks.iter().all(|c| validate_shell_log_seq(c.seq)));
    assert_eq!(chunks[63].status, v1::ShellStatus::Failed);
}

#[tokio::test]
async fn a_queued_task_is_never_read() {
    let fake = Fake::with(vec![]);
    let rec = Rec::default();
    let t0 = Instant::now();
    let mut p = pusher(&fake, &rec, Redactor::new([SECRET]), t0).await;
    set_tasks(&fake, &[task(1, &queued())]);
    p.poll(t0).await.expect("poll");
    assert_eq!(rec.statuses(), vec![v1::ShellStatus::Queued]);
    assert_eq!(fake.log_calls.lock().expect("lock").len(), 0);
}
