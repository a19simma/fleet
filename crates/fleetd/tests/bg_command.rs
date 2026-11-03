//! Background command timing from pueue: state table, baseline, timestamps, fallback, caps and
//! hostile log content.

#![expect(clippy::expect_used, reason = "test code asserts by panicking")]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use fleet_core::{PLACEHOLDER, Redactor};
use fleet_proto::{MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES};
use fleetd::bg_command::{
    Anchor, BgConfig, BgOutcome, BgState, BgWatcher, EndedBy, LOG_READ_CAP, MAX_POLL_ERRORS,
    MAX_TRACKED_TASKS, PueueCli, PueueClient, PueueError, Rule, parse_timestamp, rule,
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
            .unwrap_or(Ok(Vec::new()));
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
