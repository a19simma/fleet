//! The judge Job over a stored transcript, with a fake agent and a fake reporter. Own test
//! binary because it spawns children.

use std::future::{Future, ready};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{
    GetJobTranscriptReply, GetJobTranscriptRequest, Job, JobKind, JobState, ReportJobReply,
    ReportJobRequest, TranscriptChunk,
};
use fleet_proto::{MAX_MODEL_BYTES, MAX_TRANSCRIPT_BYTES, MAX_VERDICT_REASON_BYTES};
use fleetd::poller::Shutdown;
use fleetd::runner::{AgentOutcome, AgentRunner, JudgeError, Reporter, RunConfig};
use tempfile::TempDir;
use tonic::Status;

#[path = "common/bounded.rs"]
mod common;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MODEL: &str = "judge-model-1";

#[derive(Clone)]
struct Fake {
    reports: Arc<Mutex<Vec<ReportJobRequest>>>,
    requests: Arc<Mutex<Vec<GetJobTranscriptRequest>>>,
    reply: Result<Vec<String>, Status>,
    truncated: Arc<AtomicBool>,
    cut_at: Arc<AtomicUsize>,
}

impl Reporter for Fake {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        self.reports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        ready(Ok(ReportJobReply::default()))
    }

    fn job_transcript(
        &self,
        request: GetJobTranscriptRequest,
    ) -> impl Future<Output = Result<GetJobTranscriptReply, Status>> + Send {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        let truncated = self.truncated.load(Ordering::SeqCst);
        let cut_at = self.cut_at.load(Ordering::SeqCst);
        ready(self.reply.clone().map(|texts| {
            let last = texts.len().saturating_sub(1);
            GetJobTranscriptReply {
                target_job_id: "target1".into(),
                chunks: texts
                    .into_iter()
                    .enumerate()
                    .map(|(at, text)| TranscriptChunk {
                        text,
                        truncated: (truncated && at == last) || at == cut_at,
                        ..TranscriptChunk::default()
                    })
                    .collect(),
            }
        }))
    }
}

struct Rig {
    _dir: TempDir,
    root: PathBuf,
    record: PathBuf,
    agent: AgentRunner<Fake>,
    fake: Fake,
}

fn script(dir: &Path, record: &Path, stream: &Path) -> Result<PathBuf, std::io::Error> {
    let path = dir.join("claude");
    let body = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '2.1.289 (Claude Code)'; exit 0; fi\nprintf '%s\\n' \"$@\" > '{}'\nwc -c < transcript.jsonl >> '{}'\ncat '{}'\n",
        record.display(),
        record.display(),
        stream.display()
    );
    std::fs::write(&path, body)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn rig(
    reply: Result<Vec<String>, Status>,
    model: Option<&str>,
    result: &str,
) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let stream = dir.path().join("stream.jsonl");
    let mut lines = Vec::new();
    if let Some(model) = model {
        lines.push(serde_json::json!({"type":"system","subtype":"init","model":model}).to_string());
    }
    lines.push(serde_json::json!({"type":"result","result":result}).to_string());
    std::fs::write(&stream, lines.join("\n") + "\n")?;
    let record = dir.path().join("record");
    let claude = script(dir.path(), &record, &stream)?;
    let root = dir.path().join("jobs");
    let mut config = RunConfig::new(claude, false);
    config.jobs_dir = Some(root.clone());
    config.flush_interval = Duration::from_millis(20);
    let fake = Fake {
        reports: Arc::default(),
        requests: Arc::default(),
        reply,
        truncated: Arc::default(),
        cut_at: Arc::new(AtomicUsize::new(usize::MAX)),
    };
    let agent = AgentRunner::new(config, fake.clone(), Redactor::new(["hunter2-hunter2"]));
    Ok(Rig {
        _dir: dir,
        root,
        record,
        agent,
        fake,
    })
}

fn judge_job() -> Job {
    Job {
        job_id: "judge1".into(),
        attempt: 3,
        r#box: "boxa".into(),
        prompt: "grade it".into(),
        kind: JobKind::Judge.into(),
        target_job_id: Some("target1".into()),
        ..Job::default()
    }
}

async fn run_judge(rig: &Rig) -> Result<Option<ReportJobRequest>, Box<dyn std::error::Error>> {
    let job = judge_job();
    let dir = rig.agent.load_judge(&job, "boxa").await?;
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = rig.agent.run(&job, &dir, shutdown).await?;
    assert_eq!(outcome, AgentOutcome::Succeeded);
    rig.agent.finish_judge(&job).await;
    let reports = rig
        .fake
        .reports
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(reports
        .iter()
        .rev()
        .find(|r| r.terminal_state.is_some())
        .cloned())
}

fn ok_transcript() -> Vec<String> {
    vec!["line one\n".into(), "line two hunter2-hunter2\n".into()]
}

#[tokio::test]
async fn a_verdict_line_becomes_a_succeeded_report_with_the_verdict() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(ok_transcript()),
            Some(MODEL),
            "analysis\nVERDICT: 87 solid work",
        )?;
        let last = run_judge(&rig).await?.ok_or("no terminal report")?;
        assert_eq!(last.terminal_state, Some(JobState::Succeeded.into()));
        let verdict = last.verdict.ok_or("no verdict")?;
        assert_eq!(verdict.score, 87);
        assert_eq!(verdict.reason, "solid work");
        assert_eq!(verdict.judge_model, MODEL);
        let requests = rig
            .fake
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].job_id, "judge1");
        assert_eq!(requests[0].attempt, 3);
        assert_eq!(requests[0].r#box, "boxa");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_agent_gets_read_only_tools_and_a_redacted_transcript_file() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(Ok(ok_transcript()), Some(MODEL), "VERDICT: 50 fine")?;
        run_judge(&rig).await?;
        let record = std::fs::read_to_string(&rig.record)?;
        let args: Vec<&str> = record.lines().collect();
        let at = |flag: &str| args.iter().position(|a| *a == flag);
        let allowed = at("--allowedTools").ok_or("no allowedTools")?;
        assert_eq!(
            args[allowed + 1..allowed + 4],
            ["Read(./transcript.jsonl)", "Grep(./**)", "Glob(./**)"]
        );
        let denied = at("--disallowedTools").ok_or("no disallowedTools")?;
        for tool in ["Read", "Grep", "Glob"] {
            for path in ["../**", "~/**", "//proc/**", "//etc/**"] {
                let rule = format!("{tool}({path})");
                assert!(args[denied + 1..].contains(&rule.as_str()), "{rule}");
            }
        }
        for tool in ["Bash", "Edit", "Write", "NotebookEdit", "MultiEdit"] {
            assert!(args[denied + 1..].contains(&tool), "{tool} not denied");
        }
        assert!(args.contains(&"grade it"));
        let size: usize = args.last().ok_or("no size")?.trim().parse()?;
        assert_eq!(size, "line one\nline two [REDACTED]\n".len());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_truncated_transcript_ends_with_a_visible_marker_line() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(Ok(ok_transcript()), Some(MODEL), "VERDICT: 1 x")?;
        rig.fake.truncated.store(true, Ordering::SeqCst);
        let job = judge_job();
        let dir = rig.agent.load_judge(&job, "boxa").await?;
        let text = std::fs::read_to_string(dir.join("transcript.jsonl"))?;
        let last = text.lines().last().ok_or("empty")?;
        let value: serde_json::Value = serde_json::from_str(last)?;
        assert_eq!(value["type"], "fleet_notice");
        assert!(text.starts_with("line one\nline two [REDACTED]\n"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_marker_starts_on_its_own_line_after_an_unterminated_chunk() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(vec!["line one\n".into(), "tail".into()]),
            Some(MODEL),
            "VERDICT: 1 x",
        )?;
        rig.fake.truncated.store(true, Ordering::SeqCst);
        let job = judge_job();
        let dir = rig.agent.load_judge(&job, "boxa").await?;
        let text = std::fs::read_to_string(dir.join("transcript.jsonl"))?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], "tail");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_cut_line_does_not_glue_to_the_next_line() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(vec![
                "{\"a\":1}\n".into(),
                "{\"cut\":\"xxxx".into(),
                "{\"b\":2}\n".into(),
            ]),
            Some(MODEL),
            "VERDICT: 1 x",
        )?;
        rig.fake.cut_at.store(1, Ordering::SeqCst);
        let job = judge_job();
        let dir = rig.agent.load_judge(&job, "boxa").await?;
        let text = std::fs::read_to_string(dir.join("transcript.jsonl"))?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(lines[1], "{\"cut\":\"xxxx");
        assert_eq!(lines[2], "{\"b\":2}");
        let notice: serde_json::Value = serde_json::from_str(lines[3])?;
        assert_eq!(notice["type"], "fleet_notice");
        assert!(
            notice["notice"]
                .as_str()
                .ok_or("no notice")?
                .contains("line size limit"),
            "{text}"
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_server_marker_row_gets_the_server_limit_notice() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(vec!["{\"a\":1}\n".into(), String::new()]),
            Some(MODEL),
            "VERDICT: 1 x",
        )?;
        rig.fake.cut_at.store(1, Ordering::SeqCst);
        let job = judge_job();
        let dir = rig.agent.load_judge(&job, "boxa").await?;
        let text = std::fs::read_to_string(dir.join("transcript.jsonl"))?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[1].contains("server size limit"), "{text}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_whole_transcript_has_no_marker_line() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(Ok(ok_transcript()), Some(MODEL), "VERDICT: 1 x")?;
        let job = judge_job();
        let dir = rig.agent.load_judge(&job, "boxa").await?;
        let text = std::fs::read_to_string(dir.join("transcript.jsonl"))?;
        assert_eq!(text, "line one\nline two [REDACTED]\n");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_transcript_directory_is_removed_on_clear() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(Ok(ok_transcript()), Some(MODEL), "VERDICT: 1 x")?;
        let job = judge_job();
        let dir = rig.agent.load_judge(&job, "boxa").await?;
        assert!(dir.join("transcript.jsonl").exists());
        rig.agent.clear_judge(&job);
        assert!(!rig.root.join("judge1").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_reason_is_cut_to_the_shared_cap() -> TestResult {
    common::bounded(Box::pin(async {
        let long = "r".repeat(MAX_VERDICT_REASON_BYTES + 500);
        let rig = rig(
            Ok(ok_transcript()),
            Some(MODEL),
            &format!("VERDICT: 100 {long}"),
        )?;
        let verdict = run_judge(&rig)
            .await?
            .ok_or("no report")?
            .verdict
            .ok_or("no verdict")?;
        assert_eq!(verdict.score, 100);
        assert_eq!(verdict.reason.len(), MAX_VERDICT_REASON_BYTES);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_reason_is_redacted() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(ok_transcript()),
            Some(MODEL),
            "VERDICT: 5 leaked hunter2-hunter2 here",
        )?;
        let verdict = run_judge(&rig)
            .await?
            .ok_or("no report")?
            .verdict
            .ok_or("no verdict")?;
        assert!(!verdict.reason.contains("hunter2"), "{}", verdict.reason);
        Ok(())
    }))
    .await
}

async fn assert_failed_without_verdict(result: &str, model: Option<&str>) -> TestResult {
    let rig = rig(Ok(ok_transcript()), model, result)?;
    let last = run_judge(&rig).await?.ok_or("no terminal report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
    assert!(last.verdict.is_none());
    Ok(())
}

#[tokio::test]
async fn a_job_without_a_parseable_verdict_fails_and_stores_none() -> TestResult {
    common::bounded(Box::pin(async {
        for result in [
            "no verdict here",
            "",
            "VERDICT: 101 too high",
            "VERDICT: -1 negative",
            "VERDICT: abc words",
            "VERDICT: 50",
            "VERDICT: 50 fine\ntrailing prose",
            "verdict: 50 lowercase",
            "VERDICT: +5 signed",
        ] {
            assert_failed_without_verdict(result, Some(MODEL)).await?;
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_verdict_with_an_oversize_model_name_fails() -> TestResult {
    common::bounded(Box::pin(async {
        let model = "m".repeat(MAX_MODEL_BYTES + 1);
        assert_failed_without_verdict("VERDICT: 50 fine", Some(&model)).await
    }))
    .await
}

#[tokio::test]
async fn a_verdict_without_a_model_name_fails() -> TestResult {
    common::bounded(Box::pin(async {
        assert_failed_without_verdict("VERDICT: 50 fine", None).await
    }))
    .await
}

#[tokio::test]
async fn a_failed_fetch_refuses_the_job_with_a_fixed_reason() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Err(Status::permission_denied("lease does not match")),
            Some(MODEL),
            "",
        )?;
        let err = rig.agent.load_judge(&judge_job(), "boxa").await.err();
        assert_eq!(err, Some(JudgeError::Fetch));
        assert!(!rig.root.join("judge1").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn an_empty_transcript_refuses_the_job() -> TestResult {
    common::bounded(Box::pin(async {
        for reply in [vec![], vec![String::new()]] {
            let rig = rig(Ok(reply), Some(MODEL), "")?;
            let err = rig.agent.load_judge(&judge_job(), "boxa").await.err();
            assert_eq!(err, Some(JudgeError::Empty));
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn an_oversize_transcript_refuses_the_job() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(vec!["a".repeat(MAX_TRANSCRIPT_BYTES + 1)]),
            Some(MODEL),
            "",
        )?;
        let err = rig.agent.load_judge(&judge_job(), "boxa").await.err();
        assert_eq!(err, Some(JudgeError::Limit));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_transcript_at_the_cap_is_accepted() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig(
            Ok(vec![format!("{}\n", "a".repeat(MAX_TRANSCRIPT_BYTES - 1))]),
            Some(MODEL),
            "",
        )?;
        let dir = rig.agent.load_judge(&judge_job(), "boxa").await?;
        assert_eq!(
            std::fs::metadata(dir.join("transcript.jsonl"))?.len(),
            u64::try_from(MAX_TRANSCRIPT_BYTES)?
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_default_reporter_fails_closed() -> TestResult {
    struct Bare;
    impl Reporter for Bare {
        fn report(
            &self,
            _request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            ready(Ok(ReportJobReply::default()))
        }
    }
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let mut config = RunConfig::new("claude", false);
        config.jobs_dir = Some(dir.path().to_path_buf());
        let agent = AgentRunner::new(config, Bare, Redactor::default());
        let err = agent.load_judge(&judge_job(), "boxa").await.err();
        assert_eq!(err, Some(JudgeError::Fetch));
        Ok(())
    }))
    .await
}
