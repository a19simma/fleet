//! `fleet status` telemetry block and `--tools` table against an in-process stub.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobEvent, JobEventKind, JobState, JobSummary,
    ListJobsReply, ListJobsRequest, ReadJobEventsReply, ReadJobEventsRequest, ReadTranscriptReply,
    ReadTranscriptRequest, SubmitJobRequest,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";
const WAIT: Duration = Duration::from_secs(10);

#[derive(Default, Clone)]
struct Stub {
    summary: Option<JobSummary>,
    events: Vec<JobEvent>,
    page: usize,
    stuck: bool,
    requests: Arc<Mutex<Vec<ReadJobEventsRequest>>>,
}

fn check(request: &Request<impl Sized>) -> Result<(), Status> {
    let expected = format!("Bearer {TOKEN}");
    match request.metadata().get("authorization") {
        Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(Status::unauthenticated("bad token")),
    }
}

#[tonic::async_trait]
impl FleetJobs for Stub {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_job(&self, request: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        check(&request)?;
        let job_id = request.into_inner().job_id;
        if !job_id.starts_with("job-") {
            return Err(Status::not_found("no such job"));
        }
        Ok(Response::new(Job {
            job_id,
            state: JobState::Succeeded as i32,
            phase: "done".into(),
            summary: self.summary.clone(),
            ..Job::default()
        }))
    }

    async fn list_jobs(
        &self,
        _: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn cancel_job(&self, _: Request<CancelJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn read_transcript(
        &self,
        _: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_stats(
        &self,
        _: Request<fleet_proto::v1::GetStatsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetStatsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn read_job_events(
        &self,
        request: Request<ReadJobEventsRequest>,
    ) -> Result<Response<ReadJobEventsReply>, Status> {
        check(&request)?;
        let request = request.into_inner();
        self.requests
            .lock()
            .map_err(|_| Status::internal("poisoned"))?
            .push(request.clone());
        if !request.job_id.starts_with("job-") {
            return Err(Status::not_found("no such job"));
        }
        let after = request.after_seq;
        let limit = match usize::try_from(request.limit).unwrap_or(usize::MAX) {
            0 => self.page,
            n => n.min(self.page),
        };
        let events: Vec<JobEvent> = self
            .events
            .iter()
            .filter(|event| after.is_none_or(|a| event.seq > a))
            .take(limit)
            .cloned()
            .collect();
        let next_seq = if self.stuck {
            after.unwrap_or(0)
        } else {
            events.last().map_or_else(|| after.unwrap_or(0), |e| e.seq)
        };
        let events = if self.stuck {
            self.events.iter().take(1).cloned().collect()
        } else {
            events
        };
        Ok(Response::new(ReadJobEventsReply { events, next_seq }))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetJobsServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, token: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let token = token.to_owned();
    let mut out = Vec::new();
    let result = tokio::time::timeout(
        WAIT,
        run(
            parsed,
            move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
            &mut &b""[..],
            &mut out,
        ),
    )
    .await
    .unwrap_or_else(|_| Err(CliError::Usage("timed out".into())));
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn full_summary() -> JobSummary {
    JobSummary {
        turns: Some(4),
        duration_ms: Some(9_000),
        duration_api_ms: Some(1_500),
        stop_reason: Some("end_turn".into()),
        result_subtype: Some("success".into()),
        cost_est_usd: Some(0.25),
        tokens_in: Some(10),
        tokens_out: Some(20),
        tokens_cache_read: Some(30),
        tokens_cache_write: Some(40),
        tool_calls: Some(5),
        tool_errors: Some(1),
        bash_calls: Some(2),
        bash_nonzero: Some(1),
        denials: Some(3),
        api_retries: Some(6),
        first_edit_ms: Some(12_300),
        complete: true,
        missing: Vec::new(),
        stuck_rule: None,
        stuck_at_seq: None,
        stuck_at_ms: None,
        bundle_sha: None,
        claude_version: None,
        model: None,
    }
}

fn tool(seq: u32, name: &str) -> JobEvent {
    JobEvent {
        seq,
        ts_ms: 3_725_000 + u64::from(seq) * 1_000,
        kind: JobEventKind::Tool.into(),
        tool: Some(name.into()),
        ok: Some(true),
        dur_ms: Some(31),
        out_bytes: Some(4_096),
        cmd: Some(format!("cmd {seq}")),
        ..JobEvent::default()
    }
}

fn denial(seq: u32) -> JobEvent {
    JobEvent {
        seq,
        kind: JobEventKind::Denial.into(),
        tool: Some("Write".into()),
        ..JobEvent::default()
    }
}

#[tokio::test]
async fn status_prints_the_full_summary_block() -> TestResult {
    let url = serve(Stub {
        summary: Some(full_summary()),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    let expected = "\
telemetry:
  turns: 4
  duration: 9.0s
  api_duration: 1.5s
  cost_est_usd: 0.2500
  tokens_in: 10
  tokens_out: 20
  tokens_cache_read: 30
  tokens_cache_write: 40
  tool_calls: 5
  tool_errors: 1
  bash_calls: 2
  bash_nonzero: 1
  denials: 3
  api_retries: 6
  first_edit: 12.3s
  stop_reason: end_turn
";
    assert!(out.contains(expected), "{out}");
    assert!(!out.contains("INCOMPLETE"), "{out}");
    assert!(out.starts_with("id: job-1\n"), "{out}");
    Ok(())
}

#[tokio::test]
async fn unobserved_figures_print_dash_and_zero_stays_zero() -> TestResult {
    let summary = JobSummary {
        turns: Some(0),
        duration_ms: Some(250),
        tokens_in: Some(0),
        first_edit_ms: Some(0),
        denials: Some(0),
        complete: false,
        missing: vec!["cost_est_usd".into(), "tokens_out".into()],
        ..JobSummary::default()
    };
    let url = serve(Stub {
        summary: Some(summary),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    let expected = "\
telemetry:
  turns: 0
  duration: 250ms
  api_duration: -
  cost_est_usd: -
  tokens_in: 0
  tokens_out: -
  tokens_cache_read: -
  tokens_cache_write: -
  tool_calls: -
  tool_errors: -
  bash_calls: -
  bash_nonzero: -
  denials: 0
  api_retries: -
  first_edit: 0ms
  stop_reason: -
  INCOMPLETE (missing: cost_est_usd, tokens_out)
";
    assert!(out.contains(expected), "{out}");
    Ok(())
}

#[tokio::test]
async fn incomplete_without_names_still_says_so() -> TestResult {
    let url = serve(Stub {
        summary: Some(JobSummary::default()),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(out.contains("  INCOMPLETE (missing: -)\n"), "{out}");
    Ok(())
}

#[tokio::test]
async fn status_without_a_summary_prints_no_block_and_makes_no_event_call() -> TestResult {
    let stub = Stub {
        page: 10,
        ..Stub::default()
    };
    let requests = stub.requests.clone();
    let url = serve(stub).await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(out.contains("error: -\n"), "{out}");
    assert!(!out.contains("telemetry"), "{out}");
    assert!(!out.contains("INCOMPLETE"), "{out}");
    assert!(requests.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn summary_text_is_sanitized_and_cut() -> TestResult {
    let mut summary = full_summary();
    summary.stop_reason = Some("\u{1b}[31mred\u{1b}[0m".into());
    summary.complete = false;
    summary.missing = vec!["a\u{1b}[2Jb".into()];
    let url = serve(Stub {
        summary: Some(summary),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.contains("stop_reason: [31mred[0m\n"), "{out}");
    assert!(out.contains("(missing: a[2Jb)"), "{out}");
    Ok(())
}

#[tokio::test]
async fn tools_pages_through_every_page_and_keeps_only_tool_events() -> TestResult {
    let events = vec![
        tool(0, "Read"),
        denial(1),
        tool(2, "Bash"),
        tool(3, "Edit"),
        denial(4),
        tool(5, "Grep"),
        tool(6, "Bash"),
    ];
    let stub = Stub {
        summary: Some(full_summary()),
        events,
        page: 3,
        ..Stub::default()
    };
    let requests = stub.requests.clone();
    let url = serve(stub).await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-7", "--tools"]).await;
    res?;
    assert!(out.contains("telemetry:\n"), "{out}");
    let table = out.split("seq\t").nth(1).ok_or("no table")?;
    let rows: Vec<&str> = table.lines().skip(1).collect();
    assert_eq!(
        rows,
        [
            "0\t01:02:05\tRead\tok\t31ms\t4096\tcmd 0",
            "2\t01:02:07\tBash\tok\t31ms\t4096\tcmd 2",
            "3\t01:02:08\tEdit\tok\t31ms\t4096\tcmd 3",
            "5\t01:02:10\tGrep\tok\t31ms\t4096\tcmd 5",
            "6\t01:02:11\tBash\tok\t31ms\t4096\tcmd 6",
        ]
    );
    assert!(
        out.contains("seq\ttime\ttool\tresult\tdur\tbytes\tcmd\n"),
        "{out}"
    );
    let sent: Vec<_> = requests
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .map(|r| (r.job_id.clone(), r.after_seq, r.limit))
        .collect();
    assert_eq!(
        sent,
        [
            ("job-7".to_owned(), None, 1_000),
            ("job-7".to_owned(), Some(2), 1_000),
            ("job-7".to_owned(), Some(5), 1_000),
            ("job-7".to_owned(), Some(6), 1_000),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn tools_row_shows_exit_codes_dashes_and_cuts_the_command() -> TestResult {
    let long = JobEvent {
        seq: 1,
        kind: JobEventKind::Tool.into(),
        tool: Some("Bash".into()),
        ok: Some(false),
        exit_code: Some(2),
        cmd: Some(format!("echo \u{1b}[31m{}\n", "x".repeat(100))),
        ..JobEvent::default()
    };
    let bare = JobEvent {
        seq: 2,
        kind: JobEventKind::Tool.into(),
        ..JobEvent::default()
    };
    let failed = JobEvent {
        seq: 3,
        kind: JobEventKind::Tool.into(),
        tool: Some("Edit".into()),
        ok: Some(false),
        ..JobEvent::default()
    };
    let exact = JobEvent {
        seq: 4,
        kind: JobEventKind::Tool.into(),
        tool: Some("Bash".into()),
        cmd: Some("y".repeat(60)),
        ..JobEvent::default()
    };
    let slow = JobEvent {
        seq: 5,
        ts_ms: 86_400_000 + 5_000,
        kind: JobEventKind::Tool.into(),
        dur_ms: Some(1_000),
        ..JobEvent::default()
    };
    let quick = JobEvent {
        seq: 6,
        kind: JobEventKind::Tool.into(),
        tool: Some("Ba\u{1b}[0msh".into()),
        dur_ms: Some(999),
        ..JobEvent::default()
    };
    let url = serve(Stub {
        events: vec![long, bare, failed, exact, slow, quick],
        page: 1_000,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1", "--tools"]).await;
    res?;
    assert!(!out.contains('\u{1b}'), "{out:?}");
    let table = out.split("seq\t").nth(1).ok_or("no table")?;
    let rows: Vec<&str> = table.lines().skip(1).collect();
    let cut = format!("echo [31m{}\u{2026}", "x".repeat(50));
    assert_eq!(rows[0], format!("1\t00:00:00\tBash\texit 2\t-\t-\t{cut}"));
    assert_eq!(rows[1], "2\t00:00:00\t-\t-\t-\t-\t-");
    assert_eq!(rows[2], "3\t00:00:00\tEdit\terr\t-\t-\t-");
    assert_eq!(
        rows[3],
        format!("4\t00:00:00\tBash\t-\t-\t-\t{}", "y".repeat(60))
    );
    assert_eq!(rows[4], "5\t00:00:05\t-\t-\t1.0s\t-\t-");
    assert_eq!(rows[5], "6\t00:00:00\tBa[0msh\t-\t999ms\t-\t-");
    assert_eq!(cut.chars().count(), 60);
    Ok(())
}

#[tokio::test]
async fn tools_with_no_tool_events_says_so() -> TestResult {
    let url = serve(Stub {
        events: vec![denial(0)],
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1", "--tools"]).await;
    res?;
    assert!(out.ends_with("(no tool events)\n"), "{out}");
    Ok(())
}

#[tokio::test]
async fn tools_stops_when_the_server_does_not_advance() -> TestResult {
    let url = serve(Stub {
        events: vec![tool(0, "Read"), tool(1, "Bash")],
        page: 10,
        stuck: true,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1", "--tools"]).await;
    res?;
    assert!(out.matches("\tRead\t").count() <= 2, "{out}");
    Ok(())
}

#[tokio::test]
async fn unknown_job_and_bad_token_exit_one() -> TestResult {
    let url = serve(Stub {
        page: 10,
        ..Stub::default()
    })
    .await?;
    for args in [&["status", "nope"][..], &["status", "nope", "--tools"]] {
        let (res, out) = cli(&url, TOKEN, args).await;
        let err = res.err().ok_or("expected error")?;
        assert_eq!(err.exit_code(), 1);
        assert!(!out.contains("seq\t"), "{out}");
    }
    for args in [&["status", "job-1"][..], &["status", "job-1", "--tools"]] {
        let (res, _) = cli(&url, "wrong-token-0123456789", args).await;
        let err = res.err().ok_or("expected error")?;
        assert_eq!(err.exit_code(), 1);
        assert!(!err.to_string().contains("wrong-token"));
    }
    Ok(())
}

#[tokio::test]
async fn status_prints_the_shadow_stuck_line_after_stop_reason() -> TestResult {
    let mut summary = full_summary();
    summary.stuck_rule = Some("repeat_error".into());
    summary.stuck_at_seq = Some(7);
    summary.stuck_at_ms = Some(900);
    let url = serve(Stub {
        summary: Some(summary),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(
        out.contains("  stop_reason: end_turn\n  stuck (shadow): repeat_error at event 7\n"),
        "{out}"
    );
    Ok(())
}

#[tokio::test]
async fn status_prints_no_stuck_line_when_absent() -> TestResult {
    let url = serve(Stub {
        summary: Some(full_summary()),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(!out.contains("stuck"), "{out}");
    Ok(())
}

#[tokio::test]
async fn a_stuck_rule_without_a_position_prints_a_dash() -> TestResult {
    let mut summary = full_summary();
    summary.stuck_rule = Some("monologue".into());
    let url = serve(Stub {
        summary: Some(summary),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(
        out.contains("  stuck (shadow): monologue at event -\n"),
        "{out}"
    );
    Ok(())
}

#[tokio::test]
async fn hostile_stuck_text_is_sanitized() -> TestResult {
    let mut summary = full_summary();
    summary.stuck_rule = Some("\u{1b}[2Jrepeat\u{7}_error\nforged: line".into());
    summary.stuck_at_seq = Some(1);
    let url = serve(Stub {
        summary: Some(summary),
        page: 10,
        ..Stub::default()
    })
    .await?;
    let (res, out) = cli(&url, TOKEN, &["status", "job-1"]).await;
    res?;
    assert!(!out.contains('\u{1b}'), "{out}");
    assert!(!out.contains('\u{7}'), "{out}");
    assert!(!out.contains("\nforged: line"), "{out}");
    assert!(out.contains("  stuck (shadow): "), "{out}");
    Ok(())
}
