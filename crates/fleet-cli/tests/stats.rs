//! `fleet stats` against an in-process stub.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, CostStats, GetJobRequest, GetStatsReply, GetStatsRequest, Job, ListJobsReply,
    ListJobsRequest, Quantiles, ReadJobEventsReply, ReadJobEventsRequest, ReadTranscriptReply,
    ReadTranscriptRequest, StatsGroup, StatsGroupBy, StuckOutcomes, StuckRuleStats,
    SubmitJobRequest, Total,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";
const WAIT: Duration = Duration::from_secs(10);

#[derive(Default, Clone)]
struct Stub {
    reply: GetStatsReply,
    requests: Arc<Mutex<Vec<GetStatsRequest>>>,
}

#[tonic::async_trait]
impl FleetJobs for Stub {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_job(&self, _: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
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

    async fn read_job_events(
        &self,
        _: Request<ReadJobEventsRequest>,
    ) -> Result<Response<ReadJobEventsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsReply>, Status> {
        let expected = format!("Bearer {TOKEN}");
        match request.metadata().get("authorization") {
            Some(v) if v.as_bytes() == expected.as_bytes() => {}
            _ => return Err(Status::unauthenticated("bad token")),
        }
        self.requests
            .lock()
            .map_err(|_| Status::internal("poisoned"))?
            .push(request.into_inner());
        Ok(Response::new(self.reply.clone()))
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

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

fn quantiles(n: u64, p50: f64, p95: f64) -> Quantiles {
    Quantiles { n, p50, p95 }
}

fn total(n: u64, sum: u64) -> Total {
    Total { n, sum }
}

fn full_group(key: &str) -> StatsGroup {
    StatsGroup {
        key: key.into(),
        jobs: 12,
        succeeded: 6,
        failed: 1,
        timed_out: 1,
        cancelled: 0,
        lost: 0,
        other: 4,
        with_summary: 5,
        complete: 4,
        duration_ms: quantiles(5, 90_000.0, 1_250_000.0).into(),
        turns: quantiles(4, 8.0, 20.0).into(),
        cost_est_usd: Some(CostStats {
            n: 5,
            sum: 12.3456,
            p50: 2.0,
            p95: 4.0,
        }),
        tokens_in: total(5, 1000).into(),
        tool_calls: total(5, 200).into(),
        tool_errors: total(5, 15).into(),
        denials: total(3, 7).into(),
        stuck_jobs: 2,
        ..StatsGroup::default()
    }
}

fn reply(groups: Vec<StatsGroup>) -> GetStatsReply {
    GetStatsReply {
        groups,
        since: 100,
        until: 200,
        ..GetStatsReply::default()
    }
}

async fn stats(reply: GetStatsReply, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let url = serve(Stub {
        reply,
        ..Stub::default()
    })
    .await?;
    let mut full = vec!["stats"];
    full.extend_from_slice(args);
    let (result, out) = cli(&url, TOKEN, &full).await;
    result?;
    Ok(out)
}

fn row<'a>(out: &'a str, key: &str) -> Result<Vec<&'a str>, String> {
    out.lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|cells| cells.first() == Some(&key))
        .ok_or_else(|| format!("no row {key} in {out}"))
}

#[tokio::test]
async fn renders_the_key_columns_with_denominators() -> TestResult {
    let out = stats(reply(vec![full_group("all")]), &[]).await?;
    let header: Vec<&str> = out
        .lines()
        .find(|l| l.starts_with("group"))
        .ok_or("header")?
        .split('\t')
        .collect();
    assert_eq!(
        header,
        [
            "group",
            "jobs",
            "ok%",
            "dur_p50",
            "dur_p95",
            "cost_usd",
            "tool_err%",
            "denials",
            "stuck",
            "n"
        ]
    );
    let cells = row(&out, "all")?;
    assert_eq!(
        cells,
        [
            "all",
            "12",
            "75.0% (6/8)",
            "1m30s",
            "20m50s",
            "12.3456",
            "7.5%",
            "7",
            "2/5",
            "dur=5 cost=5 tools=5 den=3"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn absent_figures_print_a_dash_never_zero() -> TestResult {
    let group = StatsGroup {
        key: "bare".into(),
        jobs: 3,
        other: 3,
        ..StatsGroup::default()
    };
    let out = stats(reply(vec![group]), &[]).await?;
    assert_eq!(
        row(&out, "bare")?,
        [
            "bare",
            "3",
            "- (0/0)",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "dur=- cost=- tools=- den=-"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn tool_error_rate_needs_both_figures_and_calls() -> TestResult {
    let none = StatsGroup {
        key: "zero".into(),
        tool_calls: total(2, 0).into(),
        tool_errors: total(2, 0).into(),
        ..StatsGroup::default()
    };
    let lone = StatsGroup {
        key: "lone".into(),
        tool_calls: total(4, 10).into(),
        ..StatsGroup::default()
    };
    let thin = StatsGroup {
        key: "thin".into(),
        tool_calls: total(4, 10).into(),
        tool_errors: total(1, 1).into(),
        ..StatsGroup::default()
    };
    let out = stats(reply(vec![none, lone, thin]), &[]).await?;
    assert_eq!(row(&out, "zero")?[6], "-");
    assert_eq!(row(&out, "lone")?[6], "-");
    assert_eq!(row(&out, "lone")?[9], "dur=- cost=- tools=- den=-");
    assert_eq!(row(&out, "thin")?[6], "10.0%");
    assert_eq!(row(&out, "thin")?[9], "dur=- cost=- tools=1 den=-");
    Ok(())
}

#[tokio::test]
async fn success_rate_counts_finished_jobs_only() -> TestResult {
    let group = StatsGroup {
        key: "g".into(),
        jobs: 100,
        succeeded: 1,
        failed: 1,
        timed_out: 1,
        cancelled: 1,
        lost: 2,
        other: 94,
        ..StatsGroup::default()
    };
    let out = stats(reply(vec![group]), &[]).await?;
    assert_eq!(row(&out, "g")?[2], "16.7% (1/6)");
    Ok(())
}

#[tokio::test]
async fn short_and_long_durations_and_rounding() -> TestResult {
    let mut fast = full_group("fast");
    fast.duration_ms = quantiles(1, 640.4, 1_500.0).into();
    let mut minute = full_group("minute");
    minute.duration_ms = quantiles(1, 59_949.0, 60_000.0).into();
    let mut hour = full_group("hour");
    hour.duration_ms = quantiles(1, 3_605_000.0, 7_200_000.0).into();
    let mut edge = full_group("edge");
    edge.duration_ms = quantiles(1, 1_000.0, 59_950.0).into();
    let out = stats(reply(vec![fast, minute, hour, edge]), &[]).await?;
    assert_eq!(&row(&out, "edge")?[3..5], ["1.0s", "1m00s"]);
    assert_eq!(&row(&out, "fast")?[3..5], ["640ms", "1.5s"]);
    assert_eq!(&row(&out, "minute")?[3..5], ["59.9s", "1m00s"]);
    assert_eq!(&row(&out, "hour")?[3..5], ["60m05s", "120m00s"]);
    Ok(())
}

#[tokio::test]
async fn an_empty_window_says_so() -> TestResult {
    let out = stats(reply(Vec::new()), &[]).await?;
    assert!(out.contains("(no jobs in window)"), "{out}");
    assert!(!out.contains("group\t"), "{out}");
    Ok(())
}

#[tokio::test]
async fn truncation_and_clamping_are_announced() -> TestResult {
    let mut r = reply(vec![full_group("a")]);
    let plain = stats(r.clone(), &[]).await?;
    assert!(!plain.contains("truncated"), "{plain}");
    assert!(!plain.contains("clamped"), "{plain}");
    r.truncated = true;
    r.clamped = true;
    let out = stats(r, &[]).await?;
    assert!(
        out.contains("truncated: only the first groups are shown"),
        "{out}"
    );
    assert!(out.contains("clamped to 90 days"), "{out}");
    Ok(())
}

#[tokio::test]
async fn the_window_line_shows_the_effective_bounds() -> TestResult {
    let out = stats(reply(vec![full_group("a")]), &[]).await?;
    assert!(
        out.starts_with("window: 100 to 200 (unix seconds)\n"),
        "{out}"
    );
    Ok(())
}

#[tokio::test]
async fn server_text_is_sanitized() -> TestResult {
    let hostile = "ev\u{1b}[31mil\u{202e}\u{0}repo";
    let out = stats(reply(vec![full_group(hostile)]), &["--by", "repo"]).await?;
    assert!(out.contains("ev[31milrepo\t"), "{out:?}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(!out.contains('\u{202e}'), "{out:?}");
    assert!(!out.contains('\u{0}'), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn an_empty_key_is_shown_as_all() -> TestResult {
    let out = stats(reply(vec![full_group("")]), &[]).await?;
    assert_eq!(row(&out, "all")?[1], "12");
    Ok(())
}

#[tokio::test]
async fn an_unknown_group_is_labelled_unknown_and_a_real_value_stays_itself() -> TestResult {
    let unknown = StatsGroup {
        unknown: true,
        ..full_group("")
    };
    let literal = full_group("unknown");
    let out = stats(reply(vec![unknown, literal]), &["--by", "model"]).await?;
    let labels = out
        .lines()
        .filter_map(|line| line.split('\t').next())
        .filter(|cell| *cell == "unknown")
        .count();
    assert_eq!(labels, 2, "{out}");
    assert!(!out.contains("\nall\t"), "{out}");
    Ok(())
}

async fn requests_for(args: &[&str]) -> Result<Vec<GetStatsRequest>, Box<dyn std::error::Error>> {
    let stub = Stub::default();
    let seen = stub.requests.clone();
    let url = serve(stub).await?;
    let mut full = vec!["stats"];
    full.extend_from_slice(args);
    let (result, _) = cli(&url, TOKEN, &full).await;
    result?;
    Ok(seen.lock().map_err(|_| "poisoned")?.clone())
}

#[tokio::test]
async fn flags_map_onto_the_request() -> TestResult {
    let seen = requests_for(&["--repo", "R", "--box", "B", "--by", "repo"]).await?;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].repo.as_deref(), Some("R"));
    assert_eq!(seen[0].r#box.as_deref(), Some("B"));
    assert_eq!(seen[0].group_by, StatsGroupBy::Repo as i32);
    assert_eq!(seen[0].until, None);

    for (flag, expected) in [
        ("repo", StatsGroupBy::Repo),
        ("box", StatsGroupBy::Box),
        ("state", StatsGroupBy::State),
        ("day", StatsGroupBy::Day),
        ("bundle-sha", StatsGroupBy::BundleSha),
        ("claude-version", StatsGroupBy::ClaudeVersion),
        ("model", StatsGroupBy::Model),
    ] {
        let seen = requests_for(&["--by", flag]).await?;
        assert_eq!(seen[0].group_by, expected as i32, "{flag}");
    }

    let plain = requests_for(&[]).await?;
    assert_eq!(plain[0].group_by, StatsGroupBy::None as i32);
    assert_eq!(plain[0].repo, None);
    assert_eq!(plain[0].r#box, None);
    Ok(())
}

#[tokio::test]
async fn since_takes_durations_and_unix_times() -> TestResult {
    for (text, back) in [
        (None, 7 * 86_400),
        (Some("45s"), 45),
        (Some("90m"), 5_400),
        (Some("24h"), 86_400),
        (Some("7d"), 604_800),
        (Some("1d"), 86_400),
    ] {
        let args: Vec<&str> = text.map_or_else(Vec::new, |t| vec!["--since", t]);
        let before = now();
        let seen = requests_for(&args).await?;
        let after = now();
        let since = seen[0].since.ok_or("since unset")?;
        assert!(
            since >= before - back && since <= after - back,
            "{text:?}: {since} not in [{}, {}]",
            before - back,
            after - back
        );
    }
    let seen = requests_for(&["--since", "1700000000"]).await?;
    assert_eq!(seen[0].since, Some(1_700_000_000));
    let seen = requests_for(&["--since", "0"]).await?;
    assert_eq!(seen[0].since, Some(0));
    Ok(())
}

#[tokio::test]
async fn bad_since_is_a_usage_error_before_any_request() -> TestResult {
    for bad in [
        "",
        "abc",
        "0d",
        "0s",
        "-5h",
        "7x",
        "d",
        "h",
        "1.5h",
        " 7d",
        "7 d",
        "7dd",
        "+7d",
        "99999999d",
        "99999999999999999999d",
        "9999999999999999d",
        "99999999999999999999",
        "٣d",
    ] {
        let stub = Stub::default();
        let seen = stub.requests.clone();
        let url = serve(stub).await?;
        let (result, out) = cli(&url, TOKEN, &["stats", "--since", bad]).await;
        let err = result.err().ok_or_else(|| format!("{bad:?} accepted"))?;
        assert!(matches!(err, CliError::Usage(_)), "{bad:?}: {err}");
        assert_eq!(err.exit_code(), 2, "{bad:?}");
        assert!(out.is_empty(), "{bad:?}: {out}");
        assert!(seen.lock().map_err(|_| "poisoned")?.is_empty(), "{bad:?}");
    }
    Ok(())
}

#[tokio::test]
async fn the_usage_message_does_not_echo_server_text_or_crash_on_hostile_input() -> TestResult {
    let url = serve(Stub::default()).await?;
    let (result, _) = cli(&url, TOKEN, &["stats", "--since", "x\u{1b}[31m"]).await;
    let err = result.err().ok_or("accepted")?;
    assert!(!err.to_string().contains('\u{1b}'), "{err}");
    Ok(())
}

#[tokio::test]
async fn a_rejected_token_is_an_rpc_error() -> TestResult {
    let url = serve(Stub::default()).await?;
    let (result, out) = cli(&url, "wrong-token-0123456789", &["stats"]).await;
    let err = result.err().ok_or("accepted")?;
    assert!(matches!(err, CliError::Rpc(_)), "{err}");
    assert_eq!(err.exit_code(), 1);
    assert!(out.is_empty(), "{out}");
    Ok(())
}

#[tokio::test]
async fn an_unknown_grouping_is_rejected_by_clap() -> TestResult {
    let url = serve(Stub::default()).await?;
    let (result, _) = cli(&url, TOKEN, &["stats", "--by", "colour"]).await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn stuck_cell_is_the_count_over_summarized_jobs() -> TestResult {
    let some = StatsGroup {
        key: "some".into(),
        jobs: 9,
        with_summary: 4,
        stuck_jobs: 0,
        ..StatsGroup::default()
    };
    let many = StatsGroup {
        key: "many".into(),
        jobs: 9,
        with_summary: 4,
        stuck_jobs: 3,
        ..StatsGroup::default()
    };
    let none = StatsGroup {
        key: "none".into(),
        jobs: 9,
        with_summary: 0,
        stuck_jobs: 0,
        ..StatsGroup::default()
    };
    let out = stats(reply(vec![some, many, none]), &[]).await?;
    assert_eq!(row(&out, "some")?[8], "0/4");
    assert_eq!(row(&out, "many")?[8], "3/4");
    assert_eq!(row(&out, "none")?[8], "-");
    Ok(())
}

fn outcomes(jobs: u64, succeeded: u64, failed: u64, other_terminal: u64) -> StuckOutcomes {
    StuckOutcomes {
        jobs,
        succeeded,
        failed,
        other_terminal,
    }
}

#[tokio::test]
async fn stuck_rules_table_lists_each_rule_beside_clean_jobs() -> TestResult {
    let group = StatsGroup {
        key: "alpha".into(),
        jobs: 9,
        with_summary: 9,
        stuck_jobs: 5,
        stuck_rules: vec![
            StuckRuleStats {
                rule: "repeat_error".into(),
                outcomes: Some(outcomes(3, 2, 1, 0)),
            },
            StuckRuleStats {
                rule: "monologue".into(),
                outcomes: Some(outcomes(2, 0, 0, 0)),
            },
        ],
        clean: Some(outcomes(4, 3, 0, 1)),
        ..StatsGroup::default()
    };
    let unknown = StatsGroup {
        unknown: true,
        clean: Some(outcomes(1, 1, 0, 0)),
        ..StatsGroup::default()
    };
    let out = stats(reply(vec![group, unknown]), &[]).await?;
    let lines: Vec<Vec<&str>> = out
        .lines()
        .skip_while(|l| !l.starts_with("group\tstuck_rule"))
        .map(|l| l.split('\t').collect())
        .collect();
    assert_eq!(
        lines,
        [
            vec![
                "group",
                "stuck_rule",
                "flagged",
                "succeeded",
                "failed",
                "other",
                "ok%"
            ],
            vec!["alpha", "repeat_error", "3", "2", "1", "0", "66.7% (2/3)"],
            vec!["alpha", "monologue", "2", "0", "0", "0", "- (0/0)"],
            vec!["alpha", "(clean)", "4", "3", "0", "1", "75.0% (3/4)"],
            vec!["unknown", "(clean)", "1", "1", "0", "0", "100.0% (1/1)"],
        ]
    );
    Ok(())
}

#[tokio::test]
async fn no_stuck_data_prints_no_stuck_table() -> TestResult {
    let out = stats(reply(vec![full_group("all")]), &[]).await?;
    assert!(!out.contains("stuck_rule"), "{out}");
    Ok(())
}
