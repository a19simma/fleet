//! `fleet batch show`: one column per profile, one row per figure.

use std::io::Write;

use fleet_proto::v1::fleet_batches_client::FleetBatchesClient;
use fleet_proto::v1::{
    GetBatchReply, GetBatchRequest, Job, JobEvent, JobEventKind, JobSummary, ReadJobEventsRequest,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, Client, ELLIPSIS, or_dash, sanitize, sanitize_free, state_name};

/// A `FleetBatches` client carrying the bearer token.
pub(crate) type BatchesClient = FleetBatchesClient<InterceptedService<Channel, Bearer>>;

/// Events asked for per page. The server cuts a larger request to its own maximum.
const EVENTS_PAGE: u32 = 1000;
/// Most event pages read per job. A job holds at most 2000 events, so this only stops a
/// server that never ends a walk.
const MAX_EVENT_PAGES: usize = 100;
/// Longest command shown, in characters, ellipsis included.
const CMD_WIDTH: usize = 60;
/// Printed for a stamp field the job never reported.
const UNKNOWN: &str = "unknown";
/// Printed in `missing` for a job that has no summary at all.
const NO_SUMMARY: &str = "no summary";

fn duration(ms: Option<u64>) -> String {
    ms.map_or_else(
        || "-".into(),
        |ms| {
            if ms < 1000 {
                format!("{ms}ms")
            } else {
                format!("{}.{}s", ms / 1000, ms % 1000 / 100)
            }
        },
    )
}

fn stamp(value: Option<&String>) -> String {
    value.map_or_else(|| UNKNOWN.into(), |v| sanitize_free(v))
}

fn column(job: &Job) -> String {
    job.profile.as_ref().map_or_else(
        || "-".into(),
        |profile| format!("{}@{}", sanitize_free(&profile.name), profile.version),
    )
}

fn from_summary(job: &Job, pick: impl Fn(&JobSummary) -> String) -> String {
    job.summary.as_ref().map_or_else(|| "-".into(), pick)
}

fn complete(job: &Job) -> String {
    from_summary(job, |s| if s.complete { "yes" } else { "no" }.into())
}

fn missing(job: &Job) -> String {
    job.summary.as_ref().map_or_else(
        || NO_SUMMARY.into(),
        |s| {
            if s.missing.is_empty() {
                "-".into()
            } else {
                s.missing
                    .iter()
                    .map(|name| sanitize_free(name))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        },
    )
}

fn count(job: &Job, pick: impl Fn(&JobSummary) -> Option<u64>) -> String {
    from_summary(job, |s| or_dash(pick(s).as_ref()))
}

fn span(job: &Job, pick: impl Fn(&JobSummary) -> Option<u64>) -> String {
    from_summary(job, |s| duration(pick(s)))
}

fn stuck(job: &Job) -> String {
    from_summary(job, |s| {
        s.stuck_rule
            .as_ref()
            .map_or_else(|| "-".into(), |rule| sanitize_free(rule))
    })
}

fn cost(job: &Job) -> String {
    from_summary(job, |s| {
        s.cost_est_usd
            .map_or_else(|| "-".into(), |usd| format!("{usd:.4}"))
    })
}

fn profile_hash(job: &Job) -> String {
    job.profile
        .as_ref()
        .map_or_else(|| "-".into(), |p| sanitize(&p.hash))
}

fn stamp_of(job: &Job, pick: impl Fn(&JobSummary) -> Option<&String>) -> String {
    stamp(job.summary.as_ref().and_then(pick))
}

fn row(
    out: &mut impl Write,
    name: &str,
    jobs: &[Job],
    cell: impl Fn(&Job) -> String,
) -> std::io::Result<()> {
    write!(out, "{name}")?;
    for job in jobs {
        write!(out, "\t{}", cell(job))?;
    }
    writeln!(out)
}

fn command(cmd: Option<&String>) -> String {
    let clean = cmd.map_or_else(|| "-".into(), |cmd| sanitize(cmd));
    if clean.chars().count() > CMD_WIDTH {
        let mut cut: String = clean.chars().take(CMD_WIDTH - 1).collect();
        cut.push(ELLIPSIS);
        cut
    } else {
        clean
    }
}

fn is_bash(event: &JobEvent) -> bool {
    event.kind() == JobEventKind::Tool && event.tool.as_deref() == Some("Bash")
}

/// Writes the comparison of a batch.
///
/// `events` holds the events of each job in the order of `reply.jobs`. A figure the job did
/// not observe prints as `-`, never as 0. A stamp field the job did not report prints as
/// `unknown`. A job with no summary prints `-` in every telemetry row and `no summary` in
/// `missing`.
///
/// # Errors
/// Returns the output error.
pub(crate) fn write_batch(
    out: &mut impl Write,
    reply: &GetBatchReply,
    events: &[Vec<JobEvent>],
) -> std::io::Result<()> {
    let jobs = &reply.jobs;
    writeln!(out, "batch: {}", sanitize(&reply.batch_id))?;
    writeln!(out, "repo: {}", sanitize(&reply.repo))?;
    writeln!(out, "base_sha: {}", sanitize(&reply.base_sha))?;
    row(out, "profile", jobs, column)?;
    row(out, "outcome", jobs, |job| state_name(job).into())?;
    row(out, "cost_est_usd", jobs, cost)?;
    row(out, "turns", jobs, |job| count(job, |s| s.turns))?;
    row(out, "queue_wait", jobs, |job| {
        span(job, |s| s.queue_wait_ms)
    })?;
    row(out, "clone", jobs, |job| span(job, |s| s.clone_ms))?;
    row(out, "agent", jobs, |job| span(job, |s| s.duration_ms))?;
    row(out, "tool_calls", jobs, |job| count(job, |s| s.tool_calls))?;
    row(out, "tool_errors", jobs, |job| {
        count(job, |s| s.tool_errors)
    })?;
    row(out, "denials", jobs, |job| count(job, |s| s.denials))?;
    row(out, "stuck_rule", jobs, stuck)?;
    row(out, "bundle_sha", jobs, |job| {
        stamp_of(job, |s| s.bundle_sha.as_ref())
    })?;
    row(out, "claude_version", jobs, |job| {
        stamp_of(job, |s| s.claude_version.as_ref())
    })?;
    row(out, "model", jobs, |job| {
        stamp_of(job, |s| s.model.as_ref())
    })?;
    row(out, "profile_hash", jobs, profile_hash)?;
    row(out, "complete", jobs, complete)?;
    row(out, "missing", jobs, missing)?;
    for (job, job_events) in jobs.iter().zip(events) {
        writeln!(out, "commands ({}):", column(job))?;
        let mut shown = 0_usize;
        for event in job_events.iter().filter(|event| is_bash(event)) {
            writeln!(
                out,
                "  {}\t{}",
                duration(event.dur_ms),
                command(event.cmd.as_ref())
            )?;
            shown += 1;
        }
        if shown == 0 {
            writeln!(out, "  -")?;
        }
    }
    Ok(())
}

async fn read_events(client: &mut Client, id: &str) -> Result<Vec<JobEvent>, CliError> {
    let mut all = Vec::new();
    let mut after: Option<u32> = None;
    for _ in 0..MAX_EVENT_PAGES {
        let reply = client
            .read_job_events(ReadJobEventsRequest {
                job_id: id.to_owned(),
                after_seq: after,
                limit: EVENTS_PAGE,
            })
            .await?
            .into_inner();
        let Some(last) = reply.events.last().map(|event| event.seq) else {
            break;
        };
        let stalled = after.is_some_and(|cursor| last <= cursor);
        all.extend(reply.events);
        if stalled {
            break;
        }
        after = Some(last);
    }
    Ok(all)
}

/// Fetches batch `id` and the events of each of its jobs, then writes the comparison.
///
/// # Errors
/// Returns [`CliError`] on a server error status or an output failure.
pub(crate) async fn show(
    batches: &mut BatchesClient,
    jobs: &mut Client,
    id: String,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = batches
        .get_batch(GetBatchRequest { batch_id: id })
        .await?
        .into_inner();
    let mut events = Vec::with_capacity(reply.jobs.len());
    for job in &reply.jobs {
        events.push(read_events(jobs, &job.job_id).await?);
    }
    write_batch(out, &reply, &events)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use fleet_proto::v1::{JobState, ProfileRef};

    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn job(
        name: &str,
        version: u32,
        hash: &str,
        state: JobState,
        summary: Option<JobSummary>,
    ) -> Job {
        Job {
            job_id: format!("job-{name}"),
            state: state as i32,
            profile: Some(ProfileRef {
                name: name.into(),
                version,
                hash: hash.into(),
            }),
            summary,
            ..Job::default()
        }
    }

    fn bash(dur_ms: Option<u64>, cmd: &str) -> JobEvent {
        JobEvent {
            kind: JobEventKind::Tool as i32,
            tool: Some("Bash".into()),
            dur_ms,
            cmd: Some(cmd.into()),
            ..JobEvent::default()
        }
    }

    fn complete_job() -> (Job, Vec<JobEvent>) {
        let summary = JobSummary {
            turns: Some(12),
            duration_ms: Some(65_400),
            cost_est_usd: Some(0.1234),
            tool_calls: Some(30),
            tool_errors: Some(0),
            denials: Some(1),
            stuck_rule: Some("repeat_error".into()),
            bundle_sha: Some("b1".into()),
            claude_version: Some("2.1.289".into()),
            model: Some("m1".into()),
            complete: true,
            clone_ms: Some(800),
            queue_wait_ms: Some(1500),
            ..JobSummary::default()
        };
        let events = vec![
            bash(Some(1500), "cargo test"),
            JobEvent {
                kind: JobEventKind::Tool as i32,
                tool: Some("Read".into()),
                ..JobEvent::default()
            },
            bash(Some(20), "ls"),
        ];
        (
            job("alpha", 1, HASH_A, JobState::Succeeded, Some(summary)),
            events,
        )
    }

    fn no_summary_job() -> (Job, Vec<JobEvent>) {
        (job("beta", 2, HASH_B, JobState::Queued, None), Vec::new())
    }

    fn missing_hook_job() -> (Job, Vec<JobEvent>) {
        let summary = JobSummary {
            tool_calls: Some(3),
            complete: false,
            missing: vec!["hooks".into()],
            ..JobSummary::default()
        };
        (
            job("gamma", 1, HASH_C, JobState::Failed, Some(summary)),
            vec![bash(None, "make")],
        )
    }

    fn render(parts: Vec<(Job, Vec<JobEvent>)>) -> String {
        let (jobs, events): (Vec<_>, Vec<_>) = parts.into_iter().unzip();
        let reply = GetBatchReply {
            batch_id: "batch1".into(),
            repo: "https://example.com/r.git".into(),
            base_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            jobs,
            ..GetBatchReply::default()
        };
        let mut out = Vec::new();
        write_batch(&mut out, &reply, &events).expect("write to a Vec");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn a_complete_job_prints_every_figure() {
        let text = render(vec![complete_job()]);
        assert_eq!(
            text,
            "batch: batch1\n\
             repo: https://example.com/r.git\n\
             base_sha: 0123456789abcdef0123456789abcdef01234567\n\
             profile\talpha@1\n\
             outcome\tSUCCEEDED\n\
             cost_est_usd\t0.1234\n\
             turns\t12\n\
             queue_wait\t1.5s\n\
             clone\t800ms\n\
             agent\t65.4s\n\
             tool_calls\t30\n\
             tool_errors\t0\n\
             denials\t1\n\
             stuck_rule\trepeat_error\n\
             bundle_sha\tb1\n\
             claude_version\t2.1.289\n\
             model\tm1\n\
             profile_hash\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
             complete\tyes\n\
             missing\t-\n\
             commands (alpha@1):\n\
             \x20\x201.5s\tcargo test\n\
             \x20\x2020ms\tls\n"
        );
    }

    #[test]
    fn a_no_summary_job_prints_dashes_and_unknown_never_zero() {
        let text = render(vec![no_summary_job()]);
        assert_eq!(
            text,
            "batch: batch1\n\
             repo: https://example.com/r.git\n\
             base_sha: 0123456789abcdef0123456789abcdef01234567\n\
             profile\tbeta@2\n\
             outcome\tQUEUED\n\
             cost_est_usd\t-\n\
             turns\t-\n\
             queue_wait\t-\n\
             clone\t-\n\
             agent\t-\n\
             tool_calls\t-\n\
             tool_errors\t-\n\
             denials\t-\n\
             stuck_rule\t-\n\
             bundle_sha\tunknown\n\
             claude_version\tunknown\n\
             model\tunknown\n\
             profile_hash\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
             complete\t-\n\
             missing\tno summary\n\
             commands (beta@2):\n\
             \x20\x20-\n"
        );
    }

    #[test]
    fn a_missing_hook_job_keeps_unobserved_figures_as_dashes() {
        let text = render(vec![missing_hook_job()]);
        assert_eq!(
            text,
            "batch: batch1\n\
             repo: https://example.com/r.git\n\
             base_sha: 0123456789abcdef0123456789abcdef01234567\n\
             profile\tgamma@1\n\
             outcome\tFAILED\n\
             cost_est_usd\t-\n\
             turns\t-\n\
             queue_wait\t-\n\
             clone\t-\n\
             agent\t-\n\
             tool_calls\t3\n\
             tool_errors\t-\n\
             denials\t-\n\
             stuck_rule\t-\n\
             bundle_sha\tunknown\n\
             claude_version\tunknown\n\
             model\tunknown\n\
             profile_hash\tcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n\
             complete\tno\n\
             missing\thooks\n\
             commands (gamma@1):\n\
             \x20\x20-\tmake\n"
        );
    }

    #[test]
    fn columns_follow_the_job_order() {
        let text = render(vec![complete_job(), no_summary_job(), missing_hook_job()]);
        assert!(
            text.contains("\nprofile\talpha@1\tbeta@2\tgamma@1\n"),
            "{text}"
        );
        assert!(text.contains("\nmissing\t-\tno summary\thooks\n"), "{text}");
        assert!(text.contains("\ncomplete\tyes\t-\tno\n"), "{text}");
    }

    #[test]
    fn hostile_server_text_and_long_commands_are_cleaned() {
        let (mut job, mut events) = complete_job();
        job.profile.as_mut().expect("profile").name = "a\u{1b}[31mb".into();
        events.push(bash(Some(5), &format!("{}\u{202E}x", "c".repeat(100))));
        let text = render(vec![(job, events)]);
        assert!(text.contains("\nprofile\ta[31mb@1\n"), "{text}");
        let long = format!("  5ms\t{}{ELLIPSIS}\n", "c".repeat(CMD_WIDTH - 1));
        assert!(text.ends_with(&long), "{text}");
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{202E}'),
            "{text:?}"
        );
    }
}
