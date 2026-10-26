//! Telemetry output of `fleet status`: the summary block and the `--tools` table.

use std::io::Write;

use fleet_proto::v1::{JobEvent, JobEventKind, JobSummary, ReadJobEventsRequest};

use super::{CliError, Client, ELLIPSIS, or_dash, sanitize, sanitize_free};

/// Events asked for per page. The server cuts a larger request to its own maximum.
const EVENTS_PAGE: u32 = 1000;
/// Longest command shown in the table, in characters, ellipsis included.
const CMD_WIDTH: usize = 60;
const SECONDS_PER_DAY: u64 = 86_400;

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

fn clock(ts_ms: u64) -> String {
    let secs = ts_ms / 1000 % SECONDS_PER_DAY;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn cost(usd: Option<f64>) -> String {
    usd.map_or_else(|| "-".into(), |usd| format!("{usd:.4}"))
}

fn missing(names: &[String]) -> String {
    if names.is_empty() {
        "-".into()
    } else {
        names
            .iter()
            .map(|name| sanitize_free(name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Writes the telemetry block of a job summary.
///
/// A figure the job did not observe prints as `-`, never as 0. An incomplete summary ends
/// with an `INCOMPLETE (missing: ...)` line.
///
/// # Errors
/// Returns the output error.
pub(crate) fn write_summary(out: &mut impl Write, summary: &JobSummary) -> std::io::Result<()> {
    writeln!(out, "telemetry:")?;
    writeln!(out, "  turns: {}", or_dash(summary.turns.as_ref()))?;
    writeln!(out, "  duration: {}", duration(summary.duration_ms))?;
    writeln!(out, "  api_duration: {}", duration(summary.duration_api_ms))?;
    writeln!(out, "  cost_est_usd: {}", cost(summary.cost_est_usd))?;
    writeln!(out, "  tokens_in: {}", or_dash(summary.tokens_in.as_ref()))?;
    writeln!(
        out,
        "  tokens_out: {}",
        or_dash(summary.tokens_out.as_ref())
    )?;
    writeln!(
        out,
        "  tokens_cache_read: {}",
        or_dash(summary.tokens_cache_read.as_ref())
    )?;
    writeln!(
        out,
        "  tokens_cache_write: {}",
        or_dash(summary.tokens_cache_write.as_ref())
    )?;
    writeln!(
        out,
        "  tool_calls: {}",
        or_dash(summary.tool_calls.as_ref())
    )?;
    writeln!(
        out,
        "  tool_errors: {}",
        or_dash(summary.tool_errors.as_ref())
    )?;
    writeln!(
        out,
        "  bash_calls: {}",
        or_dash(summary.bash_calls.as_ref())
    )?;
    writeln!(
        out,
        "  bash_nonzero: {}",
        or_dash(summary.bash_nonzero.as_ref())
    )?;
    writeln!(out, "  denials: {}", or_dash(summary.denials.as_ref()))?;
    writeln!(
        out,
        "  api_retries: {}",
        or_dash(summary.api_retries.as_ref())
    )?;
    writeln!(out, "  first_edit: {}", duration(summary.first_edit_ms))?;
    writeln!(
        out,
        "  stop_reason: {}",
        summary
            .stop_reason
            .as_ref()
            .map_or_else(|| "-".into(), |reason| sanitize_free(reason))
    )?;
    if let Some(rule) = &summary.stuck_rule {
        writeln!(
            out,
            "  stuck (shadow): {} at event {}",
            sanitize_free(rule),
            or_dash(summary.stuck_at_seq.as_ref())
        )?;
    }
    if !summary.complete {
        writeln!(out, "  INCOMPLETE (missing: {})", missing(&summary.missing))?;
    }
    Ok(())
}

fn result(event: &JobEvent) -> String {
    match (event.exit_code, event.ok) {
        (Some(code), _) => format!("exit {code}"),
        (None, Some(true)) => "ok".into(),
        (None, Some(false)) => "err".into(),
        (None, None) => "-".into(),
    }
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

fn write_row(out: &mut impl Write, event: &JobEvent) -> std::io::Result<()> {
    writeln!(
        out,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        event.seq,
        clock(event.ts_ms),
        event
            .tool
            .as_ref()
            .map_or_else(|| "-".into(), |tool| sanitize_free(tool)),
        result(event),
        duration(event.dur_ms),
        or_dash(event.out_bytes.as_ref()),
        command(event.cmd.as_ref()),
    )
}

/// Pages through the events of job `id` and writes a table of its tool calls.
///
/// The cursor moves to the `seq` of the last event of each page, and the walk ends on an
/// empty page or when a page does not advance the cursor.
///
/// # Errors
/// Returns [`CliError`] on a server error status or an output failure.
pub(crate) async fn write_tools(
    client: &mut Client,
    id: &str,
    out: &mut impl Write,
) -> Result<(), CliError> {
    writeln!(out, "seq\ttime\ttool\tresult\tdur\tbytes\tcmd")?;
    let mut after: Option<u32> = None;
    let mut rows = 0_usize;
    loop {
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
        for event in reply
            .events
            .iter()
            .filter(|event| event.kind() == JobEventKind::Tool)
        {
            write_row(out, event)?;
            rows += 1;
        }
        if after.is_some_and(|cursor| last <= cursor) {
            break;
        }
        after = Some(last);
    }
    if rows == 0 {
        writeln!(out, "(no tool events)")?;
    }
    Ok(())
}
