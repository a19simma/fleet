//! Telemetry output of `fleet status`: the summary block and the `--tools` table.

use std::io::Write;

use fleet_proto::v1::{JobEvent, JobEventKind, JobSummary, ReadJobEventsRequest};

use super::{CliError, Client, ELLIPSIS, Scrub, ident_or_dash, or_dash};

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

fn missing(scrub: &Scrub, names: &[String]) -> String {
    if names.is_empty() {
        "-".into()
    } else {
        names
            .iter()
            .map(|name| scrub.free(name))
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
pub(crate) fn write_summary(
    out: &mut impl Write,
    scrub: &Scrub,
    summary: &JobSummary,
) -> std::io::Result<()> {
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
    writeln!(out, "  clone: {}", duration(summary.clone_ms))?;
    writeln!(out, "  push: {}", duration(summary.push_ms))?;
    writeln!(out, "  pr: {}", duration(summary.pr_ms))?;
    writeln!(out, "  queue_wait: {}", duration(summary.queue_wait_ms))?;
    writeln!(
        out,
        "  stop_reason: {}",
        summary
            .stop_reason
            .as_ref()
            .map_or_else(|| "-".into(), |reason| scrub.free(reason))
    )?;
    if let Some(rule) = &summary.stuck_rule {
        writeln!(
            out,
            "  stuck (shadow): {} at event {}",
            scrub.free(rule),
            or_dash(summary.stuck_at_seq.as_ref())
        )?;
    }
    writeln!(
        out,
        "  bundle_sha: {}",
        ident_or_dash(scrub, summary.bundle_sha.as_ref())
    )?;
    writeln!(
        out,
        "  claude_version: {}",
        ident_or_dash(scrub, summary.claude_version.as_ref())
    )?;
    writeln!(
        out,
        "  model: {}",
        ident_or_dash(scrub, summary.model.as_ref())
    )?;
    if !summary.complete {
        writeln!(
            out,
            "  INCOMPLETE (missing: {})",
            missing(scrub, &summary.missing)
        )?;
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

fn cut_to_width(clean: String) -> String {
    if clean.chars().count() > CMD_WIDTH {
        let mut cut: String = clean.chars().take(CMD_WIDTH - 1).collect();
        cut.push(ELLIPSIS);
        cut
    } else {
        clean
    }
}

fn command(scrub: &Scrub, cmd: Option<&String>) -> String {
    cut_to_width(cmd.map_or_else(|| "-".into(), |cmd| scrub.ident(cmd)))
}

fn valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

fn host_of(url: &str) -> Option<String> {
    let url = url.replace('\\', "/");
    let (scheme, rest) = url.trim().split_once("://")?;
    if !valid_scheme(scheme) {
        return None;
    }
    let (authority, tail) = rest.split_once(['/', '?', '#']).unwrap_or((rest, ""));
    if !authority.contains('@') && tail.contains('@') {
        return None;
    }
    let host = authority.rsplit('@').next()?.trim();
    (!host.is_empty()).then(|| host.to_owned())
}

/// Host and optional port of a fetch URL, without scheme, credentials, path or query.
///
/// Returns `-` when the scheme is invalid, the host is empty, or an `@` after the
/// authority cut hints that a delimiter split credentials. A backslash counts as a
/// delimiter. The host is cut to the command width.
fn url_host(scrub: &Scrub, url: Option<&String>) -> String {
    url.and_then(|url| host_of(&scrub.ident(url)))
        .map_or_else(|| "-".into(), cut_to_width)
}

fn fetch_result(event: &JobEvent) -> String {
    event
        .exit_code
        .map_or_else(|| "-".into(), |status| format!("status {status}"))
}

fn write_row(out: &mut impl Write, scrub: &Scrub, event: &JobEvent) -> std::io::Result<()> {
    if event.kind() == JobEventKind::Fetch {
        return writeln!(
            out,
            "{}\t{}\tfetch\t{}\t{}\t{}\t{}",
            event.seq,
            clock(event.ts_ms),
            fetch_result(event),
            duration(event.dur_ms),
            or_dash(event.out_bytes.as_ref()),
            url_host(scrub, event.cmd.as_ref()),
        );
    }
    writeln!(
        out,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        event.seq,
        clock(event.ts_ms),
        event
            .tool
            .as_ref()
            .map_or_else(|| "-".into(), |tool| scrub.free(tool)),
        result(event),
        duration(event.dur_ms),
        or_dash(event.out_bytes.as_ref()),
        command(scrub, event.cmd.as_ref()),
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
    scrub: &Scrub,
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
            .filter(|event| matches!(event.kind(), JobEventKind::Tool | JobEventKind::Fetch))
        {
            write_row(out, scrub, event)?;
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

#[cfg(test)]
mod tests {
    use fleet_proto::v1::JobEvent;

    use super::*;

    const TOKEN: &str = "client-token-0123456789";

    fn event(kind: JobEventKind, tool: &str, cmd: &str) -> JobEvent {
        JobEvent {
            kind: kind as i32,
            tool: Some(tool.into()),
            cmd: Some(cmd.into()),
            ..JobEvent::default()
        }
    }

    fn row(event: &JobEvent) -> String {
        let mut out = Vec::new();
        write_row(&mut out, &Scrub::new(Some(TOKEN)), event).expect("write to a Vec");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn tool_name_and_command_are_scrubbed_of_the_token() {
        let text = row(&event(
            JobEventKind::Tool,
            &format!("t{TOKEN}"),
            "echo cli\u{200B}ent-token-\u{202E}0123456789",
        ));
        assert!(!text.contains("client-token"), "{text:?}");
        assert_eq!(text.matches("[REDACTED]").count(), 2, "{text:?}");
    }

    #[test]
    fn fetch_url_host_is_scrubbed_of_the_token() {
        let text = row(&event(
            JobEventKind::Fetch,
            "WebFetch",
            &format!("https://{TOKEN}.example.com/x"),
        ));
        assert!(!text.contains("client-token"), "{text:?}");
        assert!(text.contains("[REDACTED].example.com"), "{text:?}");
    }

    #[test]
    fn command_cut_at_width_does_not_leak_a_token_prefix() {
        let cmd = format!("{}{TOKEN}", "x".repeat(55));
        let shown = command(&Scrub::new(Some(TOKEN)), Some(&cmd));
        assert!(!shown.contains("cli"), "{shown}");
        assert_eq!(shown.chars().count(), CMD_WIDTH);
        assert!(shown.ends_with(ELLIPSIS), "{shown}");
    }

    #[test]
    fn fetch_host_cut_at_width_does_not_leak_a_token_prefix() {
        let url = format!("https://{}{TOKEN}.example.com/x", "x".repeat(55));
        let shown = url_host(&Scrub::new(Some(TOKEN)), Some(&url));
        assert!(!shown.contains("cli"), "{shown}");
        assert_eq!(shown.chars().count(), CMD_WIDTH);
    }
}
