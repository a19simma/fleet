//! `fleet stats`: the `--since` parser and the statistics table.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use fleet_proto::v1::{GetStatsReply, GetStatsRequest, Quantiles, StatsGroup, StatsGroupBy, Total};

use super::{CliError, Client, StatsBy, sanitize};

const SINCE_USAGE: &str =
    "invalid --since: use a duration such as 45s, 90m, 24h or 7d, or a unix time in seconds";
const HEADER: &str = "group\tjobs\tok%\tdur_p50\tdur_p95\tcost_usd\ttool_err%\tdenials\tn";
const SECONDS_PER_MINUTE: f64 = 60.0;

/// Seconds since the unix epoch, 0 when the clock is before it.
pub(crate) fn now_seconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

/// Turns a `--since` value into a unix time in seconds.
///
/// A number followed by `s`, `m`, `h` or `d` is that long before `now`. A bare number is
/// a unix time. A zero duration, a sign, a fraction, an overflow and a duration reaching
/// before the epoch are usage errors. The message never repeats the input.
///
/// # Errors
/// Returns [`CliError::Usage`] for any value outside that grammar.
pub(crate) fn parse_since(text: &str, now: i64) -> Result<i64, CliError> {
    let usage = || CliError::Usage(SINCE_USAGE.into());
    let (digits, unit) = match text.char_indices().last() {
        Some((at, c @ ('s' | 'm' | 'h' | 'd'))) => (&text[..at], Some(c)),
        _ => (text, None),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(usage());
    }
    let value: i64 = digits.parse().map_err(|_| usage())?;
    let Some(unit) = unit else {
        return Ok(value);
    };
    let per_unit: i64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        _ => 86_400,
    };
    let span = value.checked_mul(per_unit).ok_or_else(usage)?;
    if span == 0 {
        return Err(usage());
    }
    now.checked_sub(span)
        .filter(|since| *since >= 0)
        .ok_or_else(usage)
}

fn by_group(by: Option<StatsBy>) -> StatsGroupBy {
    match by {
        None => StatsGroupBy::None,
        Some(StatsBy::Repo) => StatsGroupBy::Repo,
        Some(StatsBy::Box) => StatsGroupBy::Box,
        Some(StatsBy::State) => StatsGroupBy::State,
        Some(StatsBy::Day) => StatsGroupBy::Day,
    }
}

fn permille(part: u64, whole: u64) -> Option<u64> {
    (whole > 0).then(|| part.saturating_mul(1000).saturating_add(whole / 2) / whole)
}

fn percent(permille: u64) -> String {
    format!("{}.{}%", permille / 10, permille % 10)
}

fn millis(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{ms:.0}ms")
    } else if ms < 59_950.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        let secs = (ms / 1000.0).round();
        format!(
            "{:.0}m{:02.0}s",
            (secs / SECONDS_PER_MINUTE).floor(),
            secs % SECONDS_PER_MINUTE
        )
    }
}

fn median_and_tail(quantiles: Option<&Quantiles>) -> (String, String) {
    quantiles.map_or_else(
        || ("-".into(), "-".into()),
        |q| (millis(q.p50), millis(q.p95)),
    )
}

fn success(group: &StatsGroup) -> String {
    let finished = group.succeeded + group.failed + group.timed_out + group.cancelled + group.lost;
    permille(group.succeeded, finished).map_or_else(
        || "- (0/0)".into(),
        |rate| format!("{} ({}/{finished})", percent(rate), group.succeeded),
    )
}

fn tool_errors(calls: Option<&Total>, errors: Option<&Total>) -> (String, String) {
    let (Some(calls), Some(errors)) = (calls, errors) else {
        return ("-".into(), "-".into());
    };
    let n = calls.n.min(errors.n).to_string();
    let rate = permille(errors.sum, calls.sum).map_or_else(|| "-".into(), percent);
    (rate, n)
}

fn count(total: Option<&Total>) -> String {
    total.map_or_else(|| "-".into(), |t| t.sum.to_string())
}

fn n_of(n: Option<u64>) -> String {
    n.map_or_else(|| "-".into(), |n| n.to_string())
}

fn write_row(out: &mut impl Write, group: &StatsGroup) -> std::io::Result<()> {
    let key = sanitize(&group.key);
    let key = if key.is_empty() { "all" } else { &key };
    let (p50, p95) = median_and_tail(group.duration_ms.as_ref());
    let cost = group
        .cost_est_usd
        .as_ref()
        .map_or_else(|| "-".into(), |c| format!("{:.4}", c.sum));
    let (tool_rate, tools_n) = tool_errors(group.tool_calls.as_ref(), group.tool_errors.as_ref());
    writeln!(
        out,
        "{key}\t{}\t{}\t{p50}\t{p95}\t{cost}\t{tool_rate}\t{}\tdur={} cost={} tools={tools_n} den={}",
        group.jobs,
        success(group),
        count(group.denials.as_ref()),
        n_of(group.duration_ms.as_ref().map(|q| q.n)),
        n_of(group.cost_est_usd.as_ref().map(|c| c.n)),
        n_of(group.denials.as_ref().map(|t| t.n)),
    )
}

/// Writes the window line, the group table and any truncation or clamp notice.
///
/// A figure no job observed prints as `-`. The `ok%` cell shows its finished-job
/// denominator. The `n` cell lists how many jobs contributed to each figure.
///
/// # Errors
/// Returns the output error.
pub(crate) fn write_stats(out: &mut impl Write, reply: &GetStatsReply) -> std::io::Result<()> {
    writeln!(
        out,
        "window: {} to {} (unix seconds)",
        reply.since, reply.until
    )?;
    if reply.clamped {
        writeln!(out, "-- window clamped to 90 days --")?;
    }
    if reply.groups.is_empty() {
        writeln!(out, "(no jobs in window)")?;
    } else {
        writeln!(out, "{HEADER}")?;
        for group in &reply.groups {
            write_row(out, group)?;
        }
    }
    if reply.truncated {
        writeln!(
            out,
            "-- truncated: only the first groups are shown; narrow with --repo or --box --"
        )?;
    }
    Ok(())
}

/// Asks the server for statistics and writes the table.
///
/// # Errors
/// Returns [`CliError`] on a server error status or an output failure.
pub(crate) async fn stats(
    client: &mut Client,
    since: i64,
    repo: Option<String>,
    box_name: Option<String>,
    by: Option<StatsBy>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .get_stats(GetStatsRequest {
            since: Some(since),
            until: None,
            repo,
            r#box: box_name,
            group_by: by_group(by).into(),
        })
        .await?
        .into_inner();
    write_stats(out, &reply)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_reaching_exactly_the_epoch_is_accepted_and_before_it_is_not() {
        assert!(matches!(parse_since("10s", 10), Ok(0)));
        assert!(matches!(parse_since("11s", 10), Err(CliError::Usage(_))));
        assert!(matches!(parse_since("1m", 60), Ok(0)));
        assert!(matches!(parse_since("1h", 3_599), Err(CliError::Usage(_))));
    }

    #[test]
    fn a_bare_number_is_taken_as_a_unix_time_whatever_the_clock() {
        assert!(matches!(parse_since("0", 5), Ok(0)));
        assert!(matches!(parse_since("1700000000", 5), Ok(1_700_000_000)));
    }
}
