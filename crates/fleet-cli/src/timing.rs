//! The `fleet timing` command.

use std::fmt::Write as _;
use std::future::Future;
use std::io::Write;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_core::timing::{CommandInput, CommandRow, Summary, TimingView};
use fleet_proto::v1::{
    GetJobTimingRequest, ShellCommand, ShellStatus, StreamShellLogChunk, StreamShellLogRequest,
};
use fleet_proto::{
    MAX_SHELL_LOG_CHUNK_BYTES, MAX_SHELL_LOG_CHUNKS, shell_status_name,
    validate_shell_log_command_id, validate_shell_log_seq,
};
use tonic::{Status, Streaming};

use super::{CliError, Client, is_hostile, sanitize, sanitize_free};

/// Most bytes of one chunk this command prints. A longer chunk is cut here.
pub const MAX_PRINT_CHUNK_BYTES: usize = MAX_SHELL_LOG_CHUNK_BYTES;

/// Most log bytes one `--follow` prints before it stops with a marker.
pub const MAX_PRINT_TOTAL_BYTES: usize = MAX_SHELL_LOG_CHUNK_BYTES * MAX_SHELL_LOG_CHUNKS;

/// Most stream messages one `--follow` reads, status-only messages included.
pub const MAX_STREAM_MESSAGES: usize = MAX_SHELL_LOG_CHUNKS * 4;

/// Longest a `--follow` waits for each of two steps: opening the stream, and then printing it.
/// The server cap of 600 s plus a margin.
pub const FOLLOW_DEADLINE: Duration = Duration::from_secs(630);

/// Most characters of one command log this command prints. A longer log is cut here.
pub const MAX_LOG_CHARS: usize = 512;

const COMMANDS_KEY: &str = "commands";
const LOG_CUT_MARKER: &str = "-- log cut --";
const CUT_MARKER: &str = "-- log output cut --";
const DEADLINE_MARKER: &str = "-- follow stopped: time limit --";

/// Fetches the timing of job `job` and writes its report with [`write_report`], without the
/// command list in the plain form.
///
/// # Errors
/// Returns [`CliError::Rpc`] on a server error, including the identical not-found answer for a
/// job that is missing or not yours, [`CliError::NoTimingReport`] when the job has no stored
/// report, and [`CliError::Io`] on an output failure.
pub(crate) async fn show(
    client: &mut Client,
    redactor: &Redactor,
    job: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    fetch_report(client, redactor, job, false, json, out).await
}

/// Like [`show`], and the plain form also lists every command with its duration and log.
///
/// # Errors
/// The errors of [`show`].
pub(crate) async fn list_commands(
    client: &mut Client,
    redactor: &Redactor,
    job: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    fetch_report(client, redactor, job, true, json, out).await
}

async fn fetch_report(
    client: &mut Client,
    redactor: &Redactor,
    job: &str,
    commands: bool,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .get_job_timing(GetJobTimingRequest {
            job_id: job.to_owned(),
        })
        .await?
        .into_inner();
    let summary = reply.summary.ok_or(CliError::NoTimingReport)?;
    write_report(
        out,
        job,
        &Summary {
            api_wait_ms: summary.api_wait_ms,
            tool_ms: summary.tool_ms,
            shell_ms: summary.shell_ms,
            idle_ms: summary.idle_ms,
            overhead_ms: summary.overhead_ms,
        },
        &reply.shell_commands,
        redactor,
        commands,
        json,
    )
}

/// A source of live log chunks: the gRPC stream, or a script in a test.
pub trait ChunkSource {
    /// The next chunk, or `None` when the stream ended.
    fn next_chunk(
        &mut self,
    ) -> impl Future<Output = Result<Option<StreamShellLogChunk>, Status>> + Send;
}

impl ChunkSource for Streaming<StreamShellLogChunk> {
    fn next_chunk(
        &mut self,
    ) -> impl Future<Output = Result<Option<StreamShellLogChunk>, Status>> + Send {
        self.message()
    }
}

/// The life stage of a listed command, from the fields the server stores.
fn command_status(command: &ShellCommand) -> &'static str {
    match (command.ended_ms, command.exit_code) {
        (None, _) => "running",
        (Some(_), Some(0)) => "done",
        (Some(_), _) => "failed",
    }
}

fn json_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Detail {
    id: String,
    status: &'static str,
    background: bool,
    log: String,
    log_cut: bool,
    ended_by: Option<String>,
}

fn strip_keeping_lines(text: &str) -> String {
    text.chars()
        .filter(|c| matches!(c, '\n' | '\t') || !is_hostile(*c))
        .collect()
}

fn scrub(redactor: &Redactor, text: &str) -> String {
    let stripped = strip_keeping_lines(text);
    strip_keeping_lines(&redactor.redact_str(&stripped))
}

fn clean_log(redactor: &Redactor, log: &str, upstream_cut: bool) -> (String, bool) {
    let mut kept: String = scrub(redactor, log)
        .chars()
        .take(MAX_LOG_CHARS + 1)
        .collect();
    let over = kept.chars().count() > MAX_LOG_CHARS;
    if over {
        kept = kept.chars().take(MAX_LOG_CHARS).collect();
    }
    (kept, over || upstream_cut)
}

fn detail(command: &ShellCommand, redactor: &Redactor) -> Detail {
    let (log, log_cut) = clean_log(redactor, &command.log, command.log_truncated);
    Detail {
        id: sanitize(&command.id),
        status: command_status(command),
        background: command.background,
        log,
        log_cut,
        ended_by: command
            .ended_by
            .as_deref()
            .map(|by| sanitize_free(&scrub(redactor, by))),
    }
}

fn json_report(job: &str, view: &TimingView, rows: &[(&CommandRow, &Detail)]) -> String {
    let mut parts = String::new();
    for row in &view.rows {
        if !parts.is_empty() {
            parts.push(',');
        }
        let _ = write!(
            parts,
            "{{\"key\":{},\"ms\":{},\"permille\":{}}}",
            json_text(row.key),
            row.ms,
            row.permille,
        );
    }
    let mut commands = String::new();
    for (row, d) in rows {
        if !commands.is_empty() {
            commands.push(',');
        }
        let exit = row
            .exit
            .map_or_else(|| "null".to_owned(), |c| c.to_string());
        let ended_by = d
            .ended_by
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_text);
        let _ = write!(
            commands,
            "{{\"id\":{},\"status\":\"{}\",\"background\":{},\"command\":{},\"start_ms\":{},\"duration_ms\":{},\"exit_code\":{exit},\"truncated\":{},\"log\":{},\"log_truncated\":{},\"ended_by\":{ended_by}}}",
            json_text(&d.id),
            d.status,
            d.background,
            json_text(&row.command),
            row.start_ms,
            row.duration_ms,
            row.truncated,
            json_text(&d.log),
            d.log_cut,
        );
    }
    format!(
        "{{\"unit\":\"ms\",\"job\":{},\"total_ms\":{},\"parts\":[{parts}],\"commands\":[{commands}],\"commands_omitted\":{}}}",
        json_text(job),
        view.total_ms,
        view.commands_omitted,
    )
}

fn write_commands(
    out: &mut impl Write,
    view: &TimingView,
    rows: &[(&CommandRow, &Detail)],
) -> Result<(), CliError> {
    let label = fleet_core::timing::FIELDS
        .iter()
        .find(|f| f.key == COMMANDS_KEY)
        .map_or(COMMANDS_KEY, |f| f.label);
    writeln!(
        out,
        "{label}: {} shown, {} omitted",
        rows.len(),
        view.commands_omitted
    )?;
    for (row, d) in rows {
        write!(
            out,
            "{}\t{}\t{}\t{}ms\t{}\t{}",
            d.id,
            d.status,
            row.exit.map_or_else(|| "-".to_owned(), |c| c.to_string()),
            row.duration_ms,
            if d.background { "bg" } else { "fg" },
            row.command,
        )?;
        if row.truncated {
            write!(out, "\t(command cut)")?;
        }
        if let Some(by) = &d.ended_by {
            write!(out, "\tended_by={by}")?;
        }
        writeln!(out)?;
        for line in d.log.lines() {
            writeln!(out, "    | {line}")?;
        }
        if d.log_cut {
            writeln!(out, "    {LOG_CUT_MARKER}")?;
        }
    }
    Ok(())
}

/// Writes the timing report of `job`.
///
/// Every time is milliseconds on the job clock, where the job window is `0` to the total.
/// The table rows are `label`, milliseconds and the share of the total with one decimal; a
/// zero total shows `0.0%`. With `with_commands` the plain form adds one row per command and
/// its log, indented. With `json` the output is one object: `unit`, `job`, `total_ms`, the
/// `parts` with their `permille`, `commands` and `commands_omitted`, always whole. The command
/// text goes through the shared [`TimingView`] display rules, at most
/// [`fleet_core::timing::MAX_COMMAND_ROWS`] commands show. Every text from the server is
/// redacted with `redactor` first, then stripped of control and bidirectional characters, then
/// cut: a log to [`MAX_LOG_CHARS`] characters, with a marker, an `ended_by` to 200.
///
/// # Errors
/// Returns [`CliError::Io`] when the output fails.
pub fn write_report(
    out: &mut impl Write,
    job: &str,
    summary: &Summary,
    commands: &[ShellCommand],
    redactor: &Redactor,
    with_commands: bool,
    json: bool,
) -> Result<(), CliError> {
    let job = sanitize(job);
    let inputs: Vec<CommandInput> = commands
        .iter()
        .map(|c| CommandInput {
            command: scrub(redactor, &c.command),
            duration_ms: c.duration_ms,
            start_ms: c.started_ms,
            exit: c.exit_code,
            truncated: false,
        })
        .collect();
    let view = TimingView::new(summary, &inputs);
    let details: Vec<Detail> = commands
        .iter()
        .take(view.commands.len())
        .map(|c| detail(c, redactor))
        .collect();
    let rows: Vec<(&CommandRow, &Detail)> = view.commands.iter().zip(&details).collect();
    if json {
        writeln!(out, "{}", json_report(&job, &view, &rows))?;
        return Ok(());
    }
    let labels = fleet_core::timing::FIELDS;
    writeln!(out, "job: {job}")?;
    writeln!(out, "unit: ms, job-relative (0 is the claim)")?;
    for row in &view.rows {
        let label = labels
            .iter()
            .find(|f| f.key == row.key)
            .map_or(row.key, |f| f.label);
        writeln!(out, "{label}\t{}ms\t{}", row.ms, row.percent_label())?;
    }
    let permille = view
        .rows
        .iter()
        .fold(0u16, |sum, row| sum.saturating_add(row.permille));
    writeln!(
        out,
        "Total\t{}ms\t{}.{}%",
        view.total_ms,
        permille / 10,
        permille % 10
    )?;
    if with_commands {
        write_commands(out, &view, &rows)?;
    }
    Ok(())
}

fn utf8_boundary(buf: &[u8]) -> usize {
    let len = buf.len();
    for back in 1..=3.min(len) {
        let at = len - back;
        let need = match buf.get(at) {
            Some(0xC0..=0xDF) => 2,
            Some(0xE0..=0xEF) => 3,
            Some(0xF0..=0xF7) => 4,
            Some(0x80..=0xBF) => continue,
            _ => return len,
        };
        return if need > back { at } else { len };
    }
    len
}

fn clean_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || !is_hostile(*c))
        .collect()
}

async fn print_chunks<S: ChunkSource>(
    source: &mut S,
    command_id: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut pending: Vec<u8> = Vec::new();
    let mut next_seq: u32 = 0;
    let mut total = 0usize;
    let mut messages = 0usize;
    let mut last_newline = true;
    let mut outcome = Ok(());
    let mut cut = false;
    let mut ended = false;
    loop {
        let Some(chunk) = source.next_chunk().await? else {
            break;
        };
        messages += 1;
        let mine = chunk.command_id == command_id;
        let terminal = mine
            && matches!(
                ShellStatus::try_from(chunk.status),
                Ok(ShellStatus::Done | ShellStatus::Failed)
            );
        if mine {
            if !validate_shell_log_seq(chunk.seq) {
                return Err(CliError::Rpc(Status::invalid_argument(
                    "log stream sent an invalid chunk number",
                )));
            }
            if ShellStatus::try_from(chunk.status) == Ok(ShellStatus::Failed) {
                outcome = Err(CliError::JobEnded("failed"));
            }
            ended |= terminal;
        }
        if messages > MAX_STREAM_MESSAGES {
            if !cut {
                writeln!(out, "{CUT_MARKER}")?;
            }
            break;
        }
        if !mine {
            continue;
        }
        let fresh = chunk.seq >= next_seq;
        if !cut && fresh && !chunk.bytes.is_empty() {
            next_seq = chunk.seq.saturating_add(1);
            let room = MAX_PRINT_TOTAL_BYTES.saturating_sub(total);
            let take = chunk.bytes.len().min(MAX_PRINT_CHUNK_BYTES).min(room);
            total += take;
            pending.extend_from_slice(chunk.bytes.get(..take).unwrap_or_default());
            let whole = utf8_boundary(&pending);
            let ready: Vec<u8> = pending.drain(..whole).collect();
            let text = clean_text(&ready);
            if json {
                let status = ShellStatus::try_from(chunk.status)
                    .ok()
                    .and_then(shell_status_name)
                    .unwrap_or("unknown");
                writeln!(
                    out,
                    "{{\"command_id\":{},\"seq\":{},\"status\":\"{status}\",\"text\":{}}}",
                    json_text(command_id),
                    chunk.seq,
                    json_text(&text),
                )?;
            } else if !text.is_empty() {
                out.write_all(text.as_bytes())?;
                last_newline = text.ends_with('\n');
            }
            if take < chunk.bytes.len() || total >= MAX_PRINT_TOTAL_BYTES {
                writeln!(out, "{CUT_MARKER}")?;
                cut = true;
            }
        }
        if terminal {
            break;
        }
    }
    if !pending.is_empty() {
        let text = clean_text(&pending);
        if !json {
            out.write_all(text.as_bytes())?;
            last_newline = text.ends_with('\n');
        }
    }
    if !json && !last_newline {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    if !ended && outcome.is_ok() {
        return Err(CliError::JobEnded("status unknown"));
    }
    outcome
}

/// Prints the log chunks of a command from `source` until a terminal status, the end of the
/// stream, a print cap or [`FOLLOW_DEADLINE`].
///
/// Log text is untrusted terminal output: control and bidirectional characters are dropped
/// and only newline and tab survive. A chunk past [`MAX_PRINT_CHUNK_BYTES`] is cut, the total
/// stops at [`MAX_PRINT_TOTAL_BYTES`]; after a cut the stream is still read, without printing,
/// up to [`MAX_STREAM_MESSAGES`] for a terminal status. A repeated or lower `seq` is skipped. With `json`
/// each chunk is one JSON object per line.
///
/// # Errors
/// Returns [`CliError::Rpc`] when the stream fails, [`CliError::JobEnded`] when the command
/// ended `failed` or the follow hit [`FOLLOW_DEADLINE`], and [`CliError::JobEnded`] with
/// `status unknown` when the stream ended, or a print or message cap cut it, before a terminal
/// status for this command, and [`CliError::Io`] on an output failure.
pub async fn print_log<S: ChunkSource>(
    source: &mut S,
    command_id: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    if let Ok(result) =
        tokio::time::timeout(FOLLOW_DEADLINE, print_chunks(source, command_id, json, out)).await
    {
        result
    } else {
        writeln!(out, "{DEADLINE_MARKER}")?;
        Err(CliError::JobEnded("timed out"))
    }
}

/// Checks a `--follow` command id against the wire contract.
///
/// # Errors
/// Returns [`CliError::Usage`] with a fixed message for an id the contract refuses.
pub(crate) fn check_command_id(command_id: &str) -> Result<(), CliError> {
    if validate_shell_log_command_id(command_id) {
        Ok(())
    } else {
        Err(CliError::Usage(
            "command id must be 1 to 128 characters of letters, digits and _ . : -".to_owned(),
        ))
    }
}

/// Opens the live log of command `command_id` of job `job` and prints it with [`print_log`].
///
/// # Errors
/// Returns [`CliError::Usage`] for an id the wire contract refuses, and the errors of
/// [`print_log`].
pub(crate) async fn follow(
    client: &mut Client,
    job: &str,
    command_id: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    check_command_id(command_id)?;
    let opened = tokio::time::timeout(
        FOLLOW_DEADLINE,
        client.stream_shell_log(StreamShellLogRequest {
            job_id: job.to_owned(),
            command_id: command_id.to_owned(),
            from_seq: 0,
        }),
    )
    .await;
    let Ok(opened) = opened else {
        writeln!(out, "{DEADLINE_MARKER}")?;
        return Err(CliError::JobEnded("timed out"));
    };
    let mut stream = opened?.into_inner();
    print_log(&mut stream, command_id, json, out).await
}
