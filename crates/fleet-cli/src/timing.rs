//! The `fleet timing` command.

use std::fmt::Write as _;
use std::future::Future;
use std::io::Write;
use std::time::Duration;

use fleet_core::timing::{Summary, TimingView};
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

const CUT_MARKER: &str = "-- log output cut --";
const DEADLINE_MARKER: &str = "-- follow stopped: time limit --";

/// Writes the five-part breakdown of `job` from `view`.
///
/// Every time is milliseconds on the job clock, where the job window is `0` to the total.
/// The table rows are `label`, milliseconds and the share of the total with one decimal; a
/// zero total shows `0.0%`. With `json` the output is one object holding `unit`, `job`,
/// `total_ms` and the parts with their `permille`. The job id is echoed through [`sanitize`].
///
/// # Errors
/// Returns [`CliError::Io`] when the output fails.
pub fn write_breakdown(
    out: &mut impl Write,
    job: &str,
    view: &TimingView,
    json: bool,
) -> Result<(), CliError> {
    let job = sanitize(job);
    let labels = fleet_core::timing::FIELDS;
    if json {
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
        writeln!(
            out,
            "{{\"unit\":\"ms\",\"job\":{},\"total_ms\":{},\"parts\":[{parts}]}}",
            json_text(&job),
            view.total_ms,
        )?;
        return Ok(());
    }
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
    Ok(())
}

/// Fetches the timing of job `job` and writes its breakdown with [`write_breakdown`].
///
/// # Errors
/// Returns [`CliError::Rpc`] on a server error, including the identical not-found answer for a
/// job that is missing or not yours, [`CliError::NoTimingReport`] when the job has no stored
/// report, and [`CliError::Io`] on an output failure.
pub(crate) async fn show(
    client: &mut Client,
    job: &str,
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
    let view = TimingView::new(
        &Summary {
            api_wait_ms: summary.api_wait_ms,
            tool_ms: summary.tool_ms,
            shell_ms: summary.shell_ms,
            idle_ms: summary.idle_ms,
            overhead_ms: summary.overhead_ms,
        },
        &[],
    );
    write_breakdown(out, job, &view, json)
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

/// Writes the command list: one row per command with id, status, exit code, duration, kind
/// and the command line, or one JSON object per line.
///
/// # Errors
/// Returns [`CliError::Io`] when the output fails.
pub fn write_commands(
    out: &mut impl Write,
    commands: &[ShellCommand],
    json: bool,
) -> Result<(), CliError> {
    for command in commands {
        let status = command_status(command);
        let id = sanitize(&command.id);
        let line = sanitize_free(&command.command);
        let exit = command.exit_code.map(|c| c.to_string());
        if json {
            let exit = exit.unwrap_or_else(|| "null".to_owned());
            writeln!(
                out,
                "{{\"id\":{},\"status\":\"{status}\",\"exit_code\":{exit},\"duration_ms\":{},\"background\":{},\"command\":{}}}",
                json_text(&id),
                command.duration_ms,
                command.background,
                json_text(&line),
            )?;
        } else {
            writeln!(
                out,
                "{id}\t{status}\t{}\t{}ms\t{}\t{line}",
                exit.as_deref().unwrap_or("-"),
                command.duration_ms,
                if command.background { "bg" } else { "fg" },
            )?;
        }
    }
    Ok(())
}

/// Fetches the shell commands of job `job` and writes them with [`write_commands`].
///
/// # Errors
/// Returns [`CliError::Rpc`] on a server error, including the identical not-found answer for
/// a job that is missing or not yours, and [`CliError::Io`] on an output failure.
pub(crate) async fn list_commands(
    client: &mut Client,
    job: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .get_job_timing(GetJobTimingRequest {
            job_id: job.to_owned(),
        })
        .await?
        .into_inner();
    write_commands(out, &reply.shell_commands, json)
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
