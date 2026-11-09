//! The job timing page and its live log stream.
//!
//! `/jobs/{id}/timing` shows the timing breakdown of a job as a stacked bar of its five parts
//! and a table of those parts with the total and the command count. A second table lists each
//! pueue command the job reported with its start, end, duration, exit code, background flag and
//! end reason, and a log block under each row. The breakdown
//! comes from [`read_job_timing`] scoped to the session user and is built into a
//! [`TimingView`], the same view the CLI prints. Every duration is job-relative
//! milliseconds. A job without a report shows one plain absent line, never zeros. The bar is
//! an SVG whose segment widths are the view's permille shares, so no inline style is needed
//! under the page CSP.
//! `/jobs/{id}/shell/{command}/log` streams one task's log as server-sent events from the
//! same follow loop `StreamShellLog` uses: replay, then follow, capped at
//! [`STREAM_MAX_WAIT`]. Both routes check the job owner first and answer 404 for a job that
//! is unknown or not the caller's, so the two cases look identical.
//!
//! Log text is untrusted. [`Pane`] decodes chunks as UTF-8 across chunk borders, drops
//! control characters, line and paragraph separators and bidi overrides, cuts each line at
//! [`MAX_LINE_CHARS`] and stops at [`MAX_PANE_BYTES`]. The stream sends the text as a JSON
//! string with `<`, `>` and `&` written as `\u` escapes, and the script sets it with
//! `textContent`, never as markup.

use std::convert::Infallible;

use fleet_core::Redactor;
use fleet_core::text::{Cap, is_hostile, sanitise_lines};
use fleet_core::timing::{CommandInput, FIELDS, Summary, TimingView};
use fleet_proto::v1::{
    GetJobTimingRequest, ShellCommand, StreamShellLogChunk, StreamShellLogRequest,
};
use fleet_proto::{
    shell_status_name, validate_shell_log_command_id, validate_shell_log_seq,
    validate_shell_log_status,
};
use http_body_util::StreamBody;
use hyper::body::{Bytes, Frame};
use sqlx::Row;
use tokio::sync::mpsc;
use tonic::codegen::BoxStream;
use tonic::codegen::tokio_stream::StreamExt;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        Body,
        error::{not_found, see_other, unauthorized},
        header, page, path_param,
        request::headers,
        route,
    },
    view::{View, component, view},
};

use super::jobs::{ConsoleSlot, MAX_RENDER_BYTES};
use super::layout::{Nav, shell};
use super::pages::{auth, current, fail};
use super::passkeys::AuthError;
use crate::store::{Store, StoreError};
use crate::timing::{MAX_LOG_COMMANDS_PER_JOB, StreamLimits, read_job_timing, stream_shell_log};

/// The most characters one log line shows before the rest of it is replaced by a marker.
const MAX_LINE_CHARS: usize = 2048;

/// The most log text one stream sends, in bytes.
const MAX_PANE_BYTES: usize = MAX_RENDER_BYTES;

/// URL path of the embedded log script.
const LOG_SCRIPT_PATH: &str = "/static/tasklog.js";

const COMMAND_PREVIEW_BYTES: usize = 160;
const FRAME_QUEUE: usize = 8;
const CARRY_MAX: usize = 3;

/// The embedded log script.
///
/// It closes the `EventSource` on `error`, `end` and `fail` and never reconnects: the browser
/// would resend the request without a resume position and the replay would duplicate the pane
/// text. The state line shows `disconnected` and the viewer reopens the log by hand.
const LOG_JS: &str = r#"(function () {
  var pane = document.getElementById("task-log");
  var title = document.getElementById("task-log-title");
  var state = document.getElementById("task-log-state");
  if (!pane || !title || !state) { return; }
  var MAX_CHARS = 262144;
  var source = null;
  var text = "";
  function render() {
    if (text.length > MAX_CHARS) { text = text.slice(text.length - MAX_CHARS); }
    pane.textContent = text;
    pane.scrollTop = pane.scrollHeight;
  }
  function stop(label) {
    if (source) { source.close(); source = null; }
    state.textContent = label;
  }
  function parse(event) {
    try { return JSON.parse(event.data); } catch (err) { return null; }
  }
  function open(url, task) {
    if (source) { source.close(); }
    text = "";
    render();
    title.textContent = task;
    state.textContent = "connecting";
    source = new EventSource(url);
    source.addEventListener("chunk", function (event) {
      var data = parse(event);
      if (!data) { return; }
      text += String(data.text);
      state.textContent = String(data.status);
      render();
    });
    source.addEventListener("end", function (event) {
      var data = parse(event);
      stop(data ? "ended: " + String(data.status) : "ended");
    });
    source.addEventListener("fail", function () { stop("stream failed"); });
    source.onerror = function () { stop("disconnected"); };
  }
  document.addEventListener("click", function (event) {
    var target = event.target;
    var button = target && target.closest ? target.closest("[data-log-url]") : null;
    if (!button) { return; }
    open(button.getAttribute("data-log-url"), button.getAttribute("data-task") || "");
  });
})();
"#;

path_param!(job_id);
path_param!(command_id);

const SELECT_TASKS: &str = "\
SELECT c.command_id, (array_agg(c.status ORDER BY c.seq DESC))[1] AS status, \
max(s.command) AS command \
FROM job_shell_log_chunks c \
LEFT JOIN job_shell_commands s ON s.job_id = c.job_id AND s.id = c.command_id \
WHERE c.job_id = $1 GROUP BY c.command_id ORDER BY min(c.created_at), c.command_id LIMIT $2";

struct Task {
    id: String,
    status: String,
    command: String,
    url: String,
}

struct Line {
    key: &'static str,
    label: &'static str,
    value: String,
    share: String,
    swatch: &'static str,
}

struct Segment {
    x: String,
    width: String,
    fill: &'static str,
    title: String,
}

struct Breakdown {
    lines: Vec<Line>,
    segments: Vec<Segment>,
    commands: Vec<CommandLine>,
    omitted: usize,
}

struct CommandLine {
    command: String,
    cut: bool,
    start: String,
    end: String,
    duration: String,
    exit: String,
    background: &'static str,
    ended_by: String,
    log: String,
    log_cut: bool,
}

struct Extra {
    ended_ms: Option<u64>,
    background: bool,
    ended_by: String,
    log: String,
    log_cut: bool,
}

fn plain(text: &str) -> String {
    let mut pane = Pane::new();
    pane.push(text.as_bytes())
}

fn extra(command: &ShellCommand) -> Extra {
    let mut pane = Pane::new();
    let log = pane.push(command.log.as_bytes());
    Extra {
        ended_ms: command.ended_ms,
        background: command.background,
        ended_by: plain(command.ended_by.as_deref().unwrap_or("")),
        log,
        log_cut: command.log_truncated || pane.cut,
    }
}

fn fill_class(key: &str) -> &'static str {
    match key {
        "api_wait" => "fill-info",
        "tool" => "fill-success",
        "shell" => "fill-warning",
        "idle" => "fill-neutral",
        _ => "fill-secondary",
    }
}

fn swatch_class(key: &str) -> &'static str {
    match key {
        "api_wait" => "inline-block size-2 bg-info",
        "tool" => "inline-block size-2 bg-success",
        "shell" => "inline-block size-2 bg-warning",
        "idle" => "inline-block size-2 bg-neutral",
        "overhead" => "inline-block size-2 bg-secondary",
        _ => "inline-block size-2",
    }
}

fn breakdown(summary: &Summary, commands: &[CommandInput], extras: &[Extra]) -> Breakdown {
    let view = TimingView::new(summary, commands);
    let mut lines = Vec::new();
    let mut segments = Vec::new();
    let mut cursor: u16 = 0;
    for field in FIELDS {
        let part = view.rows.iter().find(|row| row.key == field.key);
        let (value, share) = match (part, field.key) {
            (Some(row), _) => (row.duration_label(), row.percent_label()),
            (None, "total") => (view.total_label(), String::new()),
            (None, "commands") => (
                view.commands
                    .len()
                    .saturating_add(view.commands_omitted)
                    .to_string(),
                String::new(),
            ),
            (None, _) => (String::new(), String::new()),
        };
        if let Some(row) = part
            && row.permille > 0
        {
            segments.push(Segment {
                x: cursor.to_string(),
                width: row.permille.to_string(),
                fill: fill_class(field.key),
                title: format!("{} {} {}", field.label, value, share),
            });
            cursor = cursor.saturating_add(row.permille);
        }
        lines.push(Line {
            key: field.key,
            label: field.label,
            value,
            share,
            swatch: swatch_class(field.key),
        });
    }
    Breakdown {
        lines,
        segments,
        commands: view
            .commands
            .iter()
            .zip(extras)
            .map(|(row, more)| CommandLine {
                command: row.command.clone(),
                cut: row.truncated,
                start: fleet_core::timing::human_duration_ms(row.start_ms),
                end: more
                    .ended_ms
                    .map_or_else(|| "-".to_owned(), fleet_core::timing::human_duration_ms),
                duration: fleet_core::timing::human_duration_ms(row.duration_ms),
                exit: row
                    .exit
                    .map_or_else(|| "-".to_owned(), |code| code.to_string()),
                background: if more.background { "yes" } else { "no" },
                ended_by: more.ended_by.clone(),
                log: more.log.clone(),
                log_cut: more.log_cut,
            })
            .collect(),
        omitted: view.commands_omitted,
    }
}

async fn timing_breakdown(store: &Store, user_id: i64, job_id: &str) -> Result<Option<Breakdown>> {
    let request = GetJobTimingRequest {
        job_id: job_id.to_owned(),
    };
    let reply = match read_job_timing(store.pool(), Some(user_id), &request).await {
        Ok(reply) => reply,
        Err(status) if status.code() == tonic::Code::NotFound => return Err(not_found().into()),
        Err(status) => return Err(internal(&status.code())),
    };
    let Some(summary) = reply.summary else {
        return Ok(None);
    };
    let summary = Summary {
        api_wait_ms: summary.api_wait_ms,
        tool_ms: summary.tool_ms,
        shell_ms: summary.shell_ms,
        idle_ms: summary.idle_ms,
        overhead_ms: summary.overhead_ms,
    };
    let inputs: Vec<CommandInput> = reply
        .shell_commands
        .iter()
        .map(|command| CommandInput {
            command: command.command.clone(),
            duration_ms: command.duration_ms,
            start_ms: command.started_ms,
            exit: command.exit_code,
            truncated: false,
        })
        .collect();
    let extras: Vec<Extra> = reply.shell_commands.iter().map(extra).collect();
    Ok(Some(breakdown(&summary, &inputs, &extras)))
}

fn store(cx: &Cx) -> Result<&Store> {
    app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

fn internal(err: &dyn std::fmt::Display) -> topcoat::Error {
    tracing::error!(error = %err, "tasks page read failed");
    fail(AuthError::Internal)
}

fn badge_class(status: &str) -> &'static str {
    match status {
        "running" => "badge badge-sm badge-warning",
        "done" => "badge badge-sm badge-success",
        "failed" => "badge badge-sm badge-error",
        _ => "badge badge-sm badge-ghost",
    }
}

fn log_url(job_id: &str, command_id: &str) -> String {
    format!("/jobs/{job_id}/shell/{command_id}/log")
}

async fn owned(store: &Store, user_id: i64, job_id: &str) -> Result<()> {
    match store.get_job_for(Some(user_id), job_id).await {
        Ok(_) => Ok(()),
        Err(StoreError::NotFound | StoreError::InvalidJob(_)) => Err(not_found().into()),
        Err(err) => Err(internal(&err)),
    }
}

async fn tasks(store: &Store, job_id: &str) -> Result<Vec<Task>> {
    let limit = i64::try_from(MAX_LOG_COMMANDS_PER_JOB).unwrap_or(i64::MAX);
    let rows = sqlx::query(SELECT_TASKS)
        .bind(job_id)
        .bind(limit)
        .fetch_all(store.pool())
        .await
        .map_err(|err| internal(&err))?;
    rows.iter()
        .map(|row| {
            let id: String = row.try_get("command_id").map_err(|err| internal(&err))?;
            let status: String = row.try_get("status").map_err(|err| internal(&err))?;
            let command: Option<String> = row.try_get("command").map_err(|err| internal(&err))?;
            let command = command.unwrap_or_default();
            Ok(Task {
                url: log_url(job_id, &id),
                command: sanitise_lines(
                    &Redactor::default(),
                    &command,
                    Cap::Bytes(COMMAND_PREVIEW_BYTES),
                )
                .text,
                id,
                status,
            })
        })
        .collect()
}

#[component]
async fn timing_panel(timing: Option<Breakdown>) -> Result<impl View> {
    Ok(view! {
                <section id="timing-breakdown" class="mb-3">
                    <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60">"Time breakdown (job-relative ms)"</h2>
                    if let Some(timing) = timing {
                        <svg id="timing-bar" class="mb-2 h-4 w-full border border-base-300" viewBox="0 0 1000 1" preserveAspectRatio="none" role="img" aria-label="Time breakdown">
                            for segment in timing.segments {
                                <rect class=(segment.fill) x=(segment.x.as_str()) y="0" width=(segment.width.as_str()) height="1"><title>(segment.title.as_str())</title></rect>
                            }
                        </svg>
                        <table id="timing-table" class="table table-zebra table-xs max-w-xl">
                            <tbody>
                                for line in timing.lines {
                                    <tr data-field=(line.key)>
                                        <td><span class=(line.swatch)></span> " " (line.label)</td>
                                        <td>(line.value.as_str())</td>
                                        <td>(line.share.as_str())</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                        if !timing.commands.is_empty() {
                            <table id="timing-commands" class="table table-zebra table-xs mt-2">
                                <thead>
                                    <tr>
                                        <th>"Command"</th>
                                        <th>"Start"</th>
                                        <th>"End"</th>
                                        <th>"Duration"</th>
                                        <th>"Exit"</th>
                                        <th>"Background"</th>
                                        <th>"Ended by"</th>
                                    </tr>
                                </thead>
                                for command in timing.commands {
                                    <tbody data-command="">
                                        <tr>
                                            <td class="break-all">
                                                (command.command.as_str())
                                                if command.cut {
                                                    " " <span class="badge badge-xs" data-truncated="command">"truncated"</span>
                                                }
                                            </td>
                                            <td>(command.start.as_str())</td>
                                            <td>(command.end.as_str())</td>
                                            <td>(command.duration.as_str())</td>
                                            <td>(command.exit.as_str())</td>
                                            <td>(command.background)</td>
                                            <td class="break-all">(command.ended_by.as_str())</td>
                                        </tr>
                                        <tr>
                                            <td colspan="7">
                                                <pre class="command-log max-h-48 overflow-auto whitespace-pre-wrap border border-base-300 bg-base-300 p-2 text-xs">(command.log.as_str())</pre>
                                                if command.log_cut {
                                                    <p class="text-xs text-base-content/60" data-truncated="log">"[log truncated]"</p>
                                                }
                                            </td>
                                        </tr>
                                    </tbody>
                                }
                            </table>
                        }
                        if timing.omitted > 0 {
                            <p id="timing-omitted" class="mt-1 text-xs text-base-content/60">(timing.omitted) " more commands not shown."</p>
                        }
                    } else {
                        <p id="no-timing" class="text-xs text-base-content/60">"No timing reported for this job."</p>
                    }
                </section>
    })
}

#[page("/jobs/{job_id}/timing")]
async fn timing_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let id = path_param::<JobId>(cx);
    owned(store, session.user_id, id).await?;
    let timing = timing_breakdown(store, session.user_id, id).await?;
    let tasks = tasks(store, id).await?;
    let back = format!("/jobs/{id}");
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet job timing", active: Nav::Jobs, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Timing of " (id)</h1>
                    <a class="link link-hover ml-auto" href=(back.as_str())>"Job"</a>
                </header>
                timing_panel(timing: timing)
                <div class="grid gap-3 lg:grid-cols-[26rem_1fr]">
                    <section>
                        <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60">"Shell tasks"</h2>
                        if tasks.is_empty() {
                            <p id="no-tasks" class="text-xs text-base-content/60">"No shell tasks reported."</p>
                        } else {
                            <table class="table table-zebra table-xs">
                                <thead>
                                    <tr>
                                        <th>"Task"</th>
                                        <th>"Status"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    for task in tasks {
                                        <tr>
                                            <td>
                                                <button type="button" class="link link-primary break-all text-left" data-task=(task.id.as_str()) data-log-url=(task.url.as_str())>(task.id.as_str())</button>
                                                <div class="break-all text-base-content/60">(task.command.as_str())</div>
                                            </td>
                                            <td><span class=(badge_class(task.status.as_str()))>(task.status.as_str())</span></td>
                                        </tr>
                                    }
                                </tbody>
                            </table>
                        }
                    </section>
                    <section>
                        <h2 class="mb-1 flex gap-2 text-xs font-bold uppercase text-base-content/60">
                            <span>"Log"</span>
                            <span id="task-log-title" class="normal-case"></span>
                            <span id="task-log-state" class="normal-case"></span>
                        </h2>
                        <pre id="task-log" class="h-[70vh] overflow-auto whitespace-pre-wrap border border-base-300 bg-base-300 p-2 text-xs"></pre>
                    </section>
                </div>
                <script src=(LOG_SCRIPT_PATH) defer=""></script>
            )
    })
}

#[route(GET "/static/tasklog.js")]
async fn log_script() -> Result<([(header::HeaderName, &'static str); 1], &'static str)> {
    Ok(([(header::CONTENT_TYPE, "text/javascript")], LOG_JS))
}

/// Decodes, cleans and bounds the log text of one command for display.
struct Pane {
    cut: bool,
    carry: Vec<u8>,
    column: usize,
    skipping: bool,
    sent: usize,
}

impl Pane {
    fn new() -> Self {
        Self {
            cut: false,
            carry: Vec::new(),
            column: 0,
            skipping: false,
            sent: 0,
        }
    }

    fn full(&self) -> bool {
        self.sent >= MAX_PANE_BYTES
    }

    fn push(&mut self, bytes: &[u8]) -> String {
        let mut joined = std::mem::take(&mut self.carry);
        joined.extend_from_slice(bytes);
        let mut out = String::new();
        let mut rest = joined.as_slice();
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    self.clean(valid, &mut out);
                    return out;
                }
                Err(err) => {
                    let (good, bad) = rest.split_at(err.valid_up_to());
                    self.clean(std::str::from_utf8(good).unwrap_or_default(), &mut out);
                    match err.error_len() {
                        None if bad.len() <= CARRY_MAX => {
                            self.carry = bad.to_vec();
                            return out;
                        }
                        None => {
                            self.clean("\u{fffd}", &mut out);
                            return out;
                        }
                        Some(skip) => {
                            self.clean("\u{fffd}", &mut out);
                            rest = bad.get(skip..).unwrap_or_default();
                        }
                    }
                }
            }
        }
    }

    fn clean(&mut self, text: &str, out: &mut String) {
        for ch in text.chars() {
            if self.full() {
                self.cut = true;
                return;
            }
            if ch == '\n' {
                out.push('\n');
                self.sent += 1;
                self.column = 0;
                self.skipping = false;
            } else if ch != '\t' && is_hostile(ch) || self.skipping {
            } else if self.column >= MAX_LINE_CHARS {
                out.push('\u{2026}');
                self.sent += '\u{2026}'.len_utf8();
                self.skipping = true;
                self.cut = true;
            } else {
                out.push(ch);
                self.sent += ch.len_utf8();
                self.column += 1;
            }
        }
    }
}

fn inert(json: &str) -> String {
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn frame(id: Option<u32>, event: &str, data: &serde_json::Value) -> Frame<Bytes> {
    let id = id.map(|seq| format!("id: {seq}\n")).unwrap_or_default();
    let text = format!("{id}event: {event}\ndata: {}\n\n", inert(&data.to_string()));
    Frame::data(Bytes::from(text))
}

fn end_frame(status: &str) -> Frame<Bytes> {
    frame(None, "end", &serde_json::json!({ "status": status }))
}

async fn pump(
    mut chunks: BoxStream<StreamShellLogChunk>,
    tx: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) {
    let mut pane = Pane::new();
    let mut last = "closed";
    while let Some(item) = chunks.next().await {
        let Ok(chunk) = item else {
            let fail = serde_json::json!({ "error": "log stream failed" });
            let _ = tx.send(Ok(frame(None, "fail", &fail))).await;
            return;
        };
        let status = validate_shell_log_status(chunk.status)
            .and_then(shell_status_name)
            .unwrap_or("unknown");
        let data = serde_json::json!({
            "seq": chunk.seq,
            "status": status,
            "text": pane.push(&chunk.bytes),
        });
        if tx
            .send(Ok(frame(Some(chunk.seq), "chunk", &data)))
            .await
            .is_err()
        {
            return;
        }
        if pane.full() {
            last = "truncated";
            break;
        }
        if status == "done" || status == "failed" {
            last = status;
            break;
        }
    }
    let _ = tx.send(Ok(end_frame(last))).await;
}

fn resume_from(cx: &Cx) -> u32 {
    headers(cx)
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .map_or(0, |seen| seen.saturating_add(1))
}

#[route(GET "/jobs/{job_id}/shell/{command_id}/log")]
async fn log_stream(cx: &Cx) -> Result<([(header::HeaderName, &'static str); 2], Body)> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(unauthorized().into());
    };
    let job_id = path_param::<JobId>(cx);
    let command_id = path_param::<CommandId>(cx);
    owned(store, session.user_id, job_id).await?;
    if !validate_shell_log_command_id(command_id) {
        return Err(not_found().into());
    }
    let (tx, rx) = mpsc::channel(FRAME_QUEUE);
    let from_seq = resume_from(cx);
    let request = StreamShellLogRequest {
        job_id: job_id.to_owned(),
        command_id: command_id.to_owned(),
        from_seq,
    };
    if validate_shell_log_seq(from_seq) {
        let chunks = stream_shell_log(store.pool(), &request, StreamLimits::default())
            .map_err(|err| internal(&err))?;
        tokio::spawn(pump(chunks, tx));
    } else {
        let _ = tx.try_send(Ok(end_frame("closed")));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Body::new(StreamBody::new(ReceiverStream::new(rx))),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(input: &str) -> String {
        Pane::new().push(input.as_bytes())
    }

    #[test]
    fn control_and_separator_characters_are_dropped() {
        let input = "a\u{1b}[31mb\rc\u{85}d\u{2028}e\u{2029}f\u{7}g\u{202e}h\u{7f}i\0j";
        assert_eq!(clean(input), "a[31mbcdefghij");
    }

    #[test]
    fn newline_and_tab_survive() {
        assert_eq!(clean("a\tb\r\nc\n"), "a\tb\nc\n");
    }

    #[test]
    fn markup_text_passes_through_for_the_caller_to_escape() {
        assert_eq!(clean("<script>x</script>"), "<script>x</script>");
        assert_eq!(
            inert(r#"{"text":"<script>&"}"#),
            r#"{"text":"\u003cscript\u003e\u0026"}"#
        );
    }

    #[test]
    fn a_line_is_cut_at_the_cap_and_the_next_line_starts_fresh() {
        let input = format!("{}\nok\n", "x".repeat(MAX_LINE_CHARS + 10));
        let out = clean(&input);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.first().unwrap().chars().count(), MAX_LINE_CHARS + 1);
        assert!(lines.first().unwrap().ends_with('\u{2026}'));
        assert_eq!(lines.get(1), Some(&"ok"));
    }

    #[test]
    fn a_line_of_exactly_the_cap_is_not_cut() {
        let out = clean(&"x".repeat(MAX_LINE_CHARS));
        assert_eq!(out.chars().count(), MAX_LINE_CHARS);
        assert!(!out.contains('\u{2026}'));
    }

    #[test]
    fn a_cut_line_stays_cut_across_chunks() {
        let mut pane = Pane::new();
        let first = pane.push("x".repeat(MAX_LINE_CHARS + 1).as_bytes());
        let second = pane.push(b"yyy\nz");
        assert!(first.ends_with('\u{2026}'));
        assert_eq!(second, "\nz");
    }

    #[test]
    fn the_pane_stops_at_its_byte_cap() {
        let mut pane = Pane::new();
        let line = format!("{}\n", "x".repeat(1000));
        let mut total = 0;
        while !pane.full() {
            total += pane.push(line.as_bytes()).len();
        }
        assert!(total <= MAX_PANE_BYTES);
        assert!(total + line.len() > MAX_PANE_BYTES);
        assert_eq!(pane.push(b"more"), "");
    }

    #[test]
    fn a_character_split_across_chunks_is_rebuilt() {
        let euro = "\u{20ac}".as_bytes();
        let mut pane = Pane::new();
        let a = pane.push(euro.get(..2).unwrap());
        let b = pane.push(euro.get(2..).unwrap());
        assert_eq!(a, "");
        assert_eq!(b, "\u{20ac}");
    }

    #[test]
    fn invalid_bytes_become_the_replacement_character() {
        assert_eq!(Pane::new().push(b"a\xffb\xc3("), "a\u{fffd}b\u{fffd}(");
    }

    const HOSTILE_TABLE: [(&str, char); 10] = [
        ("zero width space", '\u{200b}'),
        ("zero width non-joiner", '\u{200c}'),
        ("zero width joiner", '\u{200d}'),
        ("left-to-right mark", '\u{200e}'),
        ("byte order mark", '\u{feff}'),
        ("soft hyphen", '\u{ad}'),
        ("word joiner", '\u{2060}'),
        ("arabic letter mark", '\u{61c}'),
        ("tag latin a", '\u{e0041}'),
        ("tag cancel", '\u{e007f}'),
    ];

    #[test]
    fn every_hostile_character_is_dropped_from_the_pane() {
        for (name, ch) in HOSTILE_TABLE {
            assert_eq!(clean(&format!("a{ch}b\tc\n")), "ab\tc\n", "{name}");
        }
    }

    #[test]
    fn a_hostile_character_split_across_chunks_is_dropped() {
        for (name, ch) in HOSTILE_TABLE {
            let mut bytes = [0_u8; 4];
            let encoded = ch.encode_utf8(&mut bytes).as_bytes();
            for cut in 1..encoded.len() {
                let mut pane = Pane::new();
                let mut head = b"a".to_vec();
                head.extend_from_slice(encoded.get(..cut).unwrap());
                let mut tail = encoded.get(cut..).unwrap().to_vec();
                tail.extend_from_slice(b"b");
                let joined = pane.push(&head) + &pane.push(&tail);
                assert_eq!(joined, "ab", "{name} cut at {cut}");
            }
        }
    }
}
