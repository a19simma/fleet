//! The readable `fleet logs` view: one line per call, a short block per result, a cost footer.
//!
//! Text reaches this module already stripped and redacted by the shared parser, so nothing here
//! sanitises again. Color is a parameter and the environment is never read.

use std::collections::HashMap;
use std::io::{self, Write};

use fleet_core::Redactor;
use fleet_core::transcript::{
    Assembler, Entry, Item, Pair, PairStatus, Role, ToolId, Transcript, Update, Usage,
};

/// Result output lines shown per block.
const OUTPUT_LINES: usize = 8;

/// Characters shown per output or raw line before it is cut.
const LINE_CHARS: usize = 160;

const RESET: &str = "\u{1b}[0m";
const BOLD: &str = "\u{1b}[1m";
const DIM: &str = "\u{1b}[2m";
const RED: &str = "\u{1b}[31m";

#[derive(Clone, Copy)]
enum Tone {
    Plain,
    Bold,
    Dim,
    Red,
}

#[derive(Clone, Copy)]
struct Style {
    color: bool,
}

impl Style {
    fn line(self, out: &mut impl Write, indent: usize, tone: Tone, text: &str) -> io::Result<()> {
        let pad = " ".repeat(indent);
        let code = match tone {
            Tone::Plain => None,
            Tone::Bold => Some(BOLD),
            Tone::Dim => Some(DIM),
            Tone::Red => Some(RED),
        };
        match code {
            Some(code) if self.color => writeln!(out, "{pad}{code}{text}{RESET}"),
            _ => writeln!(out, "{pad}{text}"),
        }
    }
}

fn cut(line: &str) -> String {
    match line.char_indices().nth(LINE_CHARS) {
        Some((at, _)) => format!("{}...", &line[..at]),
        None => line.to_owned(),
    }
}

fn labelled(
    out: &mut impl Write,
    style: Style,
    indent: usize,
    tone: Tone,
    label: &str,
    text: &str,
) -> io::Result<()> {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default();
    style.line(
        out,
        indent,
        tone,
        format!("{label}:{}{first}", sep(first)).trim_end(),
    )?;
    for line in lines {
        style.line(out, indent + 2, Tone::Plain, line)?;
    }
    Ok(())
}

fn sep(first: &str) -> &'static str {
    if first.is_empty() { "" } else { " " }
}

fn output_block(out: &mut impl Write, style: Style, indent: usize, output: &str) -> io::Result<()> {
    let total = output.lines().count();
    for line in output.lines().take(OUTPUT_LINES) {
        style.line(out, indent, Tone::Plain, &cut(line))?;
    }
    if total > OUTPUT_LINES {
        let more = total - OUTPUT_LINES;
        style.line(
            out,
            indent,
            Tone::Dim,
            &format!("... {more} more line{}", if more == 1 { "" } else { "s" }),
        )?;
    }
    Ok(())
}

fn result_header(
    out: &mut impl Write,
    style: Style,
    indent: usize,
    id: Option<&ToolId>,
    status: &str,
    is_error: bool,
) -> io::Result<()> {
    let text = id.map_or_else(
        || format!("< {status}"),
        |id| format!("< {} {status}", id.as_str()),
    );
    let tone = if is_error { Tone::Red } else { Tone::Plain };
    style.line(out, indent, tone, &text)
}

fn call_line(
    out: &mut impl Write,
    style: Style,
    indent: usize,
    pair: &Pair,
    with_id: bool,
) -> io::Result<()> {
    let mut text = format!("> {}", pair.name);
    if !pair.summary.is_empty() {
        text.push(' ');
        text.push_str(&pair.summary);
    }
    if with_id {
        text.push_str(" (");
        text.push_str(pair.id.as_str());
        text.push(')');
    }
    style.line(out, indent, Tone::Bold, &text)
}

fn done_status(is_error: bool) -> &'static str {
    if is_error { "ERROR" } else { "ok" }
}

fn usage_text(usage: Usage) -> String {
    let mut parts = vec![format!(
        "tokens in {} out {}",
        usage.input_tokens, usage.output_tokens
    )];
    if let Some(read) = usage.cache_read_input_tokens {
        parts.push(format!("cache read {read}"));
    }
    if let Some(write) = usage.cache_creation_input_tokens {
        parts.push(format!("write {write}"));
    }
    parts.join(" ")
}

fn entry(out: &mut impl Write, style: Style, indent: usize, entry: &Entry) -> io::Result<()> {
    match entry {
        Entry::Message { role, text, .. } => {
            let label = match role {
                Role::User => "user",
                _ => "assistant",
            };
            labelled(out, style, indent, Tone::Plain, label, text)
        }
        Entry::Thinking { text } => labelled(out, style, indent, Tone::Dim, "thinking", text),
        Entry::System { subtype, .. } => {
            style.line(out, indent, Tone::Dim, &format!("system: {subtype}"))
        }
        Entry::RateLimit {
            status,
            utilization,
            ..
        } => {
            let used =
                utilization.map_or_else(String::new, |u| format!(", {:.0}% used", u * 100.0));
            style.line(
                out,
                indent,
                Tone::Dim,
                &format!("rate limit: {status}{used}"),
            )
        }
        Entry::Result {
            is_error,
            turns,
            duration_ms,
            cost_usd,
            usage,
            terminal_reason,
            denials,
        } => {
            let mut parts = vec![
                format!("{turns} turns"),
                format!("{}.{:03}s", duration_ms / 1000, duration_ms % 1000),
            ];
            if let Some(cost) = cost_usd {
                parts.push(format!("${cost:.4}"));
            }
            parts.push(usage_text(*usage));
            if let Some(reason) = terminal_reason {
                parts.push(format!("reason {reason}"));
            }
            if *denials > 0 {
                parts.push(format!("{denials} denials"));
            }
            let head = if *is_error { "run failed: " } else { "" };
            let tone = if *is_error { Tone::Red } else { Tone::Dim };
            style.line(
                out,
                indent,
                tone,
                &format!("-- {head}{} --", parts.join(", ")),
            )
        }
        Entry::FleetNote { text } => labelled(out, style, indent, Tone::Dim, "note", text),
        Entry::Truncated => style.line(out, indent, Tone::Dim, "-- transcript truncated --"),
        Entry::Unknown { kind, raw } => labelled(
            out,
            style,
            indent,
            Tone::Dim,
            &format!("unknown {kind}"),
            &cut(raw.lines().next().unwrap_or_default()),
        ),
        _ => style.line(out, indent, Tone::Dim, "unknown ?"),
    }
}

fn orphan(
    out: &mut impl Write,
    style: Style,
    indent: usize,
    id: &ToolId,
    is_error: bool,
    output: &str,
) -> io::Result<()> {
    let status = format!("{} (no call)", done_status(is_error));
    result_header(out, style, indent, Some(id), &status, is_error)?;
    output_block(out, style, indent + 2, output)
}

fn item(out: &mut impl Write, style: Style, indent: usize, node: &Item) -> io::Result<()> {
    match node {
        Item::Entry(e) => entry(out, style, indent, e),
        Item::Pair(pair) => {
            call_line(out, style, indent, pair, false)?;
            for child in &pair.children {
                item(out, style, indent + 2, child)?;
            }
            match &pair.status {
                PairStatus::Done { is_error, output } => {
                    result_header(
                        out,
                        style,
                        indent + 2,
                        None,
                        done_status(*is_error),
                        *is_error,
                    )?;
                    output_block(out, style, indent + 4, output)
                }
                PairStatus::NoResult => {
                    result_header(out, style, indent + 2, None, "no result", false)
                }
                _ => result_header(out, style, indent + 2, None, "pending", false),
            }
        }
        Item::Orphan {
            id,
            is_error,
            output,
        } => orphan(out, style, indent, id, *is_error, output),
        _ => style.line(out, indent, Tone::Dim, "unknown ?"),
    }
}

/// Writes a whole view, one nested tree, ending with a note when a cap cut it.
fn tree(out: &mut impl Write, style: Style, view: &Transcript) -> io::Result<()> {
    for node in view.items() {
        item(out, style, 0, node)?;
    }
    if view.capped() {
        style.line(
            out,
            0,
            Tone::Dim,
            &format!("-- view capped, {} items not shown --", view.dropped()),
        )?;
    }
    Ok(())
}

/// Reads stored chunks and writes the readable view.
///
/// Without `follow` the view is built whole and written once by [`Self::finish`]. With `follow`
/// each update is written when it arrives: a call when seen, its result later with the call id.
#[expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub rejects plain pub in a private module"
)]
pub(crate) struct Pretty<'a> {
    assembler: Assembler<'a>,
    style: Style,
    follow: bool,
    depths: HashMap<ToolId, usize>,
}

impl<'a> Pretty<'a> {
    pub(crate) fn new(redactor: &'a Redactor, color: bool, follow: bool) -> Self {
        Self {
            assembler: Assembler::new(Some(redactor)),
            style: Style { color },
            follow,
            depths: HashMap::new(),
        }
    }

    pub(crate) fn chunk(
        &mut self,
        out: &mut impl Write,
        text: &str,
        truncated: bool,
    ) -> io::Result<()> {
        let updates = self.assembler.push(text, truncated);
        if self.follow {
            self.updates(out, &updates)?;
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, out: &mut impl Write, done: bool) -> io::Result<()> {
        let closed = if done {
            self.assembler.finish()
        } else {
            Vec::new()
        };
        if self.follow {
            self.updates(out, &closed)
        } else {
            tree(out, self.style, &self.assembler.snapshot())
        }
    }

    fn depth(&self, id: &ToolId) -> usize {
        self.depths.get(id).copied().unwrap_or(0)
    }

    fn updates(&mut self, out: &mut impl Write, updates: &[Update]) -> io::Result<()> {
        let style = self.style;
        for update in updates {
            match update {
                Update::Appended { under, item: node } => {
                    let indent = under.as_ref().map_or(0, |u| self.depth(u) + 2);
                    match node {
                        Item::Pair(pair) => {
                            self.depths.insert(pair.id.clone(), indent);
                            call_line(out, style, indent, pair, true)?;
                        }
                        other => item(out, style, indent, other)?,
                    }
                }
                Update::Paired {
                    id,
                    is_error,
                    output,
                } => {
                    let indent = self.depth(id) + 2;
                    result_header(
                        out,
                        style,
                        indent,
                        Some(id),
                        done_status(*is_error),
                        *is_error,
                    )?;
                    output_block(out, style, indent + 2, output)?;
                }
                Update::NoResult { id } => {
                    result_header(out, style, self.depth(id) + 2, Some(id), "no result", false)?;
                }
                Update::Adopted { pair } => {
                    self.depths.insert(pair.id.clone(), 0);
                    call_line(out, style, 0, pair, true)?;
                    let is_error = matches!(pair.status, PairStatus::Done { is_error: true, .. });
                    let status = format!("{} (shown above)", done_status(is_error));
                    result_header(out, style, 2, Some(&pair.id), &status, is_error)?;
                }
                Update::Capped => {
                    style.line(
                        out,
                        0,
                        Tone::Dim,
                        "-- view capped, later items not shown --",
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}
