//! Shell command timing records.
//!
//! [`ShellRecorder`] turns one finished or running shell command into a [`ShellRecord`] whose
//! command and output are safe to store. Each text first loses its NUL, control, format, line
//! and paragraph separator and tag characters, so none of them can split a secret past the
//! redactor and Postgres text accepts the value. Newline and tab survive in commands and logs.
//! The text then passes the [`Redactor`] and is stripped again, and only then is it cut at a
//! character boundary to [`MAX_COMMAND_BYTES`] or [`MAX_SHELL_LOG_BYTES`], so a secret that
//! straddles the cap is replaced whole and never leaves a fragment. A record past [`MAX_SHELL_COMMANDS`] stores nothing and bumps
//! [`ShellRecorder::overflow`].

use std::fmt;

use fleet_core::Redactor;
use fleet_proto::{MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES};

/// One raw shell command observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellInput {
    /// Raw command line.
    pub command: String,
    /// Raw combined output.
    pub output: String,
    /// Start, in milliseconds.
    pub started: u64,
    /// End, in milliseconds, when the command finished.
    pub ended: Option<u64>,
    /// Exit code when known.
    pub exit_code: Option<i32>,
    /// Whether the command ran in the background.
    pub background: bool,
}

/// One redacted, bounded shell command record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellRecord {
    /// Redacted command, at most [`MAX_COMMAND_BYTES`].
    pub command: String,
    /// Redacted output, at most [`MAX_SHELL_LOG_BYTES`].
    pub output: String,
    /// Start, in milliseconds.
    pub started: u64,
    /// End, in milliseconds, when finished.
    pub ended: Option<u64>,
    /// End minus start, or zero while unfinished.
    pub duration: u64,
    /// Exit code when known.
    pub exit_code: Option<i32>,
    /// Whether the command or output was cut to its cap.
    pub truncated: bool,
    /// Whether the command ran in the background.
    pub background: bool,
}

/// Why a record was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellError {
    /// The command is empty once NUL bytes are removed.
    EmptyCommand,
    /// The end precedes the start.
    EndBeforeStart,
    /// A time exceeds `i64::MAX`, the largest the server stores.
    TimeOutOfRange,
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyCommand => "shell command is empty",
            Self::EndBeforeStart => "shell command ends before it starts",
            Self::TimeOutOfRange => "shell command time is out of range",
        })
    }
}

impl std::error::Error for ShellError {}

/// Collects up to [`MAX_SHELL_COMMANDS`] records and counts the rest.
#[derive(Debug)]
pub struct ShellRecorder {
    redactor: Redactor,
    records: Vec<ShellRecord>,
    overflow: u64,
}

/// Format (Cf), line and paragraph separator (Zl, Zp) and tag code points, sorted and
/// non-overlapping. Generated from `UnicodeData.txt`; it matches `HIDDEN_RANGES` in
/// `agent/notes.rs` and the set in `fetch.rs`. [`char::is_control`] covers Cc separately.
const HIDDEN_RANGES: &[(u32, u32)] = &[
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE007F),
];

fn is_hidden(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    let code = u32::from(c);
    HIDDEN_RANGES
        .binary_search_by(|&(low, high)| {
            if high < code {
                std::cmp::Ordering::Less
            } else if low > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn strip_hidden(text: &str, keep_layout: bool) -> String {
    text.chars()
        .filter(|&c| (keep_layout && (c == '\n' || c == '\t')) || !is_hidden(c))
        .collect()
}

/// Strips hidden characters, redacts, then strips again in case redaction exposed more.
///
/// Stripping first lets a secret split by an invisible character match the redactor. With
/// `keep_layout`, newline and tab survive for commands and logs; names and ids lose them too.
pub(crate) fn strip_redact(redactor: &Redactor, text: &str, keep_layout: bool) -> String {
    let stripped = strip_hidden(text, keep_layout);
    strip_hidden(&redactor.redact_str(&stripped), keep_layout)
}

fn clean(redactor: &Redactor, text: &str, cap: usize) -> (String, bool) {
    let mut redacted = strip_redact(redactor, text, true);
    if redacted.len() <= cap {
        return (redacted, false);
    }
    let mut end = cap;
    while !redacted.is_char_boundary(end) {
        end -= 1;
    }
    redacted.truncate(end);
    (redacted, true)
}

fn in_range(ms: u64) -> bool {
    i64::try_from(ms).is_ok()
}

impl ShellRecorder {
    /// Builds an empty recorder.
    #[must_use]
    pub fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            records: Vec::new(),
            overflow: 0,
        }
    }

    /// Records one command.
    ///
    /// A refused input stores nothing and is not counted as overflow. Past
    /// [`MAX_SHELL_COMMANDS`] stored records, a valid input only raises the overflow counter.
    ///
    /// # Errors
    ///
    /// Returns [`ShellError`] for an empty command, an end before the start, or a time above
    /// `i64::MAX`.
    pub fn record(&mut self, input: &ShellInput) -> Result<(), ShellError> {
        if strip_hidden(&input.command, true).is_empty() {
            return Err(ShellError::EmptyCommand);
        }
        if !in_range(input.started) || input.ended.is_some_and(|end| !in_range(end)) {
            return Err(ShellError::TimeOutOfRange);
        }
        if input.ended.is_some_and(|end| end < input.started) {
            return Err(ShellError::EndBeforeStart);
        }
        if self.records.len() >= MAX_SHELL_COMMANDS {
            self.overflow = self.overflow.saturating_add(1);
            return Ok(());
        }
        let (command, command_cut) = clean(&self.redactor, &input.command, MAX_COMMAND_BYTES);
        let (output, output_cut) = clean(&self.redactor, &input.output, MAX_SHELL_LOG_BYTES);
        self.records.push(ShellRecord {
            command,
            output,
            started: input.started,
            ended: input.ended,
            duration: input.ended.map_or(0, |end| end - input.started),
            exit_code: input.exit_code,
            truncated: command_cut || output_cut,
            background: input.background,
        });
        Ok(())
    }

    /// Stored records in arrival order.
    #[must_use]
    pub fn records(&self) -> &[ShellRecord] {
        &self.records
    }

    /// Valid commands dropped because the cap was reached.
    #[must_use]
    pub fn overflow(&self) -> u64 {
        self.overflow
    }
}
