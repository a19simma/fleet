//! Shell command timing records.
//!
//! [`ShellRecorder`] turns one finished or running shell command into a [`ShellRecord`] whose
//! command and output are safe to store. Each text goes through
//! [`sanitise_lines`](fleet_core::text::sanitise_lines): redact, strip hostile characters except
//! newline and tab, redact, strip, then cut at a character boundary to [`MAX_COMMAND_BYTES`] or
//! [`MAX_SHELL_LOG_BYTES`], so a secret that holds a stripped character, or that straddles
//! the cap, is replaced whole and leaves no fragment. A record past [`MAX_SHELL_COMMANDS`]
//! stores nothing and bumps [`ShellRecorder::overflow`].

use std::fmt;

use fleet_core::Redactor;
use fleet_core::text::{Cap, sanitise_lines};
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
        let command = sanitise_lines(
            &self.redactor,
            &input.command,
            Cap::Bytes(MAX_COMMAND_BYTES),
        );
        if command.text.is_empty() {
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
        let output = sanitise_lines(
            &self.redactor,
            &input.output,
            Cap::Bytes(MAX_SHELL_LOG_BYTES),
        );
        self.records.push(ShellRecord {
            command: command.text,
            output: output.text,
            started: input.started,
            ended: input.ended,
            duration: input.ended.map_or(0, |end| end - input.started),
            exit_code: input.exit_code,
            truncated: command.cut || output.cut,
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
