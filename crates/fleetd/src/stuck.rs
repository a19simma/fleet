//! Shadow-mode stuck detector over the parsed event stream.
//!
//! [`Detector`] watches tool events and assistant turns and records the first [`StuckRule`]
//! that fires. It only records: it never cancels a job, warns the agent or changes an outcome.
//! Inputs are keyed by a hash of the already redacted and capped tool name and command, and the
//! text is never stored. History is a bounded window, so memory stays constant per job.
//!
//! Rules adapt `OpenHands` stuck detection. A tool run counts as failed when `ok` is false or
//! the exit code is known and nonzero, judged when the tool event is emitted: a hook exit code
//! that arrives later is not seen.

use std::collections::VecDeque;

use sha2::{Digest, Sha256};

use crate::telemetry::JobEvent;

const KEY_BYTES: usize = 8;

/// A stuck rule, with a stable wire name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckRule {
    /// The same tool, input and output several times in a row.
    RepeatActionObservation,
    /// The same tool and input failing several times in a row with the same output.
    RepeatError,
    /// Two distinct tool calls alternating for several full cycles.
    Alternating,
    /// Several assistant turns in a row without a tool call.
    Monologue,
}

impl StuckRule {
    /// The stable name stored and sent on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RepeatActionObservation => "repeat_action_observation",
            Self::RepeatError => "repeat_error",
            Self::Alternating => "alternating",
            Self::Monologue => "monologue",
        }
    }
}

/// The first rule that fired, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stuck {
    /// The rule that fired.
    pub rule: StuckRule,
    /// Stored event position at the moment it fired.
    pub seq: u32,
    /// Arrival time in ms since job start.
    pub ts_ms: u64,
}

/// Thresholds of every rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StuckRules {
    /// Identical (tool, input, output) calls in a row for `repeat_action_observation`.
    pub repeat_action_observation: usize,
    /// Failing calls with one input and one output in a row for `repeat_error`.
    pub repeat_error: usize,
    /// Full A,B cycles for `alternating`.
    pub alternating_cycles: usize,
    /// Assistant turns without a tool call in a row for `monologue`.
    pub monologue_turns: usize,
}

impl Default for StuckRules {
    fn default() -> Self {
        Self {
            repeat_action_observation: 4,
            repeat_error: 3,
            alternating_cycles: 3,
            monologue_turns: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Step {
    input: u64,
    out: u64,
    empty: bool,
    failed: bool,
}

impl Step {
    fn same_call(self, other: Self) -> bool {
        self.input == other.input && self.out == other.out
    }
}

#[derive(Debug)]
struct Turn {
    id: Option<String>,
    has_tool: bool,
}

/// Incremental detector. Feed tool events and assistant turns, read [`Detector::fired`].
#[derive(Debug)]
pub struct Detector {
    rules: StuckRules,
    window: VecDeque<Step>,
    turn: Option<Turn>,
    text_run: usize,
    fired: Option<Stuck>,
}

fn key(parts: &[&str]) -> u64 {
    let digest = Sha256::digest(parts.join("\0").as_bytes());
    digest
        .iter()
        .take(KEY_BYTES)
        .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

impl Detector {
    /// A detector with the given thresholds. A threshold of 0 acts as 1.
    #[must_use]
    pub fn new(rules: StuckRules) -> Self {
        Self {
            rules,
            window: VecDeque::new(),
            turn: None,
            text_run: 0,
            fired: None,
        }
    }

    /// The first rule that fired, if any.
    #[must_use]
    pub fn fired(&self) -> Option<Stuck> {
        self.fired
    }

    /// Steps kept in the history window, never above [`Detector::window_cap`].
    #[must_use]
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    /// Most steps the history window keeps.
    #[must_use]
    pub fn window_cap(&self) -> usize {
        self.rules
            .repeat_action_observation
            .max(self.rules.repeat_error)
            .max(self.rules.alternating_cycles.saturating_mul(2))
            .max(2)
    }

    /// Feed a stored tool event. Other event kinds are ignored.
    pub fn tool(&mut self, event: &JobEvent) {
        if event.kind != crate::telemetry::EventKind::Tool {
            return;
        }
        let tool = event.tool.as_deref().unwrap_or_default();
        let cmd = event.cmd.as_deref().unwrap_or_default();
        let step = Step {
            input: key(&[tool, cmd]),
            out: key(&[event.out_hash.as_deref().unwrap_or_default()]),
            empty: event.out_bytes == Some(0),
            failed: event.ok == Some(false) || event.exit_code.is_some_and(|code| code != 0),
        };
        self.window.push_back(step);
        while self.window.len() > self.window_cap() {
            self.window.pop_front();
        }
        if self.fired.is_some() {
            return;
        }
        let rule = if self.repeat_action_observation() {
            Some(StuckRule::RepeatActionObservation)
        } else if self.repeat_error() {
            Some(StuckRule::RepeatError)
        } else if self.alternating() {
            Some(StuckRule::Alternating)
        } else {
            None
        };
        if let Some(rule) = rule {
            self.fired = Some(Stuck {
                rule,
                seq: event.seq,
                ts_ms: event.ts_ms,
            });
        }
    }

    /// Feed an assistant line. Lines with one message `id` are one turn.
    ///
    /// `seq` is the next stored event position, used if the rule fires.
    pub fn assistant(&mut self, id: Option<&str>, has_tool: bool, seq: u32, ts_ms: u64) {
        let same = self
            .turn
            .as_ref()
            .is_some_and(|turn| id.is_some() && turn.id.as_deref() == id);
        if same {
            if let Some(turn) = self.turn.as_mut() {
                turn.has_tool |= has_tool;
            }
            return;
        }
        self.end_turn(seq, ts_ms);
        self.turn = Some(Turn {
            id: id.map(str::to_owned),
            has_tool,
        });
    }

    /// Close the open turn: no further assistant line will join it.
    pub fn end_turn(&mut self, seq: u32, ts_ms: u64) {
        let Some(turn) = self.turn.take() else {
            return;
        };
        if turn.has_tool {
            self.text_run = 0;
            return;
        }
        self.text_run += 1;
        if self.fired.is_none() && self.text_run >= self.rules.monologue_turns.max(1) {
            self.fired = Some(Stuck {
                rule: StuckRule::Monologue,
                seq,
                ts_ms,
            });
        }
    }

    fn tail(&self, n: usize) -> Option<Vec<Step>> {
        let n = n.max(1);
        let skip = self.window.len().checked_sub(n)?;
        Some(self.window.iter().skip(skip).copied().collect())
    }

    fn repeat_action_observation(&self) -> bool {
        let Some(tail) = self.tail(self.rules.repeat_action_observation) else {
            return false;
        };
        let Some(&first) = tail.first() else {
            return false;
        };
        tail.iter().all(|step| step.same_call(first))
    }

    fn repeat_error(&self) -> bool {
        let Some(tail) = self.tail(self.rules.repeat_error) else {
            return false;
        };
        let Some(&first) = tail.first() else {
            return false;
        };
        let mut shown: Option<u64> = None;
        for step in &tail {
            if step.input != first.input || !step.failed {
                return false;
            }
            if !step.empty {
                if shown.is_some_and(|out| out != step.out) {
                    return false;
                }
                shown = Some(step.out);
            }
        }
        true
    }

    fn alternating(&self) -> bool {
        let Some(tail) = self.tail(self.rules.alternating_cycles.max(1).saturating_mul(2)) else {
            return false;
        };
        let [a, b, ..] = tail.as_slice() else {
            return false;
        };
        !a.same_call(*b)
            && tail
                .chunks(2)
                .all(|pair| matches!(pair, [x, y] if x.same_call(*a) && y.same_call(*b)))
    }
}
