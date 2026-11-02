//! Interval merging, span reconciliation and the timing view.

use std::fmt;

/// Error from building an [`Interval`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntervalError {
    /// The end lies before the start.
    Reversed,
}

impl fmt::Display for IntervalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reversed => write!(f, "interval end is before its start"),
        }
    }
}

impl std::error::Error for IntervalError {}

/// A half-open span of milliseconds, `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interval {
    start_ms: u64,
    end_ms: u64,
}

impl Interval {
    /// Builds an interval, refusing an end before the start.
    ///
    /// # Errors
    ///
    /// Returns [`IntervalError::Reversed`] when `end_ms < start_ms`.
    pub const fn new(start_ms: u64, end_ms: u64) -> Result<Self, IntervalError> {
        if end_ms < start_ms {
            return Err(IntervalError::Reversed);
        }
        Ok(Self { start_ms, end_ms })
    }

    /// Start in milliseconds.
    #[must_use]
    pub const fn start_ms(&self) -> u64 {
        self.start_ms
    }

    /// End in milliseconds.
    #[must_use]
    pub const fn end_ms(&self) -> u64 {
        self.end_ms
    }

    /// Length in milliseconds. Never overflows.
    #[must_use]
    pub const fn len_ms(&self) -> u64 {
        self.end_ms - self.start_ms
    }

    /// True when the interval covers no time.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start_ms == self.end_ms
    }
}

/// Unions a set of intervals into sorted, disjoint, non-touching, non-empty intervals.
#[must_use]
pub fn merge(set: &[Interval]) -> Vec<Interval> {
    let mut sorted: Vec<Interval> = set.iter().copied().filter(|i| !i.is_empty()).collect();
    sorted.sort_unstable();
    let mut out: Vec<Interval> = Vec::with_capacity(sorted.len());
    for next in sorted {
        match out.last_mut() {
            Some(last) if next.start_ms <= last.end_ms => {
                last.end_ms = last.end_ms.max(next.end_ms);
            }
            _ => out.push(next),
        }
    }
    out
}

/// Removes every instant of `cut` from `set`. Both inputs may be unsorted and overlapping.
#[must_use]
pub fn subtract(set: &[Interval], cut: &[Interval]) -> Vec<Interval> {
    let cuts = merge(cut);
    let mut out = Vec::new();
    for span in merge(set) {
        let mut cursor = span.start_ms;
        for c in &cuts {
            if c.end_ms <= cursor {
                continue;
            }
            if c.start_ms >= span.end_ms {
                break;
            }
            if c.start_ms > cursor {
                out.push(Interval {
                    start_ms: cursor,
                    end_ms: c.start_ms,
                });
            }
            cursor = c.end_ms;
        }
        if cursor < span.end_ms {
            out.push(Interval {
                start_ms: cursor,
                end_ms: span.end_ms,
            });
        }
    }
    out
}

/// Intersects `set` with `window`, dropping what falls outside it.
#[must_use]
pub fn clamp(set: &[Interval], window: Interval) -> Vec<Interval> {
    merge(set)
        .into_iter()
        .filter_map(|i| {
            let start_ms = i.start_ms.max(window.start_ms);
            let end_ms = i.end_ms.min(window.end_ms);
            (start_ms < end_ms).then_some(Interval { start_ms, end_ms })
        })
        .collect()
}

/// Total covered milliseconds of the union of `set`.
#[must_use]
pub fn covered_ms(set: &[Interval]) -> u64 {
    merge(set).iter().map(Interval::len_ms).sum()
}

/// Kind of a timing span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SpanKind {
    /// Foreground shell command.
    Shell,
    /// Background shell command.
    BgShell,
    /// Tool call other than shell.
    Tool,
    /// Wait on a model API request.
    ApiWait,
}

/// One timed span of a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// What the span measures.
    pub kind: SpanKind,
    /// When it ran.
    pub interval: Interval,
}

/// Five-part timing breakdown of a job. The parts sum to the job wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    /// Milliseconds waiting on the model API, not shadowed by a tool or shell span.
    pub api_wait_ms: u64,
    /// Milliseconds in tools, not shadowed by a shell span.
    pub tool_ms: u64,
    /// Milliseconds in foreground or background shell commands.
    pub shell_ms: u64,
    /// Agent window milliseconds covered by no span.
    pub idle_ms: u64,
    /// Job window milliseconds outside the agent window.
    pub overhead_ms: u64,
}

impl Summary {
    /// Sum of the five parts, saturating.
    #[must_use]
    pub const fn total_ms(&self) -> u64 {
        self.api_wait_ms
            .saturating_add(self.tool_ms)
            .saturating_add(self.shell_ms)
            .saturating_add(self.idle_ms)
            .saturating_add(self.overhead_ms)
    }
}

/// Reconciles spans into a [`Summary`].
///
/// Spans are clamped to the agent window, itself clamped to the job window.
/// Each instant counts once, for its highest kind: shell and background shell
/// over tool over API wait. Idle is agent window time with no span. Overhead is
/// the job window minus the agent window.
#[must_use]
pub fn aggregate(spans: &[Span], job_window: Interval, agent_window: Interval) -> Summary {
    let agent = clamp(&[agent_window], job_window)
        .first()
        .copied()
        .unwrap_or(Interval {
            start_ms: job_window.start_ms,
            end_ms: job_window.start_ms,
        });
    let of = |kinds: &[SpanKind]| -> Vec<Interval> {
        let picked: Vec<Interval> = spans
            .iter()
            .filter(|s| kinds.contains(&s.kind))
            .map(|s| s.interval)
            .collect();
        clamp(&picked, agent)
    };
    let shell = of(&[SpanKind::Shell, SpanKind::BgShell]);
    let tool = subtract(&of(&[SpanKind::Tool]), &shell);
    let shell_and_tool: Vec<Interval> = shell.iter().chain(tool.iter()).copied().collect();
    let api = subtract(&of(&[SpanKind::ApiWait]), &shell_and_tool);
    let shell_ms = covered_ms(&shell);
    let tool_ms = covered_ms(&tool);
    let api_wait_ms = covered_ms(&api);
    Summary {
        api_wait_ms,
        tool_ms,
        shell_ms,
        idle_ms: agent.len_ms() - shell_ms - tool_ms - api_wait_ms,
        overhead_ms: job_window.len_ms() - agent.len_ms(),
    }
}

/// Percentages are whole tenths of a percent, so the parts of a view sum to this.
pub const PERMILLE_TOTAL: u16 = 1000;

/// Most source characters of a command kept in a view, before the truncated marker.
pub const MAX_COMMAND_CHARS: usize = 256;

/// Most command rows kept in a view. Further commands count in `commands_omitted`.
pub const MAX_COMMAND_ROWS: usize = 50;

/// One displayed field: a stable key and its label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Stable machine key, shared by the CLI, the web page and the parity check.
    pub key: &'static str,
    /// Label shown to a person.
    pub label: &'static str,
}

/// Every field of a timing view, in display order. Both renderers read this list.
pub const FIELDS: &[Field] = &[
    Field {
        key: "api_wait",
        label: "API wait",
    },
    Field {
        key: "tool",
        label: "Tools",
    },
    Field {
        key: "shell",
        label: "Shell",
    },
    Field {
        key: "idle",
        label: "Idle",
    },
    Field {
        key: "overhead",
        label: "Overhead",
    },
    Field {
        key: "total",
        label: "Total",
    },
    Field {
        key: "commands",
        label: "Commands",
    },
];

/// A shell command to show, with its text already redacted upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandInput {
    /// Redacted command text. Control characters are marked by the view.
    pub command: String,
    /// Run time in milliseconds.
    pub duration_ms: u64,
    /// Start in milliseconds on the job clock.
    pub start_ms: u64,
    /// Exit code when known.
    pub exit: Option<i32>,
    /// True when upstream already cut the command.
    pub truncated: bool,
}

/// One command row of a [`TimingView`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRow {
    /// Display text: no control characters, at most [`MAX_COMMAND_CHARS`] source characters.
    pub command: String,
    /// Run time in milliseconds.
    pub duration_ms: u64,
    /// Start in milliseconds on the job clock.
    pub start_ms: u64,
    /// Exit code when known.
    pub exit: Option<i32>,
    /// True when upstream or this view cut the command.
    pub truncated: bool,
}

/// One part row of a [`TimingView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartRow {
    /// Key of the matching entry in [`FIELDS`].
    pub key: &'static str,
    /// Milliseconds in this part.
    pub ms: u64,
    /// Share of the total in tenths of a percent. The five rows sum to 1000, or all are 0.
    pub permille: u16,
}

impl PartRow {
    /// Share as text with one decimal, for example `12.3%`.
    #[must_use]
    pub fn percent_label(&self) -> String {
        format!("{}.{}%", self.permille / 10, self.permille % 10)
    }

    /// Duration as text, see [`human_duration_ms`].
    #[must_use]
    pub fn duration_label(&self) -> String {
        human_duration_ms(self.ms)
    }
}

/// The timing breakdown of a job as both renderers show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingView {
    /// The five parts in [`FIELDS`] order.
    pub rows: Vec<PartRow>,
    /// Sum of the parts, saturating.
    pub total_ms: u64,
    /// Command rows in input order, at most [`MAX_COMMAND_ROWS`].
    pub commands: Vec<CommandRow>,
    /// Commands given beyond [`MAX_COMMAND_ROWS`].
    pub commands_omitted: usize,
}

impl TimingView {
    /// Builds the view from a summary and command rows.
    #[must_use]
    pub fn new(summary: &Summary, commands: &[CommandInput]) -> Self {
        let ms = [
            summary.api_wait_ms,
            summary.tool_ms,
            summary.shell_ms,
            summary.idle_ms,
            summary.overhead_ms,
        ];
        let shares = permille_shares(&ms);
        let rows = ms
            .iter()
            .zip(shares)
            .zip(FIELDS)
            .map(|((&ms, permille), field)| PartRow {
                key: field.key,
                ms,
                permille,
            })
            .collect();
        Self {
            rows,
            total_ms: summary.total_ms(),
            commands: commands
                .iter()
                .take(MAX_COMMAND_ROWS)
                .map(command_row)
                .collect(),
            commands_omitted: commands.len().saturating_sub(MAX_COMMAND_ROWS),
        }
    }

    /// Total as text, see [`human_duration_ms`].
    #[must_use]
    pub fn total_label(&self) -> String {
        human_duration_ms(self.total_ms)
    }
}

fn command_row(input: &CommandInput) -> CommandRow {
    let (command, cut) = display_command(&input.command);
    CommandRow {
        command,
        duration_ms: input.duration_ms,
        start_ms: input.start_ms,
        exit: input.exit,
        truncated: input.truncated || cut,
    }
}

fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn display_command(text: &str) -> (String, bool) {
    let mut out = String::new();
    let mut cut = false;
    for (kept, c) in text.chars().take(MAX_COMMAND_CHARS + 1).enumerate() {
        if kept == MAX_COMMAND_CHARS {
            cut = true;
            out.push('\u{2026}');
            break;
        }
        if is_unsafe_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    (out, cut)
}

/// Splits [`PERMILLE_TOTAL`] over `parts` in proportion to their values.
///
/// Largest remainder rule: each part gets the floor of its exact share, then
/// the leftover tenths go one each to the parts with the largest remainders,
/// ties to the earlier part. The result sums to 1000. When every part is 0 the
/// result is all 0, with no division.
#[must_use]
pub fn permille_shares(parts: &[u64]) -> Vec<u16> {
    let total: u128 = parts.iter().map(|&p| u128::from(p)).sum();
    if total == 0 {
        return vec![0; parts.len()];
    }
    let scale = u128::from(PERMILLE_TOTAL);
    let mut shares: Vec<u16> = Vec::with_capacity(parts.len());
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(parts.len());
    for (i, &p) in parts.iter().enumerate() {
        let scaled = u128::from(p) * scale;
        shares.push(u16::try_from(scaled / total).unwrap_or(PERMILLE_TOTAL));
        remainders.push((scaled % total, i));
    }
    let given: u16 = shares.iter().sum();
    let leftover = usize::from(PERMILLE_TOTAL - given);
    remainders.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for &(_, i) in remainders.iter().take(leftover) {
        if let Some(share) = shares.get_mut(i) {
            *share += 1;
        }
    }
    shares
}

/// Formats milliseconds for people, deterministic and overflow-safe.
///
/// Under a second: `750ms`. Under a minute: `12.3s`, truncated to tenths.
/// Under an hour: `2m 05s`. Otherwise `1h 02m 05s`, where hours are not wrapped
/// into days. Sub-second parts of a minute or more are dropped.
#[must_use]
pub fn human_duration_ms(ms: u64) -> String {
    let secs = ms / 1000;
    if secs == 0 {
        return format!("{ms}ms");
    }
    if secs < 60 {
        return format!("{secs}.{}s", (ms % 1000) / 100);
    }
    if secs < 3600 {
        return format!("{}m {:02}s", secs / 60, secs % 60);
    }
    format!(
        "{}h {:02}m {:02}s",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Formats a [`std::time::Duration`] like [`human_duration_ms`], saturating at `u64::MAX` ms.
#[must_use]
pub fn human_duration(d: std::time::Duration) -> String {
    human_duration_ms(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Pairs<'a> = &'a [(u64, u64)];

    fn iv(a: u64, b: u64) -> Interval {
        Interval::new(a, b).expect("ordered bounds")
    }

    fn ivs(pairs: &[(u64, u64)]) -> Vec<Interval> {
        pairs.iter().map(|&(a, b)| iv(a, b)).collect()
    }

    #[test]
    fn new_rejects_reversed() {
        assert_eq!(Interval::new(5, 4), Err(IntervalError::Reversed));
        assert_eq!(Interval::new(u64::MAX, 0), Err(IntervalError::Reversed));
    }

    #[test]
    fn new_accepts_equal_and_ordered() {
        assert_eq!(Interval::new(7, 7).map(|i| i.len_ms()), Ok(0));
        assert_eq!(
            Interval::new(3, 9).map(|i| (i.start_ms(), i.end_ms())),
            Ok((3, 9))
        );
    }

    #[test]
    fn len_and_empty() {
        assert_eq!(iv(3, 9).len_ms(), 6);
        assert!(!iv(3, 9).is_empty());
        assert!(iv(4, 4).is_empty());
        assert_eq!(iv(0, u64::MAX).len_ms(), u64::MAX);
    }

    #[test]
    fn merge_table() {
        let max = u64::MAX;
        let cases: &[(&str, Pairs<'_>, Pairs<'_>)] = &[
            ("empty", &[], &[]),
            ("single", &[(1, 5)], &[(1, 5)]),
            ("touching", &[(1, 5), (5, 9)], &[(1, 9)]),
            ("touching unsorted", &[(5, 9), (1, 5)], &[(1, 9)]),
            ("overlapping", &[(1, 6), (4, 9)], &[(1, 9)]),
            ("nested", &[(1, 10), (3, 4), (5, 6)], &[(1, 10)]),
            ("duplicate", &[(2, 4), (2, 4), (2, 4)], &[(2, 4)]),
            ("disjoint", &[(10, 12), (1, 3)], &[(1, 3), (10, 12)]),
            ("zero length alone", &[(5, 5)], &[]),
            ("zero length inside", &[(1, 9), (4, 4)], &[(1, 9)]),
            (
                "zero length between",
                &[(1, 3), (5, 5), (7, 9)],
                &[(1, 3), (7, 9)],
            ),
            ("max full", &[(0, max)], &[(0, max)]),
            ("max touching", &[(0, max - 1), (max - 1, max)], &[(0, max)]),
            (
                "max tail disjoint",
                &[(0, 1), (max - 1, max)],
                &[(0, 1), (max - 1, max)],
            ),
            ("max zero length", &[(max, max)], &[]),
            (
                "chain",
                &[(1, 2), (2, 3), (3, 4), (6, 7)],
                &[(1, 4), (6, 7)],
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(merge(&ivs(input)), ivs(want), "{name}");
        }
    }

    #[test]
    fn subtract_table() {
        let max = u64::MAX;
        let cases: &[(&str, Pairs<'_>, Pairs<'_>, Pairs<'_>)] = &[
            ("empty both", &[], &[], &[]),
            ("empty set", &[], &[(1, 5)], &[]),
            ("empty cut", &[(1, 5)], &[], &[(1, 5)]),
            ("disjoint cut", &[(1, 5)], &[(7, 9)], &[(1, 5)]),
            ("cut touching start", &[(5, 9)], &[(1, 5)], &[(5, 9)]),
            ("cut touching end", &[(1, 5)], &[(5, 9)], &[(1, 5)]),
            ("cut covers all", &[(3, 5)], &[(1, 9)], &[]),
            ("cut equal", &[(3, 5)], &[(3, 5)], &[]),
            (
                "cut inside splits",
                &[(1, 10)],
                &[(4, 6)],
                &[(1, 4), (6, 10)],
            ),
            ("cut overlaps head", &[(1, 10)], &[(0, 4)], &[(4, 10)]),
            ("cut overlaps tail", &[(1, 10)], &[(8, 20)], &[(1, 8)]),
            (
                "many cuts",
                &[(0, 10)],
                &[(2, 3), (5, 6), (8, 9)],
                &[(0, 2), (3, 5), (6, 8), (9, 10)],
            ),
            (
                "duplicate cuts",
                &[(0, 10)],
                &[(2, 4), (2, 4)],
                &[(0, 2), (4, 10)],
            ),
            (
                "nested cuts",
                &[(0, 10)],
                &[(2, 8), (4, 6)],
                &[(0, 2), (8, 10)],
            ),
            (
                "overlapping set",
                &[(0, 6), (4, 10)],
                &[(5, 7)],
                &[(0, 5), (7, 10)],
            ),
            ("zero length cut", &[(0, 10)], &[(5, 5)], &[(0, 10)]),
            ("zero length set", &[(5, 5)], &[(0, 10)], &[]),
            (
                "max whole minus middle",
                &[(0, max)],
                &[(1, max - 1)],
                &[(0, 1), (max - 1, max)],
            ),
            ("max whole minus whole", &[(0, max)], &[(0, max)], &[]),
            (
                "max cut tail",
                &[(0, max)],
                &[(max - 1, max)],
                &[(0, max - 1)],
            ),
        ];
        for (name, set, cut, want) in cases {
            assert_eq!(subtract(&ivs(set), &ivs(cut)), ivs(want), "{name}");
        }
    }

    #[test]
    fn clamp_table() {
        let max = u64::MAX;
        let cases: &[(&str, Pairs<'_>, (u64, u64), Pairs<'_>)] = &[
            ("empty", &[], (0, 10), &[]),
            ("inside", &[(2, 5)], (0, 10), &[(2, 5)]),
            ("head cut", &[(0, 5)], (3, 10), &[(3, 5)]),
            ("tail cut", &[(5, 15)], (0, 10), &[(5, 10)]),
            ("both cut", &[(0, 20)], (5, 10), &[(5, 10)]),
            ("before window", &[(0, 3)], (5, 10), &[]),
            ("after window", &[(11, 15)], (5, 10), &[]),
            ("touching window start", &[(0, 5)], (5, 10), &[]),
            ("touching window end", &[(10, 12)], (5, 10), &[]),
            ("empty window", &[(0, 20)], (7, 7), &[]),
            (
                "overlapping merged",
                &[(0, 8), (6, 12)],
                (2, 10),
                &[(2, 10)],
            ),
            ("duplicates", &[(3, 6), (3, 6)], (0, 10), &[(3, 6)]),
            (
                "disjoint some outside",
                &[(0, 1), (4, 6), (20, 30)],
                (3, 10),
                &[(4, 6)],
            ),
            ("zero length inside", &[(5, 5)], (0, 10), &[]),
            ("max window", &[(0, max)], (0, max), &[(0, max)]),
            ("max into small", &[(0, max)], (10, 20), &[(10, 20)]),
            (
                "max tail",
                &[(max - 5, max)],
                (max - 3, max),
                &[(max - 3, max)],
            ),
        ];
        for (name, set, (ws, we), want) in cases {
            assert_eq!(clamp(&ivs(set), iv(*ws, *we)), ivs(want), "{name}");
        }
    }

    #[test]
    fn covered_ms_table() {
        let max = u64::MAX;
        let cases: &[(&str, Pairs<'_>, u64)] = &[
            ("empty", &[], 0),
            ("single", &[(1, 5)], 4),
            ("duplicate", &[(1, 5), (1, 5)], 4),
            ("overlap", &[(0, 6), (4, 10)], 10),
            ("disjoint", &[(0, 2), (5, 8)], 5),
            ("zero length", &[(3, 3)], 0),
            ("max", &[(0, max)], max),
            ("max overlapping pair", &[(0, max), (0, max)], max),
            ("max split", &[(0, 1), (1, max)], max),
        ];
        for (name, set, want) in cases {
            assert_eq!(covered_ms(&ivs(set)), *want, "{name}");
        }
    }

    #[test]
    fn subtract_partitions_set() {
        let set = ivs(&[(0, 100), (50, 150)]);
        let cut = ivs(&[(10, 20), (60, 70), (140, 200)]);
        let left = subtract(&set, &cut);
        let inter = subtract(&set, &left);
        assert_eq!(covered_ms(&left) + covered_ms(&inter), covered_ms(&set));
        assert_eq!(subtract(&left, &cut), left);
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    fn sp(kind: SpanKind, a: u64, b: u64) -> Span {
        Span {
            kind,
            interval: iv(a, b),
        }
    }

    fn agg(spans: &[Span]) -> Summary {
        aggregate(spans, iv(0, 100), iv(10, 90))
    }

    #[test]
    fn five_parts_sum_to_wall_for_generated_cases() {
        let kinds = [
            SpanKind::Shell,
            SpanKind::BgShell,
            SpanKind::Tool,
            SpanKind::ApiWait,
        ];
        let mut rng = Lcg(0x5eed);
        for case in 0..10_000 {
            let js = rng.next() % 500;
            let je = js + rng.next() % 500;
            let agent_start = js.saturating_sub(50) + rng.next() % 600;
            let agent_end = agent_start + rng.next() % 600;
            let n = rng.next() % 12;
            let spans: Vec<Span> = (0..n)
                .map(|_| {
                    let from = rng.next() % 1200;
                    let to = from + rng.next() % 300;
                    sp(kinds[(rng.next() % 4) as usize], from, to)
                })
                .collect();
            let job = iv(js, je);
            let sum = aggregate(&spans, job, iv(agent_start, agent_end));
            assert_eq!(sum.total_ms(), job.len_ms(), "case {case}");
        }
    }

    #[test]
    fn empty_spans_are_all_idle_and_overhead() {
        let s = agg(&[]);
        assert_eq!((s.idle_ms, s.overhead_ms), (80, 20));
        assert_eq!((s.api_wait_ms, s.tool_ms, s.shell_ms), (0, 0, 0));
    }

    #[test]
    fn precedence_shell_over_tool() {
        let s = agg(&[sp(SpanKind::Shell, 20, 40), sp(SpanKind::Tool, 20, 40)]);
        assert_eq!((s.shell_ms, s.tool_ms), (20, 0));
    }

    #[test]
    fn precedence_bgshell_over_tool() {
        let s = agg(&[sp(SpanKind::BgShell, 20, 40), sp(SpanKind::Tool, 20, 40)]);
        assert_eq!((s.shell_ms, s.tool_ms), (20, 0));
    }

    #[test]
    fn precedence_tool_over_api_wait() {
        let s = agg(&[sp(SpanKind::Tool, 20, 40), sp(SpanKind::ApiWait, 20, 40)]);
        assert_eq!((s.tool_ms, s.api_wait_ms), (20, 0));
    }

    #[test]
    fn precedence_shell_over_api_wait() {
        let s = agg(&[sp(SpanKind::Shell, 20, 40), sp(SpanKind::ApiWait, 20, 40)]);
        assert_eq!((s.shell_ms, s.api_wait_ms), (20, 0));
    }

    #[test]
    fn precedence_bgshell_over_api_wait() {
        let s = agg(&[sp(SpanKind::BgShell, 20, 40), sp(SpanKind::ApiWait, 20, 40)]);
        assert_eq!((s.shell_ms, s.api_wait_ms), (20, 0));
    }

    #[test]
    fn shell_and_bgshell_merge_into_one_part() {
        let s = agg(&[sp(SpanKind::Shell, 20, 40), sp(SpanKind::BgShell, 30, 50)]);
        assert_eq!(s.shell_ms, 30);
    }

    #[test]
    fn partial_overlap_splits_by_precedence() {
        let s = agg(&[
            sp(SpanKind::ApiWait, 10, 50),
            sp(SpanKind::Tool, 30, 60),
            sp(SpanKind::Shell, 50, 70),
        ]);
        assert_eq!(
            (
                s.api_wait_ms,
                s.tool_ms,
                s.shell_ms,
                s.idle_ms,
                s.overhead_ms
            ),
            (20, 20, 20, 20, 20)
        );
    }

    #[test]
    fn spans_outside_windows_are_clamped() {
        let s = agg(&[
            sp(SpanKind::Tool, 0, 20),
            sp(SpanKind::Shell, 80, 200),
            sp(SpanKind::ApiWait, 0, 5),
            sp(SpanKind::ApiWait, 95, 99),
        ]);
        assert_eq!(
            (
                s.api_wait_ms,
                s.tool_ms,
                s.shell_ms,
                s.idle_ms,
                s.overhead_ms
            ),
            (0, 10, 10, 60, 20)
        );
    }

    #[test]
    fn agent_window_clamped_to_job_window() {
        let s = aggregate(&[sp(SpanKind::Tool, 0, 500)], iv(100, 200), iv(50, 300));
        assert_eq!((s.tool_ms, s.idle_ms, s.overhead_ms), (100, 0, 0));
        let none = aggregate(&[sp(SpanKind::Tool, 0, 500)], iv(100, 200), iv(300, 400));
        assert_eq!((none.tool_ms, none.idle_ms, none.overhead_ms), (0, 0, 100));
    }

    fn summary(parts: [u64; 5]) -> Summary {
        Summary {
            api_wait_ms: parts[0],
            tool_ms: parts[1],
            shell_ms: parts[2],
            idle_ms: parts[3],
            overhead_ms: parts[4],
        }
    }

    fn cmd(text: &str) -> CommandInput {
        CommandInput {
            command: text.to_owned(),
            duration_ms: 5,
            start_ms: 1,
            exit: Some(0),
            truncated: false,
        }
    }

    #[test]
    fn fields_order_is_pinned() {
        let keys: Vec<&str> = FIELDS.iter().map(|f| f.key).collect();
        assert_eq!(
            keys,
            [
                "api_wait", "tool", "shell", "idle", "overhead", "total", "commands"
            ]
        );
        let labels: Vec<&str> = FIELDS.iter().map(|f| f.label).collect();
        assert_eq!(
            labels,
            [
                "API wait", "Tools", "Shell", "Idle", "Overhead", "Total", "Commands"
            ]
        );
    }

    #[test]
    fn fields_keys_are_unique() {
        for (i, a) in FIELDS.iter().enumerate() {
            for b in &FIELDS[i + 1..] {
                assert_ne!(a.key, b.key);
            }
        }
    }

    #[test]
    fn every_view_row_maps_to_exactly_one_field() {
        let view = TimingView::new(&summary([1, 2, 3, 4, 5]), &[]);
        assert_eq!(view.rows.len(), 5);
        for row in &view.rows {
            assert_eq!(FIELDS.iter().filter(|f| f.key == row.key).count(), 1);
        }
        let row_keys: Vec<&str> = view.rows.iter().map(|r| r.key).collect();
        let field_keys: Vec<&str> = FIELDS.iter().map(|f| f.key).collect();
        assert_eq!(row_keys[..], field_keys[..5]);
        assert_eq!(field_keys[5..], ["total", "commands"]);
    }

    #[test]
    fn view_carries_summary_and_total() {
        let view = TimingView::new(&summary([10, 20, 30, 40, 50]), &[]);
        let ms: Vec<u64> = view.rows.iter().map(|r| r.ms).collect();
        assert_eq!(ms, [10, 20, 30, 40, 50]);
        assert_eq!(view.total_ms, 150);
        assert_eq!(view.total_label(), "150ms");
    }

    #[test]
    fn permille_table() {
        let max = u64::MAX;
        let cases: &[(&str, &[u64], &[u16])] = &[
            ("empty", &[], &[]),
            ("all zero", &[0, 0, 0, 0, 0], &[0, 0, 0, 0, 0]),
            ("single", &[7], &[1000]),
            ("single among zeros", &[0, 9, 0], &[0, 1000, 0]),
            ("exact", &[1, 1, 1, 1], &[250, 250, 250, 250]),
            ("thirds", &[1, 1, 1], &[334, 333, 333]),
            ("remainder to largest", &[1, 2, 0], &[333, 667, 0]),
            (
                "tie to earlier",
                &[1, 1, 0, 1, 1, 1, 1],
                &[167, 167, 0, 167, 167, 166, 166],
            ),
            ("tiny part stays zero", &[1, 1_000_000], &[0, 1000]),
            ("max single", &[max, 0], &[1000, 0]),
            ("max pair", &[max, max], &[500, 500]),
            ("max and one", &[max, 1], &[1000, 0]),
            ("max triple", &[max, max, max], &[334, 333, 333]),
        ];
        for (name, parts, want) in cases {
            assert_eq!(permille_shares(parts), *want, "{name}");
        }
    }

    #[test]
    fn permille_sums_to_1000_for_generated_cases() {
        let mut rng = Lcg(0xfeed);
        for case in 0..10_000 {
            let n = 1 + (rng.next() % 8) as usize;
            let parts: Vec<u64> = (0..n)
                .map(|_| match rng.next() % 4 {
                    0 => 0,
                    1 => rng.next() % 10,
                    2 => rng.next() % 1_000_000,
                    _ => u64::MAX - rng.next() % 1000,
                })
                .collect();
            let shares = permille_shares(&parts);
            let sum: u32 = shares.iter().map(|&s| u32::from(s)).sum();
            if parts.iter().all(|&p| p == 0) {
                assert_eq!(sum, 0, "case {case}");
            } else {
                assert_eq!(sum, 1000, "case {case}");
            }
            for (p, s) in parts.iter().zip(&shares) {
                if *p == 0 {
                    assert_eq!(*s, 0, "case {case}");
                }
            }
        }
    }

    #[test]
    fn zero_duration_job_has_zero_percent_and_no_nan() {
        let view = TimingView::new(&Summary::default(), &[]);
        for row in &view.rows {
            assert_eq!(row.permille, 0);
            assert_eq!(row.percent_label(), "0.0%");
            assert_eq!(row.duration_label(), "0ms");
        }
        assert_eq!(view.total_ms, 0);
    }

    #[test]
    fn percent_label_has_one_decimal() {
        let view = TimingView::new(&summary([1, 1, 1, 0, 0]), &[]);
        let labels: Vec<String> = view.rows.iter().map(PartRow::percent_label).collect();
        assert_eq!(labels, ["33.4%", "33.3%", "33.3%", "0.0%", "0.0%"]);
        let full = TimingView::new(&summary([0, 0, 5, 0, 0]), &[]);
        assert_eq!(full.rows[2].percent_label(), "100.0%");
    }

    #[test]
    fn human_duration_table() {
        use std::time::Duration;
        let cases: &[(&str, u64, &str)] = &[
            ("zero", 0, "0ms"),
            ("one ms", 1, "1ms"),
            ("sub second", 999, "999ms"),
            ("one second", 1_000, "1.0s"),
            ("tenths truncate", 1_999, "1.9s"),
            ("seconds", 12_345, "12.3s"),
            ("just under minute", 59_999, "59.9s"),
            ("one minute", 60_000, "1m 00s"),
            ("minute and seconds", 125_000, "2m 05s"),
            ("just under hour", 3_599_999, "59m 59s"),
            ("one hour", 3_600_000, "1h 00m 00s"),
            ("hour mixed", 3_725_000, "1h 02m 05s"),
            ("hundred hours", 360_000_000, "100h 00m 00s"),
            ("max", u64::MAX, "5124095576030h 25m 51s"),
        ];
        for (name, ms, want) in cases {
            assert_eq!(human_duration_ms(*ms), *want, "{name}");
        }
        assert_eq!(human_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(human_duration(Duration::ZERO), "0ms");
        assert_eq!(human_duration(Duration::MAX), "5124095576030h 25m 51s");
    }

    #[test]
    fn command_rows_carry_fields() {
        let mut input = cmd("cargo test");
        input.exit = None;
        input.truncated = true;
        let view = TimingView::new(&Summary::default(), &[input, cmd("ls")]);
        assert_eq!(view.commands.len(), 2);
        assert_eq!(view.commands[0].command, "cargo test");
        assert_eq!(view.commands[0].exit, None);
        assert!(view.commands[0].truncated);
        assert_eq!(view.commands[1].exit, Some(0));
        assert!(!view.commands[1].truncated);
        assert_eq!(
            (view.commands[1].duration_ms, view.commands[1].start_ms),
            (5, 1)
        );
    }

    #[test]
    fn hostile_commands_hold_no_control_characters() {
        let cases: &[(&str, &str, &str)] = &[
            ("cr", "a\rb", "a\\u{d}b"),
            ("lf", "a\nb", "a\\u{a}b"),
            ("crlf", "a\r\nb", "a\\u{d}\\u{a}b"),
            ("esc", "\u{1b}[31mred", "\\u{1b}[31mred"),
            ("nul", "a\0b", "a\\u{0}b"),
            ("line separator", "a\u{2028}b", "a\\u{2028}b"),
            ("paragraph separator", "a\u{2029}b", "a\\u{2029}b"),
            ("nel", "a\u{85}b", "a\\u{85}b"),
            ("bidi override", "a\u{202e}b", "a\\u{202e}b"),
            ("tab", "a\tb", "a\\u{9}b"),
            ("plain", "echo héllo", "echo héllo"),
            ("empty", "", ""),
        ];
        for (name, input, want) in cases {
            let view = TimingView::new(&Summary::default(), &[cmd(input)]);
            let got = &view.commands[0];
            assert_eq!(got.command, *want, "{name}");
            assert!(!got.truncated, "{name}");
            assert!(
                !got.command
                    .chars()
                    .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'),
                "{name}"
            );
        }
    }

    #[test]
    fn long_command_is_cut_and_flagged() {
        let at_cap = "x".repeat(MAX_COMMAND_CHARS);
        let view = TimingView::new(&Summary::default(), &[cmd(&at_cap)]);
        assert_eq!(view.commands[0].command, at_cap);
        assert!(!view.commands[0].truncated);

        let over = "y".repeat(MAX_COMMAND_CHARS + 1);
        let view = TimingView::new(&Summary::default(), &[cmd(&over)]);
        assert_eq!(
            view.commands[0].command,
            format!("{}…", "y".repeat(MAX_COMMAND_CHARS))
        );
        assert!(view.commands[0].truncated);

        let huge = "é".repeat(1_000_000);
        let view = TimingView::new(&Summary::default(), &[cmd(&huge)]);
        assert_eq!(
            view.commands[0].command.chars().count(),
            MAX_COMMAND_CHARS + 1
        );
        assert!(view.commands[0].truncated);
    }

    #[test]
    fn upstream_truncated_flag_survives_a_short_command() {
        let mut input = cmd("short");
        input.truncated = true;
        let view = TimingView::new(&Summary::default(), &[input]);
        assert!(view.commands[0].truncated);
    }

    #[test]
    fn control_characters_cut_by_the_cap_still_escape() {
        let text = format!("{}\u{1b}tail", "z".repeat(MAX_COMMAND_CHARS - 1));
        let view = TimingView::new(&Summary::default(), &[cmd(&text)]);
        let got = &view.commands[0];
        assert!(got.command.starts_with(&"z".repeat(MAX_COMMAND_CHARS - 1)));
        assert!(got.command.contains("\\u{1b}"));
        assert!(got.truncated);
        assert!(!got.command.contains('\u{1b}'));
    }

    #[test]
    fn command_rows_are_capped_and_counted() {
        let many: Vec<CommandInput> = (0..MAX_COMMAND_ROWS + 3)
            .map(|i| cmd(&format!("c{i}")))
            .collect();
        let view = TimingView::new(&Summary::default(), &many);
        assert_eq!(view.commands.len(), MAX_COMMAND_ROWS);
        assert_eq!(view.commands_omitted, 3);
        assert_eq!(
            view.commands[MAX_COMMAND_ROWS - 1].command,
            format!("c{}", MAX_COMMAND_ROWS - 1)
        );
        let exact = TimingView::new(&Summary::default(), &many[..MAX_COMMAND_ROWS]);
        assert_eq!(exact.commands_omitted, 0);
    }
}
