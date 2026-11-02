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
}
