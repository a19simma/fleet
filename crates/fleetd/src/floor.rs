//! The Floor and the Box ceilings, applied to a validated Profile as a pure function.
//!
//! No IO, clock or environment is read here. [`apply`] returns the [`Effective`] settings a job
//! runs with; wiring them into the argv is a later step.

use std::collections::BTreeSet;

use fleet_core::Profile;

/// The permission mode of every job.
pub const PERMISSION_MODE: &str = "dontAsk";

/// The fixed deny set. Every job denies all of it; a Profile can only add entries.
///
/// The `Bash(git push *)`, `Bash(gh *)`, `Edit`, `Write`, `NotebookEdit` and `MultiEdit` entries
/// are the argv floor in `runner.rs` (ADR-0024). `Bash(curl *)` is the deny in the default
/// `agent-config/settings.json`. `Bash(git push*)` closes the form without a space, and
/// `WebFetch` is denied because fetches go through the egress proxy (ADR-0031), not the tool.
pub const FLOOR_DENY: &[&str] = &[
    "Bash(git push *)",
    "Bash(git push*)",
    "Bash(gh *)",
    "Bash(curl *)",
    "WebFetch",
    "Edit",
    "Write",
    "NotebookEdit",
    "MultiEdit",
];

/// Per-box limits and defaults. Budgets are whole US cents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxCeilings {
    /// Turn limit used when the Profile sets none.
    pub default_max_turns: u32,
    /// Highest turn limit any job may run with.
    pub max_turns: u32,
    /// Budget used when the Profile sets none.
    pub default_max_budget_cents: u64,
    /// Highest budget any job may run with.
    pub max_budget_cents: u64,
}

/// The settings a job runs with after the Floor and the ceilings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The Floor deny set, then the Profile's extra deny entries in sorted order, no repeats.
    pub deny: Vec<String>,
    /// The Profile allow entries that no Floor deny entry covers, in their original order.
    pub allow: Vec<String>,
    /// The Profile allow entries a Floor deny entry covered, in their original order.
    pub dropped_allows: Vec<String>,
    /// Always [`PERMISSION_MODE`].
    pub permission_mode: &'static str,
    /// Requested or default turns, capped at the ceiling.
    pub max_turns: u32,
    /// Requested or default budget in cents, capped at the ceiling.
    pub max_budget_cents: u64,
    /// The Profile model, unchanged.
    pub model: Option<String>,
}

/// Whether the deny entry `deny` covers the allow entry `allow`.
///
/// Matching is on exact text: tool names are case and whitespace sensitive, as in claude. A
/// covered allow is dropped, so any doubt resolves to a drop.
///
/// - Identical strings are covered.
/// - A bare tool name (`WebFetch`) covers that name and that name followed by `(`.
/// - `Tool(prefix*)` covers `Tool(arg)` when `arg` starts with `prefix`, and `Tool(prefix2*)`
///   when `prefix2` starts with `prefix`. So `Bash(git push*)` also covers `Bash(git pushd*)`.
pub fn covers(deny: &str, allow: &str) -> bool {
    if deny == allow {
        return true;
    }
    let Some((deny_tool, deny_rest)) = deny.split_once('(') else {
        return allow
            .strip_prefix(deny)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('('));
    };
    let Some(prefix) = deny_rest
        .strip_suffix(')')
        .and_then(|inner| inner.strip_suffix('*'))
    else {
        return false;
    };
    let Some((allow_tool, allow_rest)) = allow.split_once('(') else {
        return false;
    };
    if allow_tool != deny_tool {
        return false;
    }
    let inner = allow_rest.strip_suffix(')').unwrap_or(allow_rest);
    let arg = inner.strip_suffix('*').unwrap_or(inner);
    arg.starts_with(prefix)
}

/// Applies the Floor and the Box ceilings to `profile`.
pub fn apply(profile: &Profile, ceilings: &BoxCeilings) -> Effective {
    let extra: BTreeSet<&str> = profile
        .deny
        .iter()
        .map(String::as_str)
        .filter(|entry| !FLOOR_DENY.contains(entry))
        .collect();
    let deny = FLOOR_DENY
        .iter()
        .copied()
        .chain(extra)
        .map(str::to_owned)
        .collect();
    let (dropped_allows, allow): (Vec<String>, Vec<String>) = profile
        .allow
        .iter()
        .cloned()
        .partition(|entry| FLOOR_DENY.iter().any(|deny| covers(deny, entry)));
    let mut seen = BTreeSet::new();
    let dropped_allows = dropped_allows
        .into_iter()
        .filter(|entry| seen.insert(entry.clone()))
        .collect();
    Effective {
        deny,
        allow,
        dropped_allows,
        permission_mode: PERMISSION_MODE,
        max_turns: profile
            .max_turns
            .unwrap_or(ceilings.default_max_turns)
            .min(ceilings.max_turns),
        max_budget_cents: profile
            .max_budget_usd
            .unwrap_or(ceilings.default_max_budget_cents)
            .min(ceilings.max_budget_cents),
        model: profile.model.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceilings() -> BoxCeilings {
        BoxCeilings {
            default_max_turns: 30,
            max_turns: 50,
            default_max_budget_cents: 500,
            max_budget_cents: 1000,
        }
    }

    fn profile(allow: &[&str], deny: &[&str]) -> Profile {
        Profile {
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            deny: deny.iter().map(|s| (*s).to_owned()).collect(),
            ..Profile::default()
        }
    }

    fn dropped(allow: &str) -> bool {
        apply(&profile(&[allow], &[]), &ceilings())
            .dropped_allows
            .iter()
            .any(|d| d == allow)
    }

    #[test]
    fn allow_of_git_push_wildcard_is_dropped() {
        let eff = apply(&profile(&["Bash(git push*)"], &[]), &ceilings());
        assert_eq!(eff.allow.len(), 0);
        assert_eq!(eff.dropped_allows, vec!["Bash(git push*)".to_owned()]);
    }

    #[test]
    fn allow_of_a_concrete_push_is_dropped() {
        assert!(dropped("Bash(git push origin main)"));
        assert!(dropped("Bash(git push *)"));
    }

    #[test]
    fn repeated_dropped_allows_are_listed_once() {
        let eff = apply(&profile(&["Edit", "Edit", "WebFetch"], &[]), &ceilings());
        assert_eq!(
            eff.dropped_allows,
            vec!["Edit".to_owned(), "WebFetch".to_owned()]
        );
    }

    #[test]
    fn allow_of_git_status_is_kept() {
        let eff = apply(&profile(&["Bash(git status)", "Read"], &[]), &ceilings());
        assert_eq!(
            eff.allow,
            vec!["Bash(git status)".to_owned(), "Read".to_owned()]
        );
        assert_eq!(eff.dropped_allows.len(), 0);
    }

    #[test]
    fn allow_of_edit_is_dropped_and_edit_like_names_are_kept() {
        assert!(dropped("Edit"));
        assert!(dropped("Edit(src/**)"));
        assert!(!dropped("EditFoo"));
        assert!(!dropped("edit"));
        assert!(!dropped("Bash"));
    }

    #[test]
    fn a_push_prefix_also_covers_git_pushd() {
        assert!(dropped("Bash(git pushd*)"));
        assert!(dropped("Bash(git pushd)"));
    }

    #[test]
    fn a_wider_allow_than_the_deny_prefix_is_kept() {
        assert!(!dropped("Bash(git pu*)"));
        assert!(!dropped("Bash(git *)"));
        assert!(!dropped("Bash(*)"));
    }

    #[test]
    fn tool_names_match_exactly() {
        assert!(!dropped("bash(git push*)"));
        assert!(!dropped("Bash (git push*)"));
        assert!(!dropped(" Bash(git push*)"));
    }

    #[test]
    fn webfetch_allow_is_dropped_with_or_without_arguments() {
        assert!(dropped("WebFetch"));
        assert!(dropped("WebFetch(domain:example.com)"));
    }

    #[test]
    fn every_floor_entry_as_an_allow_is_dropped() {
        for entry in FLOOR_DENY {
            assert!(dropped(entry), "{entry}");
        }
    }

    #[test]
    fn turns_above_the_ceiling_are_clamped() {
        let mut p = profile(&[], &[]);
        p.max_turns = Some(500);
        assert_eq!(apply(&p, &ceilings()).max_turns, 50);
    }

    #[test]
    fn turns_below_the_ceiling_are_kept() {
        let mut p = profile(&[], &[]);
        p.max_turns = Some(7);
        assert_eq!(apply(&p, &ceilings()).max_turns, 7);
    }

    #[test]
    fn absent_turns_use_the_box_default_and_a_high_default_is_clamped() {
        let p = profile(&[], &[]);
        assert_eq!(apply(&p, &ceilings()).max_turns, 30);
        let high = BoxCeilings {
            default_max_turns: 90,
            ..ceilings()
        };
        assert_eq!(apply(&p, &high).max_turns, 50);
    }

    #[test]
    fn budget_is_clamped_kept_and_defaulted() {
        let mut p = profile(&[], &[]);
        assert_eq!(apply(&p, &ceilings()).max_budget_cents, 500);
        p.max_budget_usd = Some(10_000);
        assert_eq!(apply(&p, &ceilings()).max_budget_cents, 1000);
        p.max_budget_usd = Some(25);
        assert_eq!(apply(&p, &ceilings()).max_budget_cents, 25);
        p.max_budget_usd = None;
        let high = BoxCeilings {
            default_max_budget_cents: 9000,
            ..ceilings()
        };
        assert_eq!(apply(&p, &high).max_budget_cents, 1000);
    }

    #[test]
    fn permission_mode_is_always_dont_ask() {
        let mut p = profile(&["Bash"], &["Bash(rm *)"]);
        assert_eq!(apply(&p, &ceilings()).permission_mode, "dontAsk");
        p = Profile::default();
        assert_eq!(apply(&p, &ceilings()).permission_mode, "dontAsk");
    }

    #[test]
    fn deny_holds_the_whole_floor_without_duplicates_for_any_input() {
        for p in [
            Profile::default(),
            profile(&[], &["Edit", "Bash(rm *)", "Bash(rm *)"]),
            profile(&["Edit"], &["Bash(git push *)"]),
        ] {
            let deny = apply(&p, &ceilings()).deny;
            for entry in FLOOR_DENY {
                assert!(deny.iter().any(|d| d == entry), "{entry}");
            }
            let unique: BTreeSet<&String> = deny.iter().collect();
            assert_eq!(unique.len(), deny.len());
        }
    }

    #[test]
    fn profile_deny_entries_are_kept() {
        let deny = apply(&profile(&[], &["Bash(rm *)", "Bash(ssh *)"]), &ceilings()).deny;
        assert!(deny.contains(&"Bash(rm *)".to_owned()));
        assert!(deny.contains(&"Bash(ssh *)".to_owned()));
        assert_eq!(deny.len(), FLOOR_DENY.len() + 2);
    }

    #[test]
    fn deny_is_stable_under_reordering() {
        let a = apply(
            &profile(&[], &["Bash(b *)", "Bash(a *)", "Bash(c *)"]),
            &ceilings(),
        );
        let b = apply(
            &profile(&[], &["Bash(c *)", "Bash(b *)", "Bash(a *)"]),
            &ceilings(),
        );
        assert_eq!(a.deny, b.deny);
    }

    #[test]
    fn model_passes_through() {
        let mut p = profile(&[], &[]);
        p.model = Some("m".to_owned());
        assert_eq!(apply(&p, &ceilings()).model.as_deref(), Some("m"));
        assert_eq!(apply(&Profile::default(), &ceilings()).model, None);
    }
}
