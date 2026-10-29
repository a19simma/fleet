//! Forge-neutral types: the normalised CI outcome of a pull request and the forge error.
//!
//! This module performs no IO. [`CiResult::from_check_runs`] reads the body of the GitHub
//! `GET /repos/{owner}/{repo}/commits/{ref}/check-runs` endpoint.

use std::fmt;

use serde_json::Value;

/// The CI outcome of a pull request, whatever forge reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiResult {
    /// The pull request has no checks.
    NoChecks,
    /// At least one check waits to start and none failed or runs.
    Queued,
    /// At least one check runs and none failed.
    InProgress,
    /// Every check finished and at least one succeeded.
    Success,
    /// At least one check failed, timed out, was cancelled or needs action.
    Failure,
    /// Every check finished neutral, skipped or stale.
    Neutral,
}

/// Why a forge operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeError {
    /// The forge kind has no implementation.
    Unsupported,
    /// The operation failed. The detail is withheld.
    Failed,
}

impl fmt::Display for ForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "forge kind is not supported",
            Self::Failed => "forge operation failed",
        })
    }
}

impl std::error::Error for ForgeError {}

impl CiResult {
    /// Folds the check runs of a GitHub check-runs response into one result.
    ///
    /// A failing conclusion wins over everything, then a running check, then a queued one.
    /// A finished set is `Success` when any check succeeded and `Neutral` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Failed`] when `body` is not JSON with a `check_runs` list.
    pub fn from_check_runs(body: &str) -> Result<Self, ForgeError> {
        let value: Value = serde_json::from_str(body).map_err(|_| ForgeError::Failed)?;
        let runs = value
            .get("check_runs")
            .and_then(Value::as_array)
            .ok_or(ForgeError::Failed)?;
        if runs.is_empty() {
            return Ok(Self::NoChecks);
        }
        let mut failed = false;
        let mut running = false;
        let mut queued = false;
        let mut succeeded = false;
        for run in runs {
            let status = run.get("status").and_then(Value::as_str);
            let conclusion = run.get("conclusion").and_then(Value::as_str);
            match (status, conclusion) {
                (Some("completed"), Some("success")) => succeeded = true,
                (Some("completed"), Some("neutral" | "skipped" | "stale")) => {}
                (Some("completed"), _) => failed = true,
                (Some("in_progress"), _) => running = true,
                _ => queued = true,
            }
        }
        Ok(if failed {
            Self::Failure
        } else if running {
            Self::InProgress
        } else if queued {
            Self::Queued
        } else if succeeded {
            Self::Success
        } else {
            Self::Neutral
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn runs(items: &[&str]) -> String {
        format!(
            r#"{{"total_count":{},"check_runs":[{}]}}"#,
            items.len(),
            items.join(",")
        )
    }

    fn run(status: &str, conclusion: Option<&str>) -> String {
        let conclusion = conclusion.map_or_else(|| "null".to_owned(), |c| format!("\"{c}\""));
        format!(r#"{{"name":"build","status":"{status}","conclusion":{conclusion}}}"#)
    }

    fn fold(items: &[String]) -> Result<CiResult, ForgeError> {
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        CiResult::from_check_runs(&runs(&refs))
    }

    #[test]
    fn golden_check_runs_map_to_the_six_results() -> TestResult {
        assert_eq!(fold(&[])?, CiResult::NoChecks);
        assert_eq!(fold(&[run("queued", None)])?, CiResult::Queued);
        assert_eq!(fold(&[run("in_progress", None)])?, CiResult::InProgress);
        assert_eq!(
            fold(&[run("completed", Some("success"))])?,
            CiResult::Success
        );
        assert_eq!(
            fold(&[run("completed", Some("failure"))])?,
            CiResult::Failure
        );
        assert_eq!(
            fold(&[run("completed", Some("neutral"))])?,
            CiResult::Neutral
        );
        Ok(())
    }

    #[test]
    fn failure_beats_running_beats_queued_beats_success() -> TestResult {
        let ok = run("completed", Some("success"));
        let bad = run("completed", Some("timed_out"));
        let going = run("in_progress", None);
        let waiting = run("queued", None);
        assert_eq!(fold(&[ok.clone(), going.clone(), bad])?, CiResult::Failure);
        assert_eq!(
            fold(&[ok.clone(), waiting.clone(), going])?,
            CiResult::InProgress
        );
        assert_eq!(fold(&[ok.clone(), waiting])?, CiResult::Queued);
        assert_eq!(
            fold(&[ok, run("completed", Some("skipped"))])?,
            CiResult::Success
        );
        Ok(())
    }

    #[test]
    fn cancelled_and_action_required_fail_and_skipped_is_neutral() -> TestResult {
        for conclusion in ["cancelled", "action_required", "startup_failure"] {
            assert_eq!(
                fold(&[run("completed", Some(conclusion))])?,
                CiResult::Failure,
                "{conclusion}"
            );
        }
        assert_eq!(
            fold(&[run("completed", Some("skipped"))])?,
            CiResult::Neutral
        );
        Ok(())
    }

    #[test]
    fn a_body_without_a_check_runs_list_is_an_error() {
        for body in ["", "[]", "{}", r#"{"check_runs":3}"#] {
            assert_eq!(CiResult::from_check_runs(body), Err(ForgeError::Failed));
        }
    }
}
