use std::future::Future;

use serde::Deserialize;

use super::{CiResult, Forge, ForgeError};
use crate::broker::{GhExecutor, GitExecutor, PushTarget};

/// The GitHub forge: the existing broker executors behind [`Forge`], with no change of what
/// they run.
#[derive(Debug, Clone)]
pub struct GitHubForge<G, H> {
    git: G,
    gh: H,
}

impl<G, H> GitHubForge<G, H> {
    /// A forge over the git and `gh` executors of one Job.
    #[must_use]
    pub const fn new(git: G, gh: H) -> Self {
        Self { git, gh }
    }
}

#[derive(Deserialize)]
struct Listed {
    checks: Vec<Bucketed>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Deserialize)]
struct Bucketed {
    bucket: String,
}

/// Folds the `gh pr checks` buckets of the broker output into one [`CiResult`].
///
/// `fail` and `cancel` give `Failure`, then `pending` gives `InProgress`, an unknown bucket
/// gives `Queued`, `pass` gives `Success` and only `skipping` gives `Neutral`. An empty list
/// gives `NoChecks`.
///
/// A list the broker truncated hides checks, so without a visible `fail` or `cancel` it is
/// `Err(ForgeError::Failed)` and never a passing or pending result.
fn from_buckets(output: &str) -> Result<CiResult, ForgeError> {
    let listed: Listed = serde_json::from_str(output).map_err(|_| ForgeError::Failed)?;
    let has = |wanted: &[&str]| {
        listed
            .checks
            .iter()
            .any(|check| wanted.contains(&check.bucket.as_str()))
    };
    if listed.truncated && !has(&["fail", "cancel"]) {
        return Err(ForgeError::Failed);
    }
    Ok(if listed.checks.is_empty() {
        CiResult::NoChecks
    } else if has(&["fail", "cancel"]) {
        CiResult::Failure
    } else if has(&["pending"]) {
        CiResult::InProgress
    } else if listed
        .checks
        .iter()
        .any(|check| !matches!(check.bucket.as_str(), "pass" | "skipping"))
    {
        CiResult::Queued
    } else if has(&["pass"]) {
        CiResult::Success
    } else {
        CiResult::Neutral
    })
}

impl<G: GitExecutor, H: GhExecutor> Forge for GitHubForge<G, H> {
    async fn push(&self, target: &PushTarget) -> Result<String, ForgeError> {
        self.git.push(target).await.map_err(|_| ForgeError::Failed)
    }

    async fn create_pr(
        &self,
        target: &PushTarget,
        title: &str,
        body: &str,
    ) -> Result<String, ForgeError> {
        self.gh
            .pr_create(target, title, body)
            .await
            .map_err(|_| ForgeError::Failed)
    }

    fn ci_result(
        &self,
        target: &PushTarget,
        pr_url: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        let checks = self.gh.pr_checks(target, pr_url);
        async move {
            let output = checks.await.map_err(|_| ForgeError::Failed)?;
            from_buckets(&output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::ExecError;

    struct Fake;

    impl GitExecutor for Fake {
        fn push(
            &self,
            target: &PushTarget,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            std::future::ready(Ok(format!("push {}", target.branch())))
        }

        fn fetch(&self) -> impl Future<Output = Result<String, ExecError>> + Send {
            std::future::ready(Ok(String::new()))
        }
    }

    impl GhExecutor for Fake {
        fn pr_create(
            &self,
            target: &PushTarget,
            title: &str,
            body: &str,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            std::future::ready(Ok(format!("create {} {title} {body}", target.branch())))
        }

        fn pr_checks(
            &self,
            _target: &PushTarget,
            pr_url: &str,
        ) -> impl Future<Output = Result<String, ExecError>> + Send {
            std::future::ready(if pr_url == "refused" {
                Err(ExecError)
            } else {
                Ok(pr_url.to_owned())
            })
        }
    }

    fn checks(buckets: &[&str]) -> String {
        let items: Vec<String> = buckets
            .iter()
            .map(|b| format!(r#"{{"bucket":"{b}","name":"n"}}"#))
            .collect();
        format!(r#"{{"checks":[{}],"truncated":false}}"#, items.join(","))
    }

    #[tokio::test]
    async fn push_and_create_pr_pass_through_to_the_executors() {
        let forge = GitHubForge::new(Fake, Fake);
        let target = PushTarget::Own("job1".to_owned());
        assert_eq!(forge.push(&target).await.as_deref(), Ok("push swarm/job1"));
        assert_eq!(
            forge.create_pr(&target, "t", "b").await.as_deref(),
            Ok("create swarm/job1 t b")
        );
    }

    #[tokio::test]
    async fn buckets_map_to_the_six_results() {
        let forge = GitHubForge::new(Fake, Fake);
        let target = PushTarget::Own("job1".to_owned());
        let cases: [(&[&str], CiResult); 7] = [
            (&[], CiResult::NoChecks),
            (&["pending"], CiResult::InProgress),
            (&["mystery"], CiResult::Queued),
            (&["pass", "skipping"], CiResult::Success),
            (&["pass", "cancel"], CiResult::Failure),
            (&["fail"], CiResult::Failure),
            (&["skipping"], CiResult::Neutral),
        ];
        for (buckets, want) in cases {
            assert_eq!(
                forge.ci_result(&target, &checks(buckets)).await,
                Ok(want),
                "{buckets:?}"
            );
        }
    }

    fn truncated(buckets: &[&str]) -> String {
        checks(buckets).replace(r#""truncated":false"#, r#""truncated":true"#)
    }

    #[tokio::test]
    async fn a_truncated_list_never_reads_as_passing() {
        let forge = GitHubForge::new(Fake, Fake);
        let target = PushTarget::Own("job1".to_owned());
        let passes = vec!["pass"; 50];
        for buckets in [
            passes,
            vec!["pending"],
            vec!["mystery"],
            vec!["skipping"],
            vec![],
        ] {
            assert_eq!(
                forge.ci_result(&target, &truncated(&buckets)).await,
                Err(ForgeError::Failed),
                "{}",
                buckets.len()
            );
        }
    }

    #[tokio::test]
    async fn a_truncated_list_with_a_visible_failure_is_a_failure() {
        let forge = GitHubForge::new(Fake, Fake);
        let target = PushTarget::Own("job1".to_owned());
        for bad in ["fail", "cancel"] {
            assert_eq!(
                forge.ci_result(&target, &truncated(&["pass", bad])).await,
                Ok(CiResult::Failure),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_truncated_flag_reads_as_not_truncated() {
        let forge = GitHubForge::new(Fake, Fake);
        let target = PushTarget::Own("job1".to_owned());
        let body = r#"{"checks":[{"bucket":"pass","name":"n"}]}"#;
        assert_eq!(forge.ci_result(&target, body).await, Ok(CiResult::Success));
    }

    #[tokio::test]
    async fn a_refused_or_unreadable_read_fails() {
        let forge = GitHubForge::new(Fake, Fake);
        let target = PushTarget::Own("job1".to_owned());
        for url in ["refused", "not json"] {
            assert_eq!(forge.ci_result(&target, url).await, Err(ForgeError::Failed));
        }
    }
}
