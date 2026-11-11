//! `pr_checks` of the broker, read through a [`ForgeApi`].
//!
//! [`ApiChecks`] holds one adapter and the Job's repo. A call checks the pull request URL against
//! the repo host, resolves the token for that host, asks [`ForgeApi::ci_checks`] and builds the
//! reply the agent reads: `{"checks":[{"bucket","name"}],"truncated":bool}`. The reply has no
//! `link`, since the adapter returns names and states only. Names are redacted and stripped of
//! hostile characters, and the reply is cut to [`MAX_OUTPUT_BYTES`]. The adapter refuses more than
//! [`MAX_CHECKS`] checks, so that case is a fixed error and never a truncated list. `pr_create`
//! always refuses: the real one is `PublishGh` in `crate::publish`, which wraps this executor.

use std::future::Future;
use std::sync::Arc;

use fleet_core::Redactor;
use fleet_core::text::{Cap, sanitise_text};
use fleet_forge::{
    CheckState, CiCheck, Credential, ForgeApi, MAX_CHECKS, RepoAccess, RepoRef, Token,
};
use fleet_proto::is_ci_url;
use serde::Serialize;

use crate::broker::{
    ExecError, GhExecutor, MAX_CHECK_NAME_CHARS, MAX_OUTPUT_BYTES, MAX_PR_URL_BYTES,
};
use crate::cred::TokenSource;

#[derive(Debug, Serialize)]
struct Check {
    bucket: &'static str,
    name: String,
}

#[derive(Debug, Serialize)]
struct Checks {
    checks: Vec<Check>,
    truncated: bool,
}

/// The `pr_checks` executor of one Job over a [`ForgeApi`].
pub struct ApiChecks<F> {
    forge: F,
    repo: RepoRef,
    base: String,
    token: String,
    source: Option<Arc<dyn TokenSource>>,
}

impl<F> std::fmt::Debug for ApiChecks<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiChecks")
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

impl<F: ForgeApi> ApiChecks<F> {
    /// An executor for the pull requests of `repo`, whose base branch is `base`, with `token` as
    /// the credential of the repo host.
    #[must_use]
    pub fn new(forge: F, repo: RepoRef, base: &str, token: String) -> Self {
        Self {
            forge,
            repo,
            base: base.to_owned(),
            token,
            source: None,
        }
    }

    /// Resolves the token from `source` on every call and holds its lease until the call ends,
    /// instead of the token given to [`ApiChecks::new`]. A refresh between two calls never
    /// leaves a call with a revoked token.
    #[must_use]
    pub fn with_token_source(mut self, source: Arc<dyn TokenSource>) -> Self {
        self.source = Some(source);
        self
    }

    fn subset(checks: &[CiCheck], redactor: &Redactor) -> Result<String, ExecError> {
        let mut shown = Checks {
            checks: Vec::new(),
            truncated: false,
        };
        for check in checks.iter().take(MAX_CHECKS) {
            shown.checks.push(Check {
                bucket: bucket_name(check.state()),
                name: check_name(redactor, Some(check.name())),
            });
            if serde_json::to_string(&shown).map_err(|_| ExecError)?.len() > MAX_OUTPUT_BYTES {
                shown.checks.pop();
                shown.truncated = true;
                break;
            }
        }
        serde_json::to_string(&shown).map_err(|_| ExecError)
    }
}

impl<F: ForgeApi> GhExecutor for Option<ApiChecks<F>> {
    fn pr_create(
        &self,
        _target: &crate::broker::PushTarget,
        _title: &str,
        _body: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        std::future::ready(Err(ExecError))
    }

    async fn pr_checks(
        &self,
        target: &crate::broker::PushTarget,
        pr_url: &str,
    ) -> Result<String, ExecError> {
        match self {
            Some(checks) => checks.pr_checks(target, pr_url).await,
            None => Err(ExecError),
        }
    }
}

impl<F: ForgeApi> GhExecutor for ApiChecks<F> {
    fn pr_create(
        &self,
        _target: &crate::broker::PushTarget,
        _title: &str,
        _body: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        std::future::ready(Err(ExecError))
    }

    async fn pr_checks(
        &self,
        target: &crate::broker::PushTarget,
        pr_url: &str,
    ) -> Result<String, ExecError> {
        if !on_host(pr_url, self.repo.host().as_str()) {
            return Err(ExecError);
        }
        let leased = match &self.source {
            Some(source) => Some(source.lease().await.map_err(|failure| {
                tracing::warn!(
                    reason = failure.reason(),
                    "broker token could not be resolved"
                );
                ExecError
            })?),
            None => None,
        };
        let text = leased
            .as_ref()
            .map_or(self.token.as_str(), crate::cred::LeasedToken::token);
        let token = Token::new(text.to_owned()).map_err(|_| ExecError)?;
        let access = RepoAccess::new(
            self.repo.clone(),
            Credential::new(self.repo.host().clone(), token),
        );
        let forge_target = fleet_forge::PushTarget::new(access, &target.branch(), &self.base)
            .map_err(|_| ExecError)?;
        let found = self
            .forge
            .ci_checks(&forge_target, pr_url)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "broker pr_checks failed");
                ExecError
            })?;
        let redactor = check_redactor(
            &self.token,
            leased.as_ref().map(crate::cred::LeasedToken::token),
        );
        drop(leased);
        Self::subset(&found, &redactor)
    }
}

const fn bucket_name(state: CheckState) -> &'static str {
    match state {
        CheckState::Neutral => "skipping",
        CheckState::Success => "pass",
        CheckState::Queued | CheckState::Running => "pending",
        CheckState::Failed => "fail",
    }
}

/// A redactor for check names: the static token, the leased token when one is in use, and every
/// installation token by shape.
fn check_redactor(token: &str, leased: Option<&str>) -> Redactor {
    Redactor::new([token, leased.unwrap_or_default()]).with_installation_tokens()
}

fn check_name(redactor: &Redactor, name: Option<&str>) -> String {
    sanitise_text(
        redactor,
        name.unwrap_or_default(),
        Cap::Chars(MAX_CHECK_NAME_CHARS),
    )
    .text
    .trim()
    .to_owned()
}

pub(super) fn on_host(url: &str, host: &str) -> bool {
    url.len() <= MAX_PR_URL_BYTES
        && is_ci_url(url)
        && url
            .strip_prefix("https://")
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .is_some_and(|found| found.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use fleet_core::host::HostName;
    use fleet_forge::{CheckState, CiCheck, ForgeError, RepoRef};

    use super::*;
    use crate::broker::PushTarget;
    use crate::forge::testing::{Call, StubForge};

    const TOKEN: &str = "ghp_brokertoken1234";
    const URL: &str = "https://github.com/o/r/pull/7";

    fn repo(host: &str) -> RepoRef {
        let host = HostName::normalise(host).expect("test host is valid");
        RepoRef::new(host, "o", "r").expect("test repo is valid")
    }

    fn check(name: &str, state: CheckState) -> CiCheck {
        CiCheck::new(name, state).expect("test check is valid")
    }

    fn checks(forge: StubForge) -> ApiChecks<StubForge> {
        ApiChecks::new(forge, repo("github.com"), "main", TOKEN.to_owned())
    }

    fn own() -> PushTarget {
        PushTarget::Own("job1".to_owned())
    }

    async fn reply(found: Vec<CiCheck>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let out = checks(StubForge::new(Ok(found)))
            .pr_checks(&own(), URL)
            .await
            .map_err(|_| "pr_checks failed")?;
        Ok(serde_json::from_str(&out)?)
    }

    #[tokio::test]
    async fn every_state_maps_to_its_bucket_in_forge_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = reply(vec![
            check("a", CheckState::Success),
            check("b", CheckState::Failed),
            check("c", CheckState::Queued),
            check("d", CheckState::Running),
            check("e", CheckState::Neutral),
        ])
        .await?;
        let got: Vec<(String, String)> = value["checks"]
            .as_array()
            .ok_or("checks")?
            .iter()
            .map(|c| (c["bucket"].to_string(), c["name"].to_string()))
            .collect();
        let want: Vec<(String, String)> = [
            ("pass", "a"),
            ("fail", "b"),
            ("pending", "c"),
            ("pending", "d"),
            ("skipping", "e"),
        ]
        .iter()
        .map(|(b, n)| (format!("{b:?}"), format!("{n:?}")))
        .collect();
        assert_eq!(got, want);
        assert_eq!(value["truncated"], false);
        for c in value["checks"].as_array().ok_or("checks")? {
            let mut keys: Vec<_> = c.as_object().ok_or("object")?.keys().cloned().collect();
            keys.sort();
            assert_eq!(keys, ["bucket", "name"]);
        }
        Ok(())
    }

    #[tokio::test]
    async fn names_are_redacted_and_cut_to_the_char_cap() -> Result<(), Box<dyn std::error::Error>>
    {
        let value = reply(vec![
            check(&format!("leak {TOKEN}"), CheckState::Success),
            check(&"n".repeat(300), CheckState::Success),
        ])
        .await?;
        let first = value["checks"][0]["name"].as_str().ok_or("name")?;
        assert!(!first.contains(TOKEN), "{first}");
        assert!(first.contains("[REDACTED]"), "{first}");
        let second = value["checks"][1]["name"].as_str().ok_or("name")?;
        assert_eq!(second.chars().count(), MAX_CHECK_NAME_CHARS);
        Ok(())
    }

    #[tokio::test]
    async fn the_installation_token_shape_is_redacted_from_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let leak = format!("ghs_{}", "a".repeat(36));
        let value = reply(vec![check(&format!("x {leak}"), CheckState::Failed)]).await?;
        let name = value["checks"][0]["name"].as_str().ok_or("name")?;
        assert!(!name.contains(&leak), "{name}");
        Ok(())
    }

    #[tokio::test]
    async fn the_reply_is_cut_to_the_byte_cap_and_marked_truncated()
    -> Result<(), Box<dyn std::error::Error>> {
        let wide = "\u{1d400}".repeat(MAX_CHECK_NAME_CHARS);
        let found: Vec<CiCheck> = (0..MAX_CHECKS)
            .map(|_| check(&wide, CheckState::Success))
            .collect();
        let out = checks(StubForge::new(Ok(found)))
            .pr_checks(&own(), URL)
            .await
            .map_err(|_| "pr_checks failed")?;
        assert!(out.len() <= MAX_OUTPUT_BYTES, "{}", out.len());
        let value: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(value["truncated"], true);
        let shown = value["checks"].as_array().map_or(0, Vec::len);
        assert!(shown > 0 && shown < MAX_CHECKS, "{shown}");
        Ok(())
    }

    #[tokio::test]
    async fn a_forge_error_is_the_fixed_exec_error_with_no_detail() {
        for error in [
            ForgeError::Malformed,
            ForgeError::Unavailable,
            ForgeError::NotFound,
            ForgeError::TooLarge,
            ForgeError::Timeout,
        ] {
            let got = checks(StubForge::new(Err(error)))
                .pr_checks(&own(), URL)
                .await;
            assert_eq!(got, Err(ExecError), "{error:?}");
        }
    }

    #[tokio::test]
    async fn a_url_that_is_not_a_pull_request_of_the_host_never_reaches_the_forge() {
        let forge = StubForge::new(Ok(Vec::new()));
        let exec = checks(forge.clone());
        let long = format!(
            "https://github.com/o/r/pull/{}",
            "7".repeat(MAX_PR_URL_BYTES)
        );
        for url in [
            "https://evil.example/o/r/pull/7",
            "https://github.com.evil.example/o/r/pull/7",
            "https://github.com@evil.example/o/r/pull/7",
            "http://github.com/o/r/pull/7",
            "https://github.com/o/r/pull/7 --repo x",
            "--json=x",
            "",
            long.as_str(),
        ] {
            assert_eq!(exec.pr_checks(&own(), url).await, Err(ExecError), "{url}");
        }
        assert_eq!(forge.calls(), Vec::new());
        assert!(exec.pr_checks(&own(), URL).await.is_ok());
        assert_eq!(forge.calls().len(), 1);
    }

    #[tokio::test]
    async fn the_github_adapter_refuses_a_url_that_is_not_a_pull_request_of_the_job_repo() {
        use fleet_forge::GitHubForge;
        use fleet_forge::fake::{Fake, Shape};
        let fake = Fake::new(Shape::GitHub);
        let repo = RepoRef::new(fake.host(), "octo", "widgets").expect("repo");
        let exec = ApiChecks::new(
            GitHubForge::new(fake.clone(), fake.clone()),
            repo,
            "main",
            TOKEN.to_owned(),
        );
        for url in [
            "https://github.com/octo/widgets/pull/7?x=1",
            "https://github.com/octo/widgets/pull/7#frag",
            "https://github.com/octo/widgets/pull/7/files",
            "https://github.com/octo/widgets/pull/x",
            "https://github.com/octo/widgets/pull/0",
            "https://github.com/octo/widgets/pull/-7",
        ] {
            assert_eq!(exec.pr_checks(&own(), url).await, Err(ExecError), "{url}");
        }
        for url in [
            "https://github.com/octo/widgets/issues/7",
            "https://github.com/octo/pull/7",
            "https://github.com/../widgets/pull/7",
            "https://github.com/other/widgets/pull/7",
            "https://github.com/octo/other/pull/7",
        ] {
            assert_eq!(exec.pr_checks(&own(), url).await, Err(ExecError), "{url}");
        }
        assert_eq!(fake.request_count(), 0);
    }

    #[tokio::test]
    async fn the_url_must_be_on_the_repo_host_of_a_non_github_job() {
        let forge = StubForge::new(Ok(Vec::new()));
        let exec = ApiChecks::new(forge.clone(), repo("git.example"), "main", TOKEN.to_owned());
        assert!(exec.pr_checks(&own(), URL).await.is_err());
        assert_eq!(forge.calls(), Vec::new());
        assert!(
            exec.pr_checks(&own(), "https://git.example/o/r/pull/7")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_call_carries_the_job_branch_base_url_and_token() {
        let forge = StubForge::new(Ok(Vec::new()));
        checks(forge.clone())
            .pr_checks(&own(), URL)
            .await
            .expect("call succeeds");
        assert_eq!(
            forge.calls(),
            [Call {
                token: TOKEN.to_owned(),
                branch: own().branch(),
                base: "main".to_owned(),
                url: URL.to_owned(),
            }]
        );
    }

    #[tokio::test]
    async fn pr_create_and_the_missing_adapter_are_refused() {
        let exec = checks(StubForge::new(Ok(Vec::new())));
        assert_eq!(exec.pr_create(&own(), "t", "b").await, Err(ExecError));
        let none: Option<ApiChecks<StubForge>> = None;
        assert_eq!(none.pr_checks(&own(), URL).await, Err(ExecError));
        assert_eq!(none.pr_create(&own(), "t", "b").await, Err(ExecError));
        let some = Some(exec);
        assert!(some.pr_checks(&own(), URL).await.is_ok());
        assert_eq!(some.pr_create(&own(), "t", "b").await, Err(ExecError));
    }
}
