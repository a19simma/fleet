//! Test double: a [`ForgeApi`] that answers `ci_checks` from a fixed list and records what it was asked.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::host::{HostKind, HostName};
use fleet_forge::{CiCheck, CiResult, ForgeApi, ForgeError, PushTarget, RepoAccess, Verified};

/// One `ci_checks` call as the adapter saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The token the call carried.
    pub token: String,
    /// The Job branch.
    pub branch: String,
    /// The base branch.
    pub base: String,
    /// The pull request URL.
    pub url: String,
}

/// Answers `ci_checks` with `answer` after `delay` and records each call.
#[derive(Clone)]
pub struct StubForge {
    /// What every `ci_checks` call returns.
    pub answer: Result<Vec<CiCheck>, ForgeError>,
    /// How long a call takes.
    pub delay: Duration,
    /// The calls so far.
    pub calls: Arc<Mutex<Vec<Call>>>,
}

impl StubForge {
    /// A stub that answers `answer`.
    pub fn new(answer: Result<Vec<CiCheck>, ForgeError>) -> Self {
        Self {
            answer,
            delay: Duration::ZERO,
            calls: Arc::default(),
        }
    }

    /// The calls so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl ForgeApi for StubForge {
    fn identify(&self, _: &HostName) -> impl Future<Output = Result<HostKind, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::WrongKind))
    }

    fn verify(&self, _: &RepoAccess) -> impl Future<Output = Result<Verified, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::NotFound))
    }

    fn create_pr(
        &self,
        _: &PushTarget,
        _: &str,
        _: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Rejected))
    }

    fn ci_result(
        &self,
        _: &PushTarget,
        _: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Malformed))
    }

    async fn ci_checks(
        &self,
        target: &PushTarget,
        pr_url: &str,
    ) -> Result<Vec<CiCheck>, ForgeError> {
        let (_, token) = target.access().bind()?;
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Call {
                token: token.expose().to_owned(),
                branch: target.branch().to_owned(),
                base: target.base().to_owned(),
                url: pr_url.to_owned(),
            });
        tokio::time::sleep(self.delay).await;
        self.answer.clone()
    }
}
