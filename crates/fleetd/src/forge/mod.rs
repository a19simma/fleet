//! The forge interface of ADR-0045: push, open a pull request and read the CI result.
//!
//! [`GitHubForge`] wraps the existing broker executors and changes no behaviour. [`GiteaForge`]
//! is specified only and answers [`ForgeError::Unsupported`] to every operation.
//!
//! Today only the CI watch reads through [`Forge::ci_result`]. Nothing routes push or pull
//! request creation through a [`Forge`], and a [`GitHubForge`] bypasses `Broker::handle`: its
//! pacing, caps, input validation, redaction and dedupe do not apply to calls made on it.

use std::future::Future;

pub use fleet_core::forge::{CiResult, ForgeError};

use crate::broker::PushTarget;

mod gitea;
mod github;

pub use gitea::GiteaForge;
pub use github::GitHubForge;

/// The operations the broker needs from a forge. The target comes from the broker, never from
/// the agent.
///
/// An implementation takes any [`PushTarget`] and any `pr_url`. Validation of the job fields
/// that build the target, and the binding of `pr_url` to the pull request the job opened, live
/// in `Broker::handle` and in the caller that builds the target.
pub trait Forge: Send + Sync {
    /// Publishes the Job branch and returns a short status line.
    fn push(&self, target: &PushTarget) -> impl Future<Output = Result<String, ForgeError>> + Send;

    /// Opens a pull request from the target branch and returns its URL.
    fn create_pr(
        &self,
        target: &PushTarget,
        title: &str,
        body: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send;

    /// Reads the CI outcome of the pull request at `pr_url`.
    fn ci_result(
        &self,
        target: &PushTarget,
        pr_url: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send;
}
