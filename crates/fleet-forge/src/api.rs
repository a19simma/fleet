use std::future::Future;

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};

use crate::{ForgeError, PushTarget, RepoAccess, Verified};

/// The HTTP half of a forge (ADR-0068). It runs where the injected `Http` seam points: the
/// server for `identify` and `verify`, fleetd for the rest.
///
/// An implementation calls [`RepoAccess::bind`] before any request that carries a token, sends
/// the token to its own host only, follows no redirect, and returns a [`ForgeError`] that holds
/// no upstream text.
pub trait ForgeApi: Send + Sync {
    /// Probes whether `host` is a forge of this adapter's kind. The probe sends no credential.
    /// A host that answers as another kind, or not as a forge, is [`ForgeError::WrongKind`].
    fn identify(
        &self,
        host: &HostName,
    ) -> impl Future<Output = Result<HostKind, ForgeError>> + Send;

    /// Reads the repository. `Ok` means readable. A missing repository, a 401 and a 403 are all
    /// [`ForgeError::NotFound`], so the answer does not tell a hidden repository from a
    /// missing one.
    fn verify(
        &self,
        access: &RepoAccess,
    ) -> impl Future<Output = Result<Verified, ForgeError>> + Send;

    /// Opens a pull request from the target branch and returns its URL. When one is already open
    /// for the branch, returns the URL of the existing one.
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

/// The git half of a forge: fetch and push over HTTPS through the injected `Git` seam. fleetd
/// only.
pub trait ForgeGit: Send + Sync {
    /// Fetches the repository and returns a short status line.
    fn fetch(&self, access: &RepoAccess)
    -> impl Future<Output = Result<String, ForgeError>> + Send;

    /// Publishes the Job branch and returns a short status line.
    fn push(&self, target: &PushTarget) -> impl Future<Output = Result<String, ForgeError>> + Send;
}
