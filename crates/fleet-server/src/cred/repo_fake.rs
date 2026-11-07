//! A [`RepoVerifier`] test double that models every state a real verifier reports.

use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::repo::{RepoRef, RepoVerdict};

use super::repo_verify::{RepoCredential, RepoRefusal, RepoVerifier};
use crate::config::HostConfig;

/// What a [`FakeVerifier`] does on every call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeState {
    /// Answers with this verdict.
    Verdict(RepoVerdict),
    /// Refuses with this reason.
    Refuse(RepoRefusal),
    /// Never answers, so the caller's budget decides: [`RepoRefusal::Timeout`].
    Hang,
}

/// A scripted [`RepoVerifier`]. It records how many calls it saw, and a missing credential is
/// [`RepoRefusal::NoCredential`] before the script runs, as in the real verifier.
#[derive(Debug)]
pub struct FakeVerifier {
    state: FakeState,
    calls: AtomicUsize,
}

impl FakeVerifier {
    /// A fake in `state`.
    pub fn new(state: FakeState) -> Self {
        Self {
            state,
            calls: AtomicUsize::new(0),
        }
    }

    /// The forge confirms the repository at its own path, readable, with `push` as reported.
    /// `None` models a forge that reports no `permissions` field.
    pub fn ok(canonical_path: &str, push: Option<bool>) -> Self {
        Self::new(FakeState::Verdict(RepoVerdict {
            canonical_path: canonical_path.to_owned(),
            read: true,
            push,
            login: None,
        }))
    }

    /// The forge reports a different canonical path than the one asked, as after a rename or a
    /// transfer.
    pub fn moved(canonical_path: &str) -> Self {
        Self::ok(canonical_path, Some(true))
    }

    /// The host is outside the list.
    pub fn not_allowed_host() -> Self {
        Self::new(FakeState::Refuse(RepoRefusal::NotAllowedHost))
    }

    /// The User has no credential for the host.
    pub fn no_credential() -> Self {
        Self::new(FakeState::Refuse(RepoRefusal::NoCredential))
    }

    /// The forge answered 401, 403 or 404.
    pub fn not_found_or_no_access() -> Self {
        Self::new(FakeState::Refuse(RepoRefusal::NotFoundOrNoAccess))
    }

    /// The forge is down, refused by vetting, or answered garbage.
    pub fn upstream_unavailable() -> Self {
        Self::new(FakeState::Refuse(RepoRefusal::UpstreamUnavailable))
    }

    /// The forge never answers.
    pub fn hanging() -> Self {
        Self::new(FakeState::Hang)
    }

    /// The forge's own report of a timeout.
    pub fn timed_out() -> Self {
        Self::new(FakeState::Refuse(RepoRefusal::Timeout))
    }

    /// How many calls the fake has seen.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl RepoVerifier for FakeVerifier {
    async fn verify(
        &self,
        _host: &HostConfig,
        credential: Option<&RepoCredential>,
        _repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if credential.is_none() {
            return Err(RepoRefusal::NoCredential);
        }
        match &self.state {
            FakeState::Verdict(verdict) => Ok(verdict.clone()),
            FakeState::Refuse(refusal) => Err(*refusal),
            FakeState::Hang => std::future::pending().await,
        }
    }
}
