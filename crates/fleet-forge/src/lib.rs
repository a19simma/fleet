//! The forge interface of ADR-0068: [`ForgeApi`] and [`ForgeGit`], the injected [`Http`] and
//! [`Git`] seams, in-process fake servers and the contract harness.
//!
//! No item here reads the environment. A caller injects a seam, and tests inject a [`fake::Fake`].
//! Adapters for GitHub and Forgejo land in later tasks and register with the harness in
//! `tests/contract.rs`.

mod api;
pub mod contract;
mod error;
pub mod fake;
mod model;
mod seam;

pub use api::{ForgeApi, ForgeGit};
pub use error::ForgeError;
pub use fleet_core::forge::CiResult;
pub use model::{Credential, Permission, PushTarget, RepoAccess, RepoRef, Token, Verified};
pub use seam::{
    Git, GitCommand, GitError, GitOp, GitOutput, Http, HttpError, HttpRequest, HttpResponse,
    MAX_BODY_BYTES, Method, REPO_CHECK_BUDGET,
};
