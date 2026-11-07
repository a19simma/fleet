//! Credentials, users and capabilities.
//!
//! Sealing of secrets at rest and the credential store (ADR-0040), credential kinds and shapes
//! with GitHub token verification (ADR-0043), the `FleetCredentials` handlers (`api`), the
//! GitHub App lane (ADR-0058: key and JWT in `app_jwt`, mint client in `app_mint`, allowlists
//! in `app_policy`, mint audit rows in `store`), users, API tokens and the setup code
//! (ADR-0042: `users`, `password`, `limiter`), per-user capabilities (`capability`) and the
//! `admin` subcommand.

pub mod admin;
pub mod api;
pub mod app_jwt;
pub mod app_mint;
pub mod app_policy;
pub mod capability;
pub mod github;
pub mod limiter;
pub mod password;
pub mod seal;
pub mod store;
#[cfg(test)]
mod store_app_tests;
pub mod users;

pub use api::CredentialService;
pub use seal::{Aad, FileSealer, KeyRingError, SealError, Sealed, Sealer};
pub use users::{NewApiToken, SetupRedemption, UserError, Users};
