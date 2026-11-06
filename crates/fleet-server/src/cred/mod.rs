//! Credentials, users and capabilities.
//!
//! Sealing of secrets at rest (ADR-0040), the credential store and its release path
//! (ADR-0043), the GitHub App lane with its mint client, policy and audit (ADR-0058), and the
//! user, token and capability stores.

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
