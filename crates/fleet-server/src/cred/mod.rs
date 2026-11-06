//! Credential storage support: sealing of secrets at rest (ADR-0040).

pub mod admin;
pub mod api;
pub mod app_jwt;
pub mod app_mint;
pub mod capability;
pub mod github;
pub mod limiter;
pub mod password;
pub mod seal;
pub mod store;
pub mod users;

pub use api::CredentialService;
pub use seal::{Aad, FileSealer, KeyRingError, SealError, Sealed, Sealer};
pub use users::{NewApiToken, SetupRedemption, UserError, Users};
