//! Credential storage support: sealing of secrets at rest (ADR-0040).

pub mod seal;
pub mod store;
pub mod users;

pub use seal::{Aad, FileSealer, KeyRingError, SealError, Sealed, Sealer};
pub use users::{NewApiToken, UserError, Users};
