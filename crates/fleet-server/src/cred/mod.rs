//! Credential storage support: sealing of secrets at rest (ADR-0040).

pub mod seal;
pub mod store;

pub use seal::{Aad, FileSealer, KeyRingError, SealError, Sealed, Sealer};
