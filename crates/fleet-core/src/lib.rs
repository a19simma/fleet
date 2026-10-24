//! Domain types shared by fleetd, the server and the CLI.
//!
//! This crate performs no IO. Callers supply the clock, entropy and identity.

mod box_name;
mod ct;
mod envelope;
mod error;
mod id;
mod normalize;
mod redact;

pub use box_name::BoxName;
pub use ct::constant_time_eq;
pub use envelope::{Envelope, Identity, Priority, SCHEMA_VERSION, Source, kind};
pub use error::Error;
pub use id::EventId;
pub use normalize::{HookAllowlist, normalize_hook};
pub use redact::{MIN_SECRET_LEN, PLACEHOLDER, Redactor};
