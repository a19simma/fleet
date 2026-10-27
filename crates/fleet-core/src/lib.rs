//! Domain types shared by fleetd, the server and the CLI.
//!
//! This crate performs no IO. Callers supply the clock, entropy and identity.

mod box_name;
mod ct;
mod envelope;
mod error;
mod id;
mod normalize;
mod profile;
mod redact;
mod validate;

pub use box_name::BoxName;
pub use ct::constant_time_eq;
pub use envelope::{Envelope, Identity, Priority, SCHEMA_VERSION, Source, kind};
pub use error::Error;
pub use id::EventId;
pub use normalize::{HookAllowlist, normalize_hook};
pub use profile::{
    Attribution, ContextFile, EnvFlag, PROFILE_HASH_DOMAIN, Profile, ProfileError, ProfileHash,
    Settings, SettingsPermissions, Skill,
};
pub use redact::{MIN_SECRET_LEN, PLACEHOLDER, Redactor};
pub use validate::{
    ENV_FLAG_ALLOWLIST, MAX_BUDGET_CENTS, MAX_COMPONENT_BYTES, MAX_ENTRIES, MAX_FILE_BYTES,
    MAX_MODEL_BYTES, MAX_PATH_BYTES, MAX_RULE_BYTES, MAX_RULES, MAX_SKILL_NAME_LEN,
    MAX_TOTAL_BYTES, MAX_TURNS, ProfileInvalid,
};
