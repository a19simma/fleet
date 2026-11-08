//! Domain types shared by fleetd, the server and the CLI.
//!
//! This crate performs no IO. Callers supply the clock, entropy and identity.

mod box_name;
pub mod capability;
pub mod catalog;
pub mod credential;
mod ct;
mod envelope;
mod error;
pub mod forge;
pub mod graph;
mod id;
pub mod model_allowlist;
mod normalize;
mod profile;
mod redact;
pub mod repo;
pub mod stamp;
pub mod text;
pub mod timing;
pub mod tools;
pub mod transcript;
mod validate;

pub use box_name::BoxName;
pub use credential::GITHUB_INSTALLATION_TOKEN_PREFIX;
pub use ct::constant_time_eq;
pub use envelope::{Envelope, Identity, Priority, SCHEMA_VERSION, Source, kind};
pub use error::Error;
pub use id::EventId;
pub use normalize::{HookAllowlist, normalize_hook};
pub use profile::{
    Attribution, ContextFile, EnvFlag, ItemId, MAX_PROMPT_TEXT_BYTES, MAX_SELECTION, OwnerId,
    OwnerIdError, PROFILE_HASH_DOMAIN, PROFILE_HASH_DOMAIN_V2, PROFILE_HASH_DOMAIN_V3, Profile,
    ProfileError, ProfileHash, PromptText, PromptTextError, Selection, SelectionError, Settings,
    SettingsPermissions, Skill, Visibility, VisibilityError,
};
pub use redact::{INSTALLATION_TOKEN_MIN_BODY, MIN_SECRET_LEN, PLACEHOLDER, Redactor};
pub use validate::{
    ENV_FLAG_ALLOWLIST, MAX_BUDGET_CENTS, MAX_COMPONENT_BYTES, MAX_ENTRIES, MAX_FILE_BYTES,
    MAX_MODEL_BYTES, MAX_PATH_BYTES, MAX_RULE_BYTES, MAX_RULES, MAX_SKILL_NAME_LEN, MAX_TOOLS,
    MAX_TOTAL_BYTES, MAX_TURNS, ProfileInvalid,
};
