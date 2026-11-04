//! The `fleet catalog` and `fleet user cap` commands.

use clap::Subcommand;
use tonic::Status;

use super::CliError;

/// A `fleet catalog` action.
#[derive(Debug, Subcommand)]
pub enum CatalogAction {
    /// List the catalog items.
    List,
    /// Create an item or add a version of one. Admin only.
    Upsert {
        /// Item kind: skill, subagent, tool or context.
        kind: String,
        /// Item id.
        id: String,
        /// Item name.
        name: String,
        /// File holding the item content, or `-` to read it from stdin.
        #[arg(long)]
        file: String,
    },
    /// Switch an item on for every profile. Admin only.
    Enable {
        /// Item id.
        id: String,
    },
    /// Switch an item off for every profile. Admin only.
    Disable {
        /// Item id.
        id: String,
    },
}

/// A `fleet user` area.
#[derive(Debug, Subcommand)]
pub enum UserArea {
    /// Grant, revoke and list the capabilities of a user. Admin only.
    Cap {
        /// The capability action.
        #[command(subcommand)]
        action: CapAction,
    },
}

/// A `fleet user cap` action.
#[derive(Debug, Subcommand)]
pub enum CapAction {
    /// List the capabilities a user holds.
    List {
        /// User id.
        user: u64,
    },
    /// Grant a capability to a user.
    Grant {
        /// User id.
        user: u64,
        /// Capability name, such as `profile:tools`.
        capability: String,
    },
    /// Revoke a capability from a user.
    Revoke {
        /// User id.
        user: u64,
        /// Capability name, such as `profile:tools`.
        capability: String,
    },
}

/// Runs a `fleet catalog` action.
///
/// # Errors
/// Returns an `UNIMPLEMENTED` [`CliError::Rpc`] until the command is built.
pub(crate) fn run(_action: &CatalogAction) -> Result<(), CliError> {
    Err(CliError::Rpc(Status::unimplemented(
        "fleet catalog is not implemented",
    )))
}

/// Runs a `fleet user` area.
///
/// # Errors
/// Returns an `UNIMPLEMENTED` [`CliError::Rpc`] until the command is built.
pub(crate) fn run_user(_area: &UserArea) -> Result<(), CliError> {
    Err(CliError::Rpc(Status::unimplemented(
        "fleet user cap is not implemented",
    )))
}
