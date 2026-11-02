//! The `fleet timing` command.

use tonic::Status;

use super::CliError;

/// Shows the timing breakdown of one job.
///
/// # Errors
/// Returns an `UNIMPLEMENTED` [`CliError::Rpc`] until the command is built.
pub(crate) fn run(_job: &str, _commands: bool, _json: bool) -> Result<(), CliError> {
    Err(CliError::Rpc(Status::unimplemented(
        "fleet timing is not implemented",
    )))
}
