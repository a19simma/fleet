//! The agent CLI a Job runs under (ADR-0044).
//!
//! [`AgentRunner`] owns what differs between agent CLIs. Only `claude` exists; the
//! [`resolve`] table maps a `Job.agent` name to its runner.

mod claude;

use std::path::Path;

use crate::runner::RunConfig;

/// Fixed failure message for a Job whose `agent` names no runner.
pub const ERR_UNKNOWN_AGENT: &str = "agent is not supported";

/// What differs between agent CLIs.
pub trait AgentRunner: Send + Sync {
    /// The name a `Job.agent` carries for this runner.
    fn name(&self) -> &'static str;

    /// The executable that starts this agent.
    fn program<'a>(&self, config: &'a RunConfig) -> &'a Path;

    /// The environment variable that points the CLI at its config directory.
    fn config_dir_env(&self) -> &'static str;
}

/// The runner for the `agent` field of a Job.
///
/// An empty name comes from servers that predate the field and means `claude`. Any other
/// name that no runner claims returns `None`; the caller fails the Job with
/// [`ERR_UNKNOWN_AGENT`].
#[must_use]
pub fn resolve(agent: &str) -> Option<&'static dyn AgentRunner> {
    match agent {
        "" | claude::NAME => Some(&claude::Claude),
        _ => None,
    }
}
