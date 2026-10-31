//! The Claude Code runner.

use std::path::Path;

use fleet_core::credential::{CredentialKind, Secret};

use super::AgentRunner;
use crate::cred::JobCredentials;
use crate::runner::RunConfig;

/// The `Job.agent` name of this runner.
pub const NAME: &str = "claude";

/// The environment variable that carries an Anthropic API key.
pub const API_KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// The environment variable that carries a Claude subscription token.
pub const OAUTH_TOKEN_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// The model credential `held` gives Claude Code: the environment variable name and the secret.
///
/// An `anthropic_api_key` wins over a `claude_subscription_token` when both are held, so the
/// child never sees two. `None` when `held` has neither.
#[must_use]
pub fn model_env(held: &JobCredentials) -> Option<(&'static str, &Secret)> {
    held.get(CredentialKind::AnthropicApiKey)
        .map(|secret| (API_KEY_ENV, secret))
        .or_else(|| {
            held.get(CredentialKind::ClaudeSubscriptionToken)
                .map(|secret| (OAUTH_TOKEN_ENV, secret))
        })
}

const MODEL_HOSTS: &[&str] = &["api.anthropic.com"];

pub(super) struct Claude;

impl AgentRunner for Claude {
    fn name(&self) -> &'static str {
        NAME
    }

    fn program<'a>(&self, config: &'a RunConfig) -> &'a Path {
        &config.claude_bin
    }

    fn config_dir_env(&self) -> &'static str {
        "CLAUDE_CONFIG_DIR"
    }

    fn model_hosts(&self) -> &'static [&'static str] {
        MODEL_HOSTS
    }
}
