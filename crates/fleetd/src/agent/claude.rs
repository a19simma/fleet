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

/// Why [`TelemetryEnv::new`] refused its input. The text never carries the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryEnvError {
    /// The bearer token is empty, too short, too long or holds a byte outside visible ASCII.
    BadToken,
}

impl std::fmt::Display for TelemetryEnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("telemetry bearer token is not valid")
    }
}

impl std::error::Error for TelemetryEnvError {}

/// The `OTel` exporter variables of one Claude job (ADR-0055).
///
/// The endpoint is the in-namespace loopback address the forwarder serves. The token is held
/// as an env value only: `Debug` and the error type never show it, and it never reaches argv.
#[derive(Clone)]
pub struct TelemetryEnv {
    endpoint: String,
    headers: String,
}

impl std::fmt::Debug for TelemetryEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryEnv")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl TelemetryEnv {
    /// Builds the variables for the forwarder on `127.0.0.1:<port>` and the receiver `token`.
    ///
    /// # Errors
    ///
    /// [`TelemetryEnvError::BadToken`] when the receiver would refuse `token`. The receiver
    /// accepts any visible ASCII, including `,`, `=`, `"`, `\`, `$` and `'`, which can split the
    /// header or break env-file quoting. The systemd launcher therefore admits only
    /// `[A-Za-z0-9_-]` before it calls this.
    pub fn new(port: std::num::NonZeroU16, token: &str) -> Result<Self, TelemetryEnvError> {
        crate::otel::BearerToken::new(token).map_err(|_| TelemetryEnvError::BadToken)?;
        Ok(Self {
            endpoint: format!("http://127.0.0.1:{port}/v1/logs"),
            headers: format!("Authorization=Bearer {token}"),
        })
    }

    /// Sets every exporter variable in `env`, replacing any value already there.
    pub fn apply(
        &self,
        env: &mut std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    ) {
        for (name, value) in [
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "1"),
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", self.endpoint.as_str()),
            ("OTEL_EXPORTER_OTLP_HEADERS", self.headers.as_str()),
            ("OTEL_LOGS_EXPORT_INTERVAL", "1000"),
            ("OTEL_LOG_TOOL_DETAILS", "1"),
        ] {
            env.insert(name.into(), value.into());
        }
    }
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
