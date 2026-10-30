//! The Claude Code runner.

use std::path::Path;

use super::AgentRunner;
use crate::runner::RunConfig;

pub(super) const NAME: &str = "claude";

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
