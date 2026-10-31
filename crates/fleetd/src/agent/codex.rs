//! The Codex CLI runner (ADR-0044).
//!
//! Codex runs as `codex exec` with the Floor set by sandbox and approval settings, not by hooks:
//! the sandbox is `workspace-write` with network off, approvals are `never` and hooks are
//! disabled and never trusted. A per-job `CODEX_HOME` holds the rules file and is removed when
//! the job ends. The only secret in the child environment is `CODEX_API_KEY`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::AgentRunner;
use crate::runner::{RunConfig, env_forbidden};
use crate::workspace::validate_job_id;

/// The `Job.agent` name of this runner.
pub const NAME: &str = "codex";

/// The environment variable that carries the Codex credential.
pub const API_KEY_ENV: &str = "CODEX_API_KEY";

/// The environment variable that points Codex at its per-job home.
pub const HOME_ENV: &str = "CODEX_HOME";

/// The executable name used when no Codex path is configured.
pub const DEFAULT_PROGRAM: &str = "codex";

const SANDBOX: &str = "workspace-write";
const APPROVAL_OVERRIDE: &str = "approval_policy=\"never\"";
const HOOKS_OVERRIDE: &str = "features.hooks=false";
const NETWORK_OVERRIDE: &str = "sandbox_workspace_write.network_access=false";
const CODEX_DIR: &str = ".codex";
const RULES_DIR: &str = "rules";
const RULES_FILE: &str = "default.rules";
const CONFIG_FILE: &str = "config.toml";

const ENV_ALLOW: [&str; 9] = [
    "PATH",
    "LANG",
    "TERM",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// The Floor in `$CODEX_HOME/config.toml`.
///
/// The argv overrides the file, so a changed argv can still loosen what the file sets. The file
/// only covers a flag the argv leaves out.
pub const CONFIG_TOML: &str = "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n\n[features]\nhooks = false\n\n[sandbox_workspace_write]\nnetwork_access = false\n";

/// Extra `forbidden` command prefixes in `$CODEX_HOME/rules/default.rules`.
///
/// Codex treats a script with substitution as one invocation, so these rules narrow the plain
/// forms only. The sandbox with network off is the Floor.
pub const RULES: &str = "prefix_rule(pattern = [\"git\", \"push\"], decision = \"forbidden\", justification = \"the daemon publishes the branch\")\nprefix_rule(pattern = [\"gh\"], decision = \"forbidden\", justification = \"the daemon opens the pull request\")\nprefix_rule(pattern = [\"curl\"], decision = \"forbidden\", justification = \"fetches go through the egress proxy\")\n";

const MODEL_HOSTS: &[&str] = &["api.openai.com"];

pub(super) struct Codex;

impl AgentRunner for Codex {
    fn name(&self) -> &'static str {
        NAME
    }

    fn program<'a>(&self, config: &'a RunConfig) -> &'a Path {
        &config.codex_bin
    }

    fn config_dir_env(&self) -> &'static str {
        HOME_ENV
    }

    fn model_hosts(&self) -> &'static [&'static str] {
        MODEL_HOSTS
    }
}

/// What one Codex job runs with.
#[derive(Debug, Clone, Copy)]
pub struct CodexJob<'a> {
    /// The prompt, passed after `--` so a leading dash is never a flag.
    pub prompt: &'a str,
    /// The worktree the agent works in.
    pub cwd: &'a Path,
    /// The model, when the Profile sets one.
    pub model: Option<&'a str>,
}

/// The command line for `job`, with `program` first.
///
/// Passes no `--ignore-rules`, so the deny rules in `CODEX_HOME` apply, and no
/// `--dangerously-bypass-hook-trust` or `--dangerously-bypass-approvals-and-sandbox`.
#[must_use]
pub fn argv(program: &Path, job: &CodexJob<'_>) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![program.as_os_str().to_owned()];
    argv.extend(
        [
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--cd",
        ]
        .map(OsString::from),
    );
    argv.push(job.cwd.as_os_str().to_owned());
    argv.extend(["--sandbox", SANDBOX].map(OsString::from));
    for setting in [APPROVAL_OVERRIDE, HOOKS_OVERRIDE, NETWORK_OVERRIDE] {
        argv.extend(["-c", setting].map(OsString::from));
    }
    if let Some(model) = job.model {
        argv.extend(["--model", model].map(OsString::from));
    }
    argv.extend(["--", job.prompt].map(OsString::from));
    argv
}

/// The complete child environment.
///
/// `base` is filtered to [`ENV_ALLOW`] and `LC_*`, minus any forbidden name, so no host secret
/// passes. `api_key` becomes [`API_KEY_ENV`], the one secret. `home` is the per-job `HOME`
/// and `codex_home` the per-job [`HOME_ENV`].
#[must_use]
pub fn env(
    base: &[(OsString, OsString)],
    api_key: &str,
    job_id: &str,
    home: &Path,
    codex_home: &Path,
) -> BTreeMap<OsString, OsString> {
    let mut env: BTreeMap<OsString, OsString> = base
        .iter()
        .filter(|(name, _)| {
            name.to_str().is_some_and(|name| {
                !env_forbidden(name) && (ENV_ALLOW.contains(&name) || name.starts_with("LC_"))
            })
        })
        .cloned()
        .collect();
    let fixed: [(&str, OsString); 8] = [
        ("FLEET_JOB_ID", job_id.into()),
        ("SWARM_BOX", "1".into()),
        ("HOME", home.into()),
        (HOME_ENV, codex_home.into()),
        ("XDG_CONFIG_HOME", home.join(".config").into()),
        ("XDG_CACHE_HOME", home.join(".cache").into()),
        ("GIT_TERMINAL_PROMPT", "0".into()),
        (API_KEY_ENV, api_key.into()),
    ];
    env.extend(fixed.map(|(name, value)| (OsString::from(name), value)));
    env
}

/// The per-job `CODEX_HOME`, `<root>/.codex/<job id>`, removed on drop.
///
/// It holds the Floor config and rules, and whatever Codex writes there while it runs.
#[derive(Debug)]
pub struct CodexHome {
    path: PathBuf,
}

impl CodexHome {
    /// Builds the directory with mode 0700 and its files 0600. A leftover of the same id is
    /// replaced.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the id is invalid or a file cannot be written. A partly
    /// built directory is removed first.
    pub fn create(root: &Path, job_id: &str) -> io::Result<Self> {
        validate_job_id(job_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = root.join(CODEX_DIR);
        let path = parent.join(job_id);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)?;
        remove_if_present(&path)?;
        let home = Self { path };
        home.fill()?;
        Ok(home)
    }

    fn fill(&self) -> io::Result<()> {
        let rules = self.path.join(RULES_DIR);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&rules)?;
        for (target, body) in [
            (self.path.join(CONFIG_FILE), CONFIG_TOML),
            (rules.join(RULES_FILE), RULES),
        ] {
            fs::write(&target, body)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// The directory, the value of [`HOME_ENV`].
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CodexHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}
