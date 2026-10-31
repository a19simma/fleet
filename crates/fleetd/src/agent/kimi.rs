//! The Kimi Code runner (ADR-0044).
//!
//! Kimi runs non-interactively with the Floor set by the CLI permission mode: the per-job
//! config turns auto-approval off and no hooks are configured, so a deny cannot depend on a
//! hook running. fleetd assumes the CLI fails open when hooks are absent and so places no
//! trust in them. A per-job config directory holds `config.toml` and is removed when the job
//! ends. The only secret in the child environment is [`API_KEY_ENV`]; the config names that
//! variable and never holds the key. fleetd sets no `User-Agent`: traffic reaches the model
//! host through the `HTTPS_PROXY` CONNECT tunnel only.
//!
//! Unverified: every Kimi CLI flag and config key below was written without a Kimi CLI to
//! check against. That covers `--print`, `--output-format stream-json`, `--work-dir`,
//! `--model=`, `--prompt=`, the `KIMI_CODE_HOME` directory variable, the `KIMI_API_KEY`
//! variable name, the `default_yolo` key, the `[providers.kimi]` table with `type` and
//! `api_key_env`, the `sk-kimi-` key prefix (ADR-0043) and the model hosts in
//! [`AgentRunner::model_hosts`], which no source in the ADRs states. Also unverified: whether
//! `--print` implies auto-approve. The job path takes the stricter reading and runs a Kimi job
//! only on a disposable box. Confirm each against the installed CLI before relying on it.

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
pub const NAME: &str = "kimi";

/// Fixed failure message for a Kimi job on a box that is not disposable.
pub const ERR_NOT_DISPOSABLE: &str = "kimi needs a disposable box";

/// The environment variable that carries the Kimi credential. Unverified.
pub const API_KEY_ENV: &str = "KIMI_API_KEY";

/// The environment variable that points Kimi at its per-job directory. Unverified.
pub const HOME_ENV: &str = "KIMI_CODE_HOME";

/// The executable name used when no Kimi path is configured.
pub const DEFAULT_PROGRAM: &str = "kimi";

const KIMI_DIR: &str = ".kimi";
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

/// The Floor in `$KIMI_CODE_HOME/config.toml`.
///
/// `default_yolo = false` keeps auto-approval off. The provider names [`API_KEY_ENV`] so the
/// key stays out of the file. There is no hooks table. All keys are unverified.
pub const CONFIG_TOML: &str =
    "default_yolo = false\n\n[providers.kimi]\ntype = \"kimi\"\napi_key_env = \"KIMI_API_KEY\"\n";

const MODEL_HOSTS: &[&str] = &["api.moonshot.ai", "api.kimi.com"];

pub(super) struct Kimi;

impl AgentRunner for Kimi {
    fn name(&self) -> &'static str {
        NAME
    }

    fn program<'a>(&self, _config: &'a RunConfig) -> &'a Path {
        Path::new(DEFAULT_PROGRAM)
    }

    fn config_dir_env(&self) -> &'static str {
        HOME_ENV
    }

    fn model_hosts(&self) -> &'static [&'static str] {
        MODEL_HOSTS
    }
}

/// What one Kimi job runs with.
#[derive(Debug, Clone, Copy)]
pub struct KimiJob<'a> {
    /// The prompt, joined to `--prompt=` so a leading dash is never a flag.
    pub prompt: &'a str,
    /// The worktree the agent works in.
    pub cwd: &'a Path,
    /// The model, when the Profile sets one.
    pub model: Option<&'a str>,
}

/// The command line for `job`, with `program` first. Flags are unverified.
///
/// Passes no auto-approve flag, so the permission mode in the per-job config applies.
#[must_use]
pub fn argv(program: &Path, job: &KimiJob<'_>) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![program.as_os_str().to_owned()];
    argv.extend(["--print", "--output-format", "stream-json", "--work-dir"].map(OsString::from));
    argv.push(job.cwd.as_os_str().to_owned());
    if let Some(model) = job.model {
        argv.push(OsString::from(format!("--model={model}")));
    }
    argv.push(OsString::from(format!("--prompt={}", job.prompt)));
    argv
}

/// The complete child environment.
///
/// `base` is filtered to the allow list and `LC_*`, minus any forbidden name, so no host
/// secret passes. `api_key` becomes [`API_KEY_ENV`], the one secret. `home` is the per-job
/// `HOME` and `kimi_home` the per-job [`HOME_ENV`].
#[must_use]
pub fn env(
    base: &[(OsString, OsString)],
    api_key: &str,
    job_id: &str,
    home: &Path,
    kimi_home: &Path,
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
        (HOME_ENV, kimi_home.into()),
        ("XDG_CONFIG_HOME", home.join(".config").into()),
        ("XDG_CACHE_HOME", home.join(".cache").into()),
        ("GIT_TERMINAL_PROMPT", "0".into()),
        (API_KEY_ENV, api_key.into()),
    ];
    env.extend(fixed.map(|(name, value)| (OsString::from(name), value)));
    env
}

/// The per-job Kimi directory, `<root>/.kimi/<job id>`, removed on drop.
///
/// It holds the Floor config and whatever Kimi writes there while it runs.
#[derive(Debug)]
pub struct KimiHome {
    path: PathBuf,
}

impl KimiHome {
    /// Builds the directory with mode 0700 and its config 0600. A leftover of the same id is
    /// replaced.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the id is invalid or a file cannot be written. A partly
    /// built directory is removed first.
    pub fn create(root: &Path, job_id: &str) -> io::Result<Self> {
        validate_job_id(job_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = root.join(KIMI_DIR);
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
        fs::DirBuilder::new().mode(0o700).create(&self.path)?;
        let target = self.path.join(CONFIG_FILE);
        fs::write(&target, CONFIG_TOML)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
    }

    /// The directory, the value of [`HOME_ENV`].
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for KimiHome {
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
