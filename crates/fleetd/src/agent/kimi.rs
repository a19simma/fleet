//! The Kimi Code runner (ADR-0044).
//!
//! The argv and environment match the Kimi Code 2.4.1 CLI as run on a test box:
//! `kimi -p <prompt> --output-format stream-json [-m model]` in the job workdir. The model
//! provider comes from the `KIMI_MODEL_*` variables, so no config file is written: the per-job
//! `KIMI_CODE_HOME` directory is empty at start and is removed when the job ends. The only
//! secret in the child environment is [`API_KEY_ENV`]. fleetd sets no `User-Agent`: traffic
//! reaches the model host through the `HTTPS_PROXY` CONNECT tunnel only.
//!
//! `-p` mode asks for no approval and always runs under the auto policy, so a Kimi job runs
//! only on a disposable box ([`ERR_NOT_DISPOSABLE`]). No hook runs in the Kimi CLI, so a deny
//! cannot depend on one.
//!
//! Unverified: the `sk-kimi-` key prefix (ADR-0043), whether `-p` accepts a prompt that
//! starts with a dash, whether the static deny rules hold under the auto policy, and which
//! hosts besides [`AgentRunner::model_hosts`] the CLI contacts (auth, code and cdn hosts were
//! not observed by name).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use super::AgentRunner;
use crate::runner::{RunConfig, env_forbidden};
use crate::workspace::validate_job_id;

/// The `Job.agent` name of this runner.
pub const NAME: &str = "kimi";

/// Fixed failure message for a Kimi job on a box that is not disposable.
pub const ERR_NOT_DISPOSABLE: &str = "kimi needs a disposable box";

/// Fixed failure message for a Kimi job whose model name is not a plain identifier.
pub const ERR_BAD_MODEL: &str = "kimi model is not valid";

/// The environment variable that carries the Kimi credential.
pub const API_KEY_ENV: &str = "KIMI_MODEL_API_KEY";

/// The environment variable that points Kimi at its per-job directory.
pub const HOME_ENV: &str = "KIMI_CODE_HOME";

/// The model used when the Profile sets none.
pub const DEFAULT_MODEL: &str = "kimi-for-coding";

/// The longest model name accepted.
pub const MAX_MODEL_LEN: usize = 64;

const PROVIDER_TYPE: &str = "kimi";
const BASE_URL: &str = "https://api.kimi.ai/coding/v1";

/// The executable name used when no Kimi path is configured.
pub const DEFAULT_PROGRAM: &str = "kimi";

const KIMI_DIR: &str = ".kimi";

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

const MODEL_HOSTS: &[&str] = &["api.kimi.ai"];

/// The model name to run, or `None` for a name to refuse.
///
/// An unset `model` gives [`DEFAULT_MODEL`]. A set one passes when it is 1 to
/// [`MAX_MODEL_LEN`] ASCII letters, digits, `.`, `_`, `:`, `/` or `-` and does not start with
/// `-`. A refused name never reaches the argv or the environment.
#[must_use]
pub fn resolve_model(model: Option<&str>) -> Option<&str> {
    let Some(model) = model else {
        return Some(DEFAULT_MODEL);
    };
    let plain = !model.is_empty()
        && model.len() <= MAX_MODEL_LEN
        && !model.starts_with('-')
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
    plain.then_some(model)
}

pub(super) struct Kimi;

impl AgentRunner for Kimi {
    fn name(&self) -> &'static str {
        NAME
    }

    fn program<'a>(&self, config: &'a RunConfig) -> &'a Path {
        &config.kimi_bin
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
    /// The prompt, the argument after `-p`.
    pub prompt: &'a str,
    /// The model, when the Profile sets one.
    pub model: Option<&'a str>,
}

/// The command line for `job`, with `program` first.
///
/// The agent works in the process working directory, so the argv has no directory flag. Pass
/// a model that [`resolve_model`] accepted.
#[must_use]
pub fn argv(program: &Path, job: &KimiJob<'_>) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![program.as_os_str().to_owned()];
    argv.push(OsString::from("-p"));
    argv.push(OsString::from(job.prompt));
    argv.extend(["--output-format", "stream-json"].map(OsString::from));
    if let Some(model) = job.model {
        argv.extend(["-m", model].map(OsString::from));
    }
    argv
}

/// The complete child environment.
///
/// `base` is filtered to the allow list and `LC_*`, minus any forbidden name, so no host
/// secret passes. `api_key` becomes [`API_KEY_ENV`], the one secret, and `model` the model
/// name; pass one that [`resolve_model`] accepted. `home` is the per-job `HOME` and
/// `kimi_home` the per-job [`HOME_ENV`].
#[must_use]
pub fn env(
    base: &[(OsString, OsString)],
    api_key: &str,
    model: &str,
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
    let fixed: [(&str, OsString); 13] = [
        ("FLEET_JOB_ID", job_id.into()),
        ("SWARM_BOX", "1".into()),
        ("HOME", home.into()),
        (HOME_ENV, kimi_home.into()),
        ("XDG_CONFIG_HOME", home.join(".config").into()),
        ("XDG_CACHE_HOME", home.join(".cache").into()),
        ("GIT_TERMINAL_PROMPT", "0".into()),
        (API_KEY_ENV, api_key.into()),
        ("KIMI_MODEL_NAME", model.into()),
        ("KIMI_MODEL_PROVIDER_TYPE", PROVIDER_TYPE.into()),
        ("KIMI_MODEL_BASE_URL", BASE_URL.into()),
        ("KIMI_DISABLE_TELEMETRY", "1".into()),
        ("KIMI_CODE_NO_AUTO_UPDATE", "1".into()),
    ];
    env.extend(fixed.map(|(name, value)| (OsString::from(name), value)));
    env
}

/// The per-job Kimi directory, `<root>/.kimi/<job id>`, removed on drop.
///
/// It starts empty and holds whatever Kimi writes there while it runs.
#[derive(Debug)]
pub struct KimiHome {
    path: PathBuf,
}

impl KimiHome {
    /// Builds the empty directory with mode 0700. A leftover of the same id is replaced.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the id is invalid or the directory cannot be made.
    pub fn create(root: &Path, job_id: &str) -> io::Result<Self> {
        validate_job_id(job_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = root.join(KIMI_DIR);
        let path = parent.join(job_id);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)?;
        remove_if_present(&path)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self { path })
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
