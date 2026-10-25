//! Job workspaces: a bare mirror per repo and one git worktree per job.
//!
//! Every input is validated before git runs. Error messages are fixed text and never carry
//! the repo, ref, job id or git output.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::askpass;
use crate::group::GroupGuard;

const CACHE_DIR: &str = ".cache";
const BRANCH_PREFIX: &str = "swarm/";
const MAX_JOB_ID_LEN: usize = 64;
const HOME_DIR: &str = ".git-home";
const DEFAULT_REPO_HOST: &str = "github.com";
const PROTOCOLS: &str = "https";
const PROTOCOLS_WITH_FILE: &str = "file:https";
const MIRROR_CONFIG: &str =
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n";
const MIRROR_CONFIG_STAGING: &str = "config.fleetd-new";
const PINNED_CONFIG: [&str; 14] = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=",
    "-c",
    "http.followRedirects=false",
    "-c",
    "http.proxy=",
    "-c",
    "http.sslVerify=true",
    "-c",
    "http.curloptResolve=",
    "-c",
    "credential.helper=",
];

/// Longest a single git command may run before its process group is killed.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(300);

/// Which repos a job may name: https on an allowed host.
///
/// [`RepoPolicy::with_file_repos`] also admits `file://` urls and absolute paths. Only code
/// can turn it on: the config file and the environment have no key for it, so production
/// runs never accept a local repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPolicy {
    hosts: Vec<String>,
    token_host: Option<String>,
    allow_file: bool,
}

impl Default for RepoPolicy {
    fn default() -> Self {
        Self::new([DEFAULT_REPO_HOST])
    }
}

impl RepoPolicy {
    /// A policy that admits https repos on exactly `hosts`. No port is admitted. The token
    /// host is `github.com` when `hosts` lists it, else none.
    #[must_use]
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let hosts: Vec<String> = hosts.into_iter().map(Into::into).collect();
        let token_host = hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(DEFAULT_REPO_HOST))
            .then(|| DEFAULT_REPO_HOST.to_owned());
        Self {
            hosts,
            token_host,
            allow_file: false,
        }
    }

    /// Sets the one host whose credential prompts get the token. A host that is not an
    /// allowed host is dropped, so the token host is always one of [`RepoPolicy::hosts`].
    #[must_use]
    pub fn with_token_host(mut self, host: Option<String>) -> Self {
        self.token_host = host.filter(|h| self.allows_host(h));
        self
    }

    /// The host whose credential prompts get the token, if any.
    #[must_use]
    pub fn token_host(&self) -> Option<&str> {
        self.token_host.as_deref()
    }

    /// Also admits `file://` urls and absolute paths, and the `file` git transport. Meant
    /// for tests that serve a local bare repo.
    #[must_use]
    pub fn with_file_repos(mut self) -> Self {
        self.allow_file = true;
        self
    }

    /// The allowed hosts.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// True when `host` equals an allowed host, ignoring ASCII case.
    #[must_use]
    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
    }

    /// The value for `GIT_ALLOW_PROTOCOL` on a command that talks to the repo.
    #[must_use]
    pub fn protocols(&self) -> &'static str {
        if self.allow_file {
            PROTOCOLS_WITH_FILE
        } else {
            PROTOCOLS
        }
    }
}

/// Why a workspace could not be prepared.
#[derive(Debug)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// The repo is not https on an allowed host, is empty, starts with `-`, or uses a
    /// disallowed form. A host mismatch covers userinfo, ports and look-alike hosts.
    InvalidRepo,
    /// The base ref is empty, starts with `-` or is not a plain ref name.
    InvalidRef,
    /// The job id is not 1 to 64 bytes of ASCII letters, digits and `_`.
    InvalidJobId,
    /// A directory under the workspace root could not be created.
    Io(std::io::Error),
    /// A git command could not start or exited with failure.
    Git(&'static str),
    /// A git command ran past [`GIT_TIMEOUT`] and was killed.
    GitTimeout(&'static str),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRepo => write!(f, "repo url rejected"),
            Self::InvalidRef => write!(f, "base ref rejected"),
            Self::InvalidJobId => write!(f, "job id rejected"),
            Self::Io(_) => write!(f, "workspace directory error"),
            Self::Git(step) => write!(f, "git {step} failed"),
            Self::GitTimeout(step) => write!(f, "git {step} timed out"),
        }
    }
}

impl std::error::Error for WorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidRepo
            | Self::InvalidRef
            | Self::InvalidJobId
            | Self::Git(_)
            | Self::GitTimeout(_) => None,
        }
    }
}

/// A prepared job checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    /// Worktree directory, `<root>/<job_id>`.
    pub path: PathBuf,
    /// Branch created for the job, `swarm/<job_id>`.
    pub branch: String,
}

#[derive(Clone)]
struct Credential {
    askpass_bin: PathBuf,
    token: String,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("askpass_bin", &self.askpass_bin)
            .finish_non_exhaustive()
    }
}

/// Creates job worktrees under a configurable root.
#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
    git: PathBuf,
    timeout: Duration,
    policy: RepoPolicy,
    path_env: Option<OsString>,
    credential: Option<Credential>,
}

impl Workspace {
    /// A workspace rooted at `root`. Mirrors live in `<root>/.cache`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            git: PathBuf::from("git"),
            timeout: GIT_TIMEOUT,
            policy: RepoPolicy::default(),
            path_env: std::env::var_os("PATH"),
            credential: None,
        }
    }

    /// Lets the mirror fetch of a repo on the policy's token host authenticate through
    /// `<askpass_bin> askpass` with `token`. Only that one git child gets the token, never
    /// the init, worktree or prune calls. An empty token clears it.
    #[must_use]
    pub fn with_credential(mut self, askpass_bin: impl Into<PathBuf>, token: String) -> Self {
        self.credential = (!token.is_empty()).then(|| Credential {
            askpass_bin: askpass_bin.into(),
            token,
        });
        self
    }

    /// Uses `policy` to judge repos instead of the default, https on `github.com`.
    #[must_use]
    pub fn with_policy(mut self, policy: RepoPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Uses `git` as the git binary and `timeout` as the per-command limit.
    #[must_use]
    pub fn with_git(mut self, git: impl Into<PathBuf>, timeout: Duration) -> Self {
        self.git = git.into();
        self.timeout = timeout;
        self
    }

    /// Resets the bare mirror's config, fetches `repo` into it by explicit url, then runs
    /// `git worktree add -b swarm/<job_id>` from `origin/<base_ref>`.
    ///
    /// # Errors
    ///
    /// Returns a validation error before any process starts, or a fixed-message git or
    /// filesystem error.
    pub async fn prepare(
        &self,
        job_id: &str,
        repo: &str,
        base_ref: &str,
    ) -> Result<Checkout, WorkspaceError> {
        validate_job_id(job_id)?;
        validate_repo(repo, &self.policy)?;
        validate_ref(base_ref)?;

        let cache = self.root.join(CACHE_DIR);
        tokio::fs::create_dir_all(&cache)
            .await
            .map_err(WorkspaceError::Io)?;
        let mirror = self.mirror_path(repo);
        self.sync_mirror(&mirror, repo).await?;

        let path = self.root.join(job_id);
        let branch = format!("{BRANCH_PREFIX}{job_id}");
        let start = format!("origin/{base_ref}");
        self.git(
            &mirror,
            &[
                "worktree",
                "add",
                "-b",
                &branch,
                path.to_str().ok_or(WorkspaceError::InvalidJobId)?,
                &start,
            ],
            "worktree add",
        )
        .await?;
        Ok(Checkout { path, branch })
    }
}

impl Workspace {
    /// Removes the job's worktree and its `.finish-<job_id>` scratch dir, then prunes the
    /// mirror's worktree records. The bare mirror stays. Every step runs even when an
    /// earlier one fails.
    ///
    /// # Errors
    ///
    /// Returns the first failure, with fixed text that carries no path or id.
    pub async fn remove(&self, job_id: &str, repo: &str) -> Result<(), WorkspaceError> {
        validate_job_id(job_id)?;
        validate_repo(repo, &self.policy)?;
        let mut first = None;
        for path in [
            self.root.join(job_id),
            self.root.join(format!(".finish-{job_id}")),
        ] {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    first.get_or_insert(WorkspaceError::Io(err));
                }
            }
        }
        let mirror = self.mirror_path(repo);
        if mirror.join("HEAD").exists()
            && let Err(err) = self
                .git(&mirror, &["worktree", "prune"], "worktree prune")
                .await
        {
            first.get_or_insert(err);
        }
        first.map_or(Ok(()), Err)
    }

    fn mirror_path(&self, repo: &str) -> PathBuf {
        self.root
            .join(CACHE_DIR)
            .join(format!("{:x}.git", Sha256::digest(repo.as_bytes())))
    }

    async fn reset_mirror_config(mirror: &Path) -> Result<(), WorkspaceError> {
        if !mirror.join("HEAD").exists() {
            return Ok(());
        }
        let staging = mirror.join(MIRROR_CONFIG_STAGING);
        match tokio::fs::remove_file(&staging).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(WorkspaceError::Io(err)),
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .await
            .map_err(WorkspaceError::Io)?;
        file.write_all(MIRROR_CONFIG.as_bytes())
            .await
            .map_err(WorkspaceError::Io)?;
        drop(file);
        tokio::fs::rename(&staging, mirror.join("config"))
            .await
            .map_err(WorkspaceError::Io)
    }

    fn fetch_credential(&self, repo: &str) -> Option<(&Credential, &str)> {
        let credential = self.credential.as_ref()?;
        let token_host = self.policy.token_host()?;
        let authority = repo
            .strip_prefix("https://")?
            .split(['/', '?', '#'])
            .next()?;
        authority
            .eq_ignore_ascii_case(token_host)
            .then_some((credential, token_host))
    }

    async fn sync_mirror(&self, mirror: &Path, repo: &str) -> Result<(), WorkspaceError> {
        if !mirror.join("HEAD").exists() {
            let dir = mirror.to_str().ok_or(WorkspaceError::InvalidRepo)?;
            self.git(
                Path::new("."),
                &["init", "--bare", "--quiet", "--", dir],
                "init",
            )
            .await?;
        }
        Self::reset_mirror_config(mirror).await?;
        self.run_git(
            mirror,
            &[
                "fetch",
                "--prune",
                "--quiet",
                "--",
                repo,
                "+refs/heads/*:refs/remotes/origin/*",
            ],
            "fetch",
            self.fetch_credential(repo),
        )
        .await
    }

    async fn git(
        &self,
        dir: &Path,
        args: &[&str],
        step: &'static str,
    ) -> Result<(), WorkspaceError> {
        self.run_git(dir, args, step, None).await
    }

    async fn run_git(
        &self,
        dir: &Path,
        args: &[&str],
        step: &'static str,
        credential: Option<(&Credential, &str)>,
    ) -> Result<(), WorkspaceError> {
        let home = self.root.join(HOME_DIR);
        tokio::fs::create_dir_all(&home)
            .await
            .map_err(WorkspaceError::Io)?;
        let mut command = Command::new(&self.git);
        command.env_clear();
        if let Some(path) = &self.path_env {
            command.env("PATH", path);
        }
        if let Some((credential, host)) = credential {
            command
                .env("GIT_ASKPASS", askpass::command(&credential.askpass_bin))
                .env(askpass::HOST_ENV, host)
                .env("GH_TOKEN", &credential.token);
        }
        let mut child = command
            .arg("-C")
            .arg(dir)
            .args(PINNED_CONFIG)
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ALLOW_PROTOCOL", self.policy.protocols())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| WorkspaceError::Git(step))?;
        let mut guard = GroupGuard::new(child.id());
        let waited = tokio::time::timeout(self.timeout, child.wait()).await;
        guard.kill();
        match waited {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(_) => Err(WorkspaceError::Git(step)),
            Err(_) => {
                let _ = child.wait().await;
                Err(WorkspaceError::GitTimeout(step))
            }
        }
    }
}

pub(crate) fn validate_job_id(id: &str) -> Result<(), WorkspaceError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_JOB_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidJobId)
    }
}

pub(crate) fn validate_repo(repo: &str, policy: &RepoPolicy) -> Result<(), WorkspaceError> {
    let plain = !repo.is_empty()
        && !repo.starts_with('-')
        && !repo.contains("::")
        && !repo.chars().any(|c| c.is_control() || c.is_whitespace());
    if !plain {
        return Err(WorkspaceError::InvalidRepo);
    }
    if let Some(rest) = repo.strip_prefix("https://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        return if policy.allows_host(authority) {
            Ok(())
        } else {
            Err(WorkspaceError::InvalidRepo)
        };
    }
    let local = repo.starts_with('/')
        || repo
            .strip_prefix("file://")
            .is_some_and(|rest| rest.starts_with('/'));
    if policy.allow_file && local {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidRepo)
    }
}

pub(crate) fn validate_ref(name: &str) -> Result<(), WorkspaceError> {
    let ok = !name.is_empty()
        && !name.starts_with('-')
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"))
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && !name.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, ':' | '~' | '^' | '?' | '*' | '[' | '\\')
        });
    if ok {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidRef)
    }
}

#[cfg(test)]
mod tests {
    use fleet_core::EventId;

    use super::*;

    #[test]
    fn every_job_id_the_server_issues_passes_the_daemon_rule() {
        for _ in 0..64 {
            assert!(validate_job_id(&EventId::generate().to_string()).is_ok());
        }
    }
}
