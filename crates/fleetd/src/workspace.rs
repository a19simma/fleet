//! Job workspaces: a bare mirror per repo and one git worktree per job.
//!
//! Every input is validated before git runs. Error messages (`Display`) are fixed text and
//! never carry the repo, ref, job id or git output. A failed git step keeps a redacted
//! stderr tail, readable only through [`WorkspaceError::detail`], for logs.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fleet_core::Redactor;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::askpass;
use crate::group::GroupGuard;

const STDERR_KEEP: usize = 64 * 1024;
const DETAIL_MAX: usize = 512;
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
const REDIRECT_FILES: [&str; 2] = ["commondir", "config.worktree"];
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);
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

/// Longest wait for git's stderr to reach EOF after git has exited.
const STDERR_DRAIN: Duration = Duration::from_secs(1);

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
    /// A git command could not start or exited with failure. The second field is a redacted
    /// tail of its stderr, for logs only, never for the server.
    Git(&'static str, String),
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
            Self::Git(step, _) => write!(f, "git {step} failed"),
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
            | Self::Git(..)
            | Self::GitTimeout(_) => None,
        }
    }
}

impl WorkspaceError {
    /// The redacted tail of git's stderr for a failed git step, else `None`.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Git(_, detail) if !detail.is_empty() => Some(detail),
            _ => None,
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

#[derive(Clone)]
struct BeforeFetch(Arc<dyn Fn(&Path) + Send + Sync>);

impl fmt::Debug for BeforeFetch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeforeFetch")
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
    before_fetch: Option<BeforeFetch>,
    redactor: Redactor,
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
            before_fetch: None,
            redactor: Redactor::default(),
        }
    }

    /// Scrubs `redactor`'s secrets from the git stderr kept in [`WorkspaceError::Git`].
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Test seam: runs `hook` with the mirror path after the mirror cleanup and config reset,
    /// right before the fetch, to model an agent writing into the mirror in that window.
    #[doc(hidden)]
    #[must_use]
    pub fn with_before_fetch(mut self, hook: impl Fn(&Path) + Send + Sync + 'static) -> Self {
        self.before_fetch = Some(BeforeFetch(Arc::new(hook)));
        self
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
    /// `git worktree add -B swarm/<job_id>` from `origin/<base_ref>`.
    ///
    /// A leftover worktree directory or branch of the same job id, from a prepare that was
    /// killed or never removed, is replaced. Before the fetch, stale `*.lock` files in the
    /// mirror are deleted. That is safe only when one daemon uses the jobs directory and runs
    /// its jobs one at a time, so the jobs directory must belong to one daemon.
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
        match tokio::fs::remove_dir_all(&path).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(WorkspaceError::Io(err)),
        }
        self.git(&mirror, &["worktree", "prune"], "worktree prune")
            .await?;
        let branch = format!("{BRANCH_PREFIX}{job_id}");
        let start = format!("origin/{base_ref}");
        self.git(
            &mirror,
            &[
                "worktree",
                "add",
                "-B",
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
    /// mirror's worktree records and deletes the job's branch. The bare mirror stays. Every
    /// step runs even when an earlier one fails.
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
        if mirror.join("HEAD").exists() {
            let reference = format!("refs/heads/{BRANCH_PREFIX}{job_id}");
            if let Err(err) = self
                .git(&mirror, &["update-ref", "-d", &reference], "branch delete")
                .await
            {
                first.get_or_insert(err);
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn mirror_path(&self, repo: &str) -> PathBuf {
        self.root
            .join(CACHE_DIR)
            .join(format!("{:x}.git", Sha256::digest(repo.as_bytes())))
    }

    async fn clear_redirects(mirror: &Path) -> Result<(), WorkspaceError> {
        for name in REDIRECT_FILES {
            match tokio::fs::remove_file(mirror.join(name)).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(WorkspaceError::Io(err)),
            }
        }
        Ok(())
    }

    async fn clear_stale_locks(mirror: &Path) -> Result<(), WorkspaceError> {
        let mut pending = vec![mirror.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let mut entries = tokio::fs::read_dir(&dir)
                .await
                .map_err(WorkspaceError::Io)?;
            while let Some(entry) = entries.next_entry().await.map_err(WorkspaceError::Io)? {
                let kind = entry.file_type().await.map_err(WorkspaceError::Io)?;
                let name = entry.file_name();
                if kind.is_dir() {
                    if name != "objects" {
                        pending.push(entry.path());
                    }
                } else if Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"))
                {
                    match tokio::fs::remove_file(entry.path()).await {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(WorkspaceError::Io(err)),
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn reset_mirror_config(mirror: &Path) -> Result<(), WorkspaceError> {
        if !mirror.join("HEAD").exists() {
            return Ok(());
        }
        let staging = mirror.join(format!(
            "{MIRROR_CONFIG_STAGING}-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let written = async {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .await?;
            file.write_all(MIRROR_CONFIG.as_bytes()).await?;
            drop(file);
            tokio::fs::rename(&staging, mirror.join("config")).await
        }
        .await;
        if written.is_err() {
            let _ = tokio::fs::remove_file(&staging).await;
        }
        written.map_err(WorkspaceError::Io)
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
        if mirror.join("HEAD").exists() {
            Self::clear_redirects(mirror).await?;
            Self::clear_stale_locks(mirror).await?;
        }
        Self::reset_mirror_config(mirror).await?;
        if let Some(BeforeFetch(hook)) = &self.before_fetch {
            hook(mirror);
        }
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

    fn detail(&self, raw: &[u8]) -> String {
        let text = String::from_utf8_lossy(raw);
        let scrubbed = self.redactor.redact_str(&text);
        tail(&scrubbed, DETAIL_MAX).to_owned()
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
                .envs(askpass::env(&credential.askpass_bin))
                .env(askpass::HOST_ENV, host)
                .env("GH_TOKEN", &credential.token);
        }
        if args.first() != Some(&"init") {
            let git_dir = std::path::absolute(dir).map_err(WorkspaceError::Io)?;
            command
                .env("GIT_DIR", &git_dir)
                .env("GIT_COMMON_DIR", &git_dir);
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
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| WorkspaceError::Git(step, String::new()))?;
        let mut guard = GroupGuard::new(child.id());
        let stderr = child
            .stderr
            .take()
            .map(|pipe| tokio::spawn(read_tail(pipe)));
        let waited = tokio::time::timeout(self.timeout, child.wait()).await;
        guard.kill();
        match waited {
            Ok(Ok(status)) if status.success() => {
                if let Some(task) = stderr {
                    task.abort();
                }
                Ok(())
            }
            Ok(_) => {
                let raw = match stderr {
                    Some(mut task) => {
                        let drained = tokio::time::timeout(STDERR_DRAIN, &mut task).await;
                        task.abort();
                        drained.ok().and_then(Result::ok).unwrap_or_default()
                    }
                    None => Vec::new(),
                };
                Err(WorkspaceError::Git(step, self.detail(&raw)))
            }
            Err(_) => {
                if let Some(task) = stderr {
                    task.abort();
                }
                let _ = child.wait().await;
                Err(WorkspaceError::GitTimeout(step))
            }
        }
    }
}

fn push_tail(kept: &mut Vec<u8>, chunk: &[u8], keep: usize) {
    kept.extend_from_slice(chunk);
    if kept.len() > keep {
        kept.drain(..kept.len() - keep);
    }
}

fn tail(text: &str, max: usize) -> &str {
    let mut start = text.len().saturating_sub(max);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.get(start..).unwrap_or_default()
}

/// Reads `pipe` to the end, keeping only the last [`STDERR_KEEP`] bytes.
async fn read_tail(mut pipe: tokio::process::ChildStderr) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 4096];
    while let Ok(n) = pipe.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        push_tail(&mut kept, chunk.get(..n).unwrap_or_default(), STDERR_KEEP);
    }
    kept
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

    #[tokio::test]
    async fn concurrent_config_resets_on_one_mirror_all_succeed()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("HEAD"), "ref: refs/heads/main\n")?;
        for _ in 0..20 {
            let mut tasks = Vec::new();
            for _ in 0..16 {
                let mirror = dir.path().to_path_buf();
                tasks.push(tokio::spawn(async move {
                    Workspace::reset_mirror_config(&mirror).await.is_ok()
                }));
            }
            for task in tasks {
                assert!(task.await?);
            }
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config"))?,
            MIRROR_CONFIG
        );
        let leftovers = std::fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(MIRROR_CONFIG_STAGING)
            })
            .count();
        assert_eq!(leftovers, 0);
        Ok(())
    }

    #[test]
    fn every_job_id_the_server_issues_passes_the_daemon_rule() {
        for _ in 0..64 {
            assert!(validate_job_id(&EventId::generate().to_string()).is_ok());
        }
    }
}

#[cfg(test)]
mod tail_tests {
    use super::*;

    #[test]
    fn push_tail_keeps_only_the_last_bytes() {
        let mut kept = b"abc".to_vec();
        push_tail(&mut kept, b"def", 4);
        assert_eq!(kept, b"cdef");
        push_tail(&mut kept, b"g", 4);
        assert_eq!(kept, b"defg");
    }

    #[test]
    fn tail_never_splits_a_character() {
        assert_eq!(tail("abcdef", 3), "def");
        assert_eq!(tail("ab", 3), "ab");
        assert_eq!(tail("a\u{e9}b", 2), "b");
        assert_eq!(tail("a\u{e9}b", 3), "\u{e9}b");
    }
}
