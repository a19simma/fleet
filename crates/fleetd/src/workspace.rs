//! Job workspaces: a bare mirror per repo and one clone per job that borrows the mirror's objects.
//!
//! Every input is validated before git runs. Error messages (`Display`) are fixed text and
//! never carry the repo, ref, job id or git output. A failed git step keeps a redacted
//! stderr tail, readable only through [`WorkspaceError::detail`], for logs.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::Redactor;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::agent_config::AGENT_DIR;
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
const MIRROR_SETTINGS: [(&str, &str); 2] = [("gc.auto", "0"), ("gc.pruneExpire", "never")];
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

type AfterCloneFn = dyn Fn(&Path) -> std::io::Result<()> + Send + Sync;

#[derive(Clone)]
struct AfterClone(Arc<AfterCloneFn>);

impl fmt::Debug for AfterClone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AfterClone")
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
    after_clone: Option<AfterClone>,
    redactor: Redactor,
    job_gid: Option<u32>,
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
            after_clone: None,
            redactor: Redactor::default(),
            job_gid: None,
        }
    }

    /// Gives the cache dir to `gid` read-only (2750) and makes each job clone group-writable
    /// (2770), so the job group can read the mirror but never write it. `None`, the default,
    /// leaves the modes git and `create_dir_all` set. `.git-home` and `.finish-<id>` stay
    /// private either way.
    #[must_use]
    pub fn with_job_group(mut self, gid: Option<u32>) -> Self {
        self.job_gid = gid;
        self
    }

    /// Scrubs `redactor`'s secrets from the git stderr kept in [`WorkspaceError::Git`].
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Test seam: runs `hook` with the clone path once the clone and checkout finish and before
    /// the job group share, to model a failure in that window. An error from `hook` fails
    /// `prepare` and removes the clone directory.
    #[doc(hidden)]
    #[must_use]
    pub fn with_after_clone(
        mut self,
        hook: impl Fn(&Path) -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.after_clone = Some(AfterClone(Arc::new(hook)));
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

    /// Fetches `repo` into the bare mirror by explicit url, then runs
    /// `git clone --reference <mirror>` into `<root>/<job_id>`, then checks out
    /// `swarm/<job_id>` from `origin/<base_ref>`. The clone shares the mirror's objects
    /// through alternates and owns its refs, so the mirror records nothing about the job.
    ///
    /// A `base_ref` of 40 lowercase hex characters (see [`is_commit_sha`]) names a commit and
    /// the checkout starts at that commit. The commit must be reachable from a branch of
    /// `repo`, because the mirror fetches branches only. Otherwise the call fails at the
    /// checkout step and the clone directory is removed.
    ///
    /// A leftover directory of the same job id, from a prepare that was killed or never
    /// removed, is replaced. An existing mirror that fails the structural trust check of
    /// `sync_mirror` is deleted and rebuilt, so a mirror an agent could write before the
    /// job group lost write access needs no manual delete. Stale `*.lock` files in the mirror
    /// are deleted before each fetch.
    /// The jobs directory must belong to one daemon that runs its jobs one at a time.
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
        if let Some(gid) = self.job_gid {
            crate::jobenv::share_dir_read_only(&cache, gid).map_err(WorkspaceError::Io)?;
        }
        let mirror = Self::mirror_dir(&self.root, repo);
        self.sync_mirror(&mirror, repo).await?;

        let path = self.root.join(job_id);
        match tokio::fs::remove_dir_all(&path).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(WorkspaceError::Io(err)),
        }
        let branch = format!("{BRANCH_PREFIX}{job_id}");
        let start = if is_commit_sha(base_ref) {
            base_ref.to_owned()
        } else {
            format!("origin/{base_ref}")
        };
        let built = async {
            self.clone_checkout(&mirror, &path, &branch, &start).await?;
            if let Some(AfterClone(hook)) = &self.after_clone {
                hook(&path).map_err(WorkspaceError::Io)?;
            }
            if let Some(gid) = self.job_gid {
                let shared = path.clone();
                tokio::task::spawn_blocking(move || crate::jobenv::share_tree(&shared, gid))
                    .await
                    .map_err(|_| WorkspaceError::Io(std::io::Error::other("share task failed")))?
                    .map_err(WorkspaceError::Io)?;
            }
            Ok(())
        }
        .await;
        if let Err(err) = built {
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err);
        }
        Ok(Checkout { path, branch })
    }
}

impl Workspace {
    async fn clone_checkout(
        &self,
        mirror: &Path,
        path: &Path,
        branch: &str,
        start: &str,
    ) -> Result<(), WorkspaceError> {
        let absolute = std::path::absolute(mirror).map_err(WorkspaceError::Io)?;
        let source = absolute.to_str().ok_or(WorkspaceError::InvalidRepo)?;
        let target = path.to_str().ok_or(WorkspaceError::InvalidJobId)?;
        self.git(
            Path::new("."),
            &[
                "clone",
                "--quiet",
                "--no-checkout",
                "--no-local",
                "--reference",
                source,
                "--",
                source,
                target,
            ],
            "clone",
        )
        .await?;
        self.git(
            path,
            &[
                "fetch",
                "--quiet",
                "--",
                source,
                "+refs/remotes/origin/*:refs/remotes/origin/*",
            ],
            "clone fetch",
        )
        .await?;
        self.git(
            path,
            &["checkout", "--quiet", "-B", branch, start, "--"],
            "checkout",
        )
        .await
    }

    /// Removes the job's clone, its `.finish-<job_id>` scratch dir and its `.agent/<job_id>`
    /// agent config dir with the staging dir. The bare mirror holds no record of the job and
    /// stays. Every step runs even when an earlier one fails.
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
            self.root.join(AGENT_DIR).join(job_id),
            self.root.join(AGENT_DIR).join(format!("{job_id}.tmp")),
        ] {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    first.get_or_insert(WorkspaceError::Io(err));
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// The bare mirror of `repo` under the jobs `root`.
    pub(crate) fn mirror_dir(root: &Path, repo: &str) -> PathBuf {
        root.join(CACHE_DIR)
            .join(format!("{:x}.git", Sha256::digest(repo.as_bytes())))
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

    /// Makes the mirror safe to fetch into, then fetches `repo` into it.
    ///
    /// fleetd runs one job at a time against the jobs directory, so nothing else holds the
    /// mirror while this runs. That lets the call delete every `*.lock` file outside
    /// `objects/` before the fetch: a lock left by a fetch that fleetd killed, cancelled or
    /// timed out would otherwise fail every later fetch.
    ///
    /// An existing mirror is trusted only when it passes [`mirror_is_trusted`]. Otherwise it is
    /// renamed to a sibling `.old`, deleted and created again, which costs one full fetch. A
    /// crash mid-delete leaves only `.old` debris, which the next call removes. A new mirror is built in a
    /// sibling directory and renamed into place, so a mirror path never holds a repo without
    /// its gc settings.
    async fn sync_mirror(&self, mirror: &Path, repo: &str) -> Result<(), WorkspaceError> {
        self.ensure_mirror(mirror).await?;
        let swept = mirror.to_path_buf();
        tokio::task::spawn_blocking(move || sweep_locks(&swept))
            .await
            .map_err(|_| WorkspaceError::Io(std::io::Error::other("lock sweep")))?
            .map_err(WorkspaceError::Io)?;
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

    async fn ensure_mirror(&self, mirror: &Path) -> Result<(), WorkspaceError> {
        match tokio::fs::symlink_metadata(mirror).await {
            Ok(meta) => {
                let owned = mirror.to_path_buf();
                let trusted = tokio::task::spawn_blocking(move || mirror_is_trusted(&owned))
                    .await
                    .map_err(|_| WorkspaceError::Io(std::io::Error::other("mirror check")))?;
                if trusted {
                    return Ok(());
                }
                let aside = mirror.with_extension("old");
                remove_path(&aside).await?;
                if meta.is_dir() {
                    tokio::fs::rename(mirror, &aside)
                        .await
                        .map_err(WorkspaceError::Io)?;
                    remove_path(&aside).await?;
                } else {
                    remove_path(mirror).await?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(WorkspaceError::Io(e)),
        }
        let staging = mirror.with_extension("init");
        remove_path(&staging).await?;
        let dir = staging.to_str().ok_or(WorkspaceError::InvalidRepo)?;
        self.git(
            Path::new("."),
            &["init", "--bare", "--quiet", "--", dir],
            "init",
        )
        .await?;
        for (key, value) in MIRROR_SETTINGS {
            self.git(&staging, &["config", key, value], "init").await?;
        }
        match tokio::fs::rename(&staging, mirror).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(WorkspaceError::Io(e)),
            _ => Ok(()),
        }
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
        if !matches!(args.first(), Some(&"init" | &"clone")) {
            let mut git_dir = std::path::absolute(dir).map_err(WorkspaceError::Io)?;
            if matches!(step, "clone fetch" | "checkout") {
                git_dir.push(".git");
            }
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
            .env(
                "GIT_ALLOW_PROTOCOL",
                if matches!(step, "clone" | "clone fetch") {
                    "file"
                } else {
                    self.policy.protocols()
                },
            )
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

const FORBIDDEN_MIRROR_PATHS: [&str; 10] = [
    "commondir",
    "config.worktree",
    "gitdir",
    "shallow",
    "worktrees",
    "modules",
    "info/attributes",
    "info/grafts",
    "objects/info/alternates",
    "objects/info/http-alternates",
];

/// Entries `git init --bare` creates and a fetch needs, as `(path, is_file)`. A mirror missing
/// one is a half-deleted tree and fails trust.
const REQUIRED_MIRROR_PATHS: [(&str, bool); 6] = [
    ("HEAD", true),
    ("config", true),
    ("objects", false),
    ("refs", false),
    ("objects/pack", false),
    ("objects/info", false),
];

/// Whether `mirror` is a repo fleetd made and nobody else changed.
///
/// A mirror made before the job group lost write access could hold anything an agent wrote,
/// and fleetd fetches into it with the PAT in the environment. So the whole tree is walked
/// without following symlinks, and every entry must be a regular file or directory owned by
/// fleetd's effective uid with no group or other write bit. Every entry of
/// [`REQUIRED_MIRROR_PATHS`] must exist with the right kind. No path in
/// [`FORBIDDEN_MIRROR_PATHS`] may exist: alternates, `commondir`, `config.worktree`, shallow
/// or graft files, attributes, worktrees and submodule dirs. The `config` file may hold only
/// the `core` keys git writes at init and the gc settings fleetd seeds, with `gc.auto` 0
/// and `gc.pruneExpire` never present; any other section, key or include fails it. A failed
/// check or an unreadable entry means the mirror is rebuilt, which costs one fetch.
fn mirror_is_trusted(mirror: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = rustix::process::geteuid().as_raw();
    let Ok(entries) = mirror_entries(mirror, false) else {
        return false;
    };
    let mut layout = 0_u8;
    for (path, meta) in &entries {
        let kind = meta.file_type();
        if !(kind.is_file() || kind.is_dir()) || meta.uid() != euid || meta.mode() & 0o022 != 0 {
            return false;
        }
        let Ok(relative) = path.strip_prefix(mirror) else {
            return false;
        };
        if FORBIDDEN_MIRROR_PATHS
            .iter()
            .any(|forbidden| relative == Path::new(forbidden))
        {
            return false;
        }
        for (bit, (name, is_file)) in REQUIRED_MIRROR_PATHS.iter().enumerate() {
            if relative == Path::new(name) && kind.is_file() == *is_file {
                layout |= 1 << bit;
            }
        }
    }
    layout == (1 << REQUIRED_MIRROR_PATHS.len()) - 1
        && std::fs::read_to_string(mirror.join("config"))
            .is_ok_and(|text| mirror_config_is_trusted(&text))
}

/// Removes whatever sits at `path` without following symlinks: a directory tree, or a file or
/// symlink. A missing path is fine.
async fn remove_path(path: &Path) -> Result<(), WorkspaceError> {
    let removed = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(path).await,
        Ok(_) => tokio::fs::remove_file(path).await,
        Err(e) => Err(e),
    };
    match removed {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(WorkspaceError::Io(e)),
        _ => Ok(()),
    }
}

fn mirror_config_is_trusted(text: &str) -> bool {
    let mut section = String::new();
    let (mut auto, mut expire) = (false, false);
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.ends_with('\\') {
            return false;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_ascii_lowercase();
            if section != "core" && section != "gc" {
                return false;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        let boolean = matches!(value, "true" | "false");
        let ok = match (section.as_str(), key.as_str()) {
            ("core", "repositoryformatversion") => value == "0",
            ("core", "bare") => value == "true",
            (
                "core",
                "filemode" | "logallrefupdates" | "ignorecase" | "precomposeunicode" | "symlinks",
            ) => boolean,
            ("gc", "auto") => {
                auto = value == "0";
                auto
            }
            ("gc", "pruneexpire") => {
                expire = value == "never";
                expire
            }
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    auto && expire
}

fn mirror_entries(
    root: &Path,
    skip_objects: bool,
) -> std::io::Result<Vec<(PathBuf, std::fs::Metadata)>> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_dir() && !(skip_objects && dir == root && path.ends_with("objects")) {
                stack.push(path.clone());
            }
            found.push((path, meta));
        }
    }
    let root_meta = std::fs::symlink_metadata(root)?;
    found.push((root.to_path_buf(), root_meta));
    Ok(found)
}

fn sweep_locks(mirror: &Path) -> std::io::Result<()> {
    let entries = match mirror_entries(mirror, true) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    for (path, meta) in entries {
        let skipped = path.parent() == Some(mirror) && path.ends_with("objects");
        let is_lock = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"));
        if is_lock && !meta.is_dir() && !skipped {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
    }
    Ok(())
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

/// Whether `text` is 40 lowercase hex characters, the form of a full commit id. A base ref
/// of this form is a commit, never a branch name.
#[must_use]
pub fn is_commit_sha(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
