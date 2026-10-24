//! Job workspaces: a bare mirror per repo and one git worktree per job.
//!
//! Every input is validated before git runs. Error messages are fixed text and never carry
//! the repo, ref, job id or git output.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

const CACHE_DIR: &str = ".cache";
const BRANCH_PREFIX: &str = "swarm/";
const MAX_JOB_ID_LEN: usize = 64;
const ALLOWED_PROTOCOLS: &str = "file:https:ssh:git";

/// Why a workspace could not be prepared.
#[derive(Debug)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// The repo URL is empty, starts with `-`, carries userinfo or uses a disallowed form.
    InvalidRepo,
    /// The base ref is empty, starts with `-` or is not a plain ref name.
    InvalidRef,
    /// The job id is not a short alphanumeric identifier.
    InvalidJobId,
    /// A directory under the workspace root could not be created.
    Io(std::io::Error),
    /// A git command could not start or exited with failure.
    Git(&'static str),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRepo => write!(f, "repo url rejected"),
            Self::InvalidRef => write!(f, "base ref rejected"),
            Self::InvalidJobId => write!(f, "job id rejected"),
            Self::Io(_) => write!(f, "workspace directory error"),
            Self::Git(step) => write!(f, "git {step} failed"),
        }
    }
}

impl std::error::Error for WorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidRepo | Self::InvalidRef | Self::InvalidJobId | Self::Git(_) => None,
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

/// Creates job worktrees under a configurable root.
#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// A workspace rooted at `root`. Mirrors live in `<root>/.cache`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Fetches the bare mirror of `repo`, then runs `git worktree add -b swarm/<job_id>`
    /// from `origin/<base_ref>`.
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
        validate_repo(repo)?;
        validate_ref(base_ref)?;

        let cache = self.root.join(CACHE_DIR);
        tokio::fs::create_dir_all(&cache)
            .await
            .map_err(WorkspaceError::Io)?;
        let mirror = cache.join(format!("{:016x}.git", fnv1a(repo.as_bytes())));
        sync_mirror(&mirror, repo).await?;

        let path = self.root.join(job_id);
        let branch = format!("{BRANCH_PREFIX}{job_id}");
        let start = format!("origin/{base_ref}");
        git(
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

async fn sync_mirror(mirror: &Path, repo: &str) -> Result<(), WorkspaceError> {
    if !mirror.join("HEAD").exists() {
        let dir = mirror.to_str().ok_or(WorkspaceError::InvalidRepo)?;
        git(
            Path::new("."),
            &["init", "--bare", "--quiet", "--", dir],
            "init",
        )
        .await?;
        git(
            mirror,
            &["remote", "add", "origin", "--", repo],
            "remote add",
        )
        .await?;
    }
    git(
        mirror,
        &[
            "fetch",
            "--prune",
            "--quiet",
            "origin",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
        "fetch",
    )
    .await
}

async fn git(dir: &Path, args: &[&str], step: &'static str) -> Result<(), WorkspaceError> {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", ALLOWED_PROTOCOLS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .map_err(|_| WorkspaceError::Git(step))?;
    if status.success() {
        Ok(())
    } else {
        Err(WorkspaceError::Git(step))
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn validate_job_id(id: &str) -> Result<(), WorkspaceError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_JOB_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidJobId)
    }
}

fn validate_repo(repo: &str) -> Result<(), WorkspaceError> {
    let plain = !repo.is_empty()
        && !repo.starts_with('-')
        && !repo.contains("::")
        && !repo.chars().any(|c| c.is_control() || c.is_whitespace());
    if !plain {
        return Err(WorkspaceError::InvalidRepo);
    }
    let after_scheme = repo.split_once("://").map_or(repo, |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        return Err(WorkspaceError::InvalidRepo);
    }
    Ok(())
}

fn validate_ref(name: &str) -> Result<(), WorkspaceError> {
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
