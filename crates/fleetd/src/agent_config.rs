//! The per-job Claude Code home: an embedded default bundle or a validated operator directory.
//!
//! Every job gets `<jobs_dir>/.agent/<job id>` with a `home` inside it. The agent runs with
//! `HOME` and `CLAUDE_CONFIG_DIR` there, so it never reads the operator's `~/.claude`. The
//! directory sits outside the worktree and is built as `<job id>.tmp`, then renamed.
//!
//! The default bundle holds a short `CLAUDE.md` and a `settings.json` with permissions only.
//! `agent_config_dir` replaces files of the same name and adds others under `home/.claude`.
//! A directory is a plain copy: regular files only, at most [`MAX_ENTRIES`] entries and
//! [`MAX_BYTES`] bytes in total, no symlinks and no `..` in the path. Its `settings.json`
//! may hold the top-level keys `permissions`, `model` and `attribution` and never a
//! `bypassPermissions` default mode.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::workspace::validate_job_id;

/// Git author and committer name of a job.
pub const JOB_NAME: &str = "Fleet Job";

/// Git author and committer email of a job.
pub const JOB_EMAIL: &str = "fleet-job@fleet.invalid";

/// Most entries, files and directories, in an operator bundle directory.
pub const MAX_ENTRIES: usize = 64;

/// Most bytes in an operator bundle directory, summed over its files.
pub const MAX_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) const AGENT_DIR: &str = ".agent";
const HOME: &str = "home";
const CLAUDE_DIR: &str = ".claude";
const SETTINGS: &str = "settings.json";
const ALLOWED_SETTINGS_KEYS: [&str; 3] = ["permissions", "model", "attribution"];
const EMBEDDED: [(&str, &str); 2] = [
    ("CLAUDE.md", include_str!("../agent-config/CLAUDE.md")),
    (SETTINGS, include_str!("../agent-config/settings.json")),
];
const GITCONFIG: &str =
    "[user]\n\tname = Fleet Job\n\temail = fleet-job@fleet.invalid\n[commit]\n\tgpgsign = false\n";

/// Why an operator bundle directory was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BundleError {
    /// The directory path has a `..` component or cannot be read.
    Path,
    /// An entry is a symlink or another type than a regular file or directory.
    Entry,
    /// The directory holds more than [`MAX_ENTRIES`] entries.
    TooMany,
    /// The files add up to more than [`MAX_BYTES`].
    TooLarge,
    /// `settings.json` is not a JSON object or holds a key or value the bundle forbids.
    Settings,
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Path => "agent config directory path is unusable",
            Self::Entry => "agent config directory holds an entry that is not a regular file",
            Self::TooMany => "agent config directory holds too many entries",
            Self::TooLarge => "agent config directory is too large",
            Self::Settings => "agent config settings.json is not allowed",
        })
    }
}

impl std::error::Error for BundleError {}

/// Files that fill `home/.claude` of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    files: BTreeMap<PathBuf, Vec<u8>>,
}

impl Default for Bundle {
    fn default() -> Self {
        Self {
            files: EMBEDDED
                .iter()
                .map(|(name, text)| (PathBuf::from(name), text.as_bytes().to_vec()))
                .collect(),
        }
    }
}

impl Bundle {
    /// Copies and checks the directory at `dir` over the embedded defaults.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError`] when the path, an entry, the size or `settings.json` is
    /// rejected.
    pub fn from_dir(dir: &Path) -> Result<Self, BundleError> {
        if dir.components().any(|part| part == Component::ParentDir) {
            return Err(BundleError::Path);
        }
        let mut files = BTreeMap::new();
        let mut walk = Walk {
            entries: 0,
            bytes: 0,
        };
        let root = fs::symlink_metadata(dir).map_err(|_| BundleError::Path)?;
        if !root.is_dir() {
            return Err(BundleError::Entry);
        }
        walk.collect(dir, Path::new(""), &mut files)?;
        let mut bundle = Self::default();
        bundle.files.extend(files);
        bundle.check_settings()?;
        Ok(bundle)
    }

    fn check_settings(&self) -> Result<(), BundleError> {
        let Some(raw) = self.files.get(Path::new(SETTINGS)) else {
            return Ok(());
        };
        let value: Value = serde_json::from_slice(raw).map_err(|_| BundleError::Settings)?;
        let object = value.as_object().ok_or(BundleError::Settings)?;
        if object
            .keys()
            .any(|key| !ALLOWED_SETTINGS_KEYS.contains(&key.as_str()))
        {
            return Err(BundleError::Settings);
        }
        let bypass = object
            .get("permissions")
            .and_then(|permissions| permissions.get("defaultMode"))
            .and_then(Value::as_str)
            .is_some_and(|mode| mode.eq_ignore_ascii_case("bypassPermissions"));
        if bypass {
            return Err(BundleError::Settings);
        }
        Ok(())
    }
}

struct Walk {
    entries: usize,
    bytes: u64,
}

impl Walk {
    fn collect(
        &mut self,
        base: &Path,
        rel: &Path,
        files: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), BundleError> {
        let listing = fs::read_dir(base.join(rel)).map_err(|_| BundleError::Path)?;
        for entry in listing {
            let entry = entry.map_err(|_| BundleError::Path)?;
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(BundleError::TooMany);
            }
            let name = PathBuf::from(entry.file_name());
            let rel = rel.join(&name);
            let meta = fs::symlink_metadata(entry.path()).map_err(|_| BundleError::Path)?;
            if meta.is_dir() {
                self.collect(base, &rel, files)?;
            } else if meta.is_file() {
                self.bytes += meta.len();
                if self.bytes > MAX_BYTES {
                    return Err(BundleError::TooLarge);
                }
                let data = fs::read(entry.path()).map_err(|_| BundleError::Path)?;
                files.insert(rel, data);
            } else {
                return Err(BundleError::Entry);
            }
        }
        Ok(())
    }
}

/// One job's agent directory. Dropping it removes the directory.
#[derive(Debug)]
pub struct JobDir {
    path: PathBuf,
}

impl JobDir {
    /// Builds `<root>/.agent/<job_id>` from `bundle`, as `<job_id>.tmp` first, then renamed.
    /// A directory left by an earlier run of the same id is replaced.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the id is invalid or a file cannot be written.
    pub fn create(root: &Path, job_id: &str, bundle: &Bundle) -> io::Result<Self> {
        validate_job_id(job_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = root.join(AGENT_DIR);
        let path = parent.join(job_id);
        let staging = parent.join(format!("{job_id}.tmp"));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)?;
        remove_if_present(&staging)?;
        remove_if_present(&path)?;
        let built = Self::fill(&staging, bundle).and_then(|()| fs::rename(&staging, &path));
        if let Err(err) = built {
            let _ = fs::remove_dir_all(&staging);
            return Err(err);
        }
        Ok(Self { path })
    }

    fn fill(staging: &Path, bundle: &Bundle) -> io::Result<()> {
        let home = staging.join(HOME);
        let claude = home.join(CLAUDE_DIR);
        for dir in [
            &claude,
            &home.join(".config"),
            &home.join(".cache"),
            &home.join(".local").join("state"),
            &home.join(".local").join("share"),
        ] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        for (rel, data) in &bundle.files {
            let target = claude.join(rel);
            if let Some(dir) = target.parent() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            fs::write(&target, data)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(home.join(".gitconfig"), GITCONFIG)
    }

    /// The job directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `HOME` of the agent.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.path.join(HOME)
    }
}

impl Drop for JobDir {
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

#[cfg(test)]
mod default_bundle_tests {
    use super::{EMBEDDED, SETTINGS};
    use crate::runner::DENIED_TOOLS;
    use serde_json::Value;

    fn settings() -> Value {
        let raw = EMBEDDED
            .iter()
            .find(|(name, _)| *name == SETTINGS)
            .map(|(_, body)| *body)
            .expect("embedded settings");
        serde_json::from_str(raw).expect("settings json")
    }

    fn list(value: &Value, key: &str) -> Vec<String> {
        value["permissions"][key]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v.as_str().expect("string").to_owned())
            .collect()
    }

    #[test]
    fn allow_lets_a_job_edit_and_run_tools() {
        let allow = list(&settings(), "allow");
        for tool in ["Read", "Edit", "Write", "Glob", "Grep", "Bash"] {
            assert!(allow.iter().any(|a| a == tool), "missing {tool}");
        }
    }

    #[test]
    fn deny_holds_push_gh_and_curl() {
        let deny = list(&settings(), "deny");
        for pattern in ["Bash(git push *)", "Bash(gh *)", "Bash(curl *)"] {
            assert!(deny.iter().any(|d| d == pattern), "missing {pattern}");
        }
    }

    #[test]
    fn default_mode_is_never_bypass() {
        let value = settings();
        let mode = value["permissions"]["defaultMode"].as_str().unwrap_or("");
        assert_ne!(mode, "bypassPermissions");
        assert!(value.get("defaultMode").is_none());
    }

    #[test]
    fn argv_floor_is_a_subset_of_bundle_deny() {
        let deny = list(&settings(), "deny");
        assert!(DENIED_TOOLS.contains(&"Bash(git push *)"));
        assert!(DENIED_TOOLS.contains(&"Bash(gh *)"));
        for pattern in DENIED_TOOLS {
            assert!(deny.iter().any(|d| d == pattern), "bundle lacks {pattern}");
        }
    }
}
