//! Rollback guard run by `ExecStartPre` from the baked binary (ADR-0047).
//!
//! Three small files live in the bin root beside `current` and `previous`: [`HEALTH_FILE`]
//! holds the version that last proved healthy, [`STARTS_FILE`] counts starts of the current
//! version since then, and [`BAD_VERSIONS_FILE`] lists versions the guard rolled back from, one
//! per line, so the updater never stages them again. Every write goes to a temp file and
//! renames over the name, so a crash leaves the old content.
//!
//! [`Guard::run`] reads `current`. A marker naming it resets the counter. Otherwise the counter
//! grows by one, and once it already holds [`MAX_UNHEALTHY_STARTS`] the guard records the bad
//! version and moves `current` back to `previous` through [`Swapper::rollback`]. A corrupt,
//! oversized or non-regular counter file reads as the limit, the stricter reading: a version
//! with no proof of health and no trustworthy count rolls back. The guard never fails the unit:
//! every outcome, error included, lets the daemon start.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use fleet_core::tools::Version;
use rustix::fs::OFlags;

use super::swap::Swapper;
use super::validate_stage_version;

/// Starts of one version without a health marker before the next start rolls it back.
pub const MAX_UNHEALTHY_STARTS: u32 = 3;

/// Name of the file holding the last healthy version.
pub const HEALTH_FILE: &str = "health";

/// Name of the file counting starts since the last marker.
pub const STARTS_FILE: &str = "starts";

/// Name of the file listing versions the guard rolled back from.
pub const BAD_VERSIONS_FILE: &str = "bad_versions";

const MAX_STATE_BYTES: usize = 256;
const MAX_BAD_FILE_BYTES: usize = 8192;
const MAX_BAD_VERSIONS: usize = 64;
const STARTS_TEMP: &str = ".starts.tmp";
const HEALTH_TEMP: &str = ".health.tmp";
const BAD_TEMP: &str = ".bad_versions.tmp";

/// What one guard run did. Every outcome lets the daemon start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// `current` is absent or the baked-binary seed. Nothing was written.
    NoCurrent,
    /// The marker names `current`. The counter was cleared.
    Healthy,
    /// No marker yet. The counter now holds this many starts.
    Counted(u32),
    /// The limit passed. `current` is back on the previous version.
    RolledBack {
        /// The version rolled back from, now in the bad-version file.
        from: String,
        /// The version `current` points at now.
        to: String,
    },
    /// The limit passed and there is no `previous` to restore.
    NoPrevious,
    /// The limit passed and `previous` is a recorded bad version, so it stays unused.
    PreviousRefused,
    /// A filesystem step failed. The text names the step, never file content.
    Failed(String),
}

/// The rollback guard over one bin root.
#[derive(Debug, Clone)]
pub struct Guard {
    root: PathBuf,
    limit: u32,
}

impl Guard {
    /// A guard over `bin_root` with [`MAX_UNHEALTHY_STARTS`].
    pub fn new(bin_root: impl Into<PathBuf>) -> Self {
        Self {
            root: bin_root.into(),
            limit: MAX_UNHEALTHY_STARTS,
        }
    }

    /// Replaces the start limit. Tests shrink it.
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// The start limit.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Counts this start and rolls back when the limit has passed.
    #[must_use]
    pub fn run(&self) -> GuardOutcome {
        let swapper = Swapper::new(&self.root);
        let current = match swapper.current_version() {
            Ok(Some(version)) => version,
            Ok(None) => return GuardOutcome::NoCurrent,
            Err(err) => return GuardOutcome::Failed(err.to_string()),
        };
        if read_marker(&self.root).as_deref() == Some(current.as_str()) {
            return match clear(&self.root.join(STARTS_FILE)) {
                Ok(()) => GuardOutcome::Healthy,
                Err(err) => GuardOutcome::Failed(format!("clearing the counter: {err}")),
            };
        }
        let seen = read_starts(&self.root, &current);
        if seen < self.limit {
            let count = seen.saturating_add(1);
            return match write_atomic(
                &self.root,
                STARTS_TEMP,
                STARTS_FILE,
                format!("{}\n{count}\n", current.as_str()).as_bytes(),
            ) {
                Ok(()) => GuardOutcome::Counted(count),
                Err(err) => GuardOutcome::Failed(format!("writing the counter: {err}")),
            };
        }
        self.roll_back(&swapper, &current)
    }

    fn roll_back(&self, swapper: &Swapper, current: &Version) -> GuardOutcome {
        let previous = match swapper.previous_version() {
            Ok(Some(version)) if version != *current => version,
            Ok(_) => return GuardOutcome::NoPrevious,
            Err(err) => return GuardOutcome::Failed(err.to_string()),
        };
        if is_bad_version(&self.root, &previous) {
            return GuardOutcome::PreviousRefused;
        }
        if let Err(err) = record_bad(&self.root, current) {
            return GuardOutcome::Failed(format!("recording the bad version: {err}"));
        }
        let restored = match swapper.rollback() {
            Ok(version) => version,
            Err(err) => return GuardOutcome::Failed(err.to_string()),
        };
        let marked = write_health_marker(&self.root, &restored);
        let cleared = clear(&self.root.join(STARTS_FILE));
        if let Err(err) = marked.and(cleared) {
            return GuardOutcome::Failed(format!("resetting state after rollback: {err}"));
        }
        GuardOutcome::RolledBack {
            from: current.as_str().to_owned(),
            to: restored.as_str().to_owned(),
        }
    }
}

/// Records that `version` ran healthy: the daemon calls it after `READY=1` and one good
/// heartbeat.
///
/// # Errors
///
/// Returns the I/O error of the temp file write or the rename.
pub fn write_health_marker(bin_root: &Path, version: &Version) -> io::Result<()> {
    write_atomic(
        bin_root,
        HEALTH_TEMP,
        HEALTH_FILE,
        format!("{}\n", version.as_str()).as_bytes(),
    )
}

/// Whether `version` is in the bad-version file. An unreadable file lists nothing.
#[must_use]
pub fn is_bad_version(bin_root: &Path, version: &Version) -> bool {
    bad_versions(bin_root)
        .iter()
        .any(|line| line == version.as_str())
}

fn bad_versions(root: &Path) -> Vec<String> {
    let Some(body) = read_capped(&root.join(BAD_VERSIONS_FILE), MAX_BAD_FILE_BYTES).ok() else {
        return Vec::new();
    };
    body.lines()
        .filter(|line| validate_stage_version(line).is_ok())
        .map(str::to_owned)
        .collect()
}

fn record_bad(root: &Path, version: &Version) -> io::Result<()> {
    let mut lines = bad_versions(root);
    if lines.iter().any(|line| line == version.as_str()) {
        return Ok(());
    }
    lines.push(version.as_str().to_owned());
    let skip = lines.len().saturating_sub(MAX_BAD_VERSIONS);
    let mut body = String::new();
    for line in lines.iter().skip(skip) {
        body.push_str(line);
        body.push('\n');
    }
    write_atomic(root, BAD_TEMP, BAD_VERSIONS_FILE, body.as_bytes())
}

fn read_marker(root: &Path) -> Option<String> {
    let body = read_capped(&root.join(HEALTH_FILE), MAX_STATE_BYTES).ok()?;
    Some(body.trim_end_matches('\n').to_owned())
}

fn read_starts(root: &Path, current: &Version) -> u32 {
    let body = match read_capped(&root.join(STARTS_FILE), MAX_STATE_BYTES) {
        Ok(body) => body,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return 0,
        Err(_) => return u32::MAX,
    };
    let mut lines = body.lines();
    let (Some(version), Some(count), None) = (lines.next(), lines.next(), lines.next()) else {
        return u32::MAX;
    };
    if validate_stage_version(version).is_err() {
        return u32::MAX;
    }
    if version != current.as_str() {
        return 0;
    }
    count.parse::<u32>().unwrap_or(u32::MAX)
}

fn read_capped(path: &Path, cap: usize) -> io::Result<String> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(invalid());
    }
    let limit = u64::try_from(cap).map_err(|_| invalid())?.saturating_add(1);
    let mut buf = Vec::new();
    file.take(limit).read_to_end(&mut buf)?;
    if buf.len() > cap {
        return Err(invalid());
    }
    String::from_utf8(buf).map_err(|_| invalid())
}

fn clear(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

fn write_atomic(root: &Path, temp: &str, name: &str, body: &[u8]) -> io::Result<()> {
    let temp_path = root.join(temp);
    clear(&temp_path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
        .open(&temp_path)?;
    let written = file.write_all(body).and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = written.and_then(|()| fs::rename(&temp_path, root.join(name))) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    File::open(root).and_then(|dir| dir.sync_all())
}
