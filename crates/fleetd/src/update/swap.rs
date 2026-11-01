//! Unpack and atomic activation of a staged release (ADR-0047).
//!
//! [`Swapper::unpack`] turns `<bin_root>/<ver>/fleetd.tar.gz` into `<bin_root>/<ver>/fleetd`
//! (mode 0755, owned by the daemon user) and opens the version directory to 0755 so the job
//! uid can run it. [`Swapper::activate`] then moves two symlinks with `rename(2)`: first
//! `previous` takes the old `current` target, then `current` takes the new version. Each link
//! is built beside its final name and renamed over it, so a reader always finds a link. A
//! crash between the two renames leaves `current` on the old target. Link targets are
//! relative version names, so the state dir may be relative. A `current` that points anywhere
//! but a version name is the baked-binary seed that `tmpfiles.d` creates (`/usr/local/bin`):
//! the swap replaces it and records no `previous`, because a rollback only ever returns to a
//! version that was staged here. Nothing here restarts fleetd.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use fleet_core::tools::Version;
use rustix::fs::OFlags;

use super::unpack::{BINARY_FILE, extract};
use super::{MAX_ARCHIVE_BYTES, STAGED_FILE, StageError, validate_stage_version};

/// Name of the link to the active version.
pub const CURRENT_LINK: &str = "current";

/// Name of the link to the last good version.
pub const PREVIOUS_LINK: &str = "previous";

/// Largest unpacked `fleetd` binary, in bytes.
pub const MAX_BINARY_BYTES: u64 = MAX_ARCHIVE_BYTES;

/// Most decompressed bytes one archive may yield, headers and skipped entries included.
pub const MAX_UNPACKED_BYTES: u64 = 2 * MAX_ARCHIVE_BYTES;

const CURRENT_TEMP: &str = ".current.tmp";
const PREVIOUS_TEMP: &str = ".previous.tmp";
const BINARY_TEMP: &str = ".fleetd.tmp";

/// Why an unpack or a swap was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum SwapError {
    /// The version is not a safe directory name.
    Version,
    /// The version directory or its archive is missing, or its binary is not unpacked.
    NotStaged,
    /// The state dir or a version directory is not a directory, or has the wrong owner or mode.
    UnsafeDir(PathBuf),
    /// `current` exists and is not a symlink.
    UnsafeLink(PathBuf),
    /// The version is already `current`.
    AlreadyCurrent,
    /// The archive is malformed.
    Archive(&'static str),
    /// An archive entry is a link, or its path escapes the version directory.
    UnsafeEntry(String),
    /// The binary or the unpacked total is above its cap.
    TooLarge,
    /// A filesystem step failed.
    Io(io::Error),
}

impl fmt::Display for SwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => f.write_str("version is not a safe directory name"),
            Self::NotStaged => f.write_str("version is not staged"),
            Self::UnsafeDir(path) => write!(f, "unsafe directory {}", path.display()),
            Self::UnsafeLink(path) => write!(f, "unsafe link {}", path.display()),
            Self::AlreadyCurrent => f.write_str("version is already current"),
            Self::Archive(why) => write!(f, "archive refused: {why}"),
            Self::UnsafeEntry(path) => write!(f, "archive entry refused: {path:?}"),
            Self::TooLarge => f.write_str("archive exceeds the unpack cap"),
            Self::Io(err) => write!(f, "swap failed: {err}"),
        }
    }
}

impl std::error::Error for SwapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<StageError> for SwapError {
    fn from(_: StageError) -> Self {
        Self::Version
    }
}

/// Unpacks staged releases and flips `current` and `previous` under one state dir.
pub struct Swapper {
    bin_root: PathBuf,
    max_binary: u64,
    max_unpacked: u64,
}

impl Swapper {
    /// A swapper over `bin_root` (`/var/lib/fleet/bin` in production).
    pub fn new(bin_root: impl Into<PathBuf>) -> Self {
        Self {
            bin_root: bin_root.into(),
            max_binary: MAX_BINARY_BYTES,
            max_unpacked: MAX_UNPACKED_BYTES,
        }
    }

    /// Replaces the binary and total caps. Tests shrink them.
    #[must_use]
    pub fn with_limits(mut self, max_binary: u64, max_unpacked: u64) -> Self {
        self.max_binary = max_binary;
        self.max_unpacked = max_unpacked;
        self
    }

    /// The bin root this swapper works under.
    #[must_use]
    pub fn bin_root(&self) -> &Path {
        &self.bin_root
    }

    fn require_dir(path: &Path, modes: &[u32]) -> Result<(), SwapError> {
        let meta = fs::symlink_metadata(path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                SwapError::NotStaged
            } else {
                SwapError::Io(err)
            }
        })?;
        let uid = rustix::process::geteuid().as_raw();
        let mode_ok = modes.is_empty() || modes.contains(&(meta.mode() & 0o7777));
        if !meta.file_type().is_dir() || meta.uid() != uid || !mode_ok {
            return Err(SwapError::UnsafeDir(path.to_path_buf()));
        }
        Ok(())
    }

    fn version_dir(&self, version: &Version) -> Result<PathBuf, SwapError> {
        validate_stage_version(version.as_str())?;
        Self::require_dir(&self.bin_root, &[])?;
        let dir = self.bin_root.join(version.as_str());
        Self::require_dir(&dir, &[0o700, 0o755])?;
        Ok(dir)
    }

    fn sync_dir(dir: &Path) -> Result<(), SwapError> {
        File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(SwapError::Io)
    }

    /// Unpacks the staged archive of `version` and returns the binary path.
    ///
    /// A binary that already exists is left as is. On any error the temp file is removed and no
    /// `fleetd` file exists.
    ///
    /// # Errors
    ///
    /// Returns a [`SwapError`].
    pub fn unpack(&self, version: &Version) -> Result<PathBuf, SwapError> {
        let dir = self.version_dir(version)?;
        let binary = dir.join(BINARY_FILE);
        match fs::symlink_metadata(&binary) {
            Ok(meta) if meta.file_type().is_file() => return Ok(binary),
            Ok(_) => return Err(SwapError::UnsafeLink(binary)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(SwapError::Io(err)),
        }
        let archive = OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
            .open(dir.join(STAGED_FILE))
            .map_err(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    SwapError::NotStaged
                } else {
                    SwapError::Io(err)
                }
            })?;
        let temp = dir.join(BINARY_TEMP);
        remove_if_present(&temp)?;
        let outcome = self.write_binary(archive, &temp, &binary, &dir);
        if outcome.is_err() {
            let _ = fs::remove_file(&temp);
        }
        outcome.map(|()| binary)
    }

    fn write_binary(
        &self,
        archive: File,
        temp: &Path,
        binary: &Path,
        dir: &Path,
    ) -> Result<(), SwapError> {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
            .open(temp)
            .map_err(SwapError::Io)?;
        extract(archive, &mut out, self.max_binary, self.max_unpacked)?;
        out.sync_all().map_err(SwapError::Io)?;
        fs::set_permissions(temp, fs::Permissions::from_mode(0o755)).map_err(SwapError::Io)?;
        fs::rename(temp, binary).map_err(SwapError::Io)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).map_err(SwapError::Io)?;
        Self::sync_dir(dir)
    }

    fn read_link_target(&self, name: &str) -> Result<Option<String>, SwapError> {
        let path = self.bin_root.join(name);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(SwapError::Io(err)),
        };
        if !meta.file_type().is_symlink() {
            return Err(SwapError::UnsafeLink(path));
        }
        let target = fs::read_link(&path).map_err(SwapError::Io)?;
        match target.to_str() {
            Some(text) if validate_stage_version(text).is_ok() => Ok(Some(text.to_owned())),
            _ => Ok(None),
        }
    }

    /// The version `current` points at, or `None` when it is absent or not a version name.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError::UnsafeLink`] when `current` exists and is not a symlink.
    pub fn current_version(&self) -> Result<Option<Version>, SwapError> {
        self.link_version(CURRENT_LINK)
    }

    /// The version `previous` points at, or `None` when it is absent or not a version name.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError::UnsafeLink`] when `previous` exists and is not a symlink.
    pub fn previous_version(&self) -> Result<Option<Version>, SwapError> {
        self.link_version(PREVIOUS_LINK)
    }

    fn link_version(&self, name: &str) -> Result<Option<Version>, SwapError> {
        Ok(self
            .read_link_target(name)?
            .and_then(|text| Version::new(&text).ok()))
    }

    /// Points `current` back at `previous` and drops `previous`, so a rollback never leaves a
    /// link to the version it just left. Returns the restored version.
    ///
    /// `previous` must name a version directory that holds an unpacked binary. On any error
    /// both links are as they were.
    ///
    /// # Errors
    ///
    /// Returns [`SwapError::NotStaged`] when `previous` is absent or its binary is missing, or
    /// another [`SwapError`].
    pub fn rollback(&self) -> Result<Version, SwapError> {
        let version = self.previous_version()?.ok_or(SwapError::NotStaged)?;
        let dir = self.version_dir(&version)?;
        match fs::symlink_metadata(dir.join(BINARY_FILE)) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) | Err(_) => return Err(SwapError::NotStaged),
        }
        self.point(CURRENT_TEMP, CURRENT_LINK, version.as_str())?;
        remove_if_present(&self.bin_root.join(PREVIOUS_LINK))?;
        Self::sync_dir(&self.bin_root)?;
        Ok(version)
    }

    fn point(&self, temp: &str, name: &str, target: &str) -> Result<(), SwapError> {
        let temp_path = self.bin_root.join(temp);
        remove_if_present(&temp_path)?;
        symlink(target, &temp_path).map_err(SwapError::Io)?;
        if let Err(err) = fs::rename(&temp_path, self.bin_root.join(name)) {
            let _ = fs::remove_file(&temp_path);
            return Err(SwapError::Io(err));
        }
        Ok(())
    }

    /// Unpacks `version`, then activates it.
    ///
    /// # Errors
    ///
    /// Returns a [`SwapError`].
    pub fn swap(&self, version: &Version) -> Result<(), SwapError> {
        self.unpack(version)?;
        self.activate(version)
    }

    /// Moves `previous` to the old `current` target, then `current` to `version`.
    ///
    /// # Errors
    ///
    /// Returns a [`SwapError`].
    pub fn activate(&self, version: &Version) -> Result<(), SwapError> {
        self.activate_with(version, || Ok(()))
    }

    /// [`Self::activate`] with `between` run after `previous` is set and before `current`
    /// flips. A failure from `between` aborts with `current` unchanged.
    ///
    /// # Errors
    ///
    /// Returns a [`SwapError`].
    pub fn activate_with(
        &self,
        version: &Version,
        between: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), SwapError> {
        let dir = self.version_dir(version)?;
        match fs::symlink_metadata(dir.join(BINARY_FILE)) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) | Err(_) => return Err(SwapError::NotStaged),
        }
        let old = self.read_link_target("current")?;
        if old.as_deref() == Some(version.as_str()) {
            return Err(SwapError::AlreadyCurrent);
        }
        if let Some(old) = old.as_deref() {
            let runs = fs::symlink_metadata(self.bin_root.join(old).join(BINARY_FILE))
                .is_ok_and(|meta| meta.file_type().is_file());
            if runs {
                self.point(PREVIOUS_TEMP, PREVIOUS_LINK, old)?;
            }
        }
        between().map_err(SwapError::Io)?;
        self.point(CURRENT_TEMP, CURRENT_LINK, version.as_str())?;
        Self::sync_dir(&self.bin_root)
    }
}

fn remove_if_present(path: &Path) -> Result<(), SwapError> {
    match fs::symlink_metadata(path) {
        Ok(_) => fs::remove_file(path).map_err(SwapError::Io),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SwapError::Io(err)),
    }
}
