//! Verification of the bundled mise binary before its first run (ADR-0048).
//!
//! The pins live in Box config as [`MisePinsConfig`]. [`verify_mise`] checks the sha256 pin and
//! the minisign signature of the binary with the key the UPD-2 loader accepts
//! ([`crate::update::load_trust_root`]), and only then returns a [`VerifiedMise`]. Nothing here
//! runs mise or installs a tool.
//!
//! [`tool_hosts`] derives the exact hosts an install may reach from the closed tool registry,
//! [`check_tool_hosts`] requires the Box egress ceiling to cover them, and [`write_tool_env`]
//! writes the proxy variables the install unit reads from `tool-env`.
//!
//! [`ToolCache`] is the cache of installed tools under `/var/lib/fleet/tools`, keyed by tool
//! name and version (ADR-0048). The cache directory belongs to the install uid and the agent unit
//! mounts it read-only, so [`ToolCache::lookup`] and [`ToolCache::lease`] only read, while
//! [`ToolCache::touch`] and [`ToolCache::evict`] write and run as the install uid.

use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use fleet_core::tools::{ToolError, ToolName, Version};
use fleet_proto::MAX_SIGNATURE_BYTES;
use minisign_verify::Signature;
use rustix::fs::{FlockOperation, Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::update::{UpdateError, load_trust_root};

const SHA256_HEX_BYTES: usize = 64;
const CHUNK_BYTES: usize = 64 * 1024;

/// Longest bundled mise binary, in bytes.
pub const MAX_MISE_BYTES: u64 = 256 * 1024 * 1024;

/// Pins as they appear in Box config. Every field is required for [`MisePins::new`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MisePinsConfig {
    /// Pinned mise version.
    pub version: Option<String>,
    /// Lowercase hex sha256 of the binary.
    pub sha256: Option<String>,
    /// Path of the minisign signature file for the binary.
    pub signature_path: Option<PathBuf>,
    /// Path of the minisign public key file.
    pub public_key_path: Option<PathBuf>,
}

/// Why the bundled mise binary was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum ToolsError {
    /// A pin is absent from Box config.
    MissingPin(&'static str),
    /// A pin is present and malformed.
    InvalidPin(&'static str),
    /// The binary is not a regular file, or is a symlink.
    NotRegular,
    /// The binary or its directory is writable by group or other.
    Writable {
        /// The offending mode bits.
        mode: u32,
    },
    /// The binary or its directory is not owned by the expected uid.
    Owner {
        /// The uid found.
        found: u32,
        /// The uid required.
        expected: u32,
    },
    /// The binary is larger than the cap.
    TooLarge,
    /// The binary hashes to a different sha256 than the pin.
    ShaMismatch,
    /// The signature file is oversized, malformed or does not verify.
    Signature(String),
    /// The public key file was refused by the UPD-2 loader.
    Key(UpdateError),
    /// A file could not be opened or read.
    Io(std::io::Error),
    /// The job id is not `[A-Za-z0-9_]{1,64}`.
    InvalidId,
    /// The proxy port is zero.
    InvalidProxy,
    /// A host list entry is not a plain lowercase DNS name.
    InvalidHost,
    /// A host the install needs is not in the host list.
    HostNotAllowed,
    /// A cache tool name or version failed the closed-registry validators.
    InvalidTool,
    /// The cache holds no usable entry for the tool and version.
    NotCached,
    /// A seed tree or cache env value was refused, with the reason.
    Seed(&'static str),
}

impl fmt::Display for ToolsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPin(name) => write!(f, "mise pin {name} is missing"),
            Self::InvalidPin(name) => write!(f, "mise pin {name} is invalid"),
            Self::NotRegular => f.write_str("mise binary is not a regular file"),
            Self::Writable { mode } => write!(
                f,
                "mise binary or its directory is writable by group or other (mode {mode:o})"
            ),
            Self::Owner { found, expected } => {
                write!(f, "mise binary owned by uid {found}, expected {expected}")
            }
            Self::TooLarge => f.write_str("mise binary exceeds the size cap"),
            Self::ShaMismatch => f.write_str("mise binary does not match the pinned sha256"),
            Self::Signature(why) => write!(f, "mise signature refused: {why}"),
            Self::Key(err) => write!(f, "mise public key refused: {err}"),
            Self::Io(err) => write!(f, "mise verification io: {err}"),
            Self::InvalidId => f.write_str("tool-env job id is invalid"),
            Self::InvalidProxy => f.write_str("tool-env proxy port is invalid"),
            Self::InvalidHost => f.write_str("egress host entry is not a plain DNS name"),
            Self::HostNotAllowed => {
                f.write_str("egress ceiling lacks a host the tool install needs")
            }
            Self::InvalidTool => f.write_str("tool name or version is invalid"),
            Self::NotCached => f.write_str("tool is not in the cache"),
            Self::Seed(why) => write!(f, "cache seed refused: {why}"),
        }
    }
}

impl std::error::Error for ToolsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(err) => Some(err),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// Validated pins.
#[derive(Debug, Clone)]
pub struct MisePins {
    version: Version,
    sha256: String,
    signature_path: PathBuf,
    public_key_path: PathBuf,
}

impl MisePins {
    /// Validates `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ToolsError`] for a missing or malformed pin.
    pub fn new(config: MisePinsConfig) -> Result<Self, ToolsError> {
        let version = config.version.ok_or(ToolsError::MissingPin("version"))?;
        let sha256 = config.sha256.ok_or(ToolsError::MissingPin("sha256"))?;
        let signature_path = config
            .signature_path
            .ok_or(ToolsError::MissingPin("signature_path"))?;
        let public_key_path = config
            .public_key_path
            .ok_or(ToolsError::MissingPin("public_key_path"))?;
        let version = Version::new(&version).map_err(|_| ToolsError::InvalidPin("version"))?;
        let valid_sha = sha256.len() == SHA256_HEX_BYTES
            && sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !valid_sha {
            return Err(ToolsError::InvalidPin("sha256"));
        }
        Ok(Self {
            version,
            sha256,
            signature_path,
            public_key_path,
        })
    }
}

/// A mise binary that passed [`verify_mise`].
#[derive(Debug, Clone)]
pub struct VerifiedMise {
    path: PathBuf,
    version: Version,
}

impl VerifiedMise {
    /// The verified path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pinned version.
    #[must_use]
    pub fn version(&self) -> &Version {
        &self.version
    }
}

/// Verifies `binary` against `pins`.
///
/// # Errors
///
/// Returns the [`ToolsError`] of the first failing check.
pub fn verify_mise(
    binary: &Path,
    pins: &MisePins,
    expected_owner: u32,
) -> Result<VerifiedMise, ToolsError> {
    verify_mise_capped(binary, pins, expected_owner, MAX_MISE_BYTES)
}

/// As [`verify_mise`] with an injected size cap.
///
/// # Errors
///
/// As [`verify_mise`].
#[doc(hidden)]
pub fn verify_mise_capped(
    binary: &Path,
    pins: &MisePins,
    expected_owner: u32,
    max_bytes: u64,
) -> Result<VerifiedMise, ToolsError> {
    let flags = i32::try_from((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits()).unwrap_or(0);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(binary)
        .map_err(|err| {
            if err.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                ToolsError::NotRegular
            } else {
                ToolsError::Io(err)
            }
        })?;
    let meta = file.metadata().map_err(ToolsError::Io)?;
    if !meta.is_file() {
        return Err(ToolsError::NotRegular);
    }
    check_owner_and_mode(&meta, expected_owner)?;
    let parent_meta = fs::metadata(parent_dir(binary)).map_err(ToolsError::Io)?;
    check_owner_and_mode(&parent_meta, expected_owner)?;
    let root = load_trust_root(&pins.public_key_path, expected_owner).map_err(ToolsError::Key)?;
    let signature = read_signature(&pins.signature_path)?;
    let mut verifier = root
        .key
        .verify_stream(&signature)
        .map_err(|err| ToolsError::Signature(err.to_string()))?;
    let mut hasher = Sha256::new();
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut chunk = vec![0u8; CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut chunk).map_err(ToolsError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(ToolsError::TooLarge);
        }
        let part = chunk.get(..read).unwrap_or_default();
        hasher.update(part);
        verifier.update(part);
    }
    if hex(&hasher.finalize()) != pins.sha256 {
        return Err(ToolsError::ShaMismatch);
    }
    verifier
        .finalize()
        .map_err(|err| ToolsError::Signature(err.to_string()))?;
    Ok(VerifiedMise {
        path: binary.to_path_buf(),
        version: pins.version.clone(),
    })
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn check_owner_and_mode(meta: &fs::Metadata, expected_owner: u32) -> Result<(), ToolsError> {
    let mode = meta.mode();
    if mode & 0o022 != 0 {
        return Err(ToolsError::Writable {
            mode: mode & 0o7777,
        });
    }
    if meta.uid() != expected_owner {
        return Err(ToolsError::Owner {
            found: meta.uid(),
            expected: expected_owner,
        });
    }
    Ok(())
}

fn read_signature(path: &Path) -> Result<Signature, ToolsError> {
    let file = File::open(path).map_err(ToolsError::Io)?;
    let mut raw = Vec::new();
    file.take(MAX_SIGNATURE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(ToolsError::Io)?;
    if raw.len() > MAX_SIGNATURE_BYTES {
        return Err(ToolsError::Signature("signature file too large".to_owned()));
    }
    let text =
        std::str::from_utf8(&raw).map_err(|_| ToolsError::Signature("not UTF-8".to_owned()))?;
    Signature::decode(text).map_err(|err| ToolsError::Signature(err.to_string()))
}

/// File name of the install unit's environment file inside a job's run directory.
pub const TOOL_ENV_FILE: &str = "tool-env";

const PROXY_ENV: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

const COMMON_HOSTS: [&str; 2] = ["api.github.com", "mise-versions.jdx.dev"];
const GITHUB_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

const fn source_hosts(tool: ToolName) -> &'static [&'static str] {
    match tool {
        ToolName::Node => &["nodejs.org"],
        ToolName::Go => &["dl.google.com", "go.dev"],
        ToolName::Java => &["api.adoptium.net", "github.com"],
        ToolName::Python | ToolName::Jq | ToolName::Just | ToolName::Uv => &[],
    }
}

/// The exact hosts an install of `tools` may reach, sorted and without duplicates.
///
/// The set is the common mise and GitHub hosts plus the release hosts of each tool in the
/// closed registry. It is empty for no tools. No entry is a wildcard. The per-tool hosts are
/// unverified until a live install captures real traffic.
#[must_use]
pub fn tool_hosts(tools: &[ToolName]) -> Vec<&'static str> {
    if tools.is_empty() {
        return Vec::new();
    }
    let mut hosts: Vec<&'static str> = COMMON_HOSTS.to_vec();
    for tool in tools {
        hosts.extend_from_slice(source_hosts(*tool));
        if !matches!(tool, ToolName::Node | ToolName::Go) {
            hosts.extend_from_slice(&GITHUB_HOSTS);
        }
    }
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

fn plain_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_BYTES
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_BYTES
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Requires `ceiling`, the Box egress host list, to hold every host [`tool_hosts`] names for
/// `tools`, by exact match.
///
/// # Errors
///
/// Returns [`ToolsError::InvalidHost`] when any entry of `ceiling` is not a plain lowercase
/// DNS name (wildcards, ports, userinfo, line breaks, whitespace, non-ASCII and empty labels
/// are all refused), and [`ToolsError::HostNotAllowed`] when a needed host is absent.
pub fn check_tool_hosts(ceiling: &[String], tools: &[ToolName]) -> Result<(), ToolsError> {
    if !ceiling.iter().all(|host| plain_dns_name(host)) {
        return Err(ToolsError::InvalidHost);
    }
    let covered = tool_hosts(tools)
        .iter()
        .all(|need| ceiling.iter().any(|host| host == need));
    if covered {
        Ok(())
    } else {
        Err(ToolsError::HostNotAllowed)
    }
}

/// Writes `run_dir/<id>/tool-env` for the install unit and returns its path, or `None` when
/// `tools` is empty and no file is written.
///
/// The file holds the four proxy variables, each naming `http://127.0.0.1:<proxy_port>`, and
/// nothing else. It is created with mode 0600 and must not already exist. Call it before the
/// install unit starts. `run_dir/<id>` is opened with `O_DIRECTORY | O_NOFOLLOW` and the file is
/// created beneath that handle with `O_EXCL | O_NOFOLLOW`, so a symlink at either name is refused.
///
/// # Errors
///
/// Returns [`ToolsError::InvalidId`] for a bad job id, [`ToolsError::InvalidProxy`] for port
/// zero and [`ToolsError::Io`] when the file cannot be created or written; a partial file is
/// removed.
pub fn write_tool_env(
    run_dir: &Path,
    id: &str,
    proxy_port: u16,
    tools: &[ToolName],
) -> Result<Option<PathBuf>, ToolsError> {
    let valid_id = !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid_id {
        return Err(ToolsError::InvalidId);
    }
    if proxy_port == 0 {
        return Err(ToolsError::InvalidProxy);
    }
    if tools.is_empty() {
        return Ok(None);
    }
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let body = PROXY_ENV.iter().fold(String::new(), |mut out, name| {
        let _ = writeln!(out, "{name}={proxy}");
        out
    });
    let path = run_dir.join(id).join(TOOL_ENV_FILE);
    let root = rustix::fs::open(
        run_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| ToolsError::Io(errno.into()))?;
    let job_dir = rustix::fs::openat(
        &root,
        id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| ToolsError::Io(errno.into()))?;
    let fd = rustix::fs::openat(
        &job_dir,
        TOOL_ENV_FILE,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|errno| ToolsError::Io(errno.into()))?;
    let mut file = File::from(fd);
    if let Err(err) = file.write_all(body.as_bytes()) {
        let _ = rustix::fs::unlinkat(&job_dir, TOOL_ENV_FILE, rustix::fs::AtFlags::empty());
        return Err(ToolsError::Io(err));
    }
    Ok(Some(path))
}

/// Largest total size of the tool cache, in bytes, before [`ToolCache::evict`] removes entries.
pub const MAX_CACHE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Most entries (one per tool name and version) the cache keeps.
pub const MAX_CACHE_ENTRIES: usize = 64;

/// Most files and directories one entry walk visits before the entry counts as maximal size.
pub const MAX_ENTRY_WALK: usize = 200_000;

/// Name of the last-used marker file inside an entry.
pub const LAST_USED_FILE: &str = ".last-used";

const LAST_USED_TMP: &str = ".last-used.tmp";
const ASIDE_PREFIX: &str = ".evicting-";
const MARKER_MAX_BYTES: u64 = 32;

/// Limits for one [`ToolCache::evict`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLimits {
    /// Total size the cache may hold.
    pub max_bytes: u64,
    /// Entry count the cache may hold.
    pub max_entries: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_CACHE_BYTES,
            max_entries: MAX_CACHE_ENTRIES,
        }
    }
}

/// What one [`ToolCache::evict`] pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictReport {
    /// Entries removed, oldest first.
    pub evicted: Vec<(ToolName, Version)>,
    /// Entries that were over the limit but held by a live lease, so they stayed.
    pub skipped_in_use: usize,
    /// Total size of the entries left, in bytes.
    pub remaining_bytes: u64,
}

/// A cache entry that [`ToolCache::lookup`] accepted. The caller skips the install unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheHit {
    path: PathBuf,
}

impl CacheHit {
    /// The entry directory, `root/<name>/<version>`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A shared lock on one entry. While it lives, [`ToolCache::evict`] leaves the entry alone.
///
/// The lock is a `flock` on the entry directory. A running job takes a shared lease before it
/// uses the entry, so any number of jobs share one entry, and eviction needs the exclusive lock
/// with `LOCK_NB`, so it never waits and never removes an entry that is leased. The lock drops
/// with this value or with the process, so a crashed job cannot pin an entry.
#[derive(Debug)]
pub struct UseLease {
    _dir: OwnedFd,
}

/// Cache of installed tools keyed by `(tool name, version)` under one root.
///
/// An entry is the directory `root/<name>/<version>`. Names and versions pass the closed
/// registry validators before any path is built, so no input reaches the filesystem unchecked.
#[derive(Debug, Clone)]
pub struct ToolCache {
    root: PathBuf,
    owner: u32,
}

fn parse_key(name: &str, version: &str) -> Result<(ToolName, Version), ToolsError> {
    let name = ToolName::new(name).map_err(|_: ToolError| ToolsError::InvalidTool)?;
    let version = Version::new(version).map_err(|_: ToolError| ToolsError::InvalidTool)?;
    Ok((name, version))
}

fn same_inode(handle: &OwnedFd, path: &Path) -> Result<bool, ToolsError> {
    let held = File::from(handle.try_clone().map_err(ToolsError::Io)?)
        .metadata()
        .map_err(ToolsError::Io)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(held.dev() == meta.dev() && held.ino() == meta.ino()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(ToolsError::Io(err)),
    }
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

impl ToolCache {
    /// A cache at `root` whose entries must be owned by uid `owner`, the install uid.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, owner: u32) -> Self {
        Self {
            root: root.into(),
            owner,
        }
    }

    fn entry_path(&self, name: ToolName, version: &Version) -> PathBuf {
        self.root.join(name.as_str()).join(version.as_str())
    }

    fn usable_dir(&self, path: &Path) -> bool {
        fs::symlink_metadata(path)
            .is_ok_and(|meta| meta.is_dir() && meta.uid() == self.owner && meta.mode() & 0o022 == 0)
    }

    fn usable_entry(&self, name: ToolName, version: &Version) -> bool {
        self.usable_dir(&self.root.join(name.as_str()))
            && self.usable_dir(&self.entry_path(name, version))
    }

    /// Looks `(name, version)` up.
    ///
    /// A hit needs the name directory and the entry directory to exist, to be real directories
    /// (never symlinks), to be owned by the install uid and to be free of group and other write
    /// bits. Anything else is a miss, never an error, so the caller installs.
    ///
    /// # Errors
    ///
    /// Returns [`ToolsError::InvalidTool`] when the name is outside the registry or the version
    /// is not an exact pin.
    pub fn lookup(&self, name: &str, version: &str) -> Result<Option<CacheHit>, ToolsError> {
        let (name, version) = parse_key(name, version)?;
        if self.usable_entry(name, &version) {
            Ok(Some(CacheHit {
                path: self.entry_path(name, &version),
            }))
        } else {
            Ok(None)
        }
    }

    fn open_entry(&self, name: ToolName, version: &Version) -> Result<OwnedFd, ToolsError> {
        if !self.usable_entry(name, version) {
            return Err(ToolsError::NotCached);
        }
        rustix::fs::open(self.entry_path(name, version), dir_flags(), Mode::empty())
            .map_err(|errno| ToolsError::Io(errno.into()))
    }

    /// Takes a shared lease on an entry so eviction skips it. Read-only: it opens the entry
    /// directory and locks that handle, so the agent-side reader needs no write access.
    ///
    /// # Errors
    ///
    /// Returns [`ToolsError::InvalidTool`] for a bad key, [`ToolsError::NotCached`] when no
    /// usable entry exists and [`ToolsError::Io`] when the lock fails.
    pub fn lease(&self, name: &str, version: &str) -> Result<UseLease, ToolsError> {
        self.lease_with_hook(name, version, || {})
    }

    /// [`ToolCache::lease`] with `between` called after the entry is opened and before it is
    /// locked. A test seam: it lets a test move the entry in the window the identity recheck
    /// closes. After the lock the handle must still be the inode at the entry path, else the
    /// entry was evicted or replaced while the lock waited and the result is
    /// [`ToolsError::NotCached`].
    ///
    /// # Errors
    ///
    /// The errors of [`ToolCache::lease`].
    #[doc(hidden)]
    pub fn lease_with_hook(
        &self,
        name: &str,
        version: &str,
        between: impl FnOnce(),
    ) -> Result<UseLease, ToolsError> {
        let (name, version) = parse_key(name, version)?;
        let dir = self.open_entry(name, &version)?;
        between();
        rustix::fs::flock(&dir, FlockOperation::LockShared)
            .map_err(|errno| ToolsError::Io(errno.into()))?;
        if !same_inode(&dir, &self.entry_path(name, &version))? {
            return Err(ToolsError::NotCached);
        }
        Ok(UseLease { _dir: dir })
    }

    /// Records `now` (seconds, caller supplied) as the last use of an entry.
    ///
    /// The marker `.last-used` inside the entry is written to a temp name with `O_EXCL` and then
    /// renamed over the marker, so a reader never sees a partial value. The order never reads
    /// atime. Writer only: it runs as the install uid.
    ///
    /// # Errors
    ///
    /// Returns [`ToolsError::InvalidTool`] for a bad key, [`ToolsError::NotCached`] when no
    /// usable entry exists and [`ToolsError::Io`] on a write failure; the temp file is removed.
    pub fn touch(&self, name: &str, version: &str, now: u64) -> Result<(), ToolsError> {
        let (name, version) = parse_key(name, version)?;
        let dir = self.open_entry(name, &version)?;
        let _ = rustix::fs::unlinkat(&dir, LAST_USED_TMP, rustix::fs::AtFlags::empty());
        let fd = rustix::fs::openat(
            &dir,
            LAST_USED_TMP,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        )
        .map_err(|errno| ToolsError::Io(errno.into()))?;
        let mut file = File::from(fd);
        let written = file
            .write_all(now.to_string().as_bytes())
            .and_then(|()| file.sync_all());
        let renamed = written.map_err(ToolsError::Io).and_then(|()| {
            rustix::fs::renameat(&dir, LAST_USED_TMP, &dir, LAST_USED_FILE)
                .map_err(|errno| ToolsError::Io(errno.into()))
        });
        if renamed.is_err() {
            let _ = rustix::fs::unlinkat(&dir, LAST_USED_TMP, rustix::fs::AtFlags::empty());
        }
        renamed
    }

    fn last_used(&self, name: ToolName, version: &Version) -> u64 {
        let path = self.entry_path(name, version).join(LAST_USED_FILE);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return 0;
        };
        if !meta.is_file() || meta.len() > MARKER_MAX_BYTES || meta.uid() != self.owner {
            return 0;
        }
        fs::read_to_string(&path)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }

    fn entry_size(&self, name: ToolName, version: &Version) -> u64 {
        let mut stack = vec![self.entry_path(name, version)];
        let mut visited = 0usize;
        let mut total: u64 = 0;
        while let Some(dir) = stack.pop() {
            let Ok(read) = fs::read_dir(&dir) else {
                continue;
            };
            for item in read.flatten() {
                visited += 1;
                if visited > MAX_ENTRY_WALK {
                    return u64::MAX;
                }
                let Ok(meta) = fs::symlink_metadata(item.path()) else {
                    continue;
                };
                total = total.saturating_add(meta.len());
                if meta.is_dir() {
                    stack.push(item.path());
                }
            }
        }
        total
    }

    fn sweep_aside(&self) {
        let Ok(read) = fs::read_dir(&self.root) else {
            return;
        };
        for item in read.flatten() {
            if item.file_name().to_string_lossy().starts_with(ASIDE_PREFIX)
                && fs::symlink_metadata(item.path()).is_ok_and(|m| m.is_dir())
            {
                let _ = fs::remove_dir_all(item.path());
            }
        }
    }

    fn scan(&self) -> Vec<(u64, ToolName, Version, u64)> {
        let mut found = Vec::new();
        for name in ToolName::ALL {
            let name_dir = self.root.join(name.as_str());
            if !self.usable_dir(&name_dir) {
                continue;
            }
            let Ok(read) = fs::read_dir(&name_dir) else {
                continue;
            };
            for item in read.flatten() {
                let Some(version) = item
                    .file_name()
                    .to_str()
                    .and_then(|raw| Version::new(raw).ok())
                else {
                    continue;
                };
                if !self.usable_entry(name, &version) {
                    continue;
                }
                let size = self.entry_size(name, &version);
                found.push((self.last_used(name, &version), name, version, size));
            }
        }
        found.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
        found
    }

    fn evict_one(
        &self,
        serial: usize,
        name: ToolName,
        version: &Version,
    ) -> Result<bool, ToolsError> {
        let dir = match self.open_entry(name, version) {
            Ok(dir) => dir,
            Err(ToolsError::NotCached) => return Ok(false),
            Err(err) => return Err(err),
        };
        if rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive).is_err() {
            return Ok(false);
        }
        if !same_inode(&dir, &self.entry_path(name, version))? {
            return Ok(false);
        }
        let aside = self.root.join(format!(
            "{ASIDE_PREFIX}{}-{}-{serial}",
            name.as_str(),
            version.as_str()
        ));
        fs::rename(self.entry_path(name, version), &aside).map_err(ToolsError::Io)?;
        drop(dir);
        fs::remove_dir_all(&aside).map_err(ToolsError::Io)?;
        Ok(true)
    }

    /// Runs one eviction pass and returns what it did.
    ///
    /// Entries are ordered by the `.last-used` marker (an absent or unreadable marker counts as
    /// time 0, so it goes first) and removed oldest first while the total size exceeds
    /// `limits.max_bytes` or the count exceeds `limits.max_entries`. An entry whose directory is
    /// held by a [`UseLease`] fails the non-blocking exclusive lock and is skipped, never waited
    /// on. A removed entry is renamed to `root/.evicting-*` and then deleted, so a crash leaves
    /// either the whole entry or an aside directory that the next pass sweeps. One pass visits
    /// each entry once and walks at most [`MAX_ENTRY_WALK`] items per entry. Writer only.
    ///
    /// # Errors
    ///
    /// Returns [`ToolsError::Io`] when a rename or delete fails; entries removed before the
    /// failure stay removed.
    pub fn evict(&self, limits: CacheLimits) -> Result<EvictReport, ToolsError> {
        self.sweep_aside();
        let entries = self.scan();
        let mut total: u64 = entries.iter().fold(0, |acc, e| acc.saturating_add(e.3));
        let mut count = entries.len();
        let mut evicted = Vec::new();
        let mut skipped_in_use = 0usize;
        for (serial, (_, name, version, size)) in entries.into_iter().enumerate() {
            if total <= limits.max_bytes && count <= limits.max_entries {
                break;
            }
            if self.evict_one(serial, name, &version)? {
                total = total.saturating_sub(size);
                count -= 1;
                evicted.push((name, version));
            } else {
                skipped_in_use += 1;
            }
        }
        Ok(EvictReport {
            evicted,
            skipped_in_use,
            remaining_bytes: total,
        })
    }
}

/// Directory under the seed root that holds the `CARGO_HOME` seed (registry and git checkouts).
pub const CARGO_SUBDIR: &str = "cargo";

/// Directory under the seed root that holds the npm cache seed.
pub const NPM_SUBDIR: &str = "npm";

/// Name of the per-job `CARGO_HOME` copy inside the job directory.
pub const CARGO_HOME_DIR: &str = "cargo-home";

/// Name of the per-job npm cache copy inside the job directory.
pub const NPM_CACHE_DIR: &str = "npm-cache";

/// Default total byte cap over both seed trees.
pub const MAX_SEED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Default cap on one seed file.
pub const MAX_SEED_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Default cap on directory entries and files over both seed trees.
pub const MAX_SEED_ENTRIES: usize = 200_000;

/// Default cap on directory nesting below a seed subdirectory.
pub const MAX_SEED_DEPTH: usize = 32;

/// Caps applied while copying a seed tree.
#[derive(Debug, Clone, Copy)]
pub struct SeedLimits {
    /// Total file bytes over both trees.
    pub max_bytes: u64,
    /// Bytes in one file.
    pub max_file_bytes: u64,
    /// Entries (directories and files, subdirectory roots included) over both trees.
    pub max_entries: usize,
    /// Nesting depth below a subdirectory root; its children sit at depth 1.
    pub max_depth: usize,
}

impl Default for SeedLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_SEED_BYTES,
            max_file_bytes: MAX_SEED_FILE_BYTES,
            max_entries: MAX_SEED_ENTRIES,
            max_depth: MAX_SEED_DEPTH,
        }
    }
}

/// The per-job writable cache directories made by [`warm_job_caches`].
#[derive(Debug, Clone)]
pub struct WarmCaches {
    cargo_home: PathBuf,
    npm_cache: PathBuf,
}

impl WarmCaches {
    /// The job's own `CARGO_HOME`.
    #[must_use]
    pub fn cargo_home(&self) -> &Path {
        &self.cargo_home
    }

    /// The job's own npm cache directory.
    #[must_use]
    pub fn npm_cache(&self) -> &Path {
        &self.npm_cache
    }

    /// The job env pairs naming the copies, never the seed.
    ///
    /// # Errors
    ///
    /// See [`cache_env`].
    pub fn env(&self) -> Result<[(&'static str, String); 2], ToolsError> {
        cache_env(&self.cargo_home, &self.npm_cache)
    }
}

/// The `CARGO_HOME` and `npm_config_cache` pairs for a job env, in that order.
///
/// Pure: it only validates and formats. Both paths must be absolute, valid UTF-8 and free of
/// NUL, CR and LF, so the pairs are safe in an environment file.
///
/// # Errors
///
/// Returns [`ToolsError::Seed`] for a path that fails those checks.
pub fn cache_env(
    cargo_home: &Path,
    npm_cache: &Path,
) -> Result<[(&'static str, String); 2], ToolsError> {
    let value = |path: &Path| -> Result<String, ToolsError> {
        let text = path
            .to_str()
            .ok_or(ToolsError::Seed("cache path is not UTF-8"))?;
        if !path.is_absolute() || text.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
            return Err(ToolsError::Seed(
                "cache path is relative or has a control byte",
            ));
        }
        Ok(text.to_owned())
    };
    Ok([
        ("CARGO_HOME", value(cargo_home)?),
        ("npm_config_cache", value(npm_cache)?),
    ])
}

struct CopyState {
    limits: SeedLimits,
    entries: usize,
    bytes: u64,
}

impl CopyState {
    fn entry(&mut self) -> Result<(), ToolsError> {
        self.entries += 1;
        if self.entries > self.limits.max_entries {
            return Err(ToolsError::Seed("seed has too many entries"));
        }
        Ok(())
    }
}

/// Copies the read-only seed into the job's own writable cache directories.
///
/// `seed_root/cargo` becomes `job_dir/cargo-home` and `seed_root/npm` becomes
/// `job_dir/npm-cache`. Files are byte copies, never hardlinks or reflinks: each copy is a new
/// inode with `nlink` 1, mode 0600 (0700 when the seed file has an execute bit) in 0700
/// directories, so a write or delete in the copy cannot reach the seed. A missing seed root or
/// subdirectory yields an empty cache directory. Everything is refused, and the partial copy
/// removed, when the seed holds a symlink (including a symlinked root or subdirectory), a file
/// with `nlink` above 1, a fifo, socket or device, a file over `max_file_bytes`, more than
/// `max_bytes` in total, more than `max_entries` entries, or nesting deeper than `max_depth`.
/// Files are opened with `O_NOFOLLOW | O_NONBLOCK` and checked again on the open handle.
///
/// `job_dir` must exist and must not already hold the two destination names. It is made
/// absolute first, so the returned paths are absolute for a relative root. The seed is populated
/// by an operator or install step as the fleetd uid and is never written here. Nothing calls
/// this from the runner yet.
///
/// # Errors
///
/// Returns [`ToolsError::Seed`] for a refused seed and [`ToolsError::Io`] for an io failure,
/// including an existing destination.
pub fn warm_job_caches(
    seed_root: &Path,
    job_dir: &Path,
    limits: SeedLimits,
) -> Result<WarmCaches, ToolsError> {
    let job_dir = std::path::absolute(job_dir).map_err(ToolsError::Io)?;
    let caches = WarmCaches {
        cargo_home: job_dir.join(CARGO_HOME_DIR),
        npm_cache: job_dir.join(NPM_CACHE_DIR),
    };
    match fs::symlink_metadata(seed_root) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(ToolsError::Seed("seed root is not a real directory")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut created = Vec::new();
            let result = make_owned_dir(&caches.cargo_home, &mut created)
                .and_then(|()| make_owned_dir(&caches.npm_cache, &mut created));
            if let Err(err) = result {
                remove_created(&created);
                return Err(err);
            }
            return Ok(caches);
        }
        Err(err) => return Err(ToolsError::Io(err)),
    }
    let mut state = CopyState {
        limits,
        entries: 0,
        bytes: 0,
    };
    let mut created = Vec::new();
    let result = copy_subdir(
        &seed_root.join(CARGO_SUBDIR),
        &caches.cargo_home,
        &mut state,
        &mut created,
    )
    .and_then(|()| {
        copy_subdir(
            &seed_root.join(NPM_SUBDIR),
            &caches.npm_cache,
            &mut state,
            &mut created,
        )
    });
    if let Err(err) = result {
        remove_created(&created);
        return Err(err);
    }
    Ok(caches)
}

fn make_owned_dir(dst: &Path, created: &mut Vec<PathBuf>) -> Result<(), ToolsError> {
    make_dir(dst)?;
    created.push(dst.to_path_buf());
    Ok(())
}

fn remove_created(created: &[PathBuf]) {
    for path in created {
        let _ = fs::remove_dir_all(path);
    }
}

fn make_dir(path: &Path) -> Result<(), ToolsError> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(ToolsError::Io)
}

fn copy_subdir(
    src: &Path,
    dst: &Path,
    state: &mut CopyState,
    created: &mut Vec<PathBuf>,
) -> Result<(), ToolsError> {
    match fs::symlink_metadata(src) {
        Ok(meta) if meta.is_dir() => {
            state.entry()?;
            make_owned_dir(dst, created)?;
            copy_dir(src, dst, 0, state)
        }
        Ok(_) => Err(ToolsError::Seed(
            "seed subdirectory is not a real directory",
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => make_owned_dir(dst, created),
        Err(err) => Err(ToolsError::Io(err)),
    }
}

fn copy_dir(src: &Path, dst: &Path, depth: usize, state: &mut CopyState) -> Result<(), ToolsError> {
    for entry in fs::read_dir(src).map_err(ToolsError::Io)? {
        let entry = entry.map_err(ToolsError::Io)?;
        state.entry()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let kind = fs::symlink_metadata(&from)
            .map_err(ToolsError::Io)?
            .file_type();
        if kind.is_dir() {
            if depth + 1 > state.limits.max_depth {
                return Err(ToolsError::Seed("seed nesting is too deep"));
            }
            make_dir(&to)?;
            copy_dir(&from, &to, depth + 1, state)?;
        } else if kind.is_file() {
            copy_file(&from, &to, state)?;
        } else {
            return Err(ToolsError::Seed("seed holds a symlink or special file"));
        }
    }
    Ok(())
}

fn copy_file(from: &Path, to: &Path, state: &mut CopyState) -> Result<(), ToolsError> {
    let mut src = OpenOptions::new()
        .read(true)
        .custom_flags(
            (OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC)
                .bits()
                .cast_signed(),
        )
        .open(from)
        .map_err(ToolsError::Io)?;
    let meta = src.metadata().map_err(ToolsError::Io)?;
    if !meta.is_file() {
        return Err(ToolsError::Seed("seed holds a symlink or special file"));
    }
    if meta.nlink() > 1 {
        return Err(ToolsError::Seed("seed file has more than one hardlink"));
    }
    let len = meta.len();
    if len > state.limits.max_file_bytes {
        return Err(ToolsError::Seed("seed file is over the size cap"));
    }
    state.bytes = state.bytes.saturating_add(len);
    if state.bytes > state.limits.max_bytes {
        return Err(ToolsError::Seed("seed is over the total size cap"));
    }
    let mode = if meta.mode() & 0o111 == 0 {
        0o600
    } else {
        0o700
    };
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits().cast_signed())
        .open(to)
        .map_err(ToolsError::Io)?;
    let copied = std::io::copy(&mut (&mut src).take(len), &mut dst).map_err(ToolsError::Io)?;
    if copied != len {
        return Err(ToolsError::Seed("seed file changed while copying"));
    }
    Ok(())
}
