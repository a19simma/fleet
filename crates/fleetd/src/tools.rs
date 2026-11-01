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

use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use fleet_core::tools::{ToolName, Version};
use fleet_proto::MAX_SIGNATURE_BYTES;
use minisign_verify::Signature;
use rustix::fs::OFlags;
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

const TOOL_ENV_MODE: u32 = 0o600;
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
/// install unit starts.
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(TOOL_ENV_MODE)
        .open(&path)
        .map_err(ToolsError::Io)?;
    if let Err(err) = file.write_all(body.as_bytes()) {
        let _ = fs::remove_file(&path);
        return Err(ToolsError::Io(err));
    }
    Ok(Some(path))
}
