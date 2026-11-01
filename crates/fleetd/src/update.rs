//! Verification of a signed update manifest.
//!
//! The server relays `{version, min_protocol, seq, targets}` plus a minisign signature. This
//! module checks the signature against the trust-root key file, bounds and validates every
//! field, and refuses a manifest that is not strictly newer than the running version and the
//! last accepted `seq` (ADR-0047). The `swap` submodule unpacks a staged archive and flips the
//! `current` and `previous` links. Nothing here restarts fleetd.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::fetch_policy::HostPattern;

mod drain;
mod fetcher;
mod swap;
mod unpack;
pub use drain::{
    DRAIN_CAP, DRAIN_POLL, DrainController, DrainOutcome, DrainRefused, DrainState, Draining,
};
pub use fetcher::{
    ARCHIVE_CONNECT_TIMEOUT, ARCHIVE_TOTAL_TIMEOUT, MAX_ARCHIVE_REDIRECTS, PolicyArchiveFetcher,
    archive_caps,
};
use fleet_core::tools::Version;
use fleet_proto::{MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES};
use minisign_verify::{PublicKey, Signature};
use rustix::fs::OFlags;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
pub use swap::{
    CURRENT_LINK, MAX_BINARY_BYTES, MAX_UNPACKED_BYTES, PREVIOUS_LINK, SwapError, Swapper,
};
pub use unpack::{BINARY_FILE, MAX_TAR_ENTRIES};

/// Default path of the trust-root public key (ADR-0047).
pub const DEFAULT_TRUST_ROOT: &str = "/etc/fleetd/update.pub";

/// The uid that must own the trust root in production.
pub const ROOT_UID: u32 = 0;

/// Longest trust-root key file, in bytes. A minisign public key file is about 100 bytes.
pub const MAX_TRUST_ROOT_BYTES: usize = 1024;

/// Most targets one manifest may list.
pub const MAX_TARGETS: usize = 16;

/// Longest target name, in bytes.
pub const MAX_TARGET_NAME_BYTES: usize = 64;

/// Longest asset URL, in bytes.
pub const MAX_URL_BYTES: usize = 2048;

/// Largest archive size a manifest may declare, in bytes.
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

const SEQ_FILE: &str = "update_seq";
const SEQ_TEMP_FILE: &str = "update_seq.tmp";
const MAX_SEQ_FILE_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = 64;

/// Why a manifest, a trust root or the stored `seq` was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum UpdateError {
    /// The trust root is not a regular file, or is a symlink.
    TrustRootNotRegular,
    /// The trust root or its directory is writable by group or other.
    TrustRootWritable {
        /// The offending mode bits.
        mode: u32,
    },
    /// The trust root or its directory is not owned by the expected uid.
    TrustRootOwner {
        /// The uid found.
        found: u32,
        /// The uid required.
        expected: u32,
    },
    /// The trust root is larger than [`MAX_TRUST_ROOT_BYTES`].
    TrustRootTooLarge,
    /// The trust root is not a valid minisign public key.
    TrustRootInvalid(String),
    /// The trust root could not be opened or read.
    TrustRootIo(io::Error),
    /// The manifest is larger than `fleet_proto::MAX_MANIFEST_BYTES`.
    ManifestTooLarge,
    /// The signature is larger than `fleet_proto::MAX_SIGNATURE_BYTES`.
    SignatureTooLarge,
    /// The signature is malformed or does not verify against the trust root.
    Signature(String),
    /// The signed manifest is not valid JSON of the expected shape.
    ManifestEncoding(String),
    /// A manifest field failed validation.
    Field(&'static str),
    /// The manifest `seq` is not strictly greater than the last accepted one.
    SeqNotNewer {
        /// The `seq` offered.
        seen: u64,
        /// The highest `seq` accepted so far.
        last: u64,
    },
    /// The manifest version is not newer than the running version.
    VersionNotNewer,
    /// The manifest needs a newer protocol than this fleetd serves.
    ProtocolTooNew {
        /// The `min_protocol` offered.
        required: u32,
        /// The protocol this fleetd serves.
        supported: u32,
    },
    /// The manifest has no entry for the requested target.
    UnknownTarget,
    /// The persisted `seq` could not be read, parsed or written.
    SeqState(String),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustRootNotRegular => f.write_str("trust root is not a regular file"),
            Self::TrustRootWritable { mode } => {
                write!(
                    f,
                    "trust root or its directory is writable by group or other (mode {mode:o})"
                )
            }
            Self::TrustRootOwner { found, expected } => {
                write!(f, "trust root owned by uid {found}, expected {expected}")
            }
            Self::TrustRootTooLarge => f.write_str("trust root file is too large"),
            Self::TrustRootInvalid(why) => write!(f, "trust root is not a minisign key: {why}"),
            Self::TrustRootIo(err) => write!(f, "trust root unreadable: {err}"),
            Self::ManifestTooLarge => f.write_str("manifest exceeds the size cap"),
            Self::SignatureTooLarge => f.write_str("signature exceeds the size cap"),
            Self::Signature(why) => write!(f, "signature refused: {why}"),
            Self::ManifestEncoding(why) => write!(f, "manifest is malformed: {why}"),
            Self::Field(name) => write!(f, "manifest field {name} is invalid"),
            Self::SeqNotNewer { seen, last } => {
                write!(f, "manifest seq {seen} is not greater than {last}")
            }
            Self::VersionNotNewer => {
                f.write_str("manifest version is not newer than the running one")
            }
            Self::ProtocolTooNew {
                required,
                supported,
            } => {
                write!(
                    f,
                    "manifest needs protocol {required}, this fleetd serves {supported}"
                )
            }
            Self::UnknownTarget => f.write_str("manifest has no entry for this target"),
            Self::SeqState(why) => write!(f, "update seq state: {why}"),
        }
    }
}

impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TrustRootIo(err) => Some(err),
            _ => None,
        }
    }
}

/// The public key every update is verified against.
#[derive(Debug, Clone)]
pub struct TrustRoot {
    pub(crate) key: PublicKey,
}

/// What a manifest must beat to be accepted.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The version fleetd runs now. The manifest must be strictly newer.
    pub running: Version,
    /// The highest `seq` accepted so far. The manifest must be strictly greater.
    pub last_seq: u64,
    /// The protocol this fleetd serves. The manifest `min_protocol` may not exceed it.
    pub protocol: u32,
}

/// One downloadable build in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Lowercase hex SHA-256 of the archive.
    pub sha256: String,
    /// Archive size in bytes, above zero and at most [`MAX_ARCHIVE_BYTES`].
    pub size: u64,
    /// Optional `https` asset URL.
    pub url: Option<String>,
}

/// A verified update manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The release version.
    pub version: Version,
    /// The protocol the server speaks.
    pub min_protocol: u32,
    /// The release sequence number.
    pub seq: u64,
    targets: BTreeMap<String, Target>,
}

impl Manifest {
    /// The build for `name`.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::UnknownTarget`] when the manifest lists no such target.
    pub fn target(&self, name: &str) -> Result<&Target, UpdateError> {
        self.targets.get(name).ok_or(UpdateError::UnknownTarget)
    }
}

fn is_wrong_owner_or_writable(meta: &fs::Metadata, expected_owner: u32) -> Result<(), UpdateError> {
    let mode = meta.mode();
    if mode & 0o022 != 0 {
        return Err(UpdateError::TrustRootWritable {
            mode: mode & 0o7777,
        });
    }
    if meta.uid() != expected_owner {
        return Err(UpdateError::TrustRootOwner {
            found: meta.uid(),
            expected: expected_owner,
        });
    }
    Ok(())
}

/// Loads the trust-root public key from `path`.
///
/// Refuses a path that is not a regular file (a symlink counts), a file or parent directory
/// writable by group or other, and a file or parent directory not owned by `expected_owner`.
/// Production passes [`ROOT_UID`]. The checks run on the opened descriptor, so the file cannot
/// change between check and read.
///
/// # Errors
///
/// Returns the [`UpdateError`] for whichever check failed.
pub fn load_trust_root(path: &Path, expected_owner: u32) -> Result<TrustRoot, UpdateError> {
    let flags = i32::try_from((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits()).unwrap_or(0);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                UpdateError::TrustRootNotRegular
            } else {
                UpdateError::TrustRootIo(err)
            }
        })?;
    let meta = file.metadata().map_err(UpdateError::TrustRootIo)?;
    if !meta.is_file() {
        return Err(UpdateError::TrustRootNotRegular);
    }
    is_wrong_owner_or_writable(&meta, expected_owner)?;
    let parent_meta = fs::metadata(parent_dir(path)).map_err(UpdateError::TrustRootIo)?;
    is_wrong_owner_or_writable(&parent_meta, expected_owner)?;
    let mut raw = Vec::new();
    file.take(MAX_TRUST_ROOT_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(UpdateError::TrustRootIo)?;
    if raw.len() > MAX_TRUST_ROOT_BYTES {
        return Err(UpdateError::TrustRootTooLarge);
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| UpdateError::TrustRootInvalid("not UTF-8".to_owned()))?;
    let key =
        PublicKey::decode(text).map_err(|err| UpdateError::TrustRootInvalid(err.to_string()))?;
    Ok(TrustRoot { key })
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn numeric(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
}

fn cmp_numeric(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn cmp_pre_id(a: &str, b: &str) -> Ordering {
    match (numeric(a), numeric(b)) {
        (true, true) => cmp_numeric(a, b),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(b),
    }
}

fn cmp_versions(a: &Version, b: &Version) -> Ordering {
    let split = |v: &Version| {
        let s = v.as_str();
        match s.split_once('-') {
            Some((core, pre)) => (core.to_owned(), Some(pre.to_owned())),
            None => (s.to_owned(), None),
        }
    };
    let (core_a, pre_a) = split(a);
    let (core_b, pre_b) = split(b);
    let groups_a: Vec<&str> = core_a.split('.').collect();
    let groups_b: Vec<&str> = core_b.split('.').collect();
    for i in 0..groups_a.len().max(groups_b.len()) {
        let ord = cmp_numeric(
            groups_a.get(i).copied().unwrap_or("0"),
            groups_b.get(i).copied().unwrap_or("0"),
        );
        if ord != Ordering::Equal {
            return ord;
        }
    }
    match (pre_a, pre_b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(pa), Some(pb)) => {
            let ids_a: Vec<&str> = pa.split('.').collect();
            let ids_b: Vec<&str> = pb.split('.').collect();
            for (x, y) in ids_a.iter().zip(&ids_b) {
                let ord = cmp_pre_id(x, y);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            ids_a.len().cmp(&ids_b.len())
        }
    }
}

/// Whether `candidate` is strictly newer than `running` by semver order: numeric groups
/// compare as numbers, missing groups count as zero, and a prerelease sorts below its release.
#[must_use]
pub fn version_is_newer(candidate: &Version, running: &Version) -> bool {
    cmp_versions(candidate, running) == Ordering::Greater
}

#[derive(Debug)]
struct UniqueMap<T>(BTreeMap<String, T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for UniqueMap<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = UniqueMap<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object with unique keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, T>()? {
                    if map.len() >= MAX_TARGETS {
                        return Err(serde::de::Error::custom("too many entries"));
                    }
                    if map.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(UniqueMap(map))
            }
        }

        deserializer.deserialize_map(V(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTarget {
    sha256: String,
    size: u64,
    url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    version: Version,
    min_protocol: u32,
    seq: u64,
    targets: UniqueMap<RawTarget>,
}

fn valid_target_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TARGET_NAME_BYTES
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
}

fn valid_sha256(hex: &str) -> bool {
    hex.len() == SHA256_HEX_BYTES
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_url(url: &str) -> bool {
    url.len() <= MAX_URL_BYTES
        && url
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty())
        && url
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'\\' && b != b'@')
}

fn validate(raw: RawManifest) -> Result<Manifest, UpdateError> {
    if raw.targets.0.is_empty() {
        return Err(UpdateError::Field("targets"));
    }
    let mut targets = BTreeMap::new();
    for (name, target) in raw.targets.0 {
        if !valid_target_name(&name) {
            return Err(UpdateError::Field("targets"));
        }
        if !valid_sha256(&target.sha256) {
            return Err(UpdateError::Field("sha256"));
        }
        if target.size == 0 || target.size > MAX_ARCHIVE_BYTES {
            return Err(UpdateError::Field("size"));
        }
        if target.url.as_deref().is_some_and(|u| !valid_url(u)) {
            return Err(UpdateError::Field("url"));
        }
        targets.insert(
            name,
            Target {
                sha256: target.sha256,
                size: target.size,
                url: target.url,
            },
        );
    }
    Ok(Manifest {
        version: raw.version,
        min_protocol: raw.min_protocol,
        seq: raw.seq,
        targets,
    })
}

/// Verifies `manifest` against `signature` and the trust root, then checks it against `policy`.
///
/// The caps come first, then the signature over the exact manifest bytes, and only then the
/// JSON, so an unsigned body is never parsed. Only prehashed minisign signatures are accepted.
///
/// # Errors
///
/// Returns the [`UpdateError`] of the first failing check.
pub fn verify_manifest(
    manifest: &[u8],
    signature: &[u8],
    root: &TrustRoot,
    policy: &Policy,
) -> Result<Manifest, UpdateError> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateError::ManifestTooLarge);
    }
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(UpdateError::SignatureTooLarge);
    }
    let text = std::str::from_utf8(signature)
        .map_err(|_| UpdateError::Signature("not UTF-8".to_owned()))?;
    let sig = Signature::decode(text).map_err(|err| UpdateError::Signature(err.to_string()))?;
    root.key
        .verify(manifest, &sig, false)
        .map_err(|err| UpdateError::Signature(err.to_string()))?;
    let raw: RawManifest = serde_json::from_slice(manifest)
        .map_err(|err| UpdateError::ManifestEncoding(err.to_string()))?;
    let parsed = validate(raw)?;
    if parsed.seq <= policy.last_seq {
        return Err(UpdateError::SeqNotNewer {
            seen: parsed.seq,
            last: policy.last_seq,
        });
    }
    if !version_is_newer(&parsed.version, &policy.running) {
        return Err(UpdateError::VersionNotNewer);
    }
    if parsed.min_protocol > policy.protocol {
        return Err(UpdateError::ProtocolTooNew {
            required: parsed.min_protocol,
            supported: policy.protocol,
        });
    }
    Ok(parsed)
}

/// The highest accepted `seq`, persisted under the state directory.
#[derive(Debug, Clone)]
pub struct SeqStore {
    dir: PathBuf,
}

fn seq_err(err: impl fmt::Display) -> UpdateError {
    UpdateError::SeqState(err.to_string())
}

impl SeqStore {
    /// A store that keeps its file in `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The stored `seq`, or 0 when none was ever stored.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::SeqState`] when the file exists and is unreadable, over
    /// [`MAX_SEQ_FILE_BYTES`], or not a plain decimal `u64`. A corrupt file never reads as 0,
    /// since that would let a replayed manifest through.
    pub fn load(&self) -> Result<u64, UpdateError> {
        let file = match File::open(self.dir.join(SEQ_FILE)) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(seq_err(err)),
        };
        let mut raw = Vec::new();
        file.take(MAX_SEQ_FILE_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(seq_err)?;
        if raw.len() > MAX_SEQ_FILE_BYTES || !raw.iter().all(u8::is_ascii_digit) {
            return Err(seq_err("corrupt seq file"));
        }
        std::str::from_utf8(&raw)
            .map_err(seq_err)?
            .parse::<u64>()
            .map_err(seq_err)
    }

    /// Stores `seq` through a temp file and a rename.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::SeqNotNewer`] when `seq` is not above the stored value, and
    /// [`UpdateError::SeqState`] on an I/O failure.
    pub fn store(&self, seq: u64) -> Result<(), UpdateError> {
        self.store_with(seq, || Ok(()))
    }

    /// As [`SeqStore::store`], running `before_rename` after the temp file is synced and
    /// before the rename. Tests inject a failure there to model a crash.
    ///
    /// # Errors
    ///
    /// As [`SeqStore::store`], plus any error `before_rename` returns.
    #[doc(hidden)]
    pub fn store_with(
        &self,
        seq: u64,
        before_rename: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), UpdateError> {
        let last = self.load()?;
        if seq <= last {
            return Err(UpdateError::SeqNotNewer { seen: seq, last });
        }
        let temp = self.dir.join(SEQ_TEMP_FILE);
        let mut file = File::create(&temp).map_err(seq_err)?;
        file.write_all(seq.to_string().as_bytes())
            .map_err(seq_err)?;
        file.sync_all().map_err(seq_err)?;
        before_rename().map_err(seq_err)?;
        fs::rename(&temp, self.dir.join(SEQ_FILE)).map_err(seq_err)?;
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(seq_err)
    }
}

/// Longest staged version directory name, in bytes.
const MAX_STAGE_VERSION_BYTES: usize = 64;

/// File name of a staged archive inside its version directory.
pub const STAGED_FILE: &str = "fleetd.tar.gz";

const STAGE_TEMP_FILE: &str = ".fleetd.tar.gz.tmp";
const STAGE_CHUNK_BYTES: usize = 64 * 1024;
const HTTPS_PORT: &str = "443";

/// Why a download or a stage was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum StageError {
    /// The version is not a safe directory name.
    Version,
    /// The target carries no asset URL.
    NoUrl,
    /// The URL is not a plain `https` URL with a valid host.
    Url(&'static str),
    /// The URL host, or the host a redirect ended on, is not on the allow-list.
    HostNotAllowed,
    /// The declared size is above [`MAX_ARCHIVE_BYTES`], or the body is longer than declared.
    TooLarge,
    /// The body is shorter than the declared size.
    SizeMismatch {
        /// Bytes received.
        received: u64,
        /// Bytes declared.
        declared: u64,
    },
    /// The body hash differs from the manifest hash.
    HashMismatch,
    /// A staging directory is a symlink, not a directory, or has loose mode or owner.
    UnsafeDir(PathBuf),
    /// The version is already staged.
    AlreadyStaged,
    /// The fetcher failed.
    Fetch(io::Error),
    /// Writing the staged file failed.
    Io(io::Error),
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => f.write_str("version is not a safe directory name"),
            Self::NoUrl => f.write_str("target has no asset url"),
            Self::Url(why) => write!(f, "asset url refused: {why}"),
            Self::HostNotAllowed => f.write_str("asset host is not on the allow-list"),
            Self::TooLarge => f.write_str("archive exceeds the size cap"),
            Self::SizeMismatch { received, declared } => {
                write!(f, "received {received} bytes, manifest declares {declared}")
            }
            Self::HashMismatch => f.write_str("archive sha256 differs from the manifest"),
            Self::UnsafeDir(path) => write!(f, "unsafe staging directory {}", path.display()),
            Self::AlreadyStaged => f.write_str("version is already staged"),
            Self::Fetch(err) => write!(f, "fetch failed: {err}"),
            Self::Io(err) => write!(f, "staging failed: {err}"),
        }
    }
}

impl std::error::Error for StageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fetch(err) | Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// An open archive download.
pub struct ArchiveResponse {
    /// The URL the body came from after any redirects. The stager checks it against the
    /// allow-list again.
    pub final_url: String,
    /// The response body.
    pub body: Box<dyn Read + Send>,
}

/// The HTTP client behind [`Stager`]. The production implementation runs through the egress
/// policy; tests inject a fake.
pub trait ArchiveFetcher {
    /// Opens `url` and returns the final URL and the body.
    ///
    /// # Errors
    ///
    /// Returns the transport error.
    fn get(&self, url: &str) -> io::Result<ArchiveResponse>;
}

/// Checks that `ver` is safe as one directory name: the semver charset, no separators, no
/// dots-only name, no control bytes.
///
/// # Errors
///
/// Returns [`StageError::Version`].
pub fn validate_stage_version(ver: &str) -> Result<(), StageError> {
    Version::new(ver).map_err(|_| StageError::Version)?;
    let ok = !ver.is_empty()
        && ver.len() <= MAX_STAGE_VERSION_BYTES
        && ver.bytes().any(|b| b.is_ascii_digit())
        && ver
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if ok { Ok(()) } else { Err(StageError::Version) }
}

fn url_host(url: &str) -> Result<String, StageError> {
    if url.len() > MAX_URL_BYTES {
        return Err(StageError::Url("too long"));
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or(StageError::Url("scheme is not https"))?;
    if !rest
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'\\' && b != b'@')
    {
        return Err(StageError::Url("forbidden byte"));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end).unwrap_or_default();
    let host = match authority.split_once(':') {
        Some((host, port)) if port == HTTPS_PORT => host,
        Some(_) => return Err(StageError::Url("port")),
        None => authority,
    };
    match HostPattern::parse(host) {
        Ok(HostPattern::Exact(name)) => Ok(name),
        _ => Err(StageError::Url("host")),
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Downloads a verified target and stages it under `<bin_root>/<version>/`.
///
/// Unverified bytes sit in a 0600 temp file. Only a matching sha256 turns the file 0700 and
/// renames it into place. Nothing is swapped or restarted here.
pub struct Stager<'a, F> {
    bin_root: PathBuf,
    allow: Vec<HostPattern>,
    fetcher: &'a F,
}

impl<'a, F: ArchiveFetcher> Stager<'a, F> {
    /// A stager writing under `bin_root` (`/var/lib/fleet/bin` in production) that fetches
    /// only from hosts matching `allow`.
    pub fn new(bin_root: impl Into<PathBuf>, allow: Vec<HostPattern>, fetcher: &'a F) -> Self {
        Self {
            bin_root: bin_root.into(),
            allow,
            fetcher,
        }
    }

    fn check_url(&self, url: &str) -> Result<(), StageError> {
        let host = url_host(url)?;
        if self.allow.iter().any(|pattern| pattern.matches(&host)) {
            Ok(())
        } else {
            Err(StageError::HostNotAllowed)
        }
    }

    fn require_dir(path: &Path, mode: Option<u32>) -> Result<(), StageError> {
        let meta = fs::symlink_metadata(path).map_err(StageError::Io)?;
        let uid = rustix::process::geteuid().as_raw();
        let loose = mode.is_some_and(|want| meta.mode() & 0o7777 != want);
        if !meta.file_type().is_dir() || meta.uid() != uid || loose {
            return Err(StageError::UnsafeDir(path.to_path_buf()));
        }
        Ok(())
    }

    fn version_dir(&self, version: &Version) -> Result<PathBuf, StageError> {
        Self::require_dir(&self.bin_root, None)?;
        let dir = self.bin_root.join(version.as_str());
        match fs::symlink_metadata(&dir) {
            Ok(_) => Self::require_dir(&dir, Some(0o700))?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&dir)
                    .map_err(StageError::Io)?;
                Self::require_dir(&dir, Some(0o700))?;
            }
            Err(err) => return Err(StageError::Io(err)),
        }
        Ok(dir)
    }

    /// Fetches, checks and stages `target` as `version`, returning the staged path.
    ///
    /// # Errors
    ///
    /// Returns a [`StageError`]. On any error after the temp file exists, the temp file is
    /// removed.
    pub fn stage(&self, version: &Version, target: &Target) -> Result<PathBuf, StageError> {
        validate_stage_version(version.as_str())?;
        if target.size > MAX_ARCHIVE_BYTES {
            return Err(StageError::TooLarge);
        }
        let url = target.url.as_deref().ok_or(StageError::NoUrl)?;
        self.check_url(url)?;
        let dir = self.version_dir(version)?;
        let final_path = dir.join(STAGED_FILE);
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(StageError::AlreadyStaged);
        }
        let response = self.fetcher.get(url).map_err(StageError::Fetch)?;
        self.check_url(&response.final_url)?;
        let temp = dir.join(STAGE_TEMP_FILE);
        match fs::symlink_metadata(&temp) {
            Ok(_) => fs::remove_file(&temp).map_err(StageError::Io)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(StageError::Io(err)),
        }
        let outcome = Self::receive(&temp, response.body, target)
            .and_then(|()| Self::publish(&temp, &final_path, &dir));
        if outcome.is_err() {
            let _ = fs::remove_file(&temp);
        }
        outcome.map(|()| final_path)
    }

    fn receive(temp: &Path, body: Box<dyn Read + Send>, target: &Target) -> Result<(), StageError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
            .open(temp)
            .map_err(StageError::Io)?;
        let mut limited = body.take(target.size.saturating_add(1));
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; STAGE_CHUNK_BYTES];
        let mut received: u64 = 0;
        loop {
            let n = limited.read(&mut buf).map_err(StageError::Fetch)?;
            if n == 0 {
                break;
            }
            let chunk = buf.get(..n).unwrap_or_default();
            received = received.saturating_add(n as u64);
            if received > target.size {
                return Err(StageError::TooLarge);
            }
            hasher.update(chunk);
            file.write_all(chunk).map_err(StageError::Io)?;
        }
        if received != target.size {
            return Err(StageError::SizeMismatch {
                received,
                declared: target.size,
            });
        }
        let digest = hex_lower(&hasher.finalize());
        if !ct_eq(digest.as_bytes(), target.sha256.as_bytes()) {
            return Err(StageError::HashMismatch);
        }
        file.sync_all().map_err(StageError::Io)
    }

    fn publish(temp: &Path, final_path: &Path, dir: &Path) -> Result<(), StageError> {
        fs::set_permissions(temp, fs::Permissions::from_mode(0o700)).map_err(StageError::Io)?;
        if fs::symlink_metadata(final_path).is_ok() {
            return Err(StageError::AlreadyStaged);
        }
        fs::rename(temp, final_path).map_err(StageError::Io)?;
        File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(StageError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_file_name_has_the_current_directory_as_parent() {
        assert_eq!(parent_dir(Path::new("update.pub")), Path::new("."));
        assert_eq!(parent_dir(Path::new("a/update.pub")), Path::new("a"));
        assert_eq!(parent_dir(Path::new("/update.pub")), Path::new("/"));
    }
}
