//! Environments: named, owner-scoped bundles of secrets and setup scripts (ADR-0067).
//!
//! This module holds the entry types, their validators, the shared limits, the reserved names
//! and the version hash. It performs no IO. A version is structure only: the hash never covers
//! a secret value, so rotating a value keeps the version.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::credential::Secret;
use crate::redact::{MIN_SECRET_LEN, Redactor};
use crate::text::is_hostile_allowing_joiners;

/// Longest secret value in bytes.
pub const MAX_SECRET_BYTES: usize = 65_536;
/// Shortest secret value in bytes. Equal to [`MIN_SECRET_LEN`]: a shorter value is never redacted.
pub const MIN_SECRET_BYTES: usize = MIN_SECRET_LEN;
/// Longest script body in bytes.
pub const MAX_SCRIPT_BYTES: usize = 65_536;
/// Most entries in one version, secrets and scripts counted together.
pub const MAX_ENTRIES: usize = 64;
/// Cap on the sum of script bodies and current secret values, in bytes.
pub const MAX_TOTAL_BYTES: usize = 786_432;
/// Longest entry or environment name in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// Most egress hosts in one version.
pub const MAX_EGRESS_HOSTS: usize = 16;
/// Longest shebang line of a script in bytes, newline excluded.
pub const MAX_SHEBANG_BYTES: usize = 128;
/// Longest timeout of one script in seconds.
pub const MAX_SCRIPT_TIMEOUT_S: u32 = 600;
/// Longest sum of the script timeouts of one version in seconds.
pub const MAX_SETUP_TOTAL_S: u32 = 1200;
/// Timeout applied when a script gives none, in seconds.
pub const DEFAULT_TIMEOUT_S: u32 = 120;
/// Whether a new secret is visible to the agent when the caller says nothing (D1 option A).
pub const DEFAULT_AGENT_VISIBLE: bool = false;

/// Domain separator that opens the version hash input.
pub const VERSION_HASH_DOMAIN: &str = "fleet-env-v1\0";

/// Entry names an Environment may not define, matched after ASCII case fold.
///
/// A name ending in `*` is a prefix and matches every name that starts with the text before the
/// star, including the bare prefix. Any other name matches exactly. This is the only list: the
/// validator and its tests read it.
pub const RESERVED: &[&str] = &[
    "telemetry",
    "PATH",
    "HOME",
    "HTTPS_PROXY",
    "FLEET_*",
    "LD_*",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ANTHROPIC_*",
    "CLAUDE_*",
    "OTEL_*",
    "DYLD_*",
    "HTTP_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "GIT_*",
    "GH_*",
    "SSH_*",
    "XDG_*",
    "TMPDIR",
    "SHELL",
    "USER",
    "LOGNAME",
    "PWD",
    "OLDPWD",
    "IFS",
    "BASH_ENV",
    "ENV",
    "MISE_*",
];

/// Whether `name` collides with [`RESERVED`] after ASCII case fold.
pub fn is_reserved(name: &str) -> bool {
    RESERVED.iter().any(|rule| {
        rule.strip_suffix('*').map_or_else(
            || name.eq_ignore_ascii_case(rule),
            |prefix| {
                name.as_bytes()
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
            },
        )
    })
}

/// Why an Environment value was refused. Messages are fixed and carry no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvironmentError {
    /// The environment name is empty.
    EnvNameEmpty,
    /// The environment name is longer than [`MAX_NAME_BYTES`].
    EnvNameTooLong,
    /// The environment name has a character outside its grammar.
    EnvNameChars,
    /// The entry name is empty.
    EntryNameEmpty,
    /// The entry name is longer than [`MAX_NAME_BYTES`].
    EntryNameTooLong,
    /// The entry name has a character outside its grammar.
    EntryNameChars,
    /// The entry name is in [`RESERVED`].
    EntryNameReserved,
    /// Two entries share a name after ASCII case fold.
    EntryNameDuplicate,
    /// The secret value is shorter than [`MIN_SECRET_BYTES`].
    SecretTooShort,
    /// The secret value is longer than [`MAX_SECRET_BYTES`].
    SecretTooLong,
    /// The secret value is blank or one repeated character, so the redactor would skip it.
    SecretBlank,
    /// The secret value holds a control, format or separator character.
    SecretText,
    /// The script body is empty.
    ScriptEmpty,
    /// The script body is longer than [`MAX_SCRIPT_BYTES`].
    ScriptTooLong,
    /// The script body does not open with a `#!/` line of at most [`MAX_SHEBANG_BYTES`].
    ScriptNoShebang,
    /// The script body holds a control, format or separator character.
    ScriptText,
    /// A script timeout is outside 1 to [`MAX_SCRIPT_TIMEOUT_S`].
    TimeoutRange,
    /// The script timeouts add up to more than [`MAX_SETUP_TOTAL_S`].
    SetupTotalTooLong,
    /// The version has more than [`MAX_ENTRIES`] entries.
    TooManyEntries,
    /// The sizes add up to more than [`MAX_TOTAL_BYTES`].
    TotalTooLarge,
    /// An egress host is not an exact lowercase DNS name.
    HostInvalid,
    /// Two egress hosts are equal.
    HostDuplicate,
    /// The version has more than [`MAX_EGRESS_HOSTS`] egress hosts.
    TooManyHosts,
    /// `Delivery::Env` was asked for a secret the agent may not see.
    EnvDeliveryNeedsVisible,
}

impl EnvironmentError {
    const fn text(self) -> &'static str {
        match self {
            Self::EnvNameEmpty => "environment name is empty",
            Self::EnvNameTooLong => "environment name is too long",
            Self::EnvNameChars => "environment name has a character outside its grammar",
            Self::EntryNameEmpty => "entry name is empty",
            Self::EntryNameTooLong => "entry name is too long",
            Self::EntryNameChars => "entry name has a character outside its grammar",
            Self::EntryNameReserved => "entry name is reserved",
            Self::EntryNameDuplicate => "entry name is used twice",
            Self::SecretTooShort => "secret value is too short",
            Self::SecretTooLong => "secret value is too long",
            Self::SecretBlank => "secret value is blank or one repeated character",
            Self::SecretText => "secret value has a control or format character",
            Self::ScriptEmpty => "script body is empty",
            Self::ScriptTooLong => "script body is too long",
            Self::ScriptNoShebang => "script body does not open with a shebang line",
            Self::ScriptText => "script body has a control or format character",
            Self::TimeoutRange => "script timeout is out of range",
            Self::SetupTotalTooLong => "script timeouts add up to too much",
            Self::TooManyEntries => "too many entries",
            Self::TotalTooLarge => "entries are too large together",
            Self::HostInvalid => "egress host is not an exact lowercase DNS name",
            Self::HostDuplicate => "egress host is listed twice",
            Self::TooManyHosts => "too many egress hosts",
            Self::EnvDeliveryNeedsVisible => "env delivery needs an agent-visible secret",
        }
    }
}

impl fmt::Display for EnvironmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for EnvironmentError {}

fn within_name_len(
    raw: &str,
    empty: EnvironmentError,
    long: EnvironmentError,
) -> Result<(), EnvironmentError> {
    if raw.is_empty() {
        return Err(empty);
    }
    if raw.len() > MAX_NAME_BYTES {
        return Err(long);
    }
    Ok(())
}

/// The label a user gives an Environment. Scoped to its Owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    /// Accepts ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
    ///
    /// # Errors
    ///
    /// Returns the [`EnvironmentError`] of the first rule broken: empty, too long, or a
    /// character outside the grammar. Reserved names do not apply.
    pub fn new(raw: &str) -> Result<Self, EnvironmentError> {
        within_name_len(
            raw,
            EnvironmentError::EnvNameEmpty,
            EnvironmentError::EnvNameTooLong,
        )?;
        let mut bytes = raw.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_alphanumeric());
        if !first_ok || !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(EnvironmentError::EnvNameChars);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a secret or a script. One namespace per version, compared after ASCII case fold.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryName(String);

impl EntryName {
    /// Accepts ASCII `[A-Za-z_][A-Za-z0-9_]{0,63}` that is not in [`RESERVED`].
    ///
    /// # Errors
    ///
    /// Returns the [`EnvironmentError`] of the first rule broken. The grammar runs before the
    /// reserved check, so `PATH\n` is a character error.
    pub fn new(raw: &str) -> Result<Self, EnvironmentError> {
        within_name_len(
            raw,
            EnvironmentError::EntryNameEmpty,
            EnvironmentError::EntryNameTooLong,
        )?;
        let mut bytes = raw.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
        if !first_ok || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(EnvironmentError::EntryNameChars);
        }
        if is_reserved(raw) {
            return Err(EnvironmentError::EntryNameReserved);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn clean_text(raw: &str) -> bool {
    raw.chars()
        .all(|c| matches!(c, '\n' | '\t') || !is_hostile_allowing_joiners(c))
}

/// A validated secret value. Zeroed on drop, never printed.
pub struct SecretValue(Secret);

impl SecretValue {
    /// Accepts 8 to 65536 bytes of text the redactor can mask: no control, format or separator
    /// character except `\n` and `\t`, not blank, not one repeated character.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::SecretTooShort`], [`EnvironmentError::SecretTooLong`],
    /// [`EnvironmentError::SecretText`] or [`EnvironmentError::SecretBlank`].
    pub fn new(value: String) -> Result<Self, EnvironmentError> {
        if value.len() < MIN_SECRET_BYTES {
            return Err(EnvironmentError::SecretTooShort);
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(EnvironmentError::SecretTooLong);
        }
        if !clean_text(&value) {
            return Err(EnvironmentError::SecretText);
        }
        if Redactor::new([value.as_str()]).is_empty() {
            return Err(EnvironmentError::SecretBlank);
        }
        Ok(Self(Secret::new(value)))
    }

    /// The raw bytes.
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a value holds at least [`MIN_SECRET_BYTES`] bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// A validated script body: UTF-8, opens with a `#!/` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptBody(String);

impl ScriptBody {
    /// Accepts 1 to 65536 bytes with no control, format or separator character except `\n` and
    /// `\t`, whose first line starts with `#!/` and is at most [`MAX_SHEBANG_BYTES`] long.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::ScriptEmpty`], [`EnvironmentError::ScriptTooLong`],
    /// [`EnvironmentError::ScriptText`] or [`EnvironmentError::ScriptNoShebang`].
    pub fn new(raw: &str) -> Result<Self, EnvironmentError> {
        if raw.is_empty() {
            return Err(EnvironmentError::ScriptEmpty);
        }
        if raw.len() > MAX_SCRIPT_BYTES {
            return Err(EnvironmentError::ScriptTooLong);
        }
        if !clean_text(raw) {
            return Err(EnvironmentError::ScriptText);
        }
        let first = raw.split('\n').next().unwrap_or_default();
        if !first.starts_with("#!/") || first.len() > MAX_SHEBANG_BYTES {
            return Err(EnvironmentError::ScriptNoShebang);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The body text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An exact lowercase DNS name a setup script may reach, without port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EgressHost(String);

impl EgressHost {
    /// Accepts lowercase ASCII letter-digit-hyphen labels joined by dots: 1 to 253 bytes, at
    /// least two labels, each 1 to 63 bytes with no leading or trailing hyphen, and a last
    /// label that is not all digits (no IP literal).
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::HostInvalid`].
    pub fn new(raw: &str) -> Result<Self, EnvironmentError> {
        let invalid = EnvironmentError::HostInvalid;
        if raw.is_empty() || raw.len() > 253 {
            return Err(invalid);
        }
        let labels: Vec<&str> = raw.split('.').collect();
        if labels.len() < 2 {
            return Err(invalid);
        }
        for label in &labels {
            let ok = (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok {
                return Err(invalid);
            }
        }
        if labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The host text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a secret reaches the Job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Delivery {
    /// A file in the Job scratch directory.
    #[default]
    File,
    /// An environment variable of the agent process. Needs an agent-visible secret.
    Env,
}

/// What a failing script does to the setup run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnFail {
    /// Stop the setup run and fail the Job.
    #[default]
    Abort,
    /// Go on with the next script.
    Continue,
}

/// The structure of one secret. The sealed value lives outside the version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSpec {
    name: EntryName,
    agent_visible: bool,
    delivery: Delivery,
}

impl SecretSpec {
    /// A secret spec.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::EnvDeliveryNeedsVisible`] for [`Delivery::Env`] with
    /// `agent_visible` false: an env var for a setup-only secret has no consumer.
    pub fn new(
        name: EntryName,
        agent_visible: bool,
        delivery: Delivery,
    ) -> Result<Self, EnvironmentError> {
        if delivery == Delivery::Env && !agent_visible {
            return Err(EnvironmentError::EnvDeliveryNeedsVisible);
        }
        Ok(Self {
            name,
            agent_visible,
            delivery,
        })
    }

    /// A secret with [`DEFAULT_AGENT_VISIBLE`] and [`Delivery::File`].
    pub fn with_defaults(name: EntryName) -> Self {
        Self {
            name,
            agent_visible: DEFAULT_AGENT_VISIBLE,
            delivery: Delivery::File,
        }
    }

    /// The entry name.
    pub fn name(&self) -> &EntryName {
        &self.name
    }

    /// Whether the agent may see the value.
    pub fn agent_visible(&self) -> bool {
        self.agent_visible
    }

    /// How the value reaches the Job.
    pub fn delivery(&self) -> Delivery {
        self.delivery
    }
}

/// The structure of one script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSpec {
    name: EntryName,
    body: ScriptBody,
    on_fail: OnFail,
    timeout_s: u32,
}

impl ScriptSpec {
    /// A script spec.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::TimeoutRange`] when `timeout_s` is outside
    /// 1 to [`MAX_SCRIPT_TIMEOUT_S`].
    pub fn new(
        name: EntryName,
        body: ScriptBody,
        on_fail: OnFail,
        timeout_s: u32,
    ) -> Result<Self, EnvironmentError> {
        if !(1..=MAX_SCRIPT_TIMEOUT_S).contains(&timeout_s) {
            return Err(EnvironmentError::TimeoutRange);
        }
        Ok(Self {
            name,
            body,
            on_fail,
            timeout_s,
        })
    }

    /// A script with [`OnFail::Abort`] and [`DEFAULT_TIMEOUT_S`].
    pub fn with_defaults(name: EntryName, body: ScriptBody) -> Self {
        Self {
            name,
            body,
            on_fail: OnFail::Abort,
            timeout_s: DEFAULT_TIMEOUT_S,
        }
    }

    /// The entry name.
    pub fn name(&self) -> &EntryName {
        &self.name
    }

    /// The script text.
    pub fn body(&self) -> &ScriptBody {
        &self.body
    }

    /// What a failure does to the run.
    pub fn on_fail(&self) -> OnFail {
        self.on_fail
    }

    /// The timeout in seconds.
    pub fn timeout_s(&self) -> u32 {
        self.timeout_s
    }
}

/// One entry of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A named secret.
    Secret(SecretSpec),
    /// A named script.
    Script(ScriptSpec),
}

impl Entry {
    fn name(&self) -> &EntryName {
        match self {
            Self::Secret(s) => &s.name,
            Self::Script(s) => &s.name,
        }
    }
}

/// A validated version structure: entries and egress hosts. Fields are private so every value
/// passed the cross-entry rules in [`EnvironmentSpec::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentSpec {
    entries: Vec<Entry>,
    egress_hosts: Vec<EgressHost>,
}

impl EnvironmentSpec {
    /// Checks every cross-entry rule once.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::TooManyEntries`] past [`MAX_ENTRIES`] counting secrets and
    /// scripts together, [`EnvironmentError::EntryNameDuplicate`] for a name used twice after
    /// ASCII case fold, [`EnvironmentError::SetupTotalTooLong`],
    /// [`EnvironmentError::TotalTooLarge`] when the script bodies alone pass
    /// [`MAX_TOTAL_BYTES`], [`EnvironmentError::TooManyHosts`] and
    /// [`EnvironmentError::HostDuplicate`].
    pub fn new(
        entries: Vec<Entry>,
        egress_hosts: Vec<EgressHost>,
    ) -> Result<Self, EnvironmentError> {
        if entries.len() > MAX_ENTRIES {
            return Err(EnvironmentError::TooManyEntries);
        }
        let mut seen: Vec<String> = entries
            .iter()
            .map(|e| e.name().as_str().to_ascii_lowercase())
            .collect();
        seen.sort_unstable();
        if seen.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(EnvironmentError::EntryNameDuplicate);
        }
        let mut timeouts: u32 = 0;
        let mut bytes: usize = 0;
        for entry in &entries {
            if let Entry::Script(s) = entry {
                timeouts = timeouts.saturating_add(s.timeout_s);
                bytes = bytes.saturating_add(s.body.0.len());
            }
        }
        if timeouts > MAX_SETUP_TOTAL_S {
            return Err(EnvironmentError::SetupTotalTooLong);
        }
        if bytes > MAX_TOTAL_BYTES {
            return Err(EnvironmentError::TotalTooLarge);
        }
        if egress_hosts.len() > MAX_EGRESS_HOSTS {
            return Err(EnvironmentError::TooManyHosts);
        }
        let mut hosts: Vec<&str> = egress_hosts.iter().map(EgressHost::as_str).collect();
        hosts.sort_unstable();
        if hosts.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(EnvironmentError::HostDuplicate);
        }
        Ok(Self {
            entries,
            egress_hosts,
        })
    }

    /// The entries in the order given.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The egress hosts in the order given.
    pub fn egress_hosts(&self) -> &[EgressHost] {
        &self.egress_hosts
    }

    /// Total size of the script bodies in bytes.
    pub fn script_bytes(&self) -> usize {
        self.entries
            .iter()
            .map(|e| match e {
                Entry::Script(s) => s.body.0.len(),
                Entry::Secret(_) => 0,
            })
            .sum()
    }

    /// Checks the size cap with the sum of the current secret values added to the script bodies.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentError::TotalTooLarge`] past [`MAX_TOTAL_BYTES`].
    pub fn check_total_with_secrets(&self, secret_bytes: usize) -> Result<(), EnvironmentError> {
        if self.script_bytes().saturating_add(secret_bytes) > MAX_TOTAL_BYTES {
            return Err(EnvironmentError::TotalTooLarge);
        }
        Ok(())
    }

    /// The version hash of this structure.
    pub fn version_hash(&self) -> VersionHash {
        environment_version_hash(self)
    }
}

/// The SHA-256 content hash of a version structure.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionHash([u8; 32]);

impl VersionHash {
    /// The raw digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for VersionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for VersionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VersionHash({self})")
    }
}

fn put_len(hasher: &mut Sha256, len: usize) {
    let len = u32::try_from(len).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
}

fn put_lp(hasher: &mut Sha256, bytes: &[u8]) {
    put_len(hasher, bytes.len());
    hasher.update(bytes);
}

/// Hashes the structure of `spec`: domain, hosts sorted bytewise, secrets sorted by folded
/// name, scripts in order. Binary and length-prefixed. No secret value is an input.
pub fn environment_version_hash(spec: &EnvironmentSpec) -> VersionHash {
    let mut hasher = Sha256::new();
    hasher.update(VERSION_HASH_DOMAIN.as_bytes());

    let mut hosts: Vec<&str> = spec.egress_hosts.iter().map(EgressHost::as_str).collect();
    hosts.sort_unstable();
    put_len(&mut hasher, hosts.len());
    for host in hosts {
        put_lp(&mut hasher, host.as_bytes());
    }

    let mut secrets: Vec<&SecretSpec> = spec
        .entries
        .iter()
        .filter_map(|e| match e {
            Entry::Secret(s) => Some(s),
            Entry::Script(_) => None,
        })
        .collect();
    secrets.sort_by_key(|s| s.name.0.to_ascii_lowercase());
    put_len(&mut hasher, secrets.len());
    for secret in secrets {
        hasher.update([0x01]);
        put_lp(&mut hasher, secret.name.0.as_bytes());
        let flags =
            u8::from(secret.agent_visible) | (u8::from(secret.delivery == Delivery::Env) << 1);
        hasher.update([flags]);
    }

    let scripts: Vec<&ScriptSpec> = spec
        .entries
        .iter()
        .filter_map(|e| match e {
            Entry::Script(s) => Some(s),
            Entry::Secret(_) => None,
        })
        .collect();
    put_len(&mut hasher, scripts.len());
    for script in scripts {
        hasher.update([0x02]);
        put_lp(&mut hasher, script.name.0.as_bytes());
        hasher.update([u8::from(script.on_fail == OnFail::Continue)]);
        hasher.update(script.timeout_s.to_be_bytes());
        put_lp(&mut hasher, script.body.0.as_bytes());
    }

    VersionHash(hasher.finalize().into())
}
