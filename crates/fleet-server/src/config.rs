//! Server configuration, read from environment variables only.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_core::credential::{BotIdentity, BotIdentityError};
use fleet_core::model_allowlist::ModelAllowlist;
use fleet_proto::{DEFAULT_CI_RETRIES, MAX_CI_RETRIES};

use crate::cred::app_jwt::{AppKey, AppKeyError};
use crate::cred::app_policy::{AppPolicy, PolicyError as AppPolicyError};
use crate::cred::{FileSealer, KeyRingError};
use crate::retention::{
    DEFAULT_EVENTS_DAYS, DEFAULT_INTERVAL, DEFAULT_SUMMARIES_DAYS, MIN_INTERVAL, Policy,
    PolicyError,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:7070";
const DEFAULT_HEALTH_LISTEN: &str = "0.0.0.0:7072";

/// Why the configuration is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A required variable is unset or empty.
    Missing(&'static str),
    /// A variable holds a value that does not parse.
    Invalid {
        /// The variable name.
        var: &'static str,
        /// Why the value was refused.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(var) => write!(f, "{var} is required and must not be empty"),
            Self::Invalid { var, reason } => write!(f, "{var} is invalid: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

use crate::web::MAX_TRUSTED_HOPS;

/// Shortest accepted bearer token, in characters.
pub const MIN_TOKEN_LEN: usize = 32;

/// A string whose `Debug` output hides the value, so a derived `Debug` on a holder never
/// prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps a secret value.
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    /// The secret text.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A shared bearer token, the box token or the client token. Its `Debug` output hides the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(Secret);

impl Token {
    /// Wraps a token.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Missing`] for an empty token and [`ConfigError::Invalid`]
    /// for one shorter than [`MIN_TOKEN_LEN`] characters or with leading or trailing
    /// whitespace.
    pub fn new(raw: String) -> Result<Self, ConfigError> {
        Self::named("FLEET_TOKEN", raw)
    }

    /// Wraps a token read from `var`, which names the variable in any error.
    ///
    /// # Errors
    ///
    /// Same as [`Token::new`].
    pub fn named(var: &'static str, raw: String) -> Result<Self, ConfigError> {
        if raw.is_empty() {
            return Err(ConfigError::Missing(var));
        }
        if raw.trim() != raw {
            return Err(ConfigError::Invalid {
                var,
                reason: "must not have leading or trailing whitespace".to_owned(),
            });
        }
        if raw.chars().count() < MIN_TOKEN_LEN {
            return Err(ConfigError::Invalid {
                var,
                reason: format!("must be at least {MIN_TOKEN_LEN} characters"),
            });
        }
        Ok(Self(Secret::new(raw)))
    }

    /// The token text.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

/// Most entries `FLEET_REPO_HOSTS` may hold.
pub const MAX_REPO_HOSTS: usize = 16;

/// Longest `FLEET_REPO_HOSTS` value, in bytes.
pub const MAX_REPO_HOSTS_VALUE_LEN: usize = 4096;

const REPO_HOSTS_VAR: &str = "FLEET_REPO_HOSTS";
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_PATH_SEGMENT_LEN: usize = 64;
const MAX_PATH_SEGMENTS: usize = 8;
const GITHUB_HOST: &str = "github.com";
const GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_API_BASE: &str = "https://api.github.com";

/// The kind of forge behind a repository host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Forge {
    /// GitHub, or a GitHub Enterprise server.
    Github,
    /// Forgejo or Gitea.
    Forgejo,
}

/// One operator-approved repository host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// Lowercase ASCII DNS name, with no port and no trailing dot.
    pub host: String,
    /// The forge API dialect.
    pub forge: Forge,
    /// The HTTPS API base with no trailing slash. Its host equals [`HostConfig::host`], except that
    /// a `github` entry for `github.com` may use `api.github.com`.
    pub api_base: String,
    /// Whether the host may resolve to a private address. Defaults to `false`.
    pub allow_private: bool,
}

/// Why a `FLEET_REPO_HOSTS` value was refused. The text is fixed and never echoes the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoHostsError {
    /// The value is longer than [`MAX_REPO_HOSTS_VALUE_LEN`] bytes.
    TooLong,
    /// More than [`MAX_REPO_HOSTS`] entries.
    TooManyEntries,
    /// An entry is empty or a field is not `key=value`.
    Malformed,
    /// A field name is not `host`, `forge`, `api` or `allow_private`.
    UnknownField,
    /// A field appears twice in one entry.
    DuplicateField,
    /// `host` is missing.
    MissingHost,
    /// `forge` is missing.
    MissingForge,
    /// `api` is missing.
    MissingApi,
    /// `host` is not a lowercase ASCII DNS name without port, userinfo or trailing dot.
    InvalidHost,
    /// `forge` is not `github` or `forgejo`.
    InvalidForge,
    /// `allow_private` is not `true` or `false`.
    InvalidAllowPrivate,
    /// `api` is not an HTTPS base URL with no userinfo, port, query or fragment.
    InvalidApi,
    /// The host of `api` differs from `host`.
    ApiHostMismatch,
    /// `api` has a path that is not a plain subpath prefix.
    InvalidApiPath,
    /// Two entries name the same host.
    DuplicateHost,
}

impl fmt::Display for RepoHostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "value is too long",
            Self::TooManyEntries => "too many entries",
            Self::Malformed => "an entry is empty or a field is not key=value",
            Self::UnknownField => "an entry has an unknown field",
            Self::DuplicateField => "an entry repeats a field",
            Self::MissingHost => "an entry has no host",
            Self::MissingForge => "an entry has no forge",
            Self::MissingApi => "an entry has no api",
            Self::InvalidHost => "a host is not a lowercase ASCII DNS name",
            Self::InvalidForge => "a forge is not github or forgejo",
            Self::InvalidAllowPrivate => "allow_private is not true or false",
            Self::InvalidApi => "an api is not a plain https base URL",
            Self::ApiHostMismatch => "an api host differs from its entry host",
            Self::InvalidApiPath => "an api path is not a plain subpath prefix",
            Self::DuplicateHost => "two entries name the same host",
        })
    }
}

impl std::error::Error for RepoHostsError {}

/// The operator repository host list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoHosts {
    hosts: Vec<HostConfig>,
}

impl Default for RepoHosts {
    fn default() -> Self {
        Self {
            hosts: vec![HostConfig {
                host: GITHUB_HOST.to_owned(),
                forge: Forge::Github,
                api_base: GITHUB_API_BASE.to_owned(),
                allow_private: false,
            }],
        }
    }
}

impl RepoHosts {
    /// Whether the list differs from the default, which is true when `FLEET_REPO_HOSTS` is set
    /// to anything but the default entry.
    pub fn is_non_default(&self) -> bool {
        *self != Self::default()
    }

    /// A list with no hosts, which refuses every repository.
    pub fn none() -> Self {
        Self { hosts: Vec::new() }
    }

    /// The entry for `host`, matched exactly. Callers pass a lowercase host.
    pub fn lookup(&self, host: &str) -> Option<&HostConfig> {
        self.hosts.iter().find(|entry| entry.host == host)
    }

    /// The entries in the order configured.
    pub fn iter(&self) -> impl Iterator<Item = &HostConfig> {
        self.hosts.iter()
    }

    /// How many hosts are configured.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether no host is configured.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Parses a `FLEET_REPO_HOSTS` value: entries separated by `;`, each a comma separated list of
    /// `host=`, `forge=`, `api=` and optional `allow_private=` fields. The empty string is an empty
    /// list. No field is trimmed, so any whitespace refuses the value.
    ///
    /// # Errors
    ///
    /// Returns [`RepoHostsError`] when the value or an entry breaks the grammar, a host or API base
    /// is invalid, or two entries share a host.
    pub fn parse(raw: &str) -> Result<Self, RepoHostsError> {
        if raw.bytes().take(MAX_REPO_HOSTS_VALUE_LEN + 1).count() > MAX_REPO_HOSTS_VALUE_LEN {
            return Err(RepoHostsError::TooLong);
        }
        if raw.is_empty() {
            return Ok(Self::none());
        }
        let parts: Vec<&str> = raw.split(';').take(MAX_REPO_HOSTS + 1).collect();
        if parts.len() > MAX_REPO_HOSTS {
            return Err(RepoHostsError::TooManyEntries);
        }
        let mut hosts: Vec<HostConfig> = Vec::with_capacity(parts.len());
        for part in parts {
            let parsed = parse_host_entry(part)?;
            if hosts.iter().any(|seen| seen.host == parsed.host) {
                return Err(RepoHostsError::DuplicateHost);
            }
            hosts.push(parsed);
        }
        Ok(Self { hosts })
    }
}

fn parse_host_entry(part: &str) -> Result<HostConfig, RepoHostsError> {
    if part.is_empty() {
        return Err(RepoHostsError::Malformed);
    }
    let mut host = None;
    let mut forge = None;
    let mut api = None;
    let mut allow_private = None;
    for field in part.split(',') {
        let (key, value) = field.split_once('=').ok_or(RepoHostsError::Malformed)?;
        let slot = match key {
            "host" => &mut host,
            "forge" => &mut forge,
            "api" => &mut api,
            "allow_private" => &mut allow_private,
            _ => return Err(RepoHostsError::UnknownField),
        };
        if slot.replace(value).is_some() {
            return Err(RepoHostsError::DuplicateField);
        }
    }
    let host = host.ok_or(RepoHostsError::MissingHost)?;
    let forge = forge.ok_or(RepoHostsError::MissingForge)?;
    let api = api.ok_or(RepoHostsError::MissingApi)?;
    if !is_dns_host(host) {
        return Err(RepoHostsError::InvalidHost);
    }
    let forge = match forge {
        "github" => Forge::Github,
        "forgejo" => Forge::Forgejo,
        _ => return Err(RepoHostsError::InvalidForge),
    };
    let allow_private = match allow_private {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(RepoHostsError::InvalidAllowPrivate),
    };
    Ok(HostConfig {
        host: host.to_owned(),
        forge,
        api_base: parse_api_base(api, host, forge)?,
        allow_private,
    })
}

/// Whether `host` is a lowercase ASCII DNS name: labels of 1 to 63 letters, digits and hyphens,
/// none starting or ending with a hyphen, at most 253 bytes in all. The last label must start with
/// an ASCII lowercase letter, as every real top-level domain does, which refuses IPv4 in decimal,
/// hex and octal forms such as `0x7f000001`. A single label such as `localhost` is accepted by
/// design: the fetcher enforces the private-address check at connect time, unless `allow_private`
/// is set.
fn is_dns_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }
    let mut last = "";
    for label in host.split('.') {
        let edge = |b: Option<&u8>| b == Some(&b'-');
        let ok = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !edge(label.as_bytes().first())
            && !edge(label.as_bytes().last());
        if !ok {
            return false;
        }
        last = label;
    }
    has_letter_tld(last)
}

fn has_letter_tld(host: &str) -> bool {
    host.rsplit('.')
        .next()
        .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_lowercase()))
}

fn parse_api_base(api: &str, host: &str, forge: Forge) -> Result<String, RepoHostsError> {
    let rest = api
        .strip_prefix("https://")
        .ok_or(RepoHostsError::InvalidApi)?;
    let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
    if authority.is_empty()
        || !has_letter_tld(authority)
        || !authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(RepoHostsError::InvalidApi);
    }
    let github_api = forge == Forge::Github && host == GITHUB_HOST && authority == GITHUB_API_HOST;
    if authority != host && !github_api {
        return Err(RepoHostsError::ApiHostMismatch);
    }
    let prefix = path.strip_suffix('/').unwrap_or(path);
    if !prefix.is_empty() {
        let segments: Vec<&str> = prefix[1..].split('/').take(MAX_PATH_SEGMENTS + 1).collect();
        let plain = |segment: &&str| {
            !segment.is_empty()
                && segment.len() <= MAX_PATH_SEGMENT_LEN
                && *segment != "."
                && *segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
        };
        if segments.len() > MAX_PATH_SEGMENTS || !segments.iter().all(plain) {
            return Err(RepoHostsError::InvalidApiPath);
        }
    }
    Ok(format!("https://{authority}{prefix}"))
}

/// Longest GitHub owner login, in bytes.
pub const MAX_UPDATE_OWNER_LEN: usize = 39;

/// Longest GitHub repository name, in bytes.
pub const MAX_UPDATE_REPO_LEN: usize = 100;

/// Default pause between release feed polls, in seconds.
pub const DEFAULT_UPDATE_POLL_SECS: u64 = 900;

/// Shortest accepted `FLEET_UPDATE_POLL_SECS`.
pub const MIN_UPDATE_POLL_SECS: u64 = 60;

/// Longest accepted `FLEET_UPDATE_POLL_SECS`: one day.
pub const MAX_UPDATE_POLL_SECS: u64 = 86_400;

const UPDATE_REPO_VAR: &str = "FLEET_UPDATE_REPO";
const UPDATE_MANIFEST_VAR: &str = "FLEET_UPDATE_MANIFEST";
const UPDATE_POLL_VAR: &str = "FLEET_UPDATE_POLL_SECS";

/// Why an `owner/repo` value was refused. No variant carries the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateRepoError {
    /// The value has no slash or more than one. `/r` returns [`Self::Owner`] and `o/` returns
    /// [`Self::Repo`].
    Shape,
    /// The owner is empty, over [`MAX_UPDATE_OWNER_LEN`] bytes or holds a byte outside
    /// `[A-Za-z0-9-]`.
    Owner,
    /// The repository is empty, over [`MAX_UPDATE_REPO_LEN`] bytes, `.` or `..`, or holds a byte
    /// outside `[A-Za-z0-9._-]`.
    Repo,
}

impl fmt::Display for UpdateRepoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape => f.write_str("must be owner/repo with exactly one slash"),
            Self::Owner => write!(
                f,
                "owner must be 1 to {MAX_UPDATE_OWNER_LEN} bytes of letters, digits and `-`"
            ),
            Self::Repo => write!(
                f,
                concat!(
                    "repository must be 1 to {} bytes of letters, digits, ",
                    "`.`, `_` and `-`, and not `.` or `..`"
                ),
                MAX_UPDATE_REPO_LEN
            ),
        }
    }
}

impl std::error::Error for UpdateRepoError {}

/// The repository whose latest release carries the update manifest, parsed from
/// `FLEET_UPDATE_REPO` (ADR-0060). The fields are private so every value passed the grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRepo {
    owner: String,
    repo: String,
}

impl UpdateRepo {
    /// Parses `owner/repo` strictly. The owner is 1 to [`MAX_UPDATE_OWNER_LEN`] bytes of
    /// `[A-Za-z0-9-]`. The repository is 1 to [`MAX_UPDATE_REPO_LEN`] bytes of `[A-Za-z0-9._-]`
    /// and not `.` or `..`. Case is kept. There is no trimming.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateRepoError`] for any value outside that grammar.
    pub fn parse(raw: &str) -> Result<Self, UpdateRepoError> {
        let mut parts = raw.split('/');
        let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(UpdateRepoError::Shape);
        };
        let owner_ok = (1..=MAX_UPDATE_OWNER_LEN).contains(&owner.len())
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !owner_ok {
            return Err(UpdateRepoError::Owner);
        }
        let repo_ok = (1..=MAX_UPDATE_REPO_LEN).contains(&repo.len())
            && repo != "."
            && repo != ".."
            && repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !repo_ok {
            return Err(UpdateRepoError::Repo);
        }
        Ok(Self {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    /// The owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The repository name.
    pub fn repo(&self) -> &str {
        &self.repo
    }
}

impl fmt::Display for UpdateRepo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)
    }
}

/// Server settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address of the gRPC listener.
    pub listen: SocketAddr,
    /// Address of the health listener.
    pub health_listen: SocketAddr,
    /// Postgres connection URL.
    pub database_url: Secret,
    /// Box bearer token: `FleetIngest` and `FleetWorker`.
    pub token: Token,
    /// Client bearer token for the client-scope services, among them `FleetQuery` and
    /// `FleetJobs`. `None` when `FLEET_CLIENT_TOKEN` is unset or empty; the static client token
    /// then authenticates nobody and only per-user API tokens reach those services.
    pub client_token: Option<Token>,
    /// How long telemetry rows are kept, from `FLEET_EVENTS_RETENTION_DAYS` and
    /// `FLEET_SUMMARIES_RETENTION_DAYS`.
    pub retention: Policy,
    /// Pause between retention sweeps, from `FLEET_RETENTION_INTERVAL_SECS`.
    pub retention_interval: Duration,
    /// Most fix Jobs one failed pull request may start, from `FLEET_MAX_CI_RETRIES`: 0 to
    /// [`MAX_CI_RETRIES`], default [`DEFAULT_CI_RETRIES`]. 0 turns the retry off.
    pub max_ci_retries: u32,
    /// Path of the credential master key file, from `FLEET_MASTER_KEY_FILE`. `None` when
    /// unset or empty.
    pub master_key_file: Option<PathBuf>,
    /// Path of the signed update manifest, from `FLEET_UPDATE_MANIFEST`. The signature is the
    /// file of the same name with `.minisig` appended. `None` when unset or empty.
    pub update_manifest: Option<PathBuf>,
    /// Repository whose latest release carries the manifest, from `FLEET_UPDATE_REPO`. `None`
    /// when unset or empty. Setting it together with `FLEET_UPDATE_MANIFEST` refuses start.
    pub update_repo: Option<UpdateRepo>,
    /// Pause between release feed polls, from `FLEET_UPDATE_POLL_SECS`: [`MIN_UPDATE_POLL_SECS`]
    /// to [`MAX_UPDATE_POLL_SECS`], default [`DEFAULT_UPDATE_POLL_SECS`].
    pub update_poll: Duration,
    /// Public origin of the web UI, from `FLEET_WEB_ORIGIN` (for example
    /// `https://fleet.example.com`). `None` when unset or empty, which turns web login off.
    pub web_origin: Option<String>,
    /// `WebAuthn` relying party id, from `FLEET_WEB_RP_ID`. `None` means the host of the origin.
    pub web_rp_id: Option<String>,
    /// Bootstrap password for the first admin, from `FLEET_BOOTSTRAP_PASSWORD`. `None` when
    /// unset or empty. The server hashes it at startup and ignores it once a user exists.
    pub bootstrap_password: Option<Secret>,
    /// Trusted proxies in front of the server, from `FLEET_TRUSTED_PROXY_HOPS`: 0 to
    /// [`MAX_TRUSTED_HOPS`], default 0, which ignores `X-Forwarded-For`.
    pub trusted_proxy_hops: usize,
    /// Model ids a profile may name, from `FLEET_MODEL_ALLOWLIST`: a comma-separated list with
    /// exact, case-sensitive entries and no trimming. `None` when the variable is unset, which
    /// applies no model restriction. A set value that does not parse, the empty string
    /// included, refuses start.
    pub model_allowlist: Option<ModelAllowlist>,
    /// The GitHub App, from `FLEET_GITHUB_APP_ID` and `FLEET_GITHUB_APP_KEY_FILE`, with the bot
    /// identity from `FLEET_GITHUB_APP_BOT_NAME` and `FLEET_GITHUB_APP_BOT_EMAIL`, and the
    /// allowlists from `FLEET_GITHUB_APP_ACCOUNT`, `FLEET_GITHUB_APP_INSTALLATIONS` and
    /// `FLEET_GITHUB_APP_REPOS`. The id and the key file are both set or both unset: one without
    /// the other refuses start. The bot and account variables are required once the App is set;
    /// the installation and repository lists are optional and an unset list allows nothing.
    /// `None` when the id and the key file are unset or empty.
    pub github_app: Option<GithubAppConfig>,
    /// Repository hosts a User may add, from `FLEET_REPO_HOSTS`. Unset gives the `github.com`
    /// entry; the empty string gives no hosts, which refuses every add. A set value that does not
    /// parse refuses start without echoing it.
    pub repo_hosts: RepoHosts,
}

/// The GitHub App id, the path of its private key, the bot identity and the allowlist policy
/// (ADR-0058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubAppConfig {
    /// The App id: 1 to 20 ASCII digits with no leading zero, in the range of `u64`.
    pub app_id: u64,
    /// Path of the PEM private key. [`AppKey::load`] checks the file at startup.
    pub key_file: PathBuf,
    /// The git name and email an App Job commits under, validated by the ADR-0058 SEC-006 grammar.
    pub bot: BotIdentity,
    /// The operator account, the installation allowlist and the repository allowlist
    /// (ADR-0058, SEC-001, SEC-002, SEC-009, SEC-014).
    pub policy: AppPolicy,
}

impl GithubAppConfig {
    /// The App id as the JWT `iss` text.
    pub fn app_id_text(&self) -> String {
        self.app_id.to_string()
    }

    /// Loads the private key.
    ///
    /// # Errors
    ///
    /// Returns [`AppKeyError`] when the file is unreadable, owned by another uid than the server's,
    /// loosely permissioned, not a regular file or not a usable RSA key.
    pub fn load_key(&self) -> Result<AppKey, AppKeyError> {
        AppKey::load(&self.key_file)
    }
}

/// Why the credential store cannot start. Messages carry no key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialsStartError {
    /// Credential rows exist but `FLEET_MASTER_KEY_FILE` is unset.
    RowsWithoutKey,
    /// The key file is missing, unreadable or malformed.
    KeyRing(KeyRingError),
}

impl fmt::Display for CredentialsStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RowsWithoutKey => {
                f.write_str("credentials are stored but FLEET_MASTER_KEY_FILE is not set")
            }
            Self::KeyRing(err) => write!(f, "FLEET_MASTER_KEY_FILE: {err}"),
        }
    }
}

impl std::error::Error for CredentialsStartError {}

impl From<KeyRingError> for CredentialsStartError {
    fn from(err: KeyRingError) -> Self {
        Self::KeyRing(err)
    }
}

/// Whether the credential RPCs are available, decided once at startup (ADR-0040).
#[derive(Debug, Clone)]
pub enum CredentialsState {
    /// The key ring loaded; the credential RPCs may seal and open with it.
    Enabled(Arc<FileSealer>),
    /// No key file and no stored credentials; the credential RPCs are off.
    Disabled,
}

impl CredentialsState {
    /// The line logged once when the credential RPCs are off.
    pub const DISABLED_NOTICE: &'static str =
        "credential RPCs disabled: FLEET_MASTER_KEY_FILE is unset and no credentials are stored";

    /// Decides the state from the configured key file and whether any credential row exists.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsStartError::RowsWithoutKey`] when `key_file` is `None` and
    /// `rows_exist` is true, and [`CredentialsStartError::KeyRing`] when a configured key
    /// file cannot be loaded.
    pub fn resolve(
        key_file: Option<&Path>,
        rows_exist: bool,
    ) -> Result<Self, CredentialsStartError> {
        match key_file {
            Some(path) => Ok(Self::Enabled(Arc::new(FileSealer::load(path)?))),
            None if rows_exist => Err(CredentialsStartError::RowsWithoutKey),
            None => Ok(Self::Disabled),
        }
    }

    /// Whether the credential RPCs are available.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }
}

/// Lists the listeners bound to a non-loopback address, as `(variable, address)`.
pub fn exposed_binds(listen: &SocketAddr, health: &SocketAddr) -> Vec<(&'static str, SocketAddr)> {
    [("FLEET_LISTEN", *listen), ("FLEET_HEALTH_LISTEN", *health)]
        .into_iter()
        .filter(|(_, addr)| !is_loopback(addr))
        .collect()
}

/// Whether `addr` binds only the loopback interface, so nothing off the host can reach it.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

fn address(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: &str,
) -> Result<SocketAddr, ConfigError> {
    let raw = lookup(var).filter(|v| !v.is_empty());
    raw.as_deref()
        .unwrap_or(default)
        .parse()
        .map_err(|err: std::net::AddrParseError| ConfigError::Invalid {
            var,
            reason: err.to_string(),
        })
}

fn whole(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    let Some(raw) = lookup(var).filter(|v| !v.is_empty()) else {
        return Ok(default);
    };
    raw.parse().map_err(|_| ConfigError::Invalid {
        var,
        reason: "must be a whole number".to_owned(),
    })
}

fn number(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, ConfigError> {
    let value = whole(lookup, var, default)?;
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::Invalid {
            var,
            reason: format!("must be between {} and {}", range.start(), range.end()),
        })
    }
}

/// The variable that holds the model allowlist.
const MODEL_ALLOWLIST_VAR: &str = "FLEET_MODEL_ALLOWLIST";

const REMOVED_PROFILE_TOOLS_VAR: &str = "FLEET_ALLOW_PROFILE_TOOLS";

/// Refuses the removed `FLEET_ALLOW_PROFILE_TOOLS` switch when it is set to any value, the
/// empty string and `false` included. The reason never carries the value.
fn refuse_removed_profile_tools(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    match lookup(REMOVED_PROFILE_TOOLS_VAR) {
        None => Ok(()),
        Some(_) => Err(ConfigError::Invalid {
            var: REMOVED_PROFILE_TOOLS_VAR,
            reason: "this switch was removed; unset it and grant the profile:tools capability \
                     to each user that needs it (ADR-0054)"
                .to_owned(),
        }),
    }
}

fn model_allowlist(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<ModelAllowlist>, ConfigError> {
    lookup(MODEL_ALLOWLIST_VAR)
        .map(|raw| ModelAllowlist::parse(&raw))
        .transpose()
        .map_err(|err| ConfigError::Invalid {
            var: MODEL_ALLOWLIST_VAR,
            reason: err.to_string(),
        })
}

const MASTER_KEY_FILE_VAR: &str = "FLEET_MASTER_KEY_FILE";
const GITHUB_APP_ID_VAR: &str = "FLEET_GITHUB_APP_ID";
const GITHUB_APP_KEY_FILE_VAR: &str = "FLEET_GITHUB_APP_KEY_FILE";
const GITHUB_APP_BOT_NAME_VAR: &str = "FLEET_GITHUB_APP_BOT_NAME";
const GITHUB_APP_BOT_EMAIL_VAR: &str = "FLEET_GITHUB_APP_BOT_EMAIL";
const GITHUB_APP_ACCOUNT_VAR: &str = "FLEET_GITHUB_APP_ACCOUNT";
const GITHUB_APP_INSTALLATIONS_VAR: &str = "FLEET_GITHUB_APP_INSTALLATIONS";
const GITHUB_APP_REPOS_VAR: &str = "FLEET_GITHUB_APP_REPOS";

fn absolute(path: PathBuf, var: &'static str) -> Result<PathBuf, ConfigError> {
    std::path::absolute(path).map_err(|_| ConfigError::Invalid {
        var,
        reason: "cannot be made an absolute path".to_owned(),
    })
}

fn master_key_file(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<PathBuf>, ConfigError> {
    lookup(MASTER_KEY_FILE_VAR)
        .filter(|v| !v.is_empty())
        .map(|v| absolute(PathBuf::from(v), MASTER_KEY_FILE_VAR))
        .transpose()
}

fn github_app(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<GithubAppConfig>, ConfigError> {
    let id = lookup(GITHUB_APP_ID_VAR).filter(|v| !v.is_empty());
    let key_file = lookup(GITHUB_APP_KEY_FILE_VAR).filter(|v| !v.is_empty());
    let (id, key_file) = match (id, key_file) {
        (None, None) => return Ok(None),
        (Some(id), Some(key_file)) => (id, key_file),
        (Some(_), None) => {
            return Err(ConfigError::Invalid {
                var: GITHUB_APP_KEY_FILE_VAR,
                reason: format!("required when {GITHUB_APP_ID_VAR} is set"),
            });
        }
        (None, Some(_)) => {
            return Err(ConfigError::Invalid {
                var: GITHUB_APP_ID_VAR,
                reason: format!("required when {GITHUB_APP_KEY_FILE_VAR} is set"),
            });
        }
    };
    let valid = id.len() <= 20 && !id.starts_with('0') && id.bytes().all(|b| b.is_ascii_digit());
    let app_id = valid
        .then(|| id.parse::<u64>().ok())
        .flatten()
        .ok_or_else(|| ConfigError::Invalid {
            var: GITHUB_APP_ID_VAR,
            reason: "must be 1 to 20 ASCII digits without a leading zero, within u64".to_owned(),
        })?;
    let name =
        lookup(GITHUB_APP_BOT_NAME_VAR).ok_or(ConfigError::Missing(GITHUB_APP_BOT_NAME_VAR))?;
    let email =
        lookup(GITHUB_APP_BOT_EMAIL_VAR).ok_or(ConfigError::Missing(GITHUB_APP_BOT_EMAIL_VAR))?;
    let bot = BotIdentity::new(&name, &email).map_err(|err| ConfigError::Invalid {
        var: match err {
            BotIdentityError::Name => GITHUB_APP_BOT_NAME_VAR,
            BotIdentityError::Email => GITHUB_APP_BOT_EMAIL_VAR,
        },
        reason: err.to_string(),
    })?;
    let account =
        lookup(GITHUB_APP_ACCOUNT_VAR).ok_or(ConfigError::Missing(GITHUB_APP_ACCOUNT_VAR))?;
    let policy = AppPolicy::parse(
        &account,
        lookup(GITHUB_APP_INSTALLATIONS_VAR).as_deref(),
        lookup(GITHUB_APP_REPOS_VAR).as_deref(),
    )
    .map_err(|err| ConfigError::Invalid {
        var: match err {
            AppPolicyError::Account => GITHUB_APP_ACCOUNT_VAR,
            AppPolicyError::Installations => GITHUB_APP_INSTALLATIONS_VAR,
            AppPolicyError::Repositories => GITHUB_APP_REPOS_VAR,
        },
        reason: err.to_string(),
    })?;
    Ok(Some(GithubAppConfig {
        app_id,
        key_file: absolute(PathBuf::from(key_file), GITHUB_APP_KEY_FILE_VAR)?,
        bot,
        policy,
    }))
}

fn repo_hosts(lookup: &impl Fn(&str) -> Option<String>) -> Result<RepoHosts, ConfigError> {
    lookup(REPO_HOSTS_VAR)
        .map_or_else(|| Ok(RepoHosts::default()), |raw| RepoHosts::parse(&raw))
        .map_err(|err| ConfigError::Invalid {
            var: REPO_HOSTS_VAR,
            reason: err.to_string(),
        })
}

fn ci_retries(lookup: &impl Fn(&str) -> Option<String>) -> Result<u32, ConfigError> {
    let value = number(
        lookup,
        "FLEET_MAX_CI_RETRIES",
        u64::from(DEFAULT_CI_RETRIES),
        0..=u64::from(MAX_CI_RETRIES),
    )?;
    u32::try_from(value).map_err(|_| ConfigError::Invalid {
        var: "FLEET_MAX_CI_RETRIES",
        reason: "out of range".to_owned(),
    })
}

fn retention(lookup: &impl Fn(&str) -> Option<String>) -> Result<Policy, ConfigError> {
    let events = whole(
        lookup,
        "FLEET_EVENTS_RETENTION_DAYS",
        u64::from(DEFAULT_EVENTS_DAYS),
    )?;
    let summaries = whole(
        lookup,
        "FLEET_SUMMARIES_RETENTION_DAYS",
        u64::from(DEFAULT_SUMMARIES_DAYS),
    )?;
    let narrow = |value: u64| u32::try_from(value).unwrap_or(u32::MAX);
    Policy::new(narrow(events), narrow(summaries)).map_err(|err| ConfigError::Invalid {
        var: match err {
            PolicyError::EventsDaysOutOfRange => "FLEET_EVENTS_RETENTION_DAYS",
            _ => "FLEET_SUMMARIES_RETENTION_DAYS",
        },
        reason: err.to_string(),
    })
}

impl Config {
    /// Reads the settings from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when `FLEET_DATABASE_URL` or `FLEET_TOKEN` is missing or empty,
    /// `FLEET_CLIENT_TOKEN` is set but invalid or equal to `FLEET_TOKEN`, an address does not
    /// parse, or a retention setting is out of range. Retention days run from 1 to 3650,
    /// `FLEET_SUMMARIES_RETENTION_DAYS` must not be below `FLEET_EVENTS_RETENTION_DAYS`, and
    /// `FLEET_RETENTION_INTERVAL_SECS` is at least 60. `FLEET_MAX_CI_RETRIES` runs from 0 to 5 and
    /// defaults to 0. `FLEET_GITHUB_APP_ID` without `FLEET_GITHUB_APP_KEY_FILE`, or the reverse, is
    /// an error, and so is an App id that is not 1 to 20 ASCII digits without a leading zero that
    /// fits a `u64`. With the App set, `FLEET_GITHUB_APP_BOT_NAME` and `FLEET_GITHUB_APP_BOT_EMAIL`
    /// are required and must pass [`BotIdentity::new`], and so is `FLEET_GITHUB_APP_ACCOUNT`, a
    /// GitHub login. The optional `FLEET_GITHUB_APP_INSTALLATIONS` and `FLEET_GITHUB_APP_REPOS` are
    /// checked against the allowlist grammar and an unset one allows nothing. The App also requires
    /// `FLEET_MASTER_KEY_FILE`. A set `FLEET_REPO_HOSTS` that fails [`RepoHosts::parse`] is
    /// [`ConfigError::Invalid`] for that variable. The App key file and the master key file are
    /// made absolute against the working directory here. `FLEET_UPDATE_REPO` must pass
    /// [`UpdateRepo::parse`], must not be set with `FLEET_UPDATE_MANIFEST`, and
    /// `FLEET_UPDATE_POLL_SECS` runs from 60 to 86400 and defaults to 900.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the settings through `lookup`, which maps a variable name to its value.
    ///
    /// # Errors
    ///
    /// Same as [`Config::from_env`]: the GitHub App variables are both set or both unset, and
    /// the App id is 1 to 20 ASCII digits without a leading zero that fit a `u64`. With the App
    /// set, a bot name, email or account that is unset, or that fails [`BotIdentity::new`] or
    /// the login grammar, returns [`ConfigError::Missing`] or [`ConfigError::Invalid`], and so
    /// does an installation or repository list outside its grammar (a repository entry whose
    /// owner is not the account included). An App without a master key file
    /// is [`ConfigError::Invalid`] for `FLEET_MASTER_KEY_FILE`, and so is a key path that cannot
    /// be made absolute.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        refuse_removed_profile_tools(&lookup)?;
        let database_url = lookup("FLEET_DATABASE_URL")
            .filter(|v| !v.is_empty())
            .ok_or(ConfigError::Missing("FLEET_DATABASE_URL"))?;
        let token = Token::new(lookup("FLEET_TOKEN").unwrap_or_default())?;
        let client_token = lookup("FLEET_CLIENT_TOKEN")
            .filter(|v| !v.is_empty())
            .map(|raw| Token::named("FLEET_CLIENT_TOKEN", raw))
            .transpose()?;
        if client_token.as_ref() == Some(&token) {
            return Err(ConfigError::Invalid {
                var: "FLEET_CLIENT_TOKEN",
                reason: "must differ from FLEET_TOKEN".to_owned(),
            });
        }
        let master_key_file = master_key_file(&lookup)?;
        let github_app = github_app(&lookup)?;
        if github_app.is_some() && master_key_file.is_none() {
            return Err(ConfigError::Invalid {
                var: MASTER_KEY_FILE_VAR,
                reason: format!("required when {GITHUB_APP_ID_VAR} is set"),
            });
        }
        let update_manifest = lookup(UPDATE_MANIFEST_VAR)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let update_repo = lookup(UPDATE_REPO_VAR)
            .filter(|v| !v.is_empty())
            .map(|raw| {
                UpdateRepo::parse(&raw).map_err(|err| ConfigError::Invalid {
                    var: UPDATE_REPO_VAR,
                    reason: err.to_string(),
                })
            })
            .transpose()?;
        if update_repo.is_some() && update_manifest.is_some() {
            return Err(ConfigError::Invalid {
                var: UPDATE_REPO_VAR,
                reason: format!("must not be set together with {UPDATE_MANIFEST_VAR}"),
            });
        }
        let update_poll = Duration::from_secs(number(
            &lookup,
            UPDATE_POLL_VAR,
            DEFAULT_UPDATE_POLL_SECS,
            MIN_UPDATE_POLL_SECS..=MAX_UPDATE_POLL_SECS,
        )?);
        Ok(Self {
            listen: address(&lookup, "FLEET_LISTEN", DEFAULT_LISTEN)?,
            health_listen: address(&lookup, "FLEET_HEALTH_LISTEN", DEFAULT_HEALTH_LISTEN)?,
            database_url: Secret::new(database_url),
            token,
            client_token,
            retention: retention(&lookup)?,
            max_ci_retries: ci_retries(&lookup)?,
            model_allowlist: model_allowlist(&lookup)?,
            github_app,
            repo_hosts: repo_hosts(&lookup)?,
            master_key_file,
            update_manifest,
            update_repo,
            update_poll,
            web_origin: lookup("FLEET_WEB_ORIGIN").filter(|v| !v.is_empty()),
            web_rp_id: lookup("FLEET_WEB_RP_ID").filter(|v| !v.is_empty()),
            bootstrap_password: lookup("FLEET_BOOTSTRAP_PASSWORD")
                .filter(|v| !v.is_empty())
                .map(Secret::new),
            trusted_proxy_hops: usize::try_from(number(
                &lookup,
                "FLEET_TRUSTED_PROXY_HOPS",
                0,
                0..=MAX_TRUSTED_HOPS as u64,
            )?)
            .unwrap_or(0),
            retention_interval: Duration::from_secs(number(
                &lookup,
                "FLEET_RETENTION_INTERVAL_SECS",
                DEFAULT_INTERVAL.as_secs(),
                MIN_INTERVAL.as_secs()..=u64::from(u32::MAX),
            )?),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |var| map.get(var).cloned()
    }

    #[test]
    fn defaults_apply() {
        let config = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://u:pw@h/db"),
            ("FLEET_TOKEN", TOKEN),
        ]))
        .unwrap();
        assert_eq!(config.listen.to_string(), "127.0.0.1:7070");
        assert_eq!(config.health_listen.to_string(), "0.0.0.0:7072");
        assert_eq!(config.token.expose(), TOKEN);
        assert_eq!(config.model_allowlist, None);
    }

    fn with_allowlist(raw: &str) -> Result<Config, ConfigError> {
        let mut vars: Vec<(&str, &str)> = base();
        vars.push(("FLEET_MODEL_ALLOWLIST", raw));
        Config::from_lookup(lookup(&vars))
    }

    #[test]
    fn model_allowlist_is_read_from_the_environment() {
        let config = with_allowlist("claude-opus-4-1,claude-sonnet-4-5").unwrap();
        let list = config.model_allowlist.unwrap();
        assert_eq!(list.entries(), ["claude-opus-4-1", "claude-sonnet-4-5"]);
        assert!(list.allows("claude-opus-4-1"));
        assert!(!list.allows("Claude-Opus-4-1"));
    }

    #[test]
    fn a_bad_model_allowlist_refuses_start_without_echoing_it() {
        let over_long = "x".repeat(fleet_core::MAX_MODEL_BYTES + 1);
        let many = (0..=fleet_core::model_allowlist::MAX_ENTRIES)
            .map(|n| format!("m{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("empty entry", "a,,b".into()),
            ("trailing comma", "a,".into()),
            ("cr", "a\rb".into()),
            ("crlf", "a\r\nb".into()),
            ("nel", "a\u{85}b".into()),
            ("line separator", "a\u{2028}b".into()),
            ("backslash", "a\\b".into()),
            ("space", "a b".into()),
            ("padded", " a".into()),
            ("non-ascii", "mod\u{e8}le".into()),
            ("duplicate", "a,a".into()),
            ("over-long entry", over_long),
            ("too many entries", many),
        ];
        for (label, raw) in cases {
            let err = with_allowlist(&raw).unwrap_err();
            match &err {
                ConfigError::Invalid { var, reason } => {
                    assert_eq!(*var, "FLEET_MODEL_ALLOWLIST", "{label}");
                    assert!(raw.len() < 8 || !reason.contains(&raw), "{label}");
                }
                other => panic!("{label}: {other}"),
            }
            assert!(!err.to_string().contains('\r'), "{label}");
        }
    }

    #[test]
    fn model_allowlist_accepts_the_entry_limit() {
        let max = (0..fleet_core::model_allowlist::MAX_ENTRIES)
            .map(|n| format!("m{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let config = with_allowlist(&max).unwrap();
        assert_eq!(
            config.model_allowlist.unwrap().entries().len(),
            fleet_core::model_allowlist::MAX_ENTRIES
        );
    }

    fn key_file(tag: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fleet-cred28-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn good_ring() -> String {
        format!("k1:{}\n", "ab".repeat(32))
    }

    #[test]
    fn the_removed_profile_tools_switch_fails_startup_for_any_value() {
        let base = [
            ("FLEET_DATABASE_URL", "postgres://u:pw@h/db"),
            ("FLEET_TOKEN", TOKEN),
        ];
        assert!(Config::from_lookup(lookup(&base)).is_ok());
        for text in ["true", "false", "", "1", "zzz-echo-probe"] {
            let err = Config::from_lookup(lookup(&[
                base[0],
                base[1],
                ("FLEET_ALLOW_PROFILE_TOOLS", text),
            ]))
            .unwrap_err();
            let shown = err.to_string();
            assert!(shown.contains("FLEET_ALLOW_PROFILE_TOOLS"), "{text:?}");
            assert!(shown.contains("profile:tools"), "{text:?}");
            assert!(shown.contains("ADR-0054"), "{text:?}");
            assert!(text.is_empty() || !shown.contains(text), "{text:?}");
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: "FLEET_ALLOW_PROFILE_TOOLS",
                        ..
                    }
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn update_manifest_is_read_from_the_environment() {
        let base = [
            ("FLEET_DATABASE_URL", "postgres://u:pw@h/db"),
            ("FLEET_TOKEN", TOKEN),
        ];
        let unset = Config::from_lookup(lookup(&base)).unwrap();
        assert_eq!(unset.update_manifest, None);
        let empty = Config::from_lookup(lookup(&[base[0], base[1], ("FLEET_UPDATE_MANIFEST", "")]))
            .unwrap();
        assert_eq!(empty.update_manifest, None);
        let set = Config::from_lookup(lookup(&[
            base[0],
            base[1],
            ("FLEET_UPDATE_MANIFEST", "/etc/fleet/manifest.json"),
        ]))
        .unwrap();
        assert_eq!(
            set.update_manifest,
            Some(PathBuf::from("/etc/fleet/manifest.json"))
        );
    }

    fn with_update(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let mut all = vec![
            ("FLEET_DATABASE_URL", "postgres://u:pw@h/db"),
            ("FLEET_TOKEN", TOKEN),
        ];
        all.extend_from_slice(pairs);
        Config::from_lookup(lookup(&all))
    }

    #[test]
    fn update_repo_accepts_the_grammar() {
        for raw in [
            "o/r",
            "Owner-1/Repo.name_x-y",
            "a/.hidden",
            "a/..x",
            "a/x..",
            "a/...",
            "A/B",
            "-/-",
        ] {
            let parsed = UpdateRepo::parse(raw).unwrap_or_else(|err| panic!("{raw:?}: {err}"));
            assert_eq!(parsed.to_string(), raw);
        }
        let parsed = UpdateRepo::parse("Acme/Fleet.rs").unwrap();
        assert_eq!(parsed.owner(), "Acme");
        assert_eq!(parsed.repo(), "Fleet.rs");
    }

    #[test]
    fn update_repo_hostile_input_table() {
        let long_owner = format!("{}/r", "a".repeat(MAX_UPDATE_OWNER_LEN + 1));
        let long_repo = format!("o/{}", "a".repeat(MAX_UPDATE_REPO_LEN + 1));
        let table: Vec<(&str, String, UpdateRepoError)> = vec![
            ("empty", String::new(), UpdateRepoError::Shape),
            ("no slash", "owner".into(), UpdateRepoError::Shape),
            ("extra slash", "o/r/x".into(), UpdateRepoError::Shape),
            ("trailing slash", "o/r/".into(), UpdateRepoError::Shape),
            ("leading slash", "/o/r".into(), UpdateRepoError::Shape),
            ("empty owner", "/r".into(), UpdateRepoError::Owner),
            ("empty repo", "o/".into(), UpdateRepoError::Repo),
            ("only slash", "/".into(), UpdateRepoError::Owner),
            ("cr", "o/r\r".into(), UpdateRepoError::Repo),
            ("crlf", "o/r\r\n".into(), UpdateRepoError::Repo),
            ("lf", "o/r\n".into(), UpdateRepoError::Repo),
            ("cr in owner", "o\r/r".into(), UpdateRepoError::Owner),
            ("nel", "o/r\u{85}".into(), UpdateRepoError::Repo),
            ("u2028", "o/r\u{2028}".into(), UpdateRepoError::Repo),
            ("u2029", "o/r\u{2029}".into(), UpdateRepoError::Repo),
            ("userinfo at", "user@host/r".into(), UpdateRepoError::Owner),
            ("at in repo", "o/r@h".into(), UpdateRepoError::Repo),
            ("backslash owner", "o\\x/r".into(), UpdateRepoError::Owner),
            ("backslash repo", "o/r\\x".into(), UpdateRepoError::Repo),
            ("colon owner", "o:1/r".into(), UpdateRepoError::Owner),
            ("colon repo", "o/r:1".into(), UpdateRepoError::Repo),
            ("scheme", "https://o/r".into(), UpdateRepoError::Shape),
            ("ipv6", "[::1]/r".into(), UpdateRepoError::Owner),
            ("ipv6 repo", "o/[::1]".into(), UpdateRepoError::Repo),
            ("space owner", " o/r".into(), UpdateRepoError::Owner),
            ("space repo", "o/r ".into(), UpdateRepoError::Repo),
            ("tab", "o/r\t".into(), UpdateRepoError::Repo),
            ("inner space", "o/r r".into(), UpdateRepoError::Repo),
            ("nbsp", "o/r\u{a0}".into(), UpdateRepoError::Repo),
            ("non-ascii owner", "ö/r".into(), UpdateRepoError::Owner),
            ("non-ascii repo", "o/rö".into(), UpdateRepoError::Repo),
            (
                "fullwidth slash",
                "o\u{ff0f}r".into(),
                UpdateRepoError::Shape,
            ),
            ("dot owner", "./r".into(), UpdateRepoError::Owner),
            ("underscore owner", "o_x/r".into(), UpdateRepoError::Owner),
            ("dot repo", "o/.".into(), UpdateRepoError::Repo),
            ("dotdot repo", "o/..".into(), UpdateRepoError::Repo),
            ("dotdot owner", "../r".into(), UpdateRepoError::Owner),
            ("percent", "o/%2e%2e".into(), UpdateRepoError::Repo),
            ("query", "o/r?x=1".into(), UpdateRepoError::Repo),
            ("fragment", "o/r#x".into(), UpdateRepoError::Repo),
            ("nul", "o/r\0".into(), UpdateRepoError::Repo),
            ("over-long owner", long_owner, UpdateRepoError::Owner),
            ("over-long repo", long_repo, UpdateRepoError::Repo),
        ];
        for (label, raw, want) in table {
            assert_eq!(UpdateRepo::parse(&raw), Err(want), "{label}");
            if raw.is_empty() {
                continue;
            }
            let err = with_update(&[("FLEET_UPDATE_REPO", &raw)]).unwrap_err();
            match err {
                ConfigError::Invalid { var, reason } => {
                    assert_eq!(var, "FLEET_UPDATE_REPO", "{label}");
                    assert_eq!(reason, want.to_string(), "{label}");
                }
                other => panic!("{label}: {other}"),
            }
        }
    }

    #[test]
    fn update_repo_limits_hold_at_the_boundary_and_just_over() {
        let owner = |n: usize| format!("{}/r", "a".repeat(n));
        let repo = |n: usize| format!("o/{}", "a".repeat(n));
        assert!(UpdateRepo::parse(&owner(MAX_UPDATE_OWNER_LEN)).is_ok());
        assert!(UpdateRepo::parse(&owner(1)).is_ok());
        assert_eq!(
            UpdateRepo::parse(&owner(MAX_UPDATE_OWNER_LEN + 1)),
            Err(UpdateRepoError::Owner)
        );
        assert!(UpdateRepo::parse(&repo(MAX_UPDATE_REPO_LEN)).is_ok());
        assert!(UpdateRepo::parse(&repo(1)).is_ok());
        assert_eq!(
            UpdateRepo::parse(&repo(MAX_UPDATE_REPO_LEN + 1)),
            Err(UpdateRepoError::Repo)
        );
        assert_eq!(MAX_UPDATE_OWNER_LEN, 39);
        assert_eq!(MAX_UPDATE_REPO_LEN, 100);
    }

    #[test]
    fn update_repo_is_read_from_the_environment() {
        assert_eq!(with_update(&[]).unwrap().update_repo, None);
        assert_eq!(
            with_update(&[("FLEET_UPDATE_REPO", "")])
                .unwrap()
                .update_repo,
            None
        );
        let set = with_update(&[("FLEET_UPDATE_REPO", "Acme/fleet")]).unwrap();
        assert_eq!(
            set.update_repo,
            Some(UpdateRepo::parse("Acme/fleet").unwrap())
        );
    }

    #[test]
    fn update_repo_with_update_manifest_refuses_start() {
        let err = with_update(&[
            ("FLEET_UPDATE_REPO", "acme/fleet"),
            ("FLEET_UPDATE_MANIFEST", "/etc/fleet/manifest.json"),
        ])
        .unwrap_err();
        match err {
            ConfigError::Invalid { var, reason } => {
                assert_eq!(var, "FLEET_UPDATE_REPO");
                assert!(reason.contains("FLEET_UPDATE_MANIFEST"));
            }
            other => panic!("{other}"),
        }
        assert!(
            with_update(&[
                ("FLEET_UPDATE_REPO", ""),
                ("FLEET_UPDATE_MANIFEST", "/etc/fleet/manifest.json"),
            ])
            .is_ok()
        );
        assert!(
            with_update(&[
                ("FLEET_UPDATE_REPO", "acme/fleet"),
                ("FLEET_UPDATE_MANIFEST", ""),
            ])
            .is_ok()
        );
    }

    #[test]
    fn update_poll_secs_defaults_and_enforces_its_range() {
        assert_eq!(
            with_update(&[]).unwrap().update_poll,
            Duration::from_secs(900)
        );
        for (value, ok) in [
            ("59", false),
            ("60", true),
            ("61", true),
            ("900", true),
            ("86399", true),
            ("86400", true),
            ("86401", false),
            ("0", false),
            ("-1", false),
            ("x", false),
            ("1e3", false),
            (" 900", false),
            ("18446744073709551616", false),
        ] {
            let got = with_update(&[("FLEET_UPDATE_POLL_SECS", value)]);
            assert_eq!(got.is_ok(), ok, "{value:?}");
            match got {
                Ok(config) => assert_eq!(
                    config.update_poll,
                    Duration::from_secs(value.parse().unwrap())
                ),
                Err(ConfigError::Invalid { var, .. }) => {
                    assert_eq!(var, "FLEET_UPDATE_POLL_SECS", "{value:?}");
                }
                Err(other) => panic!("{value:?}: {other}"),
            }
        }
    }

    #[test]
    fn update_poll_secs_range_error_names_the_range() {
        let err = with_update(&[("FLEET_UPDATE_POLL_SECS", "59")]).unwrap_err();
        assert!(err.to_string().contains("between 60 and 86400"), "{err}");
    }

    #[test]
    fn master_key_file_is_read_from_the_environment() {
        let base = [
            ("FLEET_DATABASE_URL", "postgres://u:pw@h/db"),
            ("FLEET_TOKEN", TOKEN),
        ];
        let unset = Config::from_lookup(lookup(&base)).unwrap();
        assert_eq!(unset.master_key_file, None);
        let empty = Config::from_lookup(lookup(&[base[0], base[1], ("FLEET_MASTER_KEY_FILE", "")]))
            .unwrap();
        assert_eq!(empty.master_key_file, None);
        let set = Config::from_lookup(lookup(&[
            base[0],
            base[1],
            ("FLEET_MASTER_KEY_FILE", "/run/keys"),
        ]))
        .unwrap();
        assert_eq!(set.master_key_file, Some(PathBuf::from("/run/keys")));
    }

    #[test]
    fn no_key_file_and_no_rows_disables_credentials() {
        let state = CredentialsState::resolve(None, false).unwrap();
        assert!(!state.is_enabled());
    }

    #[test]
    fn no_key_file_with_rows_is_a_startup_error() {
        let err = CredentialsState::resolve(None, true).unwrap_err();
        assert_eq!(err, CredentialsStartError::RowsWithoutKey);
        assert_eq!(
            err.to_string(),
            "credentials are stored but FLEET_MASTER_KEY_FILE is not set"
        );
    }

    #[test]
    fn readable_key_file_enables_credentials() {
        let path = key_file("ok", &good_ring());
        for rows in [false, true] {
            let state = CredentialsState::resolve(Some(&path), rows).unwrap();
            assert!(state.is_enabled());
        }
    }

    #[test]
    fn missing_or_bad_key_file_is_a_startup_error_without_key_text() {
        let dir = std::env::temp_dir().join(format!("fleet-cred28-{}-none", std::process::id()));
        let missing = CredentialsState::resolve(Some(&dir.join("absent")), false).unwrap_err();
        assert_eq!(
            missing,
            CredentialsStartError::KeyRing(KeyRingError::Missing)
        );
        let secret = "ab".repeat(31);
        let bad = key_file("bad", &format!("k1:{secret}\n"));
        let err = CredentialsState::resolve(Some(&bad), false).unwrap_err();
        assert!(matches!(
            err,
            CredentialsStartError::KeyRing(KeyRingError::BadKeyLength(1))
        ));
        assert!(!err.to_string().contains(&secret));
        assert!(!format!("{err:?}").contains(&secret));
    }

    #[test]
    fn state_debug_hides_the_key() {
        let path = key_file("dbg", &good_ring());
        let state = CredentialsState::resolve(Some(&path), false).unwrap();
        assert!(!format!("{state:?}").contains(&"ab".repeat(32)));
    }

    #[test]
    fn exposed_binds_names_each_non_loopback_listener() {
        let local: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let open: SocketAddr = "0.0.0.0:2".parse().unwrap();
        assert_eq!(exposed_binds(&local, &local), vec![]);
        assert_eq!(
            exposed_binds(&local, &open),
            vec![("FLEET_HEALTH_LISTEN", open)]
        );
        assert_eq!(
            exposed_binds(&open, &open),
            vec![("FLEET_LISTEN", open), ("FLEET_HEALTH_LISTEN", open)]
        );
    }

    #[test]
    fn loopback_predicate_separates_local_from_exposed_binds() {
        let loopback = ["127.0.0.1:7070", "127.9.9.9:1", "[::1]:7070"];
        let exposed = [
            "0.0.0.0:7070",
            "[::]:7070",
            "10.0.0.5:7070",
            "192.168.1.2:80",
        ];
        for raw in loopback {
            assert!(is_loopback(&raw.parse().unwrap()), "{raw}");
        }
        for raw in exposed {
            assert!(!is_loopback(&raw.parse().unwrap()), "{raw}");
        }
    }

    #[test]
    fn overrides_apply() {
        let config = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://h/db"),
            ("FLEET_TOKEN", TOKEN),
            ("FLEET_LISTEN", "127.0.0.1:9000"),
            ("FLEET_HEALTH_LISTEN", "127.0.0.1:9001"),
        ]))
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.health_listen.port(), 9001);
    }

    #[test]
    fn missing_or_empty_token_refuses_start() {
        let url = ("FLEET_DATABASE_URL", "postgres://h/db");
        assert_eq!(
            Config::from_lookup(lookup(&[url])).unwrap_err(),
            ConfigError::Missing("FLEET_TOKEN")
        );
        assert_eq!(
            Config::from_lookup(lookup(&[url, ("FLEET_TOKEN", "")])).unwrap_err(),
            ConfigError::Missing("FLEET_TOKEN")
        );
    }

    #[test]
    fn client_token_is_optional_validated_and_distinct() {
        let base = [
            ("FLEET_DATABASE_URL", "postgres://h/db"),
            ("FLEET_TOKEN", TOKEN),
        ];
        let with = |value: &'static str| {
            let mut vars = base.to_vec();
            vars.push(("FLEET_CLIENT_TOKEN", value));
            Config::from_lookup(lookup(&vars))
        };
        assert!(
            Config::from_lookup(lookup(&base))
                .unwrap()
                .client_token
                .is_none()
        );
        assert!(with("").unwrap().client_token.is_none());
        let other = "fedcba9876543210fedcba9876543210";
        assert_eq!(with(other).unwrap().client_token.unwrap().expose(), other);
        for bad in ["short", " fedcba9876543210fedcba9876543210", TOKEN] {
            assert!(matches!(
                with(bad).unwrap_err(),
                ConfigError::Invalid {
                    var: "FLEET_CLIENT_TOKEN",
                    ..
                }
            ));
        }
    }

    #[test]
    fn missing_database_url_refuses_start() {
        assert_eq!(
            Config::from_lookup(lookup(&[("FLEET_TOKEN", TOKEN)])).unwrap_err(),
            ConfigError::Missing("FLEET_DATABASE_URL")
        );
    }

    #[test]
    fn bad_address_is_reported() {
        let err = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://h/db"),
            ("FLEET_TOKEN", TOKEN),
            ("FLEET_LISTEN", "nope"),
        ]))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "FLEET_LISTEN",
                ..
            }
        ));
    }

    #[test]
    fn short_or_padded_token_refuses_start() {
        let url = ("FLEET_DATABASE_URL", "postgres://h/db");
        let padded = format!(" {TOKEN}");
        for token in ["short", padded.as_str(), "0123456789abcdef0123456789abcde"] {
            let err = Config::from_lookup(lookup(&[url, ("FLEET_TOKEN", token)])).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: "FLEET_TOKEN",
                        ..
                    }
                ),
                "{token:?}"
            );
        }
    }

    fn base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("FLEET_DATABASE_URL", "postgres://h/db"),
            ("FLEET_TOKEN", TOKEN),
        ]
    }

    fn with(extra: &[(&'static str, &'static str)]) -> Result<Config, ConfigError> {
        let mut vars = base();
        vars.extend_from_slice(extra);
        Config::from_lookup(lookup(&vars))
    }

    const BOT_NAME: &str = "fleet-bot[bot]";
    const BOT_EMAIL: &str = "12345+fleet-bot[bot]@users.noreply.github.com";

    fn with_app(
        name: Option<&'static str>,
        email: Option<&'static str>,
    ) -> Result<Config, ConfigError> {
        let mut extra = vec![
            ("FLEET_GITHUB_APP_ID", "1"),
            ("FLEET_GITHUB_APP_KEY_FILE", "/k.pem"),
        ];
        extra.push(("FLEET_GITHUB_APP_ACCOUNT", "acme"));
        extra.extend(name.map(|n| ("FLEET_GITHUB_APP_BOT_NAME", n)));
        extra.extend(email.map(|e| ("FLEET_GITHUB_APP_BOT_EMAIL", e)));
        with(&extra)
    }

    #[test]
    fn github_app_requires_the_bot_identity() {
        for (name, email, want) in [
            (None, Some(BOT_EMAIL), "FLEET_GITHUB_APP_BOT_NAME"),
            (Some(BOT_NAME), None, "FLEET_GITHUB_APP_BOT_EMAIL"),
            (Some(""), Some(BOT_EMAIL), "FLEET_GITHUB_APP_BOT_NAME"),
            (Some(BOT_NAME), Some(""), "FLEET_GITHUB_APP_BOT_EMAIL"),
        ] {
            match with_app(name, email).unwrap_err() {
                ConfigError::Missing(var) | ConfigError::Invalid { var, .. } => {
                    assert_eq!(var, want, "{name:?} {email:?}");
                }
            }
        }
    }

    #[test]
    fn github_app_requires_the_account_and_checks_the_allowlists() {
        let app = |extra: &[(&'static str, &'static str)]| {
            let mut vars = vec![
                ("FLEET_GITHUB_APP_ID", "1"),
                ("FLEET_GITHUB_APP_KEY_FILE", "/k.pem"),
                ("FLEET_MASTER_KEY_FILE", "/run/keys"),
                ("FLEET_GITHUB_APP_BOT_NAME", BOT_NAME),
                ("FLEET_GITHUB_APP_BOT_EMAIL", BOT_EMAIL),
            ];
            vars.extend_from_slice(extra);
            with(&vars)
        };
        for account in [None, Some("")] {
            let extra: Vec<_> = account
                .map(|a| ("FLEET_GITHUB_APP_ACCOUNT", a))
                .into_iter()
                .collect();
            let err = app(&extra).unwrap_err();
            match (account, err) {
                (None, ConfigError::Missing(var)) | (Some(_), ConfigError::Invalid { var, .. }) => {
                    assert_eq!(var, "FLEET_GITHUB_APP_ACCOUNT");
                }
                (_, other) => panic!("{other}"),
            }
        }
        let denies_all = app(&[("FLEET_GITHUB_APP_ACCOUNT", "acme")])
            .unwrap()
            .github_app
            .unwrap()
            .policy;
        assert!(!denies_all.installation_allowed(1));
        assert!(!denies_all.repo_allowed("acme/widget"));
        for (var, value) in [
            ("FLEET_GITHUB_APP_ACCOUNT", "ac me"),
            ("FLEET_GITHUB_APP_INSTALLATIONS", "01"),
            ("FLEET_GITHUB_APP_INSTALLATIONS", "1,"),
            ("FLEET_GITHUB_APP_REPOS", "acme/wid*"),
            ("FLEET_GITHUB_APP_REPOS", "other/widget"),
            ("FLEET_GITHUB_APP_REPOS", "acme/widget\n"),
        ] {
            let mut extra = vec![("FLEET_GITHUB_APP_ACCOUNT", "acme"), (var, value)];
            extra.dedup_by_key(|(name, _)| *name);
            let extra: Vec<_> = if var == "FLEET_GITHUB_APP_ACCOUNT" {
                vec![(var, value)]
            } else {
                extra
            };
            match app(&extra).unwrap_err() {
                ConfigError::Invalid { var: got, reason } => {
                    assert_eq!(got, var, "{value:?}");
                    assert!(!reason.contains(value), "{reason}");
                }
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn github_app_refuses_a_hostile_bot_identity() {
        for bad in [" bot", "bot\n", "bot\u{2028}", "b<ot>", "bot\u{85}"] {
            match with_app(Some(bad), Some(BOT_EMAIL)).unwrap_err() {
                ConfigError::Invalid { var, reason } => {
                    assert_eq!(var, "FLEET_GITHUB_APP_BOT_NAME", "{bad:?}");
                    assert_eq!(reason, BotIdentityError::Name.to_string(), "{bad:?}");
                }
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
        for bad in [
            "1+A[bot]@users.noreply.github.com",
            "1+a[bot]@users.noreply.github.com\n",
            "x@evil.example",
        ] {
            match with_app(Some(BOT_NAME), Some(bad)).unwrap_err() {
                ConfigError::Invalid { var, .. } => {
                    assert_eq!(var, "FLEET_GITHUB_APP_BOT_EMAIL", "{bad:?}");
                }
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn github_app_is_none_when_both_are_unset_or_empty() {
        assert_eq!(with(&[]).unwrap().github_app, None);
        let empty = with(&[
            ("FLEET_GITHUB_APP_ID", ""),
            ("FLEET_GITHUB_APP_KEY_FILE", ""),
        ]);
        assert_eq!(empty.unwrap().github_app, None);
    }

    #[test]
    fn github_app_is_read_when_both_are_set() {
        let app = with(&[
            ("FLEET_GITHUB_APP_ID", "123456"),
            ("FLEET_GITHUB_APP_KEY_FILE", "keys/app.pem"),
            ("FLEET_MASTER_KEY_FILE", "/run/keys"),
            ("FLEET_GITHUB_APP_BOT_NAME", BOT_NAME),
            ("FLEET_GITHUB_APP_BOT_EMAIL", BOT_EMAIL),
            ("FLEET_GITHUB_APP_ACCOUNT", "Acme"),
            ("FLEET_GITHUB_APP_INSTALLATIONS", "4242,7"),
            ("FLEET_GITHUB_APP_REPOS", "acme/widget,ACME/*"),
        ])
        .unwrap()
        .github_app
        .unwrap();
        assert!(app.policy.installation_allowed(4242));
        assert!(app.policy.installation_allowed(7));
        assert!(!app.policy.installation_allowed(8));
        assert!(
            app.policy
                .repo_allowed("https://github.com/acme/anything.git")
        );
        assert!(!app.policy.repo_allowed("other/anything"));
        assert_eq!(app.bot.name(), BOT_NAME);
        assert_eq!(app.bot.email(), BOT_EMAIL);
        assert_eq!(app.app_id, 123_456);
        assert_eq!(app.app_id_text(), "123456");
        assert_eq!(app.key_file, std::path::absolute("keys/app.pem").unwrap());
        assert!(app.key_file.is_absolute());
    }

    #[test]
    fn master_key_file_is_made_absolute() {
        let config = with(&[("FLEET_MASTER_KEY_FILE", "keys/master")]).unwrap();
        assert_eq!(
            config.master_key_file,
            Some(std::path::absolute("keys/master").unwrap())
        );
    }

    #[test]
    fn github_app_without_a_master_key_refuses_start() {
        for master in [None, Some("")] {
            let mut extra = vec![
                ("FLEET_GITHUB_APP_ID", "1"),
                ("FLEET_GITHUB_APP_KEY_FILE", "/k.pem"),
                ("FLEET_GITHUB_APP_BOT_NAME", BOT_NAME),
                ("FLEET_GITHUB_APP_BOT_EMAIL", BOT_EMAIL),
                ("FLEET_GITHUB_APP_ACCOUNT", "acme"),
            ];
            extra.extend(master.map(|m| ("FLEET_MASTER_KEY_FILE", m)));
            match with(&extra).unwrap_err() {
                ConfigError::Invalid { var, .. } => assert_eq!(var, "FLEET_MASTER_KEY_FILE"),
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn github_app_id_without_key_file_refuses_start() {
        for key in [None, Some("")] {
            let mut extra = vec![("FLEET_GITHUB_APP_ID", "1")];
            extra.extend(key.map(|k| ("FLEET_GITHUB_APP_KEY_FILE", k)));
            match with(&extra).unwrap_err() {
                ConfigError::Invalid { var, .. } => assert_eq!(var, "FLEET_GITHUB_APP_KEY_FILE"),
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn github_app_key_file_without_id_refuses_start() {
        for id in [None, Some("")] {
            let mut extra = vec![("FLEET_GITHUB_APP_KEY_FILE", "/k.pem")];
            extra.extend(id.map(|i| ("FLEET_GITHUB_APP_ID", i)));
            match with(&extra).unwrap_err() {
                ConfigError::Invalid { var, .. } => assert_eq!(var, "FLEET_GITHUB_APP_ID"),
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn github_app_id_must_be_a_u64_without_leading_zero() {
        for bad in [
            "0",
            "007",
            "12a",
            "-1",
            "+1",
            "1 ",
            " 1",
            "1\n",
            "1.5",
            "18446744073709551616",
            "123456789012345678901",
            "\u{661}",
        ] {
            let err = with(&[
                ("FLEET_GITHUB_APP_ID", bad),
                ("FLEET_GITHUB_APP_KEY_FILE", "/k.pem"),
                ("FLEET_GITHUB_APP_BOT_NAME", BOT_NAME),
                ("FLEET_GITHUB_APP_BOT_EMAIL", BOT_EMAIL),
            ])
            .unwrap_err();
            match err {
                ConfigError::Invalid { var, reason } => {
                    assert_eq!(var, "FLEET_GITHUB_APP_ID", "{bad:?}");
                    assert!(
                        !reason.contains("12a") && !reason.contains("0.5"),
                        "{reason}"
                    );
                }
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
        let max = with(&[
            ("FLEET_GITHUB_APP_ID", "18446744073709551615"),
            ("FLEET_GITHUB_APP_KEY_FILE", "/k.pem"),
            ("FLEET_MASTER_KEY_FILE", "/run/keys"),
            ("FLEET_GITHUB_APP_BOT_NAME", BOT_NAME),
            ("FLEET_GITHUB_APP_BOT_EMAIL", BOT_EMAIL),
            ("FLEET_GITHUB_APP_ACCOUNT", "acme"),
        ]);
        assert_eq!(max.unwrap().github_app.unwrap().app_id, u64::MAX);
    }

    #[test]
    fn github_app_key_load_refuses_a_missing_file() {
        let app = GithubAppConfig {
            app_id: 1,
            key_file: PathBuf::from("/nonexistent/fleet-app-key.pem"),
            bot: BotIdentity::new(BOT_NAME, BOT_EMAIL).unwrap(),
            policy: AppPolicy::parse("acme", None, None).unwrap(),
        };
        assert_eq!(app.load_key().unwrap_err(), AppKeyError::Read);
    }

    #[test]
    fn ci_retries_default_to_off_and_stop_at_the_maximum() {
        assert_eq!(with(&[]).unwrap().max_ci_retries, 0);
        assert_eq!(
            with(&[("FLEET_MAX_CI_RETRIES", "")])
                .unwrap()
                .max_ci_retries,
            0
        );
        for (text, value) in [("0", 0), ("1", 1), ("2", 2), ("3", 3), ("4", 4), ("5", 5)] {
            let config = with(&[("FLEET_MAX_CI_RETRIES", text)]).unwrap();
            assert_eq!(config.max_ci_retries, value);
        }
        assert_eq!(MAX_CI_RETRIES, 5);
        for bad in ["6", "-1", "x", "99999999999"] {
            match with(&[("FLEET_MAX_CI_RETRIES", bad)]).unwrap_err() {
                ConfigError::Invalid { var, .. } => assert_eq!(var, "FLEET_MAX_CI_RETRIES"),
                other @ ConfigError::Missing(_) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn retention_defaults_apply() {
        let config = with(&[]).unwrap();
        assert_eq!(config.retention, Policy::default());
        assert_eq!(config.retention_interval, Duration::from_secs(3600));
        let empty = with(&[("FLEET_EVENTS_RETENTION_DAYS", "")]).unwrap();
        assert_eq!(empty.retention.events_days(), 90);
    }

    #[test]
    fn retention_overrides_apply() {
        let config = with(&[
            ("FLEET_EVENTS_RETENTION_DAYS", "7"),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "30"),
            ("FLEET_RETENTION_INTERVAL_SECS", "60"),
        ])
        .unwrap();
        assert_eq!(config.retention.events_days(), 7);
        assert_eq!(config.retention.summaries_days(), 30);
        assert_eq!(config.retention_interval, Duration::from_secs(60));
    }

    #[test]
    fn retention_bounds_table() {
        let cases: [(&str, &str, bool); 16] = [
            ("FLEET_EVENTS_RETENTION_DAYS", "0", false),
            ("FLEET_EVENTS_RETENTION_DAYS", "1", true),
            ("FLEET_EVENTS_RETENTION_DAYS", "365", true),
            ("FLEET_EVENTS_RETENTION_DAYS", "3651", false),
            ("FLEET_EVENTS_RETENTION_DAYS", "abc", false),
            ("FLEET_EVENTS_RETENTION_DAYS", "-1", false),
            ("FLEET_EVENTS_RETENTION_DAYS", "99999999999", false),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "99999999999", false),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "0", false),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "3650", true),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "3651", false),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "90", true),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "89", false),
            ("FLEET_RETENTION_INTERVAL_SECS", "59", false),
            ("FLEET_RETENTION_INTERVAL_SECS", "60", true),
            ("FLEET_RETENTION_INTERVAL_SECS", "x", false),
        ];
        for (var, value, ok) in cases {
            let result = with(&[(var, value)]);
            if ok {
                assert!(result.is_ok(), "{var}={value}");
            } else {
                match result.unwrap_err() {
                    ConfigError::Invalid { var: named, .. } => assert_eq!(named, var, "{value}"),
                    other @ ConfigError::Missing(_) => panic!("{other}"),
                }
            }
        }
    }

    #[test]
    fn summaries_below_events_name_the_summaries_key() {
        let err = with(&[
            ("FLEET_EVENTS_RETENTION_DAYS", "100"),
            ("FLEET_SUMMARIES_RETENTION_DAYS", "99"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("FLEET_SUMMARIES_RETENTION_DAYS"));
        assert!(
            err.to_string()
                .contains("at least the events retention days")
        );
        assert!(
            with(&[
                ("FLEET_EVENTS_RETENTION_DAYS", "100"),
                ("FLEET_SUMMARIES_RETENTION_DAYS", "100"),
            ])
            .is_ok()
        );
        assert!(
            with(&[
                ("FLEET_EVENTS_RETENTION_DAYS", "3650"),
                ("FLEET_SUMMARIES_RETENTION_DAYS", "3650"),
            ])
            .is_ok()
        );
    }

    #[test]
    fn debug_hides_secrets() {
        let config = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://u:hunter2@h/db"),
            ("FLEET_TOKEN", "s3cret-token-0123456789abcdefghij"),
        ]))
        .unwrap();
        let shown = format!("{config:?} {:?}", config.token);
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("s3cret-token"));
    }

    const GH_ENTRY: &str = "host=github.com,forge=github,api=https://api.github.com";
    const FJ_ENTRY: &str = "host=git.example.com,forge=forgejo,api=https://git.example.com";

    fn hosts(raw: &str) -> Result<RepoHosts, RepoHostsError> {
        RepoHosts::parse(raw)
    }

    fn with_hosts(raw: &str) -> Result<Config, ConfigError> {
        let mut vars: Vec<(&str, &str)> = base();
        vars.push(("FLEET_REPO_HOSTS", raw));
        Config::from_lookup(lookup(&vars))
    }

    fn entry(host: &str, forge: &str, api: &str) -> String {
        format!("host={host},forge={forge},api={api}")
    }

    #[test]
    fn repo_hosts_default_is_github_when_unset() {
        let config = with(&[]).unwrap();
        assert_eq!(config.repo_hosts.len(), 1);
        let github = config.repo_hosts.lookup("github.com").unwrap();
        assert_eq!(github.forge, Forge::Github);
        assert_eq!(github.api_base, "https://api.github.com");
        assert!(!github.allow_private);
        assert_eq!(config.repo_hosts, RepoHosts::default());
    }

    #[test]
    fn repo_hosts_is_non_default_only_when_the_variable_changes_the_list() {
        assert!(!with(&[]).unwrap().repo_hosts.is_non_default());
        assert!(
            with(&[("FLEET_REPO_HOSTS", "")])
                .unwrap()
                .repo_hosts
                .is_non_default()
        );
        let raw = "host=git.example.org,forge=forgejo,api=https://git.example.org/api/v1";
        assert!(
            with(&[("FLEET_REPO_HOSTS", raw)])
                .unwrap()
                .repo_hosts
                .is_non_default()
        );
    }

    #[test]
    fn repo_hosts_empty_string_means_no_hosts() {
        let config = with(&[("FLEET_REPO_HOSTS", "")]).unwrap();
        assert!(config.repo_hosts.is_empty());
        assert_eq!(config.repo_hosts.lookup("github.com"), None);
        assert_eq!(config.repo_hosts, RepoHosts::none());
    }

    #[test]
    fn repo_hosts_parse_two_entries() {
        let raw = format!("{GH_ENTRY};{FJ_ENTRY},allow_private=true");
        let config = with_hosts(&raw).unwrap();
        let hosts = config.repo_hosts;
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts.iter().count(), 2);
        let github = hosts.lookup("github.com").unwrap();
        assert!(!github.allow_private);
        let forgejo = hosts.lookup("git.example.com").unwrap();
        assert_eq!(forgejo.forge, Forge::Forgejo);
        assert_eq!(forgejo.api_base, "https://git.example.com");
        assert!(forgejo.allow_private);
        assert_eq!(hosts.lookup("GIT.example.com"), None);
        assert_eq!(hosts.lookup("other.example.com"), None);
    }

    #[test]
    fn repo_hosts_allow_private_false_is_accepted() {
        let raw = format!("{FJ_ENTRY},allow_private=false");
        assert!(
            !hosts(&raw)
                .unwrap()
                .lookup("git.example.com")
                .unwrap()
                .allow_private
        );
    }

    #[test]
    fn repo_hosts_api_path_is_normalised() {
        for (api, want) in [
            ("https://git.example.com/", "https://git.example.com"),
            (
                "https://git.example.com/api/v1",
                "https://git.example.com/api/v1",
            ),
            (
                "https://git.example.com/api/v1/",
                "https://git.example.com/api/v1",
            ),
        ] {
            let parsed = hosts(&entry("git.example.com", "forgejo", api)).unwrap();
            assert_eq!(
                parsed.lookup("git.example.com").unwrap().api_base,
                want,
                "{api}"
            );
        }
    }

    #[test]
    fn repo_hosts_api_path_limits_accept_the_edge() {
        let segment = "a".repeat(MAX_PATH_SEGMENT_LEN);
        let deep = ["b"; MAX_PATH_SEGMENTS].join("/");
        for path in [segment, deep, "a.b_c~d-e".to_owned()] {
            let api = format!("https://git.example.com/{path}");
            assert!(
                hosts(&entry("git.example.com", "forgejo", &api)).is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn repo_hosts_github_api_host_exception_is_narrow() {
        assert!(hosts(GH_ENTRY).is_ok());
        let cases = [
            entry("github.com", "forgejo", "https://api.github.com"),
            entry("example.com", "github", "https://api.github.com"),
            entry("ghe.example.com", "github", "https://api.github.com"),
            entry("github.com", "github", "https://api.github.com.evil.com"),
            entry("github.com", "github", "https://evil.com"),
            entry("git.example.com", "forgejo", "https://api.git.example.com"),
            entry("git.example.com", "forgejo", "https://Git.example.com"),
        ];
        for raw in cases {
            assert_eq!(hosts(&raw), Err(RepoHostsError::ApiHostMismatch), "{raw}");
        }
    }

    #[test]
    fn repo_hosts_hostile_host_is_refused() {
        let over_long = format!("{}com", "a.".repeat((MAX_HOST_LEN - 3) / 2 + 1));
        let long_label = format!("{}.com", "a".repeat(MAX_LABEL_LEN + 1));
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("uppercase", "Git.example.com".into()),
            ("cr", "git.example.com\r".into()),
            ("crlf", "git.example.com\r\n".into()),
            ("lf", "git.example.com\n".into()),
            ("nel", "git.example.com\u{85}".into()),
            ("line separator", "git.example.com\u{2028}".into()),
            ("userinfo", "user@git.example.com".into()),
            ("userinfo password", "user:pw@git.example.com".into()),
            ("port", "git.example.com:8443".into()),
            ("backslash", "git.example.com\\evil.com".into()),
            ("ipv6", "[::1]".into()),
            ("ipv6 bare", "::1".into()),
            ("ipv4", "10.0.0.1".into()),
            ("empty label", "git..example.com".into()),
            ("leading dot", ".example.com".into()),
            ("trailing dot", "git.example.com.".into()),
            ("leading hyphen", "-git.example.com".into()),
            ("trailing hyphen", "git-.example.com".into()),
            ("underscore", "git_x.example.com".into()),
            ("slash", "git.example.com/x".into()),
            ("space", "git.example.com ".into()),
            ("inner space", "git .example.com".into()),
            ("tab", "git.example.com\t".into()),
            ("non-ascii", "g\u{131}t.example.com".into()),
            ("fullwidth dot", "git\u{ff0e}example.com".into()),
            ("over-long", over_long),
            ("over-long label", long_label),
            ("hex ipv4", "0x7f000001".into()),
            ("dotted hex ipv4", "127.0.0.0x1".into()),
            ("hex last label", "a.0x".into()),
            ("bare hex", "0x".into()),
            ("dotted hex all", "0xa.0x0.0x0.0x1".into()),
            ("digit-led last label", "a.1com".into()),
            ("hyphen-led last label", "a.-com".into()),
        ];
        for (name, host) in cases {
            let raw = entry(&host, "forgejo", "https://git.example.com");
            assert_eq!(hosts(&raw), Err(RepoHostsError::InvalidHost), "{name}");
        }
        assert!(hosts(&entry("localhost", "forgejo", "https://localhost")).is_ok());
        for ok in [
            "example.com",
            "git.example.com",
            "a.xn--p1ai",
            "1.example.com",
        ] {
            let api = format!("https://{ok}");
            assert!(hosts(&entry(ok, "forgejo", &api)).is_ok(), "{ok}");
        }
        let max_label = format!("{}.com", "a".repeat(MAX_LABEL_LEN));
        let api = format!("https://{max_label}");
        assert!(hosts(&entry(&max_label, "forgejo", &api)).is_ok());
        let max_host = format!("{}com", "a.".repeat((MAX_HOST_LEN - 3) / 2));
        assert_eq!(max_host.len(), MAX_HOST_LEN);
        let api = format!("https://{max_host}");
        assert!(hosts(&entry(&max_host, "forgejo", &api)).is_ok());
        let one_over = format!("a{max_host}");
        assert_eq!(one_over.len(), MAX_HOST_LEN + 1);
        let api = format!("https://{one_over}");
        assert_eq!(
            hosts(&entry(&one_over, "forgejo", &api)),
            Err(RepoHostsError::InvalidHost)
        );
        let hyphen = "git-x.example.com";
        assert!(hosts(&entry(hyphen, "forgejo", &format!("https://{hyphen}"))).is_ok());
    }

    fn assert_api_cases(cases: Vec<(&str, String, RepoHostsError)>) {
        for (name, api, want) in cases {
            let raw = entry("git.example.com", "forgejo", &api);
            assert_eq!(hosts(&raw), Err(want), "{name}");
        }
    }

    #[test]
    fn repo_hosts_hostile_api_authority_is_refused() {
        let cases: Vec<(&str, String, RepoHostsError)> = vec![
            (
                "http",
                "http://git.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "scheme case",
                "HTTPS://git.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "no scheme",
                "git.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "ftp",
                "ftp://git.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            ("empty", String::new(), RepoHostsError::InvalidApi),
            ("empty host", "https://".into(), RepoHostsError::InvalidApi),
            (
                "empty host path",
                "https:///x".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "userinfo",
                "https://u@git.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "userinfo pw",
                "https://u:p@git.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "port",
                "https://git.example.com:8443".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "port path",
                "https://git.example.com:443/x".into(),
                RepoHostsError::InvalidApi,
            ),
            ("ipv6", "https://[::1]".into(), RepoHostsError::InvalidApi),
            (
                "hex ipv4 authority",
                "https://0x7f000001".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "dotted hex authority",
                "https://127.0.0.0x1".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "hex last label authority",
                "https://a.0x".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "bare hex authority",
                "https://0x".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "dotted hex all authority",
                "https://0xa.0x0.0x0.0x1".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "uppercase last label authority",
                "https://git.example.COM".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "ipv4 authority",
                "https://10.0.0.1".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "query",
                "https://git.example.com?x=1".into(),
                RepoHostsError::InvalidApi,
            ),
        ];
        assert_api_cases(cases);
        let ok = ["https://git.example.com", "https://a.xn--p1ai"];
        for api in ok {
            let host = api.trim_start_matches("https://");
            assert!(hosts(&entry(host, "forgejo", api)).is_ok(), "{api}");
        }
    }

    #[test]
    fn repo_hosts_hostile_api_path_is_refused() {
        let over_long = format!(
            "https://git.example.com/{}",
            "a".repeat(MAX_PATH_SEGMENT_LEN + 1)
        );
        let deep = format!(
            "https://git.example.com/{}",
            "a/".repeat(MAX_PATH_SEGMENTS + 1)
        );
        let cases: Vec<(&str, String, RepoHostsError)> = vec![
            (
                "query path",
                "https://git.example.com/api?x=1".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "fragment",
                "https://git.example.com#x".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "fragment path",
                "https://git.example.com/api#x".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "backslash",
                "https://git.example.com\\x".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "backslash path",
                "https://git.example.com/a\\b".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "dot segment",
                "https://git.example.com/./x".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "dotdot segment",
                "https://git.example.com/../x".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "empty segment",
                "https://git.example.com/a//b".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "over-long segment",
                over_long,
                RepoHostsError::InvalidApiPath,
            ),
            ("too deep", deep, RepoHostsError::InvalidApiPath),
        ];
        assert_api_cases(cases);
    }

    #[test]
    fn repo_hosts_hostile_api_bytes_are_refused() {
        let cases: Vec<(&str, String, RepoHostsError)> = vec![
            (
                "cr",
                "https://git.example.com\r".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "crlf path",
                "https://git.example.com/a\r\n".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "nel",
                "https://git.example.com/a\u{85}".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "line separator",
                "https://git.example.com/a\u{2028}".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "space",
                "https://git.example.com/a b".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "trailing space",
                "https://git.example.com ".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "non-ascii host",
                "https://g\u{131}t.example.com".into(),
                RepoHostsError::InvalidApi,
            ),
            (
                "non-ascii path",
                "https://git.example.com/\u{e9}".into(),
                RepoHostsError::InvalidApiPath,
            ),
            (
                "percent",
                "https://git.example.com/%2e%2e".into(),
                RepoHostsError::InvalidApiPath,
            ),
        ];
        assert_api_cases(cases);
    }

    #[test]
    fn repo_hosts_hostile_forge_is_refused() {
        for forge in [
            "",
            "GitHub",
            "gitea",
            "github ",
            "github\r\n",
            "github\u{2028}",
            "g\u{131}thub",
            "github\\",
        ] {
            let raw = entry("git.example.com", forge, "https://git.example.com");
            assert_eq!(hosts(&raw), Err(RepoHostsError::InvalidForge), "{forge:?}");
        }
    }

    #[test]
    fn repo_hosts_hostile_allow_private_is_refused() {
        for value in [
            "",
            "True",
            "TRUE",
            "1",
            "yes",
            "false ",
            "true\r\n",
            "true\u{85}",
            "tru\u{131}e",
        ] {
            let raw = format!("{FJ_ENTRY},allow_private={value}");
            assert_eq!(
                hosts(&raw),
                Err(RepoHostsError::InvalidAllowPrivate),
                "{value:?}"
            );
        }
    }

    #[test]
    fn repo_hosts_each_required_field_is_needed() {
        let cases = [
            (
                "forge=forgejo,api=https://git.example.com",
                RepoHostsError::MissingHost,
            ),
            (
                "host=git.example.com,api=https://git.example.com",
                RepoHostsError::MissingForge,
            ),
            (
                "host=git.example.com,forge=forgejo",
                RepoHostsError::MissingApi,
            ),
            ("allow_private=true", RepoHostsError::MissingHost),
        ];
        for (raw, want) in cases {
            assert_eq!(hosts(raw), Err(want), "{raw}");
        }
    }

    #[test]
    fn repo_hosts_grammar_errors() {
        let cases = [
            (format!("{FJ_ENTRY};"), RepoHostsError::Malformed),
            (format!(";{FJ_ENTRY}"), RepoHostsError::Malformed),
            (format!("{FJ_ENTRY};;{GH_ENTRY}"), RepoHostsError::Malformed),
            (";".to_owned(), RepoHostsError::Malformed),
            (format!("{FJ_ENTRY},"), RepoHostsError::Malformed),
            ("host".to_owned(), RepoHostsError::Malformed),
            (format!("{FJ_ENTRY},extra"), RepoHostsError::Malformed),
            (" ".to_owned(), RepoHostsError::Malformed),
            (
                format!("{FJ_ENTRY},color=red"),
                RepoHostsError::UnknownField,
            ),
            (format!("{FJ_ENTRY},Host=x"), RepoHostsError::UnknownField),
            (
                format!("{FJ_ENTRY},host=other.example.com"),
                RepoHostsError::DuplicateField,
            ),
            (
                format!("{FJ_ENTRY},forge=github"),
                RepoHostsError::DuplicateField,
            ),
            (
                format!("{FJ_ENTRY},api=https://git.example.com"),
                RepoHostsError::DuplicateField,
            ),
            (
                format!("{FJ_ENTRY},allow_private=true,allow_private=true"),
                RepoHostsError::DuplicateField,
            ),
        ];
        for (raw, want) in cases {
            assert_eq!(hosts(&raw), Err(want), "{raw}");
        }
    }

    #[test]
    fn repo_hosts_duplicate_hosts_are_refused() {
        let same = format!("{GH_ENTRY};{GH_ENTRY}");
        assert_eq!(hosts(&same), Err(RepoHostsError::DuplicateHost));
        let other_forge = format!(
            "{FJ_ENTRY};{}",
            entry("git.example.com", "github", "https://git.example.com")
        );
        assert_eq!(hosts(&other_forge), Err(RepoHostsError::DuplicateHost));
        let apart = format!("{GH_ENTRY};{FJ_ENTRY};{GH_ENTRY}");
        assert_eq!(hosts(&apart), Err(RepoHostsError::DuplicateHost));
    }

    #[test]
    fn repo_hosts_caps_apply() {
        let at_cap: Vec<String> = (0..MAX_REPO_HOSTS)
            .map(|n| {
                entry(
                    &format!("h{n}.example.com"),
                    "forgejo",
                    &format!("https://h{n}.example.com"),
                )
            })
            .collect();
        assert_eq!(hosts(&at_cap.join(";")).unwrap().len(), MAX_REPO_HOSTS);
        let over: Vec<String> = (0..=MAX_REPO_HOSTS)
            .map(|n| {
                entry(
                    &format!("h{n}.example.com"),
                    "forgejo",
                    &format!("https://h{n}.example.com"),
                )
            })
            .collect();
        assert_eq!(hosts(&over.join(";")), Err(RepoHostsError::TooManyEntries));
        let many_empty = ";".repeat(MAX_REPO_HOSTS + 1);
        assert_eq!(hosts(&many_empty), Err(RepoHostsError::TooManyEntries));
        let long = "x".repeat(MAX_REPO_HOSTS_VALUE_LEN + 1);
        assert_eq!(hosts(&long), Err(RepoHostsError::TooLong));
        let padded = "x".repeat(MAX_REPO_HOSTS_VALUE_LEN);
        assert_eq!(hosts(&padded), Err(RepoHostsError::Malformed));
    }

    #[test]
    fn a_bad_repo_hosts_value_refuses_start_without_echoing_it() {
        let secret = "sentinel-host-9f3a";
        let cases = [
            format!("host={secret}\r\n,forge=forgejo,api=https://{secret}"),
            format!("host={secret}.example.com,forge=nope,api=https://{secret}.example.com"),
            format!("host=u@{secret}.example.com,forge=forgejo,api=https://{secret}.example.com"),
            secret.to_owned(),
            format!("host={secret}.com,forge=forgejo,api=https://other.com/{secret}"),
        ];
        for raw in cases {
            match with_hosts(&raw).unwrap_err() {
                ConfigError::Invalid { var, reason } => {
                    assert_eq!(var, "FLEET_REPO_HOSTS");
                    assert!(!reason.contains(secret), "{reason}");
                    assert_ne!(reason, "");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}
