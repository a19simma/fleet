//! Server configuration, read from environment variables only.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_core::model_allowlist::ModelAllowlist;
use fleet_proto::{DEFAULT_CI_RETRIES, MAX_CI_RETRIES};

use crate::cred::app_jwt::{AppKey, AppKeyError};
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
    /// Client bearer token: `FleetQuery` and `FleetJobs`. `None` when
    /// `FLEET_CLIENT_TOKEN` is unset or empty; that closes `FleetQuery` and `FleetJobs`.
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
    /// The GitHub App, from `FLEET_GITHUB_APP_ID` and `FLEET_GITHUB_APP_KEY_FILE`. Both are set
    /// or both are unset: one without the other refuses start. `None` when both are unset or
    /// empty.
    pub github_app: Option<GithubAppConfig>,
}

/// The GitHub App id and the path of its private key (ADR-0058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubAppConfig {
    /// The App id: 1 to 20 ASCII digits with no leading zero, in the range of `u64`.
    pub app_id: u64,
    /// Path of the PEM private key. [`AppKey::load`] checks the file at startup.
    pub key_file: PathBuf,
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
    /// Returns [`AppKeyError`] when the file is unreadable, loosely permissioned, not a regular
    /// file or not a usable RSA key.
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

const GITHUB_APP_ID_VAR: &str = "FLEET_GITHUB_APP_ID";
const GITHUB_APP_KEY_FILE_VAR: &str = "FLEET_GITHUB_APP_KEY_FILE";

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
    Ok(Some(GithubAppConfig {
        app_id,
        key_file: PathBuf::from(key_file),
    }))
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
    /// Returns [`ConfigError`] when `FLEET_DATABASE_URL` or `FLEET_TOKEN` is missing or
    /// empty, `FLEET_CLIENT_TOKEN` is set but invalid or equal to `FLEET_TOKEN`, an
    /// address does not parse, or a retention setting is out of range. Retention days run
    /// from 1 to 3650, `FLEET_SUMMARIES_RETENTION_DAYS` must not be below
    /// `FLEET_EVENTS_RETENTION_DAYS`, and `FLEET_RETENTION_INTERVAL_SECS` is at least 60.
    /// `FLEET_MAX_CI_RETRIES` runs from 0 to 5 and defaults to 0. `FLEET_GITHUB_APP_ID` without
    /// `FLEET_GITHUB_APP_KEY_FILE`, or the reverse, is an error, and so is an App id that is
    /// not 1 to 20 ASCII digits without a leading zero that fits a `u64`.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the settings through `lookup`, which maps a variable name to its value.
    ///
    /// # Errors
    ///
    /// Same as [`Config::from_env`]: the GitHub App variables are both set or both unset, and
    /// the App id is 1 to 20 ASCII digits without a leading zero that fit a `u64`.
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
        Ok(Self {
            listen: address(&lookup, "FLEET_LISTEN", DEFAULT_LISTEN)?,
            health_listen: address(&lookup, "FLEET_HEALTH_LISTEN", DEFAULT_HEALTH_LISTEN)?,
            database_url: Secret::new(database_url),
            token,
            client_token,
            retention: retention(&lookup)?,
            max_ci_retries: ci_retries(&lookup)?,
            model_allowlist: model_allowlist(&lookup)?,
            github_app: github_app(&lookup)?,
            master_key_file: lookup("FLEET_MASTER_KEY_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            update_manifest: lookup("FLEET_UPDATE_MANIFEST")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
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
        ])
        .unwrap()
        .github_app
        .unwrap();
        assert_eq!(app.app_id, 123_456);
        assert_eq!(app.app_id_text(), "123456");
        assert_eq!(app.key_file, PathBuf::from("keys/app.pem"));
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
        ]);
        assert_eq!(max.unwrap().github_app.unwrap().app_id, u64::MAX);
    }

    #[test]
    fn github_app_key_load_refuses_a_missing_file() {
        let app = GithubAppConfig {
            app_id: 1,
            key_file: PathBuf::from("/nonexistent/fleet-app-key.pem"),
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
}
