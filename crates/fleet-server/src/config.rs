//! Server configuration, read from environment variables only.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_proto::{DEFAULT_CI_RETRIES, MAX_CI_RETRIES};

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
    /// Public origin of the web UI, from `FLEET_WEB_ORIGIN` (for example
    /// `https://fleet.example.com`). `None` when unset or empty, which turns web login off.
    pub web_origin: Option<String>,
    /// `WebAuthn` relying party id, from `FLEET_WEB_RP_ID`. `None` means the host of the origin.
    pub web_rp_id: Option<String>,
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
    /// `FLEET_MAX_CI_RETRIES` runs from 0 to 5 and defaults to 0.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the settings through `lookup`, which maps a variable name to its value.
    ///
    /// # Errors
    ///
    /// Same as [`Config::from_env`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
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
            master_key_file: lookup("FLEET_MASTER_KEY_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            web_origin: lookup("FLEET_WEB_ORIGIN").filter(|v| !v.is_empty()),
            web_rp_id: lookup("FLEET_WEB_RP_ID").filter(|v| !v.is_empty()),
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
