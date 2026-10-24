//! Server configuration, read from environment variables only.

use std::fmt;
use std::net::SocketAddr;

const DEFAULT_LISTEN: &str = "0.0.0.0:7070";
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

/// The shared bearer token boxes and the CLI present. Its `Debug` output hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Wraps a token.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Missing`] for an empty token.
    pub fn new(raw: String) -> Result<Self, ConfigError> {
        if raw.is_empty() {
            return Err(ConfigError::Missing("FLEET_TOKEN"));
        }
        Ok(Self(raw))
    }

    /// The token text.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Server settings.
#[derive(Clone)]
pub struct Config {
    /// Address of the gRPC listener.
    pub listen: SocketAddr,
    /// Address of the health listener.
    pub health_listen: SocketAddr,
    /// Postgres connection URL.
    pub database_url: String,
    /// Bearer token the gRPC services require.
    pub token: Token,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("health_listen", &self.health_listen)
            .field("database_url", &"<redacted>")
            .field("token", &self.token)
            .finish()
    }
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

impl Config {
    /// Reads the settings from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when `FLEET_DATABASE_URL` or `FLEET_TOKEN` is missing or
    /// empty, or an address does not parse.
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
        Ok(Self {
            listen: address(&lookup, "FLEET_LISTEN", DEFAULT_LISTEN)?,
            health_listen: address(&lookup, "FLEET_HEALTH_LISTEN", DEFAULT_HEALTH_LISTEN)?,
            database_url,
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

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
            ("FLEET_TOKEN", "t"),
        ]))
        .unwrap();
        assert_eq!(config.listen.to_string(), "0.0.0.0:7070");
        assert_eq!(config.health_listen.to_string(), "0.0.0.0:7072");
        assert_eq!(config.token.expose(), "t");
    }

    #[test]
    fn overrides_apply() {
        let config = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://h/db"),
            ("FLEET_TOKEN", "t"),
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
    fn missing_database_url_refuses_start() {
        assert_eq!(
            Config::from_lookup(lookup(&[("FLEET_TOKEN", "t")])).unwrap_err(),
            ConfigError::Missing("FLEET_DATABASE_URL")
        );
    }

    #[test]
    fn bad_address_is_reported() {
        let err = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://h/db"),
            ("FLEET_TOKEN", "t"),
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
    fn debug_hides_secrets() {
        let config = Config::from_lookup(lookup(&[
            ("FLEET_DATABASE_URL", "postgres://u:hunter2@h/db"),
            ("FLEET_TOKEN", "s3cret-token"),
        ]))
        .unwrap();
        let shown = format!("{config:?} {:?}", config.token);
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("s3cret-token"));
    }
}
