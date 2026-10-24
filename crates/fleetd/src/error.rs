use std::fmt;
use std::path::PathBuf;

/// Errors from fleetd.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A config value or environment override could not be used.
    InvalidValue {
        /// Name of the setting or variable.
        name: &'static str,
        /// The rejected value.
        value: String,
    },
    /// The config file is not valid TOML for fleetd.
    ConfigFile(toml::de::Error),
    /// A file or socket operation failed.
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// A listener or signal handler failed.
    Runtime(std::io::Error),
    /// The SQLite queue failed.
    Db(sqlx::Error),
    /// Applying the schema migrations failed.
    Migrate(sqlx::migrate::MigrateError),
    /// A stored or incoming JSON document could not be handled.
    Json(serde_json::Error),
    /// A write was attempted on a queue opened for inspection.
    ReadOnly,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue { name, value } => write!(f, "invalid {name} value: {value:?}"),
            Self::ConfigFile(err) => write!(f, "invalid config file: {err}"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Runtime(err) => write!(f, "runtime error: {err}"),
            Self::Db(err) => write!(f, "queue database error: {err}"),
            Self::Migrate(err) => write!(f, "queue migration error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::ReadOnly => write!(f, "queue was opened read-only"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigFile(err) => Some(err),
            Self::Io { source, .. } | Self::Runtime(source) => Some(source),
            Self::Db(err) => Some(err),
            Self::Migrate(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::InvalidValue { .. } | Self::ReadOnly => None,
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::Db(err)
    }
}

impl From<sqlx::migrate::MigrateError> for Error {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Migrate(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}
