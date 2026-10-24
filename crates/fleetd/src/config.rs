use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::Error;

/// Config file read when `--config` is not given and the file exists.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/fleetd/config.toml";
/// Default secrets env file. A missing file at this path is not an error.
pub const DEFAULT_SECRETS_PATH: &str = "/etc/swarm/secrets.env";
const DEFAULT_PORT: u16 = 7071;
const DEFAULT_QUEUE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_QUEUE_MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;
const DEFAULT_DEDUPE_SECS: u64 = 10;
const DEFAULT_CLAUDE_BIN: &str = "claude";
const DEFAULT_GH_BIN: &str = "gh";
const DEFAULT_HOOK_EVENTS: [&str; 5] = [
    "SessionStart",
    "UserPromptSubmit",
    "Stop",
    "Notification",
    "SessionEnd",
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    http_port: Option<u16>,
    socket_path: Option<PathBuf>,
    db_path: Option<PathBuf>,
    queue_max_bytes: Option<u64>,
    queue_max_age_secs: Option<u64>,
    hook_events: Option<Vec<String>>,
    secrets_file: Option<PathBuf>,
    box_name: Option<String>,
    dedupe_window_secs: Option<u64>,
    claude_bin: Option<PathBuf>,
    gh_bin: Option<PathBuf>,
    disposable: Option<bool>,
    jobs_dir: Option<PathBuf>,
}

/// Where redaction secrets are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsFile {
    /// Env file path.
    pub path: PathBuf,
    /// True when the operator named the path, so a missing file is a startup error.
    pub required: bool,
}

/// Resolved fleetd settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Loopback TCP port for hooks.
    pub http_port: u16,
    /// Unix socket path for local tools.
    pub socket_path: PathBuf,
    /// SQLite queue file.
    pub db_path: PathBuf,
    /// Cap on queued payload bytes.
    pub queue_max_bytes: u64,
    /// Cap on the age of a queued event.
    pub queue_max_age: Duration,
    /// Hook event names to record.
    pub hook_events: Vec<String>,
    /// Redaction secrets source.
    pub secrets_file: SecretsFile,
    /// Box name override. Defaults to the hostname when absent.
    pub box_name: Option<String>,
    /// Window in which an identical hook body is dropped as a repeat.
    pub dedupe_window: Duration,
    /// Agent binary that runs jobs.
    pub claude_bin: PathBuf,
    /// GitHub CLI binary that opens pull requests, `gh` by default.
    pub gh_bin: PathBuf,
    /// True when the box is disposable, which lets jobs run with permission checks off.
    pub disposable: bool,
    /// Directory for job worktrees and git mirrors. Defaults to `jobs` under
    /// `STATE_DIRECTORY`, else `jobs` in the working directory.
    pub jobs_dir: PathBuf,
}

impl Config {
    /// Loads config from `explicit` or, when absent, from [`DEFAULT_CONFIG_PATH`] if that
    /// file exists, then applies the process environment. Only the selected file is read.
    ///
    /// # Errors
    ///
    /// Fails when the selected file is unreadable, the TOML is invalid, or a value is rejected.
    pub fn load(explicit: Option<&Path>) -> Result<Self, Error> {
        let fallback = Path::new(DEFAULT_CONFIG_PATH);
        let path = explicit.or_else(|| fallback.exists().then_some(fallback));
        let text = path.map(read).transpose()?;
        Self::resolve(text.as_deref(), &|name| std::env::var(name).ok())
    }

    /// Resolves config from optional TOML text and an environment lookup.
    ///
    /// Precedence is environment, then file, then default. The overrides are
    /// `FLEETD_PORT`, `FLEET_BOX_NAME`, `FLEETD_DB`, `FLEETD_SOCKET` and
    /// `FLEETD_SECRETS_FILE`. Without an override the db lives under `STATE_DIRECTORY`
    /// and the socket under `RUNTIME_DIRECTORY`, else the working directory.
    ///
    /// # Errors
    ///
    /// Fails on invalid TOML, an unparsable `FLEETD_PORT`, or a zero
    /// `queue_max_bytes` or `queue_max_age_secs`. An empty environment value counts as unset.
    pub fn resolve(
        file: Option<&str>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, Error> {
        let env = |name: &str| env(name).filter(|value| !value.is_empty());
        let file: FileConfig = match file {
            Some(text) => toml::from_str(text).map_err(Error::ConfigFile)?,
            None => FileConfig::default(),
        };
        let http_port = match env("FLEETD_PORT") {
            Some(raw) => raw.parse().map_err(|_| Error::InvalidValue {
                name: "FLEETD_PORT",
                value: raw,
            })?,
            None => file.http_port.unwrap_or(DEFAULT_PORT),
        };
        let db_path = env("FLEETD_DB")
            .map(PathBuf::from)
            .or(file.db_path)
            .unwrap_or_else(|| {
                env("STATE_DIRECTORY")
                    .as_deref()
                    .and_then(first_dir)
                    .map_or_else(|| PathBuf::from("fleetd.db"), |dir| dir.join("queue.db"))
            });
        let socket_path = env("FLEETD_SOCKET")
            .map(PathBuf::from)
            .or(file.socket_path)
            .unwrap_or_else(|| {
                env("RUNTIME_DIRECTORY")
                    .as_deref()
                    .and_then(first_dir)
                    .map_or_else(
                        || PathBuf::from("fleetd.sock"),
                        |dir| dir.join("fleetd.sock"),
                    )
            });
        let named = env("FLEETD_SECRETS_FILE")
            .map(PathBuf::from)
            .or(file.secrets_file);
        let secrets_file = SecretsFile {
            required: named.is_some(),
            path: named.unwrap_or_else(|| PathBuf::from(DEFAULT_SECRETS_PATH)),
        };
        let queue_max_bytes = file.queue_max_bytes.unwrap_or(DEFAULT_QUEUE_MAX_BYTES);
        if queue_max_bytes == 0 {
            return Err(Error::InvalidValue {
                name: "queue_max_bytes",
                value: "0".to_owned(),
            });
        }
        let queue_max_age_secs = file
            .queue_max_age_secs
            .unwrap_or(DEFAULT_QUEUE_MAX_AGE_SECS);
        if queue_max_age_secs == 0 {
            return Err(Error::InvalidValue {
                name: "queue_max_age_secs",
                value: "0".to_owned(),
            });
        }
        Ok(Self {
            http_port,
            socket_path,
            db_path,
            queue_max_bytes,
            queue_max_age: Duration::from_secs(queue_max_age_secs),
            hook_events: file.hook_events.unwrap_or_else(|| {
                DEFAULT_HOOK_EVENTS
                    .iter()
                    .map(|e| (*e).to_owned())
                    .collect()
            }),
            secrets_file,
            box_name: env("FLEET_BOX_NAME")
                .or(file.box_name)
                .filter(|n| !n.is_empty()),
            dedupe_window: Duration::from_secs(
                file.dedupe_window_secs.unwrap_or(DEFAULT_DEDUPE_SECS),
            ),
            claude_bin: file
                .claude_bin
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CLAUDE_BIN)),
            gh_bin: file.gh_bin.unwrap_or_else(|| PathBuf::from(DEFAULT_GH_BIN)),
            disposable: file.disposable.unwrap_or(false),
            jobs_dir: env("FLEETD_JOBS_DIR")
                .map(PathBuf::from)
                .or(file.jobs_dir)
                .unwrap_or_else(|| {
                    env("STATE_DIRECTORY")
                        .as_deref()
                        .and_then(first_dir)
                        .map_or_else(|| PathBuf::from("jobs"), |dir| dir.join("jobs"))
                }),
        })
    }
}

fn first_dir(raw: &str) -> Option<PathBuf> {
    raw.split(':')
        .find(|part| !part.is_empty())
        .map(PathBuf::from)
}

fn read(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn defaults_are_loopback_friendly_and_name_no_host() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.http_port, 7071);
        assert_eq!(cfg.db_path, PathBuf::from("fleetd.db"));
        assert_eq!(cfg.socket_path, PathBuf::from("fleetd.sock"));
        assert_eq!(cfg.box_name, None);
        assert_eq!(cfg.queue_max_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.queue_max_age, Duration::from_secs(14 * 86_400));
        assert_eq!(cfg.hook_events.len(), 5);
        assert!(!cfg.secrets_file.required);
    }

    #[test]
    fn job_settings_default_to_a_cautious_agent() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.claude_bin, PathBuf::from("claude"));
        assert_eq!(cfg.gh_bin, PathBuf::from("gh"));
        assert!(!cfg.disposable);
        let file = "claude_bin = \"/opt/claude\"\ngh_bin = \"/opt/gh\"\ndisposable = true\n";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(cfg.claude_bin, PathBuf::from("/opt/claude"));
        assert_eq!(cfg.gh_bin, PathBuf::from("/opt/gh"));
        assert!(cfg.disposable);
        assert_eq!(cfg.jobs_dir, PathBuf::from("jobs"));
        let state = |name: &str| (name == "STATE_DIRECTORY").then(|| "/var/lib/fleetd".to_owned());
        let cfg = Config::resolve(None, &state).unwrap();
        assert_eq!(cfg.jobs_dir, PathBuf::from("/var/lib/fleetd/jobs"));
        let cfg = Config::resolve(Some("jobs_dir = \"/srv/j\"\n"), &state).unwrap();
        assert_eq!(cfg.jobs_dir, PathBuf::from("/srv/j"));
    }

    #[test]
    fn state_and_runtime_directories_set_defaults() {
        let env = env_of(&[
            ("STATE_DIRECTORY", "/var/lib/fleetd:/other"),
            ("RUNTIME_DIRECTORY", "/run/fleetd"),
        ]);
        let cfg = Config::resolve(None, &env).unwrap();
        assert_eq!(cfg.db_path, PathBuf::from("/var/lib/fleetd/queue.db"));
        assert_eq!(cfg.socket_path, PathBuf::from("/run/fleetd/fleetd.sock"));
    }

    #[test]
    fn env_overrides_file() {
        let file = "http_port = 9000\ndb_path = \"/f/q.db\"\nbox_name = \"from-file\"\nqueue_max_bytes = 10\nqueue_max_age_secs = 60\nhook_events = [\"Stop\"]\n";
        let env = env_of(&[
            ("FLEETD_PORT", "9100"),
            ("FLEETD_DB", "/e/q.db"),
            ("FLEETD_SOCKET", "/e/s.sock"),
            ("FLEET_BOX_NAME", "from-env"),
            ("FLEETD_SECRETS_FILE", "/e/secrets"),
        ]);
        let cfg = Config::resolve(Some(file), &env).unwrap();
        assert_eq!(cfg.http_port, 9100);
        assert_eq!(cfg.db_path, PathBuf::from("/e/q.db"));
        assert_eq!(cfg.socket_path, PathBuf::from("/e/s.sock"));
        assert_eq!(cfg.box_name.as_deref(), Some("from-env"));
        assert_eq!(cfg.queue_max_bytes, 10);
        assert_eq!(cfg.queue_max_age, Duration::from_secs(60));
        assert_eq!(cfg.hook_events, vec!["Stop".to_owned()]);
        assert!(cfg.secrets_file.required);
    }

    #[test]
    fn empty_env_values_count_as_unset() {
        let env = env_of(&[
            ("FLEETD_DB", ""),
            ("FLEETD_SOCKET", ""),
            ("FLEET_BOX_NAME", ""),
            ("FLEETD_SECRETS_FILE", ""),
            ("FLEETD_PORT", ""),
        ]);
        let file = "db_path = \"/f/q.db\"\nbox_name = \"from-file\"\nhttp_port = 9000\n";
        let cfg = Config::resolve(Some(file), &env).unwrap();
        assert_eq!(cfg.db_path, PathBuf::from("/f/q.db"));
        assert_eq!(cfg.box_name.as_deref(), Some("from-file"));
        assert_eq!(cfg.http_port, 9000);
        assert!(!cfg.secrets_file.required);
    }

    #[test]
    fn zero_queue_caps_are_rejected() {
        assert!(Config::resolve(Some("queue_max_bytes = 0"), &env_of(&[])).is_err());
        assert!(Config::resolve(Some("queue_max_age_secs = 0"), &env_of(&[])).is_err());
    }

    #[test]
    fn file_values_apply_without_env() {
        let cfg = Config::resolve(Some("http_port = 9000"), &env_of(&[])).unwrap();
        assert_eq!(cfg.http_port, 9000);
    }

    #[test]
    fn rejects_bad_port_and_unknown_keys() {
        assert!(Config::resolve(None, &env_of(&[("FLEETD_PORT", "nope")])).is_err());
        assert!(Config::resolve(Some("bogus = 1"), &env_of(&[])).is_err());
    }
}
