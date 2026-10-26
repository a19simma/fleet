use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::Error;
use crate::runner::{DEFAULT_MAX_BUDGET_USD, DEFAULT_MAX_TURNS};

/// Config file read when `--config` is not given and the file exists.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/fleetd/config.toml";
/// Default secrets env file. A missing file at this path is not an error.
pub const DEFAULT_SECRETS_PATH: &str = "/etc/swarm/secrets.env";
const MAX_TURNS_LIMIT: u32 = 1000;
const MAX_BUDGET_USD_LIMIT: f64 = 1000.0;
const DEFAULT_PORT: u16 = 7071;
const DEFAULT_QUEUE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_QUEUE_MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;
const DEFAULT_DEDUPE_SECS: u64 = 10;
const DEFAULT_CLAUDE_BIN: &str = "claude";
const DEFAULT_GH_BIN: &str = "gh";
const DEFAULT_REPO_HOSTS: [&str; 1] = ["github.com"];
const DEFAULT_TOKEN_HOST: &str = "github.com";
const DEFAULT_HOOK_EVENTS: [&str; 7] = [
    "SessionStart",
    "UserPromptSubmit",
    "Stop",
    "Notification",
    "SessionEnd",
    "PostToolUse",
    "PostToolUseFailure",
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
    repo_hosts: Option<Vec<String>>,
    token_host: Option<String>,
    agent_config_dir: Option<PathBuf>,
    agent_env_passthrough: Option<Vec<String>>,
    max_turns: Option<i64>,
    max_budget_usd: Option<f64>,
    hook_socket: Option<PathBuf>,
    hook_socket_uid: Option<u32>,
    hook_socket_group: Option<String>,
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
#[derive(Debug, Clone, PartialEq)]
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
    /// Hosts a job repo may name, lowercase. Jobs run only https repos on these hosts, with
    /// no port. Defaults to `github.com`. An empty list rejects every repo.
    pub repo_hosts: Vec<String>,
    /// The one host whose prompts receive `GH_TOKEN`, lowercase. Config file only. Defaults to
    /// `github.com` when `repo_hosts` lists it, else none. An explicit value must be in
    /// `repo_hosts`. A host in `repo_hosts` other than this one never gets the token.
    pub token_host: Option<String>,
    /// Directory copied over the embedded agent config bundle, config file only. Unset uses
    /// the embedded bundle alone. See [`crate::agent_config`] for what it may hold.
    pub agent_config_dir: Option<PathBuf>,
    /// Extra environment variable names the agent inherits from fleetd, config file only.
    /// Names that hold fleetd credentials or start with `FLEETD_` are rejected.
    pub agent_env_passthrough: Vec<String>,
    /// Agentic turns one job may take, 1 to 1000, 100 by default. Always passed as
    /// `--max-turns`. See [`crate::runner::DEFAULT_MAX_TURNS`].
    pub max_turns: u32,
    /// Dollars one job may spend, above 0 and at most 1000, 5.0 by default. Always passed as
    /// `--max-budget-usd`. See [`crate::runner::DEFAULT_MAX_TURNS`].
    pub max_budget_usd: f64,
    /// Admits `file://` and absolute-path repos. Always false from [`Config::resolve`],
    /// which has no file key or environment variable for it. Only code that builds a
    /// `Config` for a test sets it.
    pub allow_file_repos: bool,
    /// Second unix socket that serves only the hook routes, mode 0660. Absolute path, unset
    /// by default, which creates no second socket. Env `FLEETD_HOOK_SOCKET`. The hook client
    /// connects here instead of `socket_path` when it is set.
    pub hook_socket: Option<PathBuf>,
    /// Uid that must own the socket the hook client connects to and must be the peer on that
    /// connection. Unset means the client's own effective uid. Env `FLEETD_HOOK_SOCKET_UID`.
    pub hook_socket_uid: Option<u32>,
    /// Group that owns `hook_socket`, a numeric gid or a name from `/etc/group`. Needs
    /// `hook_socket`. Unset leaves the group the process default. Env
    /// `FLEETD_HOOK_SOCKET_GROUP`.
    pub hook_socket_group: Option<String>,
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
    /// `FLEETD_SECRETS_FILE`, plus `FLEETD_HOOK_SOCKET`, `FLEETD_HOOK_SOCKET_UID` and
    /// `FLEETD_HOOK_SOCKET_GROUP` for the hook socket keys. Without an override the db lives under `STATE_DIRECTORY`
    /// and the socket under `RUNTIME_DIRECTORY`, else the working directory.
    ///
    /// # Errors
    ///
    /// Fails on invalid TOML, an unparsable `FLEETD_PORT`, a zero
    /// `queue_max_bytes` or `queue_max_age_secs`, a `max_turns` outside 1 to 1000, a
    /// `max_budget_usd` that is not finite, not above 0 or above 1000, a `repo_hosts` entry that is not a bare
    /// host name, a `token_host` that is not in `repo_hosts`, a `hook_socket` that is relative
    /// or equals `socket_path`, an unparsable `hook_socket_uid`, or a `hook_socket_group` that
    /// is not a plain name or has no `hook_socket`. An empty environment value
    /// counts as unset.
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
        let queue_max_bytes = nonzero(
            "queue_max_bytes",
            file.queue_max_bytes,
            DEFAULT_QUEUE_MAX_BYTES,
        )?;
        let queue_max_age_secs = nonzero(
            "queue_max_age_secs",
            file.queue_max_age_secs,
            DEFAULT_QUEUE_MAX_AGE_SECS,
        )?;
        let repo_hosts = resolve_repo_hosts(file.repo_hosts)?;
        let token_host = resolve_token_host(file.token_host, &repo_hosts)?;
        let agent_env_passthrough = resolve_passthrough(file.agent_env_passthrough)?;
        let max_turns = resolve_max_turns(file.max_turns)?;
        let max_budget_usd = resolve_max_budget(file.max_budget_usd)?;
        let (hook_socket, hook_socket_uid, hook_socket_group) = resolve_hook_socket(
            &env,
            (
                file.hook_socket,
                file.hook_socket_uid,
                file.hook_socket_group,
            ),
            &socket_path,
        )?;
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
            jobs_dir: resolve_jobs_dir(&env, file.jobs_dir),
            repo_hosts,
            token_host,
            agent_config_dir: file.agent_config_dir,
            agent_env_passthrough,
            max_turns,
            max_budget_usd,
            allow_file_repos: false,
            hook_socket,
            hook_socket_uid,
            hook_socket_group,
        })
    }
}

fn nonzero(name: &'static str, raw: Option<u64>, default: u64) -> Result<u64, Error> {
    match raw.unwrap_or(default) {
        0 => Err(Error::InvalidValue {
            name,
            value: "0".to_owned(),
        }),
        value => Ok(value),
    }
}

fn resolve_jobs_dir(env: &dyn Fn(&str) -> Option<String>, file: Option<PathBuf>) -> PathBuf {
    env("FLEETD_JOBS_DIR")
        .map(PathBuf::from)
        .or(file)
        .unwrap_or_else(|| {
            env("STATE_DIRECTORY")
                .as_deref()
                .and_then(first_dir)
                .map_or_else(|| PathBuf::from("jobs"), |dir| dir.join("jobs"))
        })
}

type HookSocket = (Option<PathBuf>, Option<u32>, Option<String>);

fn resolve_hook_socket(
    env: &dyn Fn(&str) -> Option<String>,
    file: HookSocket,
    main_socket: &Path,
) -> Result<HookSocket, Error> {
    let socket = env("FLEETD_HOOK_SOCKET").map(PathBuf::from).or(file.0);
    let uid = match env("FLEETD_HOOK_SOCKET_UID") {
        Some(raw) => Some(raw.parse().map_err(|_| Error::InvalidValue {
            name: "FLEETD_HOOK_SOCKET_UID",
            value: raw,
        })?),
        None => file.1,
    };
    let group = env("FLEETD_HOOK_SOCKET_GROUP").or(file.2);
    check_hook_socket(socket.as_deref(), group.as_deref(), main_socket)?;
    Ok((socket, uid, group))
}

fn check_hook_socket(
    socket: Option<&Path>,
    group: Option<&str>,
    main_socket: &Path,
) -> Result<(), Error> {
    let invalid = |name: &'static str, value: String| Error::InvalidValue { name, value };
    if let Some(socket) = socket
        && (!socket.is_absolute() || socket == main_socket)
    {
        return Err(invalid("hook_socket", socket.display().to_string()));
    }
    let name_ok = |name: &str| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    match group {
        Some(group) if socket.is_none() || !name_ok(group) => {
            Err(invalid("hook_socket_group", group.to_owned()))
        }
        _ => Ok(()),
    }
}

fn resolve_max_turns(raw: Option<i64>) -> Result<u32, Error> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_MAX_TURNS);
    };
    u32::try_from(raw)
        .ok()
        .filter(|turns| (1..=MAX_TURNS_LIMIT).contains(turns))
        .ok_or_else(|| Error::InvalidValue {
            name: "max_turns",
            value: raw.to_string(),
        })
}

/// NaN fails both comparisons and infinity fails the upper bound, so the range alone keeps the
/// value finite.
fn resolve_max_budget(raw: Option<f64>) -> Result<f64, Error> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_MAX_BUDGET_USD);
    };
    if raw > 0.0 && raw <= MAX_BUDGET_USD_LIMIT {
        Ok(raw)
    } else {
        Err(Error::InvalidValue {
            name: "max_budget_usd",
            value: raw.to_string(),
        })
    }
}

fn resolve_repo_hosts(raw: Option<Vec<String>>) -> Result<Vec<String>, Error> {
    let hosts = raw.map_or_else(
        || DEFAULT_REPO_HOSTS.map(str::to_owned).to_vec(),
        |hosts| hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
    );
    let bare = |host: &String| {
        !host.is_empty()
            && !host.starts_with(['.', '-'])
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    };
    if hosts.iter().all(bare) {
        Ok(hosts)
    } else {
        Err(Error::InvalidValue {
            name: "repo_hosts",
            value: "<redacted>".to_owned(),
        })
    }
}

fn resolve_passthrough(raw: Option<Vec<String>>) -> Result<Vec<String>, Error> {
    let names = raw.unwrap_or_default();
    let valid = |name: &String| {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !crate::runner::env_forbidden(name)
    };
    if names.iter().all(valid) {
        Ok(names)
    } else {
        Err(Error::InvalidValue {
            name: "agent_env_passthrough",
            value: "<redacted>".to_owned(),
        })
    }
}

fn resolve_token_host(raw: Option<String>, repo_hosts: &[String]) -> Result<Option<String>, Error> {
    let listed = |host: &str| repo_hosts.iter().any(|h| h == host);
    match raw.map(|host| host.to_ascii_lowercase()) {
        Some(host) if listed(&host) => Ok(Some(host)),
        Some(_) => Err(Error::InvalidValue {
            name: "token_host",
            value: "<redacted>".to_owned(),
        }),
        None => Ok(listed(DEFAULT_TOKEN_HOST).then(|| DEFAULT_TOKEN_HOST.to_owned())),
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

    fn caps(text: &str) -> Result<(u32, f64), Error> {
        Config::resolve(Some(text), &env_of(&[])).map(|cfg| (cfg.max_turns, cfg.max_budget_usd))
    }

    #[test]
    fn caps_default_to_100_turns_and_5_dollars() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.max_turns, 100);
        assert!((cfg.max_budget_usd - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn valid_caps_are_accepted_including_the_edges() {
        for (text, turns, budget) in [
            ("max_turns = 1", 1, 5.0),
            ("max_turns = 1000", 1000, 5.0),
            ("max_turns = 37", 37, 5.0),
            ("max_budget_usd = 1000.0", 100, 1000.0),
            ("max_budget_usd = 1000", 100, 1000.0),
            ("max_budget_usd = 0.01", 100, 0.01),
            ("max_turns = 2\nmax_budget_usd = 2.5", 2, 2.5),
        ] {
            let (got_turns, got_budget) = caps(text).unwrap();
            assert_eq!(got_turns, turns, "{text}");
            assert!((got_budget - budget).abs() < f64::EPSILON, "{text}");
        }
    }

    #[test]
    fn invalid_caps_fail_startup_naming_the_key() {
        for (text, name) in [
            ("max_turns = 0", "max_turns"),
            ("max_turns = 1001", "max_turns"),
            ("max_turns = -1", "max_turns"),
            ("max_turns = 4294967297", "max_turns"),
            ("max_budget_usd = nan", "max_budget_usd"),
            ("max_budget_usd = inf", "max_budget_usd"),
            ("max_budget_usd = -inf", "max_budget_usd"),
            ("max_budget_usd = 0", "max_budget_usd"),
            ("max_budget_usd = 0.0", "max_budget_usd"),
            ("max_budget_usd = -1.5", "max_budget_usd"),
            ("max_budget_usd = 1000.01", "max_budget_usd"),
            ("max_budget_usd = 1001", "max_budget_usd"),
        ] {
            match caps(text) {
                Err(Error::InvalidValue { name: got, .. }) => assert_eq!(got, name, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
    }

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
        assert_eq!(cfg.hook_events.len(), 7);
        assert!(cfg.hook_events.iter().any(|e| e == "PostToolUse"));
        assert!(cfg.hook_events.iter().any(|e| e == "PostToolUseFailure"));
        assert!(!cfg.secrets_file.required);
    }

    #[test]
    fn hook_socket_keys_default_to_unset() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.hook_socket, None);
        assert_eq!(cfg.hook_socket_uid, None);
        assert_eq!(cfg.hook_socket_group, None);
    }

    #[test]
    fn hook_socket_keys_come_from_the_file_and_env_overrides_them() {
        let file = "hook_socket = \"/run/a/hook.sock\"\nhook_socket_uid = 7\nhook_socket_group = \"fleet-work\"\n";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(cfg.hook_socket, Some(PathBuf::from("/run/a/hook.sock")));
        assert_eq!(cfg.hook_socket_uid, Some(7));
        assert_eq!(cfg.hook_socket_group.as_deref(), Some("fleet-work"));
        let env = env_of(&[
            ("FLEETD_HOOK_SOCKET", "/run/b/hook.sock"),
            ("FLEETD_HOOK_SOCKET_UID", "8"),
            ("FLEETD_HOOK_SOCKET_GROUP", "other"),
        ]);
        let cfg = Config::resolve(Some(file), &env).unwrap();
        assert_eq!(cfg.hook_socket, Some(PathBuf::from("/run/b/hook.sock")));
        assert_eq!(cfg.hook_socket_uid, Some(8));
        assert_eq!(cfg.hook_socket_group.as_deref(), Some("other"));
    }

    #[test]
    fn invalid_hook_socket_keys_fail_startup_naming_the_key() {
        let named =
            |file: &str, env: &[(&str, &str)]| match Config::resolve(Some(file), &env_of(env)) {
                Err(Error::InvalidValue { name, .. }) => name,
                other => panic!("{other:?}"),
            };
        assert_eq!(named("hook_socket = \"hook.sock\"", &[]), "hook_socket");
        assert_eq!(
            named("socket_path = \"/a/s\"\nhook_socket = \"/a/s\"", &[]),
            "hook_socket"
        );
        assert_eq!(
            named("hook_socket_group = \"fleet-work\"", &[]),
            "hook_socket_group"
        );
        for bad in ["", "a b", "a/b", "a:b"] {
            let file = format!("hook_socket = \"/a/h\"\nhook_socket_group = {bad:?}");
            assert_eq!(named(&file, &[]), "hook_socket_group", "{bad:?}");
        }
        assert_eq!(
            named("", &[("FLEETD_HOOK_SOCKET_UID", "-1")]),
            "FLEETD_HOOK_SOCKET_UID"
        );
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
        assert_eq!(cfg.agent_config_dir, None);
        assert_eq!(cfg.agent_env_passthrough, Vec::<String>::new());
        assert_eq!(cfg.jobs_dir, PathBuf::from("jobs"));
        let state = |name: &str| (name == "STATE_DIRECTORY").then(|| "/var/lib/fleetd".to_owned());
        let cfg = Config::resolve(None, &state).unwrap();
        assert_eq!(cfg.jobs_dir, PathBuf::from("/var/lib/fleetd/jobs"));
        let cfg = Config::resolve(Some("jobs_dir = \"/srv/j\"\n"), &state).unwrap();
        assert_eq!(cfg.jobs_dir, PathBuf::from("/srv/j"));
    }

    #[test]
    fn agent_keys_resolve_and_a_credential_name_is_rejected() {
        let file = "agent_config_dir = \"/etc/fleetd/agent\"\nagent_env_passthrough = [\"ANTHROPIC_BASE_URL\", \"CLAUDE_CODE_USE_BEDROCK\"]\n";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(
            cfg.agent_config_dir,
            Some(PathBuf::from("/etc/fleetd/agent"))
        );
        assert_eq!(
            cfg.agent_env_passthrough,
            ["ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK"]
        );
        for bad in ["GH_TOKEN", "FLEETD_ASKPASS", "FLEET_TOKEN", "A=B", "", "1X"] {
            let file = format!("agent_env_passthrough = [\"{bad}\"]\n");
            assert!(Config::resolve(Some(&file), &env_of(&[])).is_err(), "{bad}");
        }
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
    fn repo_hosts_default_to_github_and_normalise_case() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.repo_hosts, vec!["github.com".to_owned()]);
        assert!(!cfg.allow_file_repos);
        let file = "repo_hosts = [\"Git.Example.com\", \"github.com\"]";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(cfg.repo_hosts, ["git.example.com", "github.com"]);
        let cfg = Config::resolve(Some("repo_hosts = []"), &env_of(&[])).unwrap();
        assert_eq!(cfg.repo_hosts, Vec::<String>::new());
    }

    #[test]
    fn repo_hosts_reject_anything_but_a_bare_host() {
        for bad in [
            "",
            "a b",
            "a/b",
            "a:443",
            "u@h",
            "-h",
            ".h",
            "a,b",
            "https://h",
        ] {
            let file = format!("repo_hosts = [\"{bad}\"]");
            assert!(Config::resolve(Some(&file), &env_of(&[])).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_host_defaults_to_github_when_listed() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.token_host.as_deref(), Some("github.com"));
        let file = "repo_hosts = [\"gitlab.com\", \"github.com\"]";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(cfg.token_host.as_deref(), Some("github.com"));
        let cfg = Config::resolve(Some("repo_hosts = [\"gitlab.com\"]"), &env_of(&[])).unwrap();
        assert_eq!(cfg.token_host, None);
        let cfg = Config::resolve(Some("repo_hosts = []"), &env_of(&[])).unwrap();
        assert_eq!(cfg.token_host, None);
    }

    #[test]
    fn token_host_names_one_listed_host_and_normalises_case() {
        let file = "repo_hosts = [\"github.com\", \"gitlab.com\"]\ntoken_host = \"GitLab.com\"";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(cfg.token_host.as_deref(), Some("gitlab.com"));
    }

    #[test]
    fn token_host_outside_repo_hosts_is_rejected_and_has_no_env_override() {
        for file in [
            "token_host = \"gitlab.com\"",
            "repo_hosts = []\ntoken_host = \"github.com\"",
            "token_host = \"\"",
        ] {
            assert!(Config::resolve(Some(file), &env_of(&[])).is_err(), "{file}");
        }
        let env = env_of(&[("FLEETD_TOKEN_HOST", "evil.example")]);
        let cfg = Config::resolve(None, &env).unwrap();
        assert_eq!(cfg.token_host.as_deref(), Some("github.com"));
    }

    #[test]
    fn no_file_key_or_env_admits_local_repos() {
        assert!(Config::resolve(Some("allow_file = true"), &env_of(&[])).is_err());
        assert!(Config::resolve(Some("allow_file_repos = true"), &env_of(&[])).is_err());
        let env = env_of(&[("FLEETD_ALLOW_FILE", "1"), ("FLEETD_ALLOW_FILE_REPOS", "1")]);
        assert!(!Config::resolve(None, &env).unwrap().allow_file_repos);
    }

    #[test]
    fn rejects_bad_port_and_unknown_keys() {
        assert!(Config::resolve(None, &env_of(&[("FLEETD_PORT", "nope")])).is_err());
        assert!(Config::resolve(Some("bogus = 1"), &env_of(&[])).is_err());
    }
}
