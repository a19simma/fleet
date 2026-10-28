use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::Error;
use crate::fetch_policy::{FetchCaps, FetchPolicy, HostPattern};
use crate::runner::{
    DEFAULT_CI_DEADLINE, DEFAULT_MAX_BUDGET_USD, DEFAULT_MAX_TURNS, DEFAULT_TIMEOUT,
};

/// Config file read when `--config` is not given and the file exists.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/fleetd/config.toml";
/// Default secrets env file. A missing file at this path is not an error.
pub const DEFAULT_SECRETS_PATH: &str = "/etc/swarm/secrets.env";
const MAX_TURNS_LIMIT: u32 = 1000;

/// Largest `ci_deadline_secs`, two hours.
const MAX_CI_DEADLINE_SECS: u64 = 7200;
/// The `RuntimeMaxSec` of `deploy/fleet-agent@.service` in seconds, the unit's own backstop.
const UNIT_RUNTIME_MAX_SECS: u64 = 2 * 60 * 60;
/// Seconds the unit's `RuntimeMaxSec` must outlast `agent_timeout_secs`, so fleetd's own
/// deadline fires first and the run reads as timed out, not as a unit kill.
const RUNTIME_MAX_HEADROOM_SECS: u64 = 5 * 60;
/// Largest `agent_timeout_secs`: [`UNIT_RUNTIME_MAX_SECS`] less [`RUNTIME_MAX_HEADROOM_SECS`].
const MAX_AGENT_TIMEOUT_SECS: u64 = UNIT_RUNTIME_MAX_SECS - RUNTIME_MAX_HEADROOM_SECS;
const MAX_BUDGET_USD_LIMIT: f64 = 1000.0;
const DEFAULT_PORT: u16 = 7071;
const DEFAULT_QUEUE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_QUEUE_MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;
const DEFAULT_DEDUPE_SECS: u64 = 10;
const DEFAULT_CLAUDE_BIN: &str = "claude";
const DEFAULT_GH_BIN: &str = "gh";
const DEFAULT_REPO_HOSTS: [&str; 1] = ["github.com"];
const DEFAULT_TOKEN_HOST: &str = "github.com";
const MAX_FETCH_BODY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FETCH_DECODED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FETCH_CONNECT_SECS: u64 = 60;
const MAX_FETCH_TOTAL_SECS: u64 = 300;
const MAX_FETCH_REDIRECTS: u64 = 10;
const MAX_FETCH_PER_JOB: u64 = 1000;
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
    agent_timeout_secs: Option<i64>,
    ci_deadline_secs: Option<i64>,
    hook_socket: Option<PathBuf>,
    hook_socket_uid: Option<u32>,
    hook_socket_group: Option<String>,
    job_group: Option<String>,
    agent_launcher: Option<String>,
    systemctl_path: Option<PathBuf>,
    fetch_policy: Option<String>,
    fetch_allow: Option<Vec<String>>,
    fetch_max_body_bytes: Option<i64>,
    fetch_max_decoded_bytes: Option<i64>,
    fetch_connect_timeout_secs: Option<i64>,
    fetch_total_timeout_secs: Option<i64>,
    fetch_max_redirects: Option<i64>,
    fetch_max_per_job: Option<i64>,
    egress_allow: Option<Vec<String>>,
}

/// How agents are started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AgentLauncher {
    /// A child process of fleetd.
    #[default]
    Direct,
    /// A `fleet-agent@<id>.service` unit started through `systemctl`.
    Systemd,
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
    /// Longest one agent run may take, 1 to [`MAX_AGENT_TIMEOUT_SECS`] seconds, 1800 by
    /// default, config file only. It sets `RunConfig::timeout` and, with the systemd launcher,
    /// the deadline past which a unit kill reads as a timeout. The unit's `RuntimeMaxSec`
    /// outlasts the maximum by [`RUNTIME_MAX_HEADROOM_SECS`].
    pub agent_timeout: Duration,
    /// Longest time to wait for the pull request checks to settle after the push, 1 to
    /// [`MAX_CI_DEADLINE_SECS`] seconds, 900 by default, config file only. A job whose checks
    /// have not settled by then ends its CI state as `timeout`. It may exceed the 120 s lease,
    /// because the wait renews the lease every `report_interval`.
    pub ci_deadline: Duration,
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
    /// Group the per-job directories are shared with, a numeric gid or a name from
    /// `/etc/group`. Unset keeps today's modes and sets no group. Env `FLEETD_JOB_GROUP`.
    pub job_group: Option<String>,
    /// How agents start, `direct` or `systemd`, `direct` by default. Env
    /// `FLEETD_AGENT_LAUNCHER`.
    pub agent_launcher: AgentLauncher,
    /// Absolute path of the `systemctl` binary the systemd launcher runs, `/usr/bin/systemctl`
    /// by default. Env `FLEETD_SYSTEMCTL_PATH`.
    pub systemctl_path: PathBuf,
    /// Which hosts `fleetd fetch` may reach. `fetch_policy` is `allow_all_public` (the default,
    /// any public host, an exfiltration path by decision in ADR-0038) or `allowlist`, which
    /// needs `fetch_allow`. Config file only: no environment variable and no Profile field
    /// sets it.
    pub fetch_policy: FetchPolicy,
    /// Limits on one fetch and on the fetches of one Job. Config file only, each key bounded:
    /// `fetch_max_body_bytes` 1 to 64 MiB, `fetch_max_decoded_bytes` from the body cap to
    /// 256 MiB, `fetch_connect_timeout_secs` 1 to 60, `fetch_total_timeout_secs` from the
    /// connect time to 300, `fetch_max_redirects` 0 to 10, `fetch_max_per_job` 1 to 1000. The
    /// URL cap is fixed at [`crate::fetch_policy::MAX_URL_BYTES`].
    pub fetch_caps: FetchCaps,
    /// Hosts the egress proxy may `CONNECT` to, `host.example` or `*.example`, empty by
    /// default. Config file only: no Profile or bundle can add hosts (ADR-0038).
    pub egress_allow: Vec<HostPattern>,
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
        let (fetch_policy, fetch_caps, egress_allow) = resolve_fetch(&file)?;
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
        let secrets_file = resolve_secrets(&env, file.secrets_file);
        let (queue_max_bytes, queue_max_age) =
            resolve_queue(file.queue_max_bytes, file.queue_max_age_secs)?;
        let repo_hosts = resolve_repo_hosts(file.repo_hosts)?;
        let token_host = resolve_token_host(file.token_host, &repo_hosts)?;
        let agent_env_passthrough = resolve_passthrough(file.agent_env_passthrough)?;
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
        let (agent_launcher, systemctl_path) =
            resolve_launcher(&env, file.agent_launcher, file.systemctl_path)?;
        Ok(Self {
            http_port,
            socket_path,
            db_path,
            queue_max_bytes,
            queue_max_age,
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
            max_turns: resolve_max_turns(file.max_turns)?,
            max_budget_usd,
            agent_timeout: resolve_agent_timeout(file.agent_timeout_secs)?,
            ci_deadline: resolve_ci_deadline(file.ci_deadline_secs)?,
            allow_file_repos: false,
            hook_socket,
            hook_socket_uid,
            hook_socket_group,
            job_group: resolve_job_group(&env, file.job_group)?,
            agent_launcher,
            systemctl_path,
            fetch_policy,
            fetch_caps,
            egress_allow,
        })
    }
}

fn resolve_secrets(env: &dyn Fn(&str) -> Option<String>, file: Option<PathBuf>) -> SecretsFile {
    let named = env("FLEETD_SECRETS_FILE").map(PathBuf::from).or(file);
    SecretsFile {
        required: named.is_some(),
        path: named.unwrap_or_else(|| PathBuf::from(DEFAULT_SECRETS_PATH)),
    }
}

fn bad_key(name: &'static str) -> Error {
    Error::InvalidValue {
        name,
        value: "<redacted>".to_owned(),
    }
}

fn bounded(
    name: &'static str,
    raw: Option<i64>,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, Error> {
    let Some(raw) = raw else { return Ok(default) };
    u64::try_from(raw)
        .ok()
        .filter(|value| range.contains(value))
        .ok_or_else(|| Error::InvalidValue {
            name,
            value: raw.to_string(),
        })
}

fn patterns(name: &'static str, raw: &[String]) -> Result<Vec<HostPattern>, Error> {
    raw.iter()
        .map(|text| HostPattern::parse(text).map_err(|_| bad_key(name)))
        .collect()
}

fn resolve_fetch(file: &FileConfig) -> Result<(FetchPolicy, FetchCaps, Vec<HostPattern>), Error> {
    let policy = match (file.fetch_policy.as_deref(), &file.fetch_allow) {
        (None | Some("allow_all_public"), None) => FetchPolicy::AllowAllPublicHosts,
        (Some("allowlist"), Some(allow)) => FetchPolicy::Allowlist(patterns("fetch_allow", allow)?),
        (Some("allowlist"), None) | (None | Some("allow_all_public"), Some(_)) => {
            return Err(bad_key("fetch_allow"));
        }
        (Some(_), _) => return Err(bad_key("fetch_policy")),
    };
    let defaults = FetchCaps::default();
    let body = bounded(
        "fetch_max_body_bytes",
        file.fetch_max_body_bytes,
        defaults.max_body_bytes,
        1..=MAX_FETCH_BODY_BYTES,
    )?;
    let decoded = bounded(
        "fetch_max_decoded_bytes",
        file.fetch_max_decoded_bytes,
        defaults.max_decoded_bytes.max(body),
        body..=MAX_FETCH_DECODED_BYTES,
    )?;
    let connect = bounded(
        "fetch_connect_timeout_secs",
        file.fetch_connect_timeout_secs,
        defaults.connect_timeout.as_secs(),
        1..=MAX_FETCH_CONNECT_SECS,
    )?;
    let total = bounded(
        "fetch_total_timeout_secs",
        file.fetch_total_timeout_secs,
        defaults.total_timeout.as_secs().max(connect),
        connect..=MAX_FETCH_TOTAL_SECS,
    )?;
    let redirects = bounded(
        "fetch_max_redirects",
        file.fetch_max_redirects,
        u64::from(defaults.max_redirects),
        0..=MAX_FETCH_REDIRECTS,
    )?;
    let per_job = bounded(
        "fetch_max_per_job",
        file.fetch_max_per_job,
        u64::from(defaults.max_fetches_per_job),
        1..=MAX_FETCH_PER_JOB,
    )?;
    let caps = FetchCaps {
        max_body_bytes: body,
        max_decoded_bytes: decoded,
        connect_timeout: Duration::from_secs(connect),
        total_timeout: Duration::from_secs(total),
        max_redirects: u8::try_from(redirects).map_err(|_| bad_key("fetch_max_redirects"))?,
        max_fetches_per_job: u32::try_from(per_job).map_err(|_| bad_key("fetch_max_per_job"))?,
        ..defaults
    };
    let egress = patterns(
        "egress_allow",
        file.egress_allow.as_deref().unwrap_or_default(),
    )?;
    Ok((policy, caps, egress))
}

fn resolve_launcher(
    env: &dyn Fn(&str) -> Option<String>,
    launcher: Option<String>,
    systemctl: Option<PathBuf>,
) -> Result<(AgentLauncher, PathBuf), Error> {
    let launcher = match env("FLEETD_AGENT_LAUNCHER").or(launcher).as_deref() {
        None | Some("direct") => AgentLauncher::Direct,
        Some("systemd") => AgentLauncher::Systemd,
        Some(other) => {
            return Err(Error::InvalidValue {
                name: "agent_launcher",
                value: other.to_owned(),
            });
        }
    };
    let systemctl = env("FLEETD_SYSTEMCTL_PATH")
        .map(PathBuf::from)
        .or(systemctl)
        .unwrap_or_else(|| PathBuf::from(crate::systemd::DEFAULT_SYSTEMCTL));
    if systemctl.is_absolute() {
        Ok((launcher, systemctl))
    } else {
        Err(Error::InvalidValue {
            name: "systemctl_path",
            value: systemctl.display().to_string(),
        })
    }
}

fn group_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn resolve_job_group(
    env: &dyn Fn(&str) -> Option<String>,
    file: Option<String>,
) -> Result<Option<String>, Error> {
    match env("FLEETD_JOB_GROUP").or(file) {
        Some(group) if !group_name_ok(&group) => Err(Error::InvalidValue {
            name: "job_group",
            value: group,
        }),
        group => Ok(group),
    }
}

fn resolve_queue(bytes: Option<u64>, age_secs: Option<u64>) -> Result<(u64, Duration), Error> {
    Ok((
        nonzero("queue_max_bytes", bytes, DEFAULT_QUEUE_MAX_BYTES)?,
        Duration::from_secs(nonzero(
            "queue_max_age_secs",
            age_secs,
            DEFAULT_QUEUE_MAX_AGE_SECS,
        )?),
    ))
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
    match group {
        Some(group) if socket.is_none() || !group_name_ok(group) => {
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

fn resolve_agent_timeout(raw: Option<i64>) -> Result<Duration, Error> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_TIMEOUT);
    };
    u64::try_from(raw)
        .ok()
        .filter(|secs| (1..=MAX_AGENT_TIMEOUT_SECS).contains(secs))
        .map(Duration::from_secs)
        .ok_or_else(|| Error::InvalidValue {
            name: "agent_timeout_secs",
            value: raw.to_string(),
        })
}

fn resolve_ci_deadline(raw: Option<i64>) -> Result<Duration, Error> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_CI_DEADLINE);
    };
    u64::try_from(raw)
        .ok()
        .filter(|secs| (1..=MAX_CI_DEADLINE_SECS).contains(secs))
        .map(Duration::from_secs)
        .ok_or_else(|| Error::InvalidValue {
            name: "ci_deadline_secs",
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
    fn agent_timeout_defaults_and_accepts_the_edges() {
        let timeout =
            |text: &str| Config::resolve(Some(text), &env_of(&[])).map(|c| c.agent_timeout);
        assert_eq!(
            Config::resolve(None, &env_of(&[])).unwrap().agent_timeout,
            Duration::from_secs(1800)
        );
        assert_eq!(
            timeout("agent_timeout_secs = 1").unwrap(),
            Duration::from_secs(1)
        );
        assert_eq!(
            timeout("agent_timeout_secs = 6900").unwrap(),
            Duration::from_secs(MAX_AGENT_TIMEOUT_SECS)
        );
    }

    #[test]
    fn ci_deadline_defaults_and_accepts_the_edges() {
        let deadline =
            |text: &str| Config::resolve(Some(text), &env_of(&[])).map(|c| c.ci_deadline);
        assert_eq!(
            Config::resolve(None, &env_of(&[])).unwrap().ci_deadline,
            Duration::from_secs(900)
        );
        assert_eq!(
            deadline("ci_deadline_secs = 1").unwrap(),
            Duration::from_secs(1)
        );
        assert_eq!(
            deadline("ci_deadline_secs = 7200").unwrap(),
            Duration::from_secs(MAX_CI_DEADLINE_SECS)
        );
    }

    #[test]
    fn invalid_ci_deadlines_fail_startup_naming_the_key() {
        for text in [
            "ci_deadline_secs = 0",
            "ci_deadline_secs = -1",
            "ci_deadline_secs = 7201",
        ] {
            match Config::resolve(Some(text), &env_of(&[])) {
                Err(Error::InvalidValue { name, .. }) => assert_eq!(name, "ci_deadline_secs"),
                other => panic!("{text}: {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_agent_timeouts_fail_startup_naming_the_key() {
        for text in [
            "agent_timeout_secs = 0",
            "agent_timeout_secs = -1",
            "agent_timeout_secs = 6901",
            "agent_timeout_secs = 7200",
        ] {
            match Config::resolve(Some(text), &env_of(&[])) {
                Err(Error::InvalidValue { name, .. }) => assert_eq!(name, "agent_timeout_secs"),
                other => panic!("{text}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_unit_runtime_max_outlasts_the_largest_agent_timeout() {
        let unit = include_str!("../../../deploy/fleet-agent@.service");
        assert!(unit.contains("\nRuntimeMaxSec=2h\n"));
        assert_eq!(UNIT_RUNTIME_MAX_SECS, 2 * 60 * 60);
        assert_eq!(
            MAX_AGENT_TIMEOUT_SECS + RUNTIME_MAX_HEADROOM_SECS,
            UNIT_RUNTIME_MAX_SECS
        );
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
    fn job_group_defaults_to_unset_and_reads_file_then_env() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.job_group, None);
        let file = "job_group = \"fleet-work\"\n";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(cfg.job_group.as_deref(), Some("fleet-work"));
        let cfg = Config::resolve(Some(file), &env_of(&[("FLEETD_JOB_GROUP", "996")])).unwrap();
        assert_eq!(cfg.job_group.as_deref(), Some("996"));
    }

    #[test]
    fn a_bad_job_group_is_rejected_by_name() {
        for bad in ["", "a b", "a:b", "x/y"] {
            let file = format!("job_group = {bad:?}");
            let name = match Config::resolve(Some(&file), &env_of(&[])) {
                Err(Error::InvalidValue { name, .. }) => name,
                other => panic!("{other:?}"),
            };
            assert_eq!(name, "job_group", "{bad:?}");
        }
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
    fn fetch_and_egress_default_to_allow_all_public_and_no_egress_hosts() {
        let cfg = Config::resolve(None, &env_of(&[])).unwrap();
        assert_eq!(cfg.fetch_policy, FetchPolicy::AllowAllPublicHosts);
        assert_eq!(cfg.fetch_caps, FetchCaps::default());
        assert_eq!(cfg.egress_allow, Vec::new());
    }

    #[test]
    fn fetch_and_egress_keys_resolve() {
        let file = "fetch_policy = \"allowlist\"\nfetch_allow = [\"Docs.Example\", \"*.example.org\"]\nfetch_max_body_bytes = 2048\nfetch_max_decoded_bytes = 4096\nfetch_connect_timeout_secs = 3\nfetch_total_timeout_secs = 9\nfetch_max_redirects = 2\nfetch_max_per_job = 7\negress_allow = [\"api.example\"]\n";
        let cfg = Config::resolve(Some(file), &env_of(&[])).unwrap();
        assert_eq!(
            cfg.fetch_policy,
            FetchPolicy::Allowlist(vec![
                HostPattern::Exact("docs.example".to_owned()),
                HostPattern::Subdomain("example.org".to_owned()),
            ])
        );
        let caps = cfg.fetch_caps;
        assert_eq!(
            (
                caps.max_body_bytes,
                caps.max_decoded_bytes,
                caps.max_redirects
            ),
            (2048, 4096, 2)
        );
        assert_eq!(caps.connect_timeout, Duration::from_secs(3));
        assert_eq!(caps.total_timeout, Duration::from_secs(9));
        assert_eq!(caps.max_fetches_per_job, 7);
        assert_eq!(caps.max_url_bytes, FetchCaps::default().max_url_bytes);
        assert_eq!(
            cfg.egress_allow,
            vec![HostPattern::Exact("api.example".to_owned())]
        );
        let explicit = Config::resolve(Some("fetch_policy = \"allow_all_public\"\n"), &env_of(&[]));
        assert_eq!(
            explicit.unwrap().fetch_policy,
            FetchPolicy::AllowAllPublicHosts
        );
        let env = env_of(&[
            ("FLEETD_FETCH_POLICY", "allowlist"),
            ("FLEETD_EGRESS_ALLOW", "x.example"),
        ]);
        let cfg = Config::resolve(None, &env).unwrap();
        assert_eq!(cfg.fetch_policy, FetchPolicy::AllowAllPublicHosts);
        assert_eq!(cfg.egress_allow, Vec::new());
    }

    #[test]
    fn fetch_caps_accept_their_edges_and_reject_the_next_value() {
        let table: [(&str, i64, i64); 6] = [
            ("fetch_max_body_bytes", 1, 64 * 1024 * 1024),
            ("fetch_max_decoded_bytes", 1, 256 * 1024 * 1024),
            ("fetch_connect_timeout_secs", 1, 60),
            ("fetch_total_timeout_secs", 1, 300),
            ("fetch_max_redirects", 0, 10),
            ("fetch_max_per_job", 1, 1000),
        ];
        let resolve = |name: &str, value: i64| {
            let extra = match name {
                "fetch_max_decoded_bytes" => "fetch_max_body_bytes = 1\n",
                "fetch_total_timeout_secs" => "fetch_connect_timeout_secs = 1\n",
                _ => "",
            };
            Config::resolve(Some(&format!("{extra}{name} = {value}\n")), &env_of(&[]))
        };
        for (name, low, high) in table {
            assert!(resolve(name, low).is_ok(), "{name} {low}");
            assert!(resolve(name, high).is_ok(), "{name} {high}");
            for bad in [low - 1, high + 1] {
                match resolve(name, bad) {
                    Err(Error::InvalidValue { name: got, .. }) => assert_eq!(got, name),
                    other => panic!("{name} {bad}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn invalid_fetch_and_egress_keys_fail_startup_naming_the_key() {
        let cases = [
            ("fetch_policy = \"open\"\n", "fetch_policy"),
            ("fetch_policy = \"allowlist\"\n", "fetch_allow"),
            ("fetch_allow = [\"a.example\"]\n", "fetch_allow"),
            (
                "fetch_policy = \"allow_all_public\"\nfetch_allow = [\"a.example\"]\n",
                "fetch_allow",
            ),
            (
                "fetch_policy = \"allowlist\"\nfetch_allow = [\"10.0.0.1\"]\n",
                "fetch_allow",
            ),
            (
                "fetch_policy = \"allowlist\"\nfetch_allow = [\"*\"]\n",
                "fetch_allow",
            ),
            ("egress_allow = [\"a b\"]\n", "egress_allow"),
            ("egress_allow = [\"*.com\"]\n", "egress_allow"),
            ("egress_allow = [\"\"]\n", "egress_allow"),
            (
                "fetch_max_body_bytes = 100\nfetch_max_decoded_bytes = 99\n",
                "fetch_max_decoded_bytes",
            ),
            (
                "fetch_connect_timeout_secs = 10\nfetch_total_timeout_secs = 9\n",
                "fetch_total_timeout_secs",
            ),
        ];
        for (text, key) in cases {
            match Config::resolve(Some(text), &env_of(&[])) {
                Err(Error::InvalidValue { name, .. }) => assert_eq!(name, key, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
        let empty = "fetch_policy = \"allowlist\"\nfetch_allow = []\n";
        let cfg = Config::resolve(Some(empty), &env_of(&[])).unwrap();
        assert_eq!(cfg.fetch_policy, FetchPolicy::Allowlist(Vec::new()));
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
