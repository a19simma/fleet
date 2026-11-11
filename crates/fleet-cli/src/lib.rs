//! The `fleet` command line client: job submission and inspection over gRPC.

pub mod batch;
pub mod catalog;
pub mod config;
pub mod credential;
pub mod edit;
pub mod env;
pub mod list;
pub mod logs;
pub mod patch;
mod pretty;
pub mod profile;
pub mod repo;
pub mod retro;
pub mod stats;
pub mod telemetry;
pub mod timing;
pub mod watch;
pub mod work;

use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;

use clap::{Parser, Subcommand};
use fleet_core::environment::EnvironmentName;
use fleet_core::text::{Cap, sanitise_lines, sanitise_text};
use fleet_proto::v1::fleet_batches_client::FleetBatchesClient;
use fleet_proto::v1::fleet_credentials_client::FleetCredentialsClient;
use fleet_proto::v1::fleet_edit_client::FleetEditClient;
use fleet_proto::v1::fleet_environments_client::FleetEnvironmentsClient;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_profiles_client::FleetProfilesClient;
use fleet_proto::v1::fleet_query_client::FleetQueryClient;
use fleet_proto::v1::fleet_repos_client::FleetReposClient;
use fleet_proto::v1::fleet_retro_client::FleetRetroClient;
use fleet_proto::v1::fleet_work_client::FleetWorkClient;
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, ListJobsRequest, SubmitJobRequest,
};
use fleet_proto::{CredentialNotice, MAX_PROFILE_MESSAGE_BYTES};
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

pub use config::{Config, ConfigError};

const MAX_SERVER_TEXT: usize = 200;
const ELLIPSIS: char = '\u{2026}';

/// Time allowed to establish the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for one request. Above the server's own 30 s limit.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
/// Interval between HTTP/2 keepalive pings.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Time to wait for a keepalive ping to be acknowledged.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest reply a client accepts. The server caps a transcript page at 4 MiB before framing.
const MAX_DECODE_BYTES: usize = 16 * 1024 * 1024;
/// Largest `--limit` the server honours.
const MAX_JOBS_LIMIT: u32 = 200;
/// Jobs shown when `--limit` is not given.
const DEFAULT_JOBS_LIMIT: u32 = 50;

/// Command line arguments.
#[derive(Debug, Parser)]
#[command(name = "fleet", version, about = "Fleet command line client")]
pub struct Cli {
    /// Server URL. Falls back to `FLEET_SERVER_URL`.
    #[arg(long, global = true)]
    pub server: Option<String>,
    /// Allow sending the token over plain http to a non-loopback host.
    #[arg(long, global = true)]
    pub insecure: bool,
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Agent names `--agent` accepts.
pub const AGENTS: [&str; 3] = ["claude", "codex", "kimi"];

/// A subcommand.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List every box and what it is doing.
    List,
    /// Submit a job and print its id.
    Submit {
        /// Repository the job works in.
        #[arg(long)]
        repo: String,
        /// Ref the job branches from.
        #[arg(long)]
        base: String,
        /// Do not open a pull request when the job finishes.
        #[arg(long)]
        no_pr: bool,
        /// Key that makes a repeated submit return the same job.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Agent that runs the job: claude, codex or kimi. Empty means claude.
        #[arg(
            long,
            value_name = "AGENT",
            value_parser = AGENTS,
            help = "Agent that runs the job [default: claude]"
        )]
        agent: Option<String>,
        /// Environment to attach to the job, by name.
        #[arg(long, value_name = "NAME", conflicts_with = "no_env")]
        env: Option<String>,
        /// Attach no environment, even when a default binding exists.
        #[arg(long)]
        no_env: bool,
        /// Task prompt, or `-` to read it from stdin.
        prompt: String,
    },
    /// List jobs.
    Jobs {
        /// Only jobs in this state, for example `running`.
        #[arg(long)]
        state: Option<String>,
        /// Most jobs to show, 1 to 200.
        #[arg(long, default_value_t = DEFAULT_JOBS_LIMIT, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_JOBS_LIMIT)))]
        limit: u32,
    },
    /// Show one job.
    Status {
        /// Job id.
        id: String,
        /// Also list the job's tool calls.
        #[arg(long)]
        tools: bool,
    },
    /// Follow a job until it ends; exits 0 only on success.
    Watch {
        /// Job id.
        id: String,
    },
    /// Print a job transcript.
    Logs {
        /// Job id.
        id: String,
        /// Keep polling until the job ends; exit nonzero unless it succeeded.
        #[arg(short, long)]
        follow: bool,
        /// Print the stored stream-json lines unchanged instead of the readable view.
        #[arg(long)]
        raw: bool,
    },
    /// Request cancellation of a job.
    Cancel {
        /// Job id.
        id: String,
    },
    /// Show job outcome and telemetry statistics.
    Stats {
        /// Window start: a duration such as `7d`, `24h` or `90m`, or a unix time in seconds.
        #[arg(long, default_value = "7d")]
        since: String,
        /// Only jobs for this repository.
        #[arg(long)]
        repo: Option<String>,
        /// Only jobs that ran on this box.
        #[arg(long = "box")]
        box_name: Option<String>,
        /// Group rows by this column. Without it one row covers every job.
        #[arg(long, value_enum)]
        by: Option<StatsBy>,
    },
    /// Show where the time of one job went.
    Timing {
        /// Job id.
        job: String,
        /// Also list the job's shell commands with their durations.
        #[arg(long)]
        commands: bool,
        /// Stream the live log of one shell command until it ends.
        #[arg(long, value_name = "COMMAND_ID", conflicts_with = "commands")]
        follow: Option<String>,
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Compare the jobs of a batch, one column per profile.
    Batch {
        /// The batch action.
        #[command(subcommand)]
        action: BatchAction,
    },
    /// List the global catalog and, as an admin, add and switch items.
    Catalog {
        /// The catalog action.
        #[command(subcommand)]
        action: catalog::CatalogAction,
    },
    /// Manage the capabilities of users.
    #[command(name = "user")]
    UserCap {
        /// The user area.
        #[command(subcommand)]
        area: catalog::UserArea,
    },
    /// Create, list, show, share, unshare and edit named agent profiles.
    Profile {
        /// The profile action.
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Store, list, delete and verify credentials. Secrets are read from stdin.
    Credential {
        /// The credential action.
        #[command(subcommand)]
        action: credential::CredentialAction,
    },
    /// Add, list and remove the repositories you work on. Each add is checked with the forge.
    Repo {
        /// The repository action.
        #[command(subcommand)]
        action: repo::RepoAction,
    },
    /// Create, list, show and remove Environments, store secrets and edit setup scripts.
    Env {
        /// The environment action.
        #[command(subcommand)]
        action: env::EnvAction,
    },
    /// Manage Work projects, items, claims and Defers on the server.
    Work(work::WorkArgs),
    /// Open and close Retros and read the brief for a Work item.
    Retro(retro::RetroArgs),
    /// File, list and decide Improvements.
    Improvement(retro::ImprovementArgs),
    /// Record and list Pitfalls.
    Pitfall(retro::PitfallArgs),
    /// File, decide and apply suggested edits.
    Edit(edit::EditArgs),
}

/// A `fleet batch` action.
#[derive(Debug, Subcommand)]
pub enum BatchAction {
    /// Show one column per profile: outcome, cost, turns, times, tool figures and commands.
    Show {
        /// Batch id.
        id: String,
    },
    /// Submit one job per profile at a pinned commit and print the batch and job ids.
    Submit {
        /// Task prompt, or `-` to read it from stdin.
        #[arg(long)]
        prompt: String,
        /// Repository the jobs work in.
        #[arg(long)]
        repo: String,
        /// Commit the jobs start from: 40 lowercase hex characters.
        #[arg(long)]
        base: String,
        /// Profile names, comma separated: 1 to 16 distinct names.
        #[arg(long)]
        profiles: String,
        /// Key that makes a repeated submit return the same batch. A fresh key is used
        /// when it is absent.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Agent that runs every job: claude, codex or kimi. Empty means claude.
        #[arg(
            long,
            value_name = "AGENT",
            value_parser = AGENTS,
            help = "Agent that runs every job [default: claude]"
        )]
        agent: Option<String>,
    },
}

/// A `fleet profile` action.
#[derive(Debug, Subcommand)]
pub enum ProfileAction {
    /// Store a profile from a JSON file or stdin; the same content keeps its version. The
    /// input may hold at most `MAX_PROFILE_JSON_BYTES` bytes.
    Create {
        /// Profile name: 1 to 64 characters of letters, digits, `_` and `-`.
        name: String,
        /// File holding the profile JSON, or `-` to read it from stdin.
        #[arg(long)]
        file: String,
    },
    /// List every profile with its latest version, hash, owner and visibility.
    List,
    /// Show a profile: owner, visibility, selection, authored prompt, content, version and hash.
    Show {
        /// Profile name, or `name@version` for a pinned version.
        target: String,
    },
    /// Share one of your profiles so every user can read it.
    Share {
        /// Profile name.
        name: String,
    },
    /// Make one of your shared profiles private again.
    Unshare {
        /// Profile name.
        name: String,
    },
    /// Switch one catalog item on or off in a profile. Saves a new version, or keeps the
    /// current one when nothing changes. The server refuses an id it does not know.
    Item {
        /// Profile name.
        profile: String,
        /// Item kind: skill, subagent, tool or context. Checked for spelling only; the server
        /// matches the id alone, so the same id under another kind is also switched off.
        #[arg(value_parser = ["skill", "subagent", "tool", "context"])]
        kind: String,
        /// Catalog item id: 1 to 64 characters of lowercase letters, digits, `_` and `-`.
        id: String,
        /// `off` stores the item as switched off; `on` removes it from the stored selection.
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Set the authored prompt of a profile from a file or stdin. Saves a new version, or
    /// keeps the current one when nothing changes. Empty input clears the prompt.
    Prompt {
        /// Profile name.
        profile: String,
        /// File holding the prompt text, or `-` to read it from stdin: at most
        /// `MAX_PROMPT_TEXT_BYTES` bytes, no control characters but newline and tab.
        #[arg(long)]
        file: String,
    },
}

/// A column `fleet stats` groups its rows by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StatsBy {
    /// One row per repository.
    Repo,
    /// One row per box.
    Box,
    /// One row per job state.
    State,
    /// One row per UTC day.
    Day,
    /// One row per agent config bundle hash.
    BundleSha,
    /// One row per Claude Code version.
    ClaudeVersion,
    /// One row per model.
    Model,
}

/// A failure while running a command.
#[derive(Debug)]
pub enum CliError {
    /// Bad configuration.
    Config(ConfigError),
    /// Bad argument value.
    Usage(String),
    /// The connection could not be set up.
    Connect(String),
    /// The server answered with an error status.
    Rpc(Status),
    /// Reading input or writing output failed.
    Io(std::io::Error),
    /// A watched or followed job ended in a state other than succeeded.
    JobEnded(&'static str),
    /// The job exists but no timing report was stored for it.
    NoTimingReport,
    /// A credential command ended in a fixed notice. It holds no server text or input.
    Credential(CredentialNotice),
    /// `edit apply` refused or failed. The message is fixed text and scrubbed git output.
    Apply(String),
}

impl CliError {
    /// Redacts the message of a server status. Without a scrubber no connection was opened,
    /// so the status is local and its message is fixed text.
    fn scrubbed(self, scrub: Option<&Scrub>) -> Self {
        match (self, scrub) {
            (Self::Rpc(status), Some(scrub)) => {
                Self::Rpc(Status::new(status.code(), scrub.text(status.message())))
            }
            (other, _) => other,
        }
    }

    /// Process exit code: 2 for usage and configuration errors, 3 for a job with no timing
    /// report, 1 for everything else.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Usage(_) => 2,
            Self::NoTimingReport => 3,
            Self::Connect(_)
            | Self::Rpc(_)
            | Self::Io(_)
            | Self::JobEnded(_)
            | Self::Apply(_)
            | Self::Credential(_) => 1,
        }
    }
}

/// Redacts, strips, redacts, strips, keeping newline and tab: [`sanitise_lines`] without a cap.
///
/// The redact before the first strip matches a secret that itself holds a stripped character.
pub(crate) fn scrub(redactor: &fleet_core::Redactor, text: &str) -> String {
    sanitise_lines(redactor, text, Cap::Bytes(usize::MAX)).text
}

fn strip_lines(text: &str) -> String {
    scrub(&fleet_core::Redactor::new(None::<String>), text)
}

/// Scrubs server text of the client token. Every path that prints server-supplied job text
/// goes through one of these.
#[derive(Clone, Debug, Default)]
pub struct Scrub {
    redactor: fleet_core::Redactor,
    secret: String,
}

impl Scrub {
    /// A scrubber for `secret`. A secret [`fleet_core::Redactor`] ignores scrubs nothing.
    #[must_use]
    pub fn new(secret: Option<&str>) -> Self {
        let redactor = fleet_core::Redactor::new(secret.map(str::to_owned));
        let secret = if redactor.is_empty() {
            String::new()
        } else {
            secret.unwrap_or_default().to_owned()
        };
        Self { redactor, secret }
    }

    fn of(config: &Config) -> Self {
        let bearer = config.bearer();
        Self::new(bearer.strip_prefix("Bearer "))
    }

    pub(crate) fn redactor(&self) -> &fleet_core::Redactor {
        &self.redactor
    }

    /// Redacts, strips, redacts and strips `text` with no length cap, keeping newline and tab.
    #[must_use]
    pub fn text(&self, text: &str) -> String {
        scrub(&self.redactor, text)
    }

    /// Scrubs `text` and strips newline and tab too, for a field printed whole on one line.
    #[must_use]
    pub fn ident(&self, text: &str) -> String {
        sanitize(&self.text(text))
    }

    /// Scrubs free-form `text` and cuts it to 200 characters.
    #[must_use]
    pub fn free(&self, text: &str) -> String {
        sanitize_free(&self.text(text))
    }

    /// Starts scrubbing one stream that arrives in pieces.
    #[must_use]
    pub fn stream(&self) -> ScrubStream<'_> {
        ScrubStream {
            scrub: self,
            tail: String::new(),
        }
    }

    fn held_len(&self, text: &str) -> usize {
        self.secret
            .char_indices()
            .skip(1)
            .map(|(at, _)| at)
            .filter(|at| text.ends_with(&self.secret[..*at]))
            .max()
            .unwrap_or(0)
    }
}

/// Scrubs a stream piece by piece. A suffix that could start the token is held back until the
/// next piece or [`ScrubStream::finish`], so a token split across pieces is still redacted.
#[derive(Debug)]
pub struct ScrubStream<'a> {
    scrub: &'a Scrub,
    tail: String,
}

impl ScrubStream<'_> {
    /// Adds `text` and returns the part that is safe to print.
    ///
    /// Strips `text` before it redacts, so a secret that holds a hostile character is not
    /// matched here. A bearer token cannot hold one.
    pub fn push(&mut self, text: &str) -> String {
        let mut whole = std::mem::take(&mut self.tail);
        whole.push_str(&strip_lines(text));
        let hold = self.scrub.held_len(&whole);
        let split = whole.len() - hold;
        let (ready, kept) = whole.split_at(split);
        let redactor = &self.scrub.redactor;
        let ready_clean = redactor.redact_str(ready);
        let all = redactor.redact_str(&whole);
        if format!("{ready_clean}{kept}") == all {
            kept.clone_into(&mut self.tail);
            return strip_lines(&ready_clean);
        }
        let all = all.into_owned();
        let end = all
            .rfind(fleet_core::PLACEHOLDER)
            .map_or(0, |at| at + fleet_core::PLACEHOLDER.len());
        all[end..].clone_into(&mut self.tail);
        strip_lines(&all[..end])
    }

    /// Ends a stream the caller cut short. A held suffix that could start the token is dropped,
    /// because the rest of the token may have been cut off with the stream.
    pub fn finish_cut(&mut self) -> String {
        let tail = std::mem::take(&mut self.tail);
        let hold = self.scrub.held_len(&tail);
        self.scrub.text(&tail[..tail.len() - hold])
    }

    /// Returns the held text, scrubbed.
    pub fn finish(&mut self) -> String {
        let tail = std::mem::take(&mut self.tail);
        self.scrub.text(&tail)
    }
}

/// Strips hostile characters from server text. The text is not shortened.
pub fn sanitize(text: &str) -> String {
    sanitise_text(
        &fleet_core::Redactor::new(None::<String>),
        text,
        Cap::Bytes(usize::MAX),
    )
    .text
}

/// Strips hostile characters from free-form server text and cuts it to 200 characters,
/// ending with an ellipsis when it was cut.
pub fn sanitize_free(text: &str) -> String {
    let clean = sanitise_text(
        &fleet_core::Redactor::new(None::<String>),
        text,
        Cap::Chars(MAX_SERVER_TEXT),
    );
    let mut text = clean.text;
    if clean.cut {
        text.push(ELLIPSIS);
    }
    text
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Usage(m) | Self::Apply(m) => write!(f, "{m}"),
            Self::Connect(m) => write!(f, "cannot connect: {m}"),
            Self::Rpc(s) => write!(
                f,
                "server error {:?}: {}",
                s.code(),
                sanitize_free(s.message())
            ),
            Self::Io(e) => write!(f, "{e}"),
            Self::JobEnded(state) => write!(f, "job ended {state}"),
            Self::NoTimingReport => write!(f, "no timing report for this job"),
            Self::Credential(notice) => f.write_str(notice.text()),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ConfigError> for CliError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<Status> for CliError {
    fn from(e: Status) -> Self {
        Self::Rpc(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

type Client = FleetJobsClient<InterceptedService<Channel, Bearer>>;
type QueryClient = FleetQueryClient<InterceptedService<Channel, Bearer>>;

struct Session {
    jobs: Client,
    query: QueryClient,
    profiles: profile::ProfilesClient,
    batches: batch::BatchesClient,
    credentials: credential::CredentialsClient,
    repos: repo::ReposClient,
    work: work::WorkClient,
    retro: retro::RetroClient,
    edit: edit::EditClient,
    environments: env::EnvironmentsClient,
    scrub: Scrub,
}

/// Adds the bearer token to every request.
#[derive(Clone)]
pub struct Bearer(MetadataValue<tonic::metadata::Ascii>);

impl tonic::service::Interceptor for Bearer {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("authorization", self.0.clone());
        Ok(request)
    }
}

async fn open_channel(config: &Config, timeouts: bool) -> Result<Channel, CliError> {
    let mut endpoint = Endpoint::from_shared(config.server.clone())
        .map_err(|e| CliError::Connect(e.to_string()))?;
    if timeouts {
        endpoint = endpoint
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true);
    }
    if config.uses_tls() {
        let mut tls = ClientTlsConfig::new().with_webpki_roots();
        if let Some(path) = &config.ca_cert {
            let pem = std::fs::read(path)
                .map_err(|e| CliError::Connect(format!("{}: {e}", path.display())))?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| CliError::Connect(e.to_string()))?;
    }
    endpoint
        .connect()
        .await
        .map_err(|e| CliError::Connect(e.to_string()))
}

fn bearer(config: &Config) -> Result<Bearer, CliError> {
    let mut value = MetadataValue::try_from(config.bearer())
        .map_err(|_| CliError::Usage("token has invalid characters".into()))?;
    value.set_sensitive(true);
    Ok(Bearer(value))
}

/// The wire value of the submit environment choice: `-` for `--no-env`, the checked name for
/// `--env`, and empty when neither flag is given.
fn environment_field(name: Option<&str>, no_env: bool) -> Result<String, CliError> {
    if no_env {
        return Ok(fleet_proto::ENV_NONE.to_owned());
    }
    name.map_or_else(
        || Ok(String::new()),
        |raw| {
            EnvironmentName::new(raw)
                .map(|checked| checked.as_str().to_owned())
                .map_err(|err| CliError::Usage(err.to_string()))
        },
    )
}

fn parse_state(name: &str) -> Result<JobState, CliError> {
    let full = format!("JOB_STATE_{}", name.to_ascii_uppercase());
    JobState::from_str_name(&full)
        .filter(|s| *s != JobState::Unspecified)
        .ok_or_else(|| CliError::Usage(format!("unknown state {}", sanitize(name))))
}

fn state_name(job: &Job) -> &'static str {
    match JobState::try_from(job.state) {
        Ok(JobState::Unspecified) | Err(_) => "UNKNOWN",
        Ok(JobState::Queued) => "QUEUED",
        Ok(JobState::Running) => "RUNNING",
        Ok(JobState::Succeeded) => "SUCCEEDED",
        Ok(JobState::Failed) => "FAILED",
        Ok(JobState::Cancelled) => "CANCELLED",
        Ok(JobState::Lost) => "LOST",
    }
}

fn or_dash<T: fmt::Display>(value: Option<&T>) -> String {
    value.map_or_else(|| "-".into(), |v| sanitize(&v.to_string()))
}

fn ident_or_dash(scrub: &Scrub, value: Option<&String>) -> String {
    value.map_or_else(|| "-".into(), |v| scrub.ident(v))
}

fn free_or_dash(scrub: &Scrub, value: Option<&String>) -> String {
    value.map_or_else(|| "-".into(), |v| scrub.free(v))
}

fn require_success(job: &Job) -> Result<(), CliError> {
    if JobState::try_from(job.state) == Ok(JobState::Succeeded) {
        Ok(())
    } else {
        Err(CliError::JobEnded(state_name(job)))
    }
}

fn write_status(out: &mut impl Write, scrub: &Scrub, job: &Job) -> std::io::Result<()> {
    writeln!(out, "id: {}", scrub.ident(&job.job_id))?;
    writeln!(out, "state: {}", state_name(job))?;
    writeln!(out, "phase: {}", scrub.ident(&job.phase))?;
    writeln!(out, "branch: {}", ident_or_dash(scrub, job.branch.as_ref()))?;
    writeln!(out, "pr_url: {}", ident_or_dash(scrub, job.pr_url.as_ref()))?;
    writeln!(out, "exit_code: {}", or_dash(job.exit_code.as_ref()))?;
    writeln!(out, "error: {}", free_or_dash(scrub, job.error.as_ref()))?;
    if let Some(summary) = &job.summary {
        telemetry::write_summary(out, scrub, summary)?;
    }
    Ok(())
}

fn read_prompt(prompt: String, stdin: &mut impl Read) -> Result<String, CliError> {
    let text = if prompt == "-" {
        let mut buf = String::new();
        stdin.read_to_string(&mut buf)?;
        buf
    } else {
        prompt
    };
    if text.trim().is_empty() {
        return Err(CliError::Usage("prompt is empty".into()));
    }
    Ok(text)
}

struct Resolved {
    config: Config,
    scrub: Scrub,
}

/// The outcome of resolving the flags and the variable lookup once per run. Every command and
/// the error scrubber share it, so the token is read once.
type Resolution = Result<Resolved, ConfigError>;

fn resolve(
    server: Option<String>,
    insecure: bool,
    lookup: impl Fn(&str) -> Option<String>,
) -> Resolution {
    Config::from_lookup(server, insecure, lookup).map(|config| {
        let scrub = Scrub::of(&config);
        Resolved { config, scrub }
    })
}

async fn session(env: &Resolution, timeouts: bool) -> Result<Session, CliError> {
    let resolved = env.as_ref().map_err(Clone::clone)?;
    let config = &resolved.config;
    if let Some(warning) = config.token_warning() {
        let _ = writeln!(std::io::stderr(), "fleet: warning: {warning}");
    }
    let channel = open_channel(config, timeouts).await?;
    let token = bearer(config)?;
    Ok(Session {
        scrub: resolved.scrub.clone(),
        jobs: FleetJobsClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        query: FleetQueryClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        profiles: FleetProfilesClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES),
        batches: FleetBatchesClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        credentials: FleetCredentialsClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        repos: FleetReposClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        work: FleetWorkClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        retro: FleetRetroClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        edit: FleetEditClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        environments: FleetEnvironmentsClient::with_interceptor(channel, token)
            .max_decoding_message_size(MAX_DECODE_BYTES),
    })
}

async fn cancel(
    mut client: Client,
    scrub: &Scrub,
    id: String,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let job = client
        .cancel_job(CancelJobRequest { job_id: id })
        .await?
        .into_inner();
    writeln!(out, "{}\t{}", scrub.ident(&job.job_id), state_name(&job))?;
    Ok(())
}

async fn list_jobs(
    client: &mut Client,
    scrub: &Scrub,
    state: Option<JobState>,
    limit: u32,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .list_jobs(ListJobsRequest {
            state: state.map(|s| s as i32),
            limit,
        })
        .await?
        .into_inner();
    for job in &reply.jobs {
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            scrub.ident(&job.job_id),
            state_name(job),
            scrub.ident(&job.repo),
            scrub.ident(&job.phase)
        )?;
    }
    if usize::try_from(limit).is_ok_and(|n| n == reply.jobs.len()) {
        writeln!(
            out,
            "-- showing {limit} jobs, the limit; raise --limit to see more --"
        )?;
    }
    Ok(())
}

async fn run_batch(
    action: BatchAction,
    env: &Resolution,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match action {
        BatchAction::Submit {
            prompt,
            repo,
            base,
            profiles,
            idempotency_key,
            agent,
        } => {
            let request = batch::prepare(
                batch::Submit {
                    prompt,
                    repo,
                    base,
                    profiles,
                    idempotency_key,
                    agent: agent.unwrap_or_default(),
                },
                stdin,
            )?;
            let mut session = session(env, timeouts).await?;
            batch::submit(&mut session.batches, &session.scrub, request, out).await
        }
        BatchAction::Show { id } => {
            let mut session = session(env, timeouts).await?;
            batch::show(
                &mut session.batches,
                &mut session.jobs,
                &session.scrub,
                id,
                out,
            )
            .await
        }
    }
}

async fn run_credential(
    action: credential::CredentialAction,
    env: &Resolution,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    credential::no_stray(action.rest())?;
    match action {
        credential::CredentialAction::List { host, .. } => {
            let only = host.as_deref().map(credential::parse_host).transpose()?;
            let mut session = session(env, timeouts).await?;
            credential::list(&mut session.credentials, &session.scrub, only.as_ref(), out).await
        }
        credential::CredentialAction::Put { kind, host, .. } => {
            let kind = credential::parse_kind(&kind)?;
            let host = credential::put_host(kind, host.as_deref())?;
            let value = credential::read_secret(stdin)?;
            let mut session = session(env, timeouts).await?;
            credential::put(
                &mut session.credentials,
                &session.scrub,
                kind,
                &host,
                value,
                out,
            )
            .await
        }
        credential::CredentialAction::Delete { id, host, .. } => {
            let id = credential::parse_id(&id)?;
            let host = host.as_deref().map(credential::parse_host).transpose()?;
            let mut session = session(env, timeouts).await?;
            credential::delete(&mut session.credentials, id, host.as_ref(), out).await
        }
        credential::CredentialAction::Verify { id, .. } => {
            let id = credential::parse_id(&id)?;
            let mut session = session(env, timeouts).await?;
            credential::verify(&mut session.credentials, &session.scrub, id, out).await
        }
    }
}

async fn run_env(
    action: env::EnvAction,
    env: &Resolution,
    timeouts: bool,
    tty: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let call = action.prepare(stdin, tty)?;
    let mut session = session(env, timeouts).await?;
    env::execute(call, &mut session.environments, &session.scrub, out).await
}

async fn run_repo(
    action: repo::RepoAction,
    env: &Resolution,
    timeouts: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    repo::no_stray(action.rest())?;
    match action {
        repo::RepoAction::List { .. } => {
            let mut session = session(env, timeouts).await?;
            repo::list(&mut session.repos, &session.scrub, out).await
        }
        repo::RepoAction::Add { repo: text, .. } => {
            let parsed = repo::parse_ref(&text)?;
            let mut session = session(env, timeouts).await?;
            repo::add(&mut session.repos, &session.scrub, &parsed, out).await
        }
        repo::RepoAction::Remove { repo: text, .. } => {
            let (host, path) = repo::locate_ref(&text)?;
            let mut session = session(env, timeouts).await?;
            repo::remove(&mut session.repos, host, path, out).await
        }
    }
}

async fn run_work(
    args: work::WorkArgs,
    env: &Resolution,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let call = args.prepare(stdin)?;
    let mut session = session(env, timeouts).await?;
    work::execute(call, &mut session.work, &session.scrub, out).await
}

async fn run_family(
    command: Command,
    env: &Resolution,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let call = match command {
        Command::Retro(args) => args.prepare()?,
        Command::Improvement(args) => args.prepare()?,
        Command::Pitfall(args) => args.prepare()?,
        Command::Edit(args) => {
            let call = args.prepare(stdin)?;
            let mut session = session(env, timeouts).await?;
            return edit::execute(call, &mut session.edit, &session.scrub, out).await;
        }
        _ => return Ok(()),
    };
    let mut session = session(env, timeouts).await?;
    retro::execute(call, &mut session.retro, &session.scrub, out).await
}

async fn run_profile(
    action: ProfileAction,
    env: &Resolution,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match action {
        ProfileAction::Create { name, file } => {
            let content = profile::read_source(&file, stdin)?;
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::create(&mut client, &session.scrub, name, content, out).await
        }
        ProfileAction::List => {
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::list(&mut client, &session.scrub, out).await
        }
        ProfileAction::Show { target } => {
            let (name, version) = profile::split_target(&target)?;
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::show(&mut client, &session.scrub, name.to_owned(), version, out).await
        }
        ProfileAction::Share { name } => {
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::set_shared(&mut client, &session.scrub, name, true, out).await
        }
        ProfileAction::Unshare { name } => {
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::set_shared(&mut client, &session.scrub, name, false, out).await
        }
        ProfileAction::Item {
            profile: name,
            kind: _,
            id,
            state,
        } => {
            let id = profile::item_id(&id)?;
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::edit(
                &mut client,
                &session.scrub,
                name,
                |content| profile::set_item(content, &id, state == "on"),
                out,
            )
            .await
        }
        ProfileAction::Prompt {
            profile: name,
            file,
        } => {
            let text = profile::read_prompt(&file, stdin)?;
            let session = session(env, timeouts).await?;
            let mut client = session.profiles;
            profile::edit(
                &mut client,
                &session.scrub,
                name,
                |content| profile::set_prompt(content, text.clone()),
                out,
            )
            .await
        }
    }
}

/// Runs a parsed command, reading a `-` prompt from `stdin` and writing results to `out`.
///
/// # Errors
/// Returns [`CliError`] on bad configuration, connection failure, a server error status
/// or an input or output failure.
pub async fn run(
    cli: Cli,
    lookup: impl Fn(&str) -> Option<String>,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    run_with(cli, lookup, true, stdin, out).await
}

async fn run_timing(
    job: &str,
    commands: bool,
    follow: Option<String>,
    json: bool,
    env: &Resolution,
    timeouts: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    if let Some(c) = &follow {
        timing::check_command_id(c)?;
    }
    let session = session(env, timeouts).await?;
    let scrub = session.scrub;
    let mut client = session.jobs;
    match follow {
        Some(c) => timing::follow(&mut client, job, &c, json, &scrub, out).await,
        None if commands => {
            timing::list_commands(&mut client, scrub.redactor(), job, json, out).await
        }
        None => timing::show(&mut client, scrub.redactor(), job, json, out).await,
    }
}

/// Like [`run`], with request timeouts and keepalive pings switched by `timeouts`.
///
/// Test seam for paused-time tests over real sockets. Not part of the stable interface.
///
/// # Errors
/// Returns [`CliError`] on the same conditions as [`run`].
#[doc(hidden)]
pub async fn run_with(
    cli: Cli,
    lookup: impl Fn(&str) -> Option<String>,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    run_with_color(cli, lookup, timeouts, false, stdin, out).await
}

/// Whether output may carry color: `tty` says stdout is a terminal and `no_color` is the value
/// of `NO_COLOR`. Only the binary reads the environment, the renderer takes the result.
#[must_use]
pub fn color_wanted(tty: bool, no_color: Option<&str>) -> bool {
    tty && no_color.is_none_or(str::is_empty)
}

/// Like [`run_with`], with color in the readable `logs` view switched by `color`.
///
/// Test seam and the binary's entry point. Not part of the stable interface.
///
/// # Errors
/// Returns [`CliError`] on the same conditions as [`run`].
#[doc(hidden)]
pub async fn run_with_color(
    cli: Cli,
    lookup: impl Fn(&str) -> Option<String>,
    timeouts: bool,
    color: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    run_with_tty(cli, lookup, timeouts, color, false, stdin, out).await
}

/// Like [`run_with_color`], with `tty` saying whether `stdin` is a terminal.
///
/// Test seam and the binary's entry point. A terminal on stdin needs an explicit `-` for
/// `env secret put`. Not part of the stable interface.
///
/// # Errors
/// Returns [`CliError`] on the same conditions as [`run`].
#[doc(hidden)]
pub async fn run_with_tty(
    cli: Cli,
    lookup: impl Fn(&str) -> Option<String>,
    timeouts: bool,
    color: bool,
    tty: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let Cli {
        server,
        insecure,
        command,
    } = cli;
    let env = resolve(server, insecure, lookup);
    Box::pin(dispatch(command, &env, timeouts, color, tty, stdin, out))
        .await
        .map_err(|e| e.scrubbed(env.as_ref().ok().map(|resolved| &resolved.scrub)))
}

async fn run_logs(
    env: &Resolution,
    timeouts: bool,
    color: bool,
    (id, follow, raw): (String, bool, bool),
    out: &mut impl Write,
) -> Result<(), CliError> {
    let session = session(env, timeouts).await?;
    let view = logs::View::new(raw, color);
    logs::logs(&session.jobs, &session.scrub, id, follow, view, out).await
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per command; each arm only routes to its module"
)]
async fn dispatch(
    command: Command,
    env: &Resolution,
    timeouts: bool,
    color: bool,
    tty: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match command {
        Command::List => {
            let mut session = session(env, timeouts).await?;
            list::list(&mut session, out).await?;
        }
        Command::Watch { id } => {
            let mut session = session(env, timeouts).await?;
            watch::watch(&mut session.jobs, &session.scrub, &id, out).await?;
        }
        Command::Submit {
            repo,
            base,
            no_pr,
            idempotency_key,
            agent,
            env: environment,
            no_env,
            prompt,
        } => {
            let environment = environment_field(environment.as_deref(), no_env)?;
            let prompt = read_prompt(prompt, stdin)?;
            let session = session(env, timeouts).await?;
            let scrub = session.scrub;
            let mut client = session.jobs;
            let job = client
                .submit_job(SubmitJobRequest {
                    idempotency_key: idempotency_key.unwrap_or_else(batch::fresh_key),
                    prompt,
                    repo,
                    base_ref: base,
                    open_pr: !no_pr,
                    agent: agent.unwrap_or_default(),
                    profile: String::new(),
                    environment,
                })
                .await?
                .into_inner();
            writeln!(out, "{}", scrub.ident(&job.job_id))?;
        }
        Command::Jobs { state, limit } => {
            let state = state.as_deref().map(parse_state).transpose()?;
            let session = session(env, timeouts).await?;
            let scrub = session.scrub;
            let mut client = session.jobs;
            list_jobs(&mut client, &scrub, state, limit, out).await?;
        }
        Command::Status { id, tools } => {
            let session = session(env, timeouts).await?;
            let scrub = session.scrub;
            let mut client = session.jobs;
            let job = client
                .get_job(GetJobRequest { job_id: id.clone() })
                .await?
                .into_inner();
            write_status(out, &scrub, &job)?;
            if tools {
                telemetry::write_tools(&mut client, &scrub, &id, out).await?;
            }
        }
        Command::Logs { id, follow, raw } => {
            run_logs(env, timeouts, color, (id, follow, raw), out).await?;
        }
        Command::Stats {
            since,
            repo,
            box_name,
            by,
        } => {
            let since = stats::parse_since(&since, stats::now_seconds())?;
            let session = session(env, timeouts).await?;
            let mut client = session.jobs;
            stats::stats(&mut client, &session.scrub, since, repo, box_name, by, out).await?;
        }
        Command::Timing {
            job,
            commands,
            follow,
            json,
        } => {
            run_timing(&job, commands, follow, json, env, timeouts, out).await?;
        }
        Command::Catalog { action } => {
            Box::pin(catalog::run(action, env, timeouts, stdin, out)).await?;
        }
        Command::UserCap { area } => {
            Box::pin(catalog::run_user(area, env, timeouts, out)).await?;
        }
        Command::Batch { action } => {
            run_batch(action, env, timeouts, stdin, out).await?;
        }
        Command::Profile { action } => {
            run_profile(action, env, timeouts, stdin, out).await?;
        }
        Command::Credential { action } => run_credential(action, env, timeouts, stdin, out).await?,
        Command::Env { action } => run_env(action, env, timeouts, tty, stdin, out).await?,
        Command::Repo { action } => run_repo(action, env, timeouts, out).await?,
        Command::Work(args) => run_work(args, env, timeouts, stdin, out).await?,
        family @ (Command::Retro(_)
        | Command::Improvement(_)
        | Command::Pitfall(_)
        | Command::Edit(_)) => run_family(family, env, timeouts, stdin, out).await?,
        Command::Cancel { id } => {
            let session = session(env, timeouts).await?;
            cancel(session.jobs, &session.scrub, id, out).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fleet_core::text::is_hostile;

    #[test]
    fn sanitize_routes_through_the_core_predicate() {
        for cp in 0..=0x0010_FFFF_u32 {
            if let Some(c) = char::from_u32(cp) {
                assert_eq!(
                    sanitize(&c.to_string()).is_empty(),
                    is_hostile(c),
                    "U+{cp:04X}"
                );
                assert_eq!(
                    Scrub::new(None).text(&c.to_string()).is_empty(),
                    is_hostile(c) && c != '\n' && c != '\t',
                    "U+{cp:04X}"
                );
            }
        }
    }

    #[test]
    fn every_printing_path_strips_the_whole_tag_block() {
        let scrub = Scrub::new(None);
        for cp in 0xE0000..=0xE007F_u32 {
            let c = char::from_u32(cp).expect("tag block is valid");
            let input = format!("a{c}b");
            assert_eq!(sanitize(&input), "ab", "U+{cp:04X}");
            assert_eq!(sanitize_free(&input), "ab", "U+{cp:04X}");
            assert_eq!(scrub.text(&input), "ab", "U+{cp:04X}");
            assert_eq!(scrub.ident(&input), "ab", "U+{cp:04X}");
            assert_eq!(scrub.free(&input), "ab", "U+{cp:04X}");
            let mut stream = scrub.stream();
            let shown = stream.push(&input) + &stream.finish();
            assert_eq!(shown, "ab", "U+{cp:04X}");
        }
        assert_eq!(sanitize("a\u{E0080}b"), "a\u{E0080}b");
    }

    #[test]
    fn scrub_redacts_a_secret_that_holds_a_stripped_character() {
        for secret in [
            "line-one-aaaa\r\nline-two-bbbb",
            "zero-\u{200B}width-secret-1",
        ] {
            let redactor = fleet_core::Redactor::new([secret]);
            assert_eq!(scrub(&redactor, &format!("x {secret} y")), "x [REDACTED] y");
        }
    }

    #[test]
    fn each_printed_field_has_an_exact_hostile_output() {
        const HOSTILE: &str = "a\u{E0041}\u{202E}\u{85}\u{2028}\r\n\tb\u{1b}[31m";
        let scrub = Scrub::new(Some(TOKEN));
        let input = format!("{HOSTILE}{TOKEN}z");
        let lines = "a\n\tb[31m[REDACTED]z";
        let flat = "ab[31m[REDACTED]z";
        assert_eq!(scrub.ident(&input), flat, "box name");
        assert_eq!(scrub.ident(&input), flat, "job id, repo, phase");
        assert_eq!(scrub.free(&input), flat, "job text and error text");
        assert_eq!(scrub.text(&input), lines, "log text");
        let mut stream = scrub.stream();
        let streamed = stream.push(&input) + &stream.finish();
        assert_eq!(streamed, lines, "streamed log text");
        assert_eq!(sanitize(&input), format!("ab[31m{TOKEN}z"), "usage name");
        let rpc = CliError::Rpc(Status::new(tonic::Code::Internal, input.clone()));
        assert_eq!(
            rpc.to_string(),
            format!("server error Internal: ab[31m{TOKEN}z"),
            "unscrubbed rpc error"
        );
        let scrubbed =
            CliError::Rpc(Status::new(tonic::Code::Internal, input)).scrubbed(Some(&scrub));
        assert_eq!(
            scrubbed.to_string(),
            "server error Internal: a\n\tb[31m[REDACTED]z".replace("a\n\tb", "ab"),
            "scrubbed rpc error"
        );
    }

    use super::*;

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize("a\u{1b}[31mb\nc\u{7}"), "a[31mbc");
    }

    #[test]
    fn sanitize_drops_bidi_and_invisible_formatting_characters() {
        for c in [
            '\u{200B}',
            '\u{200F}',
            '\u{202A}',
            '\u{202E}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{0600}',
            '\u{0605}',
            '\u{061C}',
            '\u{06DD}',
            '\u{070F}',
            '\u{180E}',
            '\u{206A}',
            '\u{206F}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
        ] {
            assert_eq!(sanitize(&format!("a{c}b")), "ab", "{c:?}");
        }
        assert_eq!(sanitize("a\u{2065}b\u{200A}c"), "a\u{2065}b\u{200A}c");
    }

    #[test]
    fn request_timeout_exceeds_the_server_timeout() {
        const { assert!(REQUEST_TIMEOUT.as_secs() > 30) };
    }

    #[test]
    fn sanitize_leaves_long_text_whole() {
        assert_eq!(sanitize(&"x".repeat(500)).chars().count(), 500);
    }

    #[test]
    fn sanitize_free_cuts_long_text_with_an_ellipsis() {
        let cut = sanitize_free(&"x".repeat(500));
        assert_eq!(cut.chars().count(), 201);
        assert!(cut.ends_with(ELLIPSIS));
        assert_eq!(sanitize_free(&"x".repeat(200)), "x".repeat(200));
    }

    fn failed_job() -> Job {
        Job {
            job_id: "j".into(),
            state: JobState::Failed as i32,
            branch: Some("b".repeat(300)),
            pr_url: Some(format!("https://example.com/{}", "p".repeat(300))),
            error: Some(format!("{}\u{202E}tail", "e".repeat(300))),
            ..Job::default()
        }
    }

    #[test]
    fn status_cuts_free_form_error_and_keeps_ids_and_urls_whole() -> Result<(), std::io::Error> {
        let mut out = Vec::new();
        write_status(&mut out, &Scrub::default(), &failed_job())?;
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(
            text.contains(&format!("branch: {}\n", "b".repeat(300))),
            "{text}"
        );
        assert!(text.contains(&"p".repeat(300)), "{text}");
        assert!(
            text.contains(&format!("error: {}\u{2026}\n", "e".repeat(200))),
            "{text}"
        );
        assert!(!text.contains('\u{202E}'), "{text:?}");
        Ok(())
    }

    #[test]
    fn require_success_accepts_only_succeeded() {
        let job = |state: JobState| Job {
            state: state as i32,
            ..Job::default()
        };
        assert!(require_success(&job(JobState::Succeeded)).is_ok());
        assert!(require_success(&job(JobState::Failed)).is_err());
    }

    #[test]
    fn exit_codes_split_usage_from_runtime() {
        assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
        assert_eq!(CliError::Config(ConfigError::InsecureHttp).exit_code(), 2);
        assert_eq!(CliError::Connect("x".into()).exit_code(), 1);
        assert_eq!(CliError::Rpc(Status::internal("x")).exit_code(), 1);
        assert_eq!(CliError::Io(std::io::Error::other("x")).exit_code(), 1);
        assert_eq!(CliError::NoTimingReport.exit_code(), 3);
    }

    #[test]
    fn parse_state_maps_every_named_state_and_rejects_the_rest() {
        for (name, state) in [
            ("queued", JobState::Queued),
            ("RUNNING", JobState::Running),
            ("Succeeded", JobState::Succeeded),
            ("failed", JobState::Failed),
            ("cancelled", JobState::Cancelled),
            ("lost", JobState::Lost),
        ] {
            assert_eq!(parse_state(name).ok(), Some(state), "{name}");
        }
        assert!(parse_state("unspecified").is_err());
        assert!(parse_state("bogus").is_err());
    }

    const TOKEN: &str = "client-token-0123456789";

    #[test]
    fn status_error_is_scrubbed_of_the_token() -> Result<(), std::io::Error> {
        let job = Job {
            job_id: "j".into(),
            state: JobState::Failed as i32,
            error: Some(format!(
                "boom cli\u{200B}ent-token-\u{202E}0123456789 {TOKEN}"
            )),
            ..Job::default()
        };
        let mut out = Vec::new();
        write_status(&mut out, &Scrub::new(Some(TOKEN)), &job)?;
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(
            text.contains("error: boom [REDACTED] [REDACTED]\n"),
            "{text:?}"
        );
        Ok(())
    }

    #[test]
    fn rpc_status_message_in_error_display_is_scrubbed() {
        let error = CliError::Rpc(Status::internal(format!("bad {TOKEN} x")))
            .scrubbed(Some(&Scrub::new(Some(TOKEN))));
        let shown = error.to_string();
        assert!(!shown.contains(TOKEN), "{shown}");
        assert!(shown.contains("[REDACTED]"), "{shown}");
        assert!(matches!(error, CliError::Rpc(s) if s.code() == tonic::Code::Internal));
    }

    #[test]
    fn scrub_stream_redacts_a_token_split_across_pieces() {
        let scrub = Scrub::new(Some(TOKEN));
        let mut stream = scrub.stream();
        let mut out = String::new();
        for piece in ["ab client-tok", "en-0123", "456789 cd"] {
            out.push_str(&stream.push(piece));
        }
        out.push_str(&stream.finish());
        assert_eq!(out, "ab [REDACTED] cd");
    }

    #[test]
    fn scrub_stream_splits_with_hostile_characters_inside() {
        let scrub = Scrub::new(Some(TOKEN));
        let mut stream = scrub.stream();
        let mut out = String::new();
        for piece in [
            "x client-\u{200B}to",
            "\u{202E}ken-01\u{FEFF}2345",
            "6789\u{2028}y",
        ] {
            out.push_str(&stream.push(piece));
        }
        out.push_str(&stream.finish());
        assert_eq!(out, "x [REDACTED]y");
    }

    #[test]
    fn scrub_stream_releases_a_held_prefix_that_never_completes() {
        let scrub = Scrub::new(Some(TOKEN));
        let mut stream = scrub.stream();
        assert_eq!(stream.push("end client-to"), "end ");
        assert_eq!(stream.push("xyz"), "client-toxyz");
        assert_eq!(stream.push("tail client-tok"), "tail ");
        assert_eq!(stream.finish(), "client-tok");
    }

    #[test]
    fn scrub_without_a_usable_secret_only_strips() {
        let scrub = Scrub::new(Some("short"));
        let mut stream = scrub.stream();
        assert_eq!(stream.push("a\u{200B}b short"), "ab short");
        assert_eq!(stream.finish(), "");
        assert_eq!(Scrub::default().text("p\u{202E}q"), "pq");
    }

    use fleet_proto::v1::JobSummary;

    fn laden_job() -> Job {
        let laden = |field: &str| format!("{field}-{TOKEN}");
        Job {
            job_id: laden("id"),
            state: JobState::Failed as i32,
            phase: laden("phase"),
            branch: Some(laden("branch")),
            pr_url: Some(format!("https://{TOKEN}@host.example/pr/1")),
            ..Job::default()
        }
    }

    fn status_of(job: &Job) -> String {
        let mut out = Vec::new();
        write_status(&mut out, &Scrub::new(Some(TOKEN)), job).expect("write to a Vec");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn status_job_id_is_scrubbed_of_the_token() {
        assert!(status_of(&laden_job()).contains("id: id-[REDACTED]\n"));
    }

    #[test]
    fn status_phase_is_scrubbed_of_the_token() {
        assert!(status_of(&laden_job()).contains("phase: phase-[REDACTED]\n"));
    }

    #[test]
    fn status_branch_is_scrubbed_of_the_token() {
        assert!(status_of(&laden_job()).contains("branch: branch-[REDACTED]\n"));
    }

    #[test]
    fn status_pr_url_userinfo_is_scrubbed_of_the_token() {
        let text = status_of(&laden_job());
        assert!(
            text.contains("pr_url: https://[REDACTED]@host.example/pr/1\n"),
            "{text}"
        );
        assert!(!text.contains("client-token"), "{text}");
    }

    fn summary_text(summary: JobSummary) -> String {
        let job = Job {
            summary: Some(summary),
            ..Job::default()
        };
        status_of(&job)
    }

    fn laden_summary(set: impl FnOnce(&mut JobSummary, String)) -> JobSummary {
        let mut summary = JobSummary::default();
        set(&mut summary, format!("v-{TOKEN}"));
        summary
    }

    #[test]
    fn summary_stop_reason_is_scrubbed_of_the_token() {
        let text = summary_text(laden_summary(|s, v| s.stop_reason = Some(v)));
        assert!(text.contains("stop_reason: v-[REDACTED]\n"), "{text}");
    }

    #[test]
    fn summary_stuck_rule_is_scrubbed_of_the_token() {
        let text = summary_text(laden_summary(|s, v| s.stuck_rule = Some(v)));
        assert!(text.contains("stuck (shadow): v-[REDACTED] at"), "{text}");
    }

    #[test]
    fn summary_missing_names_are_scrubbed_of_the_token() {
        let text = summary_text(laden_summary(|s, v| s.missing = vec![v]));
        assert!(text.contains("(missing: v-[REDACTED])"), "{text}");
    }

    #[test]
    fn summary_model_is_scrubbed_of_the_token() {
        let text = summary_text(laden_summary(|s, v| s.model = Some(v)));
        assert!(text.contains("model: v-[REDACTED]\n"), "{text}");
    }

    #[test]
    fn summary_claude_version_is_scrubbed_of_the_token() {
        let text = summary_text(laden_summary(|s, v| s.claude_version = Some(v)));
        assert!(text.contains("claude_version: v-[REDACTED]\n"), "{text}");
    }

    #[test]
    fn summary_bundle_sha_is_scrubbed_of_the_token() {
        let text = summary_text(laden_summary(|s, v| s.bundle_sha = Some(v)));
        assert!(text.contains("bundle_sha: v-[REDACTED]\n"), "{text}");
    }

    #[test]
    fn ident_strips_newlines_and_redacts() {
        let scrub = Scrub::new(Some(TOKEN));
        assert_eq!(scrub.ident(&format!("a\nb{TOKEN}\tc")), "ab[REDACTED]c");
    }

    #[test]
    fn free_cut_at_200_does_not_leak_a_token_prefix() {
        let scrub = Scrub::new(Some(TOKEN));
        let text = format!("{}{TOKEN}", "x".repeat(197));
        let shown = scrub.free(&text);
        assert!(!shown.contains("cli"), "{shown}");
        assert_eq!(shown.chars().count(), 201);
    }

    #[test]
    fn rpc_display_cut_at_200_does_not_leak_a_token_prefix() {
        let status = Status::internal(format!("{}{TOKEN}", "x".repeat(197)));
        let shown = CliError::Rpc(status)
            .scrubbed(Some(&Scrub::new(Some(TOKEN))))
            .to_string();
        assert!(!shown.contains("cli"), "{shown}");
    }

    #[test]
    fn scrub_stream_push_collapses_a_token_the_holdback_overlaps() {
        let secret = "abababababab";
        let scrub = Scrub::new(Some(secret));
        let mut stream = scrub.stream();
        assert_eq!(stream.push(secret), "[REDACTED]");
        assert_eq!(stream.finish(), "");
        let mut stream = scrub.stream();
        let mut out = stream.push("x ababab");
        out.push_str(&stream.push("ababab y"));
        out.push_str(&stream.finish());
        assert_eq!(out, "x [REDACTED] y");
    }

    #[test]
    fn scrub_stream_finish_cut_drops_a_held_token_prefix() {
        let scrub = Scrub::new(Some(TOKEN));
        let mut stream = scrub.stream();
        assert_eq!(stream.push("end client-tok"), "end ");
        assert_eq!(stream.finish_cut(), "");
        let mut stream = scrub.stream();
        assert_eq!(stream.push("end client-tok"), "end ");
        assert_eq!(stream.finish(), "client-tok");
    }
}
