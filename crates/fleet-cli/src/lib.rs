//! The `fleet` command line client: job submission and inspection over gRPC.

pub mod config;
pub mod list;
pub mod logs;
pub mod telemetry;
pub mod watch;

use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;

use clap::{Parser, Subcommand};
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_query_client::FleetQueryClient;
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, ListJobsRequest, SubmitJobRequest,
};
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
    },
    /// Request cancellation of a job.
    Cancel {
        /// Job id.
        id: String,
    },
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
}

impl CliError {
    /// Process exit code: 2 for usage and configuration errors, 1 for everything else.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Usage(_) => 2,
            Self::Connect(_) | Self::Rpc(_) | Self::Io(_) | Self::JobEnded(_) => 1,
        }
    }
}

/// Inclusive code point ranges of the Unicode `Cf` (format) category, Unicode 16.0.0.
const FORMAT_RANGES: [(u32, u32); 21] = [
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether `c` must not reach the terminal: a control character, a code point of the
/// Unicode `Cf` category, or a line or paragraph separator.
pub(crate) fn is_hostile(c: char) -> bool {
    if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
        return true;
    }
    let cp = c as u32;
    FORMAT_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Strips hostile characters from server text. The text is not shortened.
pub fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !is_hostile(*c)).collect()
}

/// Strips hostile characters from free-form server text and cuts it to 200 characters,
/// ending with an ellipsis when it was cut.
pub fn sanitize_free(text: &str) -> String {
    let mut clean: String = text
        .chars()
        .filter(|c| !is_hostile(*c))
        .take(MAX_SERVER_TEXT + 1)
        .collect();
    if clean.chars().count() > MAX_SERVER_TEXT {
        clean = clean.chars().take(MAX_SERVER_TEXT).collect();
        clean.push(ELLIPSIS);
    }
    clean
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Usage(m) => write!(f, "{m}"),
            Self::Connect(m) => write!(f, "cannot connect: {m}"),
            Self::Rpc(s) => write!(
                f,
                "server error {:?}: {}",
                s.code(),
                sanitize_free(s.message())
            ),
            Self::Io(e) => write!(f, "{e}"),
            Self::JobEnded(state) => write!(f, "job ended {state}"),
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

fn free_or_dash(value: Option<&String>) -> String {
    value.map_or_else(|| "-".into(), |v| sanitize_free(v))
}

fn require_success(job: &Job) -> Result<(), CliError> {
    if JobState::try_from(job.state) == Ok(JobState::Succeeded) {
        Ok(())
    } else {
        Err(CliError::JobEnded(state_name(job)))
    }
}

fn write_status(out: &mut impl Write, job: &Job) -> std::io::Result<()> {
    writeln!(out, "id: {}", sanitize(&job.job_id))?;
    writeln!(out, "state: {}", state_name(job))?;
    writeln!(out, "phase: {}", sanitize(&job.phase))?;
    writeln!(out, "branch: {}", or_dash(job.branch.as_ref()))?;
    writeln!(out, "pr_url: {}", or_dash(job.pr_url.as_ref()))?;
    writeln!(out, "exit_code: {}", or_dash(job.exit_code.as_ref()))?;
    writeln!(out, "error: {}", free_or_dash(job.error.as_ref()))?;
    if let Some(summary) = &job.summary {
        telemetry::write_summary(out, summary)?;
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

async fn session(
    server: Option<String>,
    insecure: bool,
    lookup: impl Fn(&str) -> Option<String>,
    timeouts: bool,
) -> Result<Session, CliError> {
    let config = Config::from_lookup(server, insecure, lookup)?;
    if let Some(warning) = config.token_warning() {
        let _ = writeln!(std::io::stderr(), "fleet: warning: {warning}");
    }
    let channel = open_channel(&config, timeouts).await?;
    let token = bearer(&config)?;
    Ok(Session {
        jobs: FleetJobsClient::with_interceptor(channel.clone(), token.clone())
            .max_decoding_message_size(MAX_DECODE_BYTES),
        query: FleetQueryClient::with_interceptor(channel, token)
            .max_decoding_message_size(MAX_DECODE_BYTES),
    })
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
    let Cli {
        server,
        insecure,
        command,
    } = cli;
    match command {
        Command::List => {
            let mut session = session(server, insecure, lookup, timeouts).await?;
            list::list(&mut session, out).await?;
        }
        Command::Watch { id } => {
            let mut session = session(server, insecure, lookup, timeouts).await?;
            watch::watch(&mut session.jobs, &id, out).await?;
        }
        Command::Submit {
            repo,
            base,
            no_pr,
            idempotency_key,
            prompt,
        } => {
            let prompt = read_prompt(prompt, stdin)?;
            let mut client = session(server, insecure, lookup, timeouts).await?.jobs;
            let job = client
                .submit_job(SubmitJobRequest {
                    idempotency_key: idempotency_key.unwrap_or_default(),
                    prompt,
                    repo,
                    base_ref: base,
                    open_pr: !no_pr,
                })
                .await?
                .into_inner();
            writeln!(out, "{}", sanitize(&job.job_id))?;
        }
        Command::Jobs { state, limit } => {
            let state = state.as_deref().map(parse_state).transpose()?;
            let mut client = session(server, insecure, lookup, timeouts).await?.jobs;
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
                    sanitize(&job.job_id),
                    state_name(job),
                    sanitize(&job.repo),
                    sanitize(&job.phase)
                )?;
            }
            if usize::try_from(limit).is_ok_and(|n| n == reply.jobs.len()) {
                writeln!(
                    out,
                    "-- showing {limit} jobs, the limit; raise --limit to see more --"
                )?;
            }
        }
        Command::Status { id, tools } => {
            let mut client = session(server, insecure, lookup, timeouts).await?.jobs;
            let job = client
                .get_job(GetJobRequest { job_id: id.clone() })
                .await?
                .into_inner();
            write_status(out, &job)?;
            if tools {
                telemetry::write_tools(&mut client, &id, out).await?;
            }
        }
        Command::Logs { id, follow } => {
            let client = session(server, insecure, lookup, timeouts).await?.jobs;
            logs::logs(&client, id, follow, out).await?;
        }
        Command::Cancel { id } => {
            let mut client = session(server, insecure, lookup, timeouts).await?.jobs;
            let job = client
                .cancel_job(CancelJobRequest { job_id: id })
                .await?
                .into_inner();
            writeln!(out, "{}\t{}", sanitize(&job.job_id), state_name(&job))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    const ALL_FORMAT: [(u32, u32); 21] = [
        (0xAD, 0xAD),
        (0x600, 0x605),
        (0x61C, 0x61C),
        (0x6DD, 0x6DD),
        (0x70F, 0x70F),
        (0x890, 0x891),
        (0x8E2, 0x8E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];

    #[test]
    fn every_format_code_point_is_hostile() {
        let mut count = 0;
        for (lo, hi) in ALL_FORMAT {
            for cp in lo..=hi {
                let c = char::from_u32(cp).expect("scalar value");
                assert!(is_hostile(c), "U+{cp:04X} not hostile");
                count += 1;
            }
        }
        assert_eq!(count, 170);
    }

    #[test]
    fn ordinary_characters_are_not_hostile() {
        for c in [
            'a',
            'Z',
            '0',
            ' ',
            '~',
            '\u{4E2D}',
            '\u{1F600}',
            '\u{E9}',
            '\u{8F0}',
        ] {
            assert!(!is_hostile(c), "{c:?} hostile");
        }
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
        write_status(&mut out, &failed_job())?;
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
}
