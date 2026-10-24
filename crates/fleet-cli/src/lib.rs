//! The `fleet` command line client: job submission and inspection over gRPC.

pub mod config;
pub mod list;
pub mod watch;

use std::fmt;
use std::io::{Read, Write};

use clap::{Parser, Subcommand};
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, ListJobsRequest, SubmitJobRequest,
};
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

pub use config::{Config, ConfigError};

const MAX_SERVER_TEXT: usize = 200;

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
    },
    /// Show one job.
    Status {
        /// Job id.
        id: String,
    },
    /// Follow a job until it ends; exits 0 only on success.
    Watch {
        /// Job id.
        id: String,
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
    /// A watched job ended in a state other than succeeded.
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

/// Strips control characters from server text and truncates it to 200 characters.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_SERVER_TEXT)
        .collect()
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Usage(m) => write!(f, "{m}"),
            Self::Connect(m) => write!(f, "cannot connect: {m}"),
            Self::Rpc(s) => write!(f, "server error {:?}: {}", s.code(), sanitize(s.message())),
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

async fn open_channel(config: &Config) -> Result<Channel, CliError> {
    let mut endpoint = Endpoint::from_shared(config.server.clone())
        .map_err(|e| CliError::Connect(e.to_string()))?;
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

async fn connect(config: &Config) -> Result<Client, CliError> {
    let channel = open_channel(config).await?;
    Ok(FleetJobsClient::with_interceptor(channel, bearer(config)?))
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

fn write_status(out: &mut impl Write, job: &Job) -> std::io::Result<()> {
    writeln!(out, "id: {}", sanitize(&job.job_id))?;
    writeln!(out, "state: {}", state_name(job))?;
    writeln!(out, "phase: {}", sanitize(&job.phase))?;
    writeln!(out, "branch: {}", or_dash(job.branch.as_ref()))?;
    writeln!(out, "pr_url: {}", or_dash(job.pr_url.as_ref()))?;
    writeln!(out, "exit_code: {}", or_dash(job.exit_code.as_ref()))?;
    writeln!(out, "error: {}", or_dash(job.error.as_ref()))
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
) -> Result<Client, CliError> {
    let config = Config::from_lookup(server, insecure, lookup)?;
    connect(&config).await
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
    let Cli {
        server,
        insecure,
        command,
    } = cli;
    match command {
        Command::List => {
            let config = Config::from_lookup(server, insecure, lookup)?;
            list::list(&config, out).await?;
        }
        Command::Watch { id } => {
            let config = Config::from_lookup(server, insecure, lookup)?;
            watch::watch(&config, &id, out).await?;
        }
        Command::Submit {
            repo,
            base,
            no_pr,
            idempotency_key,
            prompt,
        } => {
            let prompt = read_prompt(prompt, stdin)?;
            let mut client = session(server, insecure, lookup).await?;
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
        Command::Jobs { state } => {
            let state = state.as_deref().map(parse_state).transpose()?;
            let mut client = session(server, insecure, lookup).await?;
            let reply = client
                .list_jobs(ListJobsRequest {
                    state: state.map(|s| s as i32),
                    limit: 0,
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
        }
        Command::Status { id } => {
            let mut client = session(server, insecure, lookup).await?;
            let job = client
                .get_job(GetJobRequest { job_id: id })
                .await?
                .into_inner();
            write_status(out, &job)?;
        }
        Command::Cancel { id } => {
            let mut client = session(server, insecure, lookup).await?;
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
    use super::*;

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize("a\u{1b}[31mb\nc\u{7}"), "a[31mbc");
    }

    #[test]
    fn sanitize_truncates_to_200_characters() {
        assert_eq!(sanitize(&"x".repeat(500)).chars().count(), 200);
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
