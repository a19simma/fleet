//! `fleet env`: create, list, show and remove Environments, store secrets and edit scripts.
//!
//! Names pass the core validators before any connection is opened, so a hostile name never
//! reaches the server. A secret value is read from stdin and never from an argument: the parser
//! takes any stray text into a hidden field and a fixed message refuses it without repeating it.
//! A terminal on stdin needs an explicit `-`. Every read stops one byte past its cap. A refusal of
//! the secret put keeps its status code and gets a fixed message, so no server text can echo a
//! value. `show` prints names, fingerprints and structure: never a value and never a script body.

use std::io::{Read, Write};

use clap::{Subcommand, ValueEnum};
use fleet_core::environment::{
    Delivery, EntryName, EnvironmentName, MAX_SCRIPT_BYTES, MAX_SECRET_BYTES, OnFail, ScriptBody,
    ScriptSpec, SecretSpec, SecretValue,
};
use fleet_proto::v1::environment_entry_spec::Kind;
use fleet_proto::v1::fleet_environments_client::FleetEnvironmentsClient;
use fleet_proto::v1::{
    CreateEnvironmentRequest, DeleteEnvironmentRequest, EnvironmentDelivery, EnvironmentDetail,
    EnvironmentEntrySpec, EnvironmentOnFail, EnvironmentScriptSpec, EnvironmentSecretSpec,
    GetEnvironmentRequest, ListEnvironmentsRequest, PutEnvironmentSecretRequest,
    SaveEnvironmentVersionRequest,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Status};
use zeroize::Zeroizing;

use super::{Bearer, CliError, Scrub};

/// A `FleetEnvironments` client carrying the bearer token.
pub(crate) type EnvironmentsClient = FleetEnvironmentsClient<InterceptedService<Channel, Bearer>>;

const NO_ARGV_SECRET: &str =
    "the secret is read from stdin with a trailing -, never from arguments";
const NO_STRAY: &str = "unexpected extra arguments";
const NEEDS_DASH: &str = "stdin is a terminal: pipe the secret in or pass - to read it here";
const SECRET_NOT_TEXT: &str = "secret value is not valid UTF-8";
const SCRIPT_NOT_TEXT: &str = "script body is not valid UTF-8";
const SCRIPT_CLASH: &str = "that name belongs to a secret";
const SCRIPT_MISSING: &str = "no script with that name";
const SECRET_CLASH: &str = "that name belongs to a script";

/// How a secret reaches the job.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DeliveryArg {
    /// A file under the job scratch directory.
    File,
    /// An environment variable of the agent. Needs `--agent`.
    Env,
}

/// What a failing script does.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OnFailArg {
    /// Fail the job before the agent starts.
    Abort,
    /// Note the failure and run the next script.
    Continue,
}

/// A `fleet env` action.
#[derive(Debug, Subcommand)]
pub enum EnvAction {
    /// Create an empty Environment.
    Create {
        /// Environment name.
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// Refused: this action takes one name.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// List your Environments with their latest version.
    List {
        /// Refused: this action takes no arguments.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Show secret names with fingerprints and the latest structure. Never a value.
    Show {
        /// Environment name.
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// Refused: this action takes one name.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Remove an Environment.
    #[command(name = "rm")]
    Remove {
        /// Environment name.
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// Refused: this action takes one name.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Store secrets. The value is read from stdin.
    Secret {
        /// The secret action.
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Add and remove setup scripts.
    Script {
        /// The script action.
        #[command(subcommand)]
        action: ScriptAction,
    },
}

/// A `fleet env secret` action.
#[derive(Debug, Subcommand)]
pub enum SecretAction {
    /// Store a secret value read from stdin and list it in a new version. Pass `-` to read a
    /// terminal. A new secret is setup-only and delivered as a file.
    Put {
        /// Environment name.
        #[arg(allow_hyphen_values = true)]
        environment: String,
        /// Secret name.
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// `-` to read stdin even on a terminal. Anything else is refused.
        #[arg(allow_hyphen_values = true)]
        source: Option<String>,
        /// Let the agent see the value. Without it the value stays in the setup unit.
        #[arg(long)]
        agent: bool,
        /// How the value reaches the job.
        #[arg(long, value_enum)]
        delivery: Option<DeliveryArg>,
        /// Refused: the secret is never an argument.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
}

/// A `fleet env script` action.
#[derive(Debug, Subcommand)]
pub enum ScriptAction {
    /// Add or replace a script in a new version. The body comes from a file or `-` for stdin.
    Add {
        /// Environment name.
        #[arg(allow_hyphen_values = true)]
        environment: String,
        /// Script name.
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// File holding the script, or `-` to read stdin. It opens with a `#!/` line.
        #[arg(allow_hyphen_values = true)]
        source: String,
        /// What a failure does.
        #[arg(long, value_enum)]
        on_fail: Option<OnFailArg>,
        /// Timeout in seconds, 1 to 600.
        #[arg(long)]
        timeout: Option<u32>,
        /// Refused: this action takes one source.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Remove a script in a new version.
    #[command(name = "rm")]
    Remove {
        /// Environment name.
        #[arg(allow_hyphen_values = true)]
        environment: String,
        /// Script name.
        #[arg(allow_hyphen_values = true)]
        name: String,
        /// Refused: this action takes one name.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
}

/// A checked request. Building one performs no RPC.
#[derive(Debug)]
pub(crate) enum Call {
    Create(EnvironmentName),
    List,
    Show(EnvironmentName),
    Remove(EnvironmentName),
    PutSecret {
        environment: EnvironmentName,
        name: EntryName,
        value: SecretValue,
        spec: Option<SecretSpec>,
    },
    AddScript {
        environment: EnvironmentName,
        spec: ScriptSpec,
    },
    RemoveScript {
        environment: EnvironmentName,
        name: EntryName,
    },
}

fn usage(text: &str) -> CliError {
    CliError::Usage(text.to_owned())
}

fn invalid(err: impl std::fmt::Display) -> CliError {
    CliError::Usage(err.to_string())
}

fn no_stray(rest: &[String]) -> Result<(), CliError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(usage(NO_STRAY))
    }
}

fn env_name(raw: &str) -> Result<EnvironmentName, CliError> {
    EnvironmentName::new(raw).map_err(invalid)
}

fn entry_name(raw: &str) -> Result<EntryName, CliError> {
    EntryName::new(raw).map_err(invalid)
}

fn read_capped(source: &mut impl Read, cap: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap + 1));
    source.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads a secret: at most [`MAX_SECRET_BYTES`] of value, then any line ending. The read stops one
/// byte past the cap, so longer input reaches the core validator, which refuses it, without being
/// held. Trailing CR and LF are removed.
fn read_secret(source: &mut impl Read) -> Result<SecretValue, CliError> {
    let mut bytes = read_capped(source, MAX_SECRET_BYTES)?;
    while bytes.last().is_some_and(|b| matches!(b, b'\r' | b'\n')) {
        bytes.pop();
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| usage(SECRET_NOT_TEXT))?;
    SecretValue::new(text.to_owned()).map_err(invalid)
}

fn read_script(source: &str, stdin: &mut impl Read) -> Result<ScriptBody, CliError> {
    let bytes = if source == "-" {
        read_capped(stdin, MAX_SCRIPT_BYTES)?
    } else {
        read_capped(&mut std::fs::File::open(source)?, MAX_SCRIPT_BYTES)?
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| usage(SCRIPT_NOT_TEXT))?;
    ScriptBody::new(text).map_err(invalid)
}

fn secret_spec(
    name: &EntryName,
    agent: bool,
    delivery: Option<DeliveryArg>,
) -> Result<Option<SecretSpec>, CliError> {
    if !agent && delivery.is_none() {
        return Ok(None);
    }
    let delivery = match delivery {
        Some(DeliveryArg::Env) => Delivery::Env,
        Some(DeliveryArg::File) | None => Delivery::File,
    };
    SecretSpec::new(name.clone(), agent, delivery)
        .map(Some)
        .map_err(invalid)
}

impl EnvAction {
    /// Checks every input and reads stdin or a file, before any connection is opened. `tty` says
    /// whether stdin is a terminal.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for a hostile name, a stray argument, a terminal without `-`,
    /// input over its cap or a value the core validators refuse, and [`CliError::Io`] when a
    /// read fails.
    pub(crate) fn prepare(self, stdin: &mut impl Read, tty: bool) -> Result<Call, CliError> {
        match self {
            Self::Create { name, rest } => {
                no_stray(&rest)?;
                env_name(&name).map(Call::Create)
            }
            Self::List { rest } => {
                no_stray(&rest)?;
                Ok(Call::List)
            }
            Self::Show { name, rest } => {
                no_stray(&rest)?;
                env_name(&name).map(Call::Show)
            }
            Self::Remove { name, rest } => {
                no_stray(&rest)?;
                env_name(&name).map(Call::Remove)
            }
            Self::Secret { action } => action.prepare(stdin, tty),
            Self::Script { action } => action.prepare(stdin),
        }
    }
}

impl SecretAction {
    fn prepare(self, stdin: &mut impl Read, tty: bool) -> Result<Call, CliError> {
        let Self::Put {
            environment,
            name,
            source,
            agent,
            delivery,
            rest,
        } = self;
        if !rest.is_empty() || source.as_deref().is_some_and(|s| s != "-") {
            return Err(usage(NO_ARGV_SECRET));
        }
        let environment = env_name(&environment)?;
        let name = entry_name(&name)?;
        let spec = secret_spec(&name, agent, delivery)?;
        if source.is_none() && tty {
            return Err(usage(NEEDS_DASH));
        }
        let value = read_secret(stdin)?;
        Ok(Call::PutSecret {
            environment,
            name,
            value,
            spec,
        })
    }
}

impl ScriptAction {
    fn prepare(self, stdin: &mut impl Read) -> Result<Call, CliError> {
        match self {
            Self::Add {
                environment,
                name,
                source,
                on_fail,
                timeout,
                rest,
            } => {
                no_stray(&rest)?;
                let environment = env_name(&environment)?;
                let name = entry_name(&name)?;
                let body = read_script(&source, stdin)?;
                let on_fail = match on_fail {
                    Some(OnFailArg::Continue) => OnFail::Continue,
                    Some(OnFailArg::Abort) | None => OnFail::Abort,
                };
                let timeout = timeout.unwrap_or(fleet_core::environment::DEFAULT_TIMEOUT_S);
                let spec = ScriptSpec::new(name, body, on_fail, timeout).map_err(invalid)?;
                Ok(Call::AddScript { environment, spec })
            }
            Self::Remove {
                environment,
                name,
                rest,
            } => {
                no_stray(&rest)?;
                Ok(Call::RemoveScript {
                    environment: env_name(&environment)?,
                    name: entry_name(&name)?,
                })
            }
        }
    }
}

fn put_refusal(status: &Status) -> CliError {
    let text = match status.code() {
        Code::PermissionDenied => fleet_proto::ERR_ENV_NEEDS_USER_TOKEN,
        Code::NotFound => fleet_proto::ERR_ENV_NOT_FOUND,
        Code::ResourceExhausted => fleet_proto::ERR_ENV_LIMIT,
        Code::InvalidArgument => "secret value refused",
        _ => "secret store error",
    };
    CliError::Rpc(Status::new(status.code(), text))
}

fn entry_name_of(entry: &EnvironmentEntrySpec) -> Option<(&str, bool)> {
    match entry.kind.as_ref()? {
        Kind::Secret(s) => Some((s.name.as_str(), false)),
        Kind::Script(s) => Some((s.name.as_str(), true)),
    }
}

fn position(entries: &[EnvironmentEntrySpec], name: &EntryName) -> Option<(usize, bool)> {
    entries.iter().enumerate().find_map(|(i, entry)| {
        entry_name_of(entry)
            .filter(|(existing, _)| existing.eq_ignore_ascii_case(name.as_str()))
            .map(|(_, script)| (i, script))
    })
}

fn delivery_wire(delivery: Delivery) -> EnvironmentDelivery {
    match delivery {
        Delivery::File => EnvironmentDelivery::File,
        Delivery::Env => EnvironmentDelivery::Env,
    }
}

fn on_fail_wire(on_fail: OnFail) -> EnvironmentOnFail {
    match on_fail {
        OnFail::Abort => EnvironmentOnFail::Abort,
        OnFail::Continue => EnvironmentOnFail::Continue,
    }
}

fn upsert(entries: &mut Vec<EnvironmentEntrySpec>, at: Option<usize>, entry: EnvironmentEntrySpec) {
    match at.and_then(|i| entries.get_mut(i)) {
        Some(slot) => *slot = entry,
        None => entries.push(entry),
    }
}

struct Structure {
    entries: Vec<EnvironmentEntrySpec>,
    egress_hosts: Vec<String>,
}

async fn structure(
    client: &mut EnvironmentsClient,
    environment: &EnvironmentName,
) -> Result<Structure, CliError> {
    let detail = client
        .get_environment(GetEnvironmentRequest {
            name: environment.as_str().to_owned(),
        })
        .await?
        .into_inner();
    Ok(detail.latest.map_or_else(
        || Structure {
            entries: Vec::new(),
            egress_hosts: Vec::new(),
        },
        |latest| Structure {
            entries: latest.entries,
            egress_hosts: latest.egress_hosts,
        },
    ))
}

async fn save(
    client: &mut EnvironmentsClient,
    environment: &EnvironmentName,
    structure: Structure,
) -> Result<u32, CliError> {
    let reply = client
        .save_environment_version(SaveEnvironmentVersionRequest {
            environment: environment.as_str().to_owned(),
            entries: structure.entries,
            egress_hosts: structure.egress_hosts,
        })
        .await?
        .into_inner();
    Ok(reply.version)
}

fn opt_version(version: Option<u32>) -> String {
    version.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

fn show_detail(
    scrub: &Scrub,
    detail: &EnvironmentDetail,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let info = detail.environment.clone().unwrap_or_default();
    writeln!(
        out,
        "{}\t{}",
        scrub.ident(&info.name),
        opt_version(info.latest_version)
    )?;
    for secret in &detail.secrets {
        writeln!(
            out,
            "secret\t{}\t{}",
            scrub.ident(&secret.name),
            scrub.ident(&secret.fingerprint)
        )?;
    }
    let Some(latest) = &detail.latest else {
        return Ok(());
    };
    writeln!(
        out,
        "version\t{}\t{}",
        latest.version,
        scrub.ident(&latest.hash)
    )?;
    for entry in &latest.entries {
        match &entry.kind {
            Some(Kind::Secret(s)) => writeln!(
                out,
                "entry\tsecret\t{}\t{}\t{}",
                scrub.ident(&s.name),
                if s.agent_visible { "agent" } else { "setup" },
                delivery_name(s)
            )?,
            Some(Kind::Script(s)) => writeln!(
                out,
                "entry\tscript\t{}\t{}\t{}s\t{} bytes",
                scrub.ident(&s.name),
                on_fail_name(s),
                s.timeout_s
                    .map_or_else(|| "default".to_owned(), |t| t.to_string()),
                s.body.len()
            )?,
            None => {}
        }
    }
    for host in &latest.egress_hosts {
        writeln!(out, "egress\t{}", scrub.ident(host))?;
    }
    Ok(())
}

fn delivery_name(spec: &EnvironmentSecretSpec) -> &'static str {
    if spec.delivery() == EnvironmentDelivery::Env {
        "env"
    } else {
        "file"
    }
}

fn on_fail_name(spec: &EnvironmentScriptSpec) -> &'static str {
    if spec.on_fail() == EnvironmentOnFail::Continue {
        "continue"
    } else {
        "abort"
    }
}

/// Runs a checked call and prints its result.
///
/// # Errors
///
/// Returns [`CliError::Rpc`] for a server refusal, [`CliError::Usage`] when a script or secret
/// name belongs to the other kind or no script has the name, and [`CliError::Io`] when writing
/// fails.
pub(crate) async fn execute(
    call: Call,
    client: &mut EnvironmentsClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match call {
        Call::Create(name) => {
            let info = client
                .create_environment(CreateEnvironmentRequest {
                    name: name.as_str().to_owned(),
                })
                .await?
                .into_inner();
            writeln!(out, "{}", scrub.ident(&info.name))?;
        }
        Call::List => {
            let reply = client
                .list_environments(ListEnvironmentsRequest {})
                .await?
                .into_inner();
            for info in &reply.environments {
                writeln!(
                    out,
                    "{}\t{}",
                    scrub.ident(&info.name),
                    opt_version(info.latest_version)
                )?;
            }
        }
        Call::Show(name) => {
            let detail = client
                .get_environment(GetEnvironmentRequest {
                    name: name.as_str().to_owned(),
                })
                .await?
                .into_inner();
            show_detail(scrub, &detail, out)?;
        }
        Call::Remove(name) => {
            client
                .delete_environment(DeleteEnvironmentRequest {
                    name: name.as_str().to_owned(),
                })
                .await?;
            writeln!(out, "removed\t{}", name.as_str())?;
        }
        Call::PutSecret {
            environment,
            name,
            value,
            spec,
        } => put_secret(client, scrub, (environment, name, value, spec), out).await?,
        Call::AddScript { environment, spec } => {
            let mut current = structure(client, &environment).await?;
            let at = match position(&current.entries, spec.name()) {
                Some((_, false)) => return Err(usage(SCRIPT_CLASH)),
                Some((i, true)) => Some(i),
                None => None,
            };
            let entry = EnvironmentEntrySpec {
                kind: Some(Kind::Script(EnvironmentScriptSpec {
                    name: spec.name().as_str().to_owned(),
                    body: spec.body().as_str().to_owned(),
                    on_fail: on_fail_wire(spec.on_fail()).into(),
                    timeout_s: Some(spec.timeout_s()),
                })),
            };
            upsert(&mut current.entries, at, entry);
            let version = save(client, &environment, current).await?;
            writeln!(out, "{}\t{version}", spec.name().as_str())?;
        }
        Call::RemoveScript { environment, name } => {
            let mut current = structure(client, &environment).await?;
            let Some((at, true)) = position(&current.entries, &name) else {
                return Err(usage(SCRIPT_MISSING));
            };
            current.entries.remove(at);
            let version = save(client, &environment, current).await?;
            writeln!(out, "removed\t{}\t{version}", name.as_str())?;
        }
    }
    Ok(())
}

async fn put_secret(
    client: &mut EnvironmentsClient,
    scrub: &Scrub,
    (environment, name, value, spec): (EnvironmentName, EntryName, SecretValue, Option<SecretSpec>),
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut current = structure(client, &environment).await?;
    let found = position(&current.entries, &name);
    if matches!(found, Some((_, true))) {
        return Err(usage(SECRET_CLASH));
    }
    let entry = match (&spec, found) {
        (None, Some(_)) => None,
        (spec, _) => {
            let (visible, delivery) = spec.as_ref().map_or((false, Delivery::File), |s| {
                (s.agent_visible(), s.delivery())
            });
            Some(EnvironmentEntrySpec {
                kind: Some(Kind::Secret(EnvironmentSecretSpec {
                    name: name.as_str().to_owned(),
                    agent_visible: visible,
                    delivery: delivery_wire(delivery).into(),
                })),
            })
        }
    };
    let text = std::str::from_utf8(value.expose()).map_err(|_| usage(SECRET_NOT_TEXT))?;
    let reply = client
        .put_environment_secret(PutEnvironmentSecretRequest {
            environment: environment.as_str().to_owned(),
            name: name.as_str().to_owned(),
            value: text.to_owned(),
        })
        .await
        .map_err(|status| put_refusal(&status))?
        .into_inner();
    if let Some(entry) = entry {
        upsert(&mut current.entries, found.map(|(i, _)| i), entry);
    }
    let version = save(client, &environment, current).await?;
    writeln!(
        out,
        "{}\t{}\t{version}",
        name.as_str(),
        scrub.ident(&reply.fingerprint)
    )?;
    Ok(())
}
