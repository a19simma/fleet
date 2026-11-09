//! `fleet retro`, `fleet improvement` and `fleet pitfall`: the Retro commands over the
//! `FleetRetro` rpcs (ADR-0065).
//!
//! Each mutating invocation sends a fresh idempotency key unless `--idempotency-key` gives one,
//! and an empty key is refused before any connection. Every server-supplied field prints through
//! [`Scrub`]: one-line fields with [`Scrub::ident`] and multi-line text with [`Scrub::text`],
//! indented so no line of it can start a row.

use std::io::Write;

use clap::{Args, Subcommand, ValueEnum};
use fleet_core::stamp::utc_stamp;
use fleet_proto::v1::fleet_retro_client::FleetRetroClient;
use fleet_proto::v1::{
    CloseRetroRequest, DispositionImprovementRequest, FileImprovementRequest, GetWorkBriefRequest,
    Improvement, ImprovementDisposition, ImprovementKind, ListImprovementsRequest,
    ListPitfallsRequest, ListRetrosRequest, OpenRetroRequest, Pitfall, RecordPitfallRequest, Retro,
    RetroState,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, Scrub};

/// A `FleetRetro` client carrying the bearer token.
pub(crate) type RetroClient = FleetRetroClient<InterceptedService<Channel, Bearer>>;

const NO_PROJECT: &str = "this action needs --project";
const EMPTY_KEY: &str = "the idempotency key is empty";
const EMPTY_PROJECT: &str = "--project is empty";

/// The arguments every Work-project command shares.
#[derive(Debug, Args)]
pub(crate) struct Scope {
    /// Work project name. Every action needs it except the user-level pitfall actions.
    #[arg(long, short, global = true)]
    project: Option<String>,
    /// Idempotency key of a mutating action. A fresh key is made per invocation when absent.
    #[arg(long, global = true)]
    idempotency_key: Option<String>,
}

impl Scope {
    /// The idempotency key: the given one, or a fresh one.
    pub(crate) fn key(&self) -> Result<String, CliError> {
        match &self.idempotency_key {
            Some(key) if key.is_empty() => Err(CliError::Usage(EMPTY_KEY.into())),
            Some(key) => Ok(key.clone()),
            None => Ok(super::batch::fresh_key()),
        }
    }

    /// The project, refused when absent or empty.
    pub(crate) fn project(&self) -> Result<String, CliError> {
        self.optional_project()?
            .ok_or_else(|| CliError::Usage(NO_PROJECT.into()))
    }

    fn optional_project(&self) -> Result<Option<String>, CliError> {
        match &self.project {
            Some(name) if name.is_empty() => Err(CliError::Usage(EMPTY_PROJECT.into())),
            other => Ok(other.clone()),
        }
    }
}

/// A Retro state to filter by.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RetroFilter {
    /// Open Retros.
    Open,
    /// Closed Retros.
    Closed,
}

/// An Improvement kind.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KindArg {
    /// How the loop works.
    Process,
    /// Tools and scripts.
    Tooling,
    /// Documentation.
    Docs,
    /// Tests.
    Test,
    /// A known trap.
    Pitfall,
    /// Anything else.
    Other,
}

/// How an Improvement ends.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DispositionArg {
    /// Taken on.
    Accepted,
    /// Turned down.
    Rejected,
    /// Left for later.
    Deferred,
    /// Done.
    Applied,
}

/// The arguments of `fleet retro`.
#[derive(Debug, Args)]
pub struct RetroArgs {
    #[command(flatten)]
    scope: Scope,
    /// The Retro action.
    #[command(subcommand)]
    action: RetroAction,
}

/// A `fleet retro` action.
#[derive(Debug, Subcommand)]
pub enum RetroAction {
    /// Open a Retro over a span of finished Work items.
    Open {
        /// Retro title.
        title: String,
        /// First item key of the span.
        #[arg(long = "from")]
        from: Option<String>,
        /// Last item key of the span.
        #[arg(long = "to")]
        to: Option<String>,
    },
    /// List Retros.
    List {
        /// Only Retros in this state.
        #[arg(long)]
        state: Option<RetroFilter>,
    },
    /// Close a Retro. The server refuses while an Improvement has no disposition.
    Close {
        /// Retro id.
        id: u64,
    },
    /// Show the brief a worker reads before an Attempt on an item.
    Brief {
        /// Item key.
        item: String,
    },
}

/// The arguments of `fleet improvement`.
#[derive(Debug, Args)]
pub struct ImprovementArgs {
    #[command(flatten)]
    scope: Scope,
    /// The Improvement action.
    #[command(subcommand)]
    action: ImprovementAction,
}

/// A `fleet improvement` action.
#[derive(Debug, Subcommand)]
pub enum ImprovementAction {
    /// File an Improvement. An existing title adds an occurrence.
    File {
        /// Improvement title.
        title: String,
        /// Vertical the Improvement belongs to.
        #[arg(long)]
        vertical: String,
        /// Improvement kind.
        #[arg(long)]
        kind: KindArg,
        /// Improvement body.
        #[arg(long, default_value = "")]
        body: String,
        /// Retro it was found in.
        #[arg(long)]
        retro: Option<u64>,
        /// Work item it was found on.
        #[arg(long)]
        item: Option<String>,
        /// Attempt it was found in.
        #[arg(long)]
        attempt: Option<u64>,
    },
    /// List Improvements.
    List {
        /// Only Improvements of this vertical.
        #[arg(long)]
        vertical: Option<String>,
        /// Only Improvements of this Retro.
        #[arg(long)]
        retro: Option<u64>,
        /// Only Improvements with no disposition.
        #[arg(long)]
        undecided: bool,
    },
    /// Give an Improvement its disposition.
    Disposition {
        /// Improvement id.
        id: u64,
        /// How it ends.
        disposition: DispositionArg,
        /// Why.
        #[arg(long)]
        reason: String,
    },
}

/// The arguments of `fleet pitfall`.
#[derive(Debug, Args)]
pub struct PitfallArgs {
    #[command(flatten)]
    scope: Scope,
    /// The Pitfall action.
    #[command(subcommand)]
    action: PitfallAction,
}

/// A `fleet pitfall` action.
#[derive(Debug, Subcommand)]
pub enum PitfallAction {
    /// Record a Pitfall. Without `--project` it is user-level.
    Record {
        /// What goes wrong.
        symptom: String,
        /// Why it goes wrong.
        #[arg(long)]
        cause: String,
        /// How to avoid or fix it.
        #[arg(long)]
        fix: String,
    },
    /// List Pitfalls. Without `--project` the user-level ones.
    List,
}

/// A retro, improvement or pitfall action with every argument checked and its request built.
pub(crate) enum Call {
    OpenRetro(OpenRetroRequest),
    ListRetros(ListRetrosRequest),
    CloseRetro(CloseRetroRequest),
    Brief(GetWorkBriefRequest),
    FileImprovement(FileImprovementRequest),
    ListImprovements(ListImprovementsRequest),
    Disposition(DispositionImprovementRequest),
    RecordPitfall(RecordPitfallRequest),
    ListPitfalls(ListPitfallsRequest),
}

impl RetroArgs {
    /// Checks the arguments and builds the request, sending nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for a missing project or an empty key.
    pub(crate) fn prepare(self) -> Result<Call, CliError> {
        let scope = self.scope;
        Ok(match self.action {
            RetroAction::Open { title, from, to } => Call::OpenRetro(OpenRetroRequest {
                key: scope.key()?,
                project: scope.project()?,
                title,
                span_from_item_key: from,
                span_to_item_key: to,
            }),
            RetroAction::List { state } => Call::ListRetros(ListRetrosRequest {
                project: scope.project()?,
                state: state.map(|s| retro_state(s) as i32),
            }),
            RetroAction::Close { id } => Call::CloseRetro(CloseRetroRequest {
                key: scope.key()?,
                project: scope.project()?,
                retro_id: id,
            }),
            RetroAction::Brief { item } => Call::Brief(GetWorkBriefRequest {
                project: scope.project()?,
                item_key: item,
            }),
        })
    }
}

impl ImprovementArgs {
    /// Checks the arguments and builds the request, sending nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for a missing project or an empty key.
    pub(crate) fn prepare(self) -> Result<Call, CliError> {
        let scope = self.scope;
        Ok(match self.action {
            ImprovementAction::File {
                title,
                vertical,
                kind,
                body,
                retro,
                item,
                attempt,
            } => Call::FileImprovement(FileImprovementRequest {
                key: scope.key()?,
                project: scope.project()?,
                retro_id: retro,
                item_key: item,
                attempt_id: attempt,
                vertical,
                title,
                body,
                kind: improvement_kind(kind) as i32,
            }),
            ImprovementAction::List {
                vertical,
                retro,
                undecided,
            } => Call::ListImprovements(ListImprovementsRequest {
                project: scope.project()?,
                vertical,
                retro_id: retro,
                undecided: undecided.then_some(true),
            }),
            ImprovementAction::Disposition {
                id,
                disposition,
                reason,
            } => Call::Disposition(DispositionImprovementRequest {
                key: scope.key()?,
                project: scope.project()?,
                improvement_id: id,
                disposition: disposition_of(disposition) as i32,
                reason,
            }),
        })
    }
}

impl PitfallArgs {
    /// Checks the arguments and builds the request, sending nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for an empty project or an empty key.
    pub(crate) fn prepare(self) -> Result<Call, CliError> {
        let scope = self.scope;
        Ok(match self.action {
            PitfallAction::Record {
                symptom,
                cause,
                fix,
            } => Call::RecordPitfall(RecordPitfallRequest {
                key: scope.key()?,
                project: scope.optional_project()?,
                symptom,
                cause,
                fix,
            }),
            PitfallAction::List => Call::ListPitfalls(ListPitfallsRequest {
                project: scope.optional_project()?,
            }),
        })
    }
}

const fn retro_state(state: RetroFilter) -> RetroState {
    match state {
        RetroFilter::Open => RetroState::Open,
        RetroFilter::Closed => RetroState::Closed,
    }
}

const fn improvement_kind(kind: KindArg) -> ImprovementKind {
    match kind {
        KindArg::Process => ImprovementKind::Process,
        KindArg::Tooling => ImprovementKind::Tooling,
        KindArg::Docs => ImprovementKind::Docs,
        KindArg::Test => ImprovementKind::Test,
        KindArg::Pitfall => ImprovementKind::Pitfall,
        KindArg::Other => ImprovementKind::Other,
    }
}

const fn disposition_of(disposition: DispositionArg) -> ImprovementDisposition {
    match disposition {
        DispositionArg::Accepted => ImprovementDisposition::Accepted,
        DispositionArg::Rejected => ImprovementDisposition::Rejected,
        DispositionArg::Deferred => ImprovementDisposition::Deferred,
        DispositionArg::Applied => ImprovementDisposition::Applied,
    }
}

fn retro_state_name(raw: i32) -> &'static str {
    match RetroState::try_from(raw) {
        Ok(RetroState::Open) => "open",
        Ok(RetroState::Closed) => "closed",
        _ => "unknown",
    }
}

fn kind_name(raw: i32) -> &'static str {
    match ImprovementKind::try_from(raw) {
        Ok(ImprovementKind::Process) => "process",
        Ok(ImprovementKind::Tooling) => "tooling",
        Ok(ImprovementKind::Docs) => "docs",
        Ok(ImprovementKind::Test) => "test",
        Ok(ImprovementKind::Pitfall) => "pitfall",
        Ok(ImprovementKind::Other) => "other",
        _ => "unknown",
    }
}

fn disposition_name(raw: Option<i32>) -> &'static str {
    match raw.map(ImprovementDisposition::try_from) {
        None => "-",
        Some(Ok(ImprovementDisposition::Accepted)) => "accepted",
        Some(Ok(ImprovementDisposition::Rejected)) => "rejected",
        Some(Ok(ImprovementDisposition::Deferred)) => "deferred",
        Some(Ok(ImprovementDisposition::Applied)) => "applied",
        Some(_) => "unknown",
    }
}

/// `value` scrubbed onto one line, or `-` when absent.
pub(crate) fn dash(scrub: &Scrub, value: Option<&String>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| scrub.ident(v))
}

/// `-` or the number when absent or present.
fn number<T: std::fmt::Display>(value: Option<&T>) -> String {
    value.map_or_else(|| "-".to_owned(), ToString::to_string)
}

/// `text` scrubbed and indented under `label`, so no line of it can start a row.
pub(crate) fn block(scrub: &Scrub, label: &str, text: &str) -> String {
    let mut shown = format!("{label}:\n");
    for line in scrub.text(text).lines() {
        shown.push_str("  ");
        shown.push_str(line);
        shown.push('\n');
    }
    shown
}

fn retro_row(scrub: &Scrub, retro: &Retro) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        retro.id,
        retro_state_name(retro.state),
        scrub.ident(&retro.title),
        dash(scrub, retro.span_from_item_key.as_ref()),
        dash(scrub, retro.span_to_item_key.as_ref()),
        utc_stamp(retro.opened_at_ms),
        retro.closed_at_ms.map_or_else(|| "-".to_owned(), utc_stamp),
    )
}

fn print_improvement(
    out: &mut impl Write,
    scrub: &Scrub,
    improvement: &Improvement,
) -> std::io::Result<()> {
    writeln!(
        out,
        "{}\t{}\t{}\tx{}\t{}\t{}\t{}\t{}",
        improvement.id,
        kind_name(improvement.kind),
        disposition_name(improvement.disposition),
        improvement.occurrences,
        scrub.ident(&improvement.vertical),
        number(improvement.retro_id.as_ref()),
        dash(scrub, improvement.item_key.as_ref()),
        scrub.ident(&improvement.title),
    )?;
    write!(out, "{}", block(scrub, "body", &improvement.body))?;
    if let Some(reason) = &improvement.disposition_reason {
        write!(out, "{}", block(scrub, "reason", reason))?;
    }
    Ok(())
}

fn print_pitfall(out: &mut impl Write, scrub: &Scrub, pitfall: &Pitfall) -> std::io::Result<()> {
    writeln!(
        out,
        "{}\t{}\t{}\t{}",
        pitfall.id,
        dash(scrub, pitfall.project.as_ref()),
        pitfall.hits,
        scrub.ident(&pitfall.symptom),
    )?;
    write!(out, "{}", block(scrub, "cause", &pitfall.cause))?;
    write!(out, "{}", block(scrub, "fix", &pitfall.fix))
}

/// Sends one prepared [`Call`] and prints the reply.
///
/// # Errors
///
/// Returns [`CliError::Rpc`] for a server refusal and [`CliError::Io`] when writing fails.
pub(crate) async fn execute(
    call: Call,
    client: &mut RetroClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match call {
        Call::OpenRetro(r) => {
            let retro = client.open_retro(r).await?.into_inner();
            writeln!(out, "{}", retro_row(scrub, &retro))?;
        }
        Call::ListRetros(r) => {
            for retro in &client.list_retros(r).await?.into_inner().retros {
                writeln!(out, "{}", retro_row(scrub, retro))?;
            }
        }
        Call::CloseRetro(r) => {
            let retro = client.close_retro(r).await?.into_inner();
            writeln!(out, "{}", retro_row(scrub, &retro))?;
        }
        Call::Brief(r) => {
            let reply = client.get_work_brief(r).await?.into_inner();
            write!(out, "{}", block(scrub, "brief", &reply.text))?;
            writeln!(out, "dropped: {}", reply.dropped)?;
        }
        Call::FileImprovement(r) => {
            let improvement = client.file_improvement(r).await?.into_inner();
            print_improvement(out, scrub, &improvement)?;
        }
        Call::ListImprovements(r) => {
            for improvement in &client.list_improvements(r).await?.into_inner().improvements {
                print_improvement(out, scrub, improvement)?;
            }
        }
        Call::Disposition(r) => {
            let improvement = client.disposition_improvement(r).await?.into_inner();
            print_improvement(out, scrub, &improvement)?;
        }
        Call::RecordPitfall(r) => {
            let pitfall = client.record_pitfall(r).await?.into_inner();
            print_pitfall(out, scrub, &pitfall)?;
        }
        Call::ListPitfalls(r) => {
            for pitfall in &client.list_pitfalls(r).await?.into_inner().pitfalls {
                print_pitfall(out, scrub, pitfall)?;
            }
        }
    }
    Ok(())
}
