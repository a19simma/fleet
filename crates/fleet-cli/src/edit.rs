//! `fleet edit`: file, list, show, decide and apply suggested edits over the `FleetEdit` rpcs
//! (ADR-0066).
//!
//! `apply` reads one accepted file patch with `GetEdit` and applies it to the local work tree
//! through [`crate::patch`], which validates it first. It never stages or commits.

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use fleet_core::stamp::utc_stamp;
use fleet_proto::MAX_EDIT_PAYLOAD_BYTES;
use fleet_proto::v1::fleet_edit_client::FleetEditClient;
use fleet_proto::v1::{
    DecideEditRequest, EditDecision, EditKind, EditState, FileEditRequest, GetEditRequest,
    ListEditsRequest, SuggestedEdit,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Status};

use super::retro::{Scope, block};
use super::{Bearer, CliError, Scrub, patch};

/// A `FleetEdit` client carrying the bearer token.
pub(crate) type EditClient = FleetEditClient<InterceptedService<Channel, Bearer>>;

const BAD_PAYLOAD: &str = "the payload is larger than the payload limit or is not UTF-8 text";
const NOT_ACCEPTED: &str = "refused: only an accepted edit can be applied";
const NOT_A_PATCH: &str = "refused: only a file patch can be applied";
const TOKEN_HINT: &str = "; deciding needs a per-user API token, not the shared FLEET_CLIENT_TOKEN";

/// The kind of edit to file.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KindArg {
    /// A change to the slice file.
    SliceOp,
    /// A Pitfall.
    Pitfall,
    /// A patch to one file of the repository.
    FilePatch,
}

/// An edit state to filter by.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum StateArg {
    /// Waiting for a decision.
    Pending,
    /// Accepted.
    Accepted,
    /// Rejected.
    Rejected,
    /// Out of date.
    Stale,
}

/// The arguments of `fleet edit`.
#[derive(Debug, Args)]
pub struct EditArgs {
    #[command(flatten)]
    scope: Scope,
    /// The edit action.
    #[command(subcommand)]
    action: EditAction,
}

/// A `fleet edit` action.
#[derive(Debug, Subcommand)]
pub enum EditAction {
    /// File an edit. The payload is read from a file or from standard input.
    File {
        /// Edit kind.
        kind: KindArg,
        /// What the edit changes: a repository path for a file patch.
        target: String,
        /// Blob id of the target the payload was made against. Empty unless a file patch.
        #[arg(long, default_value = "")]
        base_hash: String,
        /// File holding the payload, or `-` for standard input.
        #[arg(long)]
        file: String,
    },
    /// List edits.
    List {
        /// Only edits in this state.
        #[arg(long)]
        state: Option<StateArg>,
    },
    /// Show one edit with its payload.
    Show {
        /// Edit id.
        id: u64,
    },
    /// Accept an edit. Needs a per-user API token.
    Accept {
        /// Edit id.
        id: u64,
    },
    /// Reject an edit. Needs a per-user API token.
    Reject {
        /// Edit id.
        id: u64,
    },
    /// Apply an accepted file patch to the local work tree, leaving it uncommitted and unstaged.
    Apply {
        /// Edit id.
        id: u64,
        /// A directory inside the repository to patch.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}

/// An edit action with every argument checked and its request built.
pub(crate) enum Call {
    File(FileEditRequest),
    List(ListEditsRequest),
    Show(GetEditRequest),
    Decide(DecideEditRequest),
    Apply(GetEditRequest, PathBuf),
}

fn read_payload(source: &str, stdin: &mut impl Read) -> Result<String, CliError> {
    let limit = MAX_EDIT_PAYLOAD_BYTES as u64 + 1;
    let mut bytes = Vec::new();
    if source == "-" {
        stdin.take(limit).read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(source)?
            .take(limit)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() > MAX_EDIT_PAYLOAD_BYTES {
        return Err(CliError::Usage(BAD_PAYLOAD.into()));
    }
    String::from_utf8(bytes).map_err(|_| CliError::Usage(BAD_PAYLOAD.into()))
}

impl EditArgs {
    /// Checks the arguments, reads any payload and builds the request, sending nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for a missing project, an empty key or a bad payload.
    pub(crate) fn prepare(self, stdin: &mut impl Read) -> Result<Call, CliError> {
        let scope = self.scope;
        Ok(match self.action {
            EditAction::File {
                kind,
                target,
                base_hash,
                file,
            } => {
                let key = scope.key()?;
                let project = scope.project()?;
                Call::File(FileEditRequest {
                    key,
                    project,
                    kind: edit_kind(kind) as i32,
                    target,
                    base_hash,
                    payload: read_payload(&file, stdin)?,
                })
            }
            EditAction::List { state } => Call::List(ListEditsRequest {
                project: scope.project()?,
                state: state.map(|s| edit_state(s) as i32),
            }),
            EditAction::Show { id } => Call::Show(GetEditRequest {
                project: scope.project()?,
                id,
            }),
            EditAction::Accept { id } => Call::Decide(decide(&scope, id, EditDecision::Accept)?),
            EditAction::Reject { id } => Call::Decide(decide(&scope, id, EditDecision::Reject)?),
            EditAction::Apply { id, repo } => Call::Apply(
                GetEditRequest {
                    project: scope.project()?,
                    id,
                },
                repo,
            ),
        })
    }
}

fn decide(scope: &Scope, id: u64, decision: EditDecision) -> Result<DecideEditRequest, CliError> {
    Ok(DecideEditRequest {
        key: scope.key()?,
        project: scope.project()?,
        id,
        decision: decision as i32,
    })
}

const fn edit_kind(kind: KindArg) -> EditKind {
    match kind {
        KindArg::SliceOp => EditKind::SliceOp,
        KindArg::Pitfall => EditKind::Pitfall,
        KindArg::FilePatch => EditKind::FilePatch,
    }
}

const fn edit_state(state: StateArg) -> EditState {
    match state {
        StateArg::Pending => EditState::Pending,
        StateArg::Accepted => EditState::Accepted,
        StateArg::Rejected => EditState::Rejected,
        StateArg::Stale => EditState::Stale,
    }
}

fn kind_name(raw: i32) -> &'static str {
    match EditKind::try_from(raw) {
        Ok(EditKind::SliceOp) => "slice-op",
        Ok(EditKind::Pitfall) => "pitfall",
        Ok(EditKind::FilePatch) => "file-patch",
        _ => "unknown",
    }
}

fn state_name(raw: i32) -> &'static str {
    match EditState::try_from(raw) {
        Ok(EditState::Pending) => "pending",
        Ok(EditState::Accepted) => "accepted",
        Ok(EditState::Rejected) => "rejected",
        Ok(EditState::Stale) => "stale",
        _ => "unknown",
    }
}

fn row(scrub: &Scrub, edit: &SuggestedEdit) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        edit.id,
        kind_name(edit.kind),
        state_name(edit.state),
        scrub.ident(&edit.target),
        scrub.ident(&edit.filed_by),
        utc_stamp(edit.created_at_ms),
    )
}

fn with_hint(status: Status) -> Status {
    if status.code() == Code::PermissionDenied {
        Status::new(status.code(), format!("{}{TOKEN_HINT}", status.message()))
    } else {
        status
    }
}

/// Sends one prepared [`Call`], prints the reply and for `apply` patches the work tree.
///
/// # Errors
///
/// Returns [`CliError::Rpc`] for a server refusal, [`CliError::Apply`] for a refused or failed
/// apply and [`CliError::Io`] when writing fails.
pub(crate) async fn execute(
    call: Call,
    client: &mut EditClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match call {
        Call::File(r) => {
            let edit = client.file_edit(r).await?.into_inner();
            writeln!(out, "{}", row(scrub, &edit))?;
        }
        Call::List(r) => {
            for edit in &client.list_edits(r).await?.into_inner().edits {
                writeln!(out, "{}", row(scrub, edit))?;
            }
        }
        Call::Show(r) => {
            let edit = client.get_edit(r).await?.into_inner();
            writeln!(out, "{}", row(scrub, &edit))?;
            writeln!(out, "base_hash: {}", scrub.ident(&edit.base_hash))?;
            write!(out, "{}", block(scrub, "payload", &edit.payload))?;
        }
        Call::Decide(r) => {
            let edit = client
                .decide_edit(r)
                .await
                .map_err(|s| CliError::Rpc(with_hint(s)))?
                .into_inner();
            writeln!(out, "{}", row(scrub, &edit))?;
        }
        Call::Apply(r, repo) => {
            let edit = client.get_edit(r).await?.into_inner();
            if edit.state != EditState::Accepted as i32 {
                return Err(CliError::Apply(NOT_ACCEPTED.into()));
            }
            if edit.kind != EditKind::FilePatch as i32 {
                return Err(CliError::Apply(NOT_A_PATCH.into()));
            }
            let done = patch::apply(
                &repo,
                &edit.payload,
                &edit.target,
                MAX_EDIT_PAYLOAD_BYTES,
                scrub,
            )?;
            writeln!(
                out,
                "applied edit {} to {}: uncommitted and unstaged",
                edit.id, done.target
            )?;
        }
    }
    Ok(())
}
