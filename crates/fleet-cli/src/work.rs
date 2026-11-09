//! `fleet work`: the Work tracker commands over the `FleetWork` rpcs (ADR-0064).
//!
//! Every mutating invocation sends a fresh idempotency key unless `--idempotency-key` gives one,
//! and an empty key is refused before any connection. Every server-supplied field prints through
//! [`Scrub`]: one-line fields with [`Scrub::ident`], so no field can start a forged row, and
//! multi-line text (a body, a note, an evidence tail) with [`Scrub::text`], indented so no line of
//! it can start a row either. Evidence read from a file or stdin is bounded before it is sent.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use fleet_core::stamp::utc_stamp;
use fleet_proto::v1::fleet_work_client::FleetWorkClient;
use fleet_proto::v1::{
    AddWorkDepRequest, AddWorkItemRequest, AddWorkNoteRequest, CancelWorkRequest, ClaimWorkRequest,
    CreateWorkProjectRequest, ExportWorkRequest, GetWorkItemRequest, ImportWorkReply,
    ImportWorkRequest, ListWorkDefersRequest, ListWorkItemsRequest, ListWorkProjectsRequest,
    NextWorkRequest, RemoveWorkDepRequest, ReportAttemptRequest, SetWorkSlicesRequest,
    UnblockWorkRequest, WorkAttempt, WorkDefer, WorkDeferState, WorkDep, WorkItem, WorkItemState,
    WorkProject, WorkSlice, WorkVerdict,
};
use fleet_proto::{
    MAX_EXPORT_TASKS_BYTES, MAX_IMPORT_SLICES_BYTES, MAX_IMPORT_TASKS_BYTES, MAX_IMPORT_TEXT_BYTES,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, Scrub};

/// A `FleetWork` client carrying the bearer token.
pub(crate) type WorkClient = FleetWorkClient<InterceptedService<Channel, Bearer>>;

/// Most evidence bytes the command reads. The server refuses more than this too.
const MAX_EVIDENCE_INPUT_BYTES: usize = 262_144;
const NO_PROJECT: &str = "this action needs --project";
const EMPTY_KEY: &str = "the idempotency key is empty";
const BAD_SLICE: &str = "invalid --slice: use NAME=PATH[,PATH...]";
const BAD_EVIDENCE: &str = "evidence is larger than 262144 bytes or not valid UTF-8";
const BAD_IMPORT_FILE: &str = "an import file is a symlink, too large or not valid UTF-8";
const BAD_EXPORT_TARGET: &str = "an export target is a symlink or not a regular file";

/// The arguments of `fleet work`.
#[derive(Debug, Args)]
pub struct WorkArgs {
    /// Work project name. Every action except `project` needs it.
    #[arg(long, short, global = true)]
    project: Option<String>,
    /// Idempotency key of a mutating action. A fresh key is made per invocation when absent.
    #[arg(long, global = true)]
    idempotency_key: Option<String>,
    /// The Work action.
    #[command(subcommand)]
    action: WorkAction,
}

/// A Work item state to filter by.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ItemState {
    /// Open items.
    Open,
    /// Blocked items.
    Blocked,
    /// Cancelled items.
    Cancelled,
}

/// A Defer state to filter by.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DeferState {
    /// Waiting for a decision.
    Open,
    /// Promoted to a Work item.
    Promoted,
    /// Dropped.
    Dropped,
}

/// A `fleet work project` action.
#[derive(Debug, Subcommand)]
pub enum ProjectAction {
    /// Create a Work project.
    Create {
        /// Project name.
        name: String,
        /// Registered repository the project binds to.
        #[arg(long)]
        repo: Option<String>,
    },
    /// List your Work projects.
    List,
}

/// A `fleet work dep` action.
#[derive(Debug, Subcommand)]
pub enum DepAction {
    /// Make an item depend on another.
    Add {
        /// Dependent item key.
        item: String,
        /// Key of the item it depends on.
        depends_on: String,
        /// Why the dependency exists.
        #[arg(long, default_value = "")]
        why: String,
    },
    /// Remove a dependency.
    Remove {
        /// Dependent item key.
        item: String,
        /// Key of the item it depends on.
        depends_on: String,
    },
}

/// A `fleet work` action.
#[derive(Debug, Subcommand)]
pub enum WorkAction {
    /// Create or list Work projects.
    Project {
        /// The project action.
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Replace the slice set and mergeable paths of a project.
    Slices {
        /// A slice as NAME=PATH[,PATH...]. Repeat for each slice.
        #[arg(long = "slice")]
        slices: Vec<String>,
        /// A path that belongs to no slice. Repeat for each path.
        #[arg(long)]
        mergeable: Vec<String>,
    },
    /// Add a Work item.
    Add {
        /// Item key, unique in the project.
        item: String,
        /// Item title.
        title: String,
        /// Item body.
        #[arg(long, default_value = "")]
        body: String,
        /// A slice the item touches. Repeat for each slice.
        #[arg(long = "slice")]
        slices: Vec<String>,
        /// A dependency as KEY or KEY:WHY. Repeat for each dependency.
        #[arg(long = "dep")]
        deps: Vec<String>,
    },
    /// List Work items.
    List {
        /// Only items in this state.
        #[arg(long)]
        state: Option<ItemState>,
        /// Only items that are ready to claim.
        #[arg(long)]
        ready: bool,
    },
    /// Show one item with its attempts and events.
    Show {
        /// Item key.
        item: String,
    },
    /// Add or remove a dependency.
    Dep {
        /// The dependency action.
        #[command(subcommand)]
        action: DepAction,
    },
    /// Cancel an item.
    Cancel {
        /// Item key.
        item: String,
        /// Why it is cancelled.
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Clear a blocked item.
    Unblock {
        /// Item key.
        item: String,
        /// Why it is cleared.
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Show the next ready item.
    Next,
    /// Claim an item and take its slice leases.
    Claim {
        /// Item key.
        item: String,
        /// Who holds the lease.
        #[arg(long)]
        holder: String,
        /// Lease seconds. 0 lets the server pick its default.
        #[arg(long, default_value_t = 0)]
        ttl: u32,
    },
    /// Close an attempt as passed.
    Pass {
        /// Attempt id.
        attempt: u64,
        /// Note on the result.
        #[arg(long, default_value = "")]
        note: String,
        /// File holding the evidence tail, or `-` for stdin.
        #[arg(long)]
        evidence_file: Option<String>,
    },
    /// Close an attempt as failed.
    Fail {
        /// Attempt id.
        attempt: u64,
        /// Note on the result.
        #[arg(long, default_value = "")]
        note: String,
        /// File holding the evidence tail, or `-` for stdin.
        #[arg(long)]
        evidence_file: Option<String>,
    },
    /// Add a note to an item.
    Note {
        /// Item key.
        item: String,
        /// The note.
        note: String,
    },
    /// Import a `.ralph` directory. Dry-run unless `--apply` is given.
    Import {
        /// Directory holding `tasks.json`, `slices.json`, `progress.md` and `docs-backlog.md`.
        dir: PathBuf,
        /// Write the import. Without it the server reports what it would do and writes nothing.
        #[arg(long)]
        apply: bool,
    },
    /// Write `tasks.json` and `slices.json` of the project into a directory.
    Export {
        /// Directory to write into. It must exist.
        dir: PathBuf,
    },
    /// List Defers: work found and left out of scope.
    Defers {
        /// Only Defers of this vertical.
        #[arg(long)]
        vertical: Option<String>,
        /// Only Defers in this state.
        #[arg(long)]
        state: Option<DeferState>,
    },
}

fn key(given: Option<String>) -> Result<String, CliError> {
    match given {
        Some(key) if key.is_empty() => Err(CliError::Usage(EMPTY_KEY.into())),
        Some(key) => Ok(key),
        None => Ok(super::batch::fresh_key()),
    }
}

fn project(given: Option<String>) -> Result<String, CliError> {
    given
        .filter(|name| !name.is_empty())
        .ok_or_else(|| CliError::Usage(NO_PROJECT.into()))
}

fn parse_slice(text: &str) -> Result<WorkSlice, CliError> {
    let bad = || CliError::Usage(BAD_SLICE.into());
    let (name, paths) = text.split_once('=').ok_or_else(bad)?;
    let paths: Vec<String> = paths.split(',').map(str::to_owned).collect();
    if name.is_empty() || paths.iter().any(String::is_empty) {
        return Err(bad());
    }
    Ok(WorkSlice {
        name: name.to_owned(),
        paths,
    })
}

fn parse_dep(text: &str) -> WorkDep {
    let (depends_on, why) = text.split_once(':').unwrap_or((text, ""));
    WorkDep {
        depends_on: depends_on.to_owned(),
        why: why.to_owned(),
    }
}

fn read_evidence(source: Option<&str>, stdin: &mut impl Read) -> Result<String, CliError> {
    let Some(source) = source else {
        return Ok(String::new());
    };
    let limit = MAX_EVIDENCE_INPUT_BYTES as u64 + 1;
    let mut bytes = Vec::new();
    if source == "-" {
        stdin.take(limit).read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(source)?
            .take(limit)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() > MAX_EVIDENCE_INPUT_BYTES {
        return Err(CliError::Usage(BAD_EVIDENCE.into()));
    }
    String::from_utf8(bytes).map_err(|_| CliError::Usage(BAD_EVIDENCE.into()))
}

fn read_import_file(
    dir: &Path,
    name: &str,
    cap: usize,
    required: bool,
) -> Result<String, CliError> {
    let path = dir.join(name);
    let bad = || CliError::Usage(BAD_IMPORT_FILE.into());
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => return Err(bad()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(String::new());
        }
        Err(err) => return Err(err.into()),
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(bad());
    }
    String::from_utf8(bytes).map_err(|_| bad())
}

fn import_request(project: String, dir: &Path, apply: bool) -> Result<ImportWorkRequest, CliError> {
    Ok(ImportWorkRequest {
        project,
        apply,
        tasks_json: read_import_file(dir, "tasks.json", MAX_IMPORT_TASKS_BYTES, true)?,
        slices_json: read_import_file(dir, "slices.json", MAX_IMPORT_SLICES_BYTES, false)?,
        progress_md: read_import_file(dir, "progress.md", MAX_IMPORT_TEXT_BYTES, false)?,
        backlog_md: read_import_file(dir, "docs-backlog.md", MAX_IMPORT_TEXT_BYTES, false)?,
    })
}

fn write_export(dir: &Path, name: &str, text: &str) -> Result<PathBuf, CliError> {
    let target = dir.join(name);
    match std::fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => return Err(CliError::Usage(BAD_EXPORT_TARGET.into())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let temp = dir.join(format!(".{name}.fleet-export"));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::fs::rename(&temp, &target));
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err.into());
    }
    Ok(target)
}

fn print_import(
    out: &mut impl Write,
    scrub: &Scrub,
    reply: &ImportWorkReply,
) -> std::io::Result<()> {
    let mode = if reply.applied { "applied" } else { "dry-run" };
    writeln!(
        out,
        "{mode}\tcreated={}\tunchanged={}\traised={}\tdiffering={}\tslices={}\tmergeable={}\tdefers={}",
        reply.items_created,
        reply.items_unchanged,
        reply.items_raised,
        reply.items_differing,
        reply.slices_created,
        reply.mergeable_created,
        reply.defers_created,
    )?;
    for note in &reply.notes {
        writeln!(out, "note: {}", scrub.ident(note))?;
    }
    for line in &reply.unparsed {
        writeln!(out, "unparsed: {}", scrub.ident(line))?;
    }
    if reply.unparsed_dropped > 0 {
        writeln!(out, "unparsed dropped: {}", reply.unparsed_dropped)?;
    }
    if !reply.applied {
        writeln!(out, "nothing written: pass --apply to import")?;
    }
    Ok(())
}

const fn item_state(state: ItemState) -> WorkItemState {
    match state {
        ItemState::Open => WorkItemState::Open,
        ItemState::Blocked => WorkItemState::Blocked,
        ItemState::Cancelled => WorkItemState::Cancelled,
    }
}

const fn defer_state(state: DeferState) -> WorkDeferState {
    match state {
        DeferState::Open => WorkDeferState::Open,
        DeferState::Promoted => WorkDeferState::Promoted,
        DeferState::Dropped => WorkDeferState::Dropped,
    }
}

fn item_state_name(raw: i32) -> &'static str {
    match WorkItemState::try_from(raw) {
        Ok(WorkItemState::Open) => "open",
        Ok(WorkItemState::Blocked) => "blocked",
        Ok(WorkItemState::Cancelled) => "cancelled",
        _ => "unknown",
    }
}

fn defer_state_name(raw: i32) -> &'static str {
    match WorkDeferState::try_from(raw) {
        Ok(WorkDeferState::Open) => "open",
        Ok(WorkDeferState::Promoted) => "promoted",
        Ok(WorkDeferState::Dropped) => "dropped",
        _ => "unknown",
    }
}

fn verdict_name(raw: Option<i32>) -> &'static str {
    match raw.map(WorkVerdict::try_from) {
        None => "running",
        Some(Ok(WorkVerdict::Pass)) => "pass",
        Some(Ok(WorkVerdict::Fail)) => "fail",
        Some(Ok(WorkVerdict::Lost)) => "lost",
        Some(_) => "unknown",
    }
}

fn dash(scrub: &Scrub, value: Option<&String>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| scrub.ident(v))
}

fn block(scrub: &Scrub, label: &str, text: &str) -> String {
    let mut shown = format!("{label}:\n");
    for line in scrub.text(text).lines() {
        shown.push_str("  ");
        shown.push_str(line);
        shown.push('\n');
    }
    shown
}

fn item_row(scrub: &Scrub, item: &WorkItem) -> String {
    let flag = if item.held {
        "held"
    } else if item.ready {
        "ready"
    } else {
        "-"
    };
    format!(
        "{}\t{}\t{flag}\t{}/{}\t{}",
        scrub.ident(&item.key),
        item_state_name(item.state),
        item.passes,
        item.fails,
        scrub.ident(&item.title),
    )
}

fn attempt_row(scrub: &Scrub, attempt: &WorkAttempt) -> String {
    format!(
        "attempt {}\t{}\t{}\t{}\t{}\t{}",
        attempt.id,
        scrub.ident(&attempt.item_key),
        scrub.ident(&attempt.holder),
        utc_stamp(attempt.claimed_at_ms),
        utc_stamp(attempt.expires_at_ms),
        verdict_name(attempt.verdict),
    )
}

fn project_row(scrub: &Scrub, project: &WorkProject) -> String {
    let slices: Vec<String> = project
        .slices
        .iter()
        .map(|slice| {
            let paths: Vec<String> = slice.paths.iter().map(|p| scrub.ident(p)).collect();
            format!("{}={}", scrub.ident(&slice.name), paths.join(","))
        })
        .collect();
    let mergeable: Vec<String> = project.mergeable.iter().map(|p| scrub.ident(p)).collect();
    format!(
        "{}\t{}\t{}\t{}",
        scrub.ident(&project.name),
        dash(scrub, project.repo.as_ref()),
        slices.join(" "),
        mergeable.join(","),
    )
}

fn defer_row(scrub: &Scrub, defer: &WorkDefer) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        defer.id,
        defer_state_name(defer.state),
        scrub.ident(&defer.vertical),
        dash(scrub, defer.item_key.as_ref()),
        scrub.ident(&defer.title),
        scrub.ident(&defer.reason),
    )
}

fn print_item(out: &mut impl Write, scrub: &Scrub, item: &WorkItem) -> std::io::Result<()> {
    writeln!(out, "{}", item_row(scrub, item))
}

async fn show(
    client: &mut WorkClient,
    scrub: &Scrub,
    request: GetWorkItemRequest,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client.get_work_item(request).await?.into_inner();
    if let Some(item) = &reply.item {
        print_item(out, scrub, item)?;
        let slices: Vec<String> = item.slices.iter().map(|s| scrub.ident(s)).collect();
        writeln!(out, "slices: {}", slices.join(","))?;
        for dep in &item.deps {
            writeln!(
                out,
                "dep: {}\t{}",
                scrub.ident(&dep.depends_on),
                scrub.ident(&dep.why)
            )?;
        }
        write!(out, "{}", block(scrub, "body", &item.body))?;
    }
    for attempt in &reply.attempts {
        writeln!(out, "{}", attempt_row(scrub, attempt))?;
        write!(out, "{}", block(scrub, "note", &attempt.note))?;
        write!(out, "{}", block(scrub, "evidence", &attempt.evidence_tail))?;
    }
    for event in &reply.events {
        writeln!(
            out,
            "event {}\t{}\t{}\t{}\t{}",
            event.id,
            scrub.ident(&event.kind),
            scrub.ident(&event.actor),
            dash(scrub, event.item_key.as_ref()),
            utc_stamp(event.at_ms),
        )?;
        write!(out, "{}", block(scrub, "note", &event.note))?;
    }
    Ok(())
}

/// A `fleet work` action with every argument checked and every request built.
pub(crate) enum Call {
    CreateProject(CreateWorkProjectRequest),
    ListProjects,
    SetSlices(SetWorkSlicesRequest),
    AddItem(AddWorkItemRequest),
    ListItems(ListWorkItemsRequest),
    Show(GetWorkItemRequest),
    AddDep(AddWorkDepRequest),
    RemoveDep(RemoveWorkDepRequest),
    Cancel(CancelWorkRequest),
    Unblock(UnblockWorkRequest),
    Next(NextWorkRequest),
    Claim(ClaimWorkRequest),
    Report(ReportAttemptRequest),
    Note(AddWorkNoteRequest),
    Defers(ListWorkDefersRequest),
    Import(ImportWorkRequest),
    Export(ExportWorkRequest, PathBuf),
}

impl WorkArgs {
    /// Checks the arguments, reads any evidence and builds the request, sending nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for a missing project, an empty key, a malformed slice or bad
    /// evidence, and [`CliError::Io`] when the evidence cannot be read.
    pub(crate) fn prepare(self, stdin: &mut impl Read) -> Result<Call, CliError> {
        let Self {
            project: given,
            idempotency_key,
            action,
        } = self;
        let key = || key(idempotency_key.clone());
        let project = || project(given.clone());
        Ok(match action {
            WorkAction::Project {
                action: ProjectAction::Create { name, repo },
            } => Call::CreateProject(CreateWorkProjectRequest {
                key: key()?,
                name,
                repo,
            }),
            WorkAction::Project {
                action: ProjectAction::List,
            } => Call::ListProjects,
            WorkAction::Slices { slices, mergeable } => Call::SetSlices(SetWorkSlicesRequest {
                key: key()?,
                project: project()?,
                slices: slices
                    .iter()
                    .map(|s| parse_slice(s))
                    .collect::<Result<_, _>>()?,
                mergeable,
            }),
            WorkAction::Add {
                item,
                title,
                body,
                slices,
                deps,
            } => Call::AddItem(AddWorkItemRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                title,
                body,
                slices,
                deps: deps.iter().map(|d| parse_dep(d)).collect(),
            }),
            WorkAction::List { state, ready } => Call::ListItems(ListWorkItemsRequest {
                project: project()?,
                state: state.map(|s| item_state(s) as i32),
                ready_only: ready,
            }),
            WorkAction::Show { item } => Call::Show(GetWorkItemRequest {
                project: project()?,
                item_key: item,
            }),
            WorkAction::Dep {
                action:
                    DepAction::Add {
                        item,
                        depends_on,
                        why,
                    },
            } => Call::AddDep(AddWorkDepRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                dep: Some(WorkDep { depends_on, why }),
            }),
            WorkAction::Dep {
                action: DepAction::Remove { item, depends_on },
            } => Call::RemoveDep(RemoveWorkDepRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                depends_on,
            }),
            other => return Self::prepare_attempt(other, key, project, stdin),
        })
    }

    fn prepare_attempt(
        action: WorkAction,
        key: impl Fn() -> Result<String, CliError>,
        project: impl Fn() -> Result<String, CliError>,
        stdin: &mut impl Read,
    ) -> Result<Call, CliError> {
        Ok(match action {
            WorkAction::Cancel { item, reason } => Call::Cancel(CancelWorkRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                reason,
            }),
            WorkAction::Unblock { item, reason } => Call::Unblock(UnblockWorkRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                reason,
            }),
            WorkAction::Next => Call::Next(NextWorkRequest {
                project: project()?,
            }),
            WorkAction::Claim { item, holder, ttl } => Call::Claim(ClaimWorkRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                holder,
                ttl_secs: ttl,
            }),
            WorkAction::Pass {
                attempt,
                note,
                evidence_file,
            } => Call::Report(verdict(
                key()?,
                project()?,
                (attempt, WorkVerdict::Pass),
                note,
                read_evidence(evidence_file.as_deref(), stdin)?,
            )),
            WorkAction::Fail {
                attempt,
                note,
                evidence_file,
            } => Call::Report(verdict(
                key()?,
                project()?,
                (attempt, WorkVerdict::Fail),
                note,
                read_evidence(evidence_file.as_deref(), stdin)?,
            )),
            WorkAction::Note { item, note } => Call::Note(AddWorkNoteRequest {
                key: key()?,
                project: project()?,
                item_key: item,
                note,
            }),
            WorkAction::Defers { vertical, state } => Call::Defers(ListWorkDefersRequest {
                project: project()?,
                vertical,
                state: state.map(|s| defer_state(s) as i32),
            }),
            WorkAction::Import { dir, apply } => {
                Call::Import(import_request(project()?, &dir, apply)?)
            }
            WorkAction::Export { dir } => Call::Export(
                ExportWorkRequest {
                    project: project()?,
                },
                dir,
            ),
            WorkAction::Project { .. }
            | WorkAction::Slices { .. }
            | WorkAction::Add { .. }
            | WorkAction::List { .. }
            | WorkAction::Show { .. }
            | WorkAction::Dep { .. } => return Err(CliError::Usage(NO_PROJECT.into())),
        })
    }
}

fn verdict(
    key: String,
    project: String,
    (attempt_id, verdict): (u64, WorkVerdict),
    note: String,
    evidence_tail: String,
) -> ReportAttemptRequest {
    ReportAttemptRequest {
        key,
        project,
        attempt_id,
        verdict: verdict as i32,
        note,
        evidence_tail,
    }
}

/// Sends one prepared [`Call`] and prints the reply.
///
/// # Errors
///
/// Returns [`CliError::Rpc`] for a server refusal and [`CliError::Io`] when writing fails.
pub(crate) async fn execute(
    call: Call,
    client: &mut WorkClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match call {
        Call::CreateProject(r) => {
            let reply = client.create_work_project(r).await?.into_inner();
            writeln!(out, "{}", project_row(scrub, &reply))?;
        }
        Call::ListProjects => {
            let reply = client
                .list_work_projects(ListWorkProjectsRequest {})
                .await?
                .into_inner();
            for p in &reply.projects {
                writeln!(out, "{}", project_row(scrub, p))?;
            }
        }
        Call::SetSlices(r) => {
            let reply = client.set_work_slices(r).await?.into_inner();
            writeln!(out, "{}", project_row(scrub, &reply))?;
        }
        Call::AddItem(r) => print_item(out, scrub, &client.add_work_item(r).await?.into_inner())?,
        Call::ListItems(r) => {
            let reply = client.list_work_items(r).await?.into_inner();
            for item in &reply.items {
                print_item(out, scrub, item)?;
            }
        }
        Call::Show(r) => return show(client, scrub, r, out).await,
        Call::AddDep(r) => print_item(out, scrub, &client.add_work_dep(r).await?.into_inner())?,
        Call::RemoveDep(r) => {
            print_item(out, scrub, &client.remove_work_dep(r).await?.into_inner())?;
        }
        Call::Cancel(r) => print_item(out, scrub, &client.cancel_work(r).await?.into_inner())?,
        Call::Unblock(r) => print_item(out, scrub, &client.unblock_work(r).await?.into_inner())?,
        Call::Next(r) => match client.next_work(r).await?.into_inner().item {
            Some(item) => print_item(out, scrub, &item)?,
            None => writeln!(out, "none")?,
        },
        Call::Claim(r) => {
            let attempt = client.claim_work(r).await?.into_inner();
            writeln!(out, "{}", attempt_row(scrub, &attempt))?;
        }
        Call::Report(r) => {
            let attempt = client.report_attempt(r).await?.into_inner();
            writeln!(out, "{}", attempt_row(scrub, &attempt))?;
        }
        Call::Note(r) => {
            let event = client.add_work_note(r).await?.into_inner();
            writeln!(
                out,
                "event {}\t{}\t{}",
                event.id,
                scrub.ident(&event.kind),
                scrub.ident(&event.actor)
            )?;
            write!(out, "{}", block(scrub, "note", &event.note))?;
        }
        Call::Defers(r) => {
            let reply = client.list_work_defers(r).await?.into_inner();
            for defer in &reply.defers {
                writeln!(out, "{}", defer_row(scrub, defer))?;
            }
        }
        Call::Import(r) => {
            let reply = client.import_work(r).await?.into_inner();
            print_import(out, scrub, &reply)?;
        }
        Call::Export(r, dir) => {
            let reply = client.export_work(r).await?.into_inner();
            if reply.tasks_json.len() > MAX_EXPORT_TASKS_BYTES {
                return Err(CliError::Usage(BAD_EXPORT_TARGET.into()));
            }
            for (name, text) in [
                ("tasks.json", &reply.tasks_json),
                ("slices.json", &reply.slices_json),
            ] {
                let path = write_export(&dir, name, text)?;
                writeln!(
                    out,
                    "wrote {}\t{} bytes",
                    scrub.ident(&path.display().to_string()),
                    text.len()
                )?;
            }
        }
    }
    Ok(())
}
