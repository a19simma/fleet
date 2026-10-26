//! Job submission input: the one place a client-supplied job request is validated.

use std::fmt;

use fleet_proto::v1::{JobState, ReportJobRequest, SubmitJobRequest};

/// Longest accepted idempotency key, in bytes.
pub const MAX_KEY_BYTES: usize = 128;
/// Longest accepted prompt, in bytes.
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
/// Longest accepted repository URL, in bytes.
pub const MAX_REPO_BYTES: usize = 2048;
/// Longest accepted base ref, in bytes.
pub const MAX_BASE_REF_BYTES: usize = 255;
/// Longest accepted terminal branch, in bytes.
pub const MAX_BRANCH_BYTES: usize = 128;
/// Longest accepted job id, in bytes.
pub const MAX_JOB_ID_BYTES: usize = 64;
pub use fleet_proto::MAX_CHUNKS_PER_REPORT;
/// Transcript rows stored per job. The first chunk past this becomes the marker row.
pub const MAX_TRANSCRIPT_ROWS: i64 = 50_000;
/// Bytes charged against [`MAX_TRANSCRIPT_BYTES`] for any chunk, so empty text still costs.
pub const MIN_CHUNK_COST_BYTES: usize = 64;

/// Transcript bytes stored per job. Chunks past this are dropped after one marker row.
pub const MAX_TRANSCRIPT_BYTES: usize = 4 * 1024 * 1024;
/// Longest stored progress text, in characters. Longer text is cut.
pub const MAX_PROGRESS_CHARS: usize = 200;
/// Longest stored phase, in characters. Longer text is cut.
pub const MAX_PHASE_CHARS: usize = 32;

/// Longest stored error text, in characters. Longer text is cut.
pub const MAX_ERROR_CHARS: usize = 2000;
/// Longest accepted pull request URL, in bytes.
pub const MAX_PR_URL_BYTES: usize = 2048;

/// Why a submit or terminal report was refused. The variants carry no client input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobInvalid {
    /// The idempotency key is empty, too long or has characters outside printable ASCII.
    Key,
    /// The prompt is empty, too long or contains a NUL character.
    Prompt,
    /// The repository is not an `https://` URL of bounded length without whitespace,
    /// backslashes or credentials in the authority.
    Repo,
    /// The base ref is empty, too long, starts with `-` or has whitespace or control
    /// characters.
    BaseRef,
    /// The terminal state is not `SUCCEEDED`, `FAILED` or `CANCELLED`.
    TerminalState,
    /// The pull request URL fails the same rules as the repository URL.
    PrUrl,
    /// The error text contains a NUL character.
    Error,
    /// The branch does not start with `swarm/`, is too long or has whitespace or control
    /// characters.
    Branch,
    /// The job id is empty, too long or has characters outside printable ASCII.
    JobId,
    /// The state filter is not a known job state.
    State,
    /// The stats window has a negative or out-of-range bound, or ends before it starts.
    Window,
    /// A stats filter is empty, too long or contains a NUL character.
    Filter,
    /// The stats grouping is not a known value.
    GroupBy,
}

impl fmt::Display for JobInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Key => "invalid idempotency key",
            Self::Prompt => "invalid prompt",
            Self::Repo => "invalid repo",
            Self::BaseRef => "invalid base ref",
            Self::TerminalState => "invalid terminal state",
            Self::PrUrl => "invalid pr url",
            Self::Error => "invalid error text",
            Self::Branch => "invalid branch",
            Self::JobId => "invalid job id",
            Self::State => "invalid state filter",
            Self::Window => "invalid stats window",
            Self::Filter => "invalid stats filter",
            Self::GroupBy => "invalid stats grouping",
        })
    }
}

impl std::error::Error for JobInvalid {}

/// A validated submit request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    pub(crate) key: String,
    pub(crate) prompt: String,
    pub(crate) repo: String,
    pub(crate) base_ref: String,
    pub(crate) open_pr: bool,
}

/// A validated final report: the state a box ends its job in and the result fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Terminal {
    pub(crate) state: &'static str,
    pub(crate) pr_url: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) branch: Option<String>,
}

fn bare_token(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|b| b.is_ascii_graphic())
}

fn https_url(url: &str, max: usize) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    bare_token(url, max) && !authority.is_empty() && !authority.contains('@') && !url.contains('\\')
}

/// Validates a job id taken from a client request.
///
/// # Errors
///
/// Returns [`JobInvalid::JobId`] without the offending value.
pub(crate) fn validate_job_id(job_id: &str) -> Result<(), JobInvalid> {
    if bare_token(job_id, MAX_JOB_ID_BYTES) {
        Ok(())
    } else {
        Err(JobInvalid::JobId)
    }
}

/// Validates a submit request. This is the only check on these fields.
///
/// # Errors
///
/// Returns the [`JobInvalid`] variant of the first field that fails. It never carries
/// the offending value.
pub fn validate_submit(request: &SubmitJobRequest) -> Result<NewJob, JobInvalid> {
    if !bare_token(&request.idempotency_key, MAX_KEY_BYTES) {
        return Err(JobInvalid::Key);
    }
    if request.prompt.trim().is_empty()
        || request.prompt.len() > MAX_PROMPT_BYTES
        || request.prompt.contains('\0')
    {
        return Err(JobInvalid::Prompt);
    }
    if !https_url(&request.repo, MAX_REPO_BYTES) {
        return Err(JobInvalid::Repo);
    }
    if !bare_token(&request.base_ref, MAX_BASE_REF_BYTES) || request.base_ref.starts_with('-') {
        return Err(JobInvalid::BaseRef);
    }
    Ok(NewJob {
        key: request.idempotency_key.clone(),
        prompt: request.prompt.clone(),
        repo: request.repo.clone(),
        base_ref: request.base_ref.clone(),
        open_pr: request.open_pr,
    })
}

/// Validates the terminal part of a report. A report without `terminal_state` is a
/// progress report and gives `None`; its result fields are ignored.
///
/// # Errors
///
/// Returns the [`JobInvalid`] variant of the first field that fails. It never carries
/// the offending value.
pub(crate) fn validate_terminal(
    request: &ReportJobRequest,
) -> Result<Option<Terminal>, JobInvalid> {
    let Some(raw) = request.terminal_state else {
        return Ok(None);
    };
    let state = match JobState::try_from(raw) {
        Ok(JobState::Succeeded) => "SUCCEEDED",
        Ok(JobState::Failed) => "FAILED",
        Ok(JobState::Cancelled) => "CANCELLED",
        _ => return Err(JobInvalid::TerminalState),
    };
    if let Some(url) = &request.pr_url
        && !https_url(url, MAX_PR_URL_BYTES)
    {
        return Err(JobInvalid::PrUrl);
    }
    if request.error.as_deref().is_some_and(|e| e.contains('\0')) {
        return Err(JobInvalid::Error);
    }
    if let Some(branch) = &request.branch
        && !(bare_token(branch, MAX_BRANCH_BYTES) && branch.starts_with("swarm/"))
    {
        return Err(JobInvalid::Branch);
    }
    Ok(Some(Terminal {
        state,
        pr_url: request.pr_url.clone(),
        error: request
            .error
            .as_ref()
            .map(|e| e.chars().take(MAX_ERROR_CHARS).collect()),
        exit_code: request.exit_code,
        branch: request.branch.clone(),
    }))
}
