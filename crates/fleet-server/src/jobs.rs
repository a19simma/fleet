//! Job submission input: the one place a client-supplied job request is validated.

use std::fmt;

use fleet_proto::v1::SubmitJobRequest;

/// Longest accepted idempotency key, in bytes.
pub const MAX_KEY_BYTES: usize = 128;
/// Longest accepted prompt, in bytes.
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
/// Longest accepted repository URL, in bytes.
pub const MAX_REPO_BYTES: usize = 2048;
/// Longest accepted base ref, in bytes.
pub const MAX_BASE_REF_BYTES: usize = 255;

/// Why a submit request was refused. The variants carry no client input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobInvalid {
    /// The idempotency key is empty, too long or has characters outside printable ASCII.
    Key,
    /// The prompt is empty, too long or contains a NUL character.
    Prompt,
    /// The repository is not an `https://` URL of bounded length without whitespace or
    /// credentials in the authority.
    Repo,
    /// The base ref is empty, too long or has whitespace or control characters.
    BaseRef,
}

impl fmt::Display for JobInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Key => "invalid idempotency key",
            Self::Prompt => "invalid prompt",
            Self::Repo => "invalid repo",
            Self::BaseRef => "invalid base ref",
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

fn bare_token(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|b| b.is_ascii_graphic())
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
    let https = request.repo.strip_prefix("https://").unwrap_or_default();
    let authority = https.split(['/', '?', '#']).next().unwrap_or_default();
    if !bare_token(&request.repo, MAX_REPO_BYTES) || authority.is_empty() || authority.contains('@')
    {
        return Err(JobInvalid::Repo);
    }
    if !bare_token(&request.base_ref, MAX_BASE_REF_BYTES) {
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
