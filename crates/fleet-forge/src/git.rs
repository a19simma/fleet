//! The git half both adapters share: ref validation, the runner call and the stderr
//! classification. The token travels in the [`GitCommand`] credential and goes nowhere else.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub on items the sibling adapters share"
)]

use crate::{ForgeError, Git, GitCommand, GitError, GitOp, GitOutput, RepoAccess, RepoRef};

pub(crate) const MAX_STDERR_BYTES: usize = 8 * 1024;
const LOCK_SUFFIX: &str = ".lock";
const AUTH_MARKERS: [&str; 7] = [
    "authentication failed",
    "invalid username or password",
    "could not read username",
    "could not read password",
    "denied to",
    "returned error: 401",
    "returned error: 403",
];
const NON_FAST_FORWARD: &str = "non-fast-forward";
const REJECT_MARKERS: [&str; 2] = [NON_FAST_FORWARD, "fetch first"];
const NOT_FOUND_MARKER: &str = "repository not found";
const MASK: &str = "\u{0}";

const fn map_git(error: GitError) -> ForgeError {
    match error {
        GitError::Spawn => ForgeError::Unavailable,
        GitError::Timeout => ForgeError::Timeout,
    }
}

fn has(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Maps a failed git run to a fixed error from the first [`MAX_STDERR_BYTES`] of stderr, matched
/// without regard to ASCII case. The text itself goes nowhere. Authentication markers win over
/// `non-fast-forward`, and only a push reports [`ForgeError::NonFastForward`].
///
/// The `name -> name` echo of the pushed branch is masked out first, because a branch may spell
/// `non-fast-forward`. The name alone cannot pick the label, and the reason git prints after it
/// still can.
pub(crate) fn classify(op: GitOp, output: &GitOutput, branch: Option<&str>) -> ForgeError {
    let raw = output.stderr.as_bytes();
    let head =
        String::from_utf8_lossy(raw.get(..MAX_STDERR_BYTES).unwrap_or(raw)).to_ascii_lowercase();
    let head = match branch.map(str::to_ascii_lowercase) {
        Some(name) => head.replace(&format!("{name} -> {name}"), MASK),
        None => head,
    };
    let head = head.as_bytes();
    if AUTH_MARKERS.iter().any(|marker| has(head, marker)) {
        ForgeError::Unauthorized
    } else if has(head, NOT_FOUND_MARKER) {
        ForgeError::NotFound
    } else if op == GitOp::Push && REJECT_MARKERS.iter().any(|m| has(head, m)) {
        ForgeError::NonFastForward
    } else {
        ForgeError::Rejected
    }
}

fn ends_with_lock(part: &str) -> bool {
    part.len()
        .checked_sub(LOCK_SUFFIX.len())
        .and_then(|start| part.as_bytes().get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(LOCK_SUFFIX.as_bytes()))
}

/// A branch name git accepts as a ref: no component starts with `.` or ends with `.lock`, in any
/// ASCII case. The wider hostile set is already refused by `PushTarget::new`.
pub(crate) fn ref_name(text: &str) -> Result<&str, ForgeError> {
    let bad = text
        .split('/')
        .any(|part| part.starts_with('.') || ends_with_lock(part));
    if bad {
        Err(ForgeError::Malformed)
    } else {
        Ok(text)
    }
}

/// Runs one git command for `repo`, whose host the caller already bound to the adapter, and maps
/// a failure to a fixed error.
pub(crate) async fn run<G: Git>(
    git: &G,
    op: GitOp,
    repo: &RepoRef,
    access: &RepoAccess,
    branch: Option<&str>,
) -> Result<(), ForgeError> {
    let output = git
        .run(GitCommand {
            op,
            repo: repo.clone(),
            branch: branch.map(str::to_owned),
            credential: access.credential().clone(),
        })
        .await
        .map_err(map_git)?;
    if output.code == 0 {
        Ok(())
    } else {
        Err(classify(op, &output, branch))
    }
}
