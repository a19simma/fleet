//! The GitHub adapter of [`ForgeApi`]: REST over the injected [`Http`] seam, no `gh` binary.
//!
//! The adapter takes the finished token inside the [`RepoAccess`] it is handed. GitHub App
//! minting stays outside (ADR-0068). Every request goes to `api.github.com`, and only for a
//! repository on `github.com`, so a token never travels to another host.

use std::fmt::{self, Write as _};

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use serde_json::{Value, json};

use crate::{
    ForgeApi, ForgeError, ForgeGit, Git, GitCommand, GitError, GitOp, GitOutput, Http, HttpError,
    HttpRequest, HttpResponse, MAX_BODY_BYTES, Method, Permission, PushTarget, RepoAccess, RepoRef,
    Token, Verified,
};

const API_HOST: &str = "api.github.com";
const WEB_HOST: &str = "github.com";
const API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "fleet-forge";
const MAX_SEGMENT_BYTES: usize = 100;
const MAX_NUMBER_DIGITS: usize = 10;
const MAX_SHA_BYTES: usize = 64;
const LOCK_SUFFIX: &str = ".lock";
const MAX_STDERR_BYTES: usize = 8 * 1024;
const AUTH_MARKERS: [&str; 7] = [
    "authentication failed",
    "invalid username or password",
    "could not read username",
    "could not read password",
    "denied to",
    "returned error: 401",
    "returned error: 403",
];

/// The GitHub adapter: REST over the [`Http`] seam for [`ForgeApi`] and git over HTTPS through the
/// [`Git`] seam for [`ForgeGit`]. It holds the two seams and nothing else, so it has no token to
/// print.
pub struct GitHubForge<H, G> {
    http: H,
    git: G,
}

impl<H, G> fmt::Debug for GitHubForge<H, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubForge").finish_non_exhaustive()
    }
}

impl<H, G> GitHubForge<H, G> {
    /// An adapter that sends REST through `http` and runs git through `git`.
    #[must_use]
    pub const fn new(http: H, git: G) -> Self {
        Self { http, git }
    }
}

impl<H: Http, G: Send + Sync> GitHubForge<H, G> {
    async fn call(
        &self,
        method: Method,
        path: String,
        token: Option<&Token>,
        body: Vec<u8>,
    ) -> Result<HttpResponse, ForgeError> {
        let host = HostName::normalise(API_HOST).map_err(|_| ForgeError::Malformed)?;
        let mut headers = vec![
            (
                "Accept".to_owned(),
                "application/vnd.github+json".to_owned(),
            ),
            ("X-GitHub-Api-Version".to_owned(), API_VERSION.to_owned()),
            ("User-Agent".to_owned(), USER_AGENT.to_owned()),
        ];
        if let Some(token) = token {
            headers.push((
                "Authorization".to_owned(),
                format!("Bearer {}", token.expose()),
            ));
        }
        if !body.is_empty() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        let response = self
            .http
            .send(HttpRequest {
                method,
                host,
                path,
                headers,
                body,
            })
            .await
            .map_err(map_http)?;
        if response.body.len() > MAX_BODY_BYTES {
            return Err(ForgeError::TooLarge);
        }
        Ok(response)
    }

    async fn get(&self, path: String, token: &Token) -> Result<HttpResponse, ForgeError> {
        self.call(Method::Get, path, Some(token), Vec::new()).await
    }

    async fn pull_head(
        &self,
        repo: &RepoRef,
        token: &Token,
        number: u64,
    ) -> Result<String, ForgeError> {
        let path = format!("{}/pulls/{number}", repo_path(repo)?);
        let response = self.get(path, token).await?;
        if response.status != 200 {
            return Err(status_error(response.status));
        }
        let sha = parse(&response)?
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .ok_or(ForgeError::Malformed)?
            .to_owned();
        if valid_sha(&sha) {
            Ok(sha)
        } else {
            Err(ForgeError::Malformed)
        }
    }

    async fn existing_pr(&self, target: &PushTarget, token: &Token) -> Result<String, ForgeError> {
        let repo = target.access().repo();
        let head = encode(&format!("{}:{}", repo.owner(), target.branch()));
        let path = format!(
            "{}/pulls?head={head}&state=open&per_page=1",
            repo_path(repo)?
        );
        let response = self.get(path, token).await?;
        if response.status != 200 {
            return Err(status_error(response.status));
        }
        let first = parse(&response)?
            .as_array()
            .and_then(|list| list.first())
            .and_then(|pull| pull.get("html_url"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ForgeError::Rejected)?;
        pr_number(&first, repo)?;
        Ok(first)
    }

    async fn check_tally(
        &self,
        repo: &RepoRef,
        token: &Token,
        sha: &str,
        tally: &mut Tally,
    ) -> Result<(), ForgeError> {
        let base = repo_path(repo)?;
        let runs = self
            .get(
                format!("{base}/commits/{sha}/check-runs?per_page=100"),
                token,
            )
            .await?;
        if runs.status != 200 {
            return Err(status_error(runs.status));
        }
        tally.add_runs(&parse(&runs)?)?;
        let statuses = self
            .get(format!("{base}/commits/{sha}/status"), token)
            .await?;
        match statuses.status {
            200 => tally.add_statuses(&parse(&statuses)?),
            404 => Ok(()),
            other => Err(status_error(other)),
        }
    }
}

impl<H: Send + Sync, G: Git> GitHubForge<H, G> {
    async fn run_git(
        &self,
        op: GitOp,
        access: &RepoAccess,
        branch: Option<&str>,
    ) -> Result<(), ForgeError> {
        let (repo, _) = bound(access)?;
        let output = self
            .git
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
            Err(classify(op, &output))
        }
    }
}

impl<H: Send + Sync, G: Git> ForgeGit for GitHubForge<H, G> {
    async fn fetch(&self, access: &RepoAccess) -> Result<String, ForgeError> {
        self.run_git(GitOp::Fetch, access, None).await?;
        Ok("fetched".to_owned())
    }

    async fn push(&self, target: &PushTarget) -> Result<String, ForgeError> {
        let branch = ref_name(target.branch())?;
        self.run_git(GitOp::Push, target.access(), Some(branch))
            .await?;
        Ok("pushed".to_owned())
    }
}

impl<H: Http, G: Send + Sync> ForgeApi for GitHubForge<H, G> {
    async fn identify(&self, host: &HostName) -> Result<HostKind, ForgeError> {
        if host.as_str() != WEB_HOST {
            return Err(ForgeError::WrongKind);
        }
        let response = self
            .call(Method::Get, "/rate_limit".to_owned(), None, Vec::new())
            .await?;
        match response.status {
            200 => {}
            300..=399 => return Err(ForgeError::Redirected),
            429 | 500..=599 => return Err(ForgeError::Unavailable),
            _ => return Err(ForgeError::WrongKind),
        }
        let is_github = parse(&response).is_ok_and(|body| {
            body.pointer("/resources/core")
                .is_some_and(Value::is_object)
        });
        if is_github {
            Ok(HostKind::Github)
        } else {
            Err(ForgeError::WrongKind)
        }
    }

    async fn verify(&self, access: &RepoAccess) -> Result<Verified, ForgeError> {
        let (repo, token) = bound(access)?;
        let response = self.get(repo_path(repo)?, token).await?;
        match response.status {
            200 => {}
            401 | 403 | 404 => return Err(ForgeError::NotFound),
            other => return Err(status_error(other)),
        }
        let body = parse(&response)?;
        if !body.is_object() {
            return Err(ForgeError::Malformed);
        }
        let push = match body.get("permissions") {
            None | Some(Value::Null) => Permission::Unknown,
            Some(permissions) => match permissions.get("push") {
                Some(Value::Bool(true)) => Permission::Granted,
                Some(Value::Bool(false)) => Permission::Denied,
                _ => return Err(ForgeError::Malformed),
            },
        };
        Ok(Verified { push })
    }

    async fn create_pr(
        &self,
        target: &PushTarget,
        title: &str,
        body: &str,
    ) -> Result<String, ForgeError> {
        let (repo, token) = bound(target.access())?;
        let payload = json!({
            "title": title,
            "body": body,
            "head": target.branch(),
            "base": target.base(),
        });
        let payload = serde_json::to_vec(&payload).map_err(|_| ForgeError::Malformed)?;
        let path = format!("{}/pulls", repo_path(repo)?);
        let response = self.call(Method::Post, path, Some(token), payload).await?;
        match response.status {
            201 => {
                let url = parse(&response)?
                    .get("html_url")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(ForgeError::Malformed)?;
                pr_number(&url, repo)?;
                Ok(url)
            }
            422 if already_exists(&response) => self.existing_pr(target, token).await,
            other => Err(status_error(other)),
        }
    }

    async fn ci_result(&self, target: &PushTarget, pr_url: &str) -> Result<CiResult, ForgeError> {
        let (repo, token) = bound(target.access())?;
        let number = pr_number(pr_url, repo)?;
        let sha = self.pull_head(repo, token, number).await?;
        let mut tally = Tally::default();
        self.check_tally(repo, token, &sha, &mut tally).await?;
        Ok(tally.result())
    }
}

fn bound(access: &RepoAccess) -> Result<(&RepoRef, &Token), ForgeError> {
    let (repo, token) = access.bind()?;
    if repo.host().as_str() == WEB_HOST {
        Ok((repo, token))
    } else {
        Err(ForgeError::WrongKind)
    }
}

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
fn classify(op: GitOp, output: &GitOutput) -> ForgeError {
    let raw = output.stderr.as_bytes();
    let head = raw
        .get(..MAX_STDERR_BYTES)
        .unwrap_or(raw)
        .to_ascii_lowercase();
    if AUTH_MARKERS.iter().any(|marker| has(&head, marker)) {
        ForgeError::Unauthorized
    } else if has(&head, "repository not found") {
        ForgeError::NotFound
    } else if op == GitOp::Push
        && ["non-fast-forward", "fetch first"]
            .iter()
            .any(|m| has(&head, m))
    {
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
/// ASCII case. The
/// wider hostile set is already refused by `PushTarget::new`.
fn ref_name(text: &str) -> Result<&str, ForgeError> {
    let bad = text
        .split('/')
        .any(|part| part.starts_with('.') || ends_with_lock(part));
    if bad {
        Err(ForgeError::Malformed)
    } else {
        Ok(text)
    }
}

const fn map_http(error: HttpError) -> ForgeError {
    match error {
        HttpError::Timeout => ForgeError::Timeout,
        HttpError::Reset => ForgeError::Unavailable,
        HttpError::BodyTooLarge => ForgeError::TooLarge,
        HttpError::HostRefused => ForgeError::Rejected,
    }
}

const fn status_error(status: u16) -> ForgeError {
    match status {
        300..=399 => ForgeError::Redirected,
        401 | 403 => ForgeError::Unauthorized,
        404 => ForgeError::NotFound,
        429 | 500..=599 => ForgeError::Unavailable,
        400..=499 => ForgeError::Rejected,
        _ => ForgeError::Malformed,
    }
}

fn parse(response: &HttpResponse) -> Result<Value, ForgeError> {
    serde_json::from_slice(&response.body).map_err(|_| ForgeError::Malformed)
}

fn already_exists(response: &HttpResponse) -> bool {
    parse(response).is_ok_and(|body| {
        body.get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| {
                errors.iter().any(|error| {
                    error
                        .get("message")
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.to_ascii_lowercase().contains("already exists"))
                })
            })
    })
}

/// A path segment that is safe to place in a URL path: ASCII letters, digits, `.`, `_` and `-`,
/// at most 100 bytes, never `.` or `..`.
fn segment(text: &str) -> Result<&str, ForgeError> {
    let ok = !text.is_empty()
        && text.len() <= MAX_SEGMENT_BYTES
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(text)
    } else {
        Err(ForgeError::Malformed)
    }
}

fn repo_path(repo: &RepoRef) -> Result<String, ForgeError> {
    Ok(format!(
        "/repos/{}/{}",
        segment(repo.owner())?,
        segment(repo.repo())?
    ))
}

/// Percent-encodes every byte outside the RFC 3986 unreserved set.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn valid_sha(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_SHA_BYTES && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The pull request number of `url`, which must be `https://github.com/{owner}/{repo}/pull/{n}`
/// for `repo`, compared without regard to ASCII case.
fn pr_number(url: &str, repo: &RepoRef) -> Result<u64, ForgeError> {
    let prefix = format!("https://{WEB_HOST}/{}/{}/pull/", repo.owner(), repo.repo());
    let head = url.get(..prefix.len()).ok_or(ForgeError::Malformed)?;
    if !head.eq_ignore_ascii_case(&prefix) {
        return Err(ForgeError::Malformed);
    }
    let tail = url.get(prefix.len()..).ok_or(ForgeError::Malformed)?;
    let digits = !tail.is_empty()
        && tail.len() <= MAX_NUMBER_DIGITS
        && tail.bytes().all(|b| b.is_ascii_digit());
    if !digits {
        return Err(ForgeError::Malformed);
    }
    match tail.parse::<u64>() {
        Ok(number) if number > 0 => Ok(number),
        _ => Err(ForgeError::Malformed),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Neutral,
    Success,
    Queued,
    Running,
    Failed,
}

#[derive(Debug, Default)]
struct Tally(Option<Rank>);

fn entries<'a>(body: &'a Value, key: &str) -> Result<&'a [Value], ForgeError> {
    let list = body
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ForgeError::Malformed)?;
    let incomplete = body
        .get("total_count")
        .and_then(Value::as_u64)
        .is_some_and(|total| total > list.len() as u64);
    if incomplete {
        return Err(ForgeError::Malformed);
    }
    Ok(list)
}

impl Tally {
    fn note(&mut self, rank: Rank) {
        self.0 = self.0.max(Some(rank));
    }

    fn add_runs(&mut self, body: &Value) -> Result<(), ForgeError> {
        for run in entries(body, "check_runs")? {
            let rank = match run.get("status").and_then(Value::as_str) {
                Some("completed") => match run.get("conclusion").and_then(Value::as_str) {
                    Some("success") => Rank::Success,
                    Some("neutral" | "skipped" | "stale") => Rank::Neutral,
                    Some(_) => Rank::Failed,
                    None => return Err(ForgeError::Malformed),
                },
                Some("in_progress") => Rank::Running,
                Some("queued" | "waiting" | "requested" | "pending") => Rank::Queued,
                _ => return Err(ForgeError::Malformed),
            };
            self.note(rank);
        }
        Ok(())
    }

    fn add_statuses(&mut self, body: &Value) -> Result<(), ForgeError> {
        for status in entries(body, "statuses")? {
            let rank = match status.get("state").and_then(Value::as_str) {
                Some("success") => Rank::Success,
                Some("failure" | "error") => Rank::Failed,
                Some("pending") => Rank::Running,
                _ => return Err(ForgeError::Malformed),
            };
            self.note(rank);
        }
        Ok(())
    }

    const fn result(&self) -> CiResult {
        match self.0 {
            None => CiResult::NoChecks,
            Some(Rank::Neutral) => CiResult::Neutral,
            Some(Rank::Success) => CiResult::Success,
            Some(Rank::Queued) => CiResult::Queued,
            Some(Rank::Running) => CiResult::InProgress,
            Some(Rank::Failed) => CiResult::Failure,
        }
    }
}

#[cfg(test)]
mod tests;
