//! The Gitea and Forgejo adapter of [`ForgeApi`]: REST over the injected [`Http`] seam.
//!
//! `identify` probes `GET /api/v1/version` on the host itself. The probe carries no credential
//! and the reply is read as a closed version document. `verify` reads `GET /api/v1/repos/{o}/{r}`
//! with `Authorization: token` for the repository's own host and follows no redirect.
//! `create_pr` posts the pull request and, when the forge answers that one exists, finds the open
//! pull for the exact head branch and returns its URL. `ci_result` reads the pull's head sha, then
//! the combined commit status of that sha, and reads Actions runs for the sha only when the
//! status list is empty.
//!
//! Wire shapes follow the Gitea sources: the combined status is `{state, total_count, statuses}`
//! with each entry's state under `status` (`pending`, `success`, `error`, `failure`, `warning`,
//! `skipped`); a run list is `{total_count, workflow_runs}` with `status` and `conclusion` per
//! run. Both lists page with `page` and `limit`, and the server clamps `limit` to 50 by default.
//! The combined status reports `total_count` as the page length, so a full page cannot be told
//! from a truncated one and is refused.

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use std::fmt;

use serde_json::{Value, json};

use crate::ci::{Rank, Tally, entries, valid_sha};
use crate::{
    ForgeApi, ForgeError, Http, HttpError, HttpRequest, HttpResponse, MAX_BODY_BYTES, Method,
    Permission, PushTarget, RepoAccess, RepoRef, Token, Verified,
};

const VERSION_PATH: &str = "/api/v1/version";
const USER_AGENT: &str = "fleet-forge";
const MAX_VERSION_BYTES: usize = 64;
const MAX_TITLE_BYTES: usize = 256;
const MAX_PR_BODY_BYTES: usize = 64 * 1024;
const MAX_NUMBER_DIGITS: usize = 10;
const PAGE_LIMIT: usize = 50;
const MAX_PAGES: usize = 5;

/// The Gitea and Forgejo REST adapter. It holds the [`Http`] seam and nothing else, so it has no
/// token to print.
pub struct GiteaForge<H> {
    http: H,
}

impl<H> fmt::Debug for GiteaForge<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GiteaForge").finish_non_exhaustive()
    }
}

impl<H: Http> GiteaForge<H> {
    /// An adapter that sends through `http`.
    #[must_use]
    pub const fn new(http: H) -> Self {
        Self { http }
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

/// The repository path. [`RepoRef::new`] already limits both names to 100 bytes of ASCII letters,
/// digits, `.`, `_` and `-`, never `.` or `..`, so they hold no separator or control byte.
fn repo_path(repo: &RepoRef) -> String {
    format!("/api/v1/repos/{}/{}", repo.owner(), repo.repo())
}

/// Whether `body` is the closed version document: a JSON object whose only key is `version`,
/// holding a string of 1 to 64 ASCII letters, digits, `.`, `+`, `-`, `_` or `~`.
fn version_document(body: &[u8]) -> bool {
    let Ok(Value::Object(map)) = serde_json::from_slice(body) else {
        return false;
    };
    map.len() == 1
        && map.get("version").and_then(Value::as_str).is_some_and(|v| {
            !v.is_empty()
                && v.len() <= MAX_VERSION_BYTES
                && v.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_' | b'~')
                })
        })
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

/// Whether a 409 reply says a pull request already exists for the branches: a JSON object whose
/// `message` is a string holding `already exists` in any ASCII case.
fn already_exists(response: &HttpResponse) -> bool {
    parse(response).is_ok_and(|body| {
        body.get("message")
            .and_then(Value::as_str)
            .is_some_and(|text| text.to_ascii_lowercase().contains("already exists"))
    })
}

/// The pull request number of `url`, which must be `https://{host}/{owner}/{repo}/pulls/{n}` for
/// `repo`, compared without regard to ASCII case. The number is 1 to 10 ASCII digits and not zero.
fn pr_number(url: &str, repo: &RepoRef) -> Result<u64, ForgeError> {
    let prefix = format!(
        "https://{}/{}/{}/pulls/",
        repo.host().as_str(),
        repo.owner(),
        repo.repo()
    );
    let head = url.get(..prefix.len()).ok_or(ForgeError::Malformed)?;
    if !head.eq_ignore_ascii_case(&prefix) {
        return Err(ForgeError::Malformed);
    }
    let tail = url.get(prefix.len()..).ok_or(ForgeError::Malformed)?;
    let digits = tail.len() <= MAX_NUMBER_DIGITS && tail.bytes().all(|b| b.is_ascii_digit());
    if !digits {
        return Err(ForgeError::Malformed);
    }
    match tail.parse::<u64>() {
        Ok(number) if number > 0 => Ok(number),
        _ => Err(ForgeError::Malformed),
    }
}

/// Whether `pull` is open from `branch` of `repo` itself: `head.ref` equals the branch byte for
/// byte and `head.repo.full_name` is the repository, compared without regard to ASCII case. A
/// pull from a fork, or without either field, never matches.
fn from_branch(pull: &Value, branch: &str, repo: &RepoRef) -> bool {
    let named = pull.pointer("/head/ref").and_then(Value::as_str) == Some(branch);
    let own = pull
        .pointer("/head/repo/full_name")
        .and_then(Value::as_str)
        .is_some_and(|name| {
            name.eq_ignore_ascii_case(&format!("{}/{}", repo.owner(), repo.repo()))
        });
    named && own
}

impl Tally {
    fn add_commit_statuses(&mut self, list: &[Value]) -> Result<(), ForgeError> {
        for status in list {
            let rank = match status.get("status").and_then(Value::as_str) {
                Some("success") => Rank::Success,
                Some("skipped") => Rank::Neutral,
                Some("failure" | "error" | "warning") => Rank::Failed,
                Some("pending") => Rank::Running,
                _ => return Err(ForgeError::Malformed),
            };
            self.note(rank);
        }
        Ok(())
    }
}

/// The entries under `key` of a page requested with [`PAGE_LIMIT`]. A page at the limit may have
/// a successor, so it fails closed.
fn bounded<'a>(body: &'a Value, key: &str) -> Result<&'a [Value], ForgeError> {
    let list = entries(body, key)?;
    if list.len() >= PAGE_LIMIT {
        return Err(ForgeError::Malformed);
    }
    Ok(list)
}

impl<H: Http> GiteaForge<H> {
    async fn get_json(
        &self,
        repo: &RepoRef,
        path: String,
        token: &Token,
    ) -> Result<Value, ForgeError> {
        let response = self
            .call(Method::Get, repo, path, token, Vec::new())
            .await?;
        if response.status != 200 {
            return Err(status_error(response.status));
        }
        parse(&response)
    }

    async fn pull_head(
        &self,
        repo: &RepoRef,
        token: &Token,
        number: u64,
    ) -> Result<String, ForgeError> {
        let path = format!("{}/pulls/{number}", repo_path(repo));
        let body = self.get_json(repo, path, token).await?;
        let sha = body
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .ok_or(ForgeError::Malformed)?;
        if valid_sha(sha) {
            Ok(sha.to_owned())
        } else {
            Err(ForgeError::Malformed)
        }
    }

    async fn call(
        &self,
        method: Method,
        repo: &RepoRef,
        path: String,
        token: &Token,
        body: Vec<u8>,
    ) -> Result<HttpResponse, ForgeError> {
        let mut headers = vec![
            ("Accept".to_owned(), "application/json".to_owned()),
            ("User-Agent".to_owned(), USER_AGENT.to_owned()),
            (
                "Authorization".to_owned(),
                format!("token {}", token.expose()),
            ),
        ];
        if !body.is_empty() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        let response = self
            .http
            .send(HttpRequest {
                method,
                host: repo.host().clone(),
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

    async fn existing_pr(&self, target: &PushTarget, token: &Token) -> Result<String, ForgeError> {
        let repo = target.access().repo();
        for page in 1..=MAX_PAGES {
            let path = format!(
                "{}/pulls?state=open&page={page}&limit={PAGE_LIMIT}",
                repo_path(repo)
            );
            let response = self
                .call(Method::Get, repo, path, token, Vec::new())
                .await?;
            if response.status != 200 {
                return Err(status_error(response.status));
            }
            let body = parse(&response)?;
            let pulls = body.as_array().ok_or(ForgeError::Malformed)?;
            if pulls.len() > PAGE_LIMIT {
                return Err(ForgeError::Malformed);
            }
            if let Some(pull) = pulls
                .iter()
                .find(|pull| from_branch(pull, target.branch(), repo))
            {
                let url = pull
                    .get("html_url")
                    .and_then(Value::as_str)
                    .ok_or(ForgeError::Malformed)?;
                pr_number(url, repo)?;
                return Ok(url.to_owned());
            }
            if pulls.len() < PAGE_LIMIT {
                break;
            }
        }
        Err(ForgeError::Rejected)
    }
}

impl<H: Http> ForgeApi for GiteaForge<H> {
    async fn identify(&self, host: &HostName) -> Result<HostKind, ForgeError> {
        let response = self
            .http
            .send(HttpRequest {
                method: Method::Get,
                host: host.clone(),
                path: VERSION_PATH.to_owned(),
                headers: vec![
                    ("Accept".to_owned(), "application/json".to_owned()),
                    ("User-Agent".to_owned(), USER_AGENT.to_owned()),
                ],
                body: Vec::new(),
            })
            .await
            .map_err(map_http)?;
        if response.body.len() > MAX_BODY_BYTES {
            return Err(ForgeError::TooLarge);
        }
        match response.status {
            200 => {}
            300..=399 => return Err(ForgeError::Redirected),
            429 | 500..=599 => return Err(ForgeError::Unavailable),
            _ => return Err(ForgeError::WrongKind),
        }
        if version_document(&response.body) {
            Ok(HostKind::Forgejo)
        } else {
            Err(ForgeError::WrongKind)
        }
    }

    async fn verify(&self, access: &RepoAccess) -> Result<Verified, ForgeError> {
        let (repo, token) = access.bind()?;
        let response = self
            .http
            .send(HttpRequest {
                method: Method::Get,
                host: repo.host().clone(),
                path: repo_path(repo),
                headers: vec![
                    ("Accept".to_owned(), "application/json".to_owned()),
                    ("User-Agent".to_owned(), USER_AGENT.to_owned()),
                    (
                        "Authorization".to_owned(),
                        format!("token {}", token.expose()),
                    ),
                ],
                body: Vec::new(),
            })
            .await
            .map_err(map_http)?;
        if response.body.len() > MAX_BODY_BYTES {
            return Err(ForgeError::TooLarge);
        }
        match response.status {
            200 => {}
            300..=399 => return Err(ForgeError::Redirected),
            401 | 403 | 404 => return Err(ForgeError::NotFound),
            429 | 500..=599 => return Err(ForgeError::Unavailable),
            400..=499 => return Err(ForgeError::Rejected),
            _ => return Err(ForgeError::Malformed),
        }
        let body: Value =
            serde_json::from_slice(&response.body).map_err(|_| ForgeError::Malformed)?;
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
        let (repo, token) = target.access().bind()?;
        if title.is_empty() || title.len() > MAX_TITLE_BYTES || body.len() > MAX_PR_BODY_BYTES {
            return Err(ForgeError::Malformed);
        }
        let payload = serde_json::to_vec(&json!({
            "title": title,
            "body": body,
            "head": target.branch(),
            "base": target.base(),
        }))
        .map_err(|_| ForgeError::Malformed)?;
        let path = format!("{}/pulls", repo_path(repo));
        let response = self.call(Method::Post, repo, path, token, payload).await?;
        match response.status {
            201 => {
                let body = parse(&response)?;
                let url = body
                    .get("html_url")
                    .and_then(Value::as_str)
                    .ok_or(ForgeError::Malformed)?;
                pr_number(url, repo)?;
                Ok(url.to_owned())
            }
            409 if already_exists(&response) => self.existing_pr(target, token).await,
            other => Err(status_error(other)),
        }
    }

    async fn ci_result(&self, target: &PushTarget, pr_url: &str) -> Result<CiResult, ForgeError> {
        let (repo, token) = target.access().bind()?;
        let number = pr_number(pr_url, repo)?;
        let sha = self.pull_head(repo, token, number).await?;
        let base = repo_path(repo);
        let path = format!("{base}/commits/{sha}/status?page=1&limit={PAGE_LIMIT}");
        let body = self.get_json(repo, path, token).await?;
        let statuses = bounded(&body, "statuses")?;
        let mut tally = Tally::default();
        if statuses.is_empty() {
            let path = format!("{base}/actions/runs?head_sha={sha}&page=1&limit={PAGE_LIMIT}");
            let body = self.get_json(repo, path, token).await?;
            bounded(&body, "workflow_runs")?;
            tally.add_runs(&body, "workflow_runs")?;
        } else {
            tally.add_commit_statuses(statuses)?;
        }
        Ok(tally.result())
    }
}
