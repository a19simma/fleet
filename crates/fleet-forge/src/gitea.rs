//! The Gitea and Forgejo adapter of [`ForgeApi`]: REST over the injected [`Http`] seam.
//!
//! `identify` probes `GET /api/v1/version` on the host itself. The probe carries no credential
//! and the reply is read as a closed version document. The other operations land in a later task
//! and refuse with [`ForgeError::Unavailable`] until then.

use std::fmt;
use std::future::Future;

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};

use serde_json::Value;

use crate::{
    ForgeApi, ForgeError, Http, HttpError, HttpRequest, MAX_BODY_BYTES, Method, PushTarget,
    RepoAccess, Verified,
};

const VERSION_PATH: &str = "/api/v1/version";
const USER_AGENT: &str = "fleet-forge";
const MAX_VERSION_BYTES: usize = 64;

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

    fn verify(
        &self,
        _access: &RepoAccess,
    ) -> impl Future<Output = Result<Verified, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Unavailable))
    }

    fn create_pr(
        &self,
        _target: &PushTarget,
        _title: &str,
        _body: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Unavailable))
    }

    fn ci_result(
        &self,
        _target: &PushTarget,
        _pr_url: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Unavailable))
    }
}
