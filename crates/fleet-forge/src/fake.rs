//! In-process fake forge servers behind the shared scenario names of [`crate::contract::Case`].
//!
//! A [`Fake`] implements both seams, [`Http`] and [`Git`]. [`Shape::GitHub`] answers as the GitHub
//! REST API and [`Shape::Gitea`] as the Gitea 1.22 API, for the same [`Case`]. The wire shapes
//! follow the public API documents and stay unverified against a live host until FGJ-28.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fleet_core::host::{HostKind, HostName};
use serde_json::{Value, json};

use crate::contract::Case;
use crate::{
    Git, GitCommand, GitError, GitOp, GitOutput, Http, HttpError, HttpRequest, HttpResponse,
    MAX_BODY_BYTES, Method,
};

/// Which forge the fake imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The GitHub REST API on `api.github.com`.
    GitHub,
    /// The Gitea API under `/api/v1`.
    Gitea,
}

impl Shape {
    /// The host kind an adapter of this shape identifies.
    #[must_use]
    pub const fn kind(self) -> HostKind {
        match self {
            Self::GitHub => HostKind::Github,
            Self::Gitea => HostKind::Forgejo,
        }
    }
}

/// The fake has no scenario for a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingScenario(pub Case);

impl std::fmt::Display for MissingScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fake has no scenario for {}", self.0.name())
    }
}

impl std::error::Error for MissingScenario {}

#[derive(Debug, Default)]
struct State {
    armed: Option<Case>,
    requests: usize,
    redirected: bool,
    replays: usize,
}

/// A fake forge server and git runner. Clones share one state.
#[derive(Debug, Clone)]
pub struct Fake {
    shape: Shape,
    lacking: Arc<Vec<Case>>,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, PartialEq, Eq)]
enum Endpoint {
    Identify,
    Repo,
    Pulls,
    PullByRefs,
    PullNumber,
    Checks,
    Actions,
    Unknown,
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "every reply builder returns the seam result so arms compose"
)]
fn json_reply(status: u16, body: &Value) -> Result<HttpResponse, HttpError> {
    Ok(HttpResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body.to_string().into_bytes(),
    })
}

fn not_found() -> Result<HttpResponse, HttpError> {
    json_reply(404, &json!({"message": "Not Found"}))
}

impl Fake {
    /// The token the harness hands the adapter. Fakes echo whatever token a request carries into
    /// their error bodies, so a leak shows.
    pub const TOKEN: &'static str = "0123456789abcdef0123456789abcdef01234567";

    /// A fake that answers every case.
    #[must_use]
    pub fn new(shape: Shape) -> Self {
        Self::lacking(shape, &[])
    }

    /// A fake without a scenario for each of `cases`, to prove the harness fails on one.
    #[must_use]
    pub fn lacking(shape: Shape, cases: &[Case]) -> Self {
        Self {
            shape,
            lacking: Arc::new(cases.to_vec()),
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// The shape.
    #[must_use]
    pub const fn shape(&self) -> Shape {
        self.shape
    }

    /// The host name an adapter of this shape is pointed at.
    #[must_use]
    pub fn host(&self) -> HostName {
        let text = match self.shape {
            Shape::GitHub => "github.com",
            Shape::Gitea => "git.example.com",
        };
        HostName::normalise(text).unwrap_or_else(|_| unreachable!("fixture host normalises"))
    }

    /// The pull request URL the fake serves for `octo/widgets`.
    #[must_use]
    pub fn pr_url(&self) -> String {
        match self.shape {
            Shape::GitHub => "https://github.com/octo/widgets/pull/7".to_owned(),
            Shape::Gitea => "https://git.example.com/octo/widgets/pulls/7".to_owned(),
        }
    }

    /// Arms `case` and clears the request counters.
    ///
    /// # Errors
    ///
    /// [`MissingScenario`] when the fake has no scenario for the case.
    pub fn arm(&self, case: Case) -> Result<(), MissingScenario> {
        if self.lacking.contains(&case) {
            return Err(MissingScenario(case));
        }
        *self.state() = State {
            armed: Some(case),
            ..State::default()
        };
        Ok(())
    }

    /// HTTP and git requests seen since the last [`Fake::arm`].
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.state().requests
    }

    /// Requests that carried `Authorization` after the fake had served a 3xx.
    #[must_use]
    pub fn authorization_replays(&self) -> usize {
        self.state().replays
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn classify(&self, request: &HttpRequest) -> (Endpoint, Vec<String>) {
        let path = request.path.split('?').next().unwrap_or_default();
        let segments: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let view: Vec<&str> = segments.iter().map(String::as_str).collect();
        let endpoint = match view.as_slice() {
            ["rate_limit"] if self.shape == Shape::GitHub => Endpoint::Identify,
            ["api", "v1", "version"] if self.shape == Shape::Gitea => Endpoint::Identify,
            ["rate_limit"] | ["api", "v1", "version"] => Endpoint::Identify,
            _ => self.classify_repo(&view),
        };
        (endpoint, segments)
    }

    fn classify_repo(&self, view: &[&str]) -> Endpoint {
        let ((Shape::GitHub, ["repos", _, _, rest @ ..])
        | (Shape::Gitea, ["api", "v1", "repos", _, _, rest @ ..])) = (self.shape, view)
        else {
            return Endpoint::Unknown;
        };
        match rest {
            [] => Endpoint::Repo,
            ["pulls"] => Endpoint::Pulls,
            ["pulls", number] if number.bytes().all(|b| b.is_ascii_digit()) => Endpoint::PullNumber,
            ["pulls", _, _, ..] if self.shape == Shape::Gitea => Endpoint::PullByRefs,
            ["commits", _, "check-runs"] if self.shape == Shape::GitHub => Endpoint::Checks,
            ["commits", _, "status"] if self.shape == Shape::Gitea => Endpoint::Checks,
            ["actions", "runs"] => Endpoint::Actions,
            _ => Endpoint::Unknown,
        }
    }

    fn identify_reply(&self, own_path: bool, wrong: bool) -> Result<HttpResponse, HttpError> {
        let serve = match (own_path, wrong) {
            (true, false) => self.shape,
            (_, true) => match self.shape {
                Shape::GitHub => Shape::Gitea,
                Shape::Gitea => Shape::GitHub,
            },
            (false, false) => return not_found(),
        };
        match serve {
            Shape::GitHub => json_reply(200, &json!({"resources": {"core": {"limit": 60}}})),
            Shape::Gitea => json_reply(200, &json!({"version": "1.22.0"})),
        }
    }

    fn repo_reply(case: Case, token: &str) -> Result<HttpResponse, HttpError> {
        let repo = |permissions: Value| {
            let mut body = json!({"full_name": "octo/widgets"});
            if let Some(map) = body.as_object_mut().filter(|_| !permissions.is_null()) {
                map.insert("permissions".to_owned(), permissions);
            }
            json_reply(200, &body)
        };
        match case {
            Case::VerifyReadPush => repo(json!({"admin": false, "push": true, "pull": true})),
            Case::VerifyReadOnly => repo(json!({"admin": false, "push": false, "pull": true})),
            Case::VerifyNoPermissions => repo(Value::Null),
            Case::Verify401 => json_reply(401, &json!({"message": "Bad credentials"})),
            Case::Verify403 => json_reply(403, &json!({"message": "Forbidden"})),
            Case::Verify5xx => json_reply(503, &json!({"message": "unavailable"})),
            Case::VerifyReset => Err(HttpError::Reset),
            Case::VerifySlow => Err(HttpError::Timeout),
            Case::VerifyOverCap => Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: vec![b' '; MAX_BODY_BYTES + 1],
            }),
            Case::VerifyRedirect => Ok(HttpResponse {
                status: 302,
                headers: vec![(
                    "location".to_owned(),
                    "https://redirect.example.net/octo/widgets".to_owned(),
                )],
                body: b"moved".to_vec(),
            }),
            Case::RedactedError => json_reply(
                500,
                &json!({"message": format!("internal error for credential {token}")}),
            ),
            _ => not_found(),
        }
    }

    fn pulls_reply(
        &self,
        case: Case,
        method: Method,
        endpoint: &Endpoint,
        token: &str,
    ) -> Result<HttpResponse, HttpError> {
        let created = json!({
            "number": 7,
            "html_url": self.pr_url(),
            "head": {"ref": "fleet/job-1", "repo": {"full_name": "octo/widgets"}},
        });
        match (case, method, endpoint) {
            (Case::CreatePrOk, Method::Post, Endpoint::Pulls) => json_reply(201, &created),
            (Case::CreatePrExists, Method::Post, Endpoint::Pulls) => match self.shape {
                Shape::GitHub => json_reply(
                    422,
                    &json!({"message": "Validation Failed", "errors": [
                        {"message": "A pull request already exists for octo:fleet/job-1."}
                    ]}),
                ),
                Shape::Gitea => json_reply(
                    409,
                    &json!({"message": "pull request already exists for these targets [id: 7]"}),
                ),
            },
            (Case::CreatePrExists, Method::Get, Endpoint::Pulls) => {
                json_reply(200, &json!([created]))
            }
            (Case::CreatePrExists, Method::Get, Endpoint::PullByRefs) => json_reply(200, &created),
            (Case::CreatePrRejected, Method::Post, Endpoint::Pulls) => json_reply(
                422,
                &json!({"message": format!("Validation Failed for token {token}")}),
            ),
            _ => not_found(),
        }
    }

    fn ci_reply(&self, case: Case, endpoint: &Endpoint) -> Result<HttpResponse, HttpError> {
        let named = |states: &[&'static str]| -> Vec<(String, &'static str)> {
            states
                .iter()
                .enumerate()
                .map(|(index, state)| (format!("check-{index}"), *state))
                .collect()
        };
        let checks: Vec<(String, &'static str)> = match case {
            Case::CiPending => named(&["pending"]),
            Case::CiSuccess => named(&["success"]),
            Case::CiFailure => named(&["failure"]),
            Case::CiMixed => named(&["success", "failure", "pending"]),
            Case::CiNone | Case::CiChecksNone => Vec::new(),
            Case::CiChecksMixed => vec![
                ("build".to_owned(), "success"),
                ("lint".to_owned(), "failure"),
                ("build".to_owned(), "pending"),
            ],
            Case::CiChecksBadName => vec![("bu\nild".to_owned(), "success")],
            Case::CiChecksOverCap => (0..=50)
                .map(|index| (format!("check-{index}"), "success"))
                .collect(),
            _ => return not_found(),
        };
        let states: Vec<&str> = checks.iter().map(|(_, state)| *state).collect();
        match endpoint {
            Endpoint::PullNumber => json_reply(
                200,
                &json!({"number": 7, "html_url": self.pr_url(), "head": {"sha": "abc123"}}),
            ),
            Endpoint::Checks => match self.shape {
                Shape::GitHub => {
                    let runs: Vec<Value> = checks
                        .iter()
                        .map(|(name, state)| match *state {
                            "pending" => {
                                json!({"name": name, "status": "in_progress", "conclusion": null})
                            }
                            other => {
                                json!({"name": name, "status": "completed", "conclusion": other})
                            }
                        })
                        .collect();
                    json_reply(200, &json!({"total_count": runs.len(), "check_runs": runs}))
                }
                Shape::Gitea => {
                    let overall = if states.is_empty() {
                        ""
                    } else if states.contains(&"failure") {
                        "failure"
                    } else if states.iter().all(|s| *s == "success") {
                        "success"
                    } else {
                        "pending"
                    };
                    let statuses: Vec<Value> = checks
                        .iter()
                        .map(|(name, state)| json!({"context": name, "status": state}))
                        .collect();
                    let total = statuses.len();
                    let listed = if statuses.is_empty() {
                        Value::Null
                    } else {
                        Value::Array(statuses)
                    };
                    json_reply(
                        200,
                        &json!({"state": overall, "total_count": total, "statuses": listed}),
                    )
                }
            },
            Endpoint::Actions => json_reply(200, &json!({"total_count": 0, "workflow_runs": []})),
            _ => not_found(),
        }
    }

    fn git_reply(&self, case: Case, command: &GitCommand) -> GitOutput {
        let host = command.credential.host().as_str();
        let auth_failed = match self.shape {
            Shape::GitHub => "remote: Invalid username or password.",
            Shape::Gitea => "remote: Unauthorized",
        };
        let (code, stderr) = match (case, command.op) {
            (Case::PushOk, GitOp::Push) => (
                0,
                format!("To https://{host}/octo/widgets.git\n   1a2b3c4..5d6e7f8  fleet/job-1 -> fleet/job-1\n"),
            ),
            (Case::PushNonFastForward, GitOp::Push) => (
                1,
                " ! [rejected]        fleet/job-1 -> fleet/job-1 (non-fast-forward)\nerror: failed to push some refs\n".to_owned(),
            ),
            (Case::PushRevoked, GitOp::Push) => (
                128,
                format!("{auth_failed}\nfatal: Authentication failed for 'https://{host}/octo/widgets.git/'\n"),
            ),
            (Case::FetchOk, GitOp::Fetch) => (
                0,
                format!("From https://{host}/octo/widgets\n * branch            main       -> FETCH_HEAD\n"),
            ),
            (Case::FetchAuthFailure, GitOp::Fetch) => (
                128,
                format!(
                    "{auth_failed}\nfatal: Authentication failed for 'https://oauth2:{}@{host}/octo/widgets.git/'\n",
                    Self::TOKEN
                ),
            ),
            _ => (1, "fatal: unexpected command\n".to_owned()),
        };
        GitOutput { code, stderr }
    }
}

impl Http for Fake {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        std::future::ready(self.handle(&request))
    }
}

impl Fake {
    fn handle(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let (endpoint, segments) = self.classify(request);
        let authorized = request.header("authorization").is_some();
        let token = request
            .header("authorization")
            .and_then(|value| value.split_whitespace().last())
            .unwrap_or_default()
            .to_owned();
        let case = {
            let mut state = self.state();
            state.requests += 1;
            if state.redirected && authorized {
                state.replays += 1;
            }
            state.armed
        };
        let Some(case) = case else {
            return not_found();
        };
        let own_identify = match (&endpoint, self.shape) {
            (Endpoint::Identify, Shape::GitHub) => {
                segments.first().is_some_and(|s| s == "rate_limit")
            }
            (Endpoint::Identify, Shape::Gitea) => segments.first().is_some_and(|s| s == "api"),
            _ => false,
        };
        let reply = match (&endpoint, case) {
            (Endpoint::Identify, Case::IdentifyOk) => self.identify_reply(own_identify, false),
            (Endpoint::Identify, Case::IdentifyWrongKind) => self.identify_reply(true, true),
            (Endpoint::Identify, Case::IdentifyNonForge) => Ok(HttpResponse {
                status: 200,
                headers: vec![("content-type".to_owned(), "text/html".to_owned())],
                body: b"<html><body>welcome</body></html>".to_vec(),
            }),
            (Endpoint::Repo, _) => Self::repo_reply(case, &token),
            (Endpoint::Pulls | Endpoint::PullByRefs, _) => {
                self.pulls_reply(case, request.method, &endpoint, &token)
            }
            (Endpoint::PullNumber | Endpoint::Checks | Endpoint::Actions, _) => {
                self.ci_reply(case, &endpoint)
            }
            _ => not_found(),
        };
        if matches!(&reply, Ok(response) if response.status == 302) {
            self.state().redirected = true;
        }
        reply
    }
}

impl Git for Fake {
    fn run(&self, command: GitCommand) -> impl Future<Output = Result<GitOutput, GitError>> + Send {
        std::future::ready(Ok(self.handle_git(&command)))
    }
}

impl Fake {
    fn handle_git(&self, command: &GitCommand) -> GitOutput {
        let case = {
            let mut state = self.state();
            state.requests += 1;
            state.armed
        };
        case.map_or_else(
            || GitOutput {
                code: 1,
                stderr: "fatal: no scenario armed\n".to_owned(),
            },
            |case| self.git_reply(case, command),
        )
    }
}
