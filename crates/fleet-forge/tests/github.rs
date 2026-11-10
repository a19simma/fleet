//! Per-adapter tests of `GitHubForge`: the shared contract table on the GitHub fake, then the
//! wire details the table does not cover.

use std::collections::VecDeque;
use std::error::Error;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use fleet_forge::contract::{AdapterSubject, Case, Finding, Op, run_contract};
use fleet_forge::fake::{Fake, Shape};
use fleet_forge::{
    Credential, ForgeApi, ForgeError, ForgeGit, GitHubForge, Http, HttpError, HttpRequest,
    HttpResponse, MAX_BODY_BYTES, Method, Permission, PushTarget, RepoAccess, RepoRef, Token,
    Verified,
};

type TestResult = Result<(), Box<dyn Error>>;
type Items<'a> = Vec<(&'a str, Option<&'a str>)>;

const TOKEN: &str = "0123456789abcdef0123456789abcdef01234567";
const PR_URL: &str = "https://github.com/octo/widgets/pull/7";

struct ApiOnly<A>(A);

impl<A: ForgeApi> ForgeApi for ApiOnly<A> {
    fn identify(
        &self,
        host: &HostName,
    ) -> impl Future<Output = Result<HostKind, ForgeError>> + Send {
        self.0.identify(host)
    }

    fn verify(
        &self,
        access: &RepoAccess,
    ) -> impl Future<Output = Result<Verified, ForgeError>> + Send {
        self.0.verify(access)
    }

    fn create_pr(
        &self,
        target: &PushTarget,
        title: &str,
        body: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        self.0.create_pr(target, title, body)
    }

    fn ci_result(
        &self,
        target: &PushTarget,
        pr_url: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        self.0.ci_result(target, pr_url)
    }
}

impl<A: Send + Sync> ForgeGit for ApiOnly<A> {
    fn fetch(&self, _: &RepoAccess) -> impl Future<Output = Result<String, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Unavailable))
    }

    fn push(&self, _: &PushTarget) -> impl Future<Output = Result<String, ForgeError>> + Send {
        std::future::ready(Err(ForgeError::Unavailable))
    }
}

const fn case_of(finding: &Finding) -> Case {
    match finding {
        Finding::FakeLacksCase(case)
        | Finding::SubjectLacksCase(case)
        | Finding::AuthorizationReplayed(case)
        | Finding::TokenLeaked(case)
        | Finding::Mismatch { case, .. }
        | Finding::Calls { case, .. } => *case,
    }
}

#[tokio::test]
async fn every_forge_api_case_passes_on_the_github_fake() {
    let subject = AdapterSubject(|fake: &Fake| ApiOnly(GitHubForge::new(fake.clone())));
    let report = run_contract(&subject, Shape::GitHub, || Fake::new(Shape::GitHub)).await;
    let api_findings: Vec<String> = report
        .findings
        .iter()
        .filter(|f| !matches!(case_of(f).op(), Op::Push | Op::Fetch))
        .map(ToString::to_string)
        .collect();
    assert!(api_findings.is_empty(), "{api_findings:?}");
    let api_cases = Case::ALL
        .iter()
        .filter(|c| !matches!(c.op(), Op::Push | Op::Fetch))
        .count();
    let ran_api = report
        .ran
        .iter()
        .filter(|c| !matches!(c.op(), Op::Push | Op::Fetch))
        .count();
    assert_eq!(ran_api, api_cases);
    assert_eq!(api_cases, 25);
}

#[derive(Clone, Default)]
struct Script {
    replies: Arc<Mutex<VecDeque<Result<HttpResponse, HttpError>>>>,
    seen: Arc<Mutex<Vec<HttpRequest>>>,
}

impl Script {
    fn reply(self, status: u16, body: &str) -> Self {
        self.push(Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }))
    }

    fn raw(self, status: u16, body: Vec<u8>) -> Self {
        self.push(Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body,
        }))
    }

    fn fail(self, error: HttpError) -> Self {
        self.push(Err(error))
    }

    fn push(self, reply: Result<HttpResponse, HttpError>) -> Self {
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(reply);
        self
    }

    fn seen(&self) -> Vec<HttpRequest> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Http for Script {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        let reply = self
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or(Err(HttpError::Reset));
        std::future::ready(reply)
    }
}

fn host(text: &str) -> Result<HostName, Box<dyn Error>> {
    Ok(HostName::normalise(text)?)
}

fn access_on(repo_host: &str, credential_host: &str) -> Result<RepoAccess, Box<dyn Error>> {
    let repo = RepoRef::new(host(repo_host)?, "octo", "widgets")?;
    let credential = Credential::new(host(credential_host)?, Token::new(TOKEN.to_owned())?);
    Ok(RepoAccess::new(repo, credential))
}

fn access() -> Result<RepoAccess, Box<dyn Error>> {
    access_on("github.com", "github.com")
}

fn target() -> Result<PushTarget, Box<dyn Error>> {
    Ok(PushTarget::new(access()?, "fleet/job-1", "main")?)
}

fn forge(script: &Script) -> GitHubForge<Script> {
    GitHubForge::new(script.clone())
}

fn pull(sha: &str) -> String {
    format!(r#"{{"number":7,"head":{{"sha":"{sha}"}}}}"#)
}

fn runs(items: &[(&str, Option<&str>)]) -> String {
    let list: Vec<String> = items
        .iter()
        .map(|(status, conclusion)| {
            let conclusion = conclusion.map_or_else(|| "null".to_owned(), |c| format!("\"{c}\""));
            format!(r#"{{"status":"{status}","conclusion":{conclusion}}}"#)
        })
        .collect();
    format!(
        r#"{{"total_count":{},"check_runs":[{}]}}"#,
        list.len(),
        list.join(",")
    )
}

fn statuses(states: &[&str]) -> String {
    let list: Vec<String> = states
        .iter()
        .map(|s| format!(r#"{{"state":"{s}"}}"#))
        .collect();
    format!(
        r#"{{"state":"x","total_count":{},"statuses":[{}]}}"#,
        list.len(),
        list.join(",")
    )
}

async fn ci(
    items: &[(&str, Option<&str>)],
    states: Option<&[&str]>,
) -> Result<CiResult, ForgeError> {
    let script = Script::default()
        .reply(200, &pull("abc123"))
        .reply(200, &runs(items));
    let script = match states {
        Some(states) => script.reply(200, &statuses(states)),
        None => script.reply(404, "{}"),
    };
    let target = target().map_err(|_| ForgeError::Malformed)?;
    forge(&script).ci_result(&target, PR_URL).await
}

#[tokio::test]
async fn verify_sends_one_authenticated_get_to_the_api_host() -> TestResult {
    let script = Script::default().reply(200, r#"{"permissions":{"push":true}}"#);
    let verified = forge(&script).verify(&access()?).await?;
    assert_eq!(verified.push, Permission::Granted);
    let seen = script.seen();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.host.as_str(), "api.github.com");
    assert_eq!(request.path, "/repos/octo/widgets");
    assert_eq!(
        request.header("authorization"),
        Some(&*format!("Bearer {TOKEN}"))
    );
    assert_eq!(
        request.header("accept"),
        Some("application/vnd.github+json")
    );
    assert_eq!(request.header("x-github-api-version"), Some("2022-11-28"));
    assert!(request.header("user-agent").is_some());
    assert_eq!(request.body.len(), 0);
    assert!(!request.path.contains(TOKEN));
    Ok(())
}

#[tokio::test]
async fn verify_reads_push_false_and_a_missing_or_null_permissions() -> TestResult {
    let table = [
        (r#"{"permissions":{"push":false}}"#, Permission::Denied),
        (r#"{"permissions":null}"#, Permission::Unknown),
        (r#"{"full_name":"octo/widgets"}"#, Permission::Unknown),
    ];
    for (body, expected) in table {
        let script = Script::default().reply(200, body);
        assert_eq!(
            forge(&script).verify(&access()?).await?.push,
            expected,
            "{body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn verify_refuses_hostile_response_bodies() -> TestResult {
    let nested = "[".repeat(200_000);
    let wrong = [
        "",
        "{",
        "null",
        "[]",
        "3",
        "\"x\"",
        "<html></html>",
        r#"{"permissions":[]}"#,
        r#"{"permissions":3}"#,
        r#"{"permissions":{}}"#,
        r#"{"permissions":{"push":"true"}}"#,
        r#"{"permissions":{"push":1}}"#,
        r#"{"permissions":{"push":null}}"#,
        nested.as_str(),
    ];
    for body in wrong {
        let script = Script::default().reply(200, body);
        let got = forge(&script).verify(&access()?).await;
        assert_eq!(
            got.err(),
            Some(ForgeError::Malformed),
            "{:?}",
            body.get(..20)
        );
    }
    Ok(())
}

#[tokio::test]
async fn verify_checks_the_body_cap_itself() -> TestResult {
    let at_cap = format!(
        "{{\"permissions\":null}}{}",
        " ".repeat(MAX_BODY_BYTES - 20)
    );
    assert_eq!(at_cap.len(), MAX_BODY_BYTES);
    let script = Script::default().reply(200, &at_cap);
    assert_eq!(
        forge(&script).verify(&access()?).await?.push,
        Permission::Unknown
    );
    let script = Script::default().raw(200, vec![b' '; MAX_BODY_BYTES + 1]);
    assert_eq!(
        forge(&script).verify(&access()?).await.err(),
        Some(ForgeError::TooLarge)
    );
    let script = Script::default().raw(404, vec![b' '; MAX_BODY_BYTES + 1]);
    assert_eq!(
        forge(&script).verify(&access()?).await.err(),
        Some(ForgeError::TooLarge)
    );
    Ok(())
}

#[tokio::test]
async fn verify_maps_status_and_transport_errors() -> TestResult {
    let statuses = [
        (301, ForgeError::Redirected),
        (400, ForgeError::Rejected),
        (401, ForgeError::NotFound),
        (403, ForgeError::NotFound),
        (404, ForgeError::NotFound),
        (429, ForgeError::Unavailable),
        (502, ForgeError::Unavailable),
        (204, ForgeError::Malformed),
    ];
    for (status, expected) in statuses {
        let script = Script::default().reply(status, "{}");
        assert_eq!(
            forge(&script).verify(&access()?).await.err(),
            Some(expected),
            "{status}"
        );
    }
    let transport = [
        (HttpError::Timeout, ForgeError::Timeout),
        (HttpError::Reset, ForgeError::Unavailable),
        (HttpError::BodyTooLarge, ForgeError::TooLarge),
        (HttpError::HostRefused, ForgeError::Rejected),
    ];
    for (error, expected) in transport {
        let script = Script::default().fail(error);
        assert_eq!(
            forge(&script).verify(&access()?).await.err(),
            Some(expected),
            "{error}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_repository_off_github_com_or_a_foreign_credential_sends_nothing() -> TestResult {
    let script = Script::default().reply(200, "{}");
    let other = access_on("git.example.com", "git.example.com")?;
    assert_eq!(
        forge(&script).verify(&other).await.err(),
        Some(ForgeError::WrongKind)
    );
    let mismatch = access_on("github.com", "git.example.com")?;
    assert_eq!(
        forge(&script).verify(&mismatch).await.err(),
        Some(ForgeError::HostMismatch)
    );
    let off = PushTarget::new(other, "fleet/job-1", "main")?;
    assert_eq!(
        forge(&script).create_pr(&off, "t", "b").await.err(),
        Some(ForgeError::WrongKind)
    );
    assert_eq!(
        forge(&script).ci_result(&off, PR_URL).await.err(),
        Some(ForgeError::WrongKind)
    );
    let foreign = PushTarget::new(mismatch, "fleet/job-1", "main")?;
    assert_eq!(
        forge(&script).create_pr(&foreign, "t", "b").await.err(),
        Some(ForgeError::HostMismatch)
    );
    assert_eq!(script.seen().len(), 0);
    Ok(())
}

#[tokio::test]
async fn identify_sends_no_credential_and_only_for_github_com() -> TestResult {
    let script = Script::default().reply(200, r#"{"resources":{"core":{"limit":60}}}"#);
    assert_eq!(
        forge(&script).identify(&host("github.com")?).await?,
        HostKind::Github
    );
    let seen = script.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/rate_limit");
    assert_eq!(seen[0].host.as_str(), "api.github.com");
    assert!(seen[0].header("authorization").is_none());
    let script = Script::default().reply(200, r#"{"resources":{"core":{}}}"#);
    let got = forge(&script).identify(&host("git.example.com")?).await;
    assert_eq!(got.err(), Some(ForgeError::WrongKind));
    assert_eq!(script.seen().len(), 0);
    Ok(())
}

#[tokio::test]
async fn identify_maps_status_and_refuses_other_bodies() -> TestResult {
    let statuses = [
        (302, ForgeError::Redirected),
        (404, ForgeError::WrongKind),
        (401, ForgeError::WrongKind),
        (429, ForgeError::Unavailable),
        (503, ForgeError::Unavailable),
    ];
    for (status, expected) in statuses {
        let script = Script::default().reply(status, "{}");
        let got = forge(&script).identify(&host("github.com")?).await;
        assert_eq!(got.err(), Some(expected), "{status}");
    }
    let bodies = [
        "",
        "{",
        "null",
        "[]",
        r#"{"resources":3}"#,
        r#"{"resources":{"core":3}}"#,
        r#"{"resources":{"core":null}}"#,
        r#"{"version":"1.22.0"}"#,
    ];
    for body in bodies {
        let script = Script::default().reply(200, body);
        let got = forge(&script).identify(&host("github.com")?).await;
        assert_eq!(got.err(), Some(ForgeError::WrongKind), "{body}");
    }
    let script = Script::default().raw(200, vec![b' '; MAX_BODY_BYTES + 1]);
    let got = forge(&script).identify(&host("github.com")?).await;
    assert_eq!(got.err(), Some(ForgeError::TooLarge));
    Ok(())
}

#[tokio::test]
async fn create_pr_posts_a_pull_with_the_job_branch() -> TestResult {
    let script = Script::default().reply(201, &format!(r#"{{"html_url":"{PR_URL}"}}"#));
    let url = forge(&script)
        .create_pr(&target()?, "A \"title\"\n", "body")
        .await?;
    assert_eq!(url, PR_URL);
    let seen = script.seen();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::Post);
    assert_eq!(request.host.as_str(), "api.github.com");
    assert_eq!(request.path, "/repos/octo/widgets/pulls");
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("authorization"),
        Some(&*format!("Bearer {TOKEN}"))
    );
    let sent: serde_json::Value = serde_json::from_slice(&request.body)?;
    assert_eq!(sent["title"], "A \"title\"\n");
    assert_eq!(sent["body"], "body");
    assert_eq!(sent["head"], "fleet/job-1");
    assert_eq!(sent["base"], "main");
    assert!(!String::from_utf8_lossy(&request.body).contains(TOKEN));
    Ok(())
}

#[tokio::test]
async fn create_pr_refuses_a_created_url_it_cannot_trust() -> TestResult {
    let bad = [
        "{}",
        r#"{"html_url":3}"#,
        r#"{"html_url":null}"#,
        r#"{"html_url":"https://evil.example/octo/widgets/pull/7"}"#,
        r#"{"html_url":"https://github.com/octo/other/pull/7"}"#,
        r#"{"html_url":"http://github.com/octo/widgets/pull/7"}"#,
        r#"{"html_url":"https://github.com/octo/widgets/pull/7\r\nX: y"}"#,
        "[]",
        "{",
        "",
    ];
    for body in bad {
        let script = Script::default().reply(201, body);
        let got = forge(&script).create_pr(&target()?, "t", "b").await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{body}");
    }
    let script = Script::default().reply(200, &format!(r#"{{"html_url":"{PR_URL}"}}"#));
    let got = forge(&script).create_pr(&target()?, "t", "b").await;
    assert_eq!(got.err(), Some(ForgeError::Malformed));
    Ok(())
}

#[tokio::test]
async fn create_pr_maps_status_codes() -> TestResult {
    let table = [
        (401, ForgeError::Unauthorized),
        (403, ForgeError::Unauthorized),
        (404, ForgeError::NotFound),
        (422, ForgeError::Rejected),
        (500, ForgeError::Unavailable),
        (302, ForgeError::Redirected),
    ];
    for (status, expected) in table {
        let script = Script::default().reply(status, "{}");
        let got = forge(&script).create_pr(&target()?, "t", "b").await;
        assert_eq!(got.err(), Some(expected), "{status}");
        assert_eq!(script.seen().len(), 1, "{status}");
    }
    Ok(())
}

const EXISTS: &str = r#"{"message":"Validation Failed","errors":[{"message":"A pull request already exists for octo:fleet/job-1."}]}"#;

#[tokio::test]
async fn create_pr_on_an_existing_pull_returns_the_existing_url() -> TestResult {
    let script = Script::default()
        .reply(422, EXISTS)
        .reply(200, &format!(r#"[{{"html_url":"{PR_URL}"}}]"#));
    let url = forge(&script).create_pr(&target()?, "t", "b").await?;
    assert_eq!(url, PR_URL);
    let seen = script.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].method, Method::Get);
    assert_eq!(
        seen[1].path,
        "/repos/octo/widgets/pulls?head=octo%3Afleet%2Fjob-1&state=open&per_page=1"
    );
    assert_eq!(
        seen[1].header("authorization"),
        Some(&*format!("Bearer {TOKEN}"))
    );
    Ok(())
}

#[tokio::test]
async fn create_pr_exists_detection_is_case_blind_and_exact_to_the_message() -> TestResult {
    let loud = r#"{"errors":[{"message":"x"},{"message":"PULL REQUEST ALREADY EXISTS"}]}"#;
    let script = Script::default()
        .reply(422, loud)
        .reply(200, &format!(r#"[{{"html_url":"{PR_URL}"}}]"#));
    assert_eq!(
        forge(&script).create_pr(&target()?, "t", "b").await?,
        PR_URL
    );
    let other = [
        r#"{"errors":[{"message":"No commits between main and fleet/job-1"}]}"#,
        r#"{"errors":[{"message":3}]}"#,
        r#"{"errors":[]}"#,
        r#"{"errors":"already exists"}"#,
        r#"{"message":"already exists"}"#,
        "not json",
        "",
    ];
    for body in other {
        let script = Script::default().reply(422, body);
        let got = forge(&script).create_pr(&target()?, "t", "b").await;
        assert_eq!(got.err(), Some(ForgeError::Rejected), "{body}");
        assert_eq!(script.seen().len(), 1, "{body}");
    }
    Ok(())
}

#[tokio::test]
async fn create_pr_exists_with_no_findable_pull_fails_closed() -> TestResult {
    let lookups = [
        (200, "[]", ForgeError::Rejected),
        (200, "{}", ForgeError::Rejected),
        (200, r#"[{"html_url":3}]"#, ForgeError::Rejected),
        (200, r#"[{"number":7}]"#, ForgeError::Rejected),
        (
            200,
            r#"[{"html_url":"https://evil.example/octo/widgets/pull/7"}]"#,
            ForgeError::Malformed,
        ),
        (404, "{}", ForgeError::NotFound),
        (500, "{}", ForgeError::Unavailable),
        (200, "{", ForgeError::Malformed),
    ];
    for (status, body, expected) in lookups {
        let script = Script::default().reply(422, EXISTS).reply(status, body);
        let got = forge(&script).create_pr(&target()?, "t", "b").await;
        assert_eq!(got.err(), Some(expected), "{body}");
    }
    let script = Script::default()
        .reply(422, EXISTS)
        .raw(200, vec![b' '; MAX_BODY_BYTES + 1]);
    let got = forge(&script).create_pr(&target()?, "t", "b").await;
    assert_eq!(got.err(), Some(ForgeError::TooLarge));
    Ok(())
}

#[tokio::test]
async fn create_pr_checks_the_cap_on_the_exists_body() -> TestResult {
    let script = Script::default().raw(422, vec![b' '; MAX_BODY_BYTES + 1]);
    let got = forge(&script).create_pr(&target()?, "t", "b").await;
    assert_eq!(got.err(), Some(ForgeError::TooLarge));
    Ok(())
}

#[tokio::test]
async fn ci_result_reads_the_head_then_checks_then_statuses() -> TestResult {
    let script = Script::default()
        .reply(200, &pull("abc123"))
        .reply(200, &runs(&[("completed", Some("success"))]))
        .reply(200, &statuses(&[]));
    assert_eq!(
        forge(&script).ci_result(&target()?, PR_URL).await?,
        CiResult::Success
    );
    let seen = script.seen();
    let paths: Vec<&str> = seen.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/repos/octo/widgets/pulls/7",
            "/repos/octo/widgets/commits/abc123/check-runs?per_page=100",
            "/repos/octo/widgets/commits/abc123/status",
        ]
    );
    for request in &seen {
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.host.as_str(), "api.github.com");
        assert_eq!(
            request.header("authorization"),
            Some(&*format!("Bearer {TOKEN}"))
        );
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one literal table of every mapping row"
)]
async fn ci_result_maps_every_variant() -> TestResult {
    let table: Vec<(Items<'_>, Option<Vec<&str>>, CiResult)> = vec![
        (vec![], None, CiResult::NoChecks),
        (vec![], Some(vec![]), CiResult::NoChecks),
        (vec![("queued", None)], None, CiResult::Queued),
        (vec![("waiting", None)], None, CiResult::Queued),
        (vec![("requested", None)], None, CiResult::Queued),
        (vec![("pending", None)], None, CiResult::Queued),
        (vec![("in_progress", None)], None, CiResult::InProgress),
        (
            vec![("completed", Some("success"))],
            None,
            CiResult::Success,
        ),
        (
            vec![("completed", Some("neutral"))],
            None,
            CiResult::Neutral,
        ),
        (
            vec![("completed", Some("skipped"))],
            None,
            CiResult::Neutral,
        ),
        (vec![("completed", Some("stale"))], None, CiResult::Neutral),
        (
            vec![
                ("completed", Some("neutral")),
                ("completed", Some("skipped")),
            ],
            None,
            CiResult::Neutral,
        ),
        (
            vec![
                ("completed", Some("success")),
                ("completed", Some("skipped")),
            ],
            None,
            CiResult::Success,
        ),
        (
            vec![("completed", Some("success")), ("queued", None)],
            None,
            CiResult::Queued,
        ),
        (
            vec![
                ("completed", Some("success")),
                ("queued", None),
                ("in_progress", None),
            ],
            None,
            CiResult::InProgress,
        ),
        (
            vec![("completed", Some("failure")), ("in_progress", None)],
            None,
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("timed_out"))],
            None,
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("cancelled"))],
            None,
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("action_required"))],
            None,
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("startup_failure"))],
            None,
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("something_new"))],
            None,
            CiResult::Failure,
        ),
        (vec![], Some(vec!["success"]), CiResult::Success),
        (vec![], Some(vec!["pending"]), CiResult::InProgress),
        (vec![], Some(vec!["failure"]), CiResult::Failure),
        (vec![], Some(vec!["error"]), CiResult::Failure),
        (
            vec![("completed", Some("success"))],
            Some(vec!["failure"]),
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("success"))],
            Some(vec!["pending"]),
            CiResult::InProgress,
        ),
        (
            vec![("completed", Some("neutral"))],
            Some(vec!["success"]),
            CiResult::Success,
        ),
        (
            vec![("queued", None)],
            Some(vec!["success"]),
            CiResult::Queued,
        ),
    ];
    for (items, states, expected) in table {
        let got = ci(&items, states.as_deref()).await;
        assert_eq!(got, Ok(expected), "{items:?} {states:?}");
    }
    Ok(())
}

#[tokio::test]
async fn ci_result_refuses_malformed_check_data() -> TestResult {
    let target = target()?;
    let bad_runs = [
        "",
        "{",
        "[]",
        "{}",
        r#"{"check_runs":3}"#,
        r#"{"check_runs":{}}"#,
        r#"{"check_runs":[3]}"#,
        r#"{"check_runs":[{}]}"#,
        r#"{"check_runs":[{"status":3}]}"#,
        r#"{"check_runs":[{"status":"weird"}]}"#,
        r#"{"check_runs":[{"status":"completed"}]}"#,
        r#"{"check_runs":[{"status":"completed","conclusion":null}]}"#,
        r#"{"check_runs":[{"status":"completed","conclusion":3}]}"#,
        r#"{"total_count":2,"check_runs":[{"status":"queued"}]}"#,
    ];
    for body in bad_runs {
        let script = Script::default()
            .reply(200, &pull("abc123"))
            .reply(200, body);
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{body}");
    }
    let bad_statuses = [
        "",
        "[]",
        "{}",
        r#"{"statuses":3}"#,
        r#"{"statuses":[3]}"#,
        r#"{"statuses":[{}]}"#,
        r#"{"statuses":[{"state":"weird"}]}"#,
        r#"{"statuses":[{"state":3}]}"#,
        r#"{"total_count":2,"statuses":[{"state":"success"}]}"#,
    ];
    for body in bad_statuses {
        let script = Script::default()
            .reply(200, &pull("abc123"))
            .reply(200, &runs(&[]))
            .reply(200, body);
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{body}");
    }
    Ok(())
}

#[tokio::test]
async fn ci_result_refuses_a_pull_without_a_usable_head() -> TestResult {
    let target = target()?;
    let bad = [
        "",
        "{",
        "[]",
        "{}",
        r#"{"head":3}"#,
        r#"{"head":{}}"#,
        r#"{"head":{"sha":3}}"#,
        r#"{"head":{"sha":""}}"#,
        r#"{"head":{"sha":"../../x"}}"#,
        r#"{"head":{"sha":"abc/def"}}"#,
        r#"{"head":{"sha":"abc def"}}"#,
        r#"{"head":{"sha":"abc?x=1"}}"#,
    ];
    for body in bad {
        let script = Script::default().reply(200, body);
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{body}");
        assert_eq!(script.seen().len(), 1, "{body}");
    }
    Ok(())
}

#[tokio::test]
async fn ci_result_maps_status_and_cap_on_every_step() -> TestResult {
    let target = target()?;
    let first = [
        (404, ForgeError::NotFound),
        (401, ForgeError::Unauthorized),
        (403, ForgeError::Unauthorized),
        (500, ForgeError::Unavailable),
        (302, ForgeError::Redirected),
        (204, ForgeError::Malformed),
    ];
    for (status, expected) in first {
        let script = Script::default().reply(status, "{}");
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(expected), "pull {status}");
    }
    for (status, expected) in first {
        let script = Script::default()
            .reply(200, &pull("abc123"))
            .reply(status, "{}");
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(expected), "runs {status}");
    }
    for (status, expected) in first.into_iter().filter(|(s, _)| *s != 404) {
        let script = Script::default()
            .reply(200, &pull("abc123"))
            .reply(200, &runs(&[]))
            .reply(status, "{}");
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(expected), "status {status}");
    }
    let big = vec![b' '; MAX_BODY_BYTES + 1];
    let script = Script::default().raw(200, big.clone());
    assert_eq!(
        forge(&script).ci_result(&target, PR_URL).await.err(),
        Some(ForgeError::TooLarge)
    );
    let script = Script::default()
        .reply(200, &pull("abc123"))
        .raw(200, big.clone());
    assert_eq!(
        forge(&script).ci_result(&target, PR_URL).await.err(),
        Some(ForgeError::TooLarge)
    );
    let script = Script::default()
        .reply(200, &pull("abc123"))
        .reply(200, &runs(&[]))
        .raw(200, big);
    assert_eq!(
        forge(&script).ci_result(&target, PR_URL).await.err(),
        Some(ForgeError::TooLarge)
    );
    Ok(())
}

#[tokio::test]
async fn ci_result_refuses_a_foreign_pull_url_before_any_request() -> TestResult {
    let urls = [
        "",
        "https://github.com/octo/other/pull/7",
        "https://evil.example/octo/widgets/pull/7",
        "https://github.com@evil.example/octo/widgets/pull/7",
        "https://github.com/octo/widgets/pull/7\r\nX: y",
        "https://github.com/octo/widgets/pull/../../x",
        "https://github.com/octo/widgets/pull/0",
    ];
    for url in urls {
        let script = Script::default();
        let got = forge(&script).ci_result(&target()?, url).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{url:?}");
        assert!(script.seen().is_empty(), "{url:?}");
    }
    Ok(())
}

#[test]
fn the_adapter_prints_no_token() -> TestResult {
    let script = Script::default();
    let text = format!("{:?} {:?}", forge(&script), access()?);
    assert!(!text.contains(TOKEN));
    Ok(())
}
