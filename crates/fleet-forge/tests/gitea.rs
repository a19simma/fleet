//! Per-adapter tests of `GiteaForge`: the identify and verify cases of the shared contract table
//! on the Gitea fake, then the wire details and the hostile-input table the table does not cover.

use std::collections::VecDeque;
use std::error::Error;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use fleet_forge::contract::{AdapterSubject, Case, Finding, Op, run_contract};
use fleet_forge::fake::{Fake, Shape};
use fleet_forge::{
    Credential, ForgeApi, ForgeError, ForgeGit, Git, GitCommand, GitError, GitOp, GitOutput,
    GiteaForge, GiteaGit, Http, HttpError, HttpRequest, HttpResponse, MAX_BODY_BYTES, Method,
    Permission, PushTarget, RepoAccess, RepoRef, Token, Verified,
};

type TestResult = Result<(), Box<dyn Error>>;

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

const fn is_identify(case: Case) -> bool {
    matches!(case.op(), Op::Identify)
}

#[tokio::test]
async fn every_identify_case_passes_on_the_gitea_fake() {
    let subject = AdapterSubject(|fake: &Fake| ApiOnly(GiteaForge::new(fake.clone())));
    let report = run_contract(&subject, Shape::Gitea, || Fake::new(Shape::Gitea)).await;
    let findings: Vec<String> = report
        .findings
        .iter()
        .filter(|f| is_identify(case_of(f)))
        .map(ToString::to_string)
        .collect();
    assert!(findings.is_empty(), "{findings:?}");
    let ran = report.ran.iter().filter(|c| is_identify(**c)).count();
    let owed = Case::ALL.iter().filter(|c| is_identify(**c)).count();
    assert_eq!(ran, owed);
    assert_eq!(owed, 3);
}

const fn is_create_pr(case: Case) -> bool {
    matches!(case.op(), Op::CreatePr)
}

#[tokio::test]
async fn every_create_pr_case_passes_on_the_gitea_fake() {
    let subject = AdapterSubject(|fake: &Fake| ApiOnly(GiteaForge::new(fake.clone())));
    let report = run_contract(&subject, Shape::Gitea, || Fake::new(Shape::Gitea)).await;
    let findings: Vec<String> = report
        .findings
        .iter()
        .filter(|f| is_create_pr(case_of(f)))
        .map(ToString::to_string)
        .collect();
    assert!(findings.is_empty(), "{findings:?}");
    let ran = report.ran.iter().filter(|c| is_create_pr(**c)).count();
    let owed = Case::ALL.iter().filter(|c| is_create_pr(**c)).count();
    assert_eq!(ran, owed);
    assert_eq!(owed, 3);
}

const fn is_verify(case: Case) -> bool {
    matches!(case.op(), Op::Verify)
}

#[tokio::test]
async fn every_verify_case_passes_on_the_gitea_fake() {
    let subject = AdapterSubject(|fake: &Fake| ApiOnly(GiteaForge::new(fake.clone())));
    let report = run_contract(&subject, Shape::Gitea, || Fake::new(Shape::Gitea)).await;
    let findings: Vec<String> = report
        .findings
        .iter()
        .filter(|f| is_verify(case_of(f)))
        .map(ToString::to_string)
        .collect();
    assert!(findings.is_empty(), "{findings:?}");
    let ran = report.ran.iter().filter(|c| is_verify(**c)).count();
    let owed = Case::ALL.iter().filter(|c| is_verify(**c)).count();
    assert_eq!(ran, owed);
    assert_eq!(owed, 13);
}

#[derive(Clone, Default)]
struct Script {
    replies: Arc<Mutex<VecDeque<Result<HttpResponse, HttpError>>>>,
    seen: Arc<Mutex<Vec<HttpRequest>>>,
}

impl Script {
    fn reply(self, status: u16, body: &str) -> Self {
        self.raw(status, body.as_bytes().to_vec())
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

fn forge(script: &Script) -> GiteaForge<Script> {
    GiteaForge::new(script.clone())
}

async fn identify(script: &Script) -> Result<HostKind, ForgeError> {
    let host = HostName::normalise("git.example.com").map_err(|_| ForgeError::Malformed)?;
    forge(script).identify(&host).await
}

#[tokio::test]
async fn identify_probes_the_host_itself_without_a_credential() -> TestResult {
    let script = Script::default().reply(200, r#"{"version":"1.22.0"}"#);
    let got = forge(&script).identify(&host("git.example.com")?).await?;
    assert_eq!(got, HostKind::Forgejo);
    let seen = script.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, Method::Get);
    assert_eq!(seen[0].host.as_str(), "git.example.com");
    assert_eq!(seen[0].path, "/api/v1/version");
    assert_eq!(seen[0].body.len(), 0);
    assert!(seen[0].header("authorization").is_none());
    assert!(seen[0].header("cookie").is_none());
    Ok(())
}

#[tokio::test]
async fn identify_maps_status() {
    let statuses = [
        (300, ForgeError::Redirected),
        (301, ForgeError::Redirected),
        (302, ForgeError::Redirected),
        (307, ForgeError::Redirected),
        (399, ForgeError::Redirected),
        (401, ForgeError::WrongKind),
        (403, ForgeError::WrongKind),
        (404, ForgeError::WrongKind),
        (400, ForgeError::WrongKind),
        (204, ForgeError::WrongKind),
        (201, ForgeError::WrongKind),
        (199, ForgeError::WrongKind),
        (429, ForgeError::Unavailable),
        (500, ForgeError::Unavailable),
        (503, ForgeError::Unavailable),
        (599, ForgeError::Unavailable),
    ];
    for (status, expected) in statuses {
        let script = Script::default().reply(status, r#"{"version":"1.22.0"}"#);
        assert_eq!(identify(&script).await.err(), Some(expected), "{status}");
    }
}

#[tokio::test]
async fn identify_maps_transport_errors() {
    let errors = [
        (HttpError::Timeout, ForgeError::Timeout),
        (HttpError::Reset, ForgeError::Unavailable),
        (HttpError::BodyTooLarge, ForgeError::TooLarge),
        (HttpError::HostRefused, ForgeError::Rejected),
    ];
    for (error, expected) in errors {
        let script = Script::default().fail(error);
        assert_eq!(identify(&script).await.err(), Some(expected));
    }
}

#[tokio::test]
async fn identify_checks_the_cap_before_the_status() {
    for status in [200, 302, 404, 503] {
        let script = Script::default().raw(status, vec![b' '; MAX_BODY_BYTES + 1]);
        assert_eq!(
            identify(&script).await.err(),
            Some(ForgeError::TooLarge),
            "{status}"
        );
    }
}

#[tokio::test]
async fn identify_accepts_a_body_at_the_cap() {
    let mut body = br#"{"version":"1.22.0"}"#.to_vec();
    body.resize(MAX_BODY_BYTES, b' ');
    let script = Script::default().raw(200, body);
    assert_eq!(identify(&script).await, Ok(HostKind::Forgejo));
}

#[tokio::test]
async fn identify_refuses_every_hostile_body() {
    let long = format!(r#"{{"version":"{}"}}"#, "1".repeat(65));
    let hostile: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("spaces", b"   ".to_vec()),
        ("truncated", b"{".to_vec()),
        ("truncated string", br#"{"version":"1.2"#.to_vec()),
        ("html", b"<html><body>welcome</body></html>".to_vec()),
        ("plain", b"Gitea 1.22.0".to_vec()),
        ("null", b"null".to_vec()),
        ("array", br#"[{"version":"1.22.0"}]"#.to_vec()),
        ("string", br#""1.22.0""#.to_vec()),
        ("number", b"1".to_vec()),
        ("no version", b"{}".to_vec()),
        (
            "github shape",
            br#"{"resources":{"core":{"limit":60}}}"#.to_vec(),
        ),
        ("version number", br#"{"version":1}"#.to_vec()),
        ("version float", br#"{"version":1.22}"#.to_vec()),
        ("version null", br#"{"version":null}"#.to_vec()),
        ("version bool", br#"{"version":true}"#.to_vec()),
        ("version object", br#"{"version":{"a":"1"}}"#.to_vec()),
        ("version array", br#"{"version":["1.22.0"]}"#.to_vec()),
        ("version empty", br#"{"version":""}"#.to_vec()),
        ("version over-long", long.into_bytes()),
        ("extra key", br#"{"version":"1.22.0","extra":"x"}"#.to_vec()),
        ("version space", br#"{"version":"1.22 .0"}"#.to_vec()),
        (
            "version leading space",
            br#"{"version":" 1.22.0"}"#.to_vec(),
        ),
        ("version LF", br#"{"version":"1.22.0\n"}"#.to_vec()),
        ("version CR", br#"{"version":"1.22.0\r"}"#.to_vec()),
        ("version CRLF", br#"{"version":"1.22\r\n.0"}"#.to_vec()),
        ("version tab", br#"{"version":"1\t22"}"#.to_vec()),
        ("version NUL", br#"{"version":"1\u0000"}"#.to_vec()),
        ("version DEL", br#"{"version":"1\u007f"}"#.to_vec()),
        ("version NEL", br#"{"version":"1\u0085"}"#.to_vec()),
        ("version LS", br#"{"version":"1\u2028"}"#.to_vec()),
        (
            "version non-ascii",
            "{\"version\":\"1.22.\u{e9}\"}".as_bytes().to_vec(),
        ),
        ("version slash", br#"{"version":"1/22"}"#.to_vec()),
        ("version backslash", br#"{"version":"1\\22"}"#.to_vec()),
        ("version quote", br#"{"version":"1\"22"}"#.to_vec()),
        ("version angle", br#"{"version":"<b>1</b>"}"#.to_vec()),
        ("version at", br#"{"version":"a@b"}"#.to_vec()),
        ("trailing garbage", br#"{"version":"1.22.0"} x"#.to_vec()),
        ("invalid utf8", b"{\"version\":\"1\xff\"}".to_vec()),
    ];
    for (name, body) in hostile {
        let script = Script::default().raw(200, body);
        assert_eq!(
            identify(&script).await.err(),
            Some(ForgeError::WrongKind),
            "{name}"
        );
    }
}

#[tokio::test]
async fn identify_accepts_real_version_strings_and_the_length_edge() {
    let longest = "1".repeat(64);
    for version in [
        "1.22.0",
        "1.22.0+gitea-1.22.0",
        "7.0.3+gitea-1.22.0",
        "1.23.0-rc0",
        "1.22.0-dev_x~y",
        "A",
        longest.as_str(),
    ] {
        let script = Script::default().reply(200, &format!(r#"{{"version":"{version}"}}"#));
        assert_eq!(identify(&script).await, Ok(HostKind::Forgejo), "{version}");
    }
}

#[tokio::test]
async fn identify_errors_and_debug_hold_no_response_text() {
    let marker = "SECRET-MARKER-xyz";
    let bodies = [
        format!(r#"{{"version":"{marker}\n"}}"#),
        format!(r#"{{"message":"{marker}"}}"#),
        format!("<html>{marker}</html>"),
    ];
    for body in bodies {
        for status in [200, 302, 404, 503] {
            let script = Script::default().reply(status, &body);
            if let Err(error) = identify(&script).await {
                assert!(!error.to_string().contains(marker));
                assert!(!format!("{error:?}").contains(marker));
            }
        }
    }
    let forge = GiteaForge::new(Script::default());
    assert_eq!(format!("{forge:?}"), "GiteaForge { .. }");
}

#[tokio::test]
async fn identify_follows_no_redirect() {
    let script = Script::default()
        .reply(302, "")
        .reply(200, r#"{"version":"1.22.0"}"#);
    assert_eq!(identify(&script).await.err(), Some(ForgeError::Redirected));
    assert_eq!(script.seen().len(), 1);
}

const TOKEN: &str = "0123456789abcdef0123456789abcdef01234567";

fn access_for(
    owner: &str,
    repo: &str,
    credential_host: &str,
) -> Result<RepoAccess, Box<dyn Error>> {
    let repo = RepoRef::new(host("git.example.com")?, owner, repo)?;
    let credential = Credential::new(host(credential_host)?, Token::new(TOKEN.to_owned())?);
    Ok(RepoAccess::new(repo, credential))
}

fn access() -> Result<RepoAccess, Box<dyn Error>> {
    access_for("octo", "widgets", "git.example.com")
}

async fn verify(script: &Script) -> Result<Verified, ForgeError> {
    forge(script)
        .verify(&access().map_err(|_| ForgeError::Malformed)?)
        .await
}

#[tokio::test]
async fn verify_sends_one_authenticated_get_to_the_repo_path() -> TestResult {
    let script = Script::default().reply(200, r#"{"permissions":{"push":true}}"#);
    let verified = forge(&script).verify(&access()?).await?;
    assert_eq!(verified.push, Permission::Granted);
    let seen = script.seen();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.host.as_str(), "git.example.com");
    assert_eq!(request.path, "/api/v1/repos/octo/widgets");
    assert_eq!(
        request.header("authorization"),
        Some(&*format!("token {TOKEN}"))
    );
    assert_eq!(request.header("accept"), Some("application/json"));
    assert!(request.header("user-agent").is_some());
    assert_eq!(request.body.len(), 0);
    assert!(!request.path.contains(TOKEN));
    let others = request
        .headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("authorization"))
        .all(|(_, value)| !value.contains(TOKEN));
    assert!(others);
    Ok(())
}

#[tokio::test]
async fn verify_reads_push_and_treats_absent_permissions_as_unknown() -> TestResult {
    let table = [
        (r#"{"permissions":{"push":true}}"#, Permission::Granted),
        (r#"{"permissions":{"push":false}}"#, Permission::Denied),
        (
            r#"{"permissions":{"admin":false,"push":true,"pull":true}}"#,
            Permission::Granted,
        ),
        (r#"{"permissions":null}"#, Permission::Unknown),
        (r#"{"full_name":"octo/widgets"}"#, Permission::Unknown),
    ];
    for (body, expected) in table {
        let script = Script::default().reply(200, body);
        assert_eq!(verify(&script).await?.push, expected, "{body}");
    }
    Ok(())
}

#[tokio::test]
async fn verify_refuses_hostile_response_bodies() {
    let nested = "[".repeat(200_000);
    let wrong = [
        "",
        "   ",
        "{",
        "null",
        "[]",
        "3",
        "\"x\"",
        "<html></html>",
        "{\"permissions\":{\"push\":true}\r\n",
        "{\"permissions\":\r\n[]}",
        r#"{"permissions":[]}"#,
        r#"{"permissions":3}"#,
        r#"{"permissions":"x"}"#,
        r#"{"permissions":true}"#,
        r#"{"permissions":{}}"#,
        r#"{"permissions":{"pull":true}}"#,
        r#"{"permissions":{"push":"true"}}"#,
        r#"{"permissions":{"push":1}}"#,
        r#"{"permissions":{"push":null}}"#,
        r#"{"permissions":{"push":[true]}}"#,
        nested.as_str(),
    ];
    for body in wrong {
        let script = Script::default().reply(200, body);
        assert_eq!(
            verify(&script).await.err(),
            Some(ForgeError::Malformed),
            "{:?}",
            body.get(..20)
        );
    }
    let script = Script::default().raw(200, b"{\"permissions\":{\"push\":\xff}}".to_vec());
    assert_eq!(verify(&script).await.err(), Some(ForgeError::Malformed));
}

#[tokio::test]
async fn verify_checks_the_body_cap_before_the_status() {
    let at_cap = format!(
        "{{\"permissions\":null}}{}",
        " ".repeat(MAX_BODY_BYTES - 20)
    );
    assert_eq!(at_cap.len(), MAX_BODY_BYTES);
    let script = Script::default().reply(200, &at_cap);
    assert_eq!(
        verify(&script).await.map(|v| v.push),
        Ok(Permission::Unknown)
    );
    for status in [200, 302, 401, 403, 404, 503] {
        let script = Script::default().raw(status, vec![b' '; MAX_BODY_BYTES + 1]);
        assert_eq!(
            verify(&script).await.err(),
            Some(ForgeError::TooLarge),
            "{status}"
        );
    }
}

#[tokio::test]
async fn verify_maps_status_and_transport_errors() {
    let statuses = [
        (300, ForgeError::Redirected),
        (302, ForgeError::Redirected),
        (307, ForgeError::Redirected),
        (399, ForgeError::Redirected),
        (400, ForgeError::Rejected),
        (401, ForgeError::NotFound),
        (403, ForgeError::NotFound),
        (404, ForgeError::NotFound),
        (409, ForgeError::Rejected),
        (429, ForgeError::Unavailable),
        (500, ForgeError::Unavailable),
        (502, ForgeError::Unavailable),
        (599, ForgeError::Unavailable),
        (204, ForgeError::Malformed),
        (201, ForgeError::Malformed),
        (199, ForgeError::Malformed),
    ];
    for (status, expected) in statuses {
        let script = Script::default().reply(status, "{}");
        assert_eq!(verify(&script).await.err(), Some(expected), "{status}");
    }
    let transport = [
        (HttpError::Timeout, ForgeError::Timeout),
        (HttpError::Reset, ForgeError::Unavailable),
        (HttpError::BodyTooLarge, ForgeError::TooLarge),
        (HttpError::HostRefused, ForgeError::Rejected),
    ];
    for (error, expected) in transport {
        let script = Script::default().fail(error);
        assert_eq!(verify(&script).await.err(), Some(expected), "{error}");
    }
}

#[tokio::test]
async fn verify_follows_no_redirect_and_replays_no_authorization() {
    let script = Script::default()
        .reply(302, "")
        .reply(200, r#"{"permissions":{"push":true}}"#);
    assert_eq!(verify(&script).await.err(), Some(ForgeError::Redirected));
    assert_eq!(script.seen().len(), 1);
}

#[tokio::test]
async fn verify_sends_to_the_repository_host_not_a_fixed_one() -> TestResult {
    let script = Script::default().reply(200, "{}");
    let repo = RepoRef::new(host("forge.example.net")?, "octo", "widgets")?;
    let credential = Credential::new(host("forge.example.net")?, Token::new(TOKEN.to_owned())?);
    forge(&script)
        .verify(&RepoAccess::new(repo, credential))
        .await?;
    assert_eq!(script.seen()[0].host.as_str(), "forge.example.net");
    Ok(())
}

#[tokio::test]
async fn verify_refuses_a_foreign_credential_before_any_request() -> TestResult {
    let script = Script::default().reply(200, "{}");
    let mismatch = access_for("octo", "widgets", "other.example.net")?;
    assert_eq!(
        forge(&script).verify(&mismatch).await.err(),
        Some(ForgeError::HostMismatch)
    );
    assert_eq!(script.seen().len(), 0);
    Ok(())
}

#[test]
fn hostile_owner_and_repo_never_reach_a_repo_ref() -> TestResult {
    let hostile = [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a b",
        "a\r\nb",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a?x=1",
        "a#b",
        "a%2Fb",
        "a@b",
        "a:b",
        "\u{e9}",
        "a\0b",
        "../x",
        "x/..",
        "[::1]",
    ];
    let long = "a".repeat(5000);
    let h = host("git.example.com")?;
    for bad in hostile.iter().copied().chain([long.as_str()]) {
        assert!(
            RepoRef::new(h.clone(), bad, "widgets").is_err(),
            "owner {bad:?}"
        );
        assert!(
            RepoRef::new(h.clone(), "octo", bad).is_err(),
            "repo {bad:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn verify_places_owner_and_repo_only_through_the_validated_ref() -> TestResult {
    for (owner, repo) in [("a.b_c-d", "x.y_z-1"), ("A", "B"), ("..a", "b..")] {
        let script = Script::default().reply(200, "{}");
        if let Ok(access) = access_for(owner, repo, "git.example.com") {
            forge(&script).verify(&access).await?;
            let seen = script.seen();
            assert_eq!(seen[0].path, format!("/api/v1/repos/{owner}/{repo}"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn verify_errors_and_debug_hold_no_token_or_response_text() {
    let marker = "SECRET-MARKER-xyz";
    let bodies = [
        format!(r#"{{"message":"{marker} {TOKEN}"}}"#),
        format!("<html>{marker}</html>"),
        format!(r#"{{"permissions":{{"push":"{marker}"}}}}"#),
    ];
    for body in bodies {
        for status in [200, 302, 401, 404, 503] {
            let script = Script::default().reply(status, &body);
            if let Err(error) = verify(&script).await {
                for text in [error.to_string(), format!("{error:?}")] {
                    assert!(!text.contains(marker));
                    assert!(!text.contains(TOKEN));
                }
            }
        }
    }
    let forge = GiteaForge::new(Script::default());
    assert!(!format!("{forge:?}").contains(TOKEN));
}

const PR_URL: &str = "https://git.example.com/octo/widgets/pulls/7";
const EXISTS: &str = r#"{"message":"pull request already exists for these targets [id: 7]"}"#;

fn target_for(access: RepoAccess) -> Result<PushTarget, Box<dyn Error>> {
    Ok(PushTarget::new(access, "fleet/job-1", "main")?)
}

fn target() -> Result<PushTarget, Box<dyn Error>> {
    target_for(access()?)
}

async fn create(script: &Script) -> Result<String, ForgeError> {
    forge(script)
        .create_pr(&target().map_err(|_| ForgeError::Malformed)?, "t", "b")
        .await
}

fn created(url: &str) -> String {
    serde_json::json!({"number": 7, "html_url": url}).to_string()
}

fn pull(branch: &str, full_name: &str, url: &str) -> serde_json::Value {
    serde_json::json!({
        "number": 7,
        "html_url": url,
        "head": {"ref": branch, "repo": {"full_name": full_name}},
    })
}

fn list(pulls: &[serde_json::Value]) -> String {
    serde_json::Value::Array(pulls.to_vec()).to_string()
}

#[tokio::test]
async fn create_pr_posts_a_pull_with_the_job_branch() -> TestResult {
    let script = Script::default().reply(201, &created(PR_URL));
    let url = forge(&script)
        .create_pr(&target()?, "A \"title\"\r\n\\ \u{0}", "line\nbody \"q\" \\")
        .await?;
    assert_eq!(url, PR_URL);
    let seen = script.seen();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::Post);
    assert_eq!(request.host.as_str(), "git.example.com");
    assert_eq!(request.path, "/api/v1/repos/octo/widgets/pulls");
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("accept"), Some("application/json"));
    assert!(request.header("user-agent").is_some());
    assert_eq!(
        request.header("authorization"),
        Some(&*format!("token {TOKEN}"))
    );
    let sent: serde_json::Value = serde_json::from_slice(&request.body)?;
    assert_eq!(sent["title"], "A \"title\"\r\n\\ \u{0}");
    assert_eq!(sent["body"], "line\nbody \"q\" \\");
    assert_eq!(sent["head"], "fleet/job-1");
    assert_eq!(sent["base"], "main");
    assert_eq!(sent.as_object().map(serde_json::Map::len), Some(4));
    assert!(!String::from_utf8_lossy(&request.body).contains(TOKEN));
    assert!(!request.path.contains(TOKEN));
    Ok(())
}

#[tokio::test]
async fn create_pr_bounds_the_title_and_body_before_any_request() -> TestResult {
    let adapter_target = target()?;
    let long_title = "t".repeat(257);
    let long_body = "b".repeat(64 * 1024 + 1);
    let cases = [
        ("", "b"),
        (long_title.as_str(), "b"),
        ("t", long_body.as_str()),
    ];
    for (title, body) in cases {
        let script = Script::default().reply(201, &created(PR_URL));
        let got = forge(&script).create_pr(&adapter_target, title, body).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{}", title.len());
        assert_eq!(script.seen().len(), 0);
    }
    let edge_title = "t".repeat(256);
    let edge_body = "b".repeat(64 * 1024);
    let script = Script::default().reply(201, &created(PR_URL));
    let got = forge(&script)
        .create_pr(&adapter_target, &edge_title, &edge_body)
        .await;
    assert_eq!(got.ok().as_deref(), Some(PR_URL));
    let multibyte = "\u{e9}".repeat(129);
    let script = Script::default().reply(201, &created(PR_URL));
    let got = forge(&script)
        .create_pr(&adapter_target, &multibyte, "b")
        .await;
    assert_eq!(got.err(), Some(ForgeError::Malformed));
    Ok(())
}

#[tokio::test]
async fn create_pr_refuses_a_foreign_credential_and_sends_nothing() -> TestResult {
    let script = Script::default().reply(201, &created(PR_URL));
    let mismatch = target_for(access_for("octo", "widgets", "other.example.com")?)?;
    let got = forge(&script).create_pr(&mismatch, "t", "b").await;
    assert_eq!(got.err(), Some(ForgeError::HostMismatch));
    assert_eq!(script.seen().len(), 0);
    Ok(())
}

#[tokio::test]
async fn create_pr_refuses_a_created_url_it_cannot_trust() {
    let bad = [
        "{}".to_owned(),
        r#"{"html_url":3}"#.to_owned(),
        r#"{"html_url":null}"#.to_owned(),
        r#"{"html_url":["x"]}"#.to_owned(),
        created("https://evil.example/octo/widgets/pulls/7"),
        created("https://git.example.com.evil.example/octo/widgets/pulls/7"),
        created("https://user@git.example.com/octo/widgets/pulls/7"),
        created("https://user:pw@git.example.com/octo/widgets/pulls/7"),
        created("https://git.example.com@evil.example/octo/widgets/pulls/7"),
        created("https://git.example.com:8443/octo/widgets/pulls/7"),
        created("http://git.example.com/octo/widgets/pulls/7"),
        created("https://git.example.com/octo/other/pulls/7"),
        created("https://git.example.com/other/widgets/pulls/7"),
        created("https://git.example.com/octo/widgets/pull/7"),
        created("https://git.example.com/octo/widgets/issues/7"),
        created("https://git.example.com/octo/widgets/pulls/"),
        created("https://git.example.com/octo/widgets/pulls/0"),
        created("https://git.example.com/octo/widgets/pulls/-1"),
        created("https://git.example.com/octo/widgets/pulls/+7"),
        created("https://git.example.com/octo/widgets/pulls/7a"),
        created("https://git.example.com/octo/widgets/pulls/7/files"),
        created("https://git.example.com/octo/widgets/pulls/7?x=1"),
        created("https://git.example.com/octo/widgets/pulls/7#f"),
        created("https://git.example.com/octo/widgets/pulls/\u{661}"),
        created("https://git.example.com/octo/widgets/pulls/12345678901"),
        created("https://git.example.com/octo/widgets/pulls/99999999999999999999"),
        created("https://git.example.com/octo/widgets/pulls/7\r\nX: y"),
        created("https://git.example.com/octo/widgets/pulls/7\n"),
        created("https://git.example.com/octo/widgets/pulls/7 "),
        created("https://git.example.com\\@evil.example/octo/widgets/pulls/7"),
        created("https://git.example.com/octo/widgets/pulls/7\u{2028}"),
        created("https://git.example.com/octo/widgets/pulls/7\u{85}"),
        created("https://\u{ff47}it.example.com/octo/widgets/pulls/7"),
        created(""),
        "[]".to_owned(),
        "null".to_owned(),
        "\"x\"".to_owned(),
        "{".to_owned(),
        String::new(),
    ];
    for body in bad {
        let script = Script::default().reply(201, &body);
        assert_eq!(
            create(&script).await.err(),
            Some(ForgeError::Malformed),
            "{body}"
        );
        assert_eq!(script.seen().len(), 1);
    }
    for status in [200, 202, 204] {
        let script = Script::default().reply(status, &created(PR_URL));
        assert_eq!(
            create(&script).await.err(),
            Some(ForgeError::Malformed),
            "{status}"
        );
    }
}

#[tokio::test]
async fn create_pr_accepts_the_url_in_any_ascii_case_of_host_and_path() {
    let script = Script::default().reply(
        201,
        &created("https://GIT.example.com/OCTO/Widgets/pulls/42"),
    );
    assert_eq!(
        create(&script).await.ok().as_deref(),
        Some("https://GIT.example.com/OCTO/Widgets/pulls/42")
    );
    let script = Script::default().reply(
        201,
        &created("https://git.example.com/octo/widgets/pulls/9999999999"),
    );
    assert!(create(&script).await.is_ok());
}

#[tokio::test]
async fn create_pr_maps_status_codes() {
    let table = [
        (401, ForgeError::Unauthorized),
        (403, ForgeError::Unauthorized),
        (404, ForgeError::NotFound),
        (400, ForgeError::Rejected),
        (409, ForgeError::Rejected),
        (422, ForgeError::Rejected),
        (429, ForgeError::Unavailable),
        (500, ForgeError::Unavailable),
        (599, ForgeError::Unavailable),
        (300, ForgeError::Redirected),
        (301, ForgeError::Redirected),
        (302, ForgeError::Redirected),
        (307, ForgeError::Redirected),
        (399, ForgeError::Redirected),
        (100, ForgeError::Malformed),
    ];
    for (status, expected) in table {
        let script = Script::default().reply(status, "{}");
        assert_eq!(create(&script).await.err(), Some(expected), "{status}");
        assert_eq!(script.seen().len(), 1, "{status}");
    }
    let transport = [
        (HttpError::Timeout, ForgeError::Timeout),
        (HttpError::Reset, ForgeError::Unavailable),
        (HttpError::BodyTooLarge, ForgeError::TooLarge),
        (HttpError::HostRefused, ForgeError::Rejected),
    ];
    for (error, expected) in transport {
        let script = Script::default().fail(error);
        assert_eq!(create(&script).await.err(), Some(expected));
    }
}

#[tokio::test]
async fn create_pr_checks_the_cap_before_the_status() {
    for status in [201, 409, 302, 404, 422, 503] {
        let script = Script::default().raw(status, vec![b' '; MAX_BODY_BYTES + 1]);
        assert_eq!(
            create(&script).await.err(),
            Some(ForgeError::TooLarge),
            "{status}"
        );
        assert_eq!(script.seen().len(), 1);
    }
    let mut body = created(PR_URL).into_bytes();
    body.resize(MAX_BODY_BYTES, b' ');
    let script = Script::default().raw(201, body);
    assert_eq!(create(&script).await.ok().as_deref(), Some(PR_URL));
}

#[tokio::test]
async fn create_pr_on_an_existing_pull_returns_the_existing_url() -> TestResult {
    let other = pull(
        "fleet/job-10",
        "octo/widgets",
        "https://git.example.com/octo/widgets/pulls/3",
    );
    let mine = pull("fleet/job-1", "octo/widgets", PR_URL);
    let script = Script::default()
        .reply(409, EXISTS)
        .reply(200, &list(&[other, mine]));
    assert_eq!(create(&script).await?, PR_URL);
    let seen = script.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].method, Method::Get);
    assert_eq!(seen[1].host.as_str(), "git.example.com");
    assert_eq!(
        seen[1].path,
        "/api/v1/repos/octo/widgets/pulls?state=open&page=1&limit=50"
    );
    assert_eq!(
        seen[1].header("authorization"),
        Some(&*format!("token {TOKEN}"))
    );
    assert_eq!(seen[1].body.len(), 0);
    Ok(())
}

#[tokio::test]
async fn create_pr_exists_detection_is_case_blind_and_exact_to_the_message() {
    let script = Script::default()
        .reply(409, r#"{"message":"PULL REQUEST ALREADY EXISTS"}"#)
        .reply(200, &list(&[pull("fleet/job-1", "octo/widgets", PR_URL)]));
    assert_eq!(create(&script).await.ok().as_deref(), Some(PR_URL));
    let other = [
        r#"{"message":"conflict"}"#,
        r#"{"message":3}"#,
        r#"{"message":null}"#,
        r#"{"errors":["already exists"]}"#,
        "{}",
        "[]",
        "not json",
        "",
    ];
    for body in other {
        let script = Script::default().reply(409, body);
        assert_eq!(
            create(&script).await.err(),
            Some(ForgeError::Rejected),
            "{body}"
        );
        assert_eq!(script.seen().len(), 1, "{body}");
    }
    let script = Script::default().reply(422, EXISTS);
    assert_eq!(create(&script).await.err(), Some(ForgeError::Rejected));
    assert_eq!(script.seen().len(), 1);
}

#[tokio::test]
async fn the_lookup_matches_the_head_branch_and_repository_exactly() {
    let url2 = "https://git.example.com/octo/widgets/pulls/2";
    let wrong = [
        pull("fleet/job-1x", "octo/widgets", url2),
        pull("xfleet/job-1", "octo/widgets", url2),
        pull("Fleet/Job-1", "octo/widgets", url2),
        pull("fleet/job-1", "fork/widgets", url2),
        pull("fleet/job-1", "octo/other", url2),
        serde_json::json!({"html_url": url2, "head": {"ref": "fleet/job-1"}}),
        serde_json::json!({"html_url": url2, "head": {"ref": "fleet/job-1", "repo": null}}),
        serde_json::json!({"html_url": url2, "head": {"ref": 3, "repo": {"full_name": "octo/widgets"}}}),
        serde_json::json!({"html_url": url2, "base": {"ref": "fleet/job-1"}}),
        serde_json::json!({"html_url": url2}),
        serde_json::json!("fleet/job-1"),
        serde_json::json!(null),
    ];
    let script = Script::default()
        .reply(409, EXISTS)
        .reply(200, &list(&wrong));
    assert_eq!(create(&script).await.err(), Some(ForgeError::Rejected));
    let mut mixed = wrong.to_vec();
    mixed.push(pull("fleet/job-1", "OCTO/Widgets", PR_URL));
    let script = Script::default()
        .reply(409, EXISTS)
        .reply(200, &list(&mixed));
    assert_eq!(create(&script).await.ok().as_deref(), Some(PR_URL));
}

#[tokio::test]
async fn the_lookup_pages_to_a_bound() {
    let filler: Vec<serde_json::Value> = (0..50)
        .map(|n| {
            pull(
                &format!("other/{n}"),
                "octo/widgets",
                "https://git.example.com/octo/widgets/pulls/2",
            )
        })
        .collect();
    let full = list(&filler);
    let hit = list(&[pull("fleet/job-1", "octo/widgets", PR_URL)]);
    let script = Script::default()
        .reply(409, EXISTS)
        .reply(200, &full)
        .reply(200, &hit);
    assert_eq!(create(&script).await.ok().as_deref(), Some(PR_URL));
    let seen = script.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[2].path,
        "/api/v1/repos/octo/widgets/pulls?state=open&page=2&limit=50"
    );
    let mut script = Script::default().reply(409, EXISTS);
    for _ in 0..5 {
        script = script.reply(200, &full);
    }
    script = script.reply(200, &hit);
    assert_eq!(create(&script).await.err(), Some(ForgeError::Rejected));
    assert_eq!(script.seen().len(), 6);
    let script = Script::default()
        .reply(409, EXISTS)
        .reply(200, &list(&[pull("other", "octo/widgets", PR_URL)]))
        .reply(200, &hit);
    assert_eq!(create(&script).await.err(), Some(ForgeError::Rejected));
    assert_eq!(script.seen().len(), 2);
}

#[tokio::test]
async fn create_pr_exists_with_no_findable_pull_fails_closed() {
    let foreign = list(&[pull(
        "fleet/job-1",
        "octo/widgets",
        "https://evil.example/octo/widgets/pulls/7",
    )]);
    let numberless = list(&[pull(
        "fleet/job-1",
        "octo/widgets",
        "https://git.example.com/octo/widgets/pulls/x",
    )]);
    let urlless = serde_json::json!([{"head": {"ref": "fleet/job-1", "repo": {"full_name": "octo/widgets"}}}]).to_string();
    let urltyped = serde_json::json!([{"html_url": 3, "head": {"ref": "fleet/job-1", "repo": {"full_name": "octo/widgets"}}}]).to_string();
    let lookups = [
        (200, "[]".to_owned(), ForgeError::Rejected),
        (200, "{}".to_owned(), ForgeError::Malformed),
        (200, "null".to_owned(), ForgeError::Malformed),
        (200, "{".to_owned(), ForgeError::Malformed),
        (200, String::new(), ForgeError::Malformed),
        (200, foreign, ForgeError::Malformed),
        (200, numberless, ForgeError::Malformed),
        (200, urlless, ForgeError::Malformed),
        (200, urltyped, ForgeError::Malformed),
        (401, "{}".to_owned(), ForgeError::Unauthorized),
        (404, "{}".to_owned(), ForgeError::NotFound),
        (429, "{}".to_owned(), ForgeError::Unavailable),
        (500, "{}".to_owned(), ForgeError::Unavailable),
        (302, "{}".to_owned(), ForgeError::Redirected),
        (422, "{}".to_owned(), ForgeError::Rejected),
    ];
    for (status, body, expected) in lookups {
        let script = Script::default().reply(409, EXISTS).reply(status, &body);
        assert_eq!(create(&script).await.err(), Some(expected), "{body}");
        assert_eq!(script.seen().len(), 2, "{body}");
    }
    let script = Script::default()
        .reply(409, EXISTS)
        .raw(200, vec![b' '; MAX_BODY_BYTES + 1]);
    assert_eq!(create(&script).await.err(), Some(ForgeError::TooLarge));
    let oversized = serde_json::Value::Array(vec![serde_json::Value::Null; 51]).to_string();
    let script = Script::default().reply(409, EXISTS).reply(200, &oversized);
    assert_eq!(create(&script).await.err(), Some(ForgeError::Malformed));
    let script = Script::default()
        .reply(409, EXISTS)
        .fail(HttpError::Timeout);
    assert_eq!(create(&script).await.err(), Some(ForgeError::Timeout));
}

#[tokio::test]
async fn create_pr_follows_no_redirect_and_replays_nothing() {
    let script = Script::default()
        .reply(302, "")
        .reply(201, &created(PR_URL));
    assert_eq!(create(&script).await.err(), Some(ForgeError::Redirected));
    assert_eq!(script.seen().len(), 1);
    let script = Script::default()
        .reply(409, EXISTS)
        .reply(307, "")
        .reply(200, &list(&[pull("fleet/job-1", "octo/widgets", PR_URL)]));
    assert_eq!(create(&script).await.err(), Some(ForgeError::Redirected));
    assert_eq!(script.seen().len(), 2);
}

#[tokio::test]
async fn create_pr_errors_hold_no_response_text_or_token() -> TestResult {
    let marker = "SECRET-MARKER-xyz";
    let bodies = [
        format!(r#"{{"message":"{marker} {TOKEN}"}}"#),
        format!(r#"{{"message":"already exists {marker} {TOKEN}"}}"#),
        format!("<html>{marker}</html>"),
    ];
    for body in bodies {
        for status in [201, 302, 401, 404, 409, 422, 503] {
            let script = Script::default()
                .reply(status, &body)
                .reply(200, &body)
                .reply(200, &body);
            if let Err(error) = create(&script).await {
                for text in [error.to_string(), format!("{error:?}")] {
                    assert!(!text.contains(marker));
                    assert!(!text.contains(TOKEN));
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn create_pr_validates_the_url_against_the_repository_host() -> TestResult {
    let repo = RepoRef::new(host("forge.example.org")?, "octo", "widgets")?;
    let credential = Credential::new(host("forge.example.org")?, Token::new(TOKEN.to_owned())?);
    let target = target_for(RepoAccess::new(repo, credential))?;
    let good = "https://forge.example.org/octo/widgets/pulls/7";
    let script = Script::default().reply(201, &created(good));
    let got = forge(&script).create_pr(&target, "t", "b").await;
    assert_eq!(got.ok().as_deref(), Some(good));
    assert_eq!(script.seen()[0].host.as_str(), "forge.example.org");
    let script = Script::default().reply(201, &created(PR_URL));
    let got = forge(&script).create_pr(&target, "t", "b").await;
    assert_eq!(got.err(), Some(ForgeError::Malformed));
    Ok(())
}

const fn is_ci(case: Case) -> bool {
    matches!(case.op(), Op::CiResult)
}

#[tokio::test]
async fn every_ci_result_case_passes_on_the_gitea_fake() {
    let subject = AdapterSubject(|fake: &Fake| ApiOnly(GiteaForge::new(fake.clone())));
    let report = run_contract(&subject, Shape::Gitea, || Fake::new(Shape::Gitea)).await;
    let findings: Vec<String> = report
        .findings
        .iter()
        .filter(|f| is_ci(case_of(f)))
        .map(ToString::to_string)
        .collect();
    assert!(findings.is_empty(), "{findings:?}");
    let ran = report.ran.iter().filter(|c| is_ci(**c)).count();
    let owed = Case::ALL.iter().filter(|c| is_ci(**c)).count();
    assert_eq!(ran, owed);
    assert_eq!(owed, 6);
}

fn head_of(sha: &str) -> String {
    format!(r#"{{"number":7,"head":{{"sha":"{sha}"}}}}"#)
}

fn statuses(states: &[&str]) -> String {
    let list: Vec<String> = states
        .iter()
        .map(|s| format!(r#"{{"status":"{s}"}}"#))
        .collect();
    format!(
        r#"{{"state":"x","total_count":{},"statuses":[{}]}}"#,
        list.len(),
        list.join(",")
    )
}

type Items<'a> = Vec<(&'a str, Option<&'a str>)>;

fn runs(items: &[(&str, Option<&str>)]) -> String {
    let list: Vec<String> = items
        .iter()
        .map(|(status, conclusion)| {
            conclusion.map_or_else(
                || format!(r#"{{"status":"{status}"}}"#),
                |c| format!(r#"{{"status":"{status}","conclusion":"{c}"}}"#),
            )
        })
        .collect();
    format!(
        r#"{{"total_count":{},"workflow_runs":[{}]}}"#,
        list.len(),
        list.join(",")
    )
}

async fn ci_from_statuses(states: &[&str]) -> Result<CiResult, ForgeError> {
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .reply(200, &statuses(states))
        .reply(200, &runs(&[("completed", Some("failure"))]));
    let target = target().map_err(|_| ForgeError::Malformed)?;
    forge(&script).ci_result(&target, PR_URL).await
}

async fn ci_from_runs(items: &[(&str, Option<&str>)]) -> Result<CiResult, ForgeError> {
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .reply(200, &statuses(&[]))
        .reply(200, &runs(items));
    let target = target().map_err(|_| ForgeError::Malformed)?;
    forge(&script).ci_result(&target, PR_URL).await
}

#[tokio::test]
async fn ci_result_reads_the_head_then_the_statuses() -> TestResult {
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .reply(200, &statuses(&["success"]));
    assert_eq!(
        forge(&script).ci_result(&target()?, PR_URL).await?,
        CiResult::Success
    );
    let seen = script.seen();
    let paths: Vec<&str> = seen.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/api/v1/repos/octo/widgets/pulls/7",
            "/api/v1/repos/octo/widgets/commits/abc123/status?page=1&limit=50",
        ]
    );
    for request in &seen {
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.host.as_str(), "git.example.com");
        assert_eq!(
            request.header("authorization"),
            Some(&*format!("token {TOKEN}"))
        );
    }
    Ok(())
}

#[tokio::test]
async fn ci_result_reads_the_runs_only_when_the_statuses_are_empty() -> TestResult {
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .reply(200, &statuses(&[]))
        .reply(200, &runs(&[("completed", Some("success"))]));
    assert_eq!(
        forge(&script).ci_result(&target()?, PR_URL).await?,
        CiResult::Success
    );
    let seen = script.seen();
    let paths: Vec<&str> = seen.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths[2],
        "/api/v1/repos/octo/widgets/actions/runs?head_sha=abc123&page=1&limit=50"
    );
    assert_eq!(paths.len(), 3);
    for request in &seen {
        assert_eq!(request.method, Method::Get);
        assert_eq!(
            request.header("authorization"),
            Some(&*format!("token {TOKEN}"))
        );
    }
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .reply(200, &statuses(&["pending"]))
        .reply(200, &runs(&[("completed", Some("failure"))]));
    assert_eq!(
        forge(&script).ci_result(&target()?, PR_URL).await?,
        CiResult::InProgress
    );
    assert_eq!(script.seen().len(), 2);
    Ok(())
}

#[tokio::test]
async fn ci_result_maps_every_status_state() {
    let table: Vec<(Vec<&str>, CiResult)> = vec![
        (vec!["success"], CiResult::Success),
        (vec!["pending"], CiResult::InProgress),
        (vec!["failure"], CiResult::Failure),
        (vec!["error"], CiResult::Failure),
        (vec!["warning"], CiResult::Failure),
        (vec!["skipped"], CiResult::Neutral),
        (vec!["skipped", "success"], CiResult::Success),
        (vec!["success", "pending"], CiResult::InProgress),
        (vec!["success", "failure", "pending"], CiResult::Failure),
    ];
    for (states, expected) in table {
        assert_eq!(ci_from_statuses(&states).await, Ok(expected), "{states:?}");
    }
}

#[tokio::test]
async fn ci_result_maps_every_run_state() {
    let table: Vec<(Items<'_>, CiResult)> = vec![
        (vec![], CiResult::NoChecks),
        (vec![("queued", None)], CiResult::Queued),
        (vec![("waiting", None)], CiResult::Queued),
        (vec![("requested", None)], CiResult::Queued),
        (vec![("pending", None)], CiResult::Queued),
        (vec![("in_progress", None)], CiResult::InProgress),
        (vec![("completed", Some("success"))], CiResult::Success),
        (vec![("completed", Some("skipped"))], CiResult::Neutral),
        (vec![("completed", Some("neutral"))], CiResult::Neutral),
        (vec![("completed", Some("failure"))], CiResult::Failure),
        (vec![("completed", Some("cancelled"))], CiResult::Failure),
        (
            vec![("completed", Some("something_new"))],
            CiResult::Failure,
        ),
        (
            vec![("completed", Some("success")), ("queued", None)],
            CiResult::Queued,
        ),
        (
            vec![("completed", Some("success")), ("in_progress", None)],
            CiResult::InProgress,
        ),
        (
            vec![("completed", Some("failure")), ("in_progress", None)],
            CiResult::Failure,
        ),
    ];
    for (items, expected) in table {
        assert_eq!(ci_from_runs(&items).await, Ok(expected), "{items:?}");
    }
}

#[tokio::test]
async fn ci_result_refuses_malformed_status_data() -> TestResult {
    let target = target()?;
    let cap = format!(
        r#"{{"statuses":[{}]}}"#,
        vec![r#"{"status":"success"}"#; 50].join(",")
    );
    let bad = [
        "",
        "{",
        "[]",
        "{}",
        r#"{"statuses":3}"#,
        r#"{"statuses":[3]}"#,
        r#"{"statuses":[{}]}"#,
        r#"{"statuses":[{"state":"success"}]}"#,
        r#"{"statuses":[{"status":"weird"}]}"#,
        r#"{"statuses":[{"status":3}]}"#,
        r#"{"statuses":[{"status":null}]}"#,
        r#"{"total_count":2,"statuses":[{"status":"success"}]}"#,
        cap.as_str(),
    ];
    for body in bad {
        let script = Script::default()
            .reply(200, &head_of("abc123"))
            .reply(200, body);
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{body}");
    }
    let under = format!(
        r#"{{"statuses":[{}]}}"#,
        vec![r#"{"status":"success"}"#; 49].join(",")
    );
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .reply(200, &under);
    assert_eq!(
        forge(&script).ci_result(&target, PR_URL).await,
        Ok(CiResult::Success)
    );
    Ok(())
}

#[tokio::test]
async fn ci_result_refuses_malformed_run_data() -> TestResult {
    let target = target()?;
    let cap = format!(
        r#"{{"workflow_runs":[{}]}}"#,
        vec![r#"{"status":"queued"}"#; 50].join(",")
    );
    let bad = [
        "",
        "{",
        "[]",
        "{}",
        r#"{"workflow_runs":3}"#,
        r#"{"workflow_runs":[3]}"#,
        r#"{"workflow_runs":[{}]}"#,
        r#"{"workflow_runs":[{"status":3}]}"#,
        r#"{"workflow_runs":[{"status":"weird"}]}"#,
        r#"{"workflow_runs":[{"status":"completed"}]}"#,
        r#"{"workflow_runs":[{"status":"completed","conclusion":null}]}"#,
        r#"{"workflow_runs":[{"status":"completed","conclusion":3}]}"#,
        r#"{"total_count":2,"workflow_runs":[{"status":"queued"}]}"#,
        cap.as_str(),
    ];
    for body in bad {
        let script = Script::default()
            .reply(200, &head_of("abc123"))
            .reply(200, &statuses(&[]))
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
    let table = [
        (404, ForgeError::NotFound),
        (401, ForgeError::Unauthorized),
        (403, ForgeError::Unauthorized),
        (500, ForgeError::Unavailable),
        (302, ForgeError::Redirected),
        (204, ForgeError::Malformed),
    ];
    for (status, expected) in table {
        let script = Script::default().reply(status, "{}");
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(expected), "pull {status}");
        let script = Script::default()
            .reply(200, &head_of("abc123"))
            .reply(status, "{}");
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(expected), "statuses {status}");
        let script = Script::default()
            .reply(200, &head_of("abc123"))
            .reply(200, &statuses(&[]))
            .reply(status, "{}");
        let got = forge(&script).ci_result(&target, PR_URL).await;
        assert_eq!(got.err(), Some(expected), "runs {status}");
    }
    let big = vec![b' '; MAX_BODY_BYTES + 1];
    let steps = [
        Script::default().raw(200, big.clone()),
        Script::default()
            .reply(200, &head_of("abc123"))
            .raw(200, big.clone()),
        Script::default()
            .reply(200, &head_of("abc123"))
            .reply(200, &statuses(&[]))
            .raw(200, big),
    ];
    for script in steps {
        assert_eq!(
            forge(&script).ci_result(&target, PR_URL).await.err(),
            Some(ForgeError::TooLarge)
        );
    }
    let script = Script::default()
        .reply(200, &head_of("abc123"))
        .fail(HttpError::Timeout);
    assert_eq!(
        forge(&script).ci_result(&target, PR_URL).await.err(),
        Some(ForgeError::Timeout)
    );
    Ok(())
}

#[tokio::test]
async fn ci_result_refuses_a_foreign_pull_url_before_any_request() -> TestResult {
    let urls = [
        "",
        "https://git.example.com/octo/other/pulls/7",
        "https://evil.example/octo/widgets/pulls/7",
        "https://git.example.com@evil.example/octo/widgets/pulls/7",
        "https://git.example.com/octo/widgets/pulls/7\r\nX: y",
        "https://git.example.com/octo/widgets/pulls/../../x",
        "https://git.example.com/octo/widgets/pulls/0",
    ];
    for url in urls {
        let script = Script::default();
        let got = forge(&script).ci_result(&target()?, url).await;
        assert_eq!(got.err(), Some(ForgeError::Malformed), "{url:?}");
        assert!(script.seen().is_empty(), "{url:?}");
    }
    let other = RepoAccess::new(
        RepoRef::new(host("git.example.com")?, "octo", "widgets")?,
        Credential::new(host("other.example.com")?, Token::new(TOKEN.to_owned())?),
    );
    let script = Script::default();
    let got = forge(&script).ci_result(&target_for(other)?, PR_URL).await;
    assert_eq!(got.err(), Some(ForgeError::HostMismatch));
    assert_eq!(script.seen().len(), 0);
    Ok(())
}

#[tokio::test]
async fn every_case_passes_on_the_gitea_fake() {
    let subject = AdapterSubject(|fake: &Fake| {
        GiteaForge::new(fake.clone()).with_git(fake.host(), fake.clone())
    });
    let report = run_contract(&subject, Shape::Gitea, || Fake::new(Shape::Gitea)).await;
    let findings: Vec<String> = report.findings.iter().map(ToString::to_string).collect();
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(report.ran.len(), Case::ALL.len());
    let git_cases = Case::ALL
        .iter()
        .filter(|c| matches!(c.op(), Op::Push | Op::Fetch))
        .count();
    assert_eq!(git_cases, 5);
}

#[derive(Clone, Default)]
struct GitScript {
    outputs: Arc<Mutex<VecDeque<Result<GitOutput, GitError>>>>,
    seen: Arc<Mutex<Vec<GitCommand>>>,
}

impl GitScript {
    fn output(self, code: i32, stderr: &str) -> Self {
        self.push(Ok(GitOutput {
            code,
            stderr: stderr.to_owned(),
        }))
    }

    fn fail(self, error: GitError) -> Self {
        self.push(Err(error))
    }

    fn push(self, reply: Result<GitOutput, GitError>) -> Self {
        self.outputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(reply);
        self
    }

    fn seen(&self) -> Vec<GitCommand> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Git for GitScript {
    fn run(&self, command: GitCommand) -> impl Future<Output = Result<GitOutput, GitError>> + Send {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(command);
        let reply = self
            .outputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or(Err(GitError::Spawn));
        std::future::ready(reply)
    }
}

fn git_forge(git: &GitScript) -> Result<GiteaForge<Script, GiteaGit<GitScript>>, Box<dyn Error>> {
    Ok(GiteaForge::new(Script::default()).with_git(host("git.example.com")?, git.clone()))
}

fn access_on(repo_host: &str, credential_host: &str) -> Result<RepoAccess, Box<dyn Error>> {
    let repo = RepoRef::new(host(repo_host)?, "octo", "widgets")?;
    let credential = Credential::new(host(credential_host)?, Token::new(TOKEN.to_owned())?);
    Ok(RepoAccess::new(repo, credential))
}

#[tokio::test]
async fn push_runs_one_command_for_the_validated_target() -> TestResult {
    let git = GitScript::default().output(0, "To https://git.example.com/octo/widgets.git\n");
    let status = git_forge(&git)?.push(&target()?).await?;
    assert_eq!(status, "pushed");
    let seen = git.seen();
    assert_eq!(seen.len(), 1);
    let command = &seen[0];
    assert_eq!(command.op, GitOp::Push);
    assert_eq!(command.branch.as_deref(), Some("fleet/job-1"));
    assert_eq!(command.repo.host().as_str(), "git.example.com");
    assert_eq!(command.repo.owner(), "octo");
    assert_eq!(command.repo.repo(), "widgets");
    assert_eq!(command.credential.host().as_str(), "git.example.com");
    Ok(())
}

#[tokio::test]
async fn fetch_runs_one_command_with_no_branch() -> TestResult {
    let git = GitScript::default().output(0, "");
    let status = git_forge(&git)?.fetch(&access()?).await?;
    assert_eq!(status, "fetched");
    let seen = git.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].op, GitOp::Fetch);
    assert_eq!(seen[0].branch, None);
    assert_eq!(seen[0].repo.owner(), "octo");
    Ok(())
}

#[tokio::test]
async fn the_command_and_the_adapter_print_no_token() -> TestResult {
    let git = GitScript::default().output(0, "");
    let forge = git_forge(&git)?;
    forge.push(&target()?).await?;
    let text = format!("{:?} {:?} {:?}", git.seen(), forge, access()?);
    assert!(!text.contains(TOKEN), "{text}");
    Ok(())
}

#[tokio::test]
async fn push_refuses_a_branch_git_would_refuse_before_running_anything() -> TestResult {
    for branch in [
        "a/.hidden",
        ".hidden",
        "x.lock",
        "a.lock/b",
        "a/b.lock",
        "a.LOCK",
        "a/B.Lock",
    ] {
        let git = GitScript::default().output(0, "");
        let target = PushTarget::new(access()?, branch, "main")?;
        let got = git_forge(&git)?.push(&target).await;
        assert_eq!(got, Err(ForgeError::Malformed), "{branch:?}");
        assert!(git.seen().is_empty(), "{branch:?}");
    }
    Ok(())
}

#[tokio::test]
async fn push_accepts_the_branch_edges() -> TestResult {
    for branch in ["a", "fleet/job-1", "a.b/c_d", "v1.0", "a.lockx", "lock"] {
        let git = GitScript::default().output(0, "");
        let target = PushTarget::new(access()?, branch, "main")?;
        assert_eq!(
            git_forge(&git)?.push(&target).await?,
            "pushed",
            "{branch:?}"
        );
        assert_eq!(git.seen()[0].branch.as_deref(), Some(branch));
    }
    Ok(())
}

#[test]
fn hostile_branches_never_reach_a_push_target() -> TestResult {
    let long = "a".repeat(256);
    let hostile = [
        "",
        "-x",
        "--upload-pack=x",
        "/a",
        "a/",
        "a.",
        "a..b",
        "..",
        "a//b",
        "a\\b",
        "a b",
        "a\tb",
        "a\rb",
        "a\nb",
        "a\r\nb",
        "a\0b",
        "a\u{7f}b",
        "a\u{85}b",
        "a\u{2028}b",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a~b",
        "a^b",
        "a@{b",
        "a@b",
        "a%2fb",
        "é",
        long.as_str(),
    ];
    for branch in hostile {
        assert!(
            PushTarget::new(access()?, branch, "main").is_err(),
            "{branch:?}"
        );
        assert!(
            PushTarget::new(access()?, "main", branch).is_err(),
            "{branch:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_host_other_than_the_adapters_own_runs_no_command() -> TestResult {
    let git = GitScript::default().output(0, "").output(0, "");
    let forge = git_forge(&git)?;
    let off = access_on("other.example.com", "other.example.com")?;
    let mismatch = access_on("git.example.com", "other.example.com")?;
    assert_eq!(forge.fetch(&off).await, Err(ForgeError::WrongKind));
    assert_eq!(forge.fetch(&mismatch).await, Err(ForgeError::HostMismatch));
    assert_eq!(
        forge
            .push(&PushTarget::new(off, "fleet/job-1", "main")?)
            .await,
        Err(ForgeError::WrongKind)
    );
    assert_eq!(
        forge
            .push(&PushTarget::new(mismatch, "fleet/job-1", "main")?)
            .await,
        Err(ForgeError::HostMismatch)
    );
    assert_eq!(git.seen().len(), 0);
    Ok(())
}

#[tokio::test]
async fn two_adapters_each_serve_only_their_own_host() -> TestResult {
    let first = GitScript::default().output(0, "").output(0, "");
    let second = GitScript::default().output(0, "").output(0, "");
    let one = GiteaForge::new(Script::default()).with_git(host("one.example.com")?, first.clone());
    let two = GiteaForge::new(Script::default()).with_git(host("two.example.com")?, second.clone());
    let on_one = access_on("one.example.com", "one.example.com")?;
    let on_two = access_on("two.example.com", "two.example.com")?;
    assert_eq!(one.fetch(&on_one).await?, "fetched");
    assert_eq!(two.fetch(&on_two).await?, "fetched");
    assert_eq!(one.fetch(&on_two).await, Err(ForgeError::WrongKind));
    assert_eq!(two.fetch(&on_one).await, Err(ForgeError::WrongKind));
    let pushed = PushTarget::new(on_one, "fleet/job-1", "main")?;
    assert_eq!(two.push(&pushed).await, Err(ForgeError::WrongKind));
    assert_eq!(one.push(&pushed).await?, "pushed");
    assert_eq!(first.seen().len(), 2);
    assert_eq!(second.seen().len(), 1);
    assert_eq!(
        first.seen()[0].credential.host().as_str(),
        "one.example.com"
    );
    assert_eq!(
        second.seen()[0].credential.host().as_str(),
        "two.example.com"
    );
    Ok(())
}

#[tokio::test]
async fn lookalike_and_hostile_hosts_never_reach_a_command() -> TestResult {
    let long = format!("{}.example.com", "a".repeat(300));
    let hostile = [
        "git.example.com.evil.net",
        "xgit.example.com",
        "sub.git.example.com",
        "example.com",
        "git.example.com@evil.net",
        "evil.net\r\ngit.example.com",
        "git.example.com\u{85}evil.net",
        "git.example.com\u{2028}evil.net",
        "git.example.com\\evil.net",
        "git.example.com:8443",
        "[::1]",
        "git.example.com ",
        "",
        "git..example.com",
        "gıt.example.com",
        "git.example.com\0",
        long.as_str(),
    ];
    for text in hostile {
        let git = GitScript::default().output(0, "").output(0, "");
        let forge = git_forge(&git)?;
        if let Ok(name) = HostName::normalise(text) {
            let repo = RepoRef::new(name.clone(), "octo", "widgets")?;
            let credential = Credential::new(name, Token::new(TOKEN.to_owned())?);
            let access = RepoAccess::new(repo, credential);
            assert_eq!(
                forge.fetch(&access).await,
                Err(ForgeError::WrongKind),
                "{text:?}"
            );
            let target = PushTarget::new(access, "fleet/job-1", "main")?;
            assert_eq!(
                forge.push(&target).await,
                Err(ForgeError::WrongKind),
                "{text:?}"
            );
        }
        assert!(git.seen().is_empty(), "{text:?}");
    }
    Ok(())
}

#[tokio::test]
async fn the_own_host_matches_in_any_spelling_of_the_same_name() -> TestResult {
    for text in ["GIT.EXAMPLE.COM", "git.example.com.", "Git.Example.Com"] {
        let git = GitScript::default().output(0, "");
        let access = access_on(text, text)?;
        assert_eq!(
            git_forge(&git)?.fetch(&access).await?,
            "fetched",
            "{text:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn runner_failures_map_to_fixed_errors() -> TestResult {
    let git = GitScript::default()
        .fail(GitError::Spawn)
        .fail(GitError::Timeout)
        .fail(GitError::Spawn)
        .fail(GitError::Timeout);
    let forge = git_forge(&git)?;
    assert_eq!(forge.push(&target()?).await, Err(ForgeError::Unavailable));
    assert_eq!(forge.push(&target()?).await, Err(ForgeError::Timeout));
    assert_eq!(forge.fetch(&access()?).await, Err(ForgeError::Unavailable));
    assert_eq!(forge.fetch(&access()?).await, Err(ForgeError::Timeout));
    Ok(())
}

#[tokio::test]
async fn push_classifies_stderr_into_fixed_errors() -> TestResult {
    let cases: [(i32, &str, ForgeError); 12] = [
        (
            128,
            "fatal: could not read Password for 'https://git.example.com'",
            ForgeError::Unauthorized,
        ),
        (
            22,
            "error: The requested URL returned error: 401",
            ForgeError::Unauthorized,
        ),
        (
            1,
            " ! [rejected] a -> a (non-fast-forward)",
            ForgeError::NonFastForward,
        ),
        (
            1,
            " ! [rejected] a -> a (fetch first)",
            ForgeError::NonFastForward,
        ),
        (
            128,
            "remote: Invalid username or password.",
            ForgeError::Unauthorized,
        ),
        (
            128,
            "remote: Permission to o/r.git denied to x.",
            ForgeError::Unauthorized,
        ),
        (
            22,
            "error: The requested URL returned error: 403",
            ForgeError::Unauthorized,
        ),
        (128, "remote: Repository not found.", ForgeError::NotFound),
        (
            1,
            "non-fast-forward but also Authentication failed",
            ForgeError::Unauthorized,
        ),
        (
            1,
            " ! [REJECTED] a -> a (NON-FAST-FORWARD)",
            ForgeError::NonFastForward,
        ),
        (1, "something else entirely", ForgeError::Rejected),
        (255, "", ForgeError::Rejected),
    ];
    for (code, stderr, want) in cases {
        let git = GitScript::default().output(code, stderr);
        let got = git_forge(&git)?.push(&target()?).await;
        assert_eq!(got, Err(want), "{stderr:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_branch_named_like_a_marker_does_not_pick_the_label() -> TestResult {
    let cases: [(&str, &str, ForgeError); 4] = [
        (
            "non-fast-forward",
            " ! [remote rejected] non-fast-forward -> non-fast-forward (hook declined)",
            ForgeError::Rejected,
        ),
        (
            "x-non-fast-forward-y",
            " ! [remote rejected] x-non-fast-forward-y -> x-non-fast-forward-y (hook declined)",
            ForgeError::Rejected,
        ),
        (
            "Non-Fast-Forward",
            " ! [remote rejected] non-fast-forward -> non-fast-forward (hook declined)",
            ForgeError::Rejected,
        ),
        (
            "non-fast-forward",
            " ! [rejected] non-fast-forward -> non-fast-forward (non-fast-forward)",
            ForgeError::NonFastForward,
        ),
    ];
    for (branch, stderr, want) in cases {
        let git = GitScript::default().output(1, stderr);
        let target = PushTarget::new(access()?, branch, "main")?;
        let got = git_forge(&git)?.push(&target).await;
        assert_eq!(got, Err(want), "{branch:?} {stderr:?}");
    }
    Ok(())
}

#[tokio::test]
async fn fetch_never_reports_non_fast_forward() -> TestResult {
    let cases: [(&str, ForgeError); 3] = [
        ("non-fast-forward", ForgeError::Rejected),
        ("fatal: Authentication failed", ForgeError::Unauthorized),
        ("remote: Repository not found.", ForgeError::NotFound),
    ];
    for (stderr, want) in cases {
        let git = GitScript::default().output(128, stderr);
        assert_eq!(
            git_forge(&git)?.fetch(&access()?).await,
            Err(want),
            "{stderr:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_marker_past_the_stderr_cap_is_ignored() -> TestResult {
    for (pad, want) in [
        (8 * 1024, ForgeError::Rejected),
        (8 * 1024 - 15, ForgeError::Rejected),
        (8 * 1024 - 16, ForgeError::NonFastForward),
    ] {
        let text = format!("{}non-fast-forward", "x".repeat(pad));
        let git = GitScript::default().output(1, &text);
        assert_eq!(git_forge(&git)?.push(&target()?).await, Err(want), "{pad}");
    }
    let wide = format!("{}é non-fast-forward", "é".repeat(4096));
    let git = GitScript::default().output(1, &wide);
    assert_eq!(
        git_forge(&git)?.push(&target()?).await,
        Err(ForgeError::Rejected)
    );
    Ok(())
}

#[tokio::test]
async fn no_runner_text_reaches_a_status_or_an_error() -> TestResult {
    let hostile = [
        format!(
            "fatal: Authentication failed for 'https://x-access-token:{TOKEN}@git.example.com/o/r.git/'"
        ),
        format!("{TOKEN} non-fast-forward"),
        format!("remote: Repository not found. {TOKEN}"),
        format!("{TOKEN}\r\nX-Injected: 1"),
        TOKEN.to_owned(),
    ];
    for stderr in &hostile {
        for code in [0, 1, 128] {
            let git = GitScript::default()
                .output(code, stderr)
                .output(code, stderr);
            let forge = git_forge(&git)?;
            for got in [forge.push(&target()?).await, forge.fetch(&access()?).await] {
                let text = match got {
                    Ok(text) => {
                        assert!(text == "pushed" || text == "fetched", "{text:?}");
                        text
                    }
                    Err(error) => error.to_string(),
                };
                assert!(!text.contains(TOKEN), "{text}");
                assert!(!text.contains("x-access-token"), "{text}");
                assert!(!text.contains("X-Injected"), "{text}");
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn the_masked_echo_never_joins_the_text_around_it_into_a_marker() -> TestResult {
    let git = GitScript::default().output(1, "non-fastb -> b-forward");
    let target = PushTarget::new(access()?, "b", "main")?;
    assert_eq!(
        git_forge(&git)?.push(&target).await,
        Err(ForgeError::Rejected)
    );
    Ok(())
}
