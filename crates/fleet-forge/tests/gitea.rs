//! Per-adapter tests of `GiteaForge`: the identify cases of the shared contract table on the
//! Gitea fake, then the wire details and the hostile-input table the table does not cover.

use std::collections::VecDeque;
use std::error::Error;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use fleet_forge::contract::{AdapterSubject, Case, Finding, Op, run_contract};
use fleet_forge::fake::{Fake, Shape};
use fleet_forge::{
    ForgeApi, ForgeError, ForgeGit, GiteaForge, Http, HttpError, HttpRequest, HttpResponse,
    MAX_BODY_BYTES, Method, PushTarget, RepoAccess, Verified,
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

#[tokio::test]
async fn the_other_operations_refuse_until_they_land() -> TestResult {
    use fleet_forge::{Credential, RepoRef, Token};
    let script = Script::default();
    let repo = RepoRef::new(host("git.example.com")?, "octo", "widgets")?;
    let token = Token::new("0123456789abcdef0123456789abcdef01234567".to_owned())?;
    let access = RepoAccess::new(repo, Credential::new(host("git.example.com")?, token));
    let target = PushTarget::new(access.clone(), "fleet/job-1", "main")?;
    let adapter = forge(&script);
    assert_eq!(
        adapter.verify(&access).await.err(),
        Some(ForgeError::Unavailable)
    );
    assert_eq!(
        adapter.create_pr(&target, "t", "b").await.err(),
        Some(ForgeError::Unavailable)
    );
    assert_eq!(
        adapter.ci_result(&target, "u").await.err(),
        Some(ForgeError::Unavailable)
    );
    assert_eq!(script.seen().len(), 0);
    Ok(())
}
