//! The ADR-0068 contract table and the harness self-tests.
//!
//! The table below lists every row of the ADR with the cases that realise it. A case missing
//! from the table, or a row naming a case that does not exist, fails the build. Each adapter
//! registers with one test that runs `run_contract` and `into_result` on a complete fake.

use std::collections::BTreeSet;
use std::error::Error;
use std::future::{Future, ready};
use std::sync::Mutex;

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use fleet_forge::contract::{
    AdapterSubject, Calls, Case, Driven, Finding, Outcome, Subject, drive, run_contract,
};
use fleet_forge::fake::{Fake, Shape};
use fleet_forge::{
    Credential, ForgeApi, ForgeError, ForgeGit, Git, GitCommand, GitOp, GitOutput, Http,
    HttpRequest, HttpResponse, Method, Permission, PushTarget, RepoAccess, RepoRef, Token,
    Verified,
};

type TestResult = Result<(), Box<dyn Error>>;

const SHAPES: [Shape; 2] = [Shape::GitHub, Shape::Gitea];

const ADR_TABLE: &[(&str, &[&str])] = &[
    (
        "identify ok, identify refuses a non-forge or wrong-kind host",
        &["identify-ok", "identify-non-forge", "identify-wrong-kind"],
    ),
    ("verify ok, read and push", &["verify-read-push"]),
    ("verify ok, read only", &["verify-read-only"]),
    (
        "verify ok, no permissions field",
        &["verify-no-permissions"],
    ),
    ("verify 404", &["verify-404"]),
    ("verify 401 and 403", &["verify-401", "verify-403"]),
    ("verify 5xx and reset", &["verify-5xx", "verify-reset"]),
    ("verify slow body past budget", &["verify-slow"]),
    ("verify body over cap", &["verify-over-cap"]),
    ("verify answers 3xx", &["verify-redirect"]),
    ("create_pr ok", &["create-pr-ok"]),
    ("create_pr already exists", &["create-pr-exists"]),
    ("create_pr rejected", &["create-pr-rejected"]),
    (
        "ci_result pending, success, failure, none, mixed",
        &[
            "ci-pending",
            "ci-success",
            "ci-failure",
            "ci-none",
            "ci-mixed",
        ],
    ),
    ("ci_result 404", &["ci-404"]),
    (
        "push ok, non-fast-forward, revoked token",
        &["push-ok", "push-non-fast-forward", "push-revoked"],
    ),
    (
        "fetch ok, auth failure",
        &["fetch-ok", "fetch-auth-failure"],
    ),
    ("credential for another host", &["credential-other-host"]),
    ("redacted error", &["redacted-error"]),
];

fn host(text: &str) -> Result<HostName, Box<dyn Error>> {
    Ok(HostName::normalise(text)?)
}

struct Stub {
    shape: Shape,
    ran: Mutex<Vec<Case>>,
    skip: Option<Case>,
    lie: Option<Case>,
    extra_requests: Option<Case>,
    leak: Option<Case>,
}

impl Stub {
    const fn new(shape: Shape) -> Self {
        Self {
            shape,
            ran: Mutex::new(Vec::new()),
            skip: None,
            lie: None,
            extra_requests: None,
            leak: None,
        }
    }

    fn ran(&self) -> Vec<Case> {
        self.ran.lock().map(|ran| ran.clone()).unwrap_or_default()
    }
}

async fn request(fake: &Fake) {
    let request = HttpRequest {
        method: Method::Get,
        host: fake.host(),
        path: match fake.shape() {
            Shape::GitHub => "/repos/octo/widgets".to_owned(),
            Shape::Gitea => "/api/v1/repos/octo/widgets".to_owned(),
        },
        headers: vec![("Authorization".to_owned(), format!("token {}", Fake::TOKEN))],
        body: Vec::new(),
    };
    let _ = fake.send(request).await;
}

fn fetch_command(fake: &Fake) -> Option<GitCommand> {
    let token = Token::new(Fake::TOKEN.to_owned()).ok()?;
    Some(GitCommand {
        op: GitOp::Fetch,
        repo: RepoRef::new(fake.host(), "octo", "widgets").ok()?,
        branch: None,
        credential: Credential::new(fake.host(), token),
    })
}

async fn fetch_stderr(fake: &Fake) -> String {
    let Some(command) = fetch_command(fake) else {
        return String::new();
    };
    fake.run(command)
        .await
        .map(|out| out.stderr)
        .unwrap_or_default()
}

impl Subject for Stub {
    async fn run(&self, case: Case, fake: &Fake) -> Option<Driven> {
        if let Ok(mut ran) = self.ran.lock() {
            ran.push(case);
        }
        if self.skip == Some(case) {
            return None;
        }
        if !matches!(case.calls(), Calls::None) {
            request(fake).await;
        }
        if self.extra_requests == Some(case) {
            request(fake).await;
        }
        if self.lie == Some(case) {
            return Some(Outcome::Failed(ForgeError::Malformed).into());
        }
        if self.leak == Some(case) {
            return Some(Driven {
                outcome: case.expected(self.shape),
                text: fetch_stderr(fake).await,
            });
        }
        Some(case.expected(self.shape).into())
    }
}

#[test]
fn the_adr_table_names_every_case_once() {
    let mut named = Vec::new();
    for (_, cases) in ADR_TABLE {
        named.extend_from_slice(cases);
    }
    let unique: BTreeSet<&str> = named.iter().copied().collect();
    assert_eq!(unique.len(), named.len(), "a case is named by two rows");
    let all: BTreeSet<&str> = Case::ALL.iter().map(|c| c.name()).collect();
    assert_eq!(unique, all);
    assert_eq!(Case::ALL.len(), all.len(), "two cases share a name");
}

#[test]
fn every_fake_answers_every_case() {
    for shape in SHAPES {
        let fake = Fake::new(shape);
        for &case in Case::ALL {
            assert!(fake.arm(case).is_ok(), "{shape:?} lacks {}", case.name());
        }
    }
}

#[tokio::test]
async fn the_harness_self_test_runs_every_case_against_a_recording_stub() -> TestResult {
    for shape in SHAPES {
        let stub = Stub::new(shape);
        let report = run_contract(&stub, shape, || Fake::new(shape)).await;
        assert_eq!(report.ran, Case::ALL, "{shape:?}");
        assert_eq!(stub.ran(), Case::ALL, "{shape:?}");
        report.into_result()?;
    }
    Ok(())
}

#[tokio::test]
async fn an_adapter_that_lacks_a_case_fails_the_harness() {
    for shape in SHAPES {
        let mut stub = Stub::new(shape);
        stub.skip = Some(Case::PushNonFastForward);
        let report = run_contract(&stub, shape, || Fake::new(shape)).await;
        assert!(
            report
                .findings
                .contains(&Finding::SubjectLacksCase(Case::PushNonFastForward))
        );
        assert_eq!(report.ran.len(), Case::ALL.len() - 1);
        assert!(report.into_result().is_err());
    }
}

#[tokio::test]
async fn a_fake_that_lacks_a_case_fails_the_harness() {
    for shape in SHAPES {
        let stub = Stub::new(shape);
        let report = run_contract(&stub, shape, || Fake::lacking(shape, &[Case::CiMixed])).await;
        assert_eq!(report.findings, vec![Finding::FakeLacksCase(Case::CiMixed)]);
        assert!(!stub.ran().contains(&Case::CiMixed));
        assert!(report.into_result().is_err());
    }
}

#[tokio::test]
async fn a_wrong_outcome_is_one_mismatch() {
    let shape = Shape::Gitea;
    let mut stub = Stub::new(shape);
    stub.lie = Some(Case::Verify404);
    let report = run_contract(&stub, shape, || Fake::new(shape)).await;
    assert_eq!(
        report.findings,
        vec![Finding::Mismatch {
            case: Case::Verify404,
            expected: Outcome::Failed(ForgeError::NotFound),
            actual: Outcome::Failed(ForgeError::Malformed),
        }]
    );
}

#[tokio::test]
async fn a_second_request_after_a_redirect_is_a_finding() {
    for shape in SHAPES {
        let mut stub = Stub::new(shape);
        stub.extra_requests = Some(Case::VerifyRedirect);
        let report = run_contract(&stub, shape, || Fake::new(shape)).await;
        assert!(
            report
                .findings
                .contains(&Finding::AuthorizationReplayed(Case::VerifyRedirect))
        );
        assert!(report.findings.contains(&Finding::Calls {
            case: Case::VerifyRedirect,
            seen: 2
        }));
    }
}

#[tokio::test]
async fn a_token_in_a_status_text_is_a_finding() {
    for shape in SHAPES {
        let mut stub = Stub::new(shape);
        stub.leak = Some(Case::FetchAuthFailure);
        let report = run_contract(&stub, shape, || Fake::new(shape)).await;
        assert_eq!(
            report.findings,
            vec![Finding::TokenLeaked(Case::FetchAuthFailure)]
        );
    }
}

#[tokio::test]
async fn the_leaking_stderr_holds_the_token() {
    let fake = Fake::new(Shape::Gitea);
    fake.arm(Case::FetchAuthFailure).ok();
    assert!(fetch_stderr(&fake).await.contains(Fake::TOKEN));
}

#[tokio::test]
async fn a_request_in_a_refuse_first_case_is_a_finding() {
    struct Chatty;
    impl Subject for Chatty {
        async fn run(&self, case: Case, fake: &Fake) -> Option<Driven> {
            request(fake).await;
            Some(case.expected(fake.shape()).into())
        }
    }
    let report = run_contract(&Chatty, Shape::GitHub, || Fake::new(Shape::GitHub)).await;
    assert_eq!(
        report.findings,
        vec![Finding::Calls {
            case: Case::CredentialOtherHost,
            seen: 1
        }]
    );
}

#[tokio::test]
async fn a_case_that_sends_nothing_is_a_finding() {
    struct Silent;
    impl Subject for Silent {
        fn run(&self, case: Case, fake: &Fake) -> impl Future<Output = Option<Driven>> + Send {
            ready(Some(case.expected(fake.shape()).into()))
        }
    }
    let report = run_contract(&Silent, Shape::Gitea, || Fake::new(Shape::Gitea)).await;
    assert_eq!(report.findings.len(), Case::ALL.len() - 1);
    assert!(!report.findings.contains(&Finding::Calls {
        case: Case::CredentialOtherHost,
        seen: 0
    }));
}

struct Canned {
    verify: Result<Verified, ForgeError>,
    url: String,
}

impl ForgeApi for Canned {
    fn identify(&self, _: &HostName) -> impl Future<Output = Result<HostKind, ForgeError>> + Send {
        ready(Ok(HostKind::Forgejo))
    }

    fn verify(
        &self,
        access: &RepoAccess,
    ) -> impl Future<Output = Result<Verified, ForgeError>> + Send {
        ready(access.bind().and(self.verify))
    }

    fn create_pr(
        &self,
        _: &PushTarget,
        _: &str,
        _: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        ready(Ok(self.url.clone()))
    }

    fn ci_result(
        &self,
        _: &PushTarget,
        _: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        ready(Ok(CiResult::Queued))
    }
}

impl ForgeGit for Canned {
    fn fetch(&self, _: &RepoAccess) -> impl Future<Output = Result<String, ForgeError>> + Send {
        ready(Ok("ok".to_owned()))
    }

    fn push(&self, _: &PushTarget) -> impl Future<Output = Result<String, ForgeError>> + Send {
        ready(Err(ForgeError::Rejected))
    }
}

fn canned(url: &str) -> Canned {
    Canned {
        verify: Ok(Verified {
            push: Permission::Granted,
        }),
        url: url.to_owned(),
    }
}

struct Chatter(&'static str);

impl ForgeApi for Chatter {
    fn identify(&self, _: &HostName) -> impl Future<Output = Result<HostKind, ForgeError>> + Send {
        ready(Ok(HostKind::Forgejo))
    }

    fn verify(&self, _: &RepoAccess) -> impl Future<Output = Result<Verified, ForgeError>> + Send {
        ready(Err(ForgeError::NotFound))
    }

    fn create_pr(
        &self,
        _: &PushTarget,
        _: &str,
        _: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        ready(Err(ForgeError::Rejected))
    }

    fn ci_result(
        &self,
        _: &PushTarget,
        _: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        ready(Err(ForgeError::Malformed))
    }
}

impl ForgeGit for Chatter {
    fn fetch(&self, _: &RepoAccess) -> impl Future<Output = Result<String, ForgeError>> + Send {
        ready(Ok(self.0.to_owned()))
    }

    fn push(&self, _: &PushTarget) -> impl Future<Output = Result<String, ForgeError>> + Send {
        ready(Ok(self.0.to_owned()))
    }
}

#[tokio::test]
async fn drive_keeps_the_status_text_of_push_and_fetch_and_the_error_text() {
    let fake = Fake::new(Shape::Gitea);
    let adapter = Chatter("status line");
    for case in [Case::PushOk, Case::FetchOk] {
        assert_eq!(drive(&adapter, case, &fake).await.text, "status line");
    }
    assert_eq!(
        drive(&adapter, Case::Verify404, &fake).await.text,
        ForgeError::NotFound.to_string()
    );
    assert_eq!(drive(&adapter, Case::IdentifyOk, &fake).await.text, "");
}

#[tokio::test]
async fn an_adapter_that_returns_the_token_in_a_status_is_caught() {
    let leaky = AdapterSubject(|_: &Fake| Chatter(Fake::TOKEN));
    let report = run_contract(&leaky, Shape::GitHub, || Fake::new(Shape::GitHub)).await;
    assert!(
        report
            .findings
            .contains(&Finding::TokenLeaked(Case::PushOk))
    );
    assert!(
        report
            .findings
            .contains(&Finding::TokenLeaked(Case::FetchOk))
    );
}

#[tokio::test]
async fn drive_maps_each_operation_to_an_outcome() {
    let fake = Fake::new(Shape::Gitea);
    let adapter = canned(&fake.pr_url());
    let drove = async |case| drive(&adapter, case, &fake).await.outcome;
    assert_eq!(
        drove(Case::IdentifyOk).await,
        Outcome::Identified(HostKind::Forgejo)
    );
    assert_eq!(
        drove(Case::VerifyReadPush).await,
        Outcome::Verified(Permission::Granted)
    );
    assert_eq!(drove(Case::CreatePrOk).await, Outcome::PrUrl);
    assert_eq!(drove(Case::CiSuccess).await, Outcome::Ci(CiResult::Queued));
    assert_eq!(
        drove(Case::PushOk).await,
        Outcome::Failed(ForgeError::Rejected)
    );
    assert_eq!(drove(Case::FetchOk).await, Outcome::Fetched);
}

#[tokio::test]
async fn drive_flags_another_pr_url() {
    let fake = Fake::new(Shape::GitHub);
    let adapter = canned("https://github.com/octo/widgets/pull/8");
    assert_eq!(
        drive(&adapter, Case::CreatePrOk, &fake).await.outcome,
        Outcome::BadUrl
    );
}

#[tokio::test]
async fn drive_pairs_the_credential_of_another_host_for_that_case_only() {
    let fake = Fake::new(Shape::Gitea);
    let adapter = canned(&fake.pr_url());
    assert_eq!(
        drive(&adapter, Case::CredentialOtherHost, &fake)
            .await
            .outcome,
        Outcome::Failed(ForgeError::HostMismatch)
    );
    assert_eq!(
        drive(&adapter, Case::VerifyReadPush, &fake).await.outcome,
        Outcome::Verified(Permission::Granted)
    );
}

#[tokio::test]
async fn an_adapter_subject_runs_the_adapter_per_case() {
    let subject = AdapterSubject(|fake: &Fake| canned(&fake.pr_url()));
    let fake = Fake::new(Shape::Gitea);
    fake.arm(Case::FetchOk).ok();
    assert_eq!(
        subject.run(Case::FetchOk, &fake).await,
        Some(Driven {
            outcome: Outcome::Fetched,
            text: "ok".to_owned()
        })
    );
}

#[test]
fn a_token_never_prints_and_a_mismatched_credential_is_refused() -> TestResult {
    let token = Token::new("secret-value".to_owned())?;
    assert!(!format!("{token:?}").contains("secret-value"));
    let repo = RepoRef::new(host("git.example.com")?, "octo", "widgets")?;
    let wrong = RepoAccess::new(
        repo.clone(),
        Credential::new(host("other.example.com")?, token.clone()),
    );
    assert_eq!(wrong.bind().err(), Some(ForgeError::HostMismatch));
    let right = RepoAccess::new(repo, Credential::new(host("git.example.com")?, token));
    assert_eq!(right.bind()?.1.expose(), "secret-value");
    Ok(())
}

#[test]
fn hostile_names_branches_and_tokens_are_refused() -> TestResult {
    let h = host("git.example.com")?;
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a b",
        "a\nb",
        "a\u{2028}b",
        "é",
        &"x".repeat(101),
    ] {
        assert_eq!(
            RepoRef::new(h.clone(), bad, "r").err(),
            Some(ForgeError::Malformed),
            "{bad:?}"
        );
        assert_eq!(
            RepoRef::new(h.clone(), "o", bad).err(),
            Some(ForgeError::Malformed),
            "{bad:?}"
        );
    }
    let access = RepoAccess::new(
        RepoRef::new(h.clone(), "o", "r")?,
        Credential::new(h, Token::new("t".to_owned())?),
    );
    for bad in [
        "",
        "-x",
        "/x",
        "x/",
        "x.",
        "a..b",
        "a//b",
        "a b",
        "a\tb",
        "a~b",
        "a:b",
        &"x".repeat(256),
    ] {
        assert_eq!(
            PushTarget::new(access.clone(), bad, "main").err(),
            Some(ForgeError::Malformed),
            "{bad:?}"
        );
        assert_eq!(
            PushTarget::new(access.clone(), "main", bad).err(),
            Some(ForgeError::Malformed),
            "{bad:?}"
        );
    }
    PushTarget::new(access, "fleet/job-1", "main")?;
    for bad in ["", "a b", "a\nb", "a\u{85}b", &"x".repeat(256)] {
        assert_eq!(
            Token::new(bad.to_owned()).err(),
            Some(ForgeError::Malformed),
            "{bad:?}"
        );
    }
    Ok(())
}

async fn get(path: &str, fake: &Fake) -> Result<HttpResponse, fleet_forge::HttpError> {
    fake.send(HttpRequest {
        method: Method::Get,
        host: fake.host(),
        path: path.to_owned(),
        headers: Vec::new(),
        body: Vec::new(),
    })
    .await
}

#[tokio::test]
async fn a_fake_answers_only_its_own_wire_shape() -> TestResult {
    let github = Fake::new(Shape::GitHub);
    github.arm(Case::VerifyReadPush)?;
    assert_eq!(get("/repos/octo/widgets", &github).await?.status, 200);
    assert_eq!(
        get("/api/v1/repos/octo/widgets", &github).await?.status,
        404
    );
    let gitea = Fake::new(Shape::Gitea);
    gitea.arm(Case::VerifyReadPush)?;
    assert_eq!(get("/api/v1/repos/octo/widgets", &gitea).await?.status, 200);
    assert_eq!(get("/repos/octo/widgets", &gitea).await?.status, 404);
    Ok(())
}

#[test]
fn limits_sit_on_their_exact_boundary_and_allowed_bytes_pass() -> TestResult {
    let h = host("git.example.com")?;
    RepoRef::new(h.clone(), &"x".repeat(100), "a.b_c-d")?;
    assert!(RepoRef::new(h.clone(), &"x".repeat(101), "r").is_err());
    assert!(RepoRef::new(h.clone(), "o", &"x".repeat(101)).is_err());
    for ok in ["a.b", "a_b", "a-b", "A9"] {
        RepoRef::new(h.clone(), ok, ok)?;
    }
    let access = RepoAccess::new(
        RepoRef::new(h.clone(), "o", "r")?,
        Credential::new(h, Token::new("t".to_owned())?),
    );
    PushTarget::new(access.clone(), &"x".repeat(255), "main")?;
    PushTarget::new(access.clone(), "main", &"x".repeat(255))?;
    for ok in ["a.b", "a_b", "a-b", "a/b", "a1.b_c-d/e"] {
        PushTarget::new(access.clone(), ok, ok)?;
    }
    Token::new("x".repeat(255))?;
    for bad in ["a\u{0}b", "a\u{7f}b", "a\u{1b}b"] {
        assert_eq!(
            Token::new(bad.to_owned()).err(),
            Some(ForgeError::Malformed),
            "{bad:?}"
        );
    }
    Ok(())
}

#[test]
fn the_seam_limits_are_pinned() {
    assert_eq!(fleet_forge::MAX_BODY_BYTES, 262_144);
    assert_eq!(
        fleet_forge::REPO_CHECK_BUDGET,
        std::time::Duration::from_secs(7)
    );
}

#[test]
fn a_report_is_green_only_when_clean_and_complete() {
    use fleet_forge::contract::Report;
    let clean = Report {
        ran: Case::ALL.to_vec(),
        findings: Vec::new(),
    };
    assert!(clean.into_result().is_ok());
    let short = Report {
        ran: Vec::new(),
        findings: Vec::new(),
    };
    assert!(short.into_result().is_err());
    let dirty = Report {
        ran: Case::ALL.to_vec(),
        findings: vec![Finding::TokenLeaked(Case::PushOk)],
    };
    assert!(dirty.into_result().is_err());
}

#[test]
fn a_request_debug_text_lacks_every_header_value_and_the_body() -> TestResult {
    let request = HttpRequest {
        method: Method::Post,
        host: host("git.example.com")?,
        path: "/api/v1/repos".to_owned(),
        headers: vec![
            ("Authorization".to_owned(), format!("token {}", Fake::TOKEN)),
            ("X-Other".to_owned(), "other-secret".to_owned()),
        ],
        body: b"body-secret".to_vec(),
    };
    let text = format!("{request:?}");
    assert!(!text.contains(Fake::TOKEN), "{text}");
    assert!(!text.contains("other-secret"), "{text}");
    assert!(!text.contains("body-secret"), "{text}");
    assert!(text.contains("Authorization"), "{text}");
    assert!(text.contains("/api/v1/repos"), "{text}");
    assert!(text.contains("git.example.com"), "{text}");
    assert!(text.contains("Post"), "{text}");
    assert!(text.contains("body_len: 11"), "{text}");
    assert!(format!("{request:#?}").contains("Authorization"));
    Ok(())
}

#[test]
fn a_response_debug_text_lacks_header_values_and_the_body() {
    let response = HttpResponse {
        status: 201,
        headers: vec![("Set-Cookie".to_owned(), "cookie-secret".to_owned())],
        body: b"body-secret".to_vec(),
    };
    let text = format!("{response:?}");
    assert!(!text.contains("cookie-secret"), "{text}");
    assert!(!text.contains("body-secret"), "{text}");
    assert!(text.contains("Set-Cookie"), "{text}");
    assert!(text.contains("201"), "{text}");
    assert!(text.contains("body_len: 11"), "{text}");
}

#[test]
fn a_git_output_debug_text_lacks_the_stderr() {
    let output = GitOutput {
        code: 128,
        stderr: format!("fatal: {}", Fake::TOKEN),
    };
    let text = format!("{output:?}");
    assert!(!text.contains(Fake::TOKEN), "{text}");
    assert!(text.contains("128"), "{text}");
}

#[test]
fn a_git_command_debug_text_lacks_the_token() -> TestResult {
    let command = fetch_command(&Fake::new(Shape::Gitea)).ok_or("fixture")?;
    let text = format!("{command:?}");
    assert!(!text.contains(Fake::TOKEN), "{text}");
    assert!(text.contains("redacted"), "{text}");
    Ok(())
}
