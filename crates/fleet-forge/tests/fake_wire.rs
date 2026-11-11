//! Wire-level checks of the fake servers and the pinned expectation table of the harness.
//!
//! The contract harness trusts the table and the fakes, so each is pinned here against a literal
//! copy. A changed expectation or reply fails one of these tests.

use std::error::Error;

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use fleet_forge::contract::{Calls, Case, ChecksSeen, Op, Outcome};
use fleet_forge::fake::{Fake, MissingScenario, Shape};
use fleet_forge::{
    Credential, ForgeError, Git, GitCommand, GitError, GitOp, Http, HttpError, HttpRequest,
    HttpResponse, MAX_BODY_BYTES, Method, Permission, RepoRef, Token,
};
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

const SHAPES: [Shape; 2] = [Shape::GitHub, Shape::Gitea];

fn repo_path(shape: Shape, suffix: &str) -> String {
    match shape {
        Shape::GitHub => format!("/repos/octo/widgets{suffix}"),
        Shape::Gitea => format!("/api/v1/repos/octo/widgets{suffix}"),
    }
}

async fn call(
    fake: &Fake,
    method: Method,
    path: &str,
    auth: bool,
) -> Result<HttpResponse, HttpError> {
    let headers = if auth {
        vec![("Authorization".to_owned(), format!("token {}", Fake::TOKEN))]
    } else {
        Vec::new()
    };
    fake.send(HttpRequest {
        method,
        host: fake.host(),
        path: path.to_owned(),
        headers,
        body: Vec::new(),
    })
    .await
}

fn armed(shape: Shape, case: Case) -> Result<Fake, MissingScenario> {
    let fake = Fake::new(shape);
    fake.arm(case)?;
    Ok(fake)
}

async fn json(
    shape: Shape,
    case: Case,
    method: Method,
    suffix: &str,
) -> Result<(u16, Value), Box<dyn Error>> {
    let fake = armed(shape, case)?;
    let response = call(&fake, method, &repo_path(shape, suffix), true).await?;
    Ok((response.status, serde_json::from_slice(&response.body)?))
}

#[test]
#[expect(clippy::too_many_lines, reason = "one literal table of every case")]
fn the_expected_outcome_table_is_pinned() {
    use ForgeError::{
        HostMismatch, Malformed, NonFastForward, NotFound, Redirected, Rejected, Timeout, TooLarge,
        Unauthorized, Unavailable, WrongKind,
    };
    let rows: &[(Case, Op, Calls, Outcome)] = &[
        (
            Case::IdentifyOk,
            Op::Identify,
            Calls::Any,
            Outcome::Identified(HostKind::Github),
        ),
        (
            Case::IdentifyNonForge,
            Op::Identify,
            Calls::Any,
            Outcome::Failed(WrongKind),
        ),
        (
            Case::IdentifyWrongKind,
            Op::Identify,
            Calls::Any,
            Outcome::Failed(WrongKind),
        ),
        (
            Case::VerifyReadPush,
            Op::Verify,
            Calls::Any,
            Outcome::Verified(Permission::Granted),
        ),
        (
            Case::VerifyReadOnly,
            Op::Verify,
            Calls::Any,
            Outcome::Verified(Permission::Denied),
        ),
        (
            Case::VerifyNoPermissions,
            Op::Verify,
            Calls::Any,
            Outcome::Verified(Permission::Unknown),
        ),
        (
            Case::Verify404,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(NotFound),
        ),
        (
            Case::Verify401,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(NotFound),
        ),
        (
            Case::Verify403,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(NotFound),
        ),
        (
            Case::Verify5xx,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(Unavailable),
        ),
        (
            Case::VerifyReset,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(Unavailable),
        ),
        (
            Case::VerifySlow,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(Timeout),
        ),
        (
            Case::VerifyOverCap,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(TooLarge),
        ),
        (
            Case::VerifyRedirect,
            Op::Verify,
            Calls::One,
            Outcome::Failed(Redirected),
        ),
        (Case::CreatePrOk, Op::CreatePr, Calls::Any, Outcome::PrUrl),
        (
            Case::CreatePrExists,
            Op::CreatePr,
            Calls::Any,
            Outcome::PrUrl,
        ),
        (
            Case::CreatePrRejected,
            Op::CreatePr,
            Calls::Any,
            Outcome::Failed(Rejected),
        ),
        (
            Case::CiPending,
            Op::CiResult,
            Calls::Any,
            Outcome::Ci(CiResult::InProgress),
        ),
        (
            Case::CiSuccess,
            Op::CiResult,
            Calls::Any,
            Outcome::Ci(CiResult::Success),
        ),
        (
            Case::CiFailure,
            Op::CiResult,
            Calls::Any,
            Outcome::Ci(CiResult::Failure),
        ),
        (
            Case::CiNone,
            Op::CiResult,
            Calls::Any,
            Outcome::Ci(CiResult::NoChecks),
        ),
        (
            Case::CiMixed,
            Op::CiResult,
            Calls::Any,
            Outcome::Ci(CiResult::Failure),
        ),
        (
            Case::Ci404,
            Op::CiResult,
            Calls::Any,
            Outcome::Failed(NotFound),
        ),
        (
            Case::CiChecksMixed,
            Op::CiChecks,
            Calls::Any,
            Outcome::Checks(ChecksSeen::Mixed),
        ),
        (
            Case::CiChecksNone,
            Op::CiChecks,
            Calls::Any,
            Outcome::Checks(ChecksSeen::Empty),
        ),
        (
            Case::CiChecks404,
            Op::CiChecks,
            Calls::Any,
            Outcome::Failed(NotFound),
        ),
        (
            Case::CiChecksBadName,
            Op::CiChecks,
            Calls::Any,
            Outcome::Failed(Malformed),
        ),
        (
            Case::CiChecksOverCap,
            Op::CiChecks,
            Calls::Any,
            Outcome::Failed(Malformed),
        ),
        (Case::PushOk, Op::Push, Calls::Any, Outcome::Pushed),
        (
            Case::PushNonFastForward,
            Op::Push,
            Calls::Any,
            Outcome::Failed(NonFastForward),
        ),
        (
            Case::PushRevoked,
            Op::Push,
            Calls::Any,
            Outcome::Failed(Unauthorized),
        ),
        (Case::FetchOk, Op::Fetch, Calls::Any, Outcome::Fetched),
        (
            Case::FetchAuthFailure,
            Op::Fetch,
            Calls::Any,
            Outcome::Failed(Unauthorized),
        ),
        (
            Case::CredentialOtherHost,
            Op::Verify,
            Calls::None,
            Outcome::Failed(HostMismatch),
        ),
        (
            Case::RedactedError,
            Op::Verify,
            Calls::Any,
            Outcome::Failed(Unavailable),
        ),
    ];
    assert_eq!(rows.len(), Case::ALL.len());
    for (row, case) in rows.iter().zip(Case::ALL) {
        assert_eq!(row.0, *case);
        assert_eq!(row.1, case.op(), "{}", case.name());
        assert_eq!(row.2, case.calls(), "{}", case.name());
        assert_eq!(row.3, case.expected(Shape::GitHub), "{}", case.name());
        let gitea = if matches!(case, Case::IdentifyOk) {
            Outcome::Identified(HostKind::Forgejo)
        } else {
            row.3
        };
        assert_eq!(gitea, case.expected(Shape::Gitea), "{}", case.name());
    }
}

#[test]
fn error_texts_are_pinned_and_distinct() {
    let all = [
        (ForgeError::WrongKind, "host is not the expected forge"),
        (ForgeError::NotFound, "repository not found or no access"),
        (ForgeError::Unavailable, "forge unavailable"),
        (ForgeError::Timeout, "forge request timed out"),
        (ForgeError::TooLarge, "forge reply too large"),
        (ForgeError::Redirected, "forge answered with a redirect"),
        (ForgeError::Rejected, "forge rejected the request"),
        (ForgeError::NonFastForward, "push is not a fast-forward"),
        (ForgeError::Unauthorized, "credential refused by the forge"),
        (ForgeError::HostMismatch, "credential is for another host"),
        (ForgeError::Malformed, "malformed forge input or reply"),
    ];
    for (error, text) in all {
        assert_eq!(error.to_string(), text);
    }
    assert_eq!(HttpError::Timeout.to_string(), "http call timed out");
    assert_eq!(HttpError::Reset.to_string(), "http connection failed");
    assert_eq!(HttpError::BodyTooLarge.to_string(), "http body too large");
    assert_eq!(HttpError::HostRefused.to_string(), "http host refused");
    assert_eq!(GitError::Spawn.to_string(), "git did not start");
    assert_eq!(GitError::Timeout.to_string(), "git timed out");
    assert_eq!(
        MissingScenario(Case::PushOk).to_string(),
        "fake has no scenario for push-ok"
    );
}

#[tokio::test]
async fn repo_replies_carry_the_scenario_status() -> TestResult {
    let rows: &[(Case, Result<u16, HttpError>)] = &[
        (Case::VerifyReadPush, Ok(200)),
        (Case::VerifyReadOnly, Ok(200)),
        (Case::VerifyNoPermissions, Ok(200)),
        (Case::Verify404, Ok(404)),
        (Case::Verify401, Ok(401)),
        (Case::Verify403, Ok(403)),
        (Case::Verify5xx, Ok(503)),
        (Case::VerifyReset, Err(HttpError::Reset)),
        (Case::VerifySlow, Err(HttpError::Timeout)),
        (Case::VerifyOverCap, Ok(200)),
        (Case::VerifyRedirect, Ok(302)),
        (Case::RedactedError, Ok(500)),
        (Case::PushOk, Ok(404)),
    ];
    for shape in SHAPES {
        for (case, want) in rows {
            let fake = armed(shape, *case)?;
            let got = call(&fake, Method::Get, &repo_path(shape, ""), true)
                .await
                .map(|r| r.status);
            assert_eq!(&got, want, "{shape:?} {}", case.name());
        }
    }
    Ok(())
}

#[tokio::test]
async fn permissions_follow_the_scenario() -> TestResult {
    for shape in SHAPES {
        let (_, body) = json(shape, Case::VerifyReadPush, Method::Get, "").await?;
        assert_eq!(body["permissions"]["push"], true);
        assert_eq!(body["permissions"]["pull"], true);
        assert_eq!(body["full_name"], "octo/widgets");
        let (_, body) = json(shape, Case::VerifyReadOnly, Method::Get, "").await?;
        assert_eq!(body["permissions"]["push"], false);
        assert_eq!(body["permissions"]["pull"], true);
        let (_, body) = json(shape, Case::VerifyNoPermissions, Method::Get, "").await?;
        assert!(body.get("permissions").is_none());
        assert_eq!(body["full_name"], "octo/widgets");
    }
    Ok(())
}

#[tokio::test]
async fn the_over_cap_body_is_one_byte_over() -> TestResult {
    for shape in SHAPES {
        let fake = armed(shape, Case::VerifyOverCap)?;
        let response = call(&fake, Method::Get, &repo_path(shape, ""), true).await?;
        assert_eq!(response.body.len(), MAX_BODY_BYTES + 1);
    }
    Ok(())
}

#[tokio::test]
async fn a_redirect_points_away_and_a_replayed_authorization_is_counted() -> TestResult {
    for shape in SHAPES {
        let fake = armed(shape, Case::VerifyRedirect)?;
        let first = call(&fake, Method::Get, &repo_path(shape, ""), true).await?;
        let location = first
            .headers
            .iter()
            .find(|(k, _)| k == "location")
            .map(|(_, v)| v.as_str());
        assert_eq!(location, Some("https://redirect.example.net/octo/widgets"));
        assert_eq!(fake.authorization_replays(), 0);
        call(&fake, Method::Get, &repo_path(shape, ""), false).await?;
        assert_eq!(fake.authorization_replays(), 0);
        call(&fake, Method::Get, &repo_path(shape, ""), true).await?;
        assert_eq!(fake.authorization_replays(), 1);
        assert_eq!(fake.request_count(), 3);
        fake.arm(Case::VerifyRedirect)?;
        assert_eq!(fake.authorization_replays(), 0);
        assert_eq!(fake.request_count(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn an_authorized_request_without_a_redirect_is_no_replay() -> TestResult {
    let fake = armed(Shape::Gitea, Case::VerifyReadPush)?;
    call(&fake, Method::Get, &repo_path(Shape::Gitea, ""), true).await?;
    call(&fake, Method::Get, &repo_path(Shape::Gitea, ""), true).await?;
    assert_eq!(fake.authorization_replays(), 0);
    Ok(())
}

#[tokio::test]
async fn error_bodies_echo_the_token_they_were_sent() -> TestResult {
    for shape in SHAPES {
        let fake = armed(shape, Case::RedactedError)?;
        let response = call(&fake, Method::Get, &repo_path(shape, ""), true).await?;
        assert!(String::from_utf8(response.body)?.contains(Fake::TOKEN));
        let fake = armed(shape, Case::CreatePrRejected)?;
        let response = call(&fake, Method::Post, &repo_path(shape, "/pulls"), true).await?;
        assert_eq!(response.status, 422);
        assert!(String::from_utf8(response.body)?.contains(Fake::TOKEN));
        let response = call(&fake, Method::Post, &repo_path(shape, "/pulls"), false).await?;
        assert!(!String::from_utf8(response.body)?.contains(Fake::TOKEN));
    }
    Ok(())
}

#[tokio::test]
async fn pull_request_scenarios() -> TestResult {
    for shape in SHAPES {
        let url = Fake::new(shape).pr_url();
        let (status, body) = json(shape, Case::CreatePrOk, Method::Post, "/pulls").await?;
        assert_eq!(status, 201);
        assert_eq!(body["html_url"], url.as_str());
        assert_eq!(body["number"], 7);
        let (status, _) = json(shape, Case::CreatePrOk, Method::Get, "/pulls").await?;
        assert_eq!(status, 404);
        let (status, body) = json(shape, Case::CreatePrExists, Method::Post, "/pulls").await?;
        assert_eq!(status, if shape == Shape::GitHub { 422 } else { 409 });
        assert!(body["message"].as_str().is_some_and(|m| !m.is_empty()));
        let (status, body) = json(shape, Case::CreatePrExists, Method::Get, "/pulls").await?;
        assert_eq!(status, 200);
        assert_eq!(body[0]["html_url"], url.as_str());
        let (status, body) = json(
            shape,
            Case::CreatePrExists,
            Method::Get,
            "/pulls/main/fleet/job-1",
        )
        .await?;
        if shape == Shape::Gitea {
            assert_eq!(status, 200);
            assert_eq!(body["html_url"], url.as_str());
        } else {
            assert_eq!(status, 404);
        }
        let (status, _) = json(shape, Case::CreatePrRejected, Method::Get, "/pulls").await?;
        assert_eq!(status, 404);
    }
    Ok(())
}

#[tokio::test]
async fn github_check_runs_fold_to_the_expected_result() -> TestResult {
    let rows = [
        (Case::CiPending, CiResult::InProgress),
        (Case::CiSuccess, CiResult::Success),
        (Case::CiFailure, CiResult::Failure),
        (Case::CiNone, CiResult::NoChecks),
        (Case::CiMixed, CiResult::Failure),
    ];
    for (case, want) in rows {
        let fake = armed(Shape::GitHub, case)?;
        let response = call(
            &fake,
            Method::Get,
            &repo_path(Shape::GitHub, "/commits/abc123/check-runs"),
            true,
        )
        .await?;
        assert_eq!(response.status, 200);
        let got = CiResult::from_check_runs(&String::from_utf8(response.body)?)
            .map_err(|e| e.to_string())?;
        assert_eq!(got, want, "{}", case.name());
    }
    Ok(())
}

#[tokio::test]
async fn gitea_combined_status_reports_the_expected_state() -> TestResult {
    let rows: &[(Case, &str, &[&str])] = &[
        (Case::CiPending, "pending", &["pending"]),
        (Case::CiSuccess, "success", &["success"]),
        (Case::CiFailure, "failure", &["failure"]),
        (Case::CiNone, "", &[]),
        (Case::CiMixed, "failure", &["success", "failure", "pending"]),
    ];
    for (case, state, statuses) in rows {
        let (status, body) =
            json(Shape::Gitea, *case, Method::Get, "/commits/abc123/status").await?;
        assert_eq!(status, 200);
        assert_eq!(body["state"], *state, "{}", case.name());
        assert_eq!(body["total_count"], statuses.len());
        let listed: Vec<&str> = body["statuses"]
            .as_array()
            .map(|a| a.iter().filter_map(|s| s["status"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(&listed, statuses);
        assert_eq!(body["statuses"].is_null(), statuses.is_empty());
    }
    Ok(())
}

fn listed_names(shape: Shape, body: &Value) -> Vec<String> {
    let (key, field) = match shape {
        Shape::GitHub => ("check_runs", "name"),
        Shape::Gitea => ("statuses", "context"),
    };
    body[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e[field].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn ci_checks_cases_serve_named_entries_on_both_shapes() -> TestResult {
    for shape in SHAPES {
        let suffix = match shape {
            Shape::GitHub => "/commits/abc123/check-runs",
            Shape::Gitea => "/commits/abc123/status",
        };
        let (status, body) = json(shape, Case::CiChecksMixed, Method::Get, suffix).await?;
        assert_eq!(status, 200);
        assert_eq!(listed_names(shape, &body), ["build", "lint", "build"]);
        let (_, body) = json(shape, Case::CiChecksNone, Method::Get, suffix).await?;
        assert_eq!(listed_names(shape, &body), Vec::<String>::new());
        let (_, body) = json(shape, Case::CiChecksBadName, Method::Get, suffix).await?;
        assert_eq!(listed_names(shape, &body), ["bu\nild"]);
        let (_, body) = json(shape, Case::CiChecksOverCap, Method::Get, suffix).await?;
        assert_eq!(listed_names(shape, &body).len(), 51);
        assert_eq!(body["total_count"], 51);
        let (status, _) = json(shape, Case::CiChecks404, Method::Get, "/pulls/7").await?;
        assert_eq!(status, 404);
        let (status, _) = json(shape, Case::CiChecks404, Method::Get, suffix).await?;
        assert_eq!(status, 404);
    }
    Ok(())
}

#[tokio::test]
async fn ci_lookups_resolve_the_head_and_list_no_actions() -> TestResult {
    for shape in SHAPES {
        let (status, body) = json(shape, Case::CiSuccess, Method::Get, "/pulls/7").await?;
        assert_eq!(status, 200);
        assert_eq!(body["head"]["sha"], "abc123");
        assert_eq!(body["html_url"], Fake::new(shape).pr_url().as_str());
        assert_eq!(body["number"], 7);
        let (status, body) = json(shape, Case::CiNone, Method::Get, "/actions/runs").await?;
        assert_eq!(status, 200);
        assert_eq!(body["total_count"], 0);
        assert_eq!(body["workflow_runs"].as_array().map(Vec::len), Some(0));
        let (status, _) = json(shape, Case::Ci404, Method::Get, "/pulls/7").await?;
        assert_eq!(status, 404);
        let (status, _) = json(shape, Case::Ci404, Method::Get, "/commits/abc123/status").await?;
        assert_eq!(status, 404);
        let (status, _) = json(shape, Case::Ci404, Method::Get, "/actions/runs").await?;
        assert_eq!(status, 404);
    }
    Ok(())
}

#[tokio::test]
async fn gitea_only_paths_do_not_answer_on_github() -> TestResult {
    let (status, _) = json(
        Shape::GitHub,
        Case::CiSuccess,
        Method::Get,
        "/commits/abc123/status",
    )
    .await?;
    assert_eq!(status, 404);
    let (status, _) = json(
        Shape::Gitea,
        Case::CiSuccess,
        Method::Get,
        "/commits/abc123/check-runs",
    )
    .await?;
    assert_eq!(status, 404);
    let (status, _) = json(
        Shape::GitHub,
        Case::CreatePrExists,
        Method::Get,
        "/pulls/main/x",
    )
    .await?;
    assert_eq!(status, 404);
    Ok(())
}

#[tokio::test]
async fn identify_serves_its_own_document_and_refuses_the_rest() -> TestResult {
    let own = |shape: Shape| match shape {
        Shape::GitHub => "/rate_limit",
        Shape::Gitea => "/api/v1/version",
    };
    let foreign = |shape: Shape| match shape {
        Shape::GitHub => "/api/v1/version",
        Shape::Gitea => "/rate_limit",
    };
    for shape in SHAPES {
        let fake = armed(shape, Case::IdentifyOk)?;
        let response = call(&fake, Method::Get, own(shape), false).await?;
        let body: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(response.status, 200);
        match shape {
            Shape::GitHub => assert!(body["resources"]["core"]["limit"].is_number()),
            Shape::Gitea => assert_eq!(body["version"], "1.22.0"),
        }
        assert_eq!(
            call(&fake, Method::Get, foreign(shape), false)
                .await?
                .status,
            404
        );
        let fake = armed(shape, Case::IdentifyWrongKind)?;
        let response = call(&fake, Method::Get, own(shape), false).await?;
        let body: Value = serde_json::from_slice(&response.body)?;
        match shape {
            Shape::GitHub => assert_eq!(body["version"], "1.22.0"),
            Shape::Gitea => assert!(body["resources"].is_object()),
        }
        let fake = armed(shape, Case::IdentifyNonForge)?;
        let response = call(&fake, Method::Get, own(shape), false).await?;
        assert_eq!(response.status, 200);
        assert!(String::from_utf8(response.body)?.starts_with("<html>"));
        let fake = armed(shape, Case::Verify404)?;
        assert_eq!(
            call(&fake, Method::Get, own(shape), false).await?.status,
            404
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_unarmed_fake_and_an_unknown_path_answer_404() -> TestResult {
    for shape in SHAPES {
        let fake = Fake::new(shape);
        let response = call(&fake, Method::Get, &repo_path(shape, ""), true).await?;
        assert_eq!(response.status, 404);
        assert_eq!(fake.request_count(), 1);
        fake.arm(Case::VerifyReadPush)?;
        assert_eq!(call(&fake, Method::Get, "/nope", true).await?.status, 404);
        assert_eq!(
            call(&fake, Method::Get, "/repos/octo", true).await?.status,
            404
        );
    }
    Ok(())
}

#[test]
fn a_lacking_fake_refuses_only_the_named_cases() {
    let fake = Fake::lacking(Shape::Gitea, &[Case::PushOk, Case::CiNone]);
    assert_eq!(fake.arm(Case::PushOk), Err(MissingScenario(Case::PushOk)));
    assert_eq!(fake.arm(Case::CiNone), Err(MissingScenario(Case::CiNone)));
    assert_eq!(fake.arm(Case::CiMixed), Ok(()));
    assert_eq!(fake.shape(), Shape::Gitea);
}

#[test]
fn the_fixture_urls_and_hosts() {
    assert_eq!(Fake::new(Shape::GitHub).host().as_str(), "github.com");
    assert_eq!(Fake::new(Shape::Gitea).host().as_str(), "git.example.com");
    assert_eq!(
        Fake::new(Shape::GitHub).pr_url(),
        "https://github.com/octo/widgets/pull/7"
    );
    assert_eq!(
        Fake::new(Shape::Gitea).pr_url(),
        "https://git.example.com/octo/widgets/pulls/7"
    );
    assert_eq!(Shape::GitHub.kind(), HostKind::Github);
    assert_eq!(Shape::Gitea.kind(), HostKind::Forgejo);
}

fn command(fake: &Fake, op: GitOp) -> Result<GitCommand, Box<dyn Error>> {
    let host: HostName = fake.host();
    Ok(GitCommand {
        op,
        repo: RepoRef::new(host.clone(), "octo", "widgets")?,
        branch: Some("fleet/job-1".to_owned()),
        credential: Credential::new(host, Token::new(Fake::TOKEN.to_owned())?),
    })
}

#[tokio::test]
async fn git_scenarios() -> TestResult {
    let rows: &[(Case, GitOp, i32, &str)] = &[
        (Case::PushOk, GitOp::Push, 0, "fleet/job-1 -> fleet/job-1"),
        (Case::PushNonFastForward, GitOp::Push, 1, "non-fast-forward"),
        (Case::PushRevoked, GitOp::Push, 128, "Authentication failed"),
        (Case::FetchOk, GitOp::Fetch, 0, "FETCH_HEAD"),
        (
            Case::FetchAuthFailure,
            GitOp::Fetch,
            128,
            "Authentication failed",
        ),
        (Case::PushOk, GitOp::Fetch, 1, "unexpected"),
        (Case::FetchOk, GitOp::Push, 1, "unexpected"),
        (Case::VerifyReadPush, GitOp::Push, 1, "unexpected"),
    ];
    for shape in SHAPES {
        for (case, op, code, text) in rows {
            let fake = armed(shape, *case)?;
            let out = fake.run(command(&fake, *op)?).await?;
            assert_eq!(out.code, *code, "{shape:?} {}", case.name());
            assert!(
                out.stderr.contains(text),
                "{shape:?} {} {}",
                case.name(),
                out.stderr
            );
            assert_eq!(fake.request_count(), 1);
        }
        let fake = armed(shape, Case::FetchAuthFailure)?;
        let out = fake.run(command(&fake, GitOp::Fetch)?).await?;
        assert!(out.stderr.contains(Fake::TOKEN));
        let fake = armed(shape, Case::PushRevoked)?;
        let out = fake.run(command(&fake, GitOp::Push)?).await?;
        assert!(!out.stderr.contains(Fake::TOKEN));
        let marker = if shape == Shape::GitHub {
            "Invalid username or password"
        } else {
            "Unauthorized"
        };
        assert!(out.stderr.contains(marker));
        let fake = Fake::new(shape);
        let out = fake.run(command(&fake, GitOp::Push)?).await?;
        assert_eq!(
            (out.code, out.stderr.as_str()),
            (1, "fatal: no scenario armed\n")
        );
    }
    Ok(())
}
