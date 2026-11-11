//! The forge-backed verifiers and the row-driven dispatch of [`RepoVerifiers`].

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fleet_core::credential::Secret;
use fleet_core::repo::{ForgeKind, RepoRef};
use hyper::StatusCode;
use hyper::header::HeaderValue;

use fleet_core::host::HostName;
use fleet_forge::{ForgeError, Http, HttpError, HttpRequest, Method};

use super::forge_verify::{ForgeHttp, ForgejoVerifier, GitHost, HostDirectory, refusal_of};
use super::https::{FetchError, ForgeGet, ForgeReply, ForgeTransport};
use super::repo_fake::FakeVerifier;
use super::repo_verify::{RepoCredential, RepoRefusal, RepoVerifier, RepoVerifiers};
use crate::config::{Forge, HostConfig, RepoHosts};

const TOKEN: &str = "fgj_secretsecretsecret0123456789";
const HOST: &str = "git.example.org";

type Upstream = Result<ForgeReply, FetchError>;
type Expected = Result<Option<bool>, RepoRefusal>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    host: String,
    path: String,
    allow_private: bool,
    approved_ips: Vec<IpAddr>,
    authorization: String,
    sensitive: bool,
}

struct Script {
    reply: Result<ForgeReply, FetchError>,
    seen: Mutex<Vec<Seen>>,
}

impl Script {
    fn new(reply: Result<ForgeReply, FetchError>) -> Arc<Self> {
        Arc::new(Self {
            reply,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn status(status: u16, body: &str) -> Arc<Self> {
        Self::new(Ok(ForgeReply {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.as_bytes().to_vec(),
            location: None,
        }))
    }

    fn calls(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

#[tonic::async_trait]
impl ForgeTransport for Script {
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        self.seen.lock().unwrap().push(Seen {
            host: request.host.to_owned(),
            path: request.path.to_owned(),
            allow_private: request.allow_private,
            approved_ips: request.approved_ips.to_vec(),
            authorization: request.authorization.map_or_else(String::new, |value| {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            }),
            sensitive: request.authorization.is_some_and(HeaderValue::is_sensitive),
        });
        self.reply.clone()
    }
}

struct Directory {
    row: Option<GitHost>,
    lookups: AtomicUsize,
}

impl Directory {
    fn new(row: Option<GitHost>) -> Arc<Self> {
        Arc::new(Self {
            row,
            lookups: AtomicUsize::new(0),
        })
    }
}

#[tonic::async_trait]
impl HostDirectory for Directory {
    async fn find(&self, host: &str) -> Result<Option<GitHost>, RepoRefusal> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.row.clone().filter(|_| host == HOST))
    }
}

fn row(kind: ForgeKind) -> GitHost {
    GitHost {
        kind,
        allow_private: false,
        approved_ips: Vec::new(),
    }
}

fn config() -> HostConfig {
    HostConfig {
        host: HOST.to_owned(),
        forge: Forge::Forgejo,
        api_base: format!("https://{HOST}/api/v1"),
        allow_private: false,
    }
}

fn repo(input: &str) -> RepoRef {
    RepoRef::parse_as(input, ForgeKind::Forgejo).unwrap()
}

fn pat() -> RepoCredential {
    RepoCredential::Pat(Secret::new(TOKEN.to_owned()))
}

fn verifier(script: &Arc<Script>, directory: Option<GitHost>) -> ForgejoVerifier {
    ForgejoVerifier::new(script.clone(), Directory::new(directory))
}

#[tokio::test]
async fn forgejo_verify_reads_the_row_host_with_the_token_and_the_row_flags() {
    let ip: IpAddr = "192.168.3.1".parse().unwrap();
    let script = Script::status(200, r#"{"permissions":{"push":true}}"#);
    let host = GitHost {
        kind: ForgeKind::Forgejo,
        allow_private: true,
        approved_ips: vec![ip],
    };
    let verdict = verifier(&script, Some(host))
        .verify(&config(), Some(&pat()), &repo("git.example.org/Octo/Hello"))
        .await
        .unwrap();
    assert_eq!(verdict.canonical_path, "octo/hello");
    assert!(verdict.read);
    assert_eq!(verdict.push, Some(true));
    assert_eq!(
        script.calls(),
        vec![Seen {
            host: HOST.to_owned(),
            path: "/api/v1/repos/octo/hello".to_owned(),
            allow_private: true,
            approved_ips: vec![ip],
            authorization: format!("token {TOKEN}"),
            sensitive: true,
        }]
    );
}

#[tokio::test]
async fn the_flags_come_from_the_row_not_the_operator_entry() {
    let script = Script::status(200, "{}");
    let mut entry = config();
    entry.allow_private = true;
    verifier(&script, Some(row(ForgeKind::Forgejo)))
        .verify(&entry, Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap();
    let calls = script.calls();
    assert!(!calls[0].allow_private);
    assert_eq!(calls[0].approved_ips, Vec::<IpAddr>::new());
}

#[tokio::test]
async fn a_github_row_never_reaches_the_forgejo_adapter() {
    let script = Script::status(200, "{}");
    let err = verifier(&script, Some(row(ForgeKind::Github)))
        .verify(&config(), Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap_err();
    assert_eq!(err, RepoRefusal::NotAllowedHost);
    assert_eq!(script.calls(), Vec::<Seen>::new());
}

#[tokio::test]
async fn an_unknown_row_is_not_allowed_host_without_a_request() {
    let script = Script::status(200, "{}");
    let err = verifier(&script, None)
        .verify(&config(), Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap_err();
    assert_eq!(err, RepoRefusal::NotAllowedHost);
    assert_eq!(script.calls(), Vec::<Seen>::new());
}

#[tokio::test]
async fn a_missing_or_app_credential_refuses_without_a_request() {
    let script = Script::status(200, "{}");
    let v = verifier(&script, Some(row(ForgeKind::Forgejo)));
    let r = repo("git.example.org/o/r");
    let err = v.verify(&config(), None, &r).await.unwrap_err();
    assert_eq!(err, RepoRefusal::NoCredential);
    let app = RepoCredential::App {
        user_id: 1,
        credential_id: 2,
        installation: Secret::new("12345678".to_owned()),
    };
    let err = v.verify(&config(), Some(&app), &r).await.unwrap_err();
    assert_eq!(err, RepoRefusal::NoCredential);
    assert_eq!(script.calls(), Vec::<Seen>::new());
}

#[tokio::test]
async fn upstream_outcomes_map_to_the_fixed_vocabulary() {
    let cases: [(Upstream, Expected); 10] = [
        (
            Ok(reply(200, r#"{"permissions":{"push":false}}"#)),
            Ok(Some(false)),
        ),
        (Ok(reply(200, "{}")), Ok(None)),
        (
            Ok(reply(401, "SENTINEL")),
            Err(RepoRefusal::NotFoundOrNoAccess),
        ),
        (
            Ok(reply(403, "SENTINEL")),
            Err(RepoRefusal::NotFoundOrNoAccess),
        ),
        (
            Ok(reply(404, "SENTINEL")),
            Err(RepoRefusal::NotFoundOrNoAccess),
        ),
        (
            Ok(reply(500, "SENTINEL")),
            Err(RepoRefusal::UpstreamUnavailable),
        ),
        (Ok(reply(302, "")), Err(RepoRefusal::UpstreamUnavailable)),
        (
            Ok(reply(200, "not json")),
            Err(RepoRefusal::UpstreamUnavailable),
        ),
        (
            Err(FetchError::Blocked),
            Err(RepoRefusal::UpstreamUnavailable),
        ),
        (
            Err(FetchError::TooLarge),
            Err(RepoRefusal::UpstreamUnavailable),
        ),
    ];
    for (upstream, expected) in cases {
        let script = Script::new(upstream);
        let got = verifier(&script, Some(row(ForgeKind::Forgejo)))
            .verify(&config(), Some(&pat()), &repo("git.example.org/o/r"))
            .await
            .map(|verdict| verdict.push);
        assert_eq!(got, expected);
        if let Err(refusal) = got {
            assert!(!refusal.reason().contains("SENTINEL"));
            assert!(!format!("{refusal:?}").contains(TOKEN));
        }
    }
}

fn reply(status: u16, body: &str) -> ForgeReply {
    ForgeReply {
        status: StatusCode::from_u16(status).unwrap(),
        body: body.as_bytes().to_vec(),
        location: None,
    }
}

#[tokio::test]
async fn hostile_inputs_never_reach_the_request_path() {
    let inputs = [
        "git.example.org/o/r\r\nX: y",
        "git.example.org/o/r\u{85}",
        "git.example.org/o/r\u{2028}",
        "git.example.org/../r",
        "git.example.org/o/..",
        "git.example.org/o\\p/r",
        "git.example.org/o/r?x=1",
        "git.example.org/o/r#f",
        "git.example.org/o%2fp/r",
        "git.example.org/o/r/extra",
        "git.example.org/o//r",
        "git.example.org/ o/r",
        "git.example.org/\u{e5}/r",
        "user@git.example.org/o/r",
        "git.example.org:443/o/r",
        "[::1]/o/r",
        "git.example.org/o/r.git",
        "GIT.EXAMPLE.ORG/O/R",
        &format!("git.example.org/{}/r", "a".repeat(101)),
        "git.example.org//r",
    ];
    for input in inputs {
        let script = Script::status(200, "{}");
        let Ok(parsed) = RepoRef::parse_as(input, ForgeKind::Forgejo) else {
            continue;
        };
        let outcome = verifier(&script, Some(row(ForgeKind::Forgejo)))
            .verify(&config(), Some(&pat()), &parsed)
            .await;
        for call in script.calls() {
            let tail = call.path.strip_prefix("/api/v1/repos/").unwrap_or_else(|| {
                panic!("{input:?} produced {}", call.path);
            });
            assert_eq!(call.host, HOST);
            assert_eq!(tail.split('/').count(), 2, "{input:?}");
            assert!(
                tail.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')),
                "{input:?} produced {}",
                call.path
            );
        }
        assert!(outcome.is_ok() || script.calls().is_empty(), "{input:?}");
    }
}

fn request(method: Method, headers: Vec<(String, String)>) -> HttpRequest {
    HttpRequest {
        method,
        host: HostName::normalise(HOST).unwrap(),
        path: "/api/v1/version".to_owned(),
        headers,
        body: Vec::new(),
    }
}

#[tokio::test]
async fn the_http_seam_sends_only_a_get_with_a_valid_header() {
    let script = Script::status(200, "{}");
    let http = ForgeHttp::new(script.as_ref(), false, &[]);
    assert_eq!(
        http.send(request(Method::Post, Vec::new())).await,
        Err(HttpError::HostRefused)
    );
    let bad = vec![("Authorization".to_owned(), "token a\nb".to_owned())];
    assert_eq!(
        http.send(request(Method::Get, bad)).await,
        Err(HttpError::HostRefused)
    );
    assert_eq!(script.calls(), Vec::<Seen>::new());
    let good = vec![("Authorization".to_owned(), "token abc".to_owned())];
    assert_eq!(
        http.send(request(Method::Get, good)).await.unwrap().status,
        200
    );
    assert_eq!(script.calls().len(), 1);
}

#[test]
fn every_forge_error_maps_to_one_refusal() {
    let table = [
        (ForgeError::WrongKind, RepoRefusal::UpstreamUnavailable),
        (ForgeError::NotFound, RepoRefusal::NotFoundOrNoAccess),
        (ForgeError::Unavailable, RepoRefusal::UpstreamUnavailable),
        (ForgeError::Timeout, RepoRefusal::Timeout),
        (ForgeError::TooLarge, RepoRefusal::UpstreamUnavailable),
        (ForgeError::Redirected, RepoRefusal::UpstreamUnavailable),
        (ForgeError::Rejected, RepoRefusal::UpstreamUnavailable),
        (ForgeError::NonFastForward, RepoRefusal::UpstreamUnavailable),
        (ForgeError::Unauthorized, RepoRefusal::NotFoundOrNoAccess),
        (ForgeError::HostMismatch, RepoRefusal::NotAllowedHost),
        (ForgeError::Malformed, RepoRefusal::UpstreamUnavailable),
    ];
    for (error, refusal) in table {
        assert_eq!(refusal_of(error), refusal, "{error:?}");
    }
}

fn registry(directory: Option<GitHost>) -> (RepoVerifiers, Arc<FakeVerifier>, Arc<FakeVerifier>) {
    let github = Arc::new(FakeVerifier::ok("o/r", Some(true)));
    let forgejo = Arc::new(FakeVerifier::ok("o/r", Some(false)));
    let verifiers = RepoVerifiers::new(RepoHosts::parse("").unwrap())
        .with(Forge::Github, github.clone())
        .with(Forge::Forgejo, forgejo.clone())
        .with_directory(Directory::new(directory));
    (verifiers, github, forgejo)
}

#[tokio::test]
async fn the_row_kind_picks_the_verifier_and_the_grammar() {
    let (verifiers, github, forgejo) = registry(Some(row(ForgeKind::Forgejo)));
    assert_eq!(verifiers.kind_for(HOST).await, Ok(Some(ForgeKind::Forgejo)));
    let verdict = verifiers
        .verify(Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap();
    assert_eq!(verdict.push, Some(false));
    assert_eq!((github.calls(), forgejo.calls()), (0, 1));

    let (verifiers, github, forgejo) = registry(Some(row(ForgeKind::Github)));
    assert_eq!(verifiers.kind_for(HOST).await, Ok(Some(ForgeKind::Github)));
    let verdict = verifiers
        .verify(Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap();
    assert_eq!(verdict.push, Some(true));
    assert_eq!((github.calls(), forgejo.calls()), (1, 0));
}

#[tokio::test]
async fn an_unknown_row_is_not_allowed_host_in_the_registry() {
    let (verifiers, github, forgejo) = registry(None);
    assert_eq!(verifiers.kind_for(HOST).await, Ok(None));
    let err = verifiers
        .verify(Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap_err();
    assert_eq!(err, RepoRefusal::NotAllowedHost);
    assert_eq!((github.calls(), forgejo.calls()), (0, 0));
}

#[tokio::test]
async fn a_row_overrides_the_operator_list() {
    let hosts =
        RepoHosts::parse("host=git.example.org,forge=github,api=https://git.example.org/api/v3")
            .unwrap();
    let github = Arc::new(FakeVerifier::ok("o/r", Some(true)));
    let forgejo = Arc::new(FakeVerifier::ok("o/r", Some(false)));
    let verifiers = RepoVerifiers::new(hosts)
        .with(Forge::Github, github.clone())
        .with(Forge::Forgejo, forgejo.clone())
        .with_directory(Directory::new(Some(row(ForgeKind::Forgejo))));
    verifiers
        .verify(Some(&pat()), &repo("git.example.org/o/r"))
        .await
        .unwrap();
    assert_eq!((github.calls(), forgejo.calls()), (0, 1));
}
