//! Runs `fleet host add`, `list`, `remove`, `approve-private`, `revoke-private` and `requests` against an in-process `FleetHosts` stub that
//! records every request and answers a scripted reply or status.
//!
//! Each outcome of each action is one test: the printed text is the shared notice text, a server
//! message never reaches the terminal, a hostile argument is refused before a request leaves, and
//! the exit codes follow the repo convention (2 for usage, 1 for a refusal).

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run_with};
use fleet_proto::v1::fleet_hosts_server::{FleetHosts, FleetHostsServer};
use fleet_proto::v1::{
    AddHostRequest, ApproveHostPrivateRequest, HostInfo, HostRequestInfo, ListHostRequestsReply,
    ListHostRequestsRequest, ListHostsReply, ListHostsRequest, RemoveHostReply, RemoveHostRequest,
    RevokeHostPrivateRequest,
};
use fleet_proto::{
    CredentialNotice, ERR_HOST_LIMIT, ERR_HOST_NOT_FOUND, PRECONDITION_HOST_IN_USE,
    PRECONDITION_HOST_NOT_FORGE, PRECONDITION_HOST_UNKNOWN, PRECONDITION_REPO_NOT_ALLOWED_HOST,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";
const MARKER: &str = "zqxmark";
const ADMIN_ONLY: &str = "Only an admin can remove a host.";
const ADMIN_ONLY_PRIVATE: &str = "Only an admin can do this.";

type Script<T> = Arc<Mutex<Option<Result<T, Status>>>>;

#[derive(Default, Clone)]
struct Stub {
    add: Script<HostInfo>,
    list: Script<Vec<HostInfo>>,
    remove: Script<()>,
    approve: Script<HostInfo>,
    revoke: Script<HostInfo>,
    requests: Script<Vec<HostRequestInfo>>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn note(&self, line: String) {
        self.seen.lock().unwrap().push(line);
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn check(request: &Request<impl Sized>) -> Result<(), Status> {
    let expected = format!("Bearer {TOKEN}");
    match request.metadata().get("authorization") {
        Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(Status::unauthenticated("bad token")),
    }
}

#[tonic::async_trait]
impl FleetHosts for Stub {
    async fn add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<HostInfo>, Status> {
        check(&request)?;
        self.note(format!("add {}", request.get_ref().host));
        self.add
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(Status::internal("no script")))
            .map(Response::new)
    }

    async fn list_hosts(
        &self,
        request: Request<ListHostsRequest>,
    ) -> Result<Response<ListHostsReply>, Status> {
        check(&request)?;
        self.note("list".to_owned());
        self.list
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(Status::internal("no script")))
            .map(|hosts| Response::new(ListHostsReply { hosts }))
    }

    async fn remove_host(
        &self,
        request: Request<RemoveHostRequest>,
    ) -> Result<Response<RemoveHostReply>, Status> {
        check(&request)?;
        self.note(format!("remove {}", request.get_ref().host));
        self.remove
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(Status::internal("no script")))
            .map(|()| Response::new(RemoveHostReply {}))
    }

    async fn approve_host_private(
        &self,
        request: Request<ApproveHostPrivateRequest>,
    ) -> Result<Response<HostInfo>, Status> {
        check(&request)?;
        let body = request.get_ref();
        self.note(format!(
            "approve {} {}",
            body.host,
            body.approved_ips.join(",")
        ));
        self.approve
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(Status::internal("no script")))
            .map(Response::new)
    }

    async fn revoke_host_private(
        &self,
        request: Request<RevokeHostPrivateRequest>,
    ) -> Result<Response<HostInfo>, Status> {
        check(&request)?;
        self.note(format!("revoke {}", request.get_ref().host));
        self.revoke
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(Status::internal("no script")))
            .map(Response::new)
    }

    async fn list_host_requests(
        &self,
        request: Request<ListHostRequestsRequest>,
    ) -> Result<Response<ListHostRequestsReply>, Status> {
        check(&request)?;
        self.note("requests".to_owned());
        self.requests
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(Status::internal("no script")))
            .map(|requests| Response::new(ListHostRequestsReply { requests }))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetHostsServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let env: HashMap<String, String> =
        HashMap::from([("FLEET_CLIENT_TOKEN".to_owned(), TOKEN.to_owned())]);
    let mut out = Vec::new();
    let result = run_with(
        parsed,
        move |name| env.get(name).cloned(),
        false,
        &mut b"".as_slice(),
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn info(host: &str, kind: &str, allow_private: bool) -> HostInfo {
    HostInfo {
        host: host.to_owned(),
        kind: kind.to_owned(),
        allow_private,
        ..HostInfo::default()
    }
}

fn refusal(result: Result<(), CliError>) -> (u8, String) {
    let err = result.unwrap_err();
    (err.exit_code(), err.to_string())
}

fn failed(message: &str) -> Status {
    Status::failed_precondition(message)
}

#[tokio::test]
async fn add_prints_the_row_then_the_added_notice() -> TestResult {
    let stub = Stub::default();
    *stub.add.lock().unwrap() = Some(Ok(info("git.example.org", "forgejo", false)));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["host", "add", "git.example.org"]).await;
    res?;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "git.example.org\tforgejo\tno",
            CredentialNotice::HostAdded.text()
        ]
    );
    assert_eq!(stub.seen(), ["add git.example.org"]);
    Ok(())
}

#[tokio::test]
async fn add_sends_the_normalised_punycode_form_and_prints_it() -> TestResult {
    let stub = Stub::default();
    *stub.add.lock().unwrap() = Some(Ok(info("xn--bcher-kva.example", "forgejo", false)));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["host", "add", "B\u{fc}cher.Example."]).await;
    res?;
    assert_eq!(stub.seen(), ["add xn--bcher-kva.example"]);
    assert!(
        out.starts_with("xn--bcher-kva.example\tforgejo\tno\n"),
        "{out}"
    );
    Ok(())
}

#[tokio::test]
async fn add_shows_the_private_flag_of_an_approved_host() -> TestResult {
    let stub = Stub::default();
    *stub.add.lock().unwrap() = Some(Ok(info("git.example.org", "forgejo", true)));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["host", "add", "git.example.org"]).await;
    res?;
    assert!(out.starts_with("git.example.org\tforgejo\tyes\n"), "{out}");
    Ok(())
}

#[tokio::test]
async fn a_refused_host_prints_the_shared_text_with_the_ask_an_admin_hint() -> TestResult {
    let stub = Stub::default();
    *stub.add.lock().unwrap() = Some(Err(failed(PRECONDITION_REPO_NOT_ALLOWED_HOST)));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["host", "add", "git.example.org"]).await;
    let (code, text) = refusal(res);
    assert_eq!(code, 1);
    assert_eq!(text, CredentialNotice::HostRefused.text());
    assert!(text.contains("ask an admin to approve it"), "{text}");
    assert_eq!(out, "");
    Ok(())
}

#[tokio::test]
async fn every_add_refusal_prints_its_shared_notice_and_exits_one() -> TestResult {
    let table = [
        (
            failed(PRECONDITION_HOST_NOT_FORGE),
            CredentialNotice::HostNotForge,
        ),
        (
            failed(PRECONDITION_HOST_UNKNOWN),
            CredentialNotice::HostUnknown,
        ),
        (Status::invalid_argument("x"), CredentialNotice::HostInvalid),
        (
            Status::resource_exhausted(ERR_HOST_LIMIT),
            CredentialNotice::HostLimit,
        ),
        (Status::unavailable("x"), CredentialNotice::Unavailable),
        (Status::internal("x"), CredentialNotice::Failed),
    ];
    for (status, notice) in table {
        let stub = Stub::default();
        *stub.add.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        let (res, _) = cli(&url, &["host", "add", "git.example.org"]).await;
        assert_eq!(refusal(res), (1, notice.text().to_owned()), "{notice:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_server_message_never_reaches_the_terminal() -> TestResult {
    let hostile = format!("{MARKER}\u{1b}[31m\r\n");
    for status in [
        Status::new(Code::FailedPrecondition, hostile.clone()),
        Status::new(Code::InvalidArgument, hostile.clone()),
        Status::new(Code::PermissionDenied, hostile.clone()),
        Status::new(Code::NotFound, hostile.clone()),
    ] {
        let stub = Stub::default();
        *stub.add.lock().unwrap() = Some(Err(status.clone()));
        *stub.remove.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        for args in [
            ["host", "add", "git.example.org"],
            ["host", "remove", "git.example.org"],
        ] {
            let (res, out) = cli(&url, &args).await;
            let (code, text) = refusal(res);
            assert_eq!(code, 1);
            assert!(!text.contains(MARKER) && !out.contains(MARKER), "{text}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn list_prints_host_kind_and_private_flag_per_row() -> TestResult {
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(vec![
        info("github.com", "github", false),
        info("git.example.org", "forgejo", true),
    ]));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["host", "list"]).await;
    res?;
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        ["github.com\tgithub\tno", "git.example.org\tforgejo\tyes"]
    );
    assert_eq!(stub.seen(), ["list"]);
    Ok(())
}

#[tokio::test]
async fn list_of_no_hosts_prints_nothing() -> TestResult {
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(Vec::new()));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["host", "list"]).await;
    res?;
    assert_eq!(out, "");
    Ok(())
}

#[tokio::test]
async fn list_shows_a_stored_unicode_host_in_ascii_form_and_strips_controls() -> TestResult {
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(vec![
        info("b\u{fc}cher.example", "forgejo", false),
        info("a.example\u{85}\u{2028}", "for\u{1b}gejo", false),
    ]));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["host", "list"]).await;
    res?;
    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(rows.len(), 2, "{out:?}");
    assert!(rows[0].starts_with("b\\u{fc}cher.example\t"), "{out:?}");
    assert!(
        !out.contains('\u{1b}') && !out.contains('\u{85}') && !out.contains('\u{2028}'),
        "{out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn list_refusals_print_a_fixed_notice() -> TestResult {
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Err(Status::unavailable(MARKER)));
    let url = serve(stub).await?;
    let (res, _) = cli(&url, &["host", "list"]).await;
    assert_eq!(
        refusal(res),
        (1, CredentialNotice::Unavailable.text().to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn remove_prints_the_removed_notice() -> TestResult {
    let stub = Stub::default();
    *stub.remove.lock().unwrap() = Some(Ok(()));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["host", "remove", "Git.Example.ORG."]).await;
    res?;
    assert_eq!(out, format!("{}\n", CredentialNotice::HostRemoved.text()));
    assert_eq!(stub.seen(), ["remove git.example.org"]);
    Ok(())
}

#[tokio::test]
async fn every_remove_refusal_prints_its_shared_notice() -> TestResult {
    let table = [
        (
            failed(PRECONDITION_HOST_IN_USE),
            CredentialNotice::HostInUse,
        ),
        (
            Status::not_found(ERR_HOST_NOT_FOUND),
            CredentialNotice::HostMissing,
        ),
        (
            failed(PRECONDITION_HOST_UNKNOWN),
            CredentialNotice::HostUnknown,
        ),
        (Status::invalid_argument("x"), CredentialNotice::HostInvalid),
    ];
    for (status, notice) in table {
        let stub = Stub::default();
        *stub.remove.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        let (res, _) = cli(&url, &["host", "remove", "git.example.org"]).await;
        assert_eq!(refusal(res), (1, notice.text().to_owned()), "{notice:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_non_admin_remove_prints_the_fixed_admin_only_text() -> TestResult {
    let stub = Stub::default();
    *stub.remove.lock().unwrap() = Some(Err(Status::permission_denied("admin required")));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["host", "remove", "git.example.org"]).await;
    assert_eq!(refusal(res), (1, ADMIN_ONLY.to_owned()));
    assert_eq!(out, "");
    Ok(())
}

#[tokio::test]
async fn another_permission_denial_is_not_reported_as_admin_only() -> TestResult {
    let stub = Stub::default();
    *stub.remove.lock().unwrap() = Some(Err(Status::permission_denied(MARKER)));
    let url = serve(stub).await?;
    let (res, _) = cli(&url, &["host", "remove", "git.example.org"]).await;
    let (code, text) = refusal(res);
    assert_eq!(code, 1);
    assert_ne!(text, ADMIN_ONLY);
    assert!(!text.contains(MARKER), "{text}");
    Ok(())
}

fn hostile_hosts() -> Vec<String> {
    vec![
        "git.example.com\r".to_owned(),
        "git.example.com\n".to_owned(),
        "git.example.com\r\nx.example.com".to_owned(),
        format!("{MARKER}\u{85}.example.com"),
        format!("{MARKER}\u{2028}.example.com"),
        format!("{MARKER}\u{2029}.example.com"),
        format!("{MARKER}user@git.example.com"),
        format!("{MARKER}user:{MARKER}pw@git.example.com"),
        format!("{MARKER}.example.com\\x"),
        "[::1]".to_owned(),
        "::1".to_owned(),
        "git..example.com".to_owned(),
        ".git.example.com".to_owned(),
        String::new(),
        format!("{}.example.com", "a".repeat(300)),
        "a".repeat(2000),
        "git example.com".to_owned(),
        format!(" {MARKER}.example.com"),
        format!("{MARKER}.example.com\t"),
        format!("{MARKER}\u{430}.example.com"),
        format!("{MARKER}.example.com:443"),
        format!("https://{MARKER}.example.com"),
        format!("{MARKER}.example.com/path"),
        "localhost".to_owned(),
        "192.168.3.1".to_owned(),
        "*.example.com".to_owned(),
        format!("{MARKER}.example.com\u{0}"),
    ]
}

#[tokio::test]
async fn a_hostile_host_exits_two_before_any_request_and_is_never_echoed() -> TestResult {
    let stub = Stub::default();
    *stub.add.lock().unwrap() = Some(Ok(info("git.example.org", "forgejo", false)));
    *stub.remove.lock().unwrap() = Some(Ok(()));
    let url = serve(stub.clone()).await?;
    for host in hostile_hosts() {
        for action in ["add", "remove"] {
            let (res, out) = cli(&url, &["host", action, &host]).await;
            assert!(res.is_err(), "{action} accepted {host:?}");
            let (code, text) = refusal(res);
            assert_eq!(code, 2, "{action} {host:?}: {text}");
            assert!(text.starts_with("host: "), "{host:?}: {text}");
            assert!(
                !text.contains(MARKER) && !text.contains(&host) || host.is_empty(),
                "{host:?}: {text}"
            );
            assert_eq!(out, "");
        }
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn case_and_a_trailing_dot_normalise_and_reach_the_server() -> TestResult {
    let stub = Stub::default();
    *stub.add.lock().unwrap() = Some(Ok(info("git.example.org", "forgejo", false)));
    let url = serve(stub.clone()).await?;
    for typed in ["GIT.Example.ORG", "git.example.org."] {
        let (res, _) = cli(&url, &["host", "add", typed]).await;
        res?;
    }
    assert_eq!(stub.seen(), ["add git.example.org", "add git.example.org"]);
    Ok(())
}

#[tokio::test]
async fn stray_arguments_exit_two_with_fixed_text_and_no_request() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let table = [
        (
            vec!["host", "add", "git.example.org", MARKER],
            "this action takes one host name",
        ),
        (
            vec!["host", "remove", "git.example.org", MARKER],
            "this action takes one host name",
        ),
        (
            vec!["host", "list", MARKER],
            "this action takes no arguments",
        ),
    ];
    for (args, text) in table {
        let (res, _) = cli(&url, &args).await;
        assert_eq!(refusal(res), (2, text.to_owned()), "{args:?}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn missing_arguments_exit_two_without_a_request() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    for args in [vec!["host", "add"], vec!["host", "remove"], vec!["host"]] {
        let (res, _) = cli(&url, &args).await;
        assert_eq!(res.unwrap_err().exit_code(), 2, "{args:?}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

fn approved(host: &str, ips: &[&str]) -> HostInfo {
    HostInfo {
        approved_ips: ips.iter().map(|ip| (*ip).to_owned()).collect(),
        ..info(host, "forgejo", true)
    }
}

#[tokio::test]
async fn approve_names_the_addresses_it_approved() -> TestResult {
    let stub = Stub::default();
    *stub.approve.lock().unwrap() = Some(Ok(approved("git.example.org", &["10.0.0.2", "fd00::1"])));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(
        &url,
        &[
            "host",
            "approve-private",
            "Git.Example.ORG.",
            "fd00::1",
            "10.0.0.2",
        ],
    )
    .await;
    res?;
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "git.example.org\tforgejo\tyes",
            "approved: 10.0.0.2, fd00::1",
            CredentialNotice::HostApproved.text()
        ]
    );
    assert_eq!(stub.seen(), ["approve git.example.org 10.0.0.2,fd00::1"]);
    Ok(())
}

#[tokio::test]
async fn approve_canonicalises_and_dedups_the_named_addresses() -> TestResult {
    let stub = Stub::default();
    *stub.approve.lock().unwrap() = Some(Ok(approved("git.example.org", &["10.0.0.2"])));
    let url = serve(stub.clone()).await?;
    let (res, _) = cli(
        &url,
        &[
            "host",
            "approve-private",
            "git.example.org",
            "10.0.0.2",
            "10.0.0.2",
            "FD00:0:0::1",
        ],
    )
    .await;
    res?;
    assert_eq!(stub.seen(), ["approve git.example.org 10.0.0.2,fd00::1"]);
    Ok(())
}

#[tokio::test]
async fn approve_strips_hostile_server_addresses() -> TestResult {
    let stub = Stub::default();
    *stub.approve.lock().unwrap() = Some(Ok(approved(
        "git.example.org",
        &["10.0.0.2\u{1b}[31m\r\n", "10.0.0.3\u{85}\u{2028}"],
    )));
    let url = serve(stub).await?;
    let (res, out) = cli(
        &url,
        &["host", "approve-private", "git.example.org", "10.0.0.2"],
    )
    .await;
    res?;
    assert_eq!(out.lines().count(), 3, "{out:?}");
    assert!(
        !out.contains('\u{1b}') && !out.contains('\u{85}') && !out.contains('\u{2028}'),
        "{out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_non_admin_approve_prints_the_same_text_as_an_unknown_host() -> TestResult {
    let mut texts = Vec::new();
    for status in [
        Status::not_found(ERR_HOST_NOT_FOUND),
        Status::not_found(ERR_HOST_NOT_FOUND),
    ] {
        let stub = Stub::default();
        *stub.approve.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        let (res, out) = cli(
            &url,
            &["host", "approve-private", "git.example.org", "10.0.0.2"],
        )
        .await;
        let (code, text) = refusal(res);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        texts.push(text);
    }
    assert_eq!(texts[0], texts[1]);
    assert_eq!(texts[0], CredentialNotice::HostMissing.text());
    Ok(())
}

#[tokio::test]
async fn every_approve_refusal_prints_its_shared_notice() -> TestResult {
    let table = [
        (
            failed(fleet_proto::PRECONDITION_HOST_ADDRESS_MISMATCH),
            CredentialNotice::HostAddressMismatch,
        ),
        (
            failed(PRECONDITION_REPO_NOT_ALLOWED_HOST),
            CredentialNotice::HostRefused,
        ),
        (
            failed(PRECONDITION_HOST_NOT_FORGE),
            CredentialNotice::HostNotForge,
        ),
        (
            Status::resource_exhausted(ERR_HOST_LIMIT),
            CredentialNotice::HostLimit,
        ),
        (Status::unavailable("x"), CredentialNotice::Unavailable),
        (Status::permission_denied(MARKER), CredentialNotice::Failed),
    ];
    for (status, notice) in table {
        let stub = Stub::default();
        *stub.approve.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        let (res, _) = cli(
            &url,
            &["host", "approve-private", "git.example.org", "10.0.0.2"],
        )
        .await;
        assert_eq!(refusal(res), (1, notice.text().to_owned()), "{notice:?}");
    }
    Ok(())
}

#[tokio::test]
async fn revoke_prints_the_row_then_the_revoked_notice() -> TestResult {
    let stub = Stub::default();
    *stub.revoke.lock().unwrap() = Some(Ok(info("git.example.org", "forgejo", false)));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["host", "revoke-private", "GIT.example.org."]).await;
    res?;
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "git.example.org\tforgejo\tno",
            CredentialNotice::HostRevoked.text()
        ]
    );
    assert_eq!(stub.seen(), ["revoke git.example.org"]);
    Ok(())
}

#[tokio::test]
async fn a_non_admin_revoke_or_requests_prints_the_fixed_admin_text() -> TestResult {
    let stub = Stub::default();
    *stub.revoke.lock().unwrap() = Some(Err(Status::permission_denied("admin required")));
    *stub.requests.lock().unwrap() = Some(Err(Status::permission_denied("admin required")));
    let url = serve(stub).await?;
    for args in [
        vec!["host", "revoke-private", "git.example.org"],
        vec!["host", "requests"],
    ] {
        let (res, out) = cli(&url, &args).await;
        assert_eq!(refusal(res), (1, ADMIN_ONLY_PRIVATE.to_owned()), "{args:?}");
        assert_eq!(out, "");
    }
    Ok(())
}

#[tokio::test]
async fn revoke_and_requests_refusals_print_shared_notices_and_never_server_text() -> TestResult {
    let stub = Stub::default();
    *stub.revoke.lock().unwrap() = Some(Err(Status::not_found(ERR_HOST_NOT_FOUND)));
    *stub.requests.lock().unwrap() = Some(Err(Status::permission_denied(MARKER)));
    let url = serve(stub).await?;
    let (res, _) = cli(&url, &["host", "revoke-private", "git.example.org"]).await;
    assert_eq!(
        refusal(res),
        (1, CredentialNotice::HostMissing.text().to_owned())
    );
    let (res, _) = cli(&url, &["host", "requests"]).await;
    let (code, text) = refusal(res);
    assert_eq!(code, 1);
    assert!(
        !text.contains(MARKER) && text != ADMIN_ONLY_PRIVATE,
        "{text}"
    );
    Ok(())
}

#[tokio::test]
async fn requests_prints_host_user_and_resolved_addresses() -> TestResult {
    let stub = Stub::default();
    *stub.requests.lock().unwrap() = Some(Ok(vec![
        HostRequestInfo {
            host: "b\u{fc}cher.example".to_owned(),
            requested_by: 7,
            resolved_ips: vec!["10.0.0.2".to_owned(), "fd00::1".to_owned()],
            requested_at_ms: 1,
        },
        HostRequestInfo {
            host: "a.example\u{85}".to_owned(),
            requested_by: 8,
            resolved_ips: vec!["10.0.0.3\u{1b}".to_owned()],
            requested_at_ms: 2,
        },
    ]));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["host", "requests"]).await;
    res?;
    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(rows.len(), 2, "{out:?}");
    assert_eq!(rows[0], "b\\u{fc}cher.example\t7\t10.0.0.2, fd00::1");
    assert!(
        !out.contains('\u{1b}') && !out.contains('\u{85}'),
        "{out:?}"
    );
    assert_eq!(stub.seen(), ["requests"]);
    Ok(())
}

#[tokio::test]
async fn requests_of_none_prints_nothing() -> TestResult {
    let stub = Stub::default();
    *stub.requests.lock().unwrap() = Some(Ok(Vec::new()));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["host", "requests"]).await;
    res?;
    assert_eq!(out, "");
    Ok(())
}

#[tokio::test]
async fn a_hostile_host_exits_two_before_any_admin_request() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    for host in hostile_hosts() {
        for action in ["approve-private", "revoke-private"] {
            let mut args = vec!["host", action, host.as_str()];
            if action == "approve-private" {
                args.push("10.0.0.2");
            }
            let (res, out) = cli(&url, &args).await;
            let (code, text) = refusal(res);
            assert_eq!(code, 2, "{action} {host:?}: {text}");
            assert!(text.starts_with("host: "), "{host:?}: {text}");
            assert!(
                !text.contains(MARKER) && !text.contains(&host) || host.is_empty(),
                "{host:?}: {text}"
            );
            assert_eq!(out, "");
        }
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

fn hostile_addresses() -> Vec<String> {
    vec![
        "10.0.0.2\r".to_owned(),
        "10.0.0.2\n".to_owned(),
        "10.0.0.2\r\n10.0.0.3".to_owned(),
        "10.0.0.2\u{85}".to_owned(),
        "10.0.0.2\u{2028}".to_owned(),
        format!("{MARKER}@10.0.0.2"),
        format!("{MARKER}:{MARKER}@10.0.0.2"),
        "10.0.0.2\\x".to_owned(),
        "[::1]".to_owned(),
        "[fd00::1]:443".to_owned(),
        "fe80::1%eth0".to_owned(),
        "fd00:::1".to_owned(),
        "1:2:3:4:5:6:7:8:9".to_owned(),
        "10..0.2".to_owned(),
        "10.0.0.2.".to_owned(),
        ".10.0.0.2".to_owned(),
        String::new(),
        format!("{}.0.0.2", "9".repeat(300)),
        "1".repeat(2000),
        "10.0.0 .2".to_owned(),
        " 10.0.0.2".to_owned(),
        "10.0.0.2 ".to_owned(),
        "10.0.0.2\t".to_owned(),
        "\u{661}\u{660}.0.0.2".to_owned(),
        "\u{ff11}\u{ff10}.0.0.2".to_owned(),
        "10.0.0.2:443".to_owned(),
        "https://10.0.0.2".to_owned(),
        "10.0.0.2/8".to_owned(),
        "10.0.0.256".to_owned(),
        "010.000.000.002".to_owned(),
        "0x0a.0.0.2".to_owned(),
        "167772162".to_owned(),
        "10.1".to_owned(),
        "git.example.org".to_owned(),
        "FD00::G".to_owned(),
        "10.0.0.2\u{0}".to_owned(),
    ]
}

#[tokio::test]
async fn a_malformed_address_exits_two_before_any_request_and_is_never_echoed() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    for bad in hostile_addresses() {
        for args in [
            vec!["host", "approve-private", "git.example.org", bad.as_str()],
            vec![
                "host",
                "approve-private",
                "git.example.org",
                "10.0.0.2",
                bad.as_str(),
            ],
        ] {
            let (res, out) = cli(&url, &args).await;
            let (code, text) = refusal(res);
            assert_eq!(code, 2, "{bad:?}: {text}");
            assert_eq!(text, "address: not an IP address", "{bad:?}");
            assert_eq!(out, "");
        }
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn more_than_the_address_cap_exits_two_and_duplicates_do_not_count() -> TestResult {
    let stub = Stub::default();
    *stub.approve.lock().unwrap() = Some(Ok(approved("git.example.org", &["10.0.0.1"])));
    let url = serve(stub.clone()).await?;
    let cap = fleet_proto::MAX_HOST_APPROVED_IPS;
    let many: Vec<String> = (1..=cap + 1).map(|n| format!("10.0.0.{n}")).collect();
    let mut args = vec!["host", "approve-private", "git.example.org"];
    args.extend(many.iter().map(String::as_str));
    let (res, _) = cli(&url, &args).await;
    assert_eq!(
        refusal(res),
        (2, format!("address: at most {cap} addresses"))
    );
    assert_eq!(stub.seen(), Vec::<String>::new());

    let mut args = vec!["host", "approve-private", "git.example.org"];
    args.extend(many[..cap].iter().map(String::as_str));
    args.extend(many[..cap].iter().map(String::as_str));
    let (res, _) = cli(&url, &args).await;
    res?;
    assert_eq!(stub.seen().len(), 1);
    Ok(())
}

#[tokio::test]
async fn admin_actions_refuse_stray_and_missing_arguments_with_exit_two() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let table = [
        (
            vec!["host", "revoke-private", "git.example.org", MARKER],
            "this action takes one host name",
        ),
        (
            vec!["host", "requests", MARKER],
            "this action takes no arguments",
        ),
    ];
    for (args, text) in table {
        let (res, _) = cli(&url, &args).await;
        assert_eq!(refusal(res), (2, text.to_owned()), "{args:?}");
    }
    for args in [
        vec!["host", "approve-private"],
        vec!["host", "approve-private", "git.example.org"],
        vec!["host", "revoke-private"],
    ] {
        let (res, _) = cli(&url, &args).await;
        assert_eq!(res.unwrap_err().exit_code(), 2, "{args:?}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}
