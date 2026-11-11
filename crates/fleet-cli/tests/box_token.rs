//! Runs `fleet box-token issue|list|revoke` against an in-process `FleetBoxTokens` stub that
//! records every request and answers a scripted reply or status.
//!
//! `issue` writes the plaintext token alone to stdout and nothing else there. A refusal, a
//! malformed reply and a hostile argument each leave stdout empty and exit non-zero. A server
//! message never reaches the terminal and a token shape in any other output is masked.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use fleet_cli::{Cli, CliError, run_with};
use fleet_proto::v1::fleet_box_tokens_server::{FleetBoxTokens, FleetBoxTokensServer};
use fleet_proto::v1::{
    BoxTokenInfo, IssueBoxTokenReply, IssueBoxTokenRequest, ListBoxTokensReply,
    ListBoxTokensRequest, RevokeBoxTokenReply, RevokeBoxTokenRequest,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Script<T> = Arc<Mutex<Option<Result<T, Status>>>>;

const API_TOKEN: &str = "user-api-token-0123456789";
const MARKER: &str = "zqxmark";

fn secret() -> String {
    format!("fbx_{}", "ab12".repeat(16))
}

fn name(n: u32) -> String {
    format!("box-{n}")
}

#[derive(Default, Clone)]
struct Stub {
    issue: Script<IssueBoxTokenReply>,
    list: Script<Vec<BoxTokenInfo>>,
    revoke: Script<()>,
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
    let expected = format!("Bearer {API_TOKEN}");
    match request.metadata().get("authorization") {
        Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(Status::unauthenticated("bad token")),
    }
}

fn scripted<T: Clone>(script: &Script<T>) -> Result<T, Status> {
    script
        .lock()
        .map_err(|_| Status::internal("poisoned"))?
        .clone()
        .unwrap_or_else(|| Err(Status::internal("no script")))
}

#[tonic::async_trait]
impl FleetBoxTokens for Stub {
    async fn issue_box_token(
        &self,
        request: Request<IssueBoxTokenRequest>,
    ) -> Result<Response<IssueBoxTokenReply>, Status> {
        check(&request)?;
        let body = request.get_ref();
        self.note(format!(
            "issue {} [{}] {}",
            body.r#box, body.label, body.ttl_days
        ));
        scripted(&self.issue).map(Response::new)
    }

    async fn list_box_tokens(
        &self,
        request: Request<ListBoxTokensRequest>,
    ) -> Result<Response<ListBoxTokensReply>, Status> {
        check(&request)?;
        self.note("list".to_owned());
        scripted(&self.list).map(|tokens| Response::new(ListBoxTokensReply { tokens }))
    }

    async fn revoke_box_token(
        &self,
        request: Request<RevokeBoxTokenRequest>,
    ) -> Result<Response<RevokeBoxTokenReply>, Status> {
        check(&request)?;
        self.note(format!("revoke {}", request.get_ref().id));
        scripted(&self.revoke).map(|()| Response::new(RevokeBoxTokenReply {}))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetBoxTokensServer::new(stub))
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
        HashMap::from([("FLEET_CLIENT_TOKEN".to_owned(), API_TOKEN.to_owned())]);
    let mut out = Vec::new();
    let result = run_with(
        parsed,
        move |var| env.get(var).cloned(),
        false,
        &mut b"".as_slice(),
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn refusal(result: Result<(), CliError>) -> (u8, String) {
    let err = result.unwrap_err();
    (err.exit_code(), err.to_string())
}

fn issued(token: &str) -> IssueBoxTokenReply {
    IssueBoxTokenReply {
        id: 7,
        token: token.to_owned(),
        r#box: name(5),
        expires_at: "2027-02-09 12:00:00+00".to_owned(),
    }
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn pg_stamp(secs: i64) -> String {
    let ms = u64::try_from(secs * 1000).unwrap();
    format!("{}:00+00", &fleet_core::stamp::utc_stamp(ms)[..16])
}

fn shown(secs: i64) -> String {
    fleet_core::stamp::utc_stamp(u64::try_from(secs * 1000).unwrap())
}

#[tokio::test]
async fn issue_prints_the_token_alone_on_stdout() -> TestResult {
    let stub = Stub::default();
    *stub.issue.lock().unwrap() = Some(Ok(issued(&secret())));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["box-token", "issue", &name(5)]).await;
    res?;
    assert_eq!(out, format!("{}\n", secret()));
    assert_eq!(stub.seen(), [format!("issue {} [] 0", name(5))]);
    Ok(())
}

#[tokio::test]
async fn issue_sends_the_label_and_the_lifetime() -> TestResult {
    let stub = Stub::default();
    *stub.issue.lock().unwrap() = Some(Ok(issued(&secret())));
    let url = serve(stub.clone()).await?;
    let args = [
        "box-token",
        "issue",
        &name(5),
        "--label",
        "dev laptop",
        "--ttl-days",
        "30",
    ];
    cli(&url, &args).await.0?;
    assert_eq!(stub.seen(), [format!("issue {} [dev laptop] 30", name(5))]);
    Ok(())
}

#[tokio::test]
async fn issue_accepts_the_limits_of_the_label_and_the_lifetime() -> TestResult {
    let long = "\u{e9}".repeat(64);
    for (label, ttl) in [(long.as_str(), "365"), ("", "1")] {
        let stub = Stub::default();
        *stub.issue.lock().unwrap() = Some(Ok(issued(&secret())));
        let url = serve(stub.clone()).await?;
        let args = [
            "box-token",
            "issue",
            &name(5),
            "--label",
            label,
            "--ttl-days",
            ttl,
        ];
        cli(&url, &args).await.0?;
        assert_eq!(stub.seen(), [format!("issue {} [{label}] {ttl}", name(5))]);
    }
    Ok(())
}

#[tokio::test]
async fn a_failing_issue_prints_no_token_and_exits_non_zero() -> TestResult {
    let table = [
        (Status::already_exists("x"), "box name is not available"),
        (
            Status::resource_exhausted("x"),
            "too many active box tokens",
        ),
        (
            Status::permission_denied("x"),
            "a per-user API token is required to manage box tokens",
        ),
        (
            Status::invalid_argument("x"),
            "the server refused the box name, label or lifetime",
        ),
        (Status::unauthenticated("x"), "the server refused the token"),
        (Status::unavailable("x"), "the server is unavailable"),
        (Status::internal("x"), "the request failed"),
    ];
    for (status, want) in table {
        let stub = Stub::default();
        *stub.issue.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        let (res, out) = cli(&url, &["box-token", "issue", &name(5)]).await;
        assert_eq!(out, "", "{want}");
        assert_eq!(refusal(res), (1, want.to_owned()));
    }
    Ok(())
}

#[tokio::test]
async fn a_server_message_never_reaches_the_terminal() -> TestResult {
    let hostile = format!("{MARKER}\u{1b}[31m\r\n{}", secret());
    for code in [
        Code::AlreadyExists,
        Code::ResourceExhausted,
        Code::PermissionDenied,
        Code::InvalidArgument,
        Code::NotFound,
        Code::Internal,
    ] {
        let stub = Stub::default();
        let status = Status::new(code, hostile.clone());
        *stub.issue.lock().unwrap() = Some(Err(status.clone()));
        *stub.list.lock().unwrap() = Some(Err(status.clone()));
        *stub.revoke.lock().unwrap() = Some(Err(status));
        let url = serve(stub).await?;
        let id = name(5);
        for args in [
            vec!["box-token", "issue", &id],
            vec!["box-token", "list"],
            vec!["box-token", "revoke", "7"],
        ] {
            let (res, out) = cli(&url, &args).await;
            let (exit, text) = refusal(res);
            assert_eq!(exit, 1);
            assert!(
                !text.contains(MARKER) && !text.contains(&secret()),
                "{text}"
            );
            assert_eq!(out, "");
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_malformed_token_in_the_reply_is_never_printed() -> TestResult {
    let good = secret();
    let upper = format!("fbx_{}", "AB12".repeat(16));
    let table = [
        String::new(),
        format!("{good}\n"),
        format!("{good}x"),
        format!("{good}\u{1b}[31m"),
        format!("\u{1b}[31m{good}"),
        good[..good.len() - 1].to_owned(),
        upper,
        good.replacen("fbx_", "flt_", 1),
        format!("{good}\r\nssh-evil"),
        format!(" {good}"),
    ];
    for token in table {
        let stub = Stub::default();
        *stub.issue.lock().unwrap() = Some(Ok(issued(&token)));
        let url = serve(stub).await?;
        let (res, out) = cli(&url, &["box-token", "issue", &name(5)]).await;
        assert_eq!(out, "", "{token:?}");
        let (exit, text) = refusal(res);
        assert_eq!(exit, 1, "{token:?}");
        assert!(!text.contains("ab12"), "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn a_hostile_box_name_is_refused_before_any_request() -> TestResult {
    let ok = name(5);
    let table = [
        String::new(),
        "box-".to_owned(),
        "box".to_owned(),
        "box-x".to_owned(),
        ok.to_uppercase(),
        format!(" {ok}"),
        format!("{ok} "),
        format!("{ok}\n"),
        format!("{ok}\r\n"),
        format!("{ok}\u{85}"),
        format!("{ok}\u{2028}"),
        format!("{ok}\u{202e}"),
        "box-\u{ff15}".to_owned(),
        format!("{ok}/../x"),
        format!("{ok}\\x"),
        format!("{ok}@host"),
        format!("{ok}:80"),
        "box-[::1]".to_owned(),
        "box--5".to_owned(),
        "box-+5".to_owned(),
        format!("{MARKER}{ok}"),
        format!("{ok}{MARKER}"),
    ];
    let stub = Stub::default();
    *stub.issue.lock().unwrap() = Some(Ok(issued(&secret())));
    let url = serve(stub.clone()).await?;
    for raw in table {
        let (res, out) = cli(&url, &["box-token", "issue", &raw]).await;
        let (exit, text) = refusal(res);
        assert_eq!((exit, out.as_str()), (2, ""), "{raw:?}");
        assert!(!text.contains(MARKER), "{text}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn a_hostile_label_is_refused_before_any_request() -> TestResult {
    let table = [
        "x".repeat(65),
        "\u{e9}".repeat(65),
        format!("a{MARKER}\u{7}"),
        format!("a{MARKER}\n"),
        format!("a{MARKER}\r"),
        format!("a{MARKER}\r\n"),
        format!("a{MARKER}\t"),
        format!("a{MARKER}\u{1b}[31m"),
        format!("a{MARKER}\u{85}"),
        format!("a{MARKER}\u{2028}"),
        format!("a{MARKER}\u{2029}"),
        format!("a{MARKER}\u{202e}"),
        format!("a{MARKER}\u{200b}"),
        format!("a{MARKER}\0"),
    ];
    let stub = Stub::default();
    *stub.issue.lock().unwrap() = Some(Ok(issued(&secret())));
    let url = serve(stub.clone()).await?;
    for raw in table {
        let args = ["box-token", "issue", &name(5), "--label", &raw];
        let (res, out) = cli(&url, &args).await;
        let (exit, text) = refusal(res);
        assert_eq!((exit, out.as_str()), (2, ""), "{raw:?}");
        assert!(!text.contains(MARKER), "{text}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn a_hostile_lifetime_is_refused_before_any_request() -> TestResult {
    let table = [
        "0",
        "366",
        "-1",
        "+5",
        "1.5",
        "",
        " 5",
        "5 ",
        "5\n",
        "abc",
        "\u{663}",
        "99999999999999999999",
        "4294967296",
        "0x10",
        "1e2",
    ];
    let stub = Stub::default();
    *stub.issue.lock().unwrap() = Some(Ok(issued(&secret())));
    let url = serve(stub.clone()).await?;
    for raw in table {
        let args = ["box-token", "issue", &name(5), "--ttl-days", raw];
        let (res, out) = cli(&url, &args).await;
        let (exit, _) = refusal(res);
        assert_eq!((exit, out.as_str()), (2, ""), "{raw:?}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

#[test]
fn every_required_field_is_required() {
    let box_name = name(5);
    for args in [
        vec!["fleet", "box-token", "issue"],
        vec!["fleet", "box-token", "revoke"],
        vec!["fleet", "box-token"],
        vec!["fleet", "box-token", "issue", &box_name, "--label"],
        vec!["fleet", "box-token", "issue", &box_name, "--ttl-days"],
    ] {
        assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
    }
}

#[test]
fn issue_has_no_argument_that_takes_a_token() {
    let box_name = name(5);
    for flag in ["--token", "--value", "--secret"] {
        let args = ["fleet", "box-token", "issue", &box_name, flag, "x"];
        assert!(Cli::try_parse_from(args).is_err(), "{flag}");
    }
}

#[tokio::test]
async fn revoke_prints_the_fixed_notice_and_sends_the_id() -> TestResult {
    let stub = Stub::default();
    *stub.revoke.lock().unwrap() = Some(Ok(()));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["box-token", "revoke", "42"]).await;
    res?;
    assert_eq!(out, "revoked\n");
    assert_eq!(stub.seen(), ["revoke 42"]);
    Ok(())
}

#[tokio::test]
async fn revoke_of_an_unknown_token_is_a_fixed_refusal() -> TestResult {
    let stub = Stub::default();
    *stub.revoke.lock().unwrap() = Some(Err(Status::not_found(MARKER)));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["box-token", "revoke", "42"]).await;
    assert_eq!(refusal(res), (1, "token not found".to_owned()));
    assert_eq!(out, "");
    Ok(())
}

#[tokio::test]
async fn a_hostile_revoke_id_is_refused_before_any_request() -> TestResult {
    let table = [
        "0",
        "-1",
        "+1",
        "abc",
        "",
        " 1",
        "1 ",
        "1\n",
        "1.0",
        "9223372036854775808",
        "\u{661}",
        "0x1",
    ];
    let stub = Stub::default();
    *stub.revoke.lock().unwrap() = Some(Ok(()));
    let url = serve(stub.clone()).await?;
    for raw in table {
        let (res, out) = cli(&url, &["box-token", "revoke", raw]).await;
        let (exit, _) = refusal(res);
        assert_eq!((exit, out.as_str()), (2, ""), "{raw:?}");
    }
    assert_eq!(stub.seen(), Vec::<String>::new());
    Ok(())
}

fn info(id: i64, box_name: &str, label: &str) -> BoxTokenInfo {
    BoxTokenInfo {
        id,
        r#box: box_name.to_owned(),
        label: label.to_owned(),
        created_at: "2026-11-06 21:20:33.5+00".to_owned(),
        expires_at: "2099-01-01 00:00:00+00".to_owned(),
        ..BoxTokenInfo::default()
    }
}

const HEADER: &str = "id\tbox\tlabel\tcreated\texpires\tdays_left\tlast_used\tstatus";

#[tokio::test]
async fn list_snapshot_shows_active_used_expired_and_revoked_rows() -> TestResult {
    let now = now_secs();
    let day = 86_400;
    let active_end = now + 10 * day + day / 2;
    let used_at = now - 3600;
    let mut active = info(1, &name(1), "laptop");
    active.expires_at = pg_stamp(active_end);
    let mut used = info(2, &name(2), "ci");
    used.expires_at = pg_stamp(active_end);
    used.last_used_at = Some(pg_stamp(used_at));
    let mut expired = info(3, &name(3), "old");
    expired.expires_at = "2020-01-01 00:00:00+00".to_owned();
    let mut revoked = info(4, &name(4), "gone");
    revoked.expires_at = pg_stamp(active_end);
    revoked.revoked_at = Some("2026-11-07 08:00:00+00".to_owned());
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(vec![active, used, expired, revoked]));
    let url = serve(stub.clone()).await?;
    let (res, out) = cli(&url, &["box-token", "list"]).await;
    res?;
    let end = shown(active_end);
    let want = [
        HEADER.to_owned(),
        format!(
            "1\t{}\tlaptop\t2026-11-06 21:20 UTC\t{end}\t10\tnever\tactive",
            name(1)
        ),
        format!(
            "2\t{}\tci\t2026-11-06 21:20 UTC\t{end}\t10\t{}\tactive",
            name(2),
            shown(used_at)
        ),
        format!(
            "3\t{}\told\t2026-11-06 21:20 UTC\t2020-01-01 00:00 UTC\t0\tnever\texpired",
            name(3)
        ),
        format!(
            "4\t{}\tgone\t2026-11-06 21:20 UTC\t{end}\t0\tnever\trevoked",
            name(4)
        ),
    ];
    assert_eq!(out.lines().collect::<Vec<_>>(), want);
    assert_eq!(stub.seen(), ["list"]);
    Ok(())
}

#[tokio::test]
async fn list_of_nothing_prints_the_header_only() -> TestResult {
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(Vec::new()));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["box-token", "list"]).await;
    res?;
    assert_eq!(out, format!("{HEADER}\n"));
    Ok(())
}

#[tokio::test]
async fn list_shows_an_unparsable_time_as_a_dash_and_never_the_raw_text() -> TestResult {
    let mut row = info(1, &name(1), "x");
    row.expires_at = format!("{MARKER}\u{1b}[31m");
    row.created_at = "not a time".to_owned();
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(vec![row]));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["box-token", "list"]).await;
    res?;
    let line = out.lines().nth(1).unwrap();
    assert_eq!(line, format!("1\t{}\tx\t-\t-\t-\tnever\tunknown", name(1)));
    Ok(())
}

#[tokio::test]
async fn list_masks_a_token_shape_and_strips_control_characters_in_every_field() -> TestResult {
    let hostile = format!("{MARKER}\u{1b}[31m\r\n\t{}", secret());
    let mut row = info(1, &hostile, &hostile);
    row.last_used_at = Some(hostile.clone());
    row.revoked_at = Some(hostile.clone());
    let stub = Stub::default();
    *stub.list.lock().unwrap() = Some(Ok(vec![row]));
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["box-token", "list"]).await;
    res?;
    assert!(
        !out.contains(&secret()) && !out.contains("ab12ab12"),
        "{out}"
    );
    assert!(!out.contains('\u{1b}') && !out.contains('\r'), "{out:?}");
    assert_eq!(out.lines().count(), 2, "{out:?}");
    assert_eq!(
        out.lines().nth(1).unwrap().split('\t').count(),
        8,
        "{out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn list_converts_every_time_zone_offset_to_utc() -> TestResult {
    let table = [
        ("2026-11-06 21:20:33.5+00", "2026-11-06 21:20 UTC"),
        ("2026-11-06 22:20:00+01", "2026-11-06 21:20 UTC"),
        ("2026-11-06 16:20:00-05", "2026-11-06 21:20 UTC"),
        ("2026-11-06 22:50:00+01:30", "2026-11-06 21:20 UTC"),
        ("2026-11-06 15:50:00-05:30", "2026-11-06 21:20 UTC"),
        ("2026-03-01 00:30:00+00", "2026-03-01 00:30 UTC"),
        ("2026-02-28 23:59:00+00", "2026-02-28 23:59 UTC"),
        ("2024-02-29 12:00:00+00", "2024-02-29 12:00 UTC"),
        ("2026-12-31 23:00:00+00", "2026-12-31 23:00 UTC"),
        ("2026-01-01 00:00:00+00", "2026-01-01 00:00 UTC"),
    ];
    for (given, want) in table {
        let mut row = info(1, &name(1), "x");
        row.created_at = given.to_owned();
        let stub = Stub::default();
        *stub.list.lock().unwrap() = Some(Ok(vec![row]));
        let url = serve(stub).await?;
        let (res, out) = cli(&url, &["box-token", "list"]).await;
        res?;
        let cells: Vec<&str> = out.lines().nth(1).unwrap().split('\t').collect();
        assert_eq!(cells[3], want, "{given}");
    }
    Ok(())
}

#[tokio::test]
async fn list_shows_a_malformed_or_pre_epoch_time_as_a_dash() -> TestResult {
    let table = [
        "2026-13-06 21:20:33+00",
        "2026-11-32 21:20:33+00",
        "2026-11-06 24:20:33+00",
        "2026-11-06 21:60:33+00",
        "2026-11-06 21:20:33",
        "2026-11-06T21:20:33+00",
        "26-11-06 21:20:33+00",
        "2026-11-06 21:20:33.x+00",
        "2026-11-06 21:20:33*00",
        "2026-11-06 21:20+00",
        "2026-11-06 21:20:33+0",
        "2026-11-06 21:20:33+00:0x",
        "2026-11-06-01 21:20:33+00",
        "1960-01-01 00:00:00+00",
    ];
    for given in table {
        let mut row = info(1, &name(1), "x");
        row.created_at = given.to_owned();
        let stub = Stub::default();
        *stub.list.lock().unwrap() = Some(Ok(vec![row]));
        let url = serve(stub).await?;
        let (res, out) = cli(&url, &["box-token", "list"]).await;
        res?;
        let cells: Vec<&str> = out.lines().nth(1).unwrap().split('\t').collect();
        assert_eq!(cells[3], "-", "{given}");
    }
    Ok(())
}
