//! Parity of the credential commands between the `fleet` CLI (gRPC) and the web credentials
//! page, both served by one in-process server on Postgres, plus the secret-handling tests of
//! the CLI.
//!
//! `ROWS` is the operation table: one row per operation and scenario, each with exactly one
//! classification. Both surfaces end in a notice code from `CredentialNotice`, or list the
//! stored kinds. `Same` means both ended in the same code or list and left the same rows in
//! the database. `Differs` names a documented gap with the label each surface gives, and
//! passes only while the two still disagree in exactly that way. A label is `notice:<code>`,
//! `listed`, `usage`, `404` or `absent`; `absent` means the web form cannot express the
//! request. Every row also asserts the stored kinds of the owner and of the other user after
//! the call, the fingerprint of a saved value, and that no secret reaches either surface.
//!
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because they bind sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_core::credential::{BotIdentity, Secret, fingerprint};
use fleet_proto::CredentialNotice;
use fleet_proto::v1::fleet_credentials_server::{FleetCredentials, FleetCredentialsServer};
use fleet_proto::v1::{
    CredentialInfo, DeleteCredentialReply, DeleteCredentialRequest, ListCredentialsReply,
    ListCredentialsRequest, PutCredentialRequest, VerifyCredentialReply, VerifyCredentialRequest,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::app_jwt::AppJwt;
use fleet_server::cred::app_jwt::AppKey;
use fleet_server::cred::app_mint::{AppClient, Installation, InstallationDirectory, MintError};
use fleet_server::cred::app_policy::AppPolicy;
use fleet_server::cred::capability::Capabilities;
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::{AppLane, CredentialStore};
use fleet_server::cred::{CredentialService, FileSealer, Users};
use fleet_server::service::{UpdateRelay, serve_with_credentials};
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::server::TcpIncoming;
use tonic::{Code, Request, Response, Status};

const WAIT: Duration = Duration::from_secs(30);
const ORIGIN: &str = "https://fleet.example.com";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const CLIENT_TOKEN: &str = "client-token-0123456789abcdef012345";
const CAPABILITY: &str = "forge:github_app";
const BOT_NAME: &str = "fleet-bot[bot]";
const BOT_EMAIL: &str = "12345+fleet-bot[bot]@users.noreply.github.com";
const EXPIRY_MS: i64 = 1_900_000_000_000;

const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const ANT_NEW: &str = "sk-ant-api03-zyxwvutsrqponmlkjihgfe";
const CLAUDE: &str = "sk-ant-oat01-abcdefghijklmnopqrstuv";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const APP: &str = "1234567890123";
const KIMI_MEMBER: &str = "sk-kimi-abcdefghijklmnopqrstuv";
const KIMI_PLATFORM: &str = "sk-abcdefghijklmnopqrstuvwxyz0";
const CODEX: &str = "sk-proj-abcdefghijklmnopqrstuv";
const CODEX_ALT: &str = "sk-proj-zyxwvutsrqponmlkjihgfe";
const FORGEJO: &str = "0123456789abcdef0123456789abcdef01234567";
const CLASSIC: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const SHORT: &str = "short";
const INNER_SPACE: &str = "sk-ant-api03-abcdefgh ijklmnopqrstuv";
const INNER_NEWLINE: &str = "sk-ant-api03-abcdefgh\nijklmnopqrstuv";
const LEADING_ZERO: &str = "01234567890123";
const NON_NUMERIC: &str = "12345abc";

const SECRETS: &[&str] = &[
    ANT,
    ANT_NEW,
    CLAUDE,
    PAT,
    APP,
    KIMI_MEMBER,
    KIMI_PLATFORM,
    CODEX,
    CLASSIC,
    INNER_SPACE,
    LEADING_ZERO,
    NON_NUMERIC,
    "abcdefghijklmnopqrstuvwxyz0",
];

const NO_JOB_TEXT: &str =
    "Submit a Job first. A GitHub App check mints a token for the repository of your latest Job.";
const CAPABILITY_TEXT: &str =
    "This credential kind needs the forge:github_app capability. Ask an admin to grant it.";

const D_NEWLINE: &str = "stdin carries a line ending the shell added, so the CLI strips exactly one trailing newline; the web form posts the value as typed and refuses any whitespace";
const D_NON_UTF8: &str =
    "the CLI reads raw bytes from stdin and refuses invalid UTF-8; a web form always posts text";
const D_ARGV: &str = "the CLI refuses a secret given as an argument, with a fixed usage error; the web form has no argument";
const D_NOT_CONFIGURED: &str = "a server without a credential store answers the CLI with the fixed not-configured notice and the web page with a 404";
const D_STATIC_TOKEN: &str = "the shared client token acts as the bootstrap user, so the CLI lists that user's credentials; the web page is only reachable with a user session";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Cli,
    Web,
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cli => "cli",
            Self::Web => "web",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Notice(String),
    Listed(Vec<String>),
    Page404,
    Usage,
    Absent,
    Unexpected(String),
}

impl Outcome {
    fn label(&self) -> String {
        match self {
            Self::Notice(code) => format!("notice:{code}"),
            Self::Listed(_) => "listed".to_owned(),
            Self::Page404 => "404".to_owned(),
            Self::Usage => "usage".to_owned(),
            Self::Absent => "absent".to_owned(),
            Self::Unexpected(text) => format!("unexpected:{text}"),
        }
    }

    fn took_effect(&self) -> bool {
        matches!(self, Self::Notice(code) if code == "saved" || code == "deleted")
    }
}

fn agree(cli: &Outcome, web: &Outcome) -> bool {
    !matches!(cli, Outcome::Absent | Outcome::Unexpected(_)) && cli == web
}

#[derive(Debug, Clone, Copy)]
enum Class {
    Same,
    Differs(&'static str, &'static str, &'static str),
}

struct Row {
    name: &'static str,
    op: &'static str,
    class: Class,
}

const fn same(name: &'static str, op: &'static str) -> Row {
    Row {
        name,
        op,
        class: Class::Same,
    }
}

const fn differs(
    name: &'static str,
    op: &'static str,
    why: &'static str,
    cli: &'static str,
    web: &'static str,
) -> Row {
    Row {
        name,
        op,
        class: Class::Differs(why, cli, web),
    }
}

const REQUIRED_OPERATIONS: &[&str] = &["list", "put", "delete", "verify"];

const ROWS: &[Row] = &[
    same("list/owner", "list"),
    same("list/other-user", "list"),
    same("list/empty", "list"),
    differs(
        "list/not-configured",
        "list",
        D_NOT_CONFIGURED,
        "notice:not_configured",
        "404",
    ),
    differs(
        "list/static-client-token",
        "list",
        D_STATIC_TOKEN,
        "listed",
        "absent",
    ),
    same("put/anthropic_api_key", "put"),
    same("put/claude_subscription_token", "put"),
    same("put/github_pat", "put"),
    same("put/github_app", "put"),
    same("put/kimi_membership_key", "put"),
    same("put/kimi_platform_key", "put"),
    same("put/codex_api_key", "put"),
    same("put/forgejo_pat", "put"),
    same("put/replace-existing", "put"),
    same("put/github_pat-classic", "put"),
    same("put/github_pat-github-refuses", "put"),
    same("put/github_pat-github-unavailable", "put"),
    same("put/github_app-no-capability", "put"),
    same("put/github_app-non-numeric", "put"),
    same("put/github_app-leading-zero", "put"),
    same("put/unknown-kind", "put"),
    same("put/too-short", "put"),
    same("put/inner-space", "put"),
    same("put/inner-newline", "put"),
    same("put/empty", "put"),
    same("put/over-cap", "put"),
    differs(
        "put/trailing-newline",
        "put",
        D_NEWLINE,
        "notice:saved",
        "notice:invalid",
    ),
    differs(
        "put/trailing-crlf",
        "put",
        D_NEWLINE,
        "notice:saved",
        "notice:invalid",
    ),
    differs(
        "put/non-utf8",
        "put",
        D_NON_UTF8,
        "notice:invalid",
        "absent",
    ),
    differs("put/secret-in-argv", "put", D_ARGV, "usage", "absent"),
    same("delete/own", "delete"),
    same("delete/other-users-credential", "delete"),
    same("delete/unknown-id", "delete"),
    same("delete/non-numeric-id", "delete"),
    same("delete/negative-id", "delete"),
    same("delete/id-over-i64", "delete"),
    same("verify/github_pat-valid", "verify"),
    same("verify/github_pat-refused", "verify"),
    same("verify/github_pat-unavailable", "verify"),
    same("verify/other-users-credential", "verify"),
    same("verify/unknown-id", "verify"),
    same("verify/non-numeric-id", "verify"),
    same("verify/anthropic_api_key", "verify"),
    same("verify/github_app-no-job", "verify"),
    same("verify/github_app-no-capability", "verify"),
    same("verify/github_app-no-lane", "verify"),
];

#[derive(Clone, Copy)]
enum Gh {
    Accepts,
    Rejects,
    Unavailable,
}

#[derive(Clone)]
struct FakeGithub {
    answer: Arc<Mutex<Result<GithubUser, GithubError>>>,
}

impl FakeGithub {
    fn new() -> Self {
        Self {
            answer: Arc::new(Mutex::new(Ok(GithubUser {
                login: "octo".to_owned(),
                expires_at_ms: Some(EXPIRY_MS),
            }))),
        }
    }

    fn set(&self, mode: Gh) {
        *self.answer.lock().unwrap() = match mode {
            Gh::Accepts => Ok(GithubUser {
                login: "octo".to_owned(),
                expires_at_ms: Some(EXPIRY_MS),
            }),
            Gh::Rejects => Err(GithubError::Rejected),
            Gh::Unavailable => Err(GithubError::Unavailable),
        };
    }
}

#[tonic::async_trait]
impl GithubApi for FakeGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        self.answer.lock().unwrap().clone()
    }
}

#[derive(Clone, Copy)]
struct Mode {
    lane: bool,
    configured: bool,
}

const DEFAULT: Mode = Mode {
    lane: true,
    configured: true,
};

struct Persona {
    id: i64,
    token: String,
    cookie: String,
    csrf: String,
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    }
}

static FILES: AtomicUsize = AtomicUsize::new(0);

fn file_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fleet-parity-cred-{}-{}.{tag}",
        std::process::id(),
        FILES.fetch_add(1, Ordering::Relaxed)
    ))
}

fn sealer() -> FileSealer {
    let path = file_path("keys");
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    sealer.unwrap()
}

fn app_key() -> AppKey {
    let pem = openssl::rsa::Rsa::generate(2048)
        .unwrap()
        .private_key_to_pem()
        .unwrap();
    let path = file_path("pem");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&pem).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = AppKey::load(&path);
    std::fs::remove_file(&path).unwrap();
    key.unwrap()
}

fn enc(text: &[u8]) -> String {
    let mut out = String::new();
    for byte in text {
        if byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_' {
            out.push(char::from(*byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

struct BoundDirectory;

#[tonic::async_trait]
impl InstallationDirectory for BoundDirectory {
    async fn installation(&self, _jwt: &AppJwt, id: u64) -> Result<Installation, MintError> {
        Ok(Installation {
            id,
            app_id: 12345,
            account_login: "acme".to_owned(),
            suspended: false,
        })
    }
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    service: CredentialService,
    github: FakeGithub,
    caps: Capabilities,
    admin: i64,
}

impl Rig {
    async fn start(pool: PgPool, mode: Mode) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let github = FakeGithub::new();
        let mut creds = CredentialStore::new(pool.clone(), Arc::new(sealer()));
        if mode.lane {
            let bot = BotIdentity::new(BOT_NAME, BOT_EMAIL).unwrap();
            let policy = AppPolicy::parse("acme", Some(APP), Some("acme/*")).unwrap();
            creds = creds.with_github_app(
                AppLane::new(
                    app_key(),
                    "12345".to_owned(),
                    AppClient::new().unwrap(),
                    bot,
                    policy,
                )
                .with_directory(Arc::new(BoundDirectory)),
            );
        }
        let service = CredentialService::new(creds, Arc::new(github.clone()));
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let web = if mode.configured {
            Web::with_console(auth, Some(service.clone()), store.clone())
        } else {
            Web::with_auth(auth)
        };
        let bearer = BearerAuth::new(
            &Token::new(BOX_TOKEN.to_owned()).unwrap(),
            Some(&Token::new(CLIENT_TOKEN.to_owned()).unwrap()),
        )
        .with_users(users);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let grpc = mode.configured.then(|| service.clone());
        tokio::spawn(async move {
            serve_with_credentials(
                &store,
                &bearer,
                web,
                grpc,
                UpdateRelay::default(),
                TcpIncoming::from(listener),
                std::future::pending::<()>(),
            )
            .await
        });
        let admin = sqlx::query_scalar(
            "INSERT INTO users (username, is_admin) VALUES ('ada', true) RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        Self {
            addr,
            caps: Capabilities::new(pool.clone()),
            pool,
            service,
            github,
            admin,
        }
    }

    async fn persona(&self, name: &str, seed: char) -> Persona {
        let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        let token = Users::new(self.pool.clone())
            .create_api_token(id, "t")
            .await
            .unwrap();
        let session = seed.to_string().repeat(64);
        let csrf = format!("csrf-{name}-token");
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, $3, now() + interval '1 hour')",
        )
        .bind(session.as_bytes())
        .bind(id)
        .bind(&csrf)
        .execute(&self.pool)
        .await
        .unwrap();
        Persona {
            id,
            token: String::from_utf8(token.token.expose().to_vec()).unwrap(),
            cookie: format!("{SESSION_COOKIE}={session}"),
            csrf,
        }
    }

    async fn cli(
        &self,
        token: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> (Result<(), CliError>, String) {
        run_cli(self.addr, token, args, stdin).await
    }

    async fn http(&self, method: &str, path: &str, who: &Persona, body: &str) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\nContent-Length: {}\r\nCookie: {}\r\n",
            body.len(),
            who.cookie
        );
        if method == "POST" {
            request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let _ = stream.write_all(body.as_bytes()).await;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        Reply {
            status: head.split(' ').nth(1).unwrap().parse().unwrap(),
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    async fn post(&self, who: &Persona, path: &str, fields: &str) -> Reply {
        let body = format!("csrf={}&{fields}", who.csrf);
        self.http("POST", path, who, &body).await
    }

    async fn seed(&self, user: i64, kind: &str, value: &str) {
        self.github.set(Gh::Accepts);
        self.service
            .put(
                user,
                PutCredentialRequest {
                    kind: kind.to_owned(),
                    shape: "static_secret".to_owned(),
                    value: value.to_owned(),
                    expires_at_ms: None,
                    host: String::new(),
                },
            )
            .await
            .unwrap();
    }

    async fn kinds(&self, user: i64) -> Vec<String> {
        sqlx::query_scalar("SELECT kind FROM credentials WHERE user_id = $1 ORDER BY kind")
            .bind(user)
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn print_of(&self, user: i64, kind: &str) -> String {
        sqlx::query_scalar("SELECT fingerprint FROM credentials WHERE user_id = $1 AND kind = $2")
            .bind(user)
            .bind(kind)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn id_of(&self, user: i64, kind: &str) -> String {
        let id: i64 =
            sqlx::query_scalar("SELECT id FROM credentials WHERE user_id = $1 AND kind = $2")
                .bind(user)
                .bind(kind)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        id.to_string()
    }
}

async fn run_cli(
    addr: SocketAddr,
    token: &str,
    args: &[&str],
    stdin: &[u8],
) -> (Result<(), CliError>, String) {
    let url = format!("http://{addr}");
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let token = token.to_owned();
    let mut out = Vec::new();
    let mut stdin = stdin;
    let result = tokio::time::timeout(
        WAIT,
        run(
            parsed,
            move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
            &mut stdin,
            &mut out,
        ),
    )
    .await
    .unwrap();
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[derive(Clone, Copy)]
enum Cap {
    Never,
    Held,
    Revoked,
}

#[derive(Clone, Copy)]
enum Target {
    Own(&'static str),
    Foreign(&'static str),
    Raw(&'static str),
}

#[derive(Clone, Copy)]
enum Act {
    ListOwn,
    ListOther,
    ListStatic,
    Put(&'static str, &'static [u8]),
    PutArgv(&'static str, &'static str),
    Delete(Target),
    Verify(Target),
}

#[derive(Clone, Copy)]
struct Case {
    cap: Cap,
    github: Gh,
    seed: &'static [&'static str],
    foreign: &'static [&'static str],
    act: Act,
    done: &'static [&'static str],
    saved: Option<(&'static str, &'static str)>,
    web_absent: bool,
}

const fn case(act: Act) -> Case {
    Case {
        cap: Cap::Never,
        github: Gh::Accepts,
        seed: &[],
        foreign: &[],
        act,
        done: &[],
        saved: None,
        web_absent: false,
    }
}

fn value_of(kind: &str) -> &'static str {
    match kind {
        "anthropic_api_key" => ANT,
        "claude_subscription_token" => CLAUDE,
        "github_pat" => PAT,
        "github_app" => APP,
        "kimi_membership_key" => KIMI_MEMBER,
        "kimi_platform_key" => KIMI_PLATFORM,
        "codex_api_key" => CODEX,
        _ => CODEX_ALT,
    }
}

fn kinds_in_cli_list(out: &str) -> Vec<String> {
    let mut kinds: Vec<String> = out
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .map(ToOwned::to_owned)
        .collect();
    kinds.sort();
    kinds
}

fn prints_in_cli_list(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|line| line.split('\t').nth(2))
        .map(ToOwned::to_owned)
        .collect()
}

fn web_stored_kinds(page: &str) -> Vec<String> {
    let mut kinds: Vec<String> = page
        .split("data-kind=\"")
        .skip(1)
        .filter(|chunk| chunk.contains("badge-success"))
        .filter_map(|chunk| chunk.split('"').next().map(ToOwned::to_owned))
        .collect();
    kinds.sort();
    kinds
}

fn cli_outcome(act: Act, result: &Result<(), CliError>, out: &str) -> Outcome {
    match result {
        Ok(()) => match act {
            Act::ListOwn | Act::ListOther | Act::ListStatic => {
                Outcome::Listed(kinds_in_cli_list(out))
            }
            Act::Put(..) | Act::PutArgv(..) => Outcome::Notice("saved".to_owned()),
            Act::Delete(_) => Outcome::Notice("deleted".to_owned()),
            Act::Verify(_) => Outcome::Notice("verified".to_owned()),
        },
        Err(CliError::Credential(notice)) => {
            assert_eq!(result.as_ref().unwrap_err().to_string(), notice.text());
            Outcome::Notice(notice.code().to_owned())
        }
        Err(CliError::Usage(_)) => Outcome::Usage,
        Err(other) => Outcome::Unexpected(other.to_string()),
    }
}

fn web_outcome(act: Act, reply: &Reply) -> Outcome {
    match (act, reply.status) {
        (Act::ListOwn | Act::ListOther, 200) => Outcome::Listed(web_stored_kinds(&reply.body)),
        (_, 303) => {
            let location = reply.location();
            let code = location
                .strip_prefix("/credentials?notice=")
                .unwrap_or_default();
            Outcome::Notice(code.to_owned())
        }
        (_, 404) => Outcome::Page404,
        (_, other) => Outcome::Unexpected(format!("{other}: {}", reply.body)),
    }
}

fn no_secret(surface: Surface, text: &str) {
    for secret in SECRETS {
        assert!(!text.contains(secret), "{surface} leaked a secret: {text}");
    }
}

async fn target_text(rig: &Rig, owner: &Persona, other: &Persona, target: Target) -> String {
    match target {
        Target::Own(kind) => rig.id_of(owner.id, kind).await,
        Target::Foreign(kind) => rig.id_of(other.id, kind).await,
        Target::Raw(text) => text.to_owned(),
    }
}

async fn run_case(rig: &Rig, surface: Surface, case: Case) -> Outcome {
    let seed_char = if surface == Surface::Cli { 'a' } else { 'b' };
    let owner = rig.persona(&format!("olive-{surface}"), seed_char).await;
    let other = rig
        .persona(&format!("otto-{surface}"), seed_char.to_ascii_uppercase())
        .await;
    if matches!(case.cap, Cap::Held | Cap::Revoked) {
        rig.caps
            .grant(rig.admin, owner.id, CAPABILITY)
            .await
            .unwrap();
    }
    for kind in case.seed {
        rig.seed(owner.id, kind, value_of(kind)).await;
    }
    for kind in case.foreign {
        rig.seed(other.id, kind, value_of(kind)).await;
    }
    if matches!(case.cap, Cap::Revoked) {
        rig.caps
            .revoke(rig.admin, owner.id, CAPABILITY)
            .await
            .unwrap();
    }
    rig.github.set(case.github);
    let outcome = if surface == Surface::Web && case.web_absent {
        Outcome::Absent
    } else {
        match surface {
            Surface::Cli => cli_step(rig, &owner, &other, case).await,
            Surface::Web => web_step(rig, &owner, &other, case).await,
        }
    };
    let mut expected: Vec<String> = if outcome.took_effect() {
        case.done.iter().map(|kind| (*kind).to_owned()).collect()
    } else {
        case.seed.iter().map(|kind| (*kind).to_owned()).collect()
    };
    expected.sort();
    assert_eq!(rig.kinds(owner.id).await, expected, "{surface} {outcome:?}");
    let mut foreign: Vec<String> = case.foreign.iter().map(|k| (*k).to_owned()).collect();
    foreign.sort();
    assert_eq!(rig.kinds(other.id).await, foreign, "{surface} foreign rows");
    if let (Some((kind, value)), Outcome::Notice(code)) = (case.saved, &outcome)
        && code == "saved"
    {
        assert_eq!(
            rig.print_of(owner.id, kind).await,
            fingerprint(&Secret::new(value.to_owned())),
            "{surface} stored another value"
        );
    }
    outcome
}

async fn cli_step(rig: &Rig, owner: &Persona, other: &Persona, case: Case) -> Outcome {
    let (result, out, token) = match case.act {
        Act::ListOwn => {
            let (r, o) = rig.cli(&owner.token, &["credential", "list"], b"").await;
            (r, o, owner.token.as_str())
        }
        Act::ListOther => {
            let (r, o) = rig.cli(&other.token, &["credential", "list"], b"").await;
            (r, o, other.token.as_str())
        }
        Act::ListStatic => {
            let (r, o) = rig.cli(CLIENT_TOKEN, &["credential", "list"], b"").await;
            (r, o, CLIENT_TOKEN)
        }
        Act::Put(kind, value) => {
            let (r, o) = rig
                .cli(&owner.token, &["credential", "put", kind], value)
                .await;
            (r, o, owner.token.as_str())
        }
        Act::PutArgv(kind, secret) => {
            let (r, o) = rig
                .cli(&owner.token, &["credential", "put", kind, secret], b"")
                .await;
            (r, o, owner.token.as_str())
        }
        Act::Delete(target) => {
            let id = target_text(rig, owner, other, target).await;
            let (r, o) = rig
                .cli(&owner.token, &["credential", "delete", &id], b"")
                .await;
            (r, o, owner.token.as_str())
        }
        Act::Verify(target) => {
            let id = target_text(rig, owner, other, target).await;
            let (r, o) = rig
                .cli(&owner.token, &["credential", "verify", &id], b"")
                .await;
            (r, o, owner.token.as_str())
        }
    };
    let shown = format!(
        "{out}{}",
        result
            .as_ref()
            .err()
            .map_or(String::new(), ToString::to_string)
    );
    no_secret(Surface::Cli, &shown);
    assert!(!shown.contains(token), "cli printed its token");
    if matches!(case.act, Act::ListOwn | Act::ListOther) && result.is_ok() {
        let page = rig.get_page(owner, other, case.act).await;
        for print in prints_in_cli_list(&out) {
            assert!(page.contains(&print), "web page lacks fingerprint {print}");
        }
    }
    cli_outcome(case.act, &result, &out)
}

impl Rig {
    async fn get_page(&self, owner: &Persona, other: &Persona, act: Act) -> String {
        let who = if matches!(act, Act::ListOther) {
            other
        } else {
            owner
        };
        self.http("GET", "/credentials", who, "").await.body
    }
}

async fn web_step(rig: &Rig, owner: &Persona, other: &Persona, case: Case) -> Outcome {
    let reply = match case.act {
        Act::ListOwn => rig.http("GET", "/credentials", owner, "").await,
        Act::ListOther => rig.http("GET", "/credentials", other, "").await,
        Act::Put(kind, value) => {
            rig.post(
                owner,
                "/credentials/put",
                &format!("kind={}&value={}", enc(kind.as_bytes()), enc(value)),
            )
            .await
        }
        Act::Delete(target) => {
            let id = target_text(rig, owner, other, target).await;
            rig.post(
                owner,
                "/credentials/delete",
                &format!("id={}", enc(id.as_bytes())),
            )
            .await
        }
        Act::Verify(target) => {
            let id = target_text(rig, owner, other, target).await;
            rig.post(
                owner,
                "/credentials/verify",
                &format!("id={}", enc(id.as_bytes())),
            )
            .await
        }
        Act::ListStatic | Act::PutArgv(..) => return Outcome::Absent,
    };
    no_secret(Surface::Web, &format!("{}{}", reply.head, reply.body));
    web_outcome(case.act, &reply)
}

fn row(name: &str) -> &'static Row {
    ROWS.iter().find(|row| row.name == name).unwrap()
}

async fn judge(name: &str, pool: PgPool, mode: Mode, case: Case) {
    let row = row(name);
    let rig = Box::pin(Rig::start(pool, mode)).await;
    let cli = run_case(&rig, Surface::Cli, case).await;
    let web = run_case(&rig, Surface::Web, case).await;
    assert!(
        !matches!(cli, Outcome::Unexpected(_)) && !matches!(web, Outcome::Unexpected(_)),
        "{name}: unexpected outcome: cli {cli:?} web {web:?}"
    );
    match row.class {
        Class::Same => {
            assert!(agree(&cli, &web), "{name}: cli {cli:?} web {web:?}");
            if let Outcome::Notice(code) = &cli {
                pin_text(name, code);
            }
        }
        Class::Differs(why, want_cli, want_web) => {
            assert!(
                !agree(&cli, &web),
                "{name}: gap closed ({why}): cli {cli:?} web {web:?}"
            );
            assert_eq!(
                (cli.label(), web.label()),
                (want_cli.to_owned(), want_web.to_owned()),
                "{name}: gap changed ({why})"
            );
        }
    }
}

fn pin_text(name: &str, code: &str) {
    let notice = CredentialNotice::from_code(code).unwrap();
    match name {
        "verify/github_app-no-job" => {
            assert_eq!(notice.text(), NO_JOB_TEXT);
        }
        "put/github_app-no-capability" | "verify/github_app-no-capability" => {
            assert_eq!(notice.text(), CAPABILITY_TEXT);
        }
        _ => {}
    }
}

const NO_LANE: Mode = Mode {
    lane: false,
    configured: true,
};
const NOT_CONFIGURED: Mode = Mode {
    lane: false,
    configured: false,
};

const fn one(kind: &str) -> &'static [&'static str] {
    match kind.as_bytes() {
        b"anthropic_api_key" => &["anthropic_api_key"],
        b"claude_subscription_token" => &["claude_subscription_token"],
        b"github_pat" => &["github_pat"],
        b"github_app" => &["github_app"],
        b"kimi_membership_key" => &["kimi_membership_key"],
        b"kimi_platform_key" => &["kimi_platform_key"],
        b"codex_api_key" => &["codex_api_key"],
        _ => &[],
    }
}

const fn put_ok(kind: &'static str, value: &'static str, cap: Cap) -> Case {
    Case {
        cap,
        done: one(kind),
        saved: Some((kind, value)),
        ..case(Act::Put(kind, value.as_bytes()))
    }
}

const fn put_refused(kind: &'static str, value: &'static [u8]) -> Case {
    case(Act::Put(kind, value))
}

const fn verify_seeded(kind: &'static str, github: Gh) -> Case {
    Case {
        github,
        seed: one(kind),
        ..case(Act::Verify(Target::Own(kind)))
    }
}

const fn app_verify(cap: Cap) -> Case {
    Case {
        cap,
        seed: &["github_app"],
        ..case(Act::Verify(Target::Own("github_app")))
    }
}

const fn delete_raw(id: &'static str) -> Case {
    Case {
        seed: &["anthropic_api_key"],
        ..case(Act::Delete(Target::Raw(id)))
    }
}

const fn verify_raw(id: &'static str) -> Case {
    Case {
        seed: &["anthropic_api_key"],
        ..case(Act::Verify(Target::Raw(id)))
    }
}

macro_rules! rows {
    ($($test:ident: $name:literal, $mode:expr, $case:expr;)*) => {
        const TESTED: &[&str] = &[$($name),*];
        $(
            #[sqlx::test]
            async fn $test(pool: PgPool) {
                judge($name, pool, $mode, $case).await;
            }
        )*
    };
}

rows! {
    list_owner: "list/owner", DEFAULT, Case { seed: &["anthropic_api_key", "github_pat"], foreign: &["codex_api_key"], ..case(Act::ListOwn) };
    list_other: "list/other-user", DEFAULT, Case { seed: &["anthropic_api_key", "github_pat"], foreign: &["codex_api_key"], ..case(Act::ListOther) };
    list_empty: "list/empty", DEFAULT, case(Act::ListOwn);
    list_not_configured: "list/not-configured", NOT_CONFIGURED, case(Act::ListOwn);
    list_static: "list/static-client-token", DEFAULT, Case { web_absent: true, ..case(Act::ListStatic) };
    put_anthropic: "put/anthropic_api_key", DEFAULT, put_ok("anthropic_api_key", ANT, Cap::Never);
    put_claude: "put/claude_subscription_token", DEFAULT, put_ok("claude_subscription_token", CLAUDE, Cap::Never);
    put_pat: "put/github_pat", DEFAULT, put_ok("github_pat", PAT, Cap::Never);
    put_app: "put/github_app", DEFAULT, put_ok("github_app", APP, Cap::Held);
    put_kimi_member: "put/kimi_membership_key", DEFAULT, put_ok("kimi_membership_key", KIMI_MEMBER, Cap::Never);
    put_kimi_platform: "put/kimi_platform_key", DEFAULT, put_ok("kimi_platform_key", KIMI_PLATFORM, Cap::Never);
    put_codex: "put/codex_api_key", DEFAULT, put_ok("codex_api_key", CODEX, Cap::Never);
    put_forgejo: "put/forgejo_pat", DEFAULT, put_refused("forgejo_pat", FORGEJO.as_bytes());
    put_replace: "put/replace-existing", DEFAULT, Case { seed: &["anthropic_api_key"], done: &["anthropic_api_key"], saved: Some(("anthropic_api_key", ANT_NEW)), ..case(Act::Put("anthropic_api_key", ANT_NEW.as_bytes())) };
    put_classic: "put/github_pat-classic", DEFAULT, put_refused("github_pat", CLASSIC.as_bytes());
    put_gh_rejects: "put/github_pat-github-refuses", DEFAULT, Case { github: Gh::Rejects, ..put_refused("github_pat", PAT.as_bytes()) };
    put_gh_unavailable: "put/github_pat-github-unavailable", DEFAULT, Case { github: Gh::Unavailable, ..put_refused("github_pat", PAT.as_bytes()) };
    put_app_no_cap: "put/github_app-no-capability", DEFAULT, put_refused("github_app", APP.as_bytes());
    put_app_non_numeric: "put/github_app-non-numeric", DEFAULT, Case { cap: Cap::Held, ..put_refused("github_app", NON_NUMERIC.as_bytes()) };
    put_app_zero: "put/github_app-leading-zero", DEFAULT, Case { cap: Cap::Held, ..put_refused("github_app", LEADING_ZERO.as_bytes()) };
    put_unknown_kind: "put/unknown-kind", DEFAULT, put_refused("gitlab_pat", ANT.as_bytes());
    put_short: "put/too-short", DEFAULT, put_refused("anthropic_api_key", SHORT.as_bytes());
    put_space: "put/inner-space", DEFAULT, put_refused("anthropic_api_key", INNER_SPACE.as_bytes());
    put_newline: "put/inner-newline", DEFAULT, put_refused("anthropic_api_key", INNER_NEWLINE.as_bytes());
    put_empty: "put/empty", DEFAULT, put_refused("anthropic_api_key", b"");
    put_over_cap: "put/over-cap", DEFAULT, put_refused("anthropic_api_key", &[b'a'; 513]);
    put_trailing_newline: "put/trailing-newline", DEFAULT, Case { done: &["anthropic_api_key"], saved: Some(("anthropic_api_key", ANT)), ..case(Act::Put("anthropic_api_key", b"sk-ant-api03-abcdefghijklmnopqrstuv\n")) };
    put_trailing_crlf: "put/trailing-crlf", DEFAULT, Case { done: &["anthropic_api_key"], saved: Some(("anthropic_api_key", ANT)), ..case(Act::Put("anthropic_api_key", b"sk-ant-api03-abcdefghijklmnopqrstuv\r\n")) };
    put_non_utf8: "put/non-utf8", DEFAULT, Case { web_absent: true, ..put_refused("anthropic_api_key", b"sk-ant-api03-abcdefghij\xff\xfeklmnopqrstuv") };
    put_argv: "put/secret-in-argv", DEFAULT, Case { web_absent: true, ..case(Act::PutArgv("anthropic_api_key", ANT)) };
    delete_own: "delete/own", DEFAULT, Case { seed: &["anthropic_api_key", "codex_api_key"], done: &["codex_api_key"], ..case(Act::Delete(Target::Own("anthropic_api_key"))) };
    delete_foreign: "delete/other-users-credential", DEFAULT, Case { seed: &["anthropic_api_key"], foreign: &["codex_api_key"], ..case(Act::Delete(Target::Foreign("codex_api_key"))) };
    delete_unknown: "delete/unknown-id", DEFAULT, delete_raw("999999");
    delete_non_numeric: "delete/non-numeric-id", DEFAULT, delete_raw("abc");
    delete_negative: "delete/negative-id", DEFAULT, delete_raw("-1");
    delete_over_i64: "delete/id-over-i64", DEFAULT, delete_raw("18446744073709551615");
    verify_valid: "verify/github_pat-valid", DEFAULT, verify_seeded("github_pat", Gh::Accepts);
    verify_refused: "verify/github_pat-refused", DEFAULT, Case { github: Gh::Rejects, ..verify_seeded("github_pat", Gh::Rejects) };
    verify_unavailable: "verify/github_pat-unavailable", DEFAULT, verify_seeded("github_pat", Gh::Unavailable);
    verify_foreign: "verify/other-users-credential", DEFAULT, Case { foreign: &["github_pat"], ..case(Act::Verify(Target::Foreign("github_pat"))) };
    verify_unknown: "verify/unknown-id", DEFAULT, verify_raw("999999");
    verify_non_numeric: "verify/non-numeric-id", DEFAULT, verify_raw("abc");
    verify_no_verifier: "verify/anthropic_api_key", DEFAULT, verify_seeded("anthropic_api_key", Gh::Accepts);
    verify_app_no_job: "verify/github_app-no-job", DEFAULT, app_verify(Cap::Held);
    verify_app_no_cap: "verify/github_app-no-capability", DEFAULT, app_verify(Cap::Revoked);
    verify_app_no_lane: "verify/github_app-no-lane", NO_LANE, app_verify(Cap::Held);
}

#[test]
fn the_table_covers_every_operation_with_one_classification_per_row() {
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(names.len(), ROWS.len(), "duplicate row name");
    let tested: BTreeSet<&str> = TESTED.iter().copied().collect();
    assert_eq!(tested.len(), TESTED.len(), "duplicate test");
    assert_eq!(names, tested);
    for op in REQUIRED_OPERATIONS {
        assert!(
            ROWS.iter()
                .any(|row| row.op == *op && row.name.starts_with(op)),
            "no row for {op}"
        );
    }
    for row in ROWS {
        assert!(REQUIRED_OPERATIONS.contains(&row.op), "{}", row.name);
        assert!(row.name.starts_with(row.op), "{}", row.name);
        if let Class::Differs(why, cli, web) = row.class {
            assert!(!why.is_empty(), "{}", row.name);
            assert_ne!(cli, web, "{}", row.name);
        }
    }
}

#[test]
fn every_credential_kind_has_a_put_row() {
    for kind in fleet_core::credential::CredentialKind::ALL {
        let name = format!("put/{}", kind.wire_name());
        assert!(ROWS.iter().any(|row| row.name == name), "no row {name}");
    }
}

#[test]
fn agreement_needs_equal_outcomes_and_never_counts_absent() {
    let notice = |code: &str| Outcome::Notice(code.to_owned());
    assert!(agree(&notice("saved"), &notice("saved")));
    assert!(!agree(&notice("saved"), &notice("invalid")));
    assert!(!agree(&Outcome::Absent, &Outcome::Absent));
    assert!(!agree(&Outcome::Page404, &Outcome::Absent));
    assert!(agree(
        &Outcome::Listed(vec!["a".to_owned()]),
        &Outcome::Listed(vec!["a".to_owned()])
    ));
    assert!(!agree(
        &Outcome::Listed(vec!["a".to_owned()]),
        &Outcome::Listed(Vec::new())
    ));
}

#[sqlx::test]
async fn the_web_page_renders_every_notice_text(pool: PgPool) {
    let rig = Rig::start(pool, DEFAULT).await;
    let who = rig.persona("olive-notices", 'c').await;
    for notice in CredentialNotice::ALL {
        let page = rig
            .http(
                "GET",
                &format!("/credentials?notice={}", notice.code()),
                &who,
                "",
            )
            .await;
        assert_eq!(page.status, 200, "{}", notice.code());
        let escaped = notice.text().replace('\'', "&#x27;").replace('"', "&quot;");
        assert!(
            page.body.contains(&escaped),
            "{} text missing from the page",
            notice.code()
        );
    }
}

const HOSTILE: &[&str] = &[
    "sk-ant-api03-\rHOSTILE-abcdefghijklmnop",
    "sk-ant-api03-\r\nHOSTILE-abcdefghijklmnop",
    "sk-ant-api03-\u{85}HOSTILE-abcdefghijklmnop",
    "sk-ant-api03-\u{2028}HOSTILE-abcdefghijklmnop",
    "sk-ant-api03-\0HOSTILE-abcdefghijklmnop",
    "sk-ant-api03-\u{1b}[31mHOSTILE-abcdefghijklmnop",
    "sk-ant-api03-\u{202e}HOSTILE-abcdefghijklmnop",
    "sk-ant-api03-HOSTILE-\u{e9}\u{4e2d}-abcdefghijklmnop",
    "sk-ant-api03-HOSTILE ABCDEFGHIJKLMNOP",
    "ghp_HOSTILE_abcdefghijklmnopqrstuvwxyz0123456789",
    "github_pat_HOSTILE_abcdefghijklmnop",
];

fn fragment_of(secret: &str) -> &str {
    secret
        .split(['\r', '\n', '\0', '\u{85}', '\u{2028}', '\u{1b}', '\u{202e}'])
        .next_back()
        .unwrap_or(secret)
}

fn assert_clean(what: &str, shown: &str, secret: &str) {
    assert!(
        !shown.contains(secret),
        "{what}: printed the secret: {shown:?}"
    );
    let tail = fragment_of(secret);
    assert!(
        !shown.contains("HOSTILE"),
        "{what}: printed a fragment {tail:?}: {shown:?}"
    );
    assert!(
        !shown
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t'),
        "{what}: control character reached the terminal: {shown:?}"
    );
}

fn shown_of(result: &(Result<(), CliError>, String)) -> String {
    format!(
        "{}{}",
        result.1,
        result
            .0
            .as_ref()
            .err()
            .map_or(String::new(), ToString::to_string)
    )
}

#[sqlx::test]
async fn a_hostile_secret_on_stdin_never_reaches_output_through_the_real_server(pool: PgPool) {
    let rig = Rig::start(pool, DEFAULT).await;
    let who = rig.persona("olive-hostile", 'h').await;
    for kind in [
        "anthropic_api_key",
        "github_pat",
        "github_app",
        "gitlab_pat",
    ] {
        for secret in HOSTILE {
            for github in [Gh::Accepts, Gh::Rejects, Gh::Unavailable] {
                rig.github.set(github);
                let result = rig
                    .cli(&who.token, &["credential", "put", kind], secret.as_bytes())
                    .await;
                assert_clean(kind, &shown_of(&result), secret);
            }
        }
    }
}

#[sqlx::test]
async fn a_secret_given_as_an_argument_is_refused_without_an_echo(pool: PgPool) {
    let rig = Rig::start(pool, DEFAULT).await;
    let who = rig.persona("olive-argv", 'g').await;
    for secret in HOSTILE {
        let shapes: Vec<Vec<String>> = vec![
            vec![
                "credential".into(),
                "put".into(),
                "anthropic_api_key".into(),
                (*secret).into(),
            ],
            vec![
                "credential".into(),
                "put".into(),
                "anthropic_api_key".into(),
                format!("--value={secret}"),
            ],
            vec![
                "credential".into(),
                "put".into(),
                "anthropic_api_key".into(),
                "--value".into(),
                (*secret).into(),
            ],
            vec![
                "credential".into(),
                "put".into(),
                "anthropic_api_key".into(),
                "-v".into(),
                (*secret).into(),
            ],
            vec![
                "credential".into(),
                "put".into(),
                format!("--value={secret}"),
            ],
            vec!["credential".into(), "put".into(), (*secret).into()],
            vec!["credential".into(), "list".into(), (*secret).into()],
            vec!["credential".into(), "delete".into(), (*secret).into()],
            vec!["credential".into(), "verify".into(), (*secret).into()],
        ];
        for shape in shapes {
            let mut full = vec![
                "fleet".to_owned(),
                "--server".to_owned(),
                format!("http://{}", rig.addr),
            ];
            full.extend(shape.iter().cloned());
            match Cli::try_parse_from(&full) {
                Err(err) => assert_clean("clap", &err.to_string(), secret),
                Ok(cli) => {
                    let token = who.token.clone();
                    let mut out = Vec::new();
                    let result = run(
                        cli,
                        move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
                        &mut &b""[..],
                        &mut out,
                    )
                    .await;
                    let shown = format!(
                        "{}{}",
                        String::from_utf8_lossy(&out),
                        result.err().map_or(String::new(), |e| e.to_string())
                    );
                    assert_clean(&format!("{shape:?}"), &shown, secret);
                }
            }
        }
    }
    assert_eq!(rig.kinds(who.id).await, Vec::<String>::new());
}

#[sqlx::test]
async fn an_oversize_or_non_utf8_stdin_is_refused_without_an_echo(pool: PgPool) {
    let rig = Rig::start(pool, DEFAULT).await;
    let who = rig.persona("olive-size", 's').await;
    let mut big = b"sk-ant-api03-HOSTILE-".to_vec();
    big.resize(100_000, b'a');
    let mut bad = b"sk-ant-api03-HOSTILE-".to_vec();
    bad.extend_from_slice(&[0xff, 0xfe]);
    for stdin in [big, bad] {
        let result = rig
            .cli(
                &who.token,
                &["credential", "put", "anthropic_api_key"],
                &stdin,
            )
            .await;
        let shown = shown_of(&result);
        assert!(!shown.contains("HOSTILE"), "{shown}");
        let err = result.0.unwrap_err();
        assert_eq!(err.to_string(), CredentialNotice::Invalid.text());
    }
    assert_eq!(rig.kinds(who.id).await, Vec::<String>::new());
}

#[tokio::test]
async fn a_refused_connection_does_not_print_the_secret() {
    for secret in HOSTILE {
        let (result, out) = run_cli(
            "127.0.0.1:1".parse().unwrap(),
            CLIENT_TOKEN,
            &["credential", "put", "anthropic_api_key"],
            secret.as_bytes(),
        )
        .await;
        let shown = format!("{out}{}", result.unwrap_err());
        assert_clean("connect", &shown, secret);
    }
}

#[derive(Clone)]
struct Fake {
    code: Option<Code>,
    secret: String,
}

impl Fake {
    fn status(&self) -> Status {
        Status::new(
            self.code.unwrap(),
            format!("rejected {} for good", self.secret),
        )
    }
}

#[tonic::async_trait]
impl FleetCredentials for Fake {
    async fn put_credential(
        &self,
        _request: Request<PutCredentialRequest>,
    ) -> Result<Response<CredentialInfo>, Status> {
        match self.code {
            Some(_) => Err(self.status()),
            None => Ok(Response::new(hostile_info(&self.secret))),
        }
    }

    async fn list_credentials(
        &self,
        _request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsReply>, Status> {
        match self.code {
            Some(_) => Err(self.status()),
            None => Ok(Response::new(ListCredentialsReply {
                credentials: vec![hostile_info(&self.secret)],
            })),
        }
    }

    async fn delete_credential(
        &self,
        _request: Request<DeleteCredentialRequest>,
    ) -> Result<Response<DeleteCredentialReply>, Status> {
        match self.code {
            Some(_) => Err(self.status()),
            None => Ok(Response::new(DeleteCredentialReply {})),
        }
    }

    async fn verify_credential(
        &self,
        _request: Request<VerifyCredentialRequest>,
    ) -> Result<Response<VerifyCredentialReply>, Status> {
        match self.code {
            Some(_) => Err(self.status()),
            None => Ok(Response::new(VerifyCredentialReply {
                valid: true,
                login: Some(format!("\u{1b}[31m{}\r\nowned", self.secret)),
                expires_at_ms: Some(EXPIRY_MS.unsigned_abs()),
            })),
        }
    }
}

fn hostile_info(secret: &str) -> CredentialInfo {
    CredentialInfo {
        id: 7,
        kind: format!("\u{1b}[31mkind{secret}"),
        shape: "static_secret".to_owned(),
        fingerprint: format!("ab\r\ncd{secret}"),
        login: Some(format!("\u{202e}login\u{85}{secret}")),
        expires_at_ms: Some(EXPIRY_MS.unsigned_abs()),
        host: String::new(),
    }
}

fn fake_server(fake: Fake) -> SocketAddr {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetCredentialsServer::new(fake))
            .serve_with_incoming(incoming),
    );
    addr
}

const CODES: &[Code] = &[
    Code::Cancelled,
    Code::Unknown,
    Code::InvalidArgument,
    Code::DeadlineExceeded,
    Code::NotFound,
    Code::AlreadyExists,
    Code::PermissionDenied,
    Code::ResourceExhausted,
    Code::FailedPrecondition,
    Code::Aborted,
    Code::OutOfRange,
    Code::Unimplemented,
    Code::Internal,
    Code::Unavailable,
    Code::DataLoss,
    Code::Unauthenticated,
];

#[tokio::test]
async fn a_server_message_that_echoes_the_secret_is_never_printed_on_any_rpc() {
    let secret = "sk-ant-api03-ECHOED-abcdefghijklmnop";
    let calls: [(&[&str], &[u8]); 4] = [
        (
            &["credential", "put", "anthropic_api_key"],
            secret.as_bytes(),
        ),
        (&["credential", "list"], b""),
        (&["credential", "delete", "7"], b""),
        (&["credential", "verify", "7"], b""),
    ];
    for code in CODES {
        let addr = fake_server(Fake {
            code: Some(*code),
            secret: secret.to_owned(),
        });
        for (args, stdin) in calls {
            let (result, out) = run_cli(addr, CLIENT_TOKEN, args, stdin).await;
            let shown = format!("{out}{}", result.unwrap_err());
            assert!(!shown.contains("ECHOED"), "{code:?} {args:?}: {shown}");
            assert!(!shown.contains("rejected"), "{code:?} {args:?}: {shown}");
        }
    }
}

#[tokio::test]
async fn hostile_reply_fields_are_stripped_and_redacted_on_every_success_path() {
    let addr = fake_server(Fake {
        code: None,
        secret: CLIENT_TOKEN.to_owned(),
    });
    let calls: [(&[&str], &[u8]); 4] = [
        (&["credential", "put", "anthropic_api_key"], ANT.as_bytes()),
        (&["credential", "list"], b""),
        (&["credential", "delete", "7"], b""),
        (&["credential", "verify", "7"], b""),
    ];
    for (args, stdin) in calls {
        let (result, out) = run_cli(addr, CLIENT_TOKEN, args, stdin).await;
        result.unwrap();
        assert!(!out.contains(CLIENT_TOKEN), "{args:?}: {out:?}");
        assert!(
            !out.chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "{args:?}: {out:?}"
        );
        assert!(
            !out.contains('\u{85}') && !out.contains('\u{202e}'),
            "{args:?}: {out:?}"
        );
    }
}

#[sqlx::test]
async fn a_secret_of_exactly_the_cap_is_saved_and_one_byte_more_is_refused(pool: PgPool) {
    let rig = Rig::start(pool, DEFAULT).await;
    let who = rig.persona("olive-cap", 'd').await;
    let exact = vec![b'a'; fleet_proto::MAX_CREDENTIAL_VALUE_BYTES];
    let (result, _) = rig
        .cli(
            &who.token,
            &["credential", "put", "anthropic_api_key"],
            &exact,
        )
        .await;
    result.unwrap();
    assert_eq!(
        rig.kinds(who.id).await,
        vec!["anthropic_api_key".to_owned()]
    );
    let mut over = exact.clone();
    over.push(b'a');
    let (result, _) = rig
        .cli(&who.token, &["credential", "put", "codex_api_key"], &over)
        .await;
    assert!(matches!(
        result,
        Err(CliError::Credential(CredentialNotice::Invalid))
    ));
}

#[test]
fn a_credential_notice_exits_with_code_one_and_usage_with_two() {
    for notice in CredentialNotice::ALL {
        assert_eq!(CliError::Credential(*notice).exit_code(), 1);
    }
    assert_eq!(CliError::Usage("x".to_owned()).exit_code(), 2);
}
