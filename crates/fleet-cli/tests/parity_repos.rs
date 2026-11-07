//! Parity of the repository commands between the `fleet` CLI (gRPC) and the web repositories
//! page, both served by one in-process server on Postgres with a scripted forge verifier.
//!
//! `ROWS` is the scenario table: one row per action and outcome. Each scenario runs on two
//! users of one server, one through the CLI and one through the web form, and both must end in
//! the same notice code, the same fixed text, the same listed repositories, the same verified
//! stamp and the same stored rows. A scenario can cap the rows per user and can seed a third user
//! instead of the two that act. The box token has no web equivalent, so its refusal is a
//! separate test. The tests need a Postgres superuser URL in `DATABASE_URL` and live in their
//! own binary because they bind sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_core::stamp::utc_stamp;
use fleet_proto::CredentialNotice;
use fleet_proto::v1::AddRepoRequest;
use fleet_server::auth::BearerAuth;
use fleet_server::config::{Forge, RepoHosts, Token};
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::repo_fake::FakeVerifier;
use fleet_server::cred::repo_store::RepoStore;
use fleet_server::cred::repo_verify::RepoVerifiers;
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, RepoService, Users};
use fleet_server::service::{UpdateRelay, serve_with_credentials};
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(30);
const ORIGIN: &str = "https://fleet.example.com";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const CLIENT_TOKEN: &str = "client-token-0123456789abcdef012345";
const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const HOSTS: &str = "host=github.com,forge=github,api=https://api.github.com;host=git.example.org,forge=forgejo,api=https://git.example.org/api/v1";
const REPO: &str = "github.com/octo/hello";

static FILES: AtomicUsize = AtomicUsize::new(0);

const ROWS: &[&str] = &[
    "add/ok/push_true",
    "add/ok/push_false",
    "add/ok/push_unreported",
    "add/ok/re_add_refreshes_at_cap",
    "add/refused/forgejo_host_until_migration_0037",
    "add/refused/not_allowed_host",
    "add/refused/no_credential",
    "add/refused/not_found_or_no_access",
    "add/refused/upstream_unavailable",
    "add/refused/timeout",
    "add/refused/invalid_reference",
    "add/refused/url_with_userinfo",
    "add/refused/repo_limit",
    "remove/ok",
    "remove/ok/github_kind_row_with_reserved_owner",
    "remove/refused/other_users_row",
    "remove/not_found",
    "remove/invalid_reference",
    "list/empty",
    "list/non_runnable_host",
    "list/rows",
];

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Unavailable)
    }
}

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

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    repos: RepoService,
}

impl Rig {
    async fn start(pool: PgPool, verifier: FakeVerifier, cap: usize) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let path = std::env::temp_dir().join(format!(
            "fleet-parity-repos-{}-{}.keys",
            std::process::id(),
            FILES.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
        let sealer = FileSealer::load(&path);
        std::fs::remove_file(&path).unwrap();
        let creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
        let verifier = Arc::new(verifier);
        let verifiers = RepoVerifiers::new(RepoHosts::parse(HOSTS).unwrap())
            .with(Forge::Github, verifier.clone())
            .with(Forge::Forgejo, verifier);
        let repos = RepoService::new(
            RepoStore::new(pool.clone(), creds.clone()).with_max_repos(cap),
            Arc::new(verifiers),
        );
        let service = CredentialService::new(creds, Arc::new(NoGithub)).with_repos(repos.clone());
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_console(auth, Some(service.clone()), store.clone());
        let bearer = BearerAuth::new(
            &Token::new(BOX_TOKEN.to_owned()).unwrap(),
            Some(&Token::new(CLIENT_TOKEN.to_owned()).unwrap()),
        )
        .with_users(users);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            serve_with_credentials(
                &store,
                &bearer,
                web,
                Some(service),
                UpdateRelay::default(),
                TcpIncoming::from(listener),
                std::future::pending::<()>(),
            )
            .await
        });
        Self { addr, pool, repos }
    }

    async fn persona(&self, name: &str, seed: char, with_pat: bool) -> Persona {
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
        if with_pat {
            let sealer_path = std::env::temp_dir().join(format!(
                "fleet-parity-repos-pat-{}-{}.keys",
                std::process::id(),
                FILES.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&sealer_path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
            let sealer = FileSealer::load(&sealer_path);
            std::fs::remove_file(&sealer_path).unwrap();
            CredentialStore::new(self.pool.clone(), Arc::new(sealer.unwrap()))
                .put(
                    id,
                    CredentialKind::GithubPat,
                    CredentialShape::StaticSecret,
                    Secret::new(PAT.to_owned()),
                    Some("octo".to_owned()),
                    None,
                )
                .await
                .unwrap();
        }
        Persona {
            id,
            token: String::from_utf8(token.token.expose().to_vec()).unwrap(),
            cookie: format!("{SESSION_COOKIE}={session}"),
            csrf,
        }
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

    async fn stamps(&self, user: i64) -> Vec<String> {
        let rows: Vec<i64> = sqlx::query_scalar(
            "SELECT (EXTRACT(EPOCH FROM verified_at) * 1000)::bigint FROM user_repos \
             WHERE user_id = $1 ORDER BY host, path",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await
        .unwrap();
        rows.into_iter()
            .map(|ms| utc_stamp(u64::try_from(ms).unwrap()))
            .collect()
    }

    async fn stored(&self, user: i64) -> Vec<(String, String, String, Option<bool>)> {
        sqlx::query_as(
            "SELECT host, path, forge_kind, push FROM user_repos WHERE user_id = $1 ORDER BY host, path",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }
}

fn hex(text: &str) -> String {
    text.bytes().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn enc(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.') {
            out.push(char::from(*byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

async fn run_cli(addr: SocketAddr, token: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let url = format!("http://{addr}");
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let token = token.to_owned();
    let mut out = Vec::new();
    let mut stdin: &[u8] = &[];
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
enum Act {
    Add(&'static str),
    Remove(&'static str),
    List,
}

struct Scenario {
    name: &'static str,
    verifier: fn() -> FakeVerifier,
    seed: &'static [&'static str],
    cap: usize,
    foreign: bool,
    act: Act,
    notice: Option<CredentialNotice>,
    listed: &'static [[&'static str; 5]],
}

fn ok_true() -> FakeVerifier {
    FakeVerifier::ok("octo/hello", Some(true))
}

fn ok_false() -> FakeVerifier {
    FakeVerifier::ok("octo/hello", Some(false))
}

fn ok_none() -> FakeVerifier {
    FakeVerifier::ok("octo/hello", None)
}

const UNCAPPED: usize = fleet_proto::MAX_REPOS_PER_USER;
const GHE_ADMIN: &str = "sqlgh:ghe.example.com/admin/hello";
const GH_OLD: &str = "old:github.com/octo/hello";
const GH_TRUE: [&str; 5] = ["github.com", "octo/hello", "github", "yes", "yes"];
const GH_FALSE: [&str; 5] = ["github.com", "octo/hello", "github", "yes", "no"];
const GH_NONE: [&str; 5] = ["github.com", "octo/hello", "github", "yes", "unknown"];
const FJ_SEED: &str = "sql:git.example.org/octo/hello";
const FJ_UNKNOWN: [&str; 5] = ["git.example.org", "octo/hello", "forgejo", "no", "unknown"];

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "add/ok/push_true",
        verifier: ok_true,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::Saved),
        listed: &[GH_TRUE],
    },
    Scenario {
        name: "add/ok/push_false",
        verifier: ok_false,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::Saved),
        listed: &[GH_FALSE],
    },
    Scenario {
        name: "add/ok/push_unreported",
        verifier: ok_none,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add("https://GitHub.com/Octo/Hello.git"),
        notice: Some(CredentialNotice::Saved),
        listed: &[GH_NONE],
    },
    Scenario {
        name: "add/refused/forgejo_host_until_migration_0037",
        verifier: ok_true,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add("git.example.org/octo/hello"),
        notice: Some(CredentialNotice::RepoNoCredential),
        listed: &[],
    },
    Scenario {
        name: "add/refused/not_allowed_host",
        verifier: FakeVerifier::not_allowed_host,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::RepoHostRefused),
        listed: &[],
    },
    Scenario {
        name: "add/refused/no_credential",
        verifier: FakeVerifier::no_credential,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::RepoNoCredential),
        listed: &[],
    },
    Scenario {
        name: "add/refused/not_found_or_no_access",
        verifier: FakeVerifier::not_found_or_no_access,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::RepoNotFound),
        listed: &[],
    },
    Scenario {
        name: "add/refused/upstream_unavailable",
        verifier: FakeVerifier::upstream_unavailable,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::RepoUpstreamUnavailable),
        listed: &[],
    },
    Scenario {
        name: "add/refused/timeout",
        verifier: FakeVerifier::timed_out,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::RepoTimeout),
        listed: &[],
    },
    Scenario {
        name: "add/refused/invalid_reference",
        verifier: ok_true,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add("github.com/octo"),
        notice: Some(CredentialNotice::RepoInvalid),
        listed: &[],
    },
    Scenario {
        name: "add/refused/url_with_userinfo",
        verifier: ok_true,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Add("https://user:pass@github.com/octo/hello"),
        notice: Some(CredentialNotice::RepoInvalid),
        listed: &[],
    },
    Scenario {
        name: "remove/ok",
        verifier: ok_true,
        seed: &[REPO],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Remove("https://github.com/Octo/Hello.git"),
        notice: Some(CredentialNotice::Deleted),
        listed: &[],
    },
    Scenario {
        name: "remove/not_found",
        verifier: ok_true,
        seed: &[REPO],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Remove("github.com/octo/ghost"),
        notice: Some(CredentialNotice::RepoMissing),
        listed: &[GH_TRUE],
    },
    Scenario {
        name: "remove/invalid_reference",
        verifier: ok_true,
        seed: &[REPO],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Remove("github.com/octo"),
        notice: Some(CredentialNotice::RepoInvalid),
        listed: &[GH_TRUE],
    },
    Scenario {
        name: "list/empty",
        verifier: ok_true,
        seed: &[],
        cap: UNCAPPED,
        foreign: false,
        act: Act::List,
        notice: None,
        listed: &[],
    },
    Scenario {
        name: "list/non_runnable_host",
        verifier: ok_true,
        seed: &["sql:git.example.org/octo/hello"],
        cap: UNCAPPED,
        foreign: false,
        act: Act::List,
        notice: None,
        listed: &[FJ_UNKNOWN],
    },
    Scenario {
        name: "list/rows",
        verifier: ok_true,
        seed: &[REPO],
        cap: UNCAPPED,
        foreign: false,
        act: Act::List,
        notice: None,
        listed: &[GH_TRUE],
    },
    Scenario {
        name: "add/ok/re_add_refreshes_at_cap",
        verifier: ok_true,
        seed: &[GH_OLD],
        cap: 1,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::Saved),
        listed: &[GH_TRUE],
    },
    Scenario {
        name: "add/refused/repo_limit",
        verifier: ok_true,
        seed: &[FJ_SEED],
        cap: 1,
        foreign: false,
        act: Act::Add(REPO),
        notice: Some(CredentialNotice::RepoLimit),
        listed: &[FJ_UNKNOWN],
    },
    Scenario {
        name: "remove/ok/github_kind_row_with_reserved_owner",
        verifier: ok_true,
        seed: &[GHE_ADMIN],
        cap: UNCAPPED,
        foreign: false,
        act: Act::Remove("https://GHE.example.com/Admin/Hello.git"),
        notice: Some(CredentialNotice::Deleted),
        listed: &[],
    },
    Scenario {
        name: "remove/refused/other_users_row",
        verifier: ok_true,
        seed: &[REPO],
        cap: UNCAPPED,
        foreign: true,
        act: Act::Remove(REPO),
        notice: Some(CredentialNotice::RepoMissing),
        listed: &[],
    },
];

fn cli_listing(out: &str) -> Vec<[String; 6]> {
    out.lines()
        .filter(|line| line.contains('\t'))
        .map(|line| {
            let cells: Vec<String> = line.split('\t').map(str::to_owned).collect();
            assert_eq!(cells.len(), 6, "{line}");
            cells.into_iter().collect::<Vec<_>>().try_into().unwrap()
        })
        .collect()
}

fn web_listing(page: &str) -> Vec<[String; 6]> {
    page.split("<tbody>")
        .nth(1)
        .unwrap_or_default()
        .split("<tr>")
        .skip(1)
        .map(|chunk| {
            let cells: Vec<String> = chunk
                .split("<td")
                .skip(1)
                .take(6)
                .map(|cell| {
                    let inner = cell.split_once('>').unwrap().1;
                    inner.split_once("</td>").unwrap().0.to_owned()
                })
                .collect();
            assert_eq!(cells.len(), 6, "{chunk}");
            cells.try_into().unwrap()
        })
        .collect()
}

fn escaped(text: &str) -> String {
    text.replace('\'', "&#x27;").replace('"', "&quot;")
}

async fn seed(rig: &Rig, scenario: &Scenario, users: &[&Persona]) {
    for who in users {
        for repo in scenario.seed {
            let Some((kind, raw)) = repo.split_once(':') else {
                rig.repos
                    .add(
                        who.id,
                        &AddRepoRequest {
                            repo: (*repo).to_owned(),
                        },
                    )
                    .await
                    .unwrap();
                continue;
            };
            let (host, path) = raw.split_once('/').unwrap();
            let (forge, push, at) = match kind {
                "sql" => Some(("forgejo", None, None)),
                "sqlgh" => Some(("github", None, None)),
                "old" => Some(("github", Some(false), Some("2000-01-01 00:00:00+00"))),
                _ => None,
            }
            .unwrap();
            sqlx::query(
                "INSERT INTO user_repos (user_id, host, path, forge_kind, push, verified_at) \
                 VALUES ($1, $2, $3, $4, $5, COALESCE($6::text::timestamptz, now()))",
            )
            .bind(who.id)
            .bind(host)
            .bind(path)
            .bind(forge)
            .bind(push)
            .bind(at)
            .execute(&rig.pool)
            .await
            .unwrap();
        }
    }
}

async fn check_outcome(
    rig: &Rig,
    scenario: &Scenario,
    web_user: &Persona,
    cli_result: Result<(), CliError>,
    cli_out: &str,
    web_code: Reply,
) {
    let name = scenario.name;
    let Some(notice) = scenario.notice else {
        assert!(cli_result.is_ok(), "{name}");
        assert_eq!(web_code.status, 200, "{name}");
        return;
    };
    if notice == CredentialNotice::Saved || notice == CredentialNotice::Deleted {
        assert!(cli_result.is_ok(), "{name}: {cli_out}");
        assert!(
            cli_out.trim_end().ends_with(notice.text()),
            "{name}: {cli_out}"
        );
    } else {
        let err = cli_result.unwrap_err();
        assert!(
            matches!(&err, CliError::Credential(got) if *got == notice),
            "{name} cli: {err:?}"
        );
        assert_eq!(err.exit_code(), 1, "{name}");
        assert_eq!(err.to_string(), notice.text(), "{name}");
    }
    assert_eq!(web_code.status, 303, "{name}");
    let location = web_code
        .head
        .lines()
        .find_map(|l| l.strip_prefix("location: "))
        .unwrap();
    assert_eq!(
        location,
        format!("/repos?notice={}", notice.code()),
        "{name}"
    );
    let page = rig.http("GET", location, web_user, "").await;
    assert_eq!(page.status, 200, "{name}");
    assert!(page.body.contains(&escaped(notice.text())), "{name}");
}

async fn judge(name: &str, pool: PgPool) {
    assert!(ROWS.contains(&name), "{name} is not in ROWS");
    let scenario = SCENARIOS.iter().find(|s| s.name == name).unwrap();
    let rig = Rig::start(pool, (scenario.verifier)(), scenario.cap).await;
    let cli_user = rig.persona("olive-cli", 'a', true).await;
    let web_user = rig.persona("olive-web", 'b', true).await;
    let other = rig.persona("olive-other", 'c', true).await;
    if scenario.foreign {
        seed(&rig, scenario, &[&other]).await;
    } else {
        seed(&rig, scenario, &[&cli_user, &web_user]).await;
    }

    let (cli_result, cli_out, web_code) = match scenario.act {
        Act::Add(repo) => {
            let (r, out) = run_cli(rig.addr, &cli_user.token, &["repo", "add", repo]).await;
            let reply = rig
                .post(&web_user, "/repos/add", &format!("repo={}", enc(repo)))
                .await;
            (r, out, reply)
        }
        Act::Remove(repo) => {
            let (r, out) = run_cli(rig.addr, &cli_user.token, &["repo", "remove", repo]).await;
            let Ok((host, path)) = fleet_core::repo::RepoRef::locate(repo) else {
                assert!(
                    matches!(r, Err(CliError::Credential(CredentialNotice::RepoInvalid))),
                    "{name}: the CLI refuses a bad reference before any call"
                );
                let page = rig.http("GET", "/repos", &web_user, "").await;
                return finish(&rig, scenario, [&cli_user, &web_user, &other], page).await;
            };
            let reply = rig
                .post(
                    &web_user,
                    "/repos/remove",
                    &format!("repo={}-{}", hex(&host), hex(&path)),
                )
                .await;
            (r, out, reply)
        }
        Act::List => {
            let (r, out) = run_cli(rig.addr, &cli_user.token, &["repo", "list"]).await;
            let reply = rig.http("GET", "/repos", &web_user, "").await;
            (r, out, reply)
        }
    };

    check_outcome(&rig, scenario, &web_user, cli_result, &cli_out, web_code).await;

    let page = rig.http("GET", "/repos", &web_user, "").await;
    finish(&rig, scenario, [&cli_user, &web_user, &other], page).await;
}

async fn finish(rig: &Rig, scenario: &Scenario, users: [&Persona; 3], cli_page: Reply) {
    let [cli_user, web_user, other] = users;
    let name = scenario.name;
    let (cli_list_result, cli_list_out) =
        run_cli(rig.addr, &cli_user.token, &["repo", "list"]).await;
    assert!(cli_list_result.is_ok(), "{name}");
    let want: Vec<[String; 5]> = scenario
        .listed
        .iter()
        .map(|row| row.map(str::to_owned))
        .collect();
    let (cli_rows, web_rows) = (cli_listing(&cli_list_out), web_listing(&cli_page.body));
    let shown = |rows: &[[String; 6]]| -> Vec<[String; 5]> {
        rows.iter()
            .map(|row| {
                row.iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect()
    };
    assert_eq!(shown(&cli_rows), want, "{name} cli");
    assert_eq!(shown(&web_rows), want, "{name} web");
    let stamps = |rows: &[[String; 6]]| rows.iter().map(|row| row[5].clone()).collect::<Vec<_>>();
    assert_eq!(
        stamps(&cli_rows),
        rig.stamps(cli_user.id).await,
        "{name} cli stamp"
    );
    assert_eq!(
        stamps(&web_rows),
        rig.stamps(web_user.id).await,
        "{name} web stamp"
    );
    for stamp in stamps(&cli_rows).iter().chain(&stamps(&web_rows)) {
        assert!(
            !stamp.starts_with("2000-"),
            "{name}: {stamp} was not refreshed"
        );
    }
    assert_eq!(
        rig.stored(other.id).await.len(),
        if scenario.foreign {
            scenario.seed.len()
        } else {
            0
        },
        "{name}: the third user keeps exactly its rows"
    );
    assert_eq!(
        rig.stored(cli_user.id).await,
        rig.stored(web_user.id).await,
        "{name}"
    );
}

#[test]
fn every_row_has_one_scenario_and_every_refusal_reason_has_a_row() {
    let names: BTreeSet<&str> = ROWS.iter().copied().collect();
    let scenarios: BTreeSet<&str> = SCENARIOS.iter().map(|s| s.name).collect();
    assert_eq!(names.len(), ROWS.len());
    assert_eq!(scenarios.len(), SCENARIOS.len());
    assert_eq!(names, scenarios);
    for reason in [
        "not_allowed_host",
        "no_credential",
        "not_found_or_no_access",
        "upstream_unavailable",
        "timeout",
        "repo_limit",
    ] {
        assert!(
            names.contains(format!("add/refused/{reason}").as_str()),
            "{reason}"
        );
    }
}

macro_rules! row {
    ($fn_name:ident, $row:literal) => {
        #[sqlx::test]
        async fn $fn_name(pool: PgPool) {
            judge($row, pool).await;
        }
    };
}

row!(add_ok_push_true, "add/ok/push_true");
row!(add_ok_push_false, "add/ok/push_false");
row!(add_ok_push_unreported, "add/ok/push_unreported");
row!(
    add_ok_re_add_refreshes_at_cap,
    "add/ok/re_add_refreshes_at_cap"
);
row!(
    add_refused_forgejo_host_until_migration_0037,
    "add/refused/forgejo_host_until_migration_0037"
);
row!(add_refused_not_allowed_host, "add/refused/not_allowed_host");
row!(add_refused_no_credential, "add/refused/no_credential");
row!(
    add_refused_not_found_or_no_access,
    "add/refused/not_found_or_no_access"
);
row!(
    add_refused_upstream_unavailable,
    "add/refused/upstream_unavailable"
);
row!(add_refused_timeout, "add/refused/timeout");
row!(
    add_refused_invalid_reference,
    "add/refused/invalid_reference"
);
row!(
    add_refused_url_with_userinfo,
    "add/refused/url_with_userinfo"
);
row!(add_refused_repo_limit, "add/refused/repo_limit");
row!(remove_ok, "remove/ok");
row!(
    remove_ok_github_kind_row_with_reserved_owner,
    "remove/ok/github_kind_row_with_reserved_owner"
);
row!(
    remove_refused_other_users_row,
    "remove/refused/other_users_row"
);
row!(remove_not_found, "remove/not_found");
row!(remove_invalid_reference, "remove/invalid_reference");
row!(list_empty, "list/empty");
row!(list_non_runnable_host, "list/non_runnable_host");
row!(list_rows, "list/rows");

#[sqlx::test]
async fn the_box_token_is_refused_on_every_repo_action_and_stores_nothing(pool: PgPool) {
    let rig = Rig::start(pool, ok_true(), UNCAPPED).await;
    let who = rig.persona("olive-agent", 'a', true).await;
    for args in [
        vec!["repo", "add", REPO],
        vec!["repo", "list"],
        vec!["repo", "remove", REPO],
    ] {
        let (result, out) = run_cli(rig.addr, BOX_TOKEN, &args).await;
        let err = result.unwrap_err();
        assert!(
            matches!(&err, CliError::Credential(CredentialNotice::Failed)),
            "{args:?}: {err:?}"
        );
        assert_eq!(err.exit_code(), 1);
        assert_eq!(out, "");
    }
    assert_eq!(rig.stored(who.id).await.len(), 0);
}

#[tokio::test]
async fn stray_arguments_are_a_usage_error_before_any_connection() {
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    for args in [
        vec!["repo", "list", "extra"],
        vec!["repo", "add", REPO, "extra"],
        vec!["repo", "remove", REPO, "extra"],
    ] {
        let (result, out) = run_cli(addr, "t", &args).await;
        assert!(matches!(result, Err(CliError::Usage(_))), "{args:?}");
        assert_eq!(result.unwrap_err().exit_code(), 2);
        assert_eq!(out, "");
    }
}

#[tokio::test]
async fn a_bad_reference_is_refused_before_any_connection() {
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    for action in ["add", "remove"] {
        let (result, out) = run_cli(addr, "t", &["repo", action, "github.com/a"]).await;
        assert!(
            matches!(
                result,
                Err(CliError::Credential(CredentialNotice::RepoInvalid))
            ),
            "{action}"
        );
        assert_eq!(out, "");
    }
}

#[test]
fn a_repo_notice_exits_with_code_one() {
    for notice in CredentialNotice::ALL {
        assert_eq!(CliError::Credential(*notice).exit_code(), 1);
    }
}
