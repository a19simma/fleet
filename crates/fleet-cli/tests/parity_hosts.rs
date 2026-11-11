//! Parity of `fleet host add|list|remove|approve-private|revoke-private|requests` and the web
//! git remotes page, both over one `HostService` shape on one Postgres.
//!
//! `ROWS` is the operation table, one row per operation and scenario, each with exactly one
//! classification. Both surfaces end in a notice code from `CredentialNotice` or list the
//! registered hosts. `Same` means both ended in the same code or list and left the same hosts in
//! the database. `Differs` names a documented gap with the label each surface gives, and passes
//! only while the two still disagree in exactly that way. A label is `notice:<code>`, `listed`,
//! `usage`, `refused`, `403`, `404`, `hidden` or `unexpected:<text>`. The CLI reaches the
//! service through a `FleetHosts` server that sets the caller from the bearer token, the web
//! page through a session cookie, and both through a probe fake that answers a fixed verdict.
//!
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because they bind sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_core::host::{HostKind, HostName};
use fleet_proto::CredentialNotice;
use fleet_proto::v1::fleet_hosts_server::FleetHostsServer;
use fleet_server::auth::{BearerAuth, Caller};
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::hosts::{HostProbe, HostRefusal, HostService, HostStore};
use fleet_server::service::{FleetService, UpdateRelay, serve_with_credentials};
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Status};

const WAIT: Duration = Duration::from_secs(30);
const ORIGIN: &str = "https://fleet.example.com";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const ADMIN_TOKEN: &str = "admin-token";
const USER_TOKEN: &str = "user-token";
const FORGE: &str = "git.example.com";
const OTHER: &str = "code.example.org";
const MARK: &str = "zqxmark.example.com";
const ADMIN_ONLY: &str = "Only an admin can remove a host.";
const ADMIN_ONLY_PRIVATE: &str = "Only an admin can do this.";
const PRIVATE_IP: &str = "192.168.3.7";
static FILES: AtomicUsize = AtomicUsize::new(0);

const D_HOSTILE_ADD: &str = "the CLI normalises a hostile host and refuses it with a usage error before any request; the web form refuses it with the fixed refused notice, the notice the service gives";
const D_HOSTILE_REMOVE: &str = "the CLI refuses a hostile host with a usage error before any request; the web form refuses it with the fixed unknown-host notice, the notice the service gives";
const D_APPROVE_NOT_ADMIN: &str = "the CLI approve-private gets the server NOT_FOUND for a non-admin, as for an unknown host, and prints the fixed unknown-host notice; the web page answers 404 before any service call";
const D_ADMIN_ONLY_PRIVATE: &str = "the CLI prints its fixed admin-only text; the web page answers 404, never 403, and makes no service call";
const D_REQUESTS_HIDDEN: &str = "the CLI prints its fixed admin-only text; the web page lists the hosts and leaves the pending requests out for a non-admin";
const D_HOSTILE_APPROVE: &str = "the CLI refuses a hostile host with a usage error before any request; the web form refuses it with the fixed unknown-host notice, the notice the service gives";
const D_OVER_CAP_RAW: &str = "the CLI counts the raw address arguments against the cap and refuses with a usage error before any request; the web form dedups before the cap and approves (gap: web/hosts.rs is outside this slice, see .ralph/slices.md FUP-15)";
const D_NOT_ADMIN: &str = "the CLI prints its fixed admin-only text; fleet-proto has no notice for it, so the web page answers 403";
const AT_CAP: &[&str] = &[PRIVATE_IP; fleet_proto::MAX_HOST_APPROVED_IPS];
const OVER_CAP: &[&str] = &[PRIVATE_IP; fleet_proto::MAX_HOST_APPROVED_IPS + 1];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Notice(String),
    Listed(Vec<String>),
    Usage,
    Refused,
    Forbidden,
    Missing,
    Hidden,
    Unexpected(String),
}

impl Outcome {
    fn label(&self) -> String {
        match self {
            Self::Notice(code) => format!("notice:{code}"),
            Self::Listed(_) => "listed".to_owned(),
            Self::Usage => "usage".to_owned(),
            Self::Refused => "refused".to_owned(),
            Self::Forbidden => "403".to_owned(),
            Self::Missing => "404".to_owned(),
            Self::Hidden => "hidden".to_owned(),
            Self::Unexpected(text) => format!("unexpected:{text}"),
        }
    }
}

#[derive(Clone, Copy)]
enum Class {
    Same,
    Differs(&'static str, &'static str, &'static str),
    Gap(&'static str, &'static str, &'static str),
}

#[derive(Clone, Copy)]
enum Act {
    Add(&'static str),
    Remove(&'static str),
    List,
    Approve(&'static str, &'static [&'static str]),
    Revoke(&'static str),
    Requests,
}

struct Row {
    name: &'static str,
    op: &'static str,
    act: Act,
    admin: bool,
    seed: &'static [&'static str],
    in_use: Option<&'static str>,
    granted: bool,
    pending: &'static [&'static str],
    resolves: &'static [&'static str],
    verdict: Result<HostKind, HostRefusal>,
    class: Class,
}

const OK: Result<HostKind, HostRefusal> = Ok(HostKind::Forgejo);

const fn row(name: &'static str, op: &'static str, act: Act, admin: bool, class: Class) -> Row {
    Row {
        name,
        op,
        act,
        admin,
        seed: &[],
        in_use: None,
        granted: false,
        pending: &[],
        resolves: &[],
        verdict: OK,
        class,
    }
}

const REQUIRED_OPERATIONS: &[&str] = &[
    "add",
    "list",
    "remove",
    "approve-private",
    "revoke-private",
    "requests",
];

const PRIVATE: &[&str] = &[PRIVATE_IP];
const OTHER_IP: &[&str] = &["192.168.3.8"];

fn rows() -> Vec<Row> {
    let hostile = format!("{MARK}/path");
    let hostile: &'static str = Box::leak(hostile.into_boxed_str());
    let mut all = host_rows(hostile);
    all.extend(approve_rows(hostile));
    all.extend(revoke_rows(hostile));
    all.extend(request_rows());
    all
}

fn host_rows(hostile: &'static str) -> Vec<Row> {
    vec![
        row("add/new", "add", Act::Add(FORGE), false, Class::Same),
        Row {
            seed: &[FORGE],
            ..row("add/exists", "add", Act::Add(FORGE), false, Class::Same)
        },
        row(
            "add/folded",
            "add",
            Act::Add("Git.EXAMPLE.com."),
            false,
            Class::Same,
        ),
        Row {
            verdict: Err(HostRefusal::NotAllowedHost),
            ..row("add/refused", "add", Act::Add(MARK), false, Class::Same)
        },
        Row {
            verdict: Err(HostRefusal::NotForge),
            ..row("add/not_forge", "add", Act::Add(MARK), false, Class::Same)
        },
        row(
            "add/hostile",
            "add",
            Act::Add(hostile),
            false,
            Class::Differs(D_HOSTILE_ADD, "usage", "notice:host_refused"),
        ),
        Row {
            seed: &[FORGE, OTHER],
            ..row("list/user", "list", Act::List, false, Class::Same)
        },
        Row {
            seed: &[FORGE, OTHER],
            ..row("list/admin", "list", Act::List, true, Class::Same)
        },
        row("list/default", "list", Act::List, false, Class::Same),
        Row {
            seed: &[FORGE],
            ..row(
                "remove/admin",
                "remove",
                Act::Remove(FORGE),
                true,
                Class::Same,
            )
        },
        Row {
            seed: &[FORGE],
            in_use: Some(FORGE),
            ..row(
                "remove/in_use",
                "remove",
                Act::Remove(FORGE),
                true,
                Class::Same,
            )
        },
        row(
            "remove/unknown",
            "remove",
            Act::Remove(OTHER),
            true,
            Class::Same,
        ),
        row(
            "remove/builtin",
            "remove",
            Act::Remove("github.com"),
            true,
            Class::Same,
        ),
        Row {
            seed: &[FORGE],
            ..row(
                "remove/not_admin",
                "remove",
                Act::Remove(FORGE),
                false,
                Class::Differs(D_NOT_ADMIN, "refused", "403"),
            )
        },
        Row {
            seed: &[FORGE],
            ..row(
                "remove/hostile",
                "remove",
                Act::Remove(hostile),
                true,
                Class::Differs(D_HOSTILE_REMOVE, "usage", "notice:host_missing"),
            )
        },
    ]
}

fn approve_rows(hostile: &'static str) -> Vec<Row> {
    vec![
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            ..row(
                "approve/admin",
                "approve-private",
                Act::Approve(FORGE, PRIVATE),
                true,
                Class::Same,
            )
        },
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            ..row(
                "approve/at_cap_with_duplicates",
                "approve-private",
                Act::Approve(FORGE, AT_CAP),
                true,
                Class::Same,
            )
        },
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            ..row(
                "approve/over_cap_raw",
                "approve-private",
                Act::Approve(FORGE, OVER_CAP),
                true,
                Class::Gap(D_OVER_CAP_RAW, "usage", "notice:host_approved"),
            )
        },
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            ..row(
                "approve/mismatch",
                "approve-private",
                Act::Approve(FORGE, OTHER_IP),
                true,
                Class::Same,
            )
        },
        Row {
            resolves: PRIVATE,
            ..row(
                "approve/unknown",
                "approve-private",
                Act::Approve(OTHER, PRIVATE),
                true,
                Class::Same,
            )
        },
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            verdict: Err(HostRefusal::NotForge),
            ..row(
                "approve/not_forge",
                "approve-private",
                Act::Approve(FORGE, PRIVATE),
                true,
                Class::Same,
            )
        },
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            ..row(
                "approve/not_admin",
                "approve-private",
                Act::Approve(FORGE, PRIVATE),
                false,
                Class::Differs(D_APPROVE_NOT_ADMIN, "notice:host_missing", "404"),
            )
        },
        Row {
            seed: &[FORGE],
            pending: PRIVATE,
            resolves: PRIVATE,
            ..row(
                "approve/hostile",
                "approve-private",
                Act::Approve(hostile, PRIVATE),
                true,
                Class::Differs(D_HOSTILE_APPROVE, "usage", "notice:host_missing"),
            )
        },
    ]
}

fn revoke_rows(hostile: &'static str) -> Vec<Row> {
    vec![
        Row {
            seed: &[FORGE],
            granted: true,
            ..row(
                "revoke/admin",
                "revoke-private",
                Act::Revoke(FORGE),
                true,
                Class::Same,
            )
        },
        Row {
            seed: &[FORGE],
            ..row(
                "revoke/no_grant",
                "revoke-private",
                Act::Revoke(FORGE),
                true,
                Class::Same,
            )
        },
        row(
            "revoke/unknown",
            "revoke-private",
            Act::Revoke(OTHER),
            true,
            Class::Same,
        ),
        Row {
            seed: &[FORGE],
            granted: true,
            ..row(
                "revoke/not_admin",
                "revoke-private",
                Act::Revoke(FORGE),
                false,
                Class::Differs(D_ADMIN_ONLY_PRIVATE, "refused", "404"),
            )
        },
        Row {
            seed: &[FORGE],
            granted: true,
            ..row(
                "revoke/hostile",
                "revoke-private",
                Act::Revoke(hostile),
                true,
                Class::Differs(D_HOSTILE_REMOVE, "usage", "notice:host_missing"),
            )
        },
    ]
}

fn request_rows() -> Vec<Row> {
    vec![
        Row {
            pending: PRIVATE,
            ..row(
                "requests/admin",
                "requests",
                Act::Requests,
                true,
                Class::Same,
            )
        },
        row(
            "requests/empty",
            "requests",
            Act::Requests,
            true,
            Class::Same,
        ),
        Row {
            pending: PRIVATE,
            ..row(
                "requests/not_admin",
                "requests",
                Act::Requests,
                false,
                Class::Differs(D_REQUESTS_HIDDEN, "refused", "hidden"),
            )
        },
    ]
}

struct Probe {
    verdict: Mutex<Result<HostKind, HostRefusal>>,
    resolved: Mutex<Vec<IpAddr>>,
}

#[tonic::async_trait]
impl HostProbe for Probe {
    async fn probe(&self, _host: &HostName) -> Result<HostKind, HostRefusal> {
        *self.verdict.lock().unwrap()
    }

    async fn resolve(&self, _host: &HostName) -> Vec<IpAddr> {
        self.resolved.lock().unwrap().clone()
    }

    async fn probe_approved(
        &self,
        _host: &HostName,
        _approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal> {
        *self.verdict.lock().unwrap()
    }
}

struct Rig {
    cli: SocketAddr,
    web: SocketAddr,
    pool: PgPool,
    probe: Arc<Probe>,
    admin: (i64, String, String),
    user: (i64, String, String),
}

async fn persona(pool: &PgPool, name: &str, seed: char, admin: bool) -> (i64, String, String) {
    let id: i64 =
        sqlx::query_scalar("INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id")
            .bind(name)
            .bind(admin)
            .fetch_one(pool)
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
    .execute(pool)
    .await
    .unwrap();
    (id, format!("{SESSION_COOKIE}={session}"), csrf)
}

impl Rig {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let admin = persona(&pool, "root", 'a', true).await;
        let user = persona(&pool, "olive", 'b', false).await;
        let probe = Arc::new(Probe {
            verdict: Mutex::new(OK),
            resolved: Mutex::new(Vec::new()),
        });
        let grpc = FleetService::new(store.clone()).with_hosts(Some(HostService::new(
            HostStore::new(pool.clone()),
            probe.clone(),
        )));
        let callers = [
            (
                ADMIN_TOKEN,
                Caller {
                    user_id: admin.0,
                    is_admin: true,
                },
            ),
            (
                USER_TOKEN,
                Caller {
                    user_id: user.0,
                    is_admin: false,
                },
            ),
        ];
        let guarded = FleetHostsServer::with_interceptor(grpc, move |mut request: Request<()>| {
            let sent = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(str::to_owned);
            let caller = callers
                .iter()
                .find(|(token, _)| Some(*token) == sent.as_deref())
                .map(|(_, caller)| *caller)
                .ok_or_else(|| Status::unauthenticated("bad token"))?;
            request.extensions_mut().insert(caller);
            Ok(request)
        });
        let cli_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cli = cli_listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(guarded)
                .serve_with_incoming(TcpListenerStream::new(cli_listener)),
        );
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let hosts = HostService::new(HostStore::new(pool.clone()), probe.clone());
        let web = Web::with_hosts(auth, None, None, Some(hosts), store.clone());
        let bearer =
            BearerAuth::new(&Token::new(BOX_TOKEN.to_owned()).unwrap(), None).with_users(users);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            serve_with_credentials(
                &store,
                &bearer,
                web,
                None,
                UpdateRelay::default(),
                TcpIncoming::from(listener),
                std::future::pending::<()>(),
            )
            .await
        });
        FILES.fetch_add(1, Ordering::Relaxed);
        Self {
            cli,
            web: web_addr,
            pool,
            probe,
            admin,
            user,
        }
    }

    async fn reset(&self, row: &Row) {
        sqlx::query("DELETE FROM git_host_requests")
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM user_repos")
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM git_hosts WHERE host <> 'github.com'")
            .execute(&self.pool)
            .await
            .unwrap();
        for host in row.seed {
            sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
                .bind(host)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        if let Some(host) = row.in_use {
            sqlx::query(
                "INSERT INTO user_repos (user_id, host, path, forge_kind, push) \
                 VALUES ($1, $2, 'o/r', 'forgejo', NULL)",
            )
            .bind(self.admin.0)
            .bind(host)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        for ip in row.pending {
            sqlx::query(
                "INSERT INTO git_host_requests (host, user_id, resolved) \
                 VALUES ($1, $2, ARRAY[$3]::inet[])",
            )
            .bind(row.seed.first().copied().unwrap_or(FORGE))
            .bind(self.admin.0)
            .bind(ip)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        if row.granted {
            sqlx::query(
                "UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY[$1]::inet[] \
                 WHERE host = $2",
            )
            .bind(PRIVATE_IP)
            .bind(FORGE)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        *self.probe.resolved.lock().unwrap() =
            row.resolves.iter().map(|ip| ip.parse().unwrap()).collect();
        *self.probe.verdict.lock().unwrap() = row.verdict;
    }

    async fn stored(&self) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT host || ' ' || allow_private::text || ' ' || \
             COALESCE(array_to_string(approved_ips, ','), '') || ' ' || \
             (SELECT count(*) FROM git_host_requests r WHERE r.host = g.host)::text \
             FROM git_hosts g ORDER BY host",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn run_cli(&self, row: &Row) -> Outcome {
        let token = if row.admin { ADMIN_TOKEN } else { USER_TOKEN };
        let args: Vec<&str> = match row.act {
            Act::Add(host) => vec!["host", "add", host],
            Act::Remove(host) => vec!["host", "remove", host],
            Act::List => vec!["host", "list"],
            Act::Approve(host, ips) => {
                let mut args = vec!["host", "approve-private", host];
                args.extend(ips.iter().copied());
                args
            }
            Act::Revoke(host) => vec!["host", "revoke-private", host],
            Act::Requests => vec!["host", "requests"],
        };
        let url = format!("http://{}", self.cli);
        let mut full = vec!["fleet", "--server", url.as_str()];
        full.extend(args);
        let parsed = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut stdin: &[u8] = &[];
        let result = tokio::time::timeout(
            WAIT,
            run(
                parsed,
                move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.to_owned()),
                &mut stdin,
                &mut out,
            ),
        )
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&out).into_owned();
        match (result, row.act) {
            (Ok(()), Act::List | Act::Requests) => {
                Outcome::Listed(text.lines().map(|line| line.replace('\t', " ")).collect())
            }
            (Ok(()), _) => {
                let last = text.lines().last().unwrap_or_default();
                CredentialNotice::ALL
                    .iter()
                    .find(|notice| notice.text() == last)
                    .map_or_else(
                        || Outcome::Unexpected(last.to_owned()),
                        |notice| Outcome::Notice(notice.code().to_owned()),
                    )
            }
            (Err(CliError::Credential(notice)), _) => Outcome::Notice(notice.code().to_owned()),
            (Err(CliError::Usage(_)), _) => Outcome::Usage,
            (Err(CliError::Refused(text)), _)
                if text == ADMIN_ONLY || text == ADMIN_ONLY_PRIVATE =>
            {
                Outcome::Refused
            }
            (Err(other), _) => Outcome::Unexpected(other.to_string()),
        }
    }

    async fn http(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        body: &str,
    ) -> (u16, String, String) {
        let mut stream = TcpStream::connect(self.web).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\nContent-Length: {}\r\nCookie: {cookie}\r\n",
            body.len(),
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
        (
            head.split(' ').nth(1).unwrap().parse().unwrap(),
            head.to_owned(),
            body.to_owned(),
        )
    }

    async fn run_web(&self, row: &Row) -> Outcome {
        let who = if row.admin { &self.admin } else { &self.user };
        let (status, head, body) = match row.act {
            Act::List | Act::Requests => self.http("GET", "/hosts", &who.1, "").await,
            Act::Add(host) | Act::Remove(host) | Act::Revoke(host) | Act::Approve(host, _) => {
                let path = match row.act {
                    Act::Add(_) => "/hosts/add",
                    Act::Remove(_) => "/hosts/remove",
                    Act::Revoke(_) => "/hosts/revoke",
                    _ => "/hosts/approve",
                };
                let mut encoded = String::new();
                for byte in host.bytes() {
                    let _ = write!(encoded, "%{byte:02X}");
                }
                let mut form = format!("csrf={}&host={encoded}", who.2);
                if let Act::Approve(_, ips) = row.act {
                    let _ = write!(form, "&addresses={}", ips.join("%2C"));
                }
                self.http("POST", path, &who.1, &form).await
            }
        };
        match status {
            403 => Outcome::Forbidden,
            404 => Outcome::Missing,
            200 if matches!(row.act, Act::Requests) => requested(&body),
            200 => Outcome::Listed(listed(&body)),
            303 => head
                .lines()
                .find_map(|line| line.strip_prefix("location: /hosts?notice="))
                .map_or_else(
                    || Outcome::Unexpected(head.clone()),
                    |code| Outcome::Notice(code.to_owned()),
                ),
            other => Outcome::Unexpected(other.to_string()),
        }
    }
}

fn listed(body: &str) -> Vec<String> {
    let table = body.split("id=\"hosts\"").nth(1).unwrap();
    let table = table.split("</table>").next().unwrap();
    table
        .split("<tr data-host=\"")
        .skip(1)
        .map(|chunk| {
            let cells: Vec<&str> = chunk
                .split("<td>")
                .skip(1)
                .map(|cell| cell.split("</td>").next().unwrap())
                .collect();
            cells.iter().take(3).copied().collect::<Vec<_>>().join(" ")
        })
        .collect()
}

fn requested(body: &str) -> Outcome {
    let Some(table) = body.split("id=\"host-requests\"").nth(1) else {
        return Outcome::Hidden;
    };
    let table = table.split("</table>").next().unwrap();
    Outcome::Listed(
        table
            .split("<tr data-host=\"")
            .skip(1)
            .map(|chunk| {
                let cells: Vec<&str> = chunk
                    .split("<td>")
                    .skip(1)
                    .map(|cell| cell.split("</td>").next().unwrap())
                    .collect();
                cells.iter().take(3).copied().collect::<Vec<_>>().join(" ")
            })
            .collect(),
    )
}

fn agree(cli: &Outcome, web: &Outcome) -> bool {
    !matches!(cli, Outcome::Unexpected(_)) && cli == web
}

#[sqlx::test]
async fn every_row_has_one_classification_and_holds(pool: PgPool) {
    let rig = Rig::start(pool).await;
    let table = rows();
    let mut failures = Vec::new();
    for row in &table {
        rig.reset(row).await;
        let cli = rig.run_cli(row).await;
        let after_cli = rig.stored().await;
        rig.reset(row).await;
        let web = rig.run_web(row).await;
        let after_web = rig.stored().await;
        let ok = match row.class {
            Class::Same => agree(&cli, &web) && after_cli == after_web,
            Class::Differs(why, want_cli, want_web) => {
                !why.is_empty()
                    && cli != web
                    && cli.label() == want_cli
                    && web.label() == want_web
                    && after_cli == after_web
            }
            Class::Gap(why, want_cli, want_web) => {
                !why.is_empty() && cli != web && cli.label() == want_cli && web.label() == want_web
            }
        };
        if !ok {
            failures.push(format!(
                "{}: cli {} {after_cli:?}, web {} {after_web:?}",
                row.name,
                cli.label(),
                web.label()
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    for op in REQUIRED_OPERATIONS {
        let same = table
            .iter()
            .filter(|row| row.op == *op && matches!(row.class, Class::Same))
            .count();
        assert!(same > 0, "operation {op} has no Same row");
    }
}

#[sqlx::test]
async fn a_list_row_names_the_same_hosts_on_both_surfaces(pool: PgPool) {
    let rig = Rig::start(pool).await;
    let row = Row {
        seed: &[FORGE, OTHER],
        ..row("list/user", "list", Act::List, false, Class::Same)
    };
    rig.reset(&row).await;
    let cli = rig.run_cli(&row).await;
    let web = rig.run_web(&row).await;
    assert_eq!(
        cli,
        Outcome::Listed(vec![
            "code.example.org forgejo no".to_owned(),
            "git.example.com forgejo no".to_owned(),
            "github.com github no".to_owned(),
        ])
    );
    assert_eq!(cli, web);
}

#[sqlx::test]
async fn no_surface_shows_an_approved_address_to_a_user(pool: PgPool) {
    let rig = Rig::start(pool.clone()).await;
    let row = Row {
        seed: &[FORGE],
        ..row("list/user", "list", Act::List, false, Class::Same)
    };
    rig.reset(&row).await;
    sqlx::query(
        "UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY[$1]::inet[] WHERE host = $2",
    )
    .bind(PRIVATE_IP)
    .bind(FORGE)
    .execute(&pool)
    .await
    .unwrap();
    let who = &rig.user;
    let (_, _, body) = rig.http("GET", "/hosts", &who.1, "").await;
    assert!(!body.contains(PRIVATE_IP));
    let cli = rig.run_cli(&row).await;
    assert_eq!(
        cli,
        Outcome::Listed(vec![
            "git.example.com forgejo yes".to_owned(),
            "github.com github no".to_owned(),
        ])
    );
}

#[sqlx::test]
async fn a_requests_row_lists_the_same_pending_request_on_both_surfaces(pool: PgPool) {
    let rig = Rig::start(pool).await;
    let row = Row {
        pending: PRIVATE,
        ..row(
            "requests/admin",
            "requests",
            Act::Requests,
            true,
            Class::Same,
        )
    };
    rig.reset(&row).await;
    let cli = rig.run_cli(&row).await;
    let web = rig.run_web(&row).await;
    let line = format!("{FORGE} {} {PRIVATE_IP}", rig.admin.0);
    assert_eq!(cli, Outcome::Listed(vec![line]));
    assert_eq!(cli, web);
}
