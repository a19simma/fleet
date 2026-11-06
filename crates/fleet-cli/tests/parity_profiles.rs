//! Parity of profiles, catalog and capabilities between the `fleet` CLI (gRPC) and the web
//! console, both served by one in-process server on Postgres.
//!
//! `ROWS` is the operation table: one row per operation and scenario, each with exactly one
//! classification. `Same` means the CLI and the web end in the same outcome: both done with
//! the same observed set, or both refused with the same refusal class and, where the web
//! renders a reason, the same text. `Differs` names a documented gap and passes only while
//! the two surfaces still disagree, so closing a gap turns its row red until the entry is
//! changed to `Same`. `Absent` on a surface means the web form cannot express the request.
//! Every row also asserts its guarded side effect against the database on each surface.
//!
//! The web renders no reason text for a 403 or a 404, only the status, so for those the two
//! surfaces are compared by refusal class: `PermissionDenied` is 403, `NotFound` is 404 and
//! `InvalidArgument`, `FailedPrecondition` and `AlreadyExists` are 400. A 400 body carries the
//! message and is compared as text.
//!
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_core::Profile;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::admin::{AdminCommand, run as admin_run};
use fleet_server::cred::capability::{Capabilities, PROFILE_TOOLS};
use fleet_server::profiles::{ProfileContent, create_owned};
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tonic::Code;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(30);
const ORIGIN: &str = "https://fleet.example.com";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const CLIENT_TOKEN: &str = "client-token-0123456789abcdef012345";
const MARKER: &str = "secret-marker";
const ON: &str = "sk-a";
const SECOND: &str = "sk-b";
const GONE: &str = "sk-gone";
const BASE_JSON: &str = r#"{"claude_md":"secret-marker"}"#;
const OFF_JSON: &str =
    r#"{"claude_md":"secret-marker","selection":[{"item_id":"sk-a","enabled":false}]}"#;
const PROMPT: &str = "be brief";
const NEW_ITEM: &str = "new-one";
const NEW_BODY: &str = "fresh body";
const CHANGED_BODY: &str = "changed body";
const SEED_BODY: &str = "body";

const REQUIRED_OPERATIONS: &[&str] = &[
    "list",
    "show",
    "share",
    "unshare",
    "item-on",
    "item-off",
    "set-prompt",
    "catalog-list",
    "admin-upsert",
    "admin-disable",
    "grant",
    "revoke",
];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Forbidden,
    NotFound,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Done(Vec<String>),
    Refused(Refusal, String),
    Absent,
    Unexpected(String),
}

fn agree(cli: &Outcome, web: &Outcome) -> bool {
    match (cli, web) {
        (Outcome::Done(a), Outcome::Done(b)) => a == b,
        (Outcome::Refused(a, text), Outcome::Refused(b, shown)) => {
            a == b && (shown.is_empty() || text == shown)
        }
        _ => false,
    }
}

/// The kind of an outcome with its payload dropped, used to pin each side of a documented gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Done,
    Refused(Refusal),
    Absent,
}

fn shape(outcome: &Outcome) -> Option<Shape> {
    match outcome {
        Outcome::Done(_) => Some(Shape::Done),
        Outcome::Refused(kind, _) => Some(Shape::Refused(*kind)),
        Outcome::Absent => Some(Shape::Absent),
        Outcome::Unexpected(_) => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum Class {
    Same,
    Differs(&'static str, Shape, Shape),
}

struct Row {
    name: &'static str,
    op: &'static str,
    class: Class,
}

const D_UPSERT_EXISTING: &str = "the CLI upsert replaces the content of an existing id; the web add form refuses an existing id";
const D_UNKNOWN_ITEM: &str = "the CLI can name any item id and the server refuses an unknown one; the web form only offers catalog rows, so an unknown id cannot be sent";
const D_DISABLED_ITEM: &str = "the CLI can name an admin-disabled item; the web form renders it without a toggle so it cannot be switched";
const D_HOSTILE_PROMPT: &str =
    "both refuse a control character in the prompt, with different message text";
const D_UNKNOWN_CAP: &str = "both refuse the unknown capability as invalid, with different text";

const ROWS: &[Row] = &[
    Row {
        name: "list/owner",
        op: "list",
        class: Class::Same,
    },
    Row {
        name: "list/other",
        op: "list",
        class: Class::Same,
    },
    Row {
        name: "show/shared-by-other",
        op: "show",
        class: Class::Same,
    },
    Row {
        name: "show/private-of-other",
        op: "show",
        class: Class::Same,
    },
    Row {
        name: "share/owner",
        op: "share",
        class: Class::Same,
    },
    Row {
        name: "share/non-owner-shared",
        op: "share",
        class: Class::Same,
    },
    Row {
        name: "share/non-owner-private",
        op: "share",
        class: Class::Same,
    },
    Row {
        name: "unshare/owner",
        op: "unshare",
        class: Class::Same,
    },
    Row {
        name: "unshare/non-owner-shared",
        op: "unshare",
        class: Class::Same,
    },
    Row {
        name: "unshare/non-owner-private",
        op: "unshare",
        class: Class::Same,
    },
    Row {
        name: "item-off/owner",
        op: "item-off",
        class: Class::Same,
    },
    Row {
        name: "item-off/non-owner-shared",
        op: "item-off",
        class: Class::Same,
    },
    Row {
        name: "item-off/non-owner-private",
        op: "item-off",
        class: Class::Same,
    },
    Row {
        name: "item-off/unknown-item",
        op: "item-off",
        class: Class::Differs(
            D_UNKNOWN_ITEM,
            Shape::Refused(Refusal::Invalid),
            Shape::Absent,
        ),
    },
    Row {
        name: "item-off/admin-disabled",
        op: "item-off",
        class: Class::Differs(
            D_DISABLED_ITEM,
            Shape::Refused(Refusal::Invalid),
            Shape::Absent,
        ),
    },
    Row {
        name: "item-on/owner",
        op: "item-on",
        class: Class::Same,
    },
    Row {
        name: "item-on/no-change",
        op: "item-on",
        class: Class::Same,
    },
    Row {
        name: "set-prompt/owner",
        op: "set-prompt",
        class: Class::Same,
    },
    Row {
        name: "set-prompt/non-owner-shared",
        op: "set-prompt",
        class: Class::Same,
    },
    Row {
        name: "set-prompt/hostile",
        op: "set-prompt",
        class: Class::Differs(
            D_HOSTILE_PROMPT,
            Shape::Refused(Refusal::Invalid),
            Shape::Refused(Refusal::Invalid),
        ),
    },
    Row {
        name: "catalog-list/admin",
        op: "catalog-list",
        class: Class::Same,
    },
    Row {
        name: "catalog-list/non-admin",
        op: "catalog-list",
        class: Class::Same,
    },
    Row {
        name: "admin-upsert/admin",
        op: "admin-upsert",
        class: Class::Same,
    },
    Row {
        name: "admin-upsert/non-admin",
        op: "admin-upsert",
        class: Class::Same,
    },
    Row {
        name: "admin-upsert/existing-id",
        op: "admin-upsert",
        class: Class::Differs(
            D_UPSERT_EXISTING,
            Shape::Done,
            Shape::Refused(Refusal::Invalid),
        ),
    },
    Row {
        name: "admin-disable/admin",
        op: "admin-disable",
        class: Class::Same,
    },
    Row {
        name: "admin-disable/non-admin",
        op: "admin-disable",
        class: Class::Same,
    },
    Row {
        name: "admin-disable/unknown-item",
        op: "admin-disable",
        class: Class::Same,
    },
    Row {
        name: "grant/admin",
        op: "grant",
        class: Class::Same,
    },
    Row {
        name: "grant/non-admin",
        op: "grant",
        class: Class::Same,
    },
    Row {
        name: "grant/unknown-user",
        op: "grant",
        class: Class::Same,
    },
    Row {
        name: "grant/unknown-capability",
        op: "grant",
        class: Class::Differs(
            D_UNKNOWN_CAP,
            Shape::Refused(Refusal::Invalid),
            Shape::Refused(Refusal::Invalid),
        ),
    },
    Row {
        name: "revoke/admin",
        op: "revoke",
        class: Class::Same,
    },
    Row {
        name: "revoke/non-admin",
        op: "revoke",
        class: Class::Same,
    },
    Row {
        name: "revoke/unknown-user",
        op: "revoke",
        class: Class::Same,
    },
    Row {
        name: "revoke/unknown-capability",
        op: "revoke",
        class: Class::Differs(
            D_UNKNOWN_CAP,
            Shape::Refused(Refusal::Invalid),
            Shape::Refused(Refusal::Invalid),
        ),
    },
];

const REASON_NOT_OWNER: &str = "only the owner can change this profile";
const REASON_ADMIN_REQUIRED: &str = "admin required";
const REASON_NO_SUCH_USER: &str = "no such user";

/// The exact refusal the CLI must give on a row closed by the stricter policy.
fn pinned(name: &str) -> Option<(Refusal, &'static str)> {
    match name {
        "item-off/non-owner-shared" | "set-prompt/non-owner-shared" => {
            Some((Refusal::Forbidden, REASON_NOT_OWNER))
        }
        "catalog-list/non-admin" => Some((Refusal::Forbidden, REASON_ADMIN_REQUIRED)),
        "revoke/unknown-user" => Some((Refusal::NotFound, REASON_NO_SUCH_USER)),
        _ => None,
    }
}

type State = (Vec<String>, Option<String>);

struct Persona {
    id: i64,
    token: String,
    cookie: String,
    csrf: String,
}

struct Reply {
    status: u16,
    body: String,
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    users: Users,
    owner: Persona,
    other: Persona,
    admin: Persona,
}

fn enc(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

impl Rig {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_console(auth, None, store.clone());
        let bearer = BearerAuth::new(
            &Token::new(BOX_TOKEN.to_owned()).unwrap(),
            Some(&Token::new(CLIENT_TOKEN.to_owned()).unwrap()),
        )
        .with_users(users.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            serve_with_web(
                &store,
                &bearer,
                web,
                TcpIncoming::from(listener),
                std::future::pending::<()>(),
            )
            .await
        });
        let mut rig = Self {
            addr,
            pool: pool.clone(),
            users,
            owner: placeholder(),
            other: placeholder(),
            admin: placeholder(),
        };
        rig.owner = rig.persona("olive", 'a', false).await;
        rig.other = rig.persona("otto", 'b', false).await;
        rig.admin = rig.persona("ada", 'c', true).await;
        rig
    }

    async fn persona(&self, name: &str, seed: char, admin: bool) -> Persona {
        let id = admin_run(&self.pool, &AdminCommand::CreateUser(name.into()), "op")
            .await
            .unwrap()
            .user_id;
        if admin {
            self.users.set_admin(id, true).await.unwrap();
        }
        let token = self.users.create_api_token(id, "t").await.unwrap();
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

    async fn target(&self, surface: Surface) -> i64 {
        admin_run(
            &self.pool,
            &AdminCommand::CreateUser(format!("tara-{surface}")),
            "op",
        )
        .await
        .unwrap()
        .user_id
    }

    async fn cli(
        &self,
        who: &Persona,
        args: &[&str],
        stdin: &[u8],
    ) -> (Result<(), CliError>, String) {
        let url = format!("http://{}", self.addr);
        let mut full = vec!["fleet", "--server", url.as_str()];
        full.extend_from_slice(args);
        let parsed = Cli::try_parse_from(full).unwrap();
        let token = who.token.clone();
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
            body: body.to_owned(),
        }
    }

    async fn get(&self, who: &Persona, path: &str) -> Reply {
        self.http("GET", path, who, "").await
    }

    async fn post(&self, who: &Persona, path: &str, fields: &str) -> Reply {
        let body = if fields.is_empty() {
            format!("csrf={}", who.csrf)
        } else {
            format!("csrf={}&{fields}", who.csrf)
        };
        self.http("POST", path, who, &body).await
    }

    async fn profile(&self, owner: &Persona, name: &str, json: &str, shared: bool) -> i64 {
        create_owned(
            &self.pool,
            Some(owner.id),
            None,
            name,
            ProfileContent::Json(json),
        )
        .await
        .unwrap();
        sqlx::query_scalar(
            "UPDATE profile SET visibility = $3 WHERE owner_user_id = $1 AND name = $2 RETURNING id",
        )
        .bind(owner.id)
        .bind(name)
        .bind(if shared { "shared" } else { "private" })
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn item(&self, id: &str, enabled: bool) {
        sqlx::query(
            "INSERT INTO catalog_items (id, kind, name, content, digest, admin_enabled) \
             VALUES ($1, 'skill', $1, $3, sha256($2::bytea), $4) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(SEED_BODY.as_bytes())
        .bind(SEED_BODY)
        .bind(enabled)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn catalog(&self) {
        self.item(ON, true).await;
        self.item(SECOND, true).await;
        self.item(GONE, false).await;
    }

    async fn latest(&self, id: i64) -> (i32, State) {
        let (version, content): (i32, Vec<u8>) = sqlx::query_as(
            "SELECT v.version, b.content FROM profile p \
             JOIN profile_version v ON v.profile_id = p.id AND v.version = p.latest_version \
             JOIN profile_blob b ON b.hash = v.hash WHERE p.id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        let profile = Profile::from_stored_json(&content).unwrap();
        let off = profile
            .selection
            .ids()
            .map(|id| id.as_str().to_owned())
            .collect();
        let prompt = profile.authored_prompt.map(|text| text.as_str().to_owned());
        (version, (off, prompt))
    }

    async fn visibility(&self, id: i64) -> String {
        sqlx::query_scalar("SELECT visibility FROM profile WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn profile_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM profile")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn item_row(&self, id: &str) -> Option<(String, bool)> {
        sqlx::query_as("SELECT content, admin_enabled FROM catalog_items WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .unwrap()
    }

    async fn holds(&self, user: i64) -> bool {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_capabilities WHERE user_id = $1 AND capability = $2)",
        )
        .bind(user)
        .bind(PROFILE_TOOLS)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn enabled_items(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT id FROM catalog_items WHERE admin_enabled ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }
}

fn placeholder() -> Persona {
    Persona {
        id: 0,
        token: String::new(),
        cookie: String::new(),
        csrf: String::new(),
    }
}

fn cli_outcome(result: &Result<(), CliError>, observed: Vec<String>) -> Outcome {
    match result {
        Ok(()) => Outcome::Done(observed),
        Err(CliError::Rpc(status)) => {
            let kind = match status.code() {
                Code::PermissionDenied => Refusal::Forbidden,
                Code::NotFound => Refusal::NotFound,
                Code::InvalidArgument | Code::FailedPrecondition | Code::AlreadyExists => {
                    Refusal::Invalid
                }
                other => return Outcome::Unexpected(format!("{other:?}: {}", status.message())),
            };
            Outcome::Refused(kind, status.message().to_owned())
        }
        Err(CliError::Usage(text)) => Outcome::Refused(Refusal::Invalid, text.clone()),
        Err(other) => Outcome::Unexpected(other.to_string()),
    }
}

fn web_outcome(reply: &Reply, observed: Vec<String>) -> Outcome {
    match reply.status {
        200 | 303 => Outcome::Done(observed),
        403 => Outcome::Refused(Refusal::Forbidden, String::new()),
        404 => Outcome::Refused(Refusal::NotFound, String::new()),
        400 => Outcome::Refused(Refusal::Invalid, reply.body.trim().to_owned()),
        other => Outcome::Unexpected(format!("{other}: {}", reply.body)),
    }
}

fn between<'a>(text: &'a str, open: &str, close: char) -> Vec<&'a str> {
    text.split(open)
        .skip(1)
        .filter_map(|rest| rest.split(close).next())
        .collect()
}

fn web_profile_names(page: &str) -> Vec<String> {
    let mut names: Vec<String> = page
        .split("href=\"/profiles/")
        .skip(1)
        .filter_map(|rest| {
            let (_, tail) = rest.split_once("\">")?;
            Some(tail.split('<').next()?.to_owned())
        })
        .collect();
    names.sort();
    names
}

fn cli_first_column(out: &str) -> Vec<String> {
    let mut names: Vec<String> = out
        .lines()
        .filter_map(|line| line.split('\t').next())
        .map(ToOwned::to_owned)
        .collect();
    names.sort();
    names
}

fn named(base: &str, surface: Surface) -> String {
    format!("{base}-{surface}")
}

async fn list_row(rig: &Rig, surface: Surface, as_owner: bool) -> Outcome {
    rig.catalog().await;
    rig.profile(&rig.owner, "hidden", BASE_JSON, false).await;
    rig.profile(&rig.owner, "open", BASE_JSON, true).await;
    rig.profile(&rig.other, "otto-own", BASE_JSON, false).await;
    let who = if as_owner { &rig.owner } else { &rig.other };
    let (result, names) = match surface {
        Surface::Cli => {
            let (result, out) = rig.cli(who, &["profile", "list"], b"").await;
            (cli_outcome(&result, Vec::new()), cli_first_column(&out))
        }
        Surface::Web => {
            let reply = rig.get(who, "/profiles").await;
            (
                web_outcome(&reply, Vec::new()),
                web_profile_names(&reply.body),
            )
        }
    };
    let expected: Vec<&str> = if as_owner {
        vec!["hidden", "open"]
    } else {
        vec!["open", "otto-own"]
    };
    assert_eq!(names, expected, "{surface}");
    assert_eq!(names.iter().any(|name| name == "hidden"), as_owner);
    match result {
        Outcome::Done(_) => Outcome::Done(names),
        other => other,
    }
}

async fn show_row(rig: &Rig, surface: Surface, shared: bool) -> Outcome {
    let id = rig
        .profile(&rig.owner, &named("prof", surface), BASE_JSON, shared)
        .await;
    let (outcome, text) = match surface {
        Surface::Cli => {
            let (result, out) = rig
                .cli(
                    &rig.other,
                    &["profile", "show", &named("prof", surface)],
                    b"",
                )
                .await;
            (cli_outcome(&result, Vec::new()), out)
        }
        Surface::Web => {
            let reply = rig.get(&rig.other, &format!("/profiles/{id}")).await;
            (web_outcome(&reply, Vec::new()), reply.body)
        }
    };
    assert_eq!(
        text.contains(MARKER),
        shared,
        "{surface} content leak: {text}"
    );
    outcome
}

async fn visibility_row(
    rig: &Rig,
    surface: Surface,
    as_owner: bool,
    start_shared: bool,
    share: bool,
) -> Outcome {
    let name = named("prof", surface);
    let id = rig
        .profile(&rig.owner, &name, BASE_JSON, start_shared)
        .await;
    let who = if as_owner { &rig.owner } else { &rig.other };
    let outcome = match surface {
        Surface::Cli => {
            let verb = if share { "share" } else { "unshare" };
            let (result, _) = rig.cli(who, &["profile", verb, &name], b"").await;
            cli_outcome(&result, Vec::new())
        }
        Surface::Web => {
            let verb = if share { "share" } else { "unshare" };
            let reply = rig.post(who, &format!("/profiles/{id}/{verb}"), "").await;
            web_outcome(&reply, Vec::new())
        }
    };
    let want_shared = if matches!(outcome, Outcome::Done(_)) {
        share
    } else {
        start_shared
    };
    assert_eq!(
        rig.visibility(id).await,
        if want_shared { "shared" } else { "private" },
        "{surface} {outcome:?}"
    );
    outcome
}

#[derive(Clone, Copy)]
enum Edit {
    ItemOff(&'static str),
    ItemOn(&'static str),
    Prompt(&'static str),
}

impl Edit {
    fn expected(self) -> (Vec<String>, Option<&'static str>) {
        match self {
            Self::ItemOff(id) => (vec![id.to_owned()], None),
            Self::ItemOn(_) => (Vec::new(), None),
            Self::Prompt(text) => (Vec::new(), Some(text)),
        }
    }
}

async fn web_edit(rig: &Rig, who: &Persona, id: i64, off: &[&str], prompt: &str) -> Reply {
    let mut fields = String::new();
    for item in rig.enabled_items().await {
        if !off.contains(&item.as_str()) {
            let _ = write!(fields, "on_{item}=1&");
        }
    }
    let _ = write!(fields, "prompt={}", enc(prompt));
    rig.post(who, &format!("/profiles/{id}/selection"), &fields)
        .await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plain,
    Hostile,
    WebAbsent,
}

struct EditCase {
    as_owner: bool,
    shared: bool,
    start: &'static str,
    edit: Edit,
    mode: Mode,
}

async fn edit_row(rig: &Rig, surface: Surface, case: EditCase) -> Outcome {
    rig.catalog().await;
    let name = named("prof", surface);
    let id = rig
        .profile(&rig.owner, &name, case.start, case.shared)
        .await;
    let before = rig.latest(id).await;
    let count = rig.profile_count().await;
    let who = if case.as_owner {
        &rig.owner
    } else {
        &rig.other
    };
    let start_off = before.1.0.clone();
    let outcome = match surface {
        Surface::Cli => {
            let (result, _) = match case.edit {
                Edit::ItemOff(item) => {
                    rig.cli(who, &["profile", "item", &name, "skill", item, "off"], b"")
                        .await
                }
                Edit::ItemOn(item) => {
                    rig.cli(who, &["profile", "item", &name, "skill", item, "on"], b"")
                        .await
                }
                Edit::Prompt(text) => {
                    let text = if case.mode == Mode::Hostile {
                        "a\rb"
                    } else {
                        text
                    };
                    rig.cli(
                        who,
                        &["profile", "prompt", &name, "--file", "-"],
                        text.as_bytes(),
                    )
                    .await
                }
            };
            cli_outcome(&result, Vec::new())
        }
        Surface::Web if case.mode == Mode::WebAbsent => Outcome::Absent,
        Surface::Web => {
            let reply = match case.edit {
                Edit::ItemOff(item) => {
                    let mut off: Vec<&str> = start_off.iter().map(String::as_str).collect();
                    off.push(item);
                    web_edit(rig, who, id, &off, "").await
                }
                Edit::ItemOn(item) => {
                    let off: Vec<&str> = start_off
                        .iter()
                        .map(String::as_str)
                        .filter(|kept| *kept != item)
                        .collect();
                    web_edit(rig, who, id, &off, "").await
                }
                Edit::Prompt(text) => {
                    let text = if case.mode == Mode::Hostile {
                        "a\rb"
                    } else {
                        text
                    };
                    let off: Vec<&str> = start_off.iter().map(String::as_str).collect();
                    web_edit(rig, who, id, &off, text).await
                }
            };
            web_outcome(&reply, Vec::new())
        }
    };
    let after = rig.latest(id).await;
    effect(rig, surface, &case, (&before, &after), count, &outcome).await;
    outcome
}

async fn effect(
    rig: &Rig,
    surface: Surface,
    case: &EditCase,
    (before, after): (&(i32, State), &(i32, State)),
    count: i64,
    outcome: &Outcome,
) {
    if case.as_owner && matches!(outcome, Outcome::Done(_)) {
        let (mut off, prompt) = case.edit.expected();
        if let Edit::ItemOff(_) = case.edit {
            off.extend(before.1.0.iter().cloned());
            off.sort();
        }
        let unchanged =
            matches!(case.edit, Edit::ItemOn(id) if !before.1.0.iter().any(|kept| kept == id));
        if unchanged {
            assert_eq!(after, before, "{surface} no-op changed the profile");
        } else {
            assert_eq!(after.0, before.0 + 1, "{surface}");
            assert_eq!(after.1.0, off, "{surface}");
            assert_eq!(after.1.1.as_deref(), prompt, "{surface}");
        }
    } else {
        assert_eq!(
            after, before,
            "{surface} wrote to the owner's profile: {outcome:?}"
        );
        if !case.as_owner {
            assert!(
                matches!(outcome, Outcome::Refused(..)),
                "{surface} {outcome:?}"
            );
            assert_eq!(rig.profile_count().await, count, "{surface} forked a copy");
        }
    }
}

async fn catalog_list_row(rig: &Rig, surface: Surface, as_admin: bool) -> Outcome {
    rig.catalog().await;
    let who = if as_admin { &rig.admin } else { &rig.other };
    match surface {
        Surface::Cli => {
            let (result, out) = rig.cli(who, &["catalog", "list"], b"").await;
            let ids = cli_first_column(&out);
            if as_admin {
                assert_eq!(ids, [ON, SECOND, GONE], "every item");
            } else {
                assert!(ids.is_empty(), "{ids:?}");
            }
            cli_outcome(&result, ids)
        }
        Surface::Web => {
            let reply = rig.get(who, "/catalog").await;
            let mut ids: Vec<String> = between(&reply.body, "href=\"/catalog/", '"')
                .into_iter()
                .map(ToOwned::to_owned)
                .collect();
            ids.sort();
            ids.dedup();
            if as_admin {
                assert_eq!(ids, [ON, SECOND, GONE], "every item");
            } else {
                assert!(ids.is_empty(), "{ids:?}");
            }
            web_outcome(&reply, ids)
        }
    }
}

async fn upsert_row(rig: &Rig, surface: Surface, as_admin: bool, existing: bool) -> Outcome {
    let id = named(if existing { "sk-up" } else { NEW_ITEM }, surface);
    let id = id.as_str();
    if existing {
        rig.item(id, true).await;
    }
    let who = if as_admin { &rig.admin } else { &rig.other };
    let body = if existing { CHANGED_BODY } else { NEW_BODY };
    let outcome = match surface {
        Surface::Cli => {
            let (result, _) = rig
                .cli(
                    who,
                    &["catalog", "upsert", "skill", id, id, "--file", "-"],
                    body.as_bytes(),
                )
                .await;
            cli_outcome(&result, Vec::new())
        }
        Surface::Web => {
            let fields = format!(
                "kind=skill&id={}&name={}&content={}",
                enc(id),
                enc(id),
                enc(body)
            );
            web_outcome(&rig.post(who, "/catalog", &fields).await, Vec::new())
        }
    };
    let stored = rig.item_row(id).await;
    match (&outcome, existing) {
        (Outcome::Done(_), _) => assert_eq!(stored.unwrap().0, body, "{surface}"),
        (_, true) => assert_eq!(stored.unwrap().0, SEED_BODY, "{surface}"),
        (_, false) => assert_eq!(stored, None, "{surface}"),
    }
    outcome
}

async fn disable_row(rig: &Rig, surface: Surface, as_admin: bool, known: bool) -> Outcome {
    let id = named("sk", surface);
    rig.item(&id, true).await;
    let who = if as_admin { &rig.admin } else { &rig.other };
    let target = if known { id.as_str() } else { "no-such" };
    let outcome = match surface {
        Surface::Cli => {
            let (result, _) = rig.cli(who, &["catalog", "disable", target], b"").await;
            cli_outcome(&result, Vec::new())
        }
        Surface::Web => {
            let reply = rig
                .post(who, &format!("/catalog/{target}/disable"), "")
                .await;
            web_outcome(&reply, Vec::new())
        }
    };
    let enabled = matches!(outcome, Outcome::Refused(..));
    assert_eq!(
        rig.item_row(&id).await.unwrap().1,
        enabled,
        "{surface} {outcome:?}"
    );
    assert_eq!(rig.item_row("no-such").await, None, "{surface}");
    outcome
}

enum Subject {
    Known,
    Unknown,
    NoCapability,
}

async fn capability_row(
    rig: &Rig,
    surface: Surface,
    grant: bool,
    as_admin: bool,
    subject: Subject,
) -> Outcome {
    let user = match subject {
        Subject::Unknown => 999_999,
        _ => rig.target(surface).await,
    };
    if !grant && !matches!(subject, Subject::Unknown) {
        Capabilities::new(rig.pool.clone())
            .grant(rig.admin.id, user, PROFILE_TOOLS)
            .await
            .unwrap();
    }
    let who = if as_admin { &rig.admin } else { &rig.other };
    let capability = if matches!(subject, Subject::NoCapability) {
        "profile:nothing"
    } else {
        PROFILE_TOOLS
    };
    let outcome = match surface {
        Surface::Cli => {
            let verb = if grant { "grant" } else { "revoke" };
            let id = user.to_string();
            let (result, _) = rig
                .cli(who, &["user", "cap", verb, &id, capability], b"")
                .await;
            cli_outcome(&result, Vec::new())
        }
        Surface::Web => {
            let verb = if grant { "grant" } else { "revoke" };
            let reply = rig
                .post(
                    who,
                    &format!("/users/{user}/capabilities"),
                    &format!(
                        "action={verb}&capability={}",
                        capability.replace(':', "%3A")
                    ),
                )
                .await;
            web_outcome(&reply, Vec::new())
        }
    };
    let want = if matches!(outcome, Outcome::Done(_)) {
        grant
    } else {
        !grant
    };
    let held = rig.holds(user).await;
    assert_eq!(
        held,
        want && !matches!(subject, Subject::Unknown),
        "{surface} {outcome:?}"
    );
    outcome
}

fn row(name: &str) -> &'static Row {
    ROWS.iter().find(|row| row.name == name).unwrap()
}

async fn judge<F>(name: &str, pool: PgPool, run_row: F)
where
    F: AsyncFn(&Rig, Surface) -> Outcome,
{
    let row = row(name);
    let rig = Box::pin(Rig::start(pool)).await;
    let cli = run_row(&rig, Surface::Cli).await;
    let web = run_row(&rig, Surface::Web).await;
    assert!(
        shape(&cli).is_some() && shape(&web).is_some(),
        "{name}: unexpected outcome: cli {cli:?} web {web:?}"
    );
    match row.class {
        Class::Same => {
            assert!(agree(&cli, &web), "{name}: cli {cli:?} web {web:?}");
            if let Some((kind, reason)) = pinned(name) {
                assert_eq!(
                    cli,
                    Outcome::Refused(kind, reason.to_owned()),
                    "{name}: cli reason"
                );
            }
        }
        Class::Differs(why, want_cli, want_web) => {
            assert!(
                !agree(&cli, &web),
                "{name}: gap closed ({why}): cli {cli:?} web {web:?}"
            );
            assert_eq!(
                (shape(&cli), shape(&web)),
                (Some(want_cli), Some(want_web)),
                "{name}: gap changed ({why}): cli {cli:?} web {web:?}"
            );
        }
    }
}

macro_rules! rows {
    ($($test:ident: $name:literal => $body:expr;)*) => {
        const TESTED: &[&str] = &[$($name),*];
        $(
            #[sqlx::test]
            async fn $test(pool: PgPool) {
                judge($name, pool, $body).await;
            }
        )*
    };
}

fn edit(as_owner: bool, shared: bool, start: &'static str, edit: Edit) -> EditCase {
    EditCase {
        as_owner,
        shared,
        start,
        edit,
        mode: Mode::Plain,
    }
}

rows! {
    list_owner: "list/owner" => async |r, s| list_row(r, s, true).await;
    list_other: "list/other" => async |r, s| list_row(r, s, false).await;
    show_shared: "show/shared-by-other" => async |r, s| show_row(r, s, true).await;
    show_private: "show/private-of-other" => async |r, s| show_row(r, s, false).await;
    share_owner: "share/owner" => async |r, s| visibility_row(r, s, true, false, true).await;
    share_foreign_shared: "share/non-owner-shared" => async |r, s| visibility_row(r, s, false, true, true).await;
    share_foreign_private: "share/non-owner-private" => async |r, s| visibility_row(r, s, false, false, true).await;
    unshare_owner: "unshare/owner" => async |r, s| visibility_row(r, s, true, true, false).await;
    unshare_foreign_shared: "unshare/non-owner-shared" => async |r, s| visibility_row(r, s, false, true, false).await;
    unshare_foreign_private: "unshare/non-owner-private" => async |r, s| visibility_row(r, s, false, false, false).await;
    off_owner: "item-off/owner" => async |r, s| edit_row(r, s, edit(true, false, BASE_JSON, Edit::ItemOff(ON))).await;
    off_foreign_shared: "item-off/non-owner-shared" => async |r, s| edit_row(r, s, edit(false, true, BASE_JSON, Edit::ItemOff(ON))).await;
    off_foreign_private: "item-off/non-owner-private" => async |r, s| edit_row(r, s, edit(false, false, BASE_JSON, Edit::ItemOff(ON))).await;
    off_unknown: "item-off/unknown-item" => async |r, s| edit_row(r, s, EditCase { mode: Mode::WebAbsent, ..edit(true, false, BASE_JSON, Edit::ItemOff("nope")) }).await;
    off_disabled: "item-off/admin-disabled" => async |r, s| edit_row(r, s, EditCase { mode: Mode::WebAbsent, ..edit(true, false, BASE_JSON, Edit::ItemOff(GONE)) }).await;
    on_owner: "item-on/owner" => async |r, s| edit_row(r, s, edit(true, false, OFF_JSON, Edit::ItemOn(ON))).await;
    on_no_change: "item-on/no-change" => async |r, s| edit_row(r, s, edit(true, false, BASE_JSON, Edit::ItemOn(ON))).await;
    prompt_owner: "set-prompt/owner" => async |r, s| edit_row(r, s, edit(true, false, BASE_JSON, Edit::Prompt(PROMPT))).await;
    prompt_foreign_shared: "set-prompt/non-owner-shared" => async |r, s| edit_row(r, s, edit(false, true, BASE_JSON, Edit::Prompt(PROMPT))).await;
    prompt_hostile: "set-prompt/hostile" => async |r, s| edit_row(r, s, EditCase { mode: Mode::Hostile, ..edit(true, false, BASE_JSON, Edit::Prompt(PROMPT)) }).await;
    catalog_admin: "catalog-list/admin" => async |r, s| catalog_list_row(r, s, true).await;
    catalog_other: "catalog-list/non-admin" => async |r, s| catalog_list_row(r, s, false).await;
    upsert_admin: "admin-upsert/admin" => async |r, s| upsert_row(r, s, true, false).await;
    upsert_other: "admin-upsert/non-admin" => async |r, s| upsert_row(r, s, false, false).await;
    upsert_existing: "admin-upsert/existing-id" => async |r, s| upsert_row(r, s, true, true).await;
    disable_admin: "admin-disable/admin" => async |r, s| disable_row(r, s, true, true).await;
    disable_other: "admin-disable/non-admin" => async |r, s| disable_row(r, s, false, true).await;
    disable_unknown: "admin-disable/unknown-item" => async |r, s| disable_row(r, s, true, false).await;
    grant_admin: "grant/admin" => async |r, s| capability_row(r, s, true, true, Subject::Known).await;
    grant_other: "grant/non-admin" => async |r, s| capability_row(r, s, true, false, Subject::Known).await;
    grant_unknown_user: "grant/unknown-user" => async |r, s| capability_row(r, s, true, true, Subject::Unknown).await;
    grant_unknown_cap: "grant/unknown-capability" => async |r, s| capability_row(r, s, true, true, Subject::NoCapability).await;
    revoke_admin: "revoke/admin" => async |r, s| capability_row(r, s, false, true, Subject::Known).await;
    revoke_other: "revoke/non-admin" => async |r, s| capability_row(r, s, false, false, Subject::Known).await;
    revoke_unknown_user: "revoke/unknown-user" => async |r, s| capability_row(r, s, false, true, Subject::Unknown).await;
    revoke_unknown_cap: "revoke/unknown-capability" => async |r, s| capability_row(r, s, false, true, Subject::NoCapability).await;
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
        if let Class::Differs(why, ..) = row.class {
            assert!(!why.is_empty(), "{}", row.name);
        }
    }
}

#[test]
fn agreement_compares_the_class_and_the_text() {
    let refused = |kind, text: &str| Outcome::Refused(kind, text.to_owned());
    assert!(agree(
        &refused(Refusal::Forbidden, "x"),
        &refused(Refusal::Forbidden, "")
    ));
    assert!(agree(
        &refused(Refusal::Invalid, "x"),
        &refused(Refusal::Invalid, "x")
    ));
    assert!(!agree(
        &refused(Refusal::Invalid, "x"),
        &refused(Refusal::Invalid, "y")
    ));
    assert!(!agree(
        &refused(Refusal::Forbidden, ""),
        &refused(Refusal::NotFound, "")
    ));
    assert!(!agree(
        &Outcome::Done(Vec::new()),
        &refused(Refusal::Forbidden, "")
    ));
    assert!(!agree(&Outcome::Absent, &Outcome::Absent));
    assert!(!agree(
        &Outcome::Done(vec!["a".to_owned()]),
        &Outcome::Done(Vec::new())
    ));
}
