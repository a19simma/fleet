//! Parity of Environments between the `fleet` CLI (gRPC) and the web console, both served by
//! one in-process server on Postgres (ADR-0067).
//!
//! `SCENARIOS` is the operation table: one row per operation and case, each with one class.
//! `Same` means both surfaces end in the same outcome: both done with the same stored state,
//! or both refused with the same status class (and, for the CLI, the fixed refusal text).
//! `SameStored` is `Same` on what is stored, with a named difference in the version structure.
//! `Gap` names a surface that cannot express the request and pins the shape of each side, so
//! the row turns red when a gap closes. A web `Absent` row posts to the route that would carry
//! the request and requires a 404 or 405 and an unchanged database.
//!
//! The web renders a status and a notice code for a refusal, not the service text, so the
//! surfaces are compared by status class: `NotFound` is a 404 or the `missing` notice,
//! `InvalidArgument` the `invalid` notice, `AlreadyExists` the `exists` notice. The foreign-name
//! rows seed the name on another user and require the same answer as an unknown name.
//!
//! The tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary
//! because they bind a socket.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code asserts by panicking and indexes parsed fixtures"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::environment_binding_key::Key;
use fleet_proto::v1::environment_entry_spec::Kind;
use fleet_proto::v1::{
    CreateEnvironmentRequest, EnvironmentBindingKey, EnvironmentEntrySpec, EnvironmentOnFail,
    EnvironmentRepoKey, EnvironmentScriptSpec, EnvironmentSecretSpec, GetEnvironmentDefaultRequest,
    GetEnvironmentRequest, PutEnvironmentSecretRequest, SaveEnvironmentVersionRequest,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{EnvironmentService, EnvironmentStore};
use fleet_server::service::{UpdateRelay, serve_with_environments};
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
const VALUE: &str = "pve-token-Zk93abQ7xw";
const SHEBANG: &str = "#!/bin/sh\necho a\n";
const REPO: &str = "github.com/octo/hello";

static FILES: AtomicUsize = AtomicUsize::new(0);

const REQUIRED_OPERATIONS: &[&str] = &[
    "create",
    "list",
    "show",
    "put-secret",
    "delete-secret",
    "add-script",
    "remove-script",
    "delete-env",
    "set-default",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Done,
    Refused(Code),
    Absent,
}

#[derive(Debug, Clone, Copy)]
enum Class {
    Same,
    SameStored(&'static str),
    Gap(&'static str, Shape, Shape),
}

#[derive(Clone, Copy)]
enum Seed {
    Env(&'static str),
    Secret(&'static str, &'static str),
    Script(&'static str, &'static str),
    Repo,
}

#[derive(Clone, Copy)]
enum CliAct {
    Run(&'static [&'static str], &'static str),
    Absent(&'static [&'static str]),
}

#[derive(Clone, Copy)]
enum WebAct {
    Get(&'static str),
    Post(&'static str, &'static str),
    Absent(&'static str, &'static str),
}

struct Scenario {
    name: &'static str,
    op: &'static str,
    seed: &'static [Seed],
    cap: bool,
    foreign: bool,
    cli: CliAct,
    web: WebAct,
    class: Class,
    shape: Shape,
    cli_text: Option<&'static str>,
    listing: Option<&'static [(&'static str, &'static str)]>,
    show: bool,
    cli_has: &'static [&'static str],
    web_has: &'static [&'static str],
}

const BASE: Scenario = Scenario {
    name: "",
    op: "",
    seed: &[],
    cap: true,
    foreign: false,
    cli: CliAct::Run(&[], ""),
    web: WebAct::Get("/environments"),
    class: Class::Same,
    shape: Shape::Done,
    cli_text: None,
    listing: None,
    show: false,
    cli_has: &[],
    web_has: &[],
};

const G_NO_WEB_SCRIPTS: &str =
    "the web pages show scripts but have no form to add or remove one; only the CLI edits them";
const G_NO_WEB_DEFAULT: &str =
    "the web pages have no form to bind a default; only the CLI sets, shows and clears one";
const G_NO_CLI_SECRET_RM: &str =
    "the CLI has no command to delete a stored secret; only the web page deletes one";

const MISSING: Shape = Shape::Refused(Code::NotFound);

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "create/ok",
        op: "create",
        cli: CliAct::Run(&["env", "create", "build"], ""),
        web: WebAct::Post("/environments/create", "name=build"),
        ..BASE
    },
    Scenario {
        name: "create/refused/exists",
        op: "create",
        seed: &[Seed::Env("build")],
        cli: CliAct::Run(&["env", "create", "build"], ""),
        web: WebAct::Post("/environments/create", "name=build"),
        shape: Shape::Refused(Code::AlreadyExists),
        cli_text: Some(fleet_proto::ERR_ENV_EXISTS),
        ..BASE
    },
    Scenario {
        name: "create/refused/bad_name",
        op: "create",
        cli: CliAct::Run(&["env", "create", "-x"], ""),
        web: WebAct::Post("/environments/create", "name=-x"),
        shape: Shape::Refused(Code::InvalidArgument),
        ..BASE
    },
    Scenario {
        name: "list/empty",
        op: "list",
        cli: CliAct::Run(&["env", "list"], ""),
        web: WebAct::Get("/environments"),
        listing: Some(&[]),
        ..BASE
    },
    Scenario {
        name: "list/rows",
        op: "list",
        seed: &[Seed::Env("alpha"), Seed::Secret("beta", "TOKEN")],
        cli: CliAct::Run(&["env", "list"], ""),
        web: WebAct::Get("/environments"),
        listing: Some(&[("alpha", "-"), ("beta", "1")]),
        ..BASE
    },
    Scenario {
        name: "show/ok",
        op: "show",
        seed: &[Seed::Secret("build", "TOKEN")],
        cli: CliAct::Run(&["env", "show", "build"], ""),
        web: WebAct::Get("/environments/build"),
        show: true,
        ..BASE
    },
    Scenario {
        name: "show/refused/foreign_name",
        op: "show",
        seed: &[Seed::Secret("build", "TOKEN")],
        foreign: true,
        cli: CliAct::Run(&["env", "show", "build"], ""),
        web: WebAct::Get("/environments/build"),
        shape: MISSING,
        cli_text: Some(fleet_proto::ERR_ENV_NOT_FOUND),
        ..BASE
    },
    Scenario {
        name: "show/refused/unknown_name",
        op: "show",
        cli: CliAct::Run(&["env", "show", "build"], ""),
        web: WebAct::Get("/environments/build"),
        shape: MISSING,
        cli_text: Some(fleet_proto::ERR_ENV_NOT_FOUND),
        ..BASE
    },
    Scenario {
        name: "show/ok/scripts_without_capability",
        op: "show",
        seed: &[Seed::Script("build", "setup")],
        cap: false,
        cli: CliAct::Run(&["env", "show", "build"], ""),
        web: WebAct::Get("/environments/build"),
        cli_has: &["entry\tscript\tsetup\t"],
        web_has: &["You do not hold env:scripts"],
        ..BASE
    },
    Scenario {
        name: "put-secret/ok",
        op: "put-secret",
        seed: &[Seed::Env("build")],
        cli: CliAct::Run(&["env", "secret", "put", "build", "TOKEN", "-"], VALUE),
        web: WebAct::Post(
            "/environments/build/secrets/put",
            "name=TOKEN&value=pve-token-Zk93abQ7xw",
        ),
        class: Class::SameStored(
            "the CLI also saves a version that declares the secret; the web page only stores the value",
        ),
        ..BASE
    },
    Scenario {
        name: "put-secret/refused/value_too_short",
        op: "put-secret",
        seed: &[Seed::Env("build")],
        cli: CliAct::Run(&["env", "secret", "put", "build", "TOKEN", "-"], "abc"),
        web: WebAct::Post("/environments/build/secrets/put", "name=TOKEN&value=abc"),
        shape: Shape::Refused(Code::InvalidArgument),
        ..BASE
    },
    Scenario {
        name: "put-secret/refused/foreign_name",
        op: "put-secret",
        seed: &[Seed::Env("build")],
        foreign: true,
        cli: CliAct::Run(&["env", "secret", "put", "build", "TOKEN", "-"], VALUE),
        web: WebAct::Post(
            "/environments/build/secrets/put",
            "name=TOKEN&value=pve-token-Zk93abQ7xw",
        ),
        shape: MISSING,
        cli_text: Some(fleet_proto::ERR_ENV_NOT_FOUND),
        ..BASE
    },
    Scenario {
        name: "delete-secret/ok",
        op: "delete-secret",
        seed: &[Seed::Secret("build", "TOKEN")],
        cli: CliAct::Absent(&["env", "secret", "rm", "build", "TOKEN"]),
        web: WebAct::Post("/environments/build/secrets/delete", "name=TOKEN"),
        class: Class::Gap(G_NO_CLI_SECRET_RM, Shape::Absent, Shape::Done),
        ..BASE
    },
    Scenario {
        name: "delete-secret/refused/unknown_secret",
        op: "delete-secret",
        seed: &[Seed::Env("build")],
        cli: CliAct::Absent(&["env", "secret", "rm", "build", "TOKEN"]),
        web: WebAct::Post("/environments/build/secrets/delete", "name=TOKEN"),
        class: Class::Gap(G_NO_CLI_SECRET_RM, Shape::Absent, MISSING),
        shape: MISSING,
        ..BASE
    },
    Scenario {
        name: "delete-secret/refused/foreign_name",
        op: "delete-secret",
        seed: &[Seed::Secret("build", "TOKEN")],
        foreign: true,
        cli: CliAct::Absent(&["env", "secret", "rm", "build", "TOKEN"]),
        web: WebAct::Post("/environments/build/secrets/delete", "name=TOKEN"),
        class: Class::Gap(G_NO_CLI_SECRET_RM, Shape::Absent, MISSING),
        shape: MISSING,
        ..BASE
    },
    Scenario {
        name: "add-script/ok",
        op: "add-script",
        seed: &[Seed::Env("build")],
        cli: CliAct::Run(&["env", "script", "add", "build", "setup", "-"], SHEBANG),
        web: WebAct::Absent("/environments/build/scripts/add", "name=setup"),
        class: Class::Gap(G_NO_WEB_SCRIPTS, Shape::Done, Shape::Absent),
        ..BASE
    },
    Scenario {
        name: "add-script/refused/capability",
        op: "add-script",
        seed: &[Seed::Env("build")],
        cap: false,
        cli: CliAct::Run(&["env", "script", "add", "build", "setup", "-"], SHEBANG),
        web: WebAct::Absent("/environments/build/scripts/add", "name=setup"),
        class: Class::Gap(
            G_NO_WEB_SCRIPTS,
            Shape::Refused(Code::PermissionDenied),
            Shape::Absent,
        ),
        shape: Shape::Refused(Code::PermissionDenied),
        cli_text: Some(fleet_proto::ERR_ENV_SCRIPTS_NOT_GRANTED),
        ..BASE
    },
    Scenario {
        name: "remove-script/ok",
        op: "remove-script",
        seed: &[Seed::Script("build", "setup")],
        cli: CliAct::Run(&["env", "script", "rm", "build", "setup"], ""),
        web: WebAct::Absent("/environments/build/scripts/delete", "name=setup"),
        class: Class::Gap(G_NO_WEB_SCRIPTS, Shape::Done, Shape::Absent),
        ..BASE
    },
    Scenario {
        name: "delete-env/ok",
        op: "delete-env",
        seed: &[Seed::Secret("build", "TOKEN")],
        cli: CliAct::Run(&["env", "rm", "build"], ""),
        web: WebAct::Post("/environments/build/delete", ""),
        ..BASE
    },
    Scenario {
        name: "delete-env/refused/foreign_name",
        op: "delete-env",
        seed: &[Seed::Secret("build", "TOKEN")],
        foreign: true,
        cli: CliAct::Run(&["env", "rm", "build"], ""),
        web: WebAct::Post("/environments/build/delete", ""),
        shape: MISSING,
        cli_text: Some(fleet_proto::ERR_ENV_NOT_FOUND),
        ..BASE
    },
    Scenario {
        name: "delete-env/refused/unknown_name",
        op: "delete-env",
        cli: CliAct::Run(&["env", "rm", "build"], ""),
        web: WebAct::Post("/environments/build/delete", ""),
        shape: MISSING,
        cli_text: Some(fleet_proto::ERR_ENV_NOT_FOUND),
        ..BASE
    },
    Scenario {
        name: "set-default/ok",
        op: "set-default",
        seed: &[Seed::Env("build"), Seed::Repo],
        cli: CliAct::Run(&["env", "default", "set", "build", "--repo", REPO], ""),
        web: WebAct::Absent(
            "/environments/build/default",
            "repo=github.com%2Focto%2Fhello",
        ),
        class: Class::Gap(G_NO_WEB_DEFAULT, Shape::Done, Shape::Absent),
        ..BASE
    },
    Scenario {
        name: "set-default/refused/foreign_name",
        op: "set-default",
        seed: &[Seed::Env("build"), Seed::Repo],
        foreign: true,
        cli: CliAct::Run(&["env", "default", "set", "build", "--repo", REPO], ""),
        web: WebAct::Absent(
            "/environments/build/default",
            "repo=github.com%2Focto%2Fhello",
        ),
        class: Class::Gap(G_NO_WEB_DEFAULT, MISSING, Shape::Absent),
        shape: MISSING,
        cli_text: Some(fleet_proto::ERR_ENV_NOT_FOUND),
        ..BASE
    },
];

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
    service: EnvironmentService,
}

impl Rig {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let path = std::env::temp_dir().join(format!(
            "fleet-parity-env-{}-{}.keys",
            std::process::id(),
            FILES.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
        let sealer = FileSealer::load(&path);
        std::fs::remove_file(&path).unwrap();
        let service = EnvironmentService::new(EnvironmentStore::new(
            pool.clone(),
            Arc::new(sealer.unwrap()),
        ));
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_environments(auth, None, Some(service.clone()), store.clone());
        let bearer = BearerAuth::new(
            &Token::new(BOX_TOKEN.to_owned()).unwrap(),
            Some(&Token::new(CLIENT_TOKEN.to_owned()).unwrap()),
        )
        .with_users(users);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = service.clone();
        tokio::spawn(async move {
            serve_with_environments(
                &store,
                &bearer,
                web,
                None,
                Some(served),
                UpdateRelay::default(),
                TcpIncoming::from(listener),
                std::future::pending::<()>(),
            )
            .await
        });
        Self {
            addr,
            pool,
            service,
        }
    }

    async fn persona(&self, name: &str, seed: char, cap: bool) -> Persona {
        let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        if cap {
            self.grant(id).await;
        }
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

    async fn grant(&self, user: i64) {
        sqlx::query(
            "INSERT INTO user_capabilities (user_id, capability, granted_by) \
             VALUES ($1, 'env:scripts', $1) ON CONFLICT DO NOTHING",
        )
        .bind(user)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn revoke(&self, user: i64) {
        sqlx::query(
            "DELETE FROM user_capabilities WHERE user_id = $1 AND capability = 'env:scripts'",
        )
        .bind(user)
        .execute(&self.pool)
        .await
        .unwrap();
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
        let body = if fields.is_empty() {
            format!("csrf={}", who.csrf)
        } else {
            format!("csrf={}&{fields}", who.csrf)
        };
        self.http("POST", path, who, &body).await
    }

    async fn seed(&self, user: i64, steps: &[Seed], cap: bool) {
        let mut entries: Vec<(&str, Vec<EnvironmentEntrySpec>)> = Vec::new();
        let mut wanted_scripts = false;
        for step in steps {
            let (env, entry) = match *step {
                Seed::Env(env) => (env, None),
                Seed::Secret(env, name) => (
                    env,
                    Some(EnvironmentEntrySpec {
                        kind: Some(Kind::Secret(EnvironmentSecretSpec {
                            name: name.to_owned(),
                            agent_visible: true,
                            delivery: 0,
                        })),
                    }),
                ),
                Seed::Script(env, name) => {
                    wanted_scripts = true;
                    (
                        env,
                        Some(EnvironmentEntrySpec {
                            kind: Some(Kind::Script(EnvironmentScriptSpec {
                                name: name.to_owned(),
                                body: SHEBANG.to_owned(),
                                on_fail: EnvironmentOnFail::Abort.into(),
                                timeout_s: Some(30),
                            })),
                        }),
                    )
                }
                Seed::Repo => {
                    sqlx::query(
                        "INSERT INTO user_repos (user_id, host, path, forge_kind, push, verified_at) \
                         VALUES ($1, 'github.com', 'octo/hello', 'github', true, now())",
                    )
                    .bind(user)
                    .execute(&self.pool)
                    .await
                    .unwrap();
                    continue;
                }
            };
            match entries.iter_mut().find(|(name, _)| *name == env) {
                Some((_, list)) => list.extend(entry),
                None => entries.push((env, entry.into_iter().collect())),
            }
        }
        if wanted_scripts {
            self.grant(user).await;
        }
        for (env, list) in entries {
            self.service
                .create(
                    user,
                    &CreateEnvironmentRequest {
                        name: env.to_owned(),
                    },
                )
                .await
                .unwrap();
            for entry in &list {
                if let Some(Kind::Secret(spec)) = &entry.kind {
                    self.service
                        .put_secret(
                            user,
                            &PutEnvironmentSecretRequest {
                                environment: env.to_owned(),
                                name: spec.name.clone(),
                                value: VALUE.to_owned(),
                            },
                        )
                        .await
                        .unwrap();
                }
            }
            if !list.is_empty() {
                self.service
                    .save_version(
                        user,
                        &SaveEnvironmentVersionRequest {
                            environment: env.to_owned(),
                            entries: list,
                            egress_hosts: Vec::new(),
                        },
                    )
                    .await
                    .unwrap();
            }
        }
        if wanted_scripts && !cap {
            self.revoke(user).await;
        }
    }

    async fn stored(&self, user: i64, scenario: &Scenario) -> Vec<String> {
        let mut lines = Vec::new();
        for info in self.service.list(user).await.unwrap().environments {
            lines.push(format!("env {}", info.name));
            let detail = self
                .service
                .get(user, &GetEnvironmentRequest { name: info.name })
                .await
                .unwrap();
            let name = detail.environment.unwrap().name;
            for secret in detail.secrets {
                lines.push(format!(
                    "secret {name} {} {}",
                    secret.name, secret.fingerprint
                ));
            }
        }
        if scenario.seed.iter().any(|s| matches!(s, Seed::Repo)) {
            let bound = self
                .service
                .get_default(
                    user,
                    &GetEnvironmentDefaultRequest {
                        key: Some(EnvironmentBindingKey {
                            key: Some(Key::Repo(EnvironmentRepoKey {
                                host: "github.com".to_owned(),
                                path: "octo/hello".to_owned(),
                            })),
                        }),
                    },
                )
                .await
                .unwrap();
            lines.push(format!("default {REPO} {:?}", bound.environment));
        }
        lines
    }

    async fn structure(&self, user: i64) -> Vec<String> {
        let mut lines = Vec::new();
        for info in self.service.list(user).await.unwrap().environments {
            let detail = self
                .service
                .get(user, &GetEnvironmentRequest { name: info.name })
                .await
                .unwrap();
            let name = detail.environment.unwrap().name;
            let Some(latest) = detail.latest else {
                lines.push(format!("version {name} none"));
                continue;
            };
            lines.push(format!("version {name} {}", latest.version));
            for entry in latest.entries {
                match entry.kind {
                    Some(Kind::Secret(s)) => lines.push(format!("entry {name} secret {}", s.name)),
                    Some(Kind::Script(s)) => lines.push(format!("entry {name} script {}", s.name)),
                    None => {}
                }
            }
        }
        lines
    }
}

async fn run_cli(
    addr: SocketAddr,
    token: &str,
    args: &[&str],
    stdin: &str,
) -> (Result<(), CliError>, String) {
    let url = format!("http://{addr}");
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let token = token.to_owned();
    let mut out = Vec::new();
    let mut input = stdin.as_bytes();
    let result = tokio::time::timeout(
        WAIT,
        run(
            parsed,
            move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
            &mut input,
            &mut out,
        ),
    )
    .await
    .unwrap();
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn cli_shape(result: &Result<(), CliError>) -> Shape {
    match result {
        Ok(()) => Shape::Done,
        Err(CliError::Rpc(status)) => Shape::Refused(status.code()),
        Err(CliError::Usage(_)) => Shape::Refused(Code::InvalidArgument),
        Err(other) => panic!("unexpected cli error {other:?}"),
    }
}

fn web_shape(act: WebAct, reply: &Reply) -> Shape {
    if let WebAct::Absent(..) = act {
        return if matches!(reply.status, 404 | 405) {
            Shape::Absent
        } else {
            panic!("route answered {}", reply.status)
        };
    }
    match reply.status {
        200 => Shape::Done,
        404 => Shape::Refused(Code::NotFound),
        303 => {
            let location = reply
                .head
                .lines()
                .find_map(|l| l.strip_prefix("location: "))
                .unwrap();
            let notice = location.split_once("notice=").unwrap().1;
            match notice {
                "created" | "deleted" | "secret_saved" | "secret_deleted" => Shape::Done,
                "invalid" => Shape::Refused(Code::InvalidArgument),
                "exists" => Shape::Refused(Code::AlreadyExists),
                "limit" => Shape::Refused(Code::ResourceExhausted),
                "missing" => Shape::Refused(Code::NotFound),
                other => panic!("notice {other}"),
            }
        }
        other => panic!("status {other}"),
    }
}

fn cli_listing(out: &str) -> Vec<(String, String)> {
    out.lines()
        .map(|line| {
            let (name, version) = line.split_once('\t').unwrap();
            (name.to_owned(), version.to_owned())
        })
        .collect()
}

fn web_listing(page: &str) -> Vec<(String, String)> {
    let Some(table) = page.split("<tbody>").nth(1) else {
        return Vec::new();
    };
    table
        .split("<tr>")
        .skip(1)
        .map(|chunk| {
            let cells: Vec<&str> = chunk.split("<td>").skip(1).collect();
            let name = cells[0]
                .split_once('>')
                .unwrap()
                .1
                .split_once("</a>")
                .unwrap()
                .0;
            let version = cells[1].split_once("</td>").unwrap().0;
            let version = match version {
                "none" => "-",
                other => other.trim_start_matches('v'),
            };
            (name.to_owned(), version.to_owned())
        })
        .collect()
}

async fn judge(name: &str, pool: PgPool) {
    let scenario = SCENARIOS.iter().find(|s| s.name == name).unwrap();
    let rig = Rig::start(pool).await;
    let cli_user = rig.persona("olive-cli", 'a', scenario.cap).await;
    let web_user = rig.persona("olive-web", 'b', scenario.cap).await;
    let other = rig.persona("olive-other", 'c', true).await;
    let repo: Vec<Seed> = scenario
        .seed
        .iter()
        .copied()
        .filter(|s| matches!(s, Seed::Repo))
        .collect();
    if scenario.foreign {
        rig.seed(other.id, scenario.seed, scenario.cap).await;
        rig.seed(cli_user.id, &repo, scenario.cap).await;
        rig.seed(web_user.id, &repo, scenario.cap).await;
    } else {
        rig.seed(cli_user.id, scenario.seed, scenario.cap).await;
        rig.seed(web_user.id, scenario.seed, scenario.cap).await;
    }
    let probe = Scenario {
        seed: if scenario.op == "set-default" {
            &[Seed::Repo]
        } else {
            &[]
        },
        ..BASE
    };
    let stored_before = (
        rig.stored(cli_user.id, &probe).await,
        rig.stored(web_user.id, &probe).await,
    );
    let structure_before = (
        rig.structure(cli_user.id).await,
        rig.structure(web_user.id).await,
    );

    let (cli_result, cli_out) = match scenario.cli {
        CliAct::Run(args, stdin) => {
            let (r, out) = run_cli(rig.addr, &cli_user.token, args, stdin).await;
            (Some(r), out)
        }
        CliAct::Absent(args) => {
            let url = "http://127.0.0.1:1";
            let mut full = vec!["fleet", "--server", url];
            full.extend_from_slice(args);
            assert!(Cli::try_parse_from(full).is_err(), "{name}: cli parses");
            (None, String::new())
        }
    };
    let web_reply = match scenario.web {
        WebAct::Get(path) => rig.http("GET", path, &web_user, "").await,
        WebAct::Post(path, fields) | WebAct::Absent(path, fields) => {
            rig.post(&web_user, path, fields).await
        }
    };

    let cli = cli_result.as_ref().map_or(Shape::Absent, cli_shape);
    let web = web_shape(scenario.web, &web_reply);
    match scenario.class {
        Class::Same | Class::SameStored(_) => {
            assert_eq!(cli, scenario.shape, "{name}: cli");
            assert_eq!(web, scenario.shape, "{name}: web");
        }
        Class::Gap(why, want_cli, want_web) => {
            assert_eq!(cli, want_cli, "{name}: cli ({why})");
            assert_eq!(web, want_web, "{name}: web ({why})");
            assert_ne!(cli, web, "{name}: a closed gap must become Same ({why})");
        }
    }
    if let (Some(Err(CliError::Rpc(status))), Some(text)) = (&cli_result, scenario.cli_text) {
        assert_eq!(status.message(), text, "{name}");
    }

    let stored_after = (
        rig.stored(cli_user.id, &probe).await,
        rig.stored(web_user.id, &probe).await,
    );
    let structure_after = (
        rig.structure(cli_user.id).await,
        rig.structure(web_user.id).await,
    );
    if cli == Shape::Done && !matches!(scenario.op, "list" | "show") {
        assert_ne!(
            (&stored_before.0, &structure_before.0),
            (&stored_after.0, &structure_after.0),
            "{name}: cli changed nothing"
        );
    }
    if web == Shape::Done && !matches!(scenario.op, "list" | "show") {
        assert_ne!(
            (&stored_before.1, &structure_before.1),
            (&stored_after.1, &structure_after.1),
            "{name}: web changed nothing"
        );
    }
    if cli != Shape::Done {
        assert_eq!(stored_before.0, stored_after.0, "{name}: cli refusal wrote");
        assert_eq!(
            structure_before.0, structure_after.0,
            "{name}: cli refusal wrote"
        );
    }
    if web != Shape::Done {
        assert_eq!(stored_before.1, stored_after.1, "{name}: web refusal wrote");
        assert_eq!(
            structure_before.1, structure_after.1,
            "{name}: web refusal wrote"
        );
    }
    if cli == Shape::Done && web == Shape::Done {
        match scenario.class {
            Class::Same => {
                assert_eq!(stored_after.0, stored_after.1, "{name}: stored");
                assert_eq!(structure_after.0, structure_after.1, "{name}: structure");
            }
            Class::SameStored(why) => {
                assert_eq!(stored_after.0, stored_after.1, "{name}: stored");
                assert_ne!(
                    structure_after.0, structure_after.1,
                    "{name}: gap closed ({why})"
                );
            }
            Class::Gap(..) => {}
        }
    }

    if let Some(expected) = scenario.listing {
        let want: Vec<(String, String)> = expected
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(cli_listing(&cli_out), want, "{name}: cli listing");
        assert_eq!(web_listing(&web_reply.body), want, "{name}: web listing");
    }
    if scenario.show {
        let lines = &stored_after.0;
        let fingerprints: Vec<&str> = lines
            .iter()
            .filter_map(|l| {
                l.strip_prefix("secret ")
                    .map(|r| r.rsplit(' ').next().unwrap())
            })
            .collect();
        assert!(!fingerprints.is_empty(), "{name}: no fingerprint seeded");
        for fp in fingerprints {
            assert!(cli_out.contains(fp), "{name}: cli fingerprint");
            assert!(web_reply.body.contains(fp), "{name}: web fingerprint");
        }
        assert!(!cli_out.contains(VALUE), "{name}: cli leaked a value");
        assert!(
            !web_reply.body.contains(VALUE),
            "{name}: web leaked a value"
        );
    }
    for needle in scenario.cli_has {
        assert!(
            cli_out.contains(needle),
            "{name}: cli lacks {needle:?}: {cli_out}"
        );
    }
    if !scenario.web_has.is_empty() {
        let page = rig.http("GET", "/environments/build", &web_user, "").await;
        for needle in scenario.web_has {
            assert!(page.body.contains(needle), "{name}: web lacks {needle:?}");
        }
    }
    let mut leak = String::new();
    write!(leak, "{}{}", cli_out, web_reply.body).unwrap();
    assert!(!leak.contains(VALUE), "{name}: value echoed");
}

macro_rules! rows {
    ($($test:ident => $name:literal,)*) => {
        $(
            #[sqlx::test]
            async fn $test(pool: PgPool) {
                judge($name, pool).await;
            }
        )*
        const ROWS: &[&str] = &[$($name),*];
    };
}

rows! {
    create_ok => "create/ok",
    create_exists => "create/refused/exists",
    create_bad_name => "create/refused/bad_name",
    list_empty => "list/empty",
    list_rows => "list/rows",
    show_ok => "show/ok",
    show_foreign => "show/refused/foreign_name",
    show_unknown => "show/refused/unknown_name",
    show_scripts_without_capability => "show/ok/scripts_without_capability",
    put_secret_ok => "put-secret/ok",
    put_secret_short => "put-secret/refused/value_too_short",
    put_secret_foreign => "put-secret/refused/foreign_name",
    delete_secret_ok => "delete-secret/ok",
    delete_secret_unknown => "delete-secret/refused/unknown_secret",
    delete_secret_foreign => "delete-secret/refused/foreign_name",
    add_script_ok => "add-script/ok",
    add_script_capability => "add-script/refused/capability",
    remove_script_ok => "remove-script/ok",
    delete_env_ok => "delete-env/ok",
    delete_env_foreign => "delete-env/refused/foreign_name",
    delete_env_unknown => "delete-env/refused/unknown_name",
    set_default_ok => "set-default/ok",
    set_default_foreign => "set-default/refused/foreign_name",
}

#[test]
fn every_scenario_has_a_test_and_every_operation_a_row() {
    let named: BTreeSet<&str> = SCENARIOS.iter().map(|s| s.name).collect();
    let tested: BTreeSet<&str> = ROWS.iter().copied().collect();
    assert_eq!(named, tested);
    assert_eq!(named.len(), SCENARIOS.len());
    let ops: BTreeSet<&str> = SCENARIOS.iter().map(|s| s.op).collect();
    let required: BTreeSet<&str> = REQUIRED_OPERATIONS.iter().copied().collect();
    assert_eq!(ops, required);
    assert!(SCENARIOS.iter().any(|s| s.foreign));
    assert!(SCENARIOS.iter().any(|s| s.name.ends_with("/capability")));
}
