//! The `FleetEnvironments` RPCs (ADR-0067) through the production auth layer: caller classes,
//! foreign-name answers, required fields, the `env:scripts` gate and secret hiding. The tests
//! need a Postgres superuser URL in `DATABASE_URL` and live in their own binary because they
//! bind sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fleet_core::credential::{Secret, fingerprint};
use fleet_proto::v1::fleet_environments_client::FleetEnvironmentsClient;
use fleet_proto::v1::{
    ClearEnvironmentDefaultRequest, EnvironmentBindingKey, GetEnvironmentDefaultRequest,
    SetEnvironmentDefaultRequest,
};
use fleet_proto::v1::{
    CreateEnvironmentRequest, DeleteEnvironmentRequest, DeleteEnvironmentSecretRequest,
    EnvironmentDelivery, EnvironmentEntrySpec, EnvironmentOnFail, EnvironmentScriptSpec,
    EnvironmentSecretSpec, GetEnvironmentRequest, GetEnvironmentVersionRequest,
    ListEnvironmentVersionsRequest, ListEnvironmentsRequest, PutEnvironmentSecretRequest,
    SaveEnvironmentVersionRequest, environment_entry_spec::Kind,
};
use fleet_proto::{
    ERR_ENV_NEEDS_USER_TOKEN, ERR_ENV_NOT_FOUND, ERR_ENV_SCRIPTS_NOT_GRANTED,
    PRECONDITION_NOT_CONFIGURED,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{
    EnvironmentService, EnvironmentStore, REASON_ENTRY_KIND, REASON_ENUM, REASON_VERSION_REQUIRED,
};
use fleet_server::service::router_with_environments;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const VALUE: &str = "pve-token-Zk93abQ7xw";
const MARK: &str = "MARKER-rpc-secret-value-q7";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn sealer(tag: &str) -> FileSealer {
    let tag = format!("{tag}-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    let path =
        std::env::temp_dir().join(format!("fleet-env-rpc-{}-{tag}.keys", std::process::id()));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

fn store(pool: &PgPool, tag: &str) -> EnvironmentStore {
    EnvironmentStore::new(pool.clone(), Arc::new(sealer(tag)))
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    users: Users,
}

async fn rig_with(pool: PgPool, configured: bool) -> Rig {
    let core = Store::new(pool.clone());
    core.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let service = configured.then(|| EnvironmentService::new(store(&pool, "rig")));
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with_environments(&core, &auth, None, service).serve_with_incoming(incoming),
    );
    Rig { addr, pool, users }
}

async fn rig(pool: PgPool) -> Rig {
    rig_with(pool, true).await
}

async fn bare_user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    let id = bare_user(pool, name).await;
    sqlx::query(
        "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, 'env:scripts', $1)",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn token_of(rig: &Rig, user: i64) -> String {
    let made = rig.users.create_api_token(user, "t").await.unwrap();
    String::from_utf8(made.token.expose().to_vec()).unwrap()
}

fn client(rig: &Rig) -> FleetEnvironmentsClient<Channel> {
    FleetEnvironmentsClient::new(
        Endpoint::from_shared(format!("http://{}", rig.addr))
            .unwrap()
            .connect_lazy(),
    )
}

fn authed<T>(message: T, token: Option<&str>) -> Request<T> {
    let mut request = Request::new(message);
    if let Some(token) = token {
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
        );
    }
    request
}

fn secret_entry(name: &str) -> EnvironmentEntrySpec {
    EnvironmentEntrySpec {
        kind: Some(Kind::Secret(EnvironmentSecretSpec {
            name: name.to_owned(),
            agent_visible: false,
            delivery: EnvironmentDelivery::Unspecified.into(),
        })),
    }
}

fn script_entry(name: &str, body: &str, timeout_s: Option<u32>) -> EnvironmentEntrySpec {
    EnvironmentEntrySpec {
        kind: Some(Kind::Script(EnvironmentScriptSpec {
            name: name.to_owned(),
            body: body.to_owned(),
            on_fail: EnvironmentOnFail::Unspecified.into(),
            timeout_s,
        })),
    }
}

#[derive(Clone, Copy, Debug)]
enum Rpc {
    Create,
    List,
    Get,
    Delete,
    PutSecret,
    DeleteSecret,
    Save,
    GetVersion,
    ListVersions,
    SetDefault,
    GetDefault,
    ClearDefault,
}

const ALL: [Rpc; 12] = [
    Rpc::Create,
    Rpc::List,
    Rpc::Get,
    Rpc::Delete,
    Rpc::PutSecret,
    Rpc::DeleteSecret,
    Rpc::Save,
    Rpc::GetVersion,
    Rpc::ListVersions,
    Rpc::SetDefault,
    Rpc::GetDefault,
    Rpc::ClearDefault,
];

async fn call(rig: &Rig, rpc: Rpc, token: Option<&str>, name: &str) -> Result<(), Status> {
    let mut c = client(rig);
    let n = name.to_owned();
    match rpc {
        Rpc::Create => c
            .create_environment(authed(CreateEnvironmentRequest { name: n }, token))
            .await
            .map(drop),
        Rpc::List => c
            .list_environments(authed(ListEnvironmentsRequest {}, token))
            .await
            .map(drop),
        Rpc::Get => c
            .get_environment(authed(GetEnvironmentRequest { name: n }, token))
            .await
            .map(drop),
        Rpc::Delete => c
            .delete_environment(authed(DeleteEnvironmentRequest { name: n }, token))
            .await
            .map(drop),
        Rpc::PutSecret => c
            .put_environment_secret(authed(
                PutEnvironmentSecretRequest {
                    environment: n,
                    name: "TOKEN".to_owned(),
                    value: VALUE.to_owned(),
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::DeleteSecret => c
            .delete_environment_secret(authed(
                DeleteEnvironmentSecretRequest {
                    environment: n,
                    name: "TOKEN".to_owned(),
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::Save => c
            .save_environment_version(authed(
                SaveEnvironmentVersionRequest {
                    environment: n,
                    entries: vec![secret_entry("TOKEN")],
                    egress_hosts: vec![],
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::GetVersion => c
            .get_environment_version(authed(
                GetEnvironmentVersionRequest {
                    environment: n,
                    version: 1,
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::ListVersions => c
            .list_environment_versions(authed(
                ListEnvironmentVersionsRequest { environment: n },
                token,
            ))
            .await
            .map(drop),
        Rpc::SetDefault => c
            .set_environment_default(authed(
                SetEnvironmentDefaultRequest {
                    key: Some(binding_key()),
                    environment: n,
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::GetDefault => c
            .get_environment_default(authed(
                GetEnvironmentDefaultRequest {
                    key: Some(binding_key()),
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::ClearDefault => c
            .clear_environment_default(authed(
                ClearEnvironmentDefaultRequest {
                    key: Some(binding_key()),
                },
                token,
            ))
            .await
            .map(drop),
    }
}

fn binding_key() -> EnvironmentBindingKey {
    EnvironmentBindingKey {
        key: Some(fleet_proto::v1::environment_binding_key::Key::Profile(
            "bound".to_owned(),
        )),
    }
}

fn target(rpc: Rpc) -> &'static str {
    match rpc {
        Rpc::Create => "fresh",
        Rpc::Delete => "doomed",
        _ => "own",
    }
}

const TABLES: [&str; 5] = [
    "environment",
    "environment_version",
    "environment_entry",
    "environment_secret",
    "environment_use",
];

async fn counts(pool: &PgPool) -> Vec<i64> {
    let mut out = Vec::new();
    for table in TABLES {
        let n: i64 = match table {
            "environment" => sqlx::query_scalar("SELECT count(*) FROM environment"),
            "environment_version" => sqlx::query_scalar("SELECT count(*) FROM environment_version"),
            "environment_entry" => sqlx::query_scalar("SELECT count(*) FROM environment_entry"),
            "environment_secret" => sqlx::query_scalar("SELECT count(*) FROM environment_secret"),
            _ => sqlx::query_scalar("SELECT count(*) FROM environment_use"),
        }
        .fetch_one(pool)
        .await
        .unwrap();
        out.push(n);
    }
    out
}

async fn exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM environment WHERE name = $1)")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn seed(rig: &Rig, owner: i64, name: &str) {
    let store = store(&rig.pool, "seed");
    let id = store
        .create_environment(
            owner,
            &fleet_core::environment::EnvironmentName::new(name).unwrap(),
        )
        .await
        .unwrap();
    let token = fleet_core::environment::EntryName::new("TOKEN").unwrap();
    store
        .put_secret(
            owner,
            id,
            &token,
            &fleet_core::environment::SecretValue::new(VALUE.to_owned()).unwrap(),
        )
        .await
        .unwrap();
    let spec = fleet_core::environment::EnvironmentSpec::new(
        vec![fleet_core::environment::Entry::Secret(
            fleet_core::environment::SecretSpec::with_defaults(token),
        )],
        vec![],
    )
    .unwrap();
    store.save_version(owner, id, &spec).await.unwrap();
}

#[sqlx::test]
async fn every_method_meets_the_caller_class_it_is_owed(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let api = token_of(&rig, alice).await;
    let revoked = rig.users.create_api_token(alice, "r").await.unwrap();
    let revoked_value = String::from_utf8(revoked.token.expose().to_vec()).unwrap();
    rig.users.revoke_api_token(alice, revoked.id).await.unwrap();
    seed(&rig, alice, "own").await;
    seed(&rig, alice, "doomed").await;
    sqlx::query("INSERT INTO profile (owner_user_id, name) VALUES ($1, 'bound')")
        .bind(alice)
        .execute(&rig.pool)
        .await
        .unwrap();
    let before = counts(&rig.pool).await;
    let denied: [(&str, Option<&str>, Code, Option<&str>); 5] = [
        (
            "client",
            Some(CLIENT),
            Code::PermissionDenied,
            Some(ERR_ENV_NEEDS_USER_TOKEN),
        ),
        (
            "box",
            Some(BOX),
            Code::PermissionDenied,
            Some("bearer token not valid for this service"),
        ),
        ("no header", None, Code::Unauthenticated, None),
        ("revoked", Some(&revoked_value), Code::Unauthenticated, None),
        (
            "bogus",
            Some("d5cb2d7a5e1f4c0e9a3b"),
            Code::Unauthenticated,
            None,
        ),
    ];
    for (label, token, code, message) in denied {
        for rpc in ALL {
            let status = call(&rig, rpc, token, target(rpc)).await.unwrap_err();
            assert_eq!(status.code(), code, "{label} {rpc:?}");
            if let Some(message) = message {
                assert_eq!(status.message(), message, "{label} {rpc:?}");
            }
        }
        assert_eq!(counts(&rig.pool).await, before, "{label} changed rows");
        assert!(!exists(&rig.pool, "fresh").await, "{label}");
    }
    for rpc in ALL {
        call(&rig, rpc, Some(&api), target(rpc))
            .await
            .unwrap_or_else(|e| panic!("api {rpc:?}: {e}"));
    }
    assert!(exists(&rig.pool, "fresh").await);
    assert!(!exists(&rig.pool, "doomed").await);
}

#[sqlx::test]
async fn a_foreign_name_answers_exactly_as_an_unknown_name(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let bob = user(&rig.pool, "bob").await;
    seed(&rig, alice, "alice-env").await;
    seed(&rig, bob, "bob-env").await;
    let bob_token = token_of(&rig, bob).await;
    let before = counts(&rig.pool).await;
    for rpc in ALL {
        if matches!(
            rpc,
            Rpc::Create | Rpc::List | Rpc::GetDefault | Rpc::ClearDefault
        ) {
            continue;
        }
        let foreign = call(&rig, rpc, Some(&bob_token), "alice-env")
            .await
            .unwrap_err();
        let unknown = call(&rig, rpc, Some(&bob_token), "ghost")
            .await
            .unwrap_err();
        assert_eq!(foreign.code(), Code::NotFound, "{rpc:?}");
        assert_eq!(foreign.message(), ERR_ENV_NOT_FOUND, "{rpc:?}");
        assert_eq!(
            (foreign.code(), foreign.message()),
            (unknown.code(), unknown.message()),
            "{rpc:?}"
        );
        assert_eq!(counts(&rig.pool).await, before, "{rpc:?} changed rows");
    }
    assert!(exists(&rig.pool, "alice-env").await);
}

#[sqlx::test]
async fn create_and_list_see_only_the_callers_own_environments(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let bob = user(&rig.pool, "bob").await;
    seed(&rig, alice, "shared-name").await;
    let bob_token = token_of(&rig, bob).await;
    let alice_token = token_of(&rig, alice).await;
    let mut c = client(&rig);
    let own = c
        .create_environment(authed(
            CreateEnvironmentRequest {
                name: "shared-name".into(),
            },
            Some(&bob_token),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(own.latest_version, None);
    let bobs = c
        .list_environments(authed(ListEnvironmentsRequest {}, Some(&bob_token)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(bobs.environments.len(), 1);
    assert_eq!(bobs.environments[0].latest_version, None);
    let alices = c
        .list_environments(authed(ListEnvironmentsRequest {}, Some(&alice_token)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(alices.environments.len(), 1);
    assert_eq!(alices.environments[0].latest_version, Some(1));
}

#[sqlx::test]
async fn each_required_field_is_refused_with_its_own_message_and_no_write(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let token = token_of(&rig, alice).await;
    seed(&rig, alice, "own").await;
    let before = counts(&rig.pool).await;
    let mut c = client(&rig);
    let t = Some(token.as_str());
    let put = |environment: &str, name: &str, value: &str| PutEnvironmentSecretRequest {
        environment: environment.to_owned(),
        name: name.to_owned(),
        value: value.to_owned(),
    };
    let save =
        |environment: &str, entries: Vec<EnvironmentEntrySpec>| SaveEnvironmentVersionRequest {
            environment: environment.to_owned(),
            entries,
            egress_hosts: vec![],
        };
    let env_visible = EnvironmentEntrySpec {
        kind: Some(Kind::Secret(EnvironmentSecretSpec {
            name: "TOKEN".into(),
            agent_visible: false,
            delivery: EnvironmentDelivery::Env.into(),
        })),
    };
    let mut got: Vec<(&str, Status, &str)> = Vec::new();
    let mut note =
        |label: &'static str, status: Status, want: &'static str| got.push((label, status, want));
    note(
        "create without name",
        c.create_environment(authed(
            CreateEnvironmentRequest {
                name: String::new(),
            },
            t,
        ))
        .await
        .unwrap_err(),
        "environment name is empty",
    );
    note(
        "put without environment",
        c.put_environment_secret(authed(put("", "TOKEN", VALUE), t))
            .await
            .unwrap_err(),
        "environment name is empty",
    );
    note(
        "put without name",
        c.put_environment_secret(authed(put("own", "", VALUE), t))
            .await
            .unwrap_err(),
        "entry name is empty",
    );
    note(
        "put with short value",
        c.put_environment_secret(authed(put("own", "TOKEN", "short"), t))
            .await
            .unwrap_err(),
        "secret value is too short",
    );
    note(
        "delete secret without name",
        c.delete_environment_secret(authed(
            DeleteEnvironmentSecretRequest {
                environment: "own".into(),
                name: String::new(),
            },
            t,
        ))
        .await
        .unwrap_err(),
        "entry name is empty",
    );
    note(
        "save without environment",
        c.save_environment_version(authed(save("", vec![]), t))
            .await
            .unwrap_err(),
        "environment name is empty",
    );
    note(
        "save script without name",
        c.save_environment_version(authed(
            save("own", vec![script_entry("", SHEBANG, None)]),
            t,
        ))
        .await
        .unwrap_err(),
        "entry name is empty",
    );
    note(
        "save script with empty body",
        c.save_environment_version(authed(
            save("own", vec![script_entry("setup", "", None)]),
            t,
        ))
        .await
        .unwrap_err(),
        "script body is empty",
    );
    note(
        "save entry without kind",
        c.save_environment_version(authed(
            save("own", vec![EnvironmentEntrySpec { kind: None }]),
            t,
        ))
        .await
        .unwrap_err(),
        REASON_ENTRY_KIND,
    );
    note(
        "save env delivery without agent_visible",
        c.save_environment_version(authed(save("own", vec![env_visible]), t))
            .await
            .unwrap_err(),
        "env delivery needs an agent-visible secret",
    );
    note(
        "save script timeout over the cap",
        c.save_environment_version(authed(
            save("own", vec![script_entry("setup", SHEBANG, Some(601))]),
            t,
        ))
        .await
        .unwrap_err(),
        "script timeout is out of range",
    );
    note(
        "save unknown delivery",
        c.save_environment_version(authed(
            save(
                "own",
                vec![EnvironmentEntrySpec {
                    kind: Some(Kind::Secret(EnvironmentSecretSpec {
                        name: "TOKEN".into(),
                        agent_visible: true,
                        delivery: 99,
                    })),
                }],
            ),
            t,
        ))
        .await
        .unwrap_err(),
        REASON_ENUM,
    );
    note(
        "save unknown on_fail",
        c.save_environment_version(authed(
            save(
                "own",
                vec![EnvironmentEntrySpec {
                    kind: Some(Kind::Script(EnvironmentScriptSpec {
                        name: "setup".into(),
                        body: SHEBANG.into(),
                        on_fail: 99,
                        timeout_s: None,
                    })),
                }],
            ),
            t,
        ))
        .await
        .unwrap_err(),
        REASON_ENUM,
    );
    note(
        "get version zero",
        c.get_environment_version(authed(
            GetEnvironmentVersionRequest {
                environment: "own".into(),
                version: 0,
            },
            t,
        ))
        .await
        .unwrap_err(),
        REASON_VERSION_REQUIRED,
    );
    for (label, status, want) in got {
        assert_eq!(status.code(), Code::InvalidArgument, "{label}");
        assert_eq!(status.message(), want, "{label}");
    }
    assert_eq!(counts(&rig.pool).await, before);
}

#[sqlx::test]
async fn a_script_save_needs_the_env_scripts_grant(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = bare_user(&rig.pool, "alice").await;
    let token = token_of(&rig, alice).await;
    seed(&rig, alice, "own").await;
    let before = counts(&rig.pool).await;
    let mut c = client(&rig);
    let with_script = SaveEnvironmentVersionRequest {
        environment: "own".into(),
        entries: vec![secret_entry("TOKEN"), script_entry("setup", SHEBANG, None)],
        egress_hosts: vec![],
    };
    let status = c
        .save_environment_version(authed(with_script.clone(), Some(&token)))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(status.message(), ERR_ENV_SCRIPTS_NOT_GRANTED);
    assert_eq!(counts(&rig.pool).await, before);
    sqlx::query(
        "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, 'env:scripts', $1)",
    )
    .bind(alice)
    .execute(&rig.pool)
    .await
    .unwrap();
    let saved = c
        .save_environment_version(authed(with_script, Some(&token)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((saved.version, saved.created), (2, true));
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn logs() -> &'static LogBuffer {
    static BUFFER: std::sync::OnceLock<LogBuffer> = std::sync::OnceLock::new();
    static INIT: std::sync::Once = std::sync::Once::new();
    let buffer = BUFFER.get_or_init(LogBuffer::default);
    INIT.call_once(|| {
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(buffer.clone())
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .finish(),
        )
        .unwrap();
    });
    buffer
}

#[sqlx::test]
async fn no_log_status_or_reply_carries_a_secret_value(pool: PgPool) {
    let buffer = logs();
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let token = token_of(&rig, alice).await;
    seed(&rig, alice, "own").await;
    let t = Some(token.as_str());
    let mut c = client(&rig);
    let put = |environment: &str, name: &str| PutEnvironmentSecretRequest {
        environment: environment.to_owned(),
        name: name.to_owned(),
        value: MARK.to_owned(),
    };
    let ok = c
        .put_environment_secret(authed(put("own", "OTHER"), t))
        .await
        .unwrap();
    let missing = c
        .put_environment_secret(authed(put("ghost", "OTHER"), t))
        .await
        .unwrap_err();
    let invalid = c
        .put_environment_secret(authed(put("own", ""), t))
        .await
        .unwrap_err();
    let denied = c
        .put_environment_secret(authed(put("own", "OTHER"), Some(CLIENT)))
        .await
        .unwrap_err();
    let detail = c
        .get_environment(authed(GetEnvironmentRequest { name: "own".into() }, t))
        .await
        .unwrap();
    let shown = format!(
        "{ok:?} {missing:?} {invalid:?} {denied:?} {detail:?} {:?}",
        put("own", "OTHER")
    );
    assert!(!shown.contains(MARK), "{shown}");
    assert!(shown.contains("<redacted>"));
    assert_eq!(
        ok.into_inner().fingerprint,
        fingerprint(&Secret::new(MARK.to_owned()))
    );
    let captured = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(captured.contains("environment secret stored"), "{captured}");
    assert!(!captured.contains(MARK), "the value reached the logs");
}

#[sqlx::test]
async fn an_environment_lives_through_its_whole_lifecycle(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let token = token_of(&rig, alice).await;
    let t = Some(token.as_str());
    let mut c = client(&rig);
    let made = c
        .create_environment(authed(
            CreateEnvironmentRequest {
                name: "Prod".into(),
            },
            t,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((made.name.as_str(), made.latest_version), ("Prod", None));
    let twice = c
        .create_environment(authed(
            CreateEnvironmentRequest {
                name: "prod".into(),
            },
            t,
        ))
        .await
        .unwrap_err();
    assert_eq!(twice.code(), Code::AlreadyExists);
    let put = c
        .put_environment_secret(authed(
            PutEnvironmentSecretRequest {
                environment: "PROD".into(),
                name: "TOKEN".into(),
                value: VALUE.into(),
            },
            t,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(put.fingerprint, fingerprint(&Secret::new(VALUE.to_owned())));
    let entries = vec![
        EnvironmentEntrySpec {
            kind: Some(Kind::Secret(EnvironmentSecretSpec {
                name: "TOKEN".into(),
                agent_visible: true,
                delivery: EnvironmentDelivery::Env.into(),
            })),
        },
        script_entry("setup", SHEBANG, Some(30)),
    ];
    let save = SaveEnvironmentVersionRequest {
        environment: "prod".into(),
        entries: entries.clone(),
        egress_hosts: vec!["example.com".into()],
    };
    let first = c
        .save_environment_version(authed(save.clone(), t))
        .await
        .unwrap()
        .into_inner();
    let again = c
        .save_environment_version(authed(save, t))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((first.version, first.created), (1, true));
    assert_eq!((again.version, again.created), (1, false));
    let version = c
        .get_environment_version(authed(
            GetEnvironmentVersionRequest {
                environment: "prod".into(),
                version: 1,
            },
            t,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(version.entries.len(), 2);
    assert_eq!(version.egress_hosts, ["example.com"]);
    assert_eq!(version.entries[0].kind, entries[0].kind);
    let listed = c
        .list_environment_versions(authed(
            ListEnvironmentVersionsRequest {
                environment: "prod".into(),
            },
            t,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.versions.len(), 1);
    assert_eq!(listed.versions[0].hash, version.hash);
    let missing = c
        .get_environment_version(authed(
            GetEnvironmentVersionRequest {
                environment: "prod".into(),
                version: 9,
            },
            t,
        ))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);
    let detail = c
        .get_environment(authed(
            GetEnvironmentRequest {
                name: "prod".into(),
            },
            t,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(detail.secrets.len(), 1);
    assert_eq!(detail.secrets[0].fingerprint, put.fingerprint);
    assert_eq!(detail.environment.as_ref().unwrap().latest_version, Some(1));
    assert!(!format!("{detail:?}").contains(VALUE));
    c.delete_environment_secret(authed(
        DeleteEnvironmentSecretRequest {
            environment: "prod".into(),
            name: "TOKEN".into(),
        },
        t,
    ))
    .await
    .unwrap();
    let gone = c
        .delete_environment_secret(authed(
            DeleteEnvironmentSecretRequest {
                environment: "prod".into(),
                name: "TOKEN".into(),
            },
            t,
        ))
        .await
        .unwrap_err();
    assert_eq!(gone.code(), Code::NotFound);
    c.delete_environment(authed(
        DeleteEnvironmentRequest {
            name: "prod".into(),
        },
        t,
    ))
    .await
    .unwrap();
    let after = c
        .get_environment(authed(
            GetEnvironmentRequest {
                name: "prod".into(),
            },
            t,
        ))
        .await
        .unwrap_err();
    assert_eq!(after.code(), Code::NotFound);
}

#[sqlx::test]
async fn an_unconfigured_service_refuses_every_user_call(pool: PgPool) {
    let rig = rig_with(pool, false).await;
    let alice = user(&rig.pool, "alice").await;
    let token = token_of(&rig, alice).await;
    for rpc in ALL {
        let status = call(&rig, rpc, Some(&token), target(rpc))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition, "{rpc:?}");
        assert_eq!(status.message(), PRECONDITION_NOT_CONFIGURED, "{rpc:?}");
    }
}
