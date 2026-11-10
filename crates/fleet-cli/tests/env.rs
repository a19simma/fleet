//! `fleet env` against an in-process `FleetEnvironments` stub: the hostile-name table, the
//! stdin-only secret path, the read bounds, fingerprint-only output and the read-modify-write of
//! the structure for scripts and secret entries.

#![expect(
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    reason = "test code asserts by panicking"
)]

use std::io::Read;
use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run_with_tty};
use fleet_core::environment::{MAX_NAME_BYTES, MAX_SCRIPT_BYTES, MAX_SECRET_BYTES};
use fleet_proto::v1::environment_binding_key::Key;
use fleet_proto::v1::environment_entry_spec::Kind;
use fleet_proto::v1::fleet_environments_server::{FleetEnvironments, FleetEnvironmentsServer};
use fleet_proto::v1::{
    ClearEnvironmentDefaultReply, ClearEnvironmentDefaultRequest, GetEnvironmentDefaultReply,
    GetEnvironmentDefaultRequest, SetEnvironmentDefaultReply, SetEnvironmentDefaultRequest,
};
use fleet_proto::v1::{
    CreateEnvironmentRequest, DeleteEnvironmentReply, DeleteEnvironmentRequest,
    DeleteEnvironmentSecretReply, DeleteEnvironmentSecretRequest, EnvironmentDelivery,
    EnvironmentDetail, EnvironmentEntrySpec, EnvironmentInfo, EnvironmentOnFail,
    EnvironmentScriptSpec, EnvironmentSecretInfo, EnvironmentSecretSpec, EnvironmentVersion,
    GetEnvironmentRequest, GetEnvironmentVersionRequest, ListEnvironmentVersionsReply,
    ListEnvironmentVersionsRequest, ListEnvironmentsReply, ListEnvironmentsRequest,
    PutEnvironmentSecretReply, PutEnvironmentSecretRequest, SaveEnvironmentVersionReply,
    SaveEnvironmentVersionRequest,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";
const MARKER: &str = "hunter2-marker-value-7731";

#[derive(Default, Clone)]
struct Stub {
    calls: Arc<Mutex<Vec<&'static str>>>,
    detail: Option<EnvironmentDetail>,
    list: Vec<EnvironmentInfo>,
    puts: Arc<Mutex<Vec<PutEnvironmentSecretRequest>>>,
    saves: Arc<Mutex<Vec<SaveEnvironmentVersionRequest>>>,
    creates: Arc<Mutex<Vec<CreateEnvironmentRequest>>>,
    deletes: Arc<Mutex<Vec<DeleteEnvironmentRequest>>>,
    gets: Arc<Mutex<Vec<GetEnvironmentRequest>>>,
    fail_list: Option<Status>,
    fail_put: Option<Status>,
    bound: Option<String>,
    fail_default: Option<Status>,
    sets: Arc<Mutex<Vec<SetEnvironmentDefaultRequest>>>,
    default_gets: Arc<Mutex<Vec<GetEnvironmentDefaultRequest>>>,
    clears: Arc<Mutex<Vec<ClearEnvironmentDefaultRequest>>>,
}

fn locked<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, Status> {
    mutex.lock().map_err(|_| Status::internal("poisoned"))
}

impl Stub {
    fn note(&self, name: &'static str) -> Result<(), Status> {
        locked(&self.calls)?.push(name);
        Ok(())
    }
}

#[tonic::async_trait]
impl FleetEnvironments for Stub {
    async fn set_environment_default(
        &self,
        request: Request<SetEnvironmentDefaultRequest>,
    ) -> Result<Response<SetEnvironmentDefaultReply>, Status> {
        self.note("set_default")?;
        locked(&self.sets)?.push(request.into_inner());
        if let Some(status) = &self.fail_default {
            return Err(status.clone());
        }
        Ok(Response::new(SetEnvironmentDefaultReply {}))
    }

    async fn get_environment_default(
        &self,
        request: Request<GetEnvironmentDefaultRequest>,
    ) -> Result<Response<GetEnvironmentDefaultReply>, Status> {
        self.note("get_default")?;
        locked(&self.default_gets)?.push(request.into_inner());
        if let Some(status) = &self.fail_default {
            return Err(status.clone());
        }
        Ok(Response::new(GetEnvironmentDefaultReply {
            environment: self.bound.clone(),
        }))
    }

    async fn clear_environment_default(
        &self,
        request: Request<ClearEnvironmentDefaultRequest>,
    ) -> Result<Response<ClearEnvironmentDefaultReply>, Status> {
        self.note("clear_default")?;
        locked(&self.clears)?.push(request.into_inner());
        if let Some(status) = &self.fail_default {
            return Err(status.clone());
        }
        Ok(Response::new(ClearEnvironmentDefaultReply {}))
    }

    async fn create_environment(
        &self,
        request: Request<CreateEnvironmentRequest>,
    ) -> Result<Response<EnvironmentInfo>, Status> {
        self.note("create")?;
        let request = request.into_inner();
        let name = request.name.clone();
        locked(&self.creates)?.push(request);
        Ok(Response::new(EnvironmentInfo {
            name,
            latest_version: None,
        }))
    }

    async fn list_environments(
        &self,
        _request: Request<ListEnvironmentsRequest>,
    ) -> Result<Response<ListEnvironmentsReply>, Status> {
        self.note("list")?;
        if let Some(status) = &self.fail_list {
            return Err(status.clone());
        }
        Ok(Response::new(ListEnvironmentsReply {
            environments: self.list.clone(),
        }))
    }

    async fn get_environment(
        &self,
        request: Request<GetEnvironmentRequest>,
    ) -> Result<Response<EnvironmentDetail>, Status> {
        self.note("get")?;
        let request = request.into_inner();
        let name = request.name.clone();
        locked(&self.gets)?.push(request);
        Ok(Response::new(self.detail.clone().unwrap_or(
            EnvironmentDetail {
                environment: Some(EnvironmentInfo {
                    name,
                    latest_version: None,
                }),
                secrets: vec![],
                latest: None,
            },
        )))
    }

    async fn delete_environment(
        &self,
        request: Request<DeleteEnvironmentRequest>,
    ) -> Result<Response<DeleteEnvironmentReply>, Status> {
        self.note("delete")?;
        locked(&self.deletes)?.push(request.into_inner());
        Ok(Response::new(DeleteEnvironmentReply {}))
    }

    async fn put_environment_secret(
        &self,
        request: Request<PutEnvironmentSecretRequest>,
    ) -> Result<Response<PutEnvironmentSecretReply>, Status> {
        self.note("put")?;
        locked(&self.puts)?.push(request.into_inner());
        if let Some(status) = &self.fail_put {
            return Err(status.clone());
        }
        Ok(Response::new(PutEnvironmentSecretReply {
            fingerprint: "fp-aaaa1111".into(),
        }))
    }

    async fn delete_environment_secret(
        &self,
        _request: Request<DeleteEnvironmentSecretRequest>,
    ) -> Result<Response<DeleteEnvironmentSecretReply>, Status> {
        self.note("delete_secret")?;
        Ok(Response::new(DeleteEnvironmentSecretReply {}))
    }

    async fn save_environment_version(
        &self,
        request: Request<SaveEnvironmentVersionRequest>,
    ) -> Result<Response<SaveEnvironmentVersionReply>, Status> {
        self.note("save")?;
        locked(&self.saves)?.push(request.into_inner());
        Ok(Response::new(SaveEnvironmentVersionReply {
            version: 4,
            created: true,
        }))
    }

    async fn get_environment_version(
        &self,
        _request: Request<GetEnvironmentVersionRequest>,
    ) -> Result<Response<EnvironmentVersion>, Status> {
        self.note("get_version")?;
        Err(Status::unimplemented("no"))
    }

    async fn list_environment_versions(
        &self,
        _request: Request<ListEnvironmentVersionsRequest>,
    ) -> Result<Response<ListEnvironmentVersionsReply>, Status> {
        self.note("list_versions")?;
        Err(Status::unimplemented("no"))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetEnvironmentsServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli_with(
    url: &str,
    args: &[&str],
    tty: bool,
    stdin: &mut impl Read,
) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let mut out = Vec::new();
    let result = run_with_tty(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
        true,
        false,
        tty,
        stdin,
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

async fn cli(url: &str, args: &[&str], stdin: &[u8]) -> (Result<(), CliError>, String) {
    let mut stdin = stdin;
    cli_with(url, args, false, &mut stdin).await
}

fn calls(stub: &Stub) -> Vec<&'static str> {
    stub.calls.lock().unwrap().clone()
}

struct Filler {
    left: usize,
    served: Arc<Mutex<usize>>,
}

impl Read for Filler {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.left);
        for (i, slot) in buf.iter_mut().take(n).enumerate() {
            *slot = b'a' + u8::try_from(i % 23).unwrap();
        }
        self.left -= n;
        *self.served.lock().unwrap() += n;
        Ok(n)
    }
}

struct Tripwire(Arc<Mutex<bool>>);

impl Read for Tripwire {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        *self.0.lock().unwrap() = true;
        Ok(0)
    }
}

fn value_of(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| b'a' + u8::try_from(i % 23).unwrap())
        .collect()
}

fn hostile_names() -> Vec<String> {
    let mut names: Vec<String> = [
        "a\r",
        "a\r\n",
        "a\n",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{202e}b",
        "a\u{200b}b",
        "a\0b",
        " a",
        "a ",
        "a b",
        "a\tb",
        "\u{ff21}BC",
        "caf\u{e9}",
        "\u{130}",
        "\u{212a}",
        "-a",
        ".a",
        "",
        "a/b",
        "a:b",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    names.push("a".repeat(MAX_NAME_BYTES + 1));
    names
}

fn assert_usage(result: &Result<(), CliError>) {
    let err = result.as_ref().unwrap_err();
    assert!(matches!(err, CliError::Usage(_)), "{err}");
    assert_eq!(err.exit_code(), 2);
}

#[tokio::test]
async fn hostile_environment_names_are_refused_before_any_rpc() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    for name in hostile_names() {
        let value = format!("{MARKER}\n");
        let cases: Vec<Vec<&str>> = vec![
            vec!["env", "create", &name],
            vec!["env", "show", &name],
            vec!["env", "rm", &name],
            vec!["env", "secret", "put", &name, "TOKEN_A", "-"],
            vec!["env", "script", "add", &name, "setup", "-"],
            vec!["env", "script", "rm", &name, "setup"],
        ];
        for args in cases {
            let (result, out) = cli(&url, &args, value.as_bytes()).await;
            assert_usage(&result);
            assert_eq!(out, "");
        }
    }
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn hostile_entry_names_are_refused_before_any_rpc() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let mut names = hostile_names();
    names.extend(
        ["PATH", "path", "Fleet_x", "GIT_DIR", "1abc", "a-b", "a.b"]
            .iter()
            .map(|s| (*s).to_owned()),
    );
    let body = b"#!/bin/sh\ntrue\n";
    for name in names {
        let secret = format!("{MARKER}\n");
        let (result, _) = cli(
            &url,
            &["env", "secret", "put", "dev", &name, "-"],
            secret.as_bytes(),
        )
        .await;
        assert_usage(&result);
        let (result, _) = cli(&url, &["env", "script", "add", "dev", &name, "-"], body).await;
        assert_usage(&result);
        let (result, _) = cli(&url, &["env", "script", "rm", "dev", &name], b"").await;
        assert_usage(&result);
    }
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn a_valid_name_reaches_the_server_as_a_positive_control() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let longest = "a".repeat(MAX_NAME_BYTES);
    let (result, out) = cli(&url, &["env", "create", &longest], b"").await;
    result?;
    assert_eq!(out.trim_end(), longest);
    assert_eq!(calls(&stub), ["create"]);
    assert_eq!(stub.creates.lock().unwrap()[0].name, longest);
    Ok(())
}

#[tokio::test]
async fn no_flag_or_positional_can_carry_a_secret_value() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let value = MARKER;
    let value_eq = format!("--value={MARKER}");
    let secret_eq = format!("--secret={MARKER}");
    let attempts: Vec<Vec<&str>> = vec![
        vec!["env", "secret", "put", "dev", "TOKEN_A", "--value", value],
        vec!["env", "secret", "put", "dev", "TOKEN_A", &value_eq],
        vec!["env", "secret", "put", "dev", "TOKEN_A", &secret_eq],
        vec!["env", "secret", "put", "dev", "TOKEN_A", value],
        vec!["env", "secret", "put", "dev", "TOKEN_A", "-", value],
        vec!["env", "secret", "put", "dev", "TOKEN_A", value, "-"],
        vec!["env", "secret", "put", "dev", "TOKEN_A", "-v", value],
    ];
    for args in attempts {
        let (result, out) = cli(&url, &args, format!("{MARKER}\n").as_bytes()).await;
        assert_usage(&result);
        let text = result.unwrap_err().to_string();
        assert!(!text.contains(MARKER), "{text}");
        assert!(!out.contains(MARKER), "{out}");
    }
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn tty_stdin_without_a_dash_is_refused_and_never_read() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let touched = Arc::new(Mutex::new(false));
    let mut stdin = Tripwire(touched.clone());
    let (result, _) = cli_with(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        true,
        &mut stdin,
    )
    .await;
    assert_usage(&result);
    assert!(!*touched.lock().unwrap());
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn tty_stdin_with_a_dash_and_piped_stdin_without_one_both_read() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let value = format!("{MARKER}\n");
    let mut stdin = value.as_bytes();
    let (result, _) = cli_with(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A", "-"],
        true,
        &mut stdin,
    )
    .await;
    result?;
    let (result, _) = cli(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_B"],
        value.as_bytes(),
    )
    .await;
    result?;
    let puts = stub.puts.lock().unwrap().clone();
    assert_eq!(puts.len(), 2);
    assert!(puts.iter().all(|p| p.value == MARKER));
    Ok(())
}

#[tokio::test]
async fn secret_read_accepts_exactly_the_cap_and_refuses_one_more() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let exact = value_of(MAX_SECRET_BYTES);
    for tail in [&b""[..], b"\n", b"\r\n"] {
        let mut input = exact.clone();
        input.extend_from_slice(tail);
        let (result, _) = cli(&url, &["env", "secret", "put", "dev", "TOKEN_A"], &input).await;
        result?;
    }
    let puts = stub.puts.lock().unwrap().clone();
    assert_eq!(puts.len(), 3);
    assert!(puts.iter().all(|p| p.value.len() == MAX_SECRET_BYTES));
    let before = calls(&stub).len();
    let over = value_of(MAX_SECRET_BYTES + 1);
    let (result, _) = cli(&url, &["env", "secret", "put", "dev", "TOKEN_A"], &over).await;
    assert!(result.is_err());
    assert_eq!(calls(&stub).len(), before);
    Ok(())
}

#[tokio::test]
async fn secret_read_stops_one_byte_past_the_cap_on_endless_input() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let served = Arc::new(Mutex::new(0));
    let mut stdin = Filler {
        left: usize::MAX,
        served: served.clone(),
    };
    let (result, out) = cli_with(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        false,
        &mut stdin,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(out, "");
    assert_eq!(*served.lock().unwrap(), MAX_SECRET_BYTES + 1);
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn a_bad_secret_value_is_refused_before_any_rpc() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let inputs: [&[u8]; 6] = [
        b"",
        b"short\n",
        b"aaaaaaaaaaaa\n",
        b"bad\x00value-long-enough\n",
        b"\xff\xfe-not-utf8-but-long\n",
        b"nel\xc2\x85value-long-enough\n",
    ];
    for input in inputs {
        let (result, _) = cli(&url, &["env", "secret", "put", "dev", "TOKEN_A"], input).await;
        assert!(result.is_err());
    }
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn the_secret_value_reaches_the_server_and_nothing_else() -> TestResult {
    let stub = Stub {
        fail_put: Some(Status::internal(format!("echo {MARKER}"))),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let input = format!("{MARKER}\n");
    let (result, out) = cli(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        input.as_bytes(),
    )
    .await;
    assert_eq!(stub.puts.lock().unwrap()[0].value, MARKER);
    let err = result.unwrap_err();
    let text = format!("{err} {err:?}");
    assert!(!text.contains(MARKER), "{text}");
    assert!(!out.contains(MARKER), "{out}");
    let parsed = Cli::try_parse_from(["fleet", "env", "secret", "put", "dev", "TOKEN_A", "-"])?;
    assert!(!format!("{parsed:?}").contains(MARKER));

    let ok = Stub::default();
    let url = serve(ok.clone()).await?;
    let (result, out) = cli(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        input.as_bytes(),
    )
    .await;
    result?;
    assert!(!out.contains(MARKER), "{out}");
    assert!(out.contains("fp-aaaa1111"), "{out}");
    Ok(())
}

#[tokio::test]
async fn a_put_refusal_keeps_its_code_and_a_fixed_message() -> TestResult {
    let stub = Stub {
        fail_put: Some(Status::permission_denied(
            fleet_proto::ERR_ENV_NEEDS_USER_TOKEN,
        )),
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let input = format!("{MARKER}\n");
    let (result, _) = cli(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        input.as_bytes(),
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        err.to_string()
            .contains(fleet_proto::ERR_ENV_NEEDS_USER_TOKEN),
        "{err}"
    );
    assert!(matches!(err, CliError::Rpc(ref s) if s.code() == tonic::Code::PermissionDenied));
    Ok(())
}

#[tokio::test]
async fn a_static_token_refusal_is_printed_plainly() -> TestResult {
    let stub = Stub {
        fail_list: Some(Status::permission_denied(
            fleet_proto::ERR_ENV_NEEDS_USER_TOKEN,
        )),
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (result, _) = cli(&url, &["env", "list"], b"").await;
    let err = result.unwrap_err();
    assert!(
        err.to_string()
            .contains(fleet_proto::ERR_ENV_NEEDS_USER_TOKEN),
        "{err}"
    );
    assert_eq!(err.exit_code(), 1);
    Ok(())
}

fn secret_entry(name: &str, visible: bool, delivery: EnvironmentDelivery) -> EnvironmentEntrySpec {
    EnvironmentEntrySpec {
        kind: Some(Kind::Secret(EnvironmentSecretSpec {
            name: name.into(),
            agent_visible: visible,
            delivery: delivery.into(),
        })),
    }
}

fn script_entry(name: &str, body: &str) -> EnvironmentEntrySpec {
    EnvironmentEntrySpec {
        kind: Some(Kind::Script(EnvironmentScriptSpec {
            name: name.into(),
            body: body.into(),
            on_fail: EnvironmentOnFail::Continue.into(),
            timeout_s: Some(30),
        })),
    }
}

fn detail_with(entries: Vec<EnvironmentEntrySpec>) -> EnvironmentDetail {
    EnvironmentDetail {
        environment: Some(EnvironmentInfo {
            name: "dev".into(),
            latest_version: Some(3),
        }),
        secrets: vec![EnvironmentSecretInfo {
            name: "TOKEN_A".into(),
            fingerprint: "fp-bbbb2222".into(),
        }],
        latest: Some(EnvironmentVersion {
            version: 3,
            hash: "abc123".into(),
            entries,
            egress_hosts: vec!["example.org".into()],
        }),
    }
}

#[tokio::test]
async fn create_list_and_rm_send_the_checked_name_and_print_rows() -> TestResult {
    let stub = Stub {
        list: vec![
            EnvironmentInfo {
                name: "dev".into(),
                latest_version: Some(3),
            },
            EnvironmentInfo {
                name: "ci".into(),
                latest_version: None,
            },
        ],
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(&url, &["env", "list"], b"").await;
    result?;
    assert_eq!(out, "dev\t3\nci\t-\n");
    let (result, _) = cli(&url, &["env", "create", "dev"], b"").await;
    result?;
    let (result, _) = cli(&url, &["env", "rm", "dev"], b"").await;
    result?;
    assert_eq!(stub.creates.lock().unwrap()[0].name, "dev");
    assert_eq!(stub.deletes.lock().unwrap()[0].name, "dev");
    assert_eq!(calls(&stub), ["list", "create", "delete"]);
    for args in [["env", "list", "x"], ["env", "create", "dev"]] {
        let mut extra = args.to_vec();
        extra.push("stray");
        let (result, _) = cli(&url, &extra, b"").await;
        assert_usage(&result);
    }
    assert_eq!(calls(&stub).len(), 3);
    Ok(())
}

#[tokio::test]
async fn show_prints_fingerprints_and_structure_never_values_or_script_bodies() -> TestResult {
    let hostile = format!("evil\u{1b}[31m{TOKEN}\u{202e}");
    let mut detail = detail_with(vec![
        secret_entry("TOKEN_A", true, EnvironmentDelivery::Env),
        script_entry("setup", &format!("#!/bin/sh\necho {MARKER}\n")),
    ]);
    detail.secrets.push(EnvironmentSecretInfo {
        name: "TOKEN_B".into(),
        fingerprint: hostile,
    });
    let stub = Stub {
        detail: Some(detail),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(&url, &["env", "show", "dev"], b"").await;
    result?;
    assert!(out.contains("fp-bbbb2222"), "{out}");
    assert!(out.contains("TOKEN_A"), "{out}");
    assert!(out.contains("setup"), "{out}");
    assert!(out.contains("example.org"), "{out}");
    assert!(!out.contains(MARKER), "{out}");
    assert!(!out.contains(TOKEN), "{out}");
    assert!(
        !out.contains('\u{1b}') && !out.contains('\u{202e}'),
        "{out}"
    );
    assert_eq!(calls(&stub), ["get"]);
    assert_eq!(stub.gets.lock().unwrap()[0].name, "dev");
    Ok(())
}

#[tokio::test]
async fn secret_put_adds_the_entry_and_keeps_the_rest_of_the_structure() -> TestResult {
    let stub = Stub {
        detail: Some(detail_with(vec![script_entry(
            "setup",
            "#!/bin/sh\ntrue\n",
        )])),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let input = format!("{MARKER}\n");
    let (result, out) = cli(
        &url,
        &[
            "env",
            "secret",
            "put",
            "dev",
            "TOKEN_A",
            "--agent",
            "--delivery",
            "env",
        ],
        input.as_bytes(),
    )
    .await;
    result?;
    assert_eq!(calls(&stub), ["get", "put", "save"]);
    let save = stub.saves.lock().unwrap()[0].clone();
    assert_eq!(save.environment, "dev");
    assert_eq!(save.egress_hosts, ["example.org"]);
    assert_eq!(save.entries.len(), 2);
    assert_eq!(save.entries[0], script_entry("setup", "#!/bin/sh\ntrue\n"));
    assert_eq!(
        save.entries[1],
        secret_entry("TOKEN_A", true, EnvironmentDelivery::Env)
    );
    assert!(out.contains("fp-aaaa1111"), "{out}");
    Ok(())
}

#[tokio::test]
async fn secret_put_defaults_to_setup_only_file_delivery_and_keeps_an_existing_spec() -> TestResult
{
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let input = format!("{MARKER}\n");
    let (result, _) = cli(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        input.as_bytes(),
    )
    .await;
    result?;
    assert_eq!(
        stub.saves.lock().unwrap()[0].entries,
        [secret_entry("TOKEN_A", false, EnvironmentDelivery::File)]
    );
    let kept = Stub {
        detail: Some(detail_with(vec![secret_entry(
            "TOKEN_A",
            true,
            EnvironmentDelivery::Env,
        )])),
        ..Stub::default()
    };
    let url = serve(kept.clone()).await?;
    let (result, _) = cli(
        &url,
        &["env", "secret", "put", "dev", "TOKEN_A"],
        input.as_bytes(),
    )
    .await;
    result?;
    assert_eq!(
        kept.saves.lock().unwrap()[0].entries,
        [secret_entry("TOKEN_A", true, EnvironmentDelivery::Env)]
    );
    Ok(())
}

#[tokio::test]
async fn env_delivery_without_agent_and_a_script_name_clash_are_refused_without_a_put() -> TestResult
{
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let input = format!("{MARKER}\n");
    let (result, _) = cli(
        &url,
        &[
            "env",
            "secret",
            "put",
            "dev",
            "TOKEN_A",
            "--delivery",
            "env",
        ],
        input.as_bytes(),
    )
    .await;
    assert_usage(&result);
    assert_eq!(calls(&stub), Vec::<&str>::new());
    let clash = Stub {
        detail: Some(detail_with(vec![script_entry(
            "TOKEN_A",
            "#!/bin/sh\ntrue\n",
        )])),
        ..Stub::default()
    };
    let url = serve(clash.clone()).await?;
    let (result, _) = cli(
        &url,
        &["env", "secret", "put", "dev", "token_a"],
        input.as_bytes(),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls(&clash), ["get"]);
    Ok(())
}

#[tokio::test]
async fn script_add_reads_stdin_or_a_file_and_replaces_a_same_named_script() -> TestResult {
    let stub = Stub {
        detail: Some(detail_with(vec![
            secret_entry("TOKEN_A", false, EnvironmentDelivery::File),
            script_entry("setup", "#!/bin/sh\nold\n"),
        ])),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(
        &url,
        &[
            "env",
            "script",
            "add",
            "dev",
            "setup",
            "-",
            "--on-fail",
            "abort",
            "--timeout",
            "45",
        ],
        b"#!/bin/sh\nnew\n",
    )
    .await;
    result?;
    assert!(out.contains("setup"), "{out}");
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("s.sh");
    std::fs::write(&path, "#!/bin/sh\nfrom-file\n")?;
    let (result, _) = cli(
        &url,
        &[
            "env",
            "script",
            "add",
            "dev",
            "other",
            path.to_str().unwrap(),
        ],
        b"",
    )
    .await;
    result?;
    let saves = stub.saves.lock().unwrap().clone();
    assert_eq!(saves.len(), 2);
    assert_eq!(saves[0].egress_hosts, ["example.org"]);
    assert_eq!(saves[0].entries.len(), 2);
    assert_eq!(
        saves[0].entries[0],
        secret_entry("TOKEN_A", false, EnvironmentDelivery::File)
    );
    assert_eq!(
        saves[0].entries[1],
        EnvironmentEntrySpec {
            kind: Some(Kind::Script(EnvironmentScriptSpec {
                name: "setup".into(),
                body: "#!/bin/sh\nnew\n".into(),
                on_fail: EnvironmentOnFail::Abort.into(),
                timeout_s: Some(45),
            })),
        }
    );
    let Some(Kind::Script(added)) = &saves[1].entries[2].kind else {
        return Err("no script".into());
    };
    assert_eq!(added.name, "other");
    assert_eq!(added.body, "#!/bin/sh\nfrom-file\n");
    Ok(())
}

#[tokio::test]
async fn script_add_bounds_its_read_and_checks_the_body_before_any_rpc() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let head = b"#!/bin/sh\n";
    let mut exact = head.to_vec();
    exact.extend(value_of(MAX_SCRIPT_BYTES - head.len()));
    let (result, _) = cli(&url, &["env", "script", "add", "dev", "setup", "-"], &exact).await;
    result?;
    let before = calls(&stub).len();
    let served = Arc::new(Mutex::new(0));
    let mut endless = Filler {
        left: usize::MAX,
        served: served.clone(),
    };
    let (result, _) = cli_with(
        &url,
        &["env", "script", "add", "dev", "setup", "-"],
        false,
        &mut endless,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(*served.lock().unwrap(), MAX_SCRIPT_BYTES + 1);
    let mut over = exact.clone();
    over.push(b'a');
    let (result, _) = cli(&url, &["env", "script", "add", "dev", "setup", "-"], &over).await;
    assert!(result.is_err());
    for bad in [&b""[..], b"echo no shebang\n", b"#!/bin/sh\x00\n"] {
        let (result, _) = cli(&url, &["env", "script", "add", "dev", "setup", "-"], bad).await;
        assert!(result.is_err());
    }
    let (result, _) = cli(
        &url,
        &[
            "env",
            "script",
            "add",
            "dev",
            "setup",
            "-",
            "--timeout",
            "601",
        ],
        head,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls(&stub).len(), before);
    Ok(())
}

#[tokio::test]
async fn script_add_refuses_a_name_held_by_a_secret_and_saves_nothing() -> TestResult {
    let stub = Stub {
        detail: Some(detail_with(vec![secret_entry(
            "TOKEN_A",
            false,
            EnvironmentDelivery::File,
        )])),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, _) = cli(
        &url,
        &["env", "script", "add", "dev", "token_a", "-"],
        b"#!/bin/sh\n",
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls(&stub), ["get"]);
    Ok(())
}

#[tokio::test]
async fn script_rm_drops_only_that_script_and_an_unknown_one_saves_nothing() -> TestResult {
    let stub = Stub {
        detail: Some(detail_with(vec![
            secret_entry("TOKEN_A", false, EnvironmentDelivery::File),
            script_entry("setup", "#!/bin/sh\ntrue\n"),
        ])),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, _) = cli(&url, &["env", "script", "rm", "dev", "setup"], b"").await;
    result?;
    assert_eq!(
        stub.saves.lock().unwrap()[0].entries,
        [secret_entry("TOKEN_A", false, EnvironmentDelivery::File)]
    );
    let (result, _) = cli(&url, &["env", "script", "rm", "dev", "TOKEN_A"], b"").await;
    assert!(result.is_err());
    let (result, _) = cli(&url, &["env", "script", "rm", "dev", "nothing"], b"").await;
    assert!(result.is_err());
    assert_eq!(calls(&stub), ["get", "save", "get", "get"]);
    Ok(())
}

fn hostile_profiles() -> Vec<String> {
    let mut names = hostile_names();
    names.extend(["a@b", "a.b", "a\\b", "[::1]"].map(str::to_owned));
    names
}

fn hostile_repos() -> Vec<String> {
    let mut refs: Vec<String> = [
        "",
        "github.com/octo",
        "github.com/a/b/c",
        "http://github.com/a/b",
        "github.com/a/%41",
        "github.com/a b/c",
        "github.com/a/b;c",
        "github.com/a/b\r",
        "github.com/a/b\r\n",
        "github.com/a/b\u{85}",
        "github.com/a/b\u{2028}",
        "user@github.com/a/b",
        "github.com\\a/b",
        "[::1]/a/b",
        "example.com:80/a/b",
        "github.com/./b",
        "github.com/a/..",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    refs.push(format!("github.com/{}/b", "a".repeat(4096)));
    refs
}

#[tokio::test]
async fn hostile_names_on_every_default_action_are_refused_before_any_rpc() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    for action in ["set", "show", "clear"] {
        if action == "set" {
            for bad in hostile_names() {
                let args = ["env", "default", "set", &bad, "--profile", "reviewer"];
                let (result, out) = cli(&url, &args, b"").await;
                assert_usage(&result);
                assert_eq!(out, "");
            }
        }
        for bad in hostile_profiles() {
            let mut args = vec!["env", "default", action];
            if action == "set" {
                args.push("ci");
            }
            args.extend(["--profile", &bad]);
            let (result, out) = cli(&url, &args, b"").await;
            assert_usage(&result);
            assert_eq!(out, "");
        }
        for bad in hostile_repos() {
            let mut args = vec!["env", "default", action];
            if action == "set" {
                args.push("ci");
            }
            args.extend(["--repo", &bad]);
            let (result, out) = cli(&url, &args, b"").await;
            assert_usage(&result);
            assert_eq!(out, "");
        }
    }
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn a_default_needs_exactly_one_key_and_takes_no_stray_arguments() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let both = [
        "env",
        "default",
        "show",
        "--repo",
        "github.com/a/b",
        "--profile",
        "p",
    ];
    assert!(Cli::try_parse_from(["fleet", "--server", &url].into_iter().chain(both)).is_err());
    let none = ["env", "default", "show"];
    assert!(Cli::try_parse_from(["fleet", "--server", &url].into_iter().chain(none)).is_err());
    let (result, _) = cli(
        &url,
        &["env", "default", "set", "ci", "--profile", "p", "extra"],
        b"",
    )
    .await;
    assert_usage(&result);
    let (result, _) = cli(
        &url,
        &["env", "default", "show", "--profile", "p", "x"],
        b"",
    )
    .await;
    assert_usage(&result);
    assert_eq!(calls(&stub), Vec::<&str>::new());
    Ok(())
}

#[tokio::test]
async fn set_show_and_clear_send_the_checked_key_by_repo_or_profile() -> TestResult {
    let stub = Stub {
        bound: Some("ci".into()),
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(
        &url,
        &[
            "env",
            "default",
            "set",
            "ci",
            "--repo",
            "GitHub.com/Octo/Hello.git",
        ],
        b"",
    )
    .await;
    result?;
    assert_eq!(out, "bound\tci\n");
    let (result, out) = cli(
        &url,
        &["env", "default", "set", "ci", "--profile", "rev_1"],
        b"",
    )
    .await;
    result?;
    assert_eq!(out, "bound\tci\n");
    let (result, out) = cli(
        &url,
        &["env", "default", "show", "--repo", "github.com/octo/hello"],
        b"",
    )
    .await;
    result?;
    assert_eq!(out, "ci\n");
    let (result, out) = cli(&url, &["env", "default", "show", "--profile", "rev_1"], b"").await;
    result?;
    assert_eq!(out, "ci\n");
    let (result, out) = cli(
        &url,
        &["env", "default", "clear", "--repo", "github.com/octo/hello"],
        b"",
    )
    .await;
    result?;
    assert_eq!(out, "cleared\n");
    let (result, out) = cli(
        &url,
        &["env", "default", "clear", "--profile", "rev_1"],
        b"",
    )
    .await;
    result?;
    assert_eq!(out, "cleared\n");
    assert_eq!(
        calls(&stub),
        [
            "set_default",
            "set_default",
            "get_default",
            "get_default",
            "clear_default",
            "clear_default"
        ]
    );
    let sets = stub.sets.lock().unwrap();
    assert_eq!(sets[0].environment, "ci");
    let Some(Key::Repo(repo)) = sets[0].key.clone().and_then(|k| k.key) else {
        panic!("repo key expected");
    };
    assert_eq!(
        (repo.host.as_str(), repo.path.as_str()),
        ("github.com", "octo/hello")
    );
    assert_eq!(
        sets[1].key.clone().and_then(|k| k.key),
        Some(Key::Profile("rev_1".into()))
    );
    let gets = stub.default_gets.lock().unwrap();
    assert_eq!(
        gets[1].key.clone().and_then(|k| k.key),
        Some(Key::Profile("rev_1".into()))
    );
    let clears = stub.clears.lock().unwrap();
    assert!(matches!(
        clears[0].key.clone().and_then(|k| k.key),
        Some(Key::Repo(_))
    ));
    assert_eq!(
        clears[1].key.clone().and_then(|k| k.key),
        Some(Key::Profile("rev_1".into()))
    );
    Ok(())
}

#[tokio::test]
async fn show_of_an_unbound_key_prints_none_and_a_refusal_keeps_its_code() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["env", "default", "show", "--profile", "p"], b"").await;
    result?;
    assert_eq!(out, "none\n");
    let stub = Stub {
        fail_default: Some(Status::not_found("environment binding key not found")),
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (result, out) = cli(
        &url,
        &["env", "default", "set", "ci", "--profile", "p"],
        b"",
    )
    .await;
    let Err(CliError::Rpc(status)) = result else {
        panic!("rpc refusal expected");
    };
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert_eq!(out, "");
    Ok(())
}
