//! The install unit wrapper: the in-namespace forwarder, the proxy environment of the install
//! child and the refusals before anything runs. The child is a shell script standing in for mise.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use fleetd::agent_exec::{
    TOOL_INSTALL_ARGS, ToolInstallError, apply_proxy_env, exec_tool_install, run_tool_install,
};
use fleetd::jobsock::{
    JobContext, JobSocket, Limits, Peer, PeerId, ServeFuture, Service, ServiceName, Services,
    TOOL_INSTALL_SLICE, socket_path,
};
use fleetd::tools::{MisePins, MisePinsConfig};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const ID: &str = "job_1";
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

struct InstallPeer;

impl Peer for InstallPeer {
    fn identity(&self, _: &UnixStream) -> std::io::Result<PeerId> {
        Ok(PeerId {
            pid: 1,
            cgroup: format!("0::/{TOOL_INSTALL_SLICE}/fleet-tool-install@{ID}.service\n"),
        })
    }
}

struct Echo;

impl Service for Echo {
    fn serve(&self, _: JobContext, mut stream: UnixStream) -> ServeFuture<'_> {
        Box::pin(async move {
            let mut buf = [0_u8; 4];
            if stream.read_exact(&mut buf).await.is_ok() {
                let _ = stream.write_all(&buf).await;
            }
        })
    }
}

fn run_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::DirBuilder::new()
        .mode(0o750)
        .create(dir.path().join(ID))
        .unwrap();
    dir
}

fn script(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("fake-mise");
    fs::write(&path, format!("#!/bin/bash\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn ephemeral() -> SocketAddr {
    SocketAddr::from((LOOPBACK, 0))
}

#[test]
fn the_child_gets_install_locked_and_the_forwarder_proxy_env() {
    let dir = run_dir();
    let out = dir.path().join("seen");
    let program = script(
        dir.path(),
        &format!(
            "printf '%s|%s|%s|%s|%s|%s\\n' \"$*\" \"$HTTPS_PROXY\" \"$http_proxy\" \"${{NO_PROXY-unset}}\" \"${{ALL_PROXY-unset}}\" \"$https_proxy\" > {}\nexit 7",
            out.display()
        ),
    );
    let code = run_tool_install(dir.path(), ID, &program, ephemeral()).unwrap();
    assert_eq!(code, 7);
    let seen = fs::read_to_string(&out).unwrap();
    let fields: Vec<&str> = seen.trim_end().split('|').collect();
    assert_eq!(fields[0], TOOL_INSTALL_ARGS.join(" "));
    assert_eq!(TOOL_INSTALL_ARGS, ["install", "--locked"]);
    assert!(fields[1].starts_with("http://127.0.0.1:"), "{seen}");
    assert_eq!(fields[1], fields[2]);
    assert_eq!(fields[1], fields[5]);
    assert_eq!(&fields[3..5], ["unset", "unset"]);
}

#[test]
fn the_proxy_env_overrides_the_four_urls_and_removes_the_bypass_variables() {
    let mut command = Command::new("true");
    for name in [
        "HTTPS_PROXY",
        "http_proxy",
        "NO_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(name, "stale");
    }
    apply_proxy_env(&mut command, "http://127.0.0.1:9");
    let env: std::collections::BTreeMap<String, Option<String>> = command
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        assert_eq!(env[name].as_deref(), Some("http://127.0.0.1:9"), "{name}");
    }
    for name in ["NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"] {
        assert_eq!(env.get(name), Some(&None), "{name}");
    }
}

#[test]
fn a_port_in_use_fails_before_the_child_runs() {
    let dir = run_dir();
    let taken = std::net::TcpListener::bind(ephemeral()).unwrap();
    let ran = dir.path().join("ran");
    let program = script(dir.path(), &format!("touch {}", ran.display()));
    let err = run_tool_install(dir.path(), ID, &program, taken.local_addr().unwrap()).unwrap_err();
    assert_eq!(err, ToolInstallError::Listen(std::io::ErrorKind::AddrInUse));
    assert!(!ran.exists());
}

#[test]
fn a_missing_program_reports_exec() {
    let dir = run_dir();
    let err =
        run_tool_install(dir.path(), ID, &dir.path().join("absent"), ephemeral()).unwrap_err();
    assert_eq!(err, ToolInstallError::Exec(std::io::ErrorKind::NotFound));
}

#[test]
fn a_bad_id_is_refused_before_any_listener() {
    let dir = run_dir();
    let program = script(dir.path(), "exit 0");
    for id in ["", "..", "a/b", "a b", "job\n1"] {
        let err = run_tool_install(dir.path(), id, &program, ephemeral()).unwrap_err();
        assert_eq!(err, ToolInstallError::InvalidId, "{id:?}");
    }
}

#[test]
fn missing_pins_exit_with_the_fixed_message_and_start_nothing() {
    let dir = run_dir();
    let ran = dir.path().join("ran");
    let program = script(dir.path(), &format!("touch {}", ran.display()));
    let err = exec_tool_install(dir.path(), ID, &program, None, 0);
    assert_eq!(err, ToolInstallError::MissingPins);
    assert_eq!(err.to_string(), "mise pins are not configured");
    assert!(!ran.exists());
}

#[test]
fn an_unverifiable_binary_is_refused_and_never_run() {
    let dir = run_dir();
    let ran = dir.path().join("ran");
    let program = script(dir.path(), &format!("touch {}", ran.display()));
    let pins = MisePins::new(MisePinsConfig {
        version: Some("2025.1.1".to_owned()),
        sha256: Some("0".repeat(64)),
        signature_path: Some(dir.path().join("sig")),
        public_key_path: Some(dir.path().join("key")),
    })
    .unwrap();
    let err = exec_tool_install(dir.path(), ID, &program, Some(&pins), 0);
    assert_eq!(err, ToolInstallError::Unverified);
    assert_eq!(err.to_string(), "bundled mise failed verification");
    assert!(!ran.exists());
}

#[test]
fn an_invalid_id_beats_missing_pins() {
    let dir = run_dir();
    let program = script(dir.path(), "exit 0");
    assert_eq!(
        exec_tool_install(dir.path(), "a/b", &program, None, 0),
        ToolInstallError::InvalidId
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_install_child_reaches_the_egress_proxy_through_the_forwarder() {
    let dir = run_dir();
    let mut services = Services::new();
    services.insert(ServiceName::EgressProxy, Arc::new(Echo));
    let socket = JobSocket::bind(
        &socket_path(dir.path(), ID).unwrap(),
        ID,
        services,
        Arc::new(InstallPeer),
        Limits::default(),
    )
    .unwrap();
    let out = dir.path().join("reply");
    let program = script(
        dir.path(),
        &format!(
            "hp=${{HTTPS_PROXY#http://}}\nexec 3<>/dev/tcp/${{hp%:*}}/${{hp##*:}}\nprintf ping >&3\nread -r -n 4 -t 10 reply <&3\nprintf '%s' \"$reply\" > {}",
            out.display()
        ),
    );
    let root = dir.path().to_path_buf();
    let code = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || run_tool_install(&root, ID, &program, ephemeral())),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(fs::read_to_string(&out).unwrap(), "ping");
    assert_eq!(socket.rejected(), 0);
}

fn run_binary(config: &str, id: &str) -> (Option<i32>, String, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, config).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .arg("--config")
        .arg(&path)
        .args(["tool-install-exec", id, "--run-dir"])
        .arg(dir.path())
        .env_clear()
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_subcommand_exits_2_with_a_fixed_message_when_pins_are_absent() {
    let (code, stdout, stderr) = run_binary("", ID);
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "fleetd tool-install-exec: mise pins are not configured\n"
    );
}

#[test]
fn the_subcommand_refuses_a_bad_id_and_a_partial_pin_table() {
    let (code, _, stderr) = run_binary("", "bad-id");
    assert_eq!(code, Some(2));
    assert_eq!(stderr, "fleetd tool-install-exec: job id is not valid\n");
    let (code, _, stderr) = run_binary("[mise]\nversion = \"2025.1.1\"\n", ID);
    assert_eq!(code, Some(2));
    assert_eq!(
        stderr,
        "fleetd tool-install-exec: mise pin sha256 is missing\n"
    );
}

#[test]
fn the_subcommand_refuses_pins_whose_binary_is_not_the_bundled_one() {
    let config = format!(
        "[mise]\nversion = \"2025.1.1\"\nsha256 = \"{}\"\nsignature_path = \"/nonexistent/sig\"\npublic_key_path = \"/nonexistent/key\"\n",
        "0".repeat(64)
    );
    let (code, _, stderr) = run_binary(&config, ID);
    assert_eq!(code, Some(2));
    assert_eq!(
        stderr,
        "fleetd tool-install-exec: bundled mise failed verification\n"
    );
}
