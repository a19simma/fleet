//! Runs the `fleet` binary and checks its process exit codes.

use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fleet(env: &[(&str, &str)], args: &[&str]) -> Result<std::process::Output, std::io::Error> {
    let home = tempfile::tempdir()?;
    Command::new(env!("CARGO_BIN_EXE_fleet"))
        .env_clear()
        .env("HOME", home.path())
        .envs(env.iter().copied())
        .args(args)
        .output()
}

#[test]
fn missing_configuration_exits_two() -> TestResult {
    let out = fleet(&[], &["jobs"])?;
    assert_eq!(out.status.code(), Some(2));
    Ok(())
}

#[test]
fn clap_usage_error_exits_two() -> TestResult {
    let out = fleet(&[], &["submit"])?;
    assert_eq!(out.status.code(), Some(2));
    Ok(())
}

#[test]
fn plain_http_to_a_remote_host_exits_two_without_printing_the_token() -> TestResult {
    let out = fleet(
        &[
            ("FLEET_SERVER_URL", "http://example.invalid:7070"),
            ("FLEET_CLIENT_TOKEN", "secret-token-value"),
        ],
        &["jobs"],
    )?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("secret-token-value"), "{stderr}");
    Ok(())
}

#[test]
fn connection_failure_exits_one() -> TestResult {
    let out = fleet(
        &[
            ("FLEET_SERVER_URL", "http://127.0.0.1:1"),
            ("FLEET_CLIENT_TOKEN", "t"),
        ],
        &["jobs"],
    )?;
    assert_eq!(out.status.code(), Some(1));
    Ok(())
}
