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

#[test]
fn bad_stats_window_exits_two_before_connecting() -> TestResult {
    let out = fleet(
        &[
            ("FLEET_SERVER_URL", "http://127.0.0.1:1"),
            ("FLEET_CLIENT_TOKEN", "t"),
        ],
        &["stats", "--since", "soon"],
    )?;
    assert_eq!(out.status.code(), Some(2));
    Ok(())
}

const OFFLINE: [(&str, &str); 2] = [
    ("FLEET_SERVER_URL", "http://127.0.0.1:1"),
    ("FLEET_CLIENT_TOKEN", "t"),
];

fn submit_with_agent(agent: &[&str]) -> Result<std::process::Output, std::io::Error> {
    let mut args = vec!["submit", "--repo", "r", "--base", "main"];
    args.extend_from_slice(agent);
    args.push("fix it");
    fleet(&OFFLINE, &args)
}

fn batch_with_agent(agent: &[&str]) -> Result<std::process::Output, std::io::Error> {
    let mut args = vec![
        "batch",
        "submit",
        "--repo",
        "r",
        "--base",
        "0123456789abcdef0123456789abcdef01234567",
        "--profiles",
        "alpha",
        "--prompt",
        "fix it",
    ];
    args.extend_from_slice(agent);
    fleet(&OFFLINE, &args)
}

#[test]
fn unknown_submit_agent_exits_two_before_connecting() -> TestResult {
    let out = submit_with_agent(&["--agent", "gpt"])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("claude"), "{stderr}");
    Ok(())
}

#[test]
fn unknown_batch_agent_exits_two_before_connecting() -> TestResult {
    let out = batch_with_agent(&["--agent", "gpt"])?;
    assert_eq!(out.status.code(), Some(2));
    Ok(())
}

#[test]
fn empty_and_wrong_case_agents_are_rejected() -> TestResult {
    for agent in ["", "Claude", "claude "] {
        assert_eq!(
            submit_with_agent(&["--agent", agent])?.status.code(),
            Some(2)
        );
        assert_eq!(
            batch_with_agent(&["--agent", agent])?.status.code(),
            Some(2)
        );
    }
    Ok(())
}

#[test]
fn known_and_absent_agents_pass_parsing_and_reach_the_network() -> TestResult {
    for agent in [
        &["--agent", "claude"][..],
        &["--agent", "codex"],
        &["--agent", "kimi"],
        &[],
    ] {
        assert_eq!(
            submit_with_agent(agent)?.status.code(),
            Some(1),
            "{agent:?}"
        );
        assert_eq!(batch_with_agent(agent)?.status.code(), Some(1), "{agent:?}");
    }
    Ok(())
}
