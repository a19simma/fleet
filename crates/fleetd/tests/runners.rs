//! Agent name resolution and Codex runner tests.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fleetd::agent::codex::{self, CodexHome, CodexJob};
use fleetd::agent::{ERR_UNKNOWN_AGENT, resolve};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn an_empty_agent_name_resolves_to_claude() {
    assert_eq!(
        resolve("").map(fleetd::agent::AgentRunner::name),
        Some("claude")
    );
}

#[test]
fn the_claude_name_resolves_to_claude() {
    assert_eq!(
        resolve("claude").map(fleetd::agent::AgentRunner::name),
        Some("claude")
    );
}

#[test]
fn an_unknown_agent_name_resolves_to_nothing() {
    assert!(resolve("kimi").is_none());
    assert!(resolve("Claude").is_none());
    assert_eq!(ERR_UNKNOWN_AGENT, "agent is not supported");
}

#[test]
fn the_codex_name_resolves_to_codex() {
    assert_eq!(
        resolve("codex").map(fleetd::agent::AgentRunner::name),
        Some("codex")
    );
}

fn job<'a>(cwd: &'a Path, model: Option<&'a str>) -> CodexJob<'a> {
    CodexJob {
        prompt: "-fix it",
        cwd,
        model,
    }
}

fn strings(argv: &[OsString]) -> Vec<String> {
    argv.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn the_codex_argv_is_golden() {
    let argv = strings(&codex::argv(
        Path::new("codex"),
        &job(Path::new("/work"), Some("o3")),
    ));
    assert_eq!(
        argv,
        [
            "codex",
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--cd",
            "/work",
            "--sandbox",
            "workspace-write",
            "-c",
            "approval_policy=\"never\"",
            "-c",
            "features.hooks=false",
            "-c",
            "sandbox_workspace_write.network_access=false",
            "--model",
            "o3",
            "--",
            "-fix it",
        ]
    );
}

#[test]
fn the_codex_argv_omits_the_model_when_unset() {
    let argv = strings(&codex::argv(
        Path::new("codex"),
        &job(Path::new("/w"), None),
    ));
    assert!(!argv.contains(&"--model".to_owned()));
}

#[test]
fn the_codex_argv_never_loosens_the_floor() {
    let argv = strings(&codex::argv(
        Path::new("codex"),
        &job(Path::new("/w"), None),
    ));
    for flag in [
        "--ignore-rules",
        "--dangerously-bypass-hook-trust",
        "--dangerously-bypass-approvals-and-sandbox",
        "--full-auto",
        "danger-full-access",
    ] {
        assert!(!argv.iter().any(|arg| arg == flag), "{flag}");
    }
}

fn pair(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
}

#[test]
fn only_the_codex_api_key_reaches_the_child_env() {
    let base = [
        pair("PATH", "/bin"),
        pair("LC_ALL", "C"),
        pair("HTTPS_PROXY", "http://p:1"),
        pair("CODEX_API_KEY", "host-key"),
        pair("OPENAI_API_KEY", "sk-host"),
        pair("ANTHROPIC_API_KEY", "sk-ant"),
        pair("CLAUDE_CODE_OAUTH_TOKEN", "oauth"),
        pair("GH_TOKEN", "gh"),
        pair("GITHUB_TOKEN", "gh"),
        pair("FLEET_TOKEN", "fleet"),
        pair("FLEETD_ASKPASS", "x"),
        pair("SSH_AUTH_SOCK", "/s"),
        pair("CODEX_HOME", "/operator"),
    ];
    let env = codex::env(
        &base,
        "job-key",
        "job1",
        Path::new("/h"),
        Path::new("/h/codex"),
    );
    let secrets: Vec<_> = env
        .keys()
        .filter(|name| {
            let name = name.to_string_lossy().to_uppercase();
            ["KEY", "TOKEN", "SECRET", "PASS", "AUTH_SOCK"]
                .iter()
                .any(|part| name.contains(part))
        })
        .collect();
    assert_eq!(secrets, [&OsString::from("CODEX_API_KEY")]);
    assert_eq!(
        env.get(&OsString::from("CODEX_API_KEY")),
        Some(&OsString::from("job-key"))
    );
    assert_eq!(
        env.get(&OsString::from("CODEX_HOME")),
        Some(&OsString::from("/h/codex"))
    );
    assert_eq!(
        env.get(&OsString::from("HOME")),
        Some(&OsString::from("/h"))
    );
    assert_eq!(
        env.get(&OsString::from("HTTPS_PROXY")),
        Some(&OsString::from("http://p:1"))
    );
    assert!(env.contains_key(&OsString::from("LC_ALL")));
}

#[test]
fn the_per_job_codex_home_is_private_and_removed_on_drop() -> TestResult {
    let root = TempDir::new()?;
    let home = CodexHome::create(root.path(), "job1")?;
    let path = home.path().to_path_buf();
    assert_eq!(path, root.path().join(".codex").join("job1"));
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o700
    );
    let config = path.join("config.toml");
    assert_eq!(
        std::fs::metadata(&config)?.permissions().mode() & 0o777,
        0o600
    );
    std::fs::write(path.join("auth.json"), "secret")?;
    drop(home);
    assert!(!path.exists());
    assert!(root.path().join(".codex").exists());
    Ok(())
}

#[test]
fn a_codex_home_rejects_a_bad_job_id() -> TestResult {
    let root = TempDir::new()?;
    for id in ["", "..", "a/b"] {
        assert!(CodexHome::create(root.path(), id).is_err());
    }
    Ok(())
}

#[test]
fn a_deny_holds_with_hooks_disabled() -> TestResult {
    let argv = strings(&codex::argv(
        Path::new("codex"),
        &job(Path::new("/w"), None),
    ));
    let has = |pair: [&str; 2]| argv.windows(2).any(|w| w == pair);
    assert!(has(["-c", "features.hooks=false"]));
    assert!(has(["--sandbox", "workspace-write"]));
    assert!(has(["-c", "approval_policy=\"never\""]));
    assert!(has(["-c", "sandbox_workspace_write.network_access=false"]));

    let config: toml::Table = codex::CONFIG_TOML.parse()?;
    assert_eq!(config["features"]["hooks"].as_bool(), Some(false));
    assert_eq!(config["approval_policy"].as_str(), Some("never"));
    assert_eq!(config["sandbox_mode"].as_str(), Some("workspace-write"));
    assert_eq!(
        config["sandbox_workspace_write"]["network_access"].as_bool(),
        Some(false)
    );
    for word in ["git", "gh", "curl"] {
        assert!(
            codex::RULES
                .lines()
                .any(|line| line.contains(&format!("[\"{word}\"")) && line.contains("forbidden")),
            "{word}"
        );
    }

    let root = TempDir::new()?;
    let home = CodexHome::create(root.path(), "job1")?;
    assert!(!home.path().join("hooks.json").exists());
    assert_eq!(
        std::fs::read_to_string(home.path().join("rules").join("default.rules"))?,
        codex::RULES
    );
    Ok(())
}
