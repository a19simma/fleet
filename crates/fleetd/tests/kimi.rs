//! Kimi Code runner tests: argv, child environment, per-job home and the Floor.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fleetd::agent::kimi::{self, KimiHome, KimiJob};
use fleetd::agent::{AgentRunner, resolve};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn job<'a>(cwd: &'a Path, model: Option<&'a str>) -> KimiJob<'a> {
    KimiJob {
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

fn pair(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
}

#[test]
fn the_kimi_name_resolves_to_kimi() {
    let runner = resolve("kimi");
    assert_eq!(runner.map(AgentRunner::name), Some("kimi"));
    assert_eq!(
        runner.map(AgentRunner::config_dir_env),
        Some("KIMI_CODE_HOME")
    );
}

#[test]
fn the_kimi_argv_is_golden() {
    let argv = strings(&kimi::argv(
        Path::new("kimi"),
        &job(Path::new("/work"), Some("k2")),
    ));
    assert_eq!(
        argv,
        [
            "kimi",
            "--print",
            "--output-format",
            "stream-json",
            "--work-dir",
            "/work",
            "--model",
            "k2",
            "--prompt=-fix it",
        ]
    );
}

#[test]
fn the_kimi_argv_omits_the_model_when_unset() {
    let argv = strings(&kimi::argv(Path::new("kimi"), &job(Path::new("/w"), None)));
    assert!(!argv.contains(&"--model".to_owned()));
}

#[test]
fn the_kimi_argv_never_loosens_the_floor() {
    let argv = strings(&kimi::argv(Path::new("kimi"), &job(Path::new("/w"), None)));
    for flag in ["--yolo", "-y", "--yes", "--auto-approve", "--afk"] {
        assert!(!argv.iter().any(|arg| arg == flag), "{flag}");
    }
}

#[test]
fn only_the_kimi_api_key_reaches_the_child_env() {
    let base = [
        pair("PATH", "/bin"),
        pair("LC_ALL", "C"),
        pair("HTTPS_PROXY", "http://p:1"),
        pair("KIMI_API_KEY", "host-key"),
        pair("MOONSHOT_API_KEY", "host-key"),
        pair("ANTHROPIC_API_KEY", "sk-ant"),
        pair("CODEX_API_KEY", "x"),
        pair("GH_TOKEN", "gh"),
        pair("FLEET_TOKEN", "fleet"),
        pair("SSH_AUTH_SOCK", "/s"),
        pair("KIMI_CODE_HOME", "/operator"),
    ];
    let env = kimi::env(
        &base,
        "sk-kimi-job",
        "job1",
        Path::new("/h"),
        Path::new("/h/kimi"),
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
    assert_eq!(secrets, [&OsString::from(kimi::API_KEY_ENV)]);
    assert_eq!(
        env.get(&OsString::from(kimi::API_KEY_ENV)),
        Some(&OsString::from("sk-kimi-job"))
    );
    assert_eq!(
        env.get(&OsString::from("KIMI_CODE_HOME")),
        Some(&OsString::from("/h/kimi"))
    );
    assert_eq!(
        env.get(&OsString::from("HTTPS_PROXY")),
        Some(&OsString::from("http://p:1"))
    );
    assert!(env.contains_key(&OsString::from("LC_ALL")));
}

#[test]
fn the_per_job_kimi_home_is_private_and_removed_on_drop() -> TestResult {
    let root = TempDir::new()?;
    let home = KimiHome::create(root.path(), "job1")?;
    let path = home.path().to_path_buf();
    assert_eq!(path, root.path().join(".kimi").join("job1"));
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o700
    );
    let config = path.join("config.toml");
    assert_eq!(
        std::fs::metadata(&config)?.permissions().mode() & 0o777,
        0o600
    );
    drop(home);
    assert!(!path.exists());
    assert!(root.path().join(".kimi").exists());
    Ok(())
}

#[test]
fn a_kimi_home_rejects_a_bad_job_id() -> TestResult {
    let root = TempDir::new()?;
    for id in ["", "..", "a/b"] {
        assert!(KimiHome::create(root.path(), id).is_err());
    }
    Ok(())
}

#[test]
fn the_config_names_the_key_variable_and_never_holds_the_key() -> TestResult {
    let config: toml::Table = kimi::CONFIG_TOML.parse()?;
    assert_eq!(
        config["providers"]["kimi"]["api_key_env"].as_str(),
        Some(kimi::API_KEY_ENV)
    );
    assert!(config["providers"]["kimi"].get("api_key").is_none());
    assert!(!kimi::CONFIG_TOML.contains("sk-kimi-"));
    Ok(())
}

#[test]
fn a_deny_holds_with_hooks_absent() -> TestResult {
    let config: toml::Table = kimi::CONFIG_TOML.parse()?;
    assert_eq!(config["default_yolo"].as_bool(), Some(false));
    assert!(config.get("hooks").is_none());

    let root = TempDir::new()?;
    let home = KimiHome::create(root.path(), "job1")?;
    assert_eq!(
        std::fs::read_to_string(home.path().join("config.toml"))?,
        kimi::CONFIG_TOML
    );
    assert!(!home.path().join("hooks.json").exists());
    let entries = std::fs::read_dir(home.path())?.count();
    assert_eq!(entries, 1);
    Ok(())
}

#[test]
fn the_user_agent_is_left_alone() {
    let argv = strings(&kimi::argv(Path::new("kimi"), &job(Path::new("/w"), None)));
    assert!(
        !argv
            .iter()
            .any(|arg| arg.to_lowercase().contains("user-agent"))
    );
    let lower = kimi::CONFIG_TOML.to_lowercase();
    assert!(!lower.contains("user-agent") && !lower.contains("user_agent"));
    assert!(!lower.contains("headers"));
    let env = kimi::env(&[], "k", "job1", Path::new("/h"), Path::new("/h/kimi"));
    assert!(
        env.keys()
            .all(|name| !name.to_string_lossy().to_uppercase().contains("USER_AGENT"))
    );
}
