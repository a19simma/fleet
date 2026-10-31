//! Kimi Code runner tests: argv, child environment, per-job home and the Floor.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fleetd::agent::kimi::{self, KimiHome, KimiJob};
use fleetd::agent::{AgentRunner, resolve};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn job(model: Option<&str>) -> KimiJob<'_> {
    KimiJob {
        prompt: "-fix it",
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

fn get<'a>(env: &'a std::collections::BTreeMap<OsString, OsString>, name: &str) -> Option<&'a str> {
    env.get(&OsString::from(name)).and_then(|v| v.to_str())
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
fn the_kimi_model_host_is_the_overseas_api_only() {
    assert_eq!(
        resolve("kimi").map(AgentRunner::model_hosts),
        Some(&["api.kimi.ai"][..])
    );
}

#[test]
fn the_kimi_argv_is_the_real_cli_shape() {
    let argv = strings(&kimi::argv(Path::new("/opt/kimi"), &job(Some("k2"))));
    assert_eq!(
        argv,
        [
            "/opt/kimi",
            "-p",
            "-fix it",
            "--output-format",
            "stream-json",
            "-m",
            "k2"
        ]
    );
}

#[test]
fn the_kimi_argv_omits_the_model_when_unset() {
    let argv = strings(&kimi::argv(Path::new("kimi"), &job(None)));
    assert_eq!(
        argv,
        ["kimi", "-p", "-fix it", "--output-format", "stream-json"]
    );
}

#[test]
fn the_kimi_argv_has_none_of_the_flags_the_cli_lacks() {
    let argv = strings(&kimi::argv(Path::new("kimi"), &job(Some("k2"))));
    for arg in &argv {
        assert!(
            !arg.starts_with("--print")
                && !arg.starts_with("--work-dir")
                && !arg.starts_with("--prompt=")
                && !arg.starts_with("--model="),
            "{arg}"
        );
    }
    for flag in ["--yolo", "-y", "--yes", "--auto-approve", "--afk"] {
        assert!(!argv.iter().any(|arg| arg == flag), "{flag}");
    }
}

#[test]
fn the_runner_program_is_the_configured_kimi_binary() {
    let mut config = fleetd::runner::RunConfig::new("claude", false);
    assert_eq!(
        resolve("kimi").map(|runner| runner.program(&config).to_path_buf()),
        Some(Path::new("kimi").to_path_buf())
    );
    config.kimi_bin = Path::new("/opt/kimi").to_path_buf();
    assert_eq!(
        resolve("kimi").map(|runner| runner.program(&config).to_path_buf()),
        Some(Path::new("/opt/kimi").to_path_buf())
    );
}

#[test]
fn the_default_program_is_kimi() {
    assert_eq!(kimi::DEFAULT_PROGRAM, "kimi");
}

#[test]
fn an_unset_model_is_the_default_and_a_plain_one_passes() {
    assert_eq!(kimi::resolve_model(None), Some("kimi-for-coding"));
    for model in ["k2", "kimi-k2.5", "moonshot/kimi_k2:latest", "A1"] {
        assert_eq!(kimi::resolve_model(Some(model)), Some(model));
    }
    let longest = "a".repeat(kimi::MAX_MODEL_LEN);
    assert_eq!(kimi::resolve_model(Some(&longest)), Some(longest.as_str()));
}

#[test]
fn a_hostile_model_name_is_refused() {
    let over = "a".repeat(kimi::MAX_MODEL_LEN + 1);
    let hostile = [
        "",
        "a\rb",
        "a\r\nb",
        "a\nb",
        "a b",
        " k2",
        "k2 ",
        "a\tb",
        "a=b",
        "K=1",
        "a\0b",
        "a\u{85}b",
        "a\u{2028}b",
        "-m",
        "--x",
        "k\u{e9}",
        "a;b",
        "a$b",
        "a`b",
        "a\\b",
        "a'b",
        "a\"b",
        over.as_str(),
    ];
    for model in hostile {
        assert_eq!(kimi::resolve_model(Some(model)), None, "{model:?}");
    }
}

#[test]
fn only_the_model_api_key_reaches_the_child_env() {
    let base = [
        pair("PATH", "/bin"),
        pair("LC_ALL", "C"),
        pair("HTTPS_PROXY", "http://p:1"),
        pair("KIMI_API_KEY", "host-key"),
        pair("KIMI_MODEL_API_KEY", "host-key"),
        pair("KIMI_MODEL_NAME", "host-model"),
        pair("KIMI_MODEL_BASE_URL", "http://evil"),
        pair("KIMI_DISABLE_TELEMETRY", "0"),
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
        "kimi-for-coding",
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
    assert_eq!(secrets, [&OsString::from("KIMI_MODEL_API_KEY")]);
    assert_eq!(kimi::API_KEY_ENV, "KIMI_MODEL_API_KEY");
    assert_eq!(get(&env, "KIMI_MODEL_API_KEY"), Some("sk-kimi-job"));
    assert_eq!(get(&env, "KIMI_MODEL_NAME"), Some("kimi-for-coding"));
    assert_eq!(get(&env, "KIMI_MODEL_PROVIDER_TYPE"), Some("kimi"));
    assert_eq!(
        get(&env, "KIMI_MODEL_BASE_URL"),
        Some("https://api.kimi.ai/coding/v1")
    );
    assert_eq!(get(&env, "KIMI_DISABLE_TELEMETRY"), Some("1"));
    assert_eq!(get(&env, "KIMI_CODE_NO_AUTO_UPDATE"), Some("1"));
    assert_eq!(get(&env, "KIMI_CODE_HOME"), Some("/h/kimi"));
    assert_eq!(get(&env, "HTTPS_PROXY"), Some("http://p:1"));
    assert!(env.contains_key(&OsString::from("LC_ALL")));
    assert!(!env.contains_key(&OsString::from("KIMI_API_KEY")));
}

#[test]
fn the_model_name_reaches_only_its_own_variable() {
    let env = kimi::env(
        &[],
        "k",
        "kimi-k2.5",
        "job1",
        Path::new("/h"),
        Path::new("/h/kimi"),
    );
    assert_eq!(get(&env, "KIMI_MODEL_NAME"), Some("kimi-k2.5"));
    let holders = env
        .values()
        .filter(|value| value.to_str() == Some("kimi-k2.5"))
        .count();
    assert_eq!(holders, 1);
}

#[test]
fn the_per_job_kimi_home_is_private_empty_and_removed_on_drop() -> TestResult {
    let root = TempDir::new()?;
    let home = KimiHome::create(root.path(), "job1")?;
    let path = home.path().to_path_buf();
    assert_eq!(path, root.path().join(".kimi").join("job1"));
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(std::fs::read_dir(&path)?.count(), 0);
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
fn the_user_agent_is_left_alone() {
    let argv = strings(&kimi::argv(Path::new("kimi"), &job(None)));
    assert!(
        !argv
            .iter()
            .any(|arg| arg.to_lowercase().contains("user-agent"))
    );
    let env = kimi::env(
        &[],
        "k",
        "kimi-for-coding",
        "job1",
        Path::new("/h"),
        Path::new("/h/kimi"),
    );
    assert!(
        env.keys()
            .all(|name| !name.to_string_lossy().to_uppercase().contains("USER_AGENT"))
    );
}
