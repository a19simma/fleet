//! Agent name resolution and Codex runner tests.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fleet_core::Redactor;
use fleet_core::Selection;
use fleet_core::catalog::{CatalogEntry, CatalogItem, CatalogKind};
use fleet_proto::v1::{JobEvent, JobEventKind};
use fleetd::agent::codex::{self, CodexHome, CodexJob};
use fleetd::agent::notes::{dropped_subagent_events, sanitise_note};
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
    assert!(resolve("gemini").is_none());
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

mod claude_telemetry {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::num::NonZeroU16;

    use fleetd::agent::{TelemetryEnv, TelemetryEnvError};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn port() -> NonZeroU16 {
        NonZeroU16::new(43_210).unwrap_or(NonZeroU16::MIN)
    }

    fn os(text: &str) -> OsString {
        OsString::from(text)
    }

    #[test]
    fn the_env_map_is_pinned_over_a_relative_path_base() -> Result<(), TelemetryEnvError> {
        let mut env: BTreeMap<OsString, OsString> = BTreeMap::from([
            (os("HOME"), os("jobs/home")),
            (os("CLAUDE_CONFIG_DIR"), os("jobs/home/.claude")),
        ]);
        TelemetryEnv::new(port(), TOKEN)?.apply(&mut env);
        let want: BTreeMap<OsString, OsString> = [
            ("HOME", "jobs/home"),
            ("CLAUDE_CONFIG_DIR", "jobs/home/.claude"),
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "1"),
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            (
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "http://127.0.0.1:43210/v1/logs",
            ),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "Authorization=Bearer 0123456789abcdef0123456789abcdef",
            ),
            ("OTEL_LOGS_EXPORT_INTERVAL", "1000"),
            ("OTEL_LOG_TOOL_DETAILS", "1"),
        ]
        .map(|(key, value)| (os(key), os(value)))
        .into();
        assert_eq!(env, want);
        Ok(())
    }

    #[test]
    fn the_token_appears_only_in_the_headers_value() -> Result<(), TelemetryEnvError> {
        let mut env = BTreeMap::new();
        TelemetryEnv::new(port(), TOKEN)?.apply(&mut env);
        let holders: Vec<&OsString> = env
            .iter()
            .filter(|(_, value)| value.to_string_lossy().contains(TOKEN))
            .map(|(key, _)| key)
            .collect();
        assert_eq!(holders, [&os("OTEL_EXPORTER_OTLP_HEADERS")]);
        Ok(())
    }

    #[test]
    fn debug_and_errors_never_show_the_token() -> Result<(), TelemetryEnvError> {
        let built = TelemetryEnv::new(port(), TOKEN)?;
        assert!(!format!("{built:?}").contains(TOKEN));
        assert!(!format!("{built:#?}").contains(TOKEN));
        let leaky = format!("{TOKEN}\r\nX-Evil: 1");
        let err = TelemetryEnv::new(port(), &leaky).err();
        assert_eq!(err, Some(TelemetryEnvError::BadToken));
        let shown = format!("{err:?} {}", TelemetryEnvError::BadToken);
        assert!(!shown.contains(TOKEN));
        Ok(())
    }

    #[test]
    fn a_hostile_token_adds_no_variable() {
        for bad in [
            "",
            "short",
            "a b a b a b a b a b a b a b a b",
            "tok\nen0123456789012345678",
        ] {
            assert_eq!(
                TelemetryEnv::new(port(), bad).err(),
                Some(TelemetryEnvError::BadToken),
                "{bad:?}"
            );
        }
    }
}

fn entry(
    kind: CatalogKind,
    id: &str,
    enabled: bool,
) -> Result<CatalogEntry, Box<dyn std::error::Error>> {
    let body = if kind == CatalogKind::Tool {
        "22.1.0"
    } else {
        "body"
    };
    Ok(CatalogEntry::new(
        CatalogItem::new(kind, id, id, body)?,
        enabled,
    ))
}

fn catalog(subagents: usize) -> Result<Vec<CatalogEntry>, Box<dyn std::error::Error>> {
    let mut out = vec![entry(CatalogKind::Skill, "skill-one", true)?];
    for index in 0..subagents {
        out.push(entry(
            CatalogKind::Subagent,
            &format!("agent-{index}"),
            true,
        )?);
    }
    out.push(entry(CatalogKind::Subagent, "agent-off", false)?);
    Ok(out)
}

fn notes(agent: &str, subagents: usize) -> Result<Vec<JobEvent>, Box<dyn std::error::Error>> {
    Ok(dropped_subagent_events(
        agent,
        &Selection::default(),
        &catalog(subagents)?,
        &Redactor::new(Vec::<String>::new()),
        7,
        1234,
    )?)
}

#[test]
fn kimi_with_n_dropped_subagents_emits_exactly_n_notes() -> TestResult {
    for n in [0usize, 1, 2, 5] {
        let events = notes("kimi", n)?;
        assert_eq!(events.len(), n, "{n}");
    }
    Ok(())
}

#[test]
fn a_kimi_note_is_a_phase_event_naming_the_item() -> TestResult {
    let events = notes("kimi", 2)?;
    let details: Vec<_> = events
        .iter()
        .map(|e| e.detail.clone().unwrap_or_default())
        .collect();
    assert_eq!(
        details,
        [
            "kimi has no subagents: dropped agent-0",
            "kimi has no subagents: dropped agent-1"
        ]
    );
    for (offset, event) in events.iter().enumerate() {
        assert_eq!(event.kind, i32::from(JobEventKind::Phase));
        assert_eq!(event.seq, 7 + u32::try_from(offset)?);
        assert_eq!(event.ts_ms, 1234);
    }
    Ok(())
}

#[test]
fn claude_codex_and_default_emit_no_notes() -> TestResult {
    for agent in ["claude", "", "codex", "gemini"] {
        assert!(notes(agent, 3)?.is_empty(), "{agent}");
    }
    Ok(())
}

#[test]
fn a_subagent_the_selection_switched_off_gets_no_kimi_note() -> TestResult {
    let selection = Selection::from_json(br#"[{"item_id":"agent-0"}]"#)?;
    let events = dropped_subagent_events(
        "kimi",
        &selection,
        &catalog(2)?,
        &Redactor::new(Vec::<String>::new()),
        1,
        0,
    )?;
    assert_eq!(events.len(), 1);
    Ok(())
}

#[test]
fn a_note_scrubs_a_secret_shaped_id() -> TestResult {
    let secret = "secretvalue-0123456789";
    let catalog = vec![entry(CatalogKind::Subagent, secret, true)?];
    let events = dropped_subagent_events(
        "kimi",
        &Selection::default(),
        &catalog,
        &Redactor::new([secret]),
        1,
        0,
    )?;
    let detail = events[0].detail.clone().unwrap_or_default();
    assert!(!detail.contains(secret), "{detail}");
    assert!(detail.starts_with("kimi has no subagents: dropped "));
    Ok(())
}

#[test]
fn a_note_over_the_detail_cap_is_cut_on_a_char_boundary() {
    let long = "x".repeat(fleet_proto::MAX_EVENT_DETAIL_BYTES * 2);
    let out = sanitise_note(&long, &Redactor::new(Vec::<String>::new()));
    assert_eq!(out.len(), fleet_proto::MAX_EVENT_DETAIL_BYTES);
    let wide = "\u{e9}".repeat(fleet_proto::MAX_EVENT_DETAIL_BYTES);
    let out = sanitise_note(&wide, &Redactor::new(Vec::<String>::new()));
    assert!(out.len() <= fleet_proto::MAX_EVENT_DETAIL_BYTES);
    assert!(out.chars().all(|c| c == '\u{e9}'));
}

#[test]
fn hostile_characters_are_stripped_from_note_text() {
    let redactor = Redactor::new(Vec::<String>::new());
    for (raw, want) in [
        ("a\rb", "ab"),
        ("a\r\nb", "ab"),
        ("a\nb", "ab"),
        ("a\u{85}b", "ab"),
        ("a\u{2028}b", "ab"),
        ("a\u{2029}b", "ab"),
        ("a\u{202e}b", "ab"),
        ("a\u{2066}b", "ab"),
        ("a\u{e0041}b", "ab"),
        ("a\u{1b}b", "ab"),
        ("a\tb", "ab"),
        ("a\u{0}b", "ab"),
    ] {
        assert_eq!(sanitise_note(raw, &redactor), want, "{raw:?}");
    }
}

#[test]
fn a_hostile_id_cannot_reach_a_note() {
    for raw in ["a\nb", "a\u{202e}b", "A", ""] {
        assert!(
            CatalogItem::new(CatalogKind::Subagent, raw, "n", "b").is_err(),
            "{raw:?}"
        );
    }
}
