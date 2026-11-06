//! The per-job config bundle: the embedded default, the operator directory checks and the
//! job directory lifecycle.

use std::os::unix::fs::symlink;
use std::path::Path;

use fleet_core::Profile;
use fleet_core::catalog::{CatalogItem, CatalogKind};
use fleetd::agent_config::{
    AGENT_PROTOCOL, Bundle, BundleError, JobDir, MAX_BYTES, MAX_ENTRIES, protocol_for,
};
use fleetd::floor::BoxCeilings;
use fleetd::jobsock::ServiceName;
use fleetd::profile_apply::{ApplyError, apply_effective};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn settings(dir: &Path, json: &str) -> TestResult {
    std::fs::write(dir.join("settings.json"), json)?;
    Ok(())
}

#[test]
fn the_protocol_is_unchanged_with_no_service_and_names_fetch_when_it_is_on() {
    assert_eq!(protocol_for(&[]), AGENT_PROTOCOL);
    assert!(AGENT_PROTOCOL.starts_with("You run as an unattended fleet job."));
    assert_eq!(protocol_for(&[ServiceName::EgressProxy]), AGENT_PROTOCOL);
    let with = protocol_for(&[ServiceName::Fetch]);
    assert!(with.starts_with(AGENT_PROTOCOL));
    assert!(with.contains("fleetd fetch <url>"));
    assert_eq!(
        protocol_for(&[ServiceName::Fetch, ServiceName::Fetch]),
        with
    );
}

#[test]
fn the_broker_line_is_added_only_for_the_broker_and_says_push_is_optional() {
    let with = protocol_for(&[ServiceName::Broker]);
    assert!(with.starts_with(AGENT_PROTOCOL));
    assert_ne!(with, AGENT_PROTOCOL);
    assert!(with.contains("fleetd broker push"));
    assert!(with.contains("optional"));
    assert!(with.contains("publishes"));
    assert_eq!(
        protocol_for(&[ServiceName::Broker, ServiceName::Broker]),
        with
    );
    assert_eq!(
        protocol_for(&[ServiceName::EgressProxy, ServiceName::Broker]),
        with
    );
    let both = protocol_for(&[ServiceName::Fetch, ServiceName::Broker]);
    assert!(both.starts_with(AGENT_PROTOCOL));
    assert!(both.contains("fleetd fetch <url>"));
    assert!(both.contains("fleetd broker push"));
    assert_eq!(
        protocol_for(&[ServiceName::Broker, ServiceName::Fetch]),
        both
    );
}

#[test]
fn the_scratch_gitconfig_refuses_a_plain_push_and_keeps_the_job_identity() -> TestResult {
    let jobs = TempDir::new()?;
    let job = JobDir::create(jobs.path(), "j1", &Bundle::default())?;
    let gitconfig = std::fs::read_to_string(job.home().join(".gitconfig"))?;
    assert!(gitconfig.contains("[push]\n\tdefault = nothing\n"));
    assert!(gitconfig.contains("gpgsign = false"));
    assert!(!gitconfig.contains("askpass"));
    assert!(!gitconfig.contains("credential"));
    Ok(())
}

#[test]
fn the_embedded_bundle_ships_a_broker_skill_with_the_text_rules() -> TestResult {
    let jobs = TempDir::new()?;
    let job = JobDir::create(jobs.path(), "j1", &Bundle::default())?;
    let skill = std::fs::read_to_string(job.home().join(".claude/skills/broker/SKILL.md"))?;
    assert!(skill.starts_with("---\nname: broker\ndescription: "));
    for want in [
        "fleetd broker push",
        "fleetd broker pr_create <title> <body>",
        "fleetd broker pr_checks",
        "fleetd broker fetch",
        "mentions",
        "#",
        "URLs",
        "HTML",
        "entities",
    ] {
        assert!(skill.contains(want), "{want}");
    }
    assert!(skill.contains("Never run git push or gh"));
    Ok(())
}

#[test]
fn the_embedded_bundle_ships_a_fetch_skill_that_forbids_curl_and_wget() -> TestResult {
    let jobs = TempDir::new()?;
    let job = JobDir::create(jobs.path(), "j1", &Bundle::default())?;
    let skill = std::fs::read_to_string(job.home().join(".claude/skills/fetch/SKILL.md"))?;
    assert!(skill.starts_with("---\nname: fetch\ndescription: "));
    assert!(skill.contains("fleetd fetch <url>"));
    assert!(skill.contains("Never use curl or wget"));
    assert!(skill.contains("untrusted"));
    let dir = TempDir::new()?;
    std::fs::write(dir.path().join("CLAUDE.md"), "persona")?;
    let kept = Bundle::from_dir(dir.path())?;
    assert_ne!(kept.sha256(), Bundle::default().sha256());
    let jobs = TempDir::new()?;
    let job = JobDir::create(jobs.path(), "j2", &kept)?;
    assert!(job.home().join(".claude/skills/fetch/SKILL.md").is_file());
    Ok(())
}

#[test]
fn a_plain_directory_is_accepted() -> TestResult {
    let dir = TempDir::new()?;
    std::fs::write(dir.path().join("CLAUDE.md"), "persona")?;
    std::fs::create_dir(dir.path().join("skills"))?;
    std::fs::write(dir.path().join("skills").join("a.md"), "skill")?;
    settings(
        dir.path(),
        r#"{"permissions":{"allow":["Bash(git add *)"],"defaultMode":"dontAsk"},"model":"m","attribution":{"commit":""}}"#,
    )?;
    let bundle = Bundle::from_dir(dir.path())?;
    let jobs = TempDir::new()?;
    let job = JobDir::create(jobs.path(), "j1", &bundle)?;
    let claude = job.home().join(".claude");
    assert_eq!(
        std::fs::read_to_string(claude.join("CLAUDE.md"))?,
        "persona"
    );
    assert_eq!(
        std::fs::read_to_string(claude.join("skills").join("a.md"))?,
        "skill"
    );
    Ok(())
}

#[test]
fn a_path_with_a_parent_component_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    std::fs::create_dir(dir.path().join("inner"))?;
    let sneaky = dir.path().join("inner").join("..").join("inner");
    assert_eq!(Bundle::from_dir(&sneaky), Err(BundleError::Path));
    Ok(())
}

#[test]
fn a_missing_directory_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    assert_eq!(
        Bundle::from_dir(&dir.path().join("absent")),
        Err(BundleError::Path)
    );
    Ok(())
}

#[test]
fn a_symlinked_file_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let outside = TempDir::new()?;
    std::fs::write(outside.path().join("secret"), "x")?;
    symlink(outside.path().join("secret"), dir.path().join("CLAUDE.md"))?;
    assert_eq!(Bundle::from_dir(dir.path()), Err(BundleError::Entry));
    Ok(())
}

#[test]
fn a_symlinked_subdirectory_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let outside = TempDir::new()?;
    symlink(outside.path(), dir.path().join("skills"))?;
    assert_eq!(Bundle::from_dir(dir.path()), Err(BundleError::Entry));
    Ok(())
}

#[test]
fn a_symlinked_root_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let real = TempDir::new()?;
    let link = dir.path().join("link");
    symlink(real.path(), &link)?;
    assert_eq!(Bundle::from_dir(&link), Err(BundleError::Entry));
    Ok(())
}

#[test]
fn more_than_the_entry_cap_is_rejected_and_the_cap_itself_passes() -> TestResult {
    let dir = TempDir::new()?;
    for n in 0..MAX_ENTRIES {
        std::fs::write(dir.path().join(format!("f{n}.md")), "x")?;
    }
    Bundle::from_dir(dir.path())?;
    std::fs::write(dir.path().join("one-more.md"), "x")?;
    assert_eq!(Bundle::from_dir(dir.path()), Err(BundleError::TooMany));
    Ok(())
}

#[test]
fn more_than_the_byte_cap_is_rejected_and_the_cap_itself_passes() -> TestResult {
    let dir = TempDir::new()?;
    let cap = usize::try_from(MAX_BYTES)?;
    std::fs::write(dir.path().join("big.bin"), vec![b'a'; cap])?;
    Bundle::from_dir(dir.path())?;
    std::fs::write(dir.path().join("extra.bin"), "x")?;
    assert_eq!(Bundle::from_dir(dir.path()), Err(BundleError::TooLarge));
    Ok(())
}

#[test]
fn settings_keys_outside_the_allowlist_are_rejected() -> TestResult {
    for json in [
        r#"{"hooks":{}}"#,
        r#"{"env":{"A":"b"}}"#,
        r#"{"permissions":{},"apiKeyHelper":"x"}"#,
        r#"{"enabledPlugins":{}}"#,
    ] {
        let dir = TempDir::new()?;
        settings(dir.path(), json)?;
        assert_eq!(
            Bundle::from_dir(dir.path()),
            Err(BundleError::Settings),
            "{json}"
        );
    }
    Ok(())
}

#[test]
fn a_bypass_default_mode_is_rejected() -> TestResult {
    for mode in ["bypassPermissions", "BypassPermissions"] {
        let dir = TempDir::new()?;
        settings(
            dir.path(),
            &format!(r#"{{"permissions":{{"defaultMode":"{mode}"}}}}"#),
        )?;
        assert_eq!(
            Bundle::from_dir(dir.path()),
            Err(BundleError::Settings),
            "{mode}"
        );
    }
    Ok(())
}

#[test]
fn settings_that_are_not_an_object_are_rejected() -> TestResult {
    for json in ["[]", "not json", "\"x\""] {
        let dir = TempDir::new()?;
        settings(dir.path(), json)?;
        assert_eq!(
            Bundle::from_dir(dir.path()),
            Err(BundleError::Settings),
            "{json}"
        );
    }
    Ok(())
}

#[test]
fn the_embedded_bundle_carries_the_commit_permissions_and_no_attribution() -> TestResult {
    let jobs = TempDir::new()?;
    let job = JobDir::create(jobs.path(), "j1", &Bundle::default())?;
    let claude = job.home().join(".claude");
    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(claude.join("settings.json"))?)?;
    let list = |key: &str| -> Vec<String> {
        settings["permissions"][key]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(list("allow"), ["Read", "Glob", "Grep", "Bash"]);
    assert_eq!(
        list("deny"),
        [
            "Bash(git push *)",
            "Bash(gh *)",
            "Bash(curl *)",
            "Edit",
            "Write",
            "NotebookEdit",
            "MultiEdit"
        ]
    );
    assert_eq!(settings["attribution"]["commit"], "");
    assert_eq!(settings["attribution"]["pr"], "");
    let keys: Vec<&String> = settings.as_object().ok_or("object")?.keys().collect();
    assert_eq!(keys, ["attribution", "permissions"]);
    let persona = std::fs::read_to_string(claude.join("CLAUDE.md"))?;
    assert!(persona.contains("semantic message"));
    assert!(persona.contains("attribution"));
    let gitconfig = std::fs::read_to_string(job.home().join(".gitconfig"))?;
    assert!(gitconfig.contains("gpgsign = false"));
    Ok(())
}

#[test]
fn the_job_dir_is_built_by_rename_replaces_a_stale_one_and_drops_clean() -> TestResult {
    let jobs = TempDir::new()?;
    let stale = jobs.path().join(".agent").join("j1");
    std::fs::create_dir_all(&stale)?;
    std::fs::write(stale.join("old"), "x")?;
    let leftover = jobs.path().join(".agent").join("j1.tmp");
    std::fs::create_dir_all(&leftover)?;
    let job = JobDir::create(jobs.path(), "j1", &Bundle::default())?;
    assert_eq!(job.path(), stale);
    assert!(!stale.join("old").exists());
    assert!(!leftover.exists());
    assert!(job.home().join(".claude").join("settings.json").exists());
    drop(job);
    assert!(!stale.exists());
    Ok(())
}

#[test]
fn an_invalid_job_id_is_rejected_before_any_path_is_built() -> TestResult {
    let jobs = TempDir::new()?;
    for id in ["", "../x", "a/b", "a.b"] {
        assert!(
            JobDir::create(jobs.path(), id, &Bundle::default()).is_err(),
            "{id}"
        );
    }
    assert!(!jobs.path().join(".agent").exists());
    Ok(())
}

fn logical() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("CLAUDE.md", b"persona"),
        ("skills/a.md", b"skill"),
        (".hidden", b"h"),
        (
            "settings.json",
            br#"{"permissions":{"defaultMode":"dontAsk"},"model":"m"}"#,
        ),
    ]
}

fn write_tree(dir: &Path, files: &[(&str, &[u8])]) -> TestResult {
    for (path, data) in files {
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, data)?;
    }
    Ok(())
}

fn files_of(files: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    files
        .iter()
        .map(|(path, data)| ((*path).to_owned(), data.to_vec()))
        .collect()
}

type Pair = (Result<Bundle, BundleError>, Result<Bundle, BundleError>);

fn one() -> &'static [u8] {
    b"x"
}

fn both(files: &[(&str, &[u8])]) -> Result<Pair, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    write_tree(dir.path(), files)?;
    Ok((
        Bundle::from_dir(dir.path()),
        Bundle::from_files(files_of(files)),
    ))
}

#[test]
fn from_files_matches_from_dir_for_the_same_logical_bundle() -> TestResult {
    let (dir, files) = both(&logical())?;
    assert_eq!(dir, files);
    let reversed: Vec<_> = files_of(&logical()).into_iter().rev().collect();
    assert_eq!(Bundle::from_files(reversed), dir);
    assert_eq!(dir?.sha256(), files?.sha256());
    Ok(())
}

#[test]
fn from_files_overrides_the_defaults_like_from_dir() -> TestResult {
    let (dir, files) = both(&[("CLAUDE.md", b"mine")])?;
    assert_eq!(dir, files);
    assert_ne!(files?, Bundle::default());
    Ok(())
}

#[test]
fn an_empty_file_set_is_the_default_bundle() -> TestResult {
    let none: Vec<(String, Vec<u8>)> = Vec::new();
    assert_eq!(Bundle::from_files(none), Ok(Bundle::default()));
    let (dir, files) = both(&[])?;
    assert_eq!(dir, files);
    Ok(())
}

#[test]
fn from_files_entry_cap_matches_from_dir() -> TestResult {
    let names: Vec<String> = (0..=MAX_ENTRIES).map(|n| format!("f{n}.md")).collect();
    let at_cap: Vec<(&str, &[u8])> = names[..MAX_ENTRIES]
        .iter()
        .map(|n| (n.as_str(), one()))
        .collect();
    let (dir, files) = both(&at_cap)?;
    assert_eq!(dir, files);
    assert!(files.is_ok());
    let over: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), one())).collect();
    let (dir, files) = both(&over)?;
    assert_eq!(dir, Err(BundleError::TooMany));
    assert_eq!(files, Err(BundleError::TooMany));
    Ok(())
}

#[test]
fn from_files_counts_implied_directories_like_from_dir() -> TestResult {
    let names: Vec<String> = (0..MAX_ENTRIES / 2).map(|n| format!("d{n}/f")).collect();
    let tree: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), one())).collect();
    let (dir, files) = both(&tree)?;
    assert_eq!(dir, files);
    assert!(files.is_ok());
    let mut over = tree.clone();
    over.push(("one/more", b"x"));
    let (dir, files) = both(&over)?;
    assert_eq!(dir, Err(BundleError::TooMany));
    assert_eq!(files, Err(BundleError::TooMany));
    Ok(())
}

#[test]
fn from_files_byte_cap_matches_from_dir() -> TestResult {
    let cap = usize::try_from(MAX_BYTES)?;
    let big = vec![b'a'; cap];
    let (dir, files) = both(&[("big.bin", &big)])?;
    assert_eq!(dir, files);
    assert!(files.is_ok());
    let (dir, files) = both(&[("big.bin", &big), ("extra.bin", b"x")])?;
    assert_eq!(dir, Err(BundleError::TooLarge));
    assert_eq!(files, Err(BundleError::TooLarge));
    Ok(())
}

#[test]
fn from_files_settings_rules_match_from_dir() -> TestResult {
    for json in [
        r#"{"hooks":{}}"#,
        r#"{"env":{"A":"b"}}"#,
        r#"{"permissions":{},"apiKeyHelper":"x"}"#,
        r#"{"enabledPlugins":{}}"#,
        r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
        r#"{"permissions":{"defaultMode":"BypassPermissions"}}"#,
        "[]",
        "not json",
        "\"x\"",
    ] {
        let (dir, files) = both(&[("settings.json", json.as_bytes())])?;
        assert_eq!(dir, Err(BundleError::Settings), "{json}");
        assert_eq!(files, Err(BundleError::Settings), "{json}");
    }
    Ok(())
}

#[test]
fn from_files_rejects_a_duplicate_path() {
    let files = vec![("CLAUDE.md", b"a".to_vec()), ("CLAUDE.md", b"b".to_vec())];
    assert_eq!(Bundle::from_files(files), Err(BundleError::Path));
}

#[test]
fn from_files_rejects_unusable_paths() {
    for path in [
        "../x", "a/../b", "/abs", "a\\b", "a\0b", "", ".", "./a", "a//b", "a/",
    ] {
        assert_eq!(
            Bundle::from_files([(path, b"x".to_vec())]),
            Err(BundleError::Path),
            "{path:?}"
        );
    }
}

#[test]
fn from_files_rejects_a_file_that_is_also_a_directory() {
    let files = vec![("a", b"x".to_vec()), ("a/b", b"y".to_vec())];
    assert_eq!(Bundle::from_files(files), Err(BundleError::Entry));
}

fn frozen_set() -> Result<Vec<CatalogItem>, Box<dyn std::error::Error>> {
    Ok(vec![
        CatalogItem::new(
            CatalogKind::Skill,
            "s1",
            "lint",
            "---\nname: lint\ndescription: lint the tree\n---\nRun the linter.\n",
        )?,
        CatalogItem::new(
            CatalogKind::Subagent,
            "a1",
            "review",
            "---\nname: review\ndescription: review a diff\n---\nRead the diff.\n",
        )?,
        CatalogItem::new(CatalogKind::Context, "c1", "rules", "House rules.\n")?,
        CatalogItem::new(CatalogKind::Tool, "t1", "jq", "1.7.1")?,
    ])
}

fn ceilings() -> BoxCeilings {
    BoxCeilings {
        default_max_turns: 30,
        max_turns: 50,
        default_max_budget_cents: 500,
        max_budget_cents: 1000,
    }
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> TestResult {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if std::fs::symlink_metadata(&path)?.is_dir() {
            walk(&path, out)?;
        }
        out.push(path);
    }
    Ok(())
}

#[test]
fn the_effective_set_round_trips_through_the_bundle_parser_and_the_job_dir() -> TestResult {
    let applied = apply_effective(
        &Profile::default(),
        &frozen_set()?,
        &Bundle::default(),
        &ceilings(),
        "go",
    )?;
    let jobs = TempDir::new()?;
    let real = jobs.path().join("real");
    std::fs::create_dir(&real)?;
    let link = jobs.path().join("link");
    symlink(&real, &link)?;
    let job = JobDir::create(&link, "j1", &applied.bundle)?;
    let claude = job.home().join(".claude");
    let reread = Bundle::from_dir(&claude)?;
    assert_eq!(reread, applied.bundle);
    assert_eq!(reread.sha256(), applied.bundle.sha256());
    let settings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(claude.join("settings.json"))?)?;
    assert!(
        settings
            .pointer("/permissions/allow")
            .is_some_and(serde_json::Value::is_array)
    );
    assert!(
        std::fs::read_to_string(claude.join("skills/lint/SKILL.md"))?.contains("Run the linter.")
    );
    assert!(std::fs::read_to_string(claude.join("agents/review.md"))?.contains("Read the diff."));
    let md = std::fs::read_to_string(claude.join("CLAUDE.md"))?;
    let imports: Vec<&str> = md.lines().filter_map(|l| l.strip_prefix('@')).collect();
    assert_eq!(imports, [".claude/ctx/rules.md"]);
    for import in imports {
        assert_eq!(
            std::fs::read_to_string(claude.join(import))?,
            "House rules.\n"
        );
    }
    let inside = std::fs::canonicalize(job.path())?;
    let mut all = Vec::new();
    walk(&real, &mut all)?;
    assert!(all.iter().any(|p| p.ends_with("agents/review.md")));
    for path in all {
        assert!(
            std::fs::canonicalize(&path)?.starts_with(real.canonicalize()?),
            "{path:?}"
        );
    }
    assert!(inside.starts_with(real.canonicalize()?));
    Ok(())
}

#[test]
fn a_relative_root_and_a_planted_staging_link_never_escape() -> TestResult {
    let jobs = TempDir::new()?;
    let outside = TempDir::new()?;
    std::fs::write(outside.path().join("keep"), "x")?;
    let agent = jobs.path().join(".agent");
    std::fs::create_dir(&agent)?;
    symlink(outside.path(), agent.join("j2.tmp"))?;
    let cwd = std::env::current_dir()?;
    let mut relative = std::path::PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(jobs.path().strip_prefix("/")?);
    assert!(relative.is_relative());
    let applied = apply_effective(
        &Profile::default(),
        &frozen_set()?,
        &Bundle::default(),
        &ceilings(),
        "go",
    )?;
    let job = JobDir::create(&relative, "j2", &applied.bundle)?;
    assert!(job.home().join(".claude/skills/lint/SKILL.md").is_file());
    let mut left = Vec::new();
    walk(outside.path(), &mut left)?;
    assert_eq!(left, [outside.path().join("keep")]);
    assert_eq!(std::fs::read_to_string(outside.path().join("keep"))?, "x");
    Ok(())
}

fn subagent_outcome(body: &str) -> Result<(), ApplyError> {
    let items = [CatalogItem::new(CatalogKind::Subagent, "a1", "probe", body)
        .map_err(|_| ApplyError::Collision)?];
    apply_effective(
        &Profile::default(),
        &items,
        &Bundle::default(),
        &ceilings(),
        "go",
    )
    .map(|_| ())
}

const ALLOWED_KEYS: [&str; 4] = ["name", "description", "color", "tools"];
const DENIED_TOOLS: [&str; 5] = ["WebFetch", "Edit", "Write", "NotebookEdit", "MultiEdit"];

fn assert_parser_sees_nothing_banned(body: &str) -> TestResult {
    let Some(rest) = body.strip_prefix("---\n") else {
        return Ok(());
    };
    let end = rest.find("\n---\n").map_or(rest.len(), |i| i + 1);
    let value: serde_norway::Value = serde_norway::from_str(&rest[..end])?;
    let Some(map) = value.as_mapping() else {
        return Err(format!("not a mapping: {body:?}").into());
    };
    for (key, val) in map {
        let key = key
            .as_str()
            .ok_or_else(|| format!("non-string key: {body:?}"))?;
        assert!(ALLOWED_KEYS.contains(&key), "{key:?} in {body:?}");
        if key == "tools" {
            let text = val
                .as_str()
                .ok_or_else(|| format!("tools not a string: {body:?}"))?;
            for tool in text.split(',').map(str::trim) {
                assert!(
                    !DENIED_TOOLS.iter().any(|d| d.eq_ignore_ascii_case(tool)),
                    "{tool:?} in {body:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn the_subagent_allowlist_refuses_every_hostile_frontmatter() {
    let hostile = [
        "---  \nname: a\npermissionMode: x\n---\nb",
        "--- \nname: a\npermissionMode: x\n---\nb",
        "\n---\nname: a\npermissionMode: x\n---\nb",
        " ---\nname: a\npermissionMode: x\n---\nb",
        "\u{feff}---\nname: a\npermissionMode: x\n---\nb",
        "\u{feff}name: a\nb",
        "----\nname: a\npermissionMode: x\n----\nb",
        "---\nname: x\rpermissionMode: bypassPermissions\n---\nb",
        "---\nname: x\u{85}permissionMode: bypassPermissions\n---\nb",
        "---\nname: x\u{2028}permissionMode: bypassPermissions\n---\nb",
        "---\nname: x\u{2029}permissionMode: bypassPermissions\n---\nb",
        "---\nname: a\n\"permissionMode\": x\n---\nb",
        "---\nname: a\n'permissionMode': x\n---\nb",
        "---\n{name: x, permissionMode: y}\n---\nb",
        "---\n{\n  name: x,\n  permissionMode: y\n}\n---\nb",
        "---\nname: a\n? permissionMode\n: x\n---\nb",
        "---\nname: a\n\"tools\": Edit\n---\nb",
        "---\n{tools: [Edit]}\n---\nb",
        "---\n  name: a\n  permissionMode: x\n---\nb",
        "---\n\tname: a\n\tpermissionMode: x\n---\nb",
        "---\nname: a\n  permissionMode: x\n---\nb",
        "---\nname: |\n  x\npermissionMode: y\n---\nb",
        "---\nname: >\n  x\npermissionMode: y\n---\nb",
        "---\nname: &anchor x\npermissionMode: *anchor\n---\nb",
        "---\nname: *anchor\n---\nb",
        "---\nname: a\nname: b\n---\nb",
        "---\nname: a\ntools: Read\ntools: Edit\n---\nb",
        "---\nname: a\nPermissionMode: x\n---\nb",
        "---\nname: a\nPERMISSIONMODE: x\n---\nb",
        "---\nname: a\nTools: Edit\n---\nb",
        "---\nname: a\nhooks: x\n---\nb",
        "---\nname: a\nmodel: opus\n---\nb",
        "---\nname: a\nmcpServers: x\n---\nb",
        "---\nname: a\n...\npermissionMode: x\n---\nb",
        "---\nname: a\n--- \npermissionMode: x\n---\nb",
        "---\nname: a\n---\n---\npermissionMode: x\n---\n",
        "---\nname: a\ntools: Read, Edit\n---\nb",
        "---\nname: a\ntools: write\n---\nb",
        "---\nname: a\ntools: MultiEdit\n---\nb",
        "---\nname: a\ntools: Read,\n  Edit\n---\nb",
        "---\nname: a\ntools:\n  - Edit\n---\nb",
        "---\nname: a\ntools:\n- Edit\n---\nb",
        "---\nname: a\ntools: [Read,\n  Edit]\n---\nb",
        "---\nname: a\ntools: [Edit]\n---\nb",
        "---\nname: a\ntools: Read,,Grep\n---\nb",
        "---\r\nname: a\r\ntools: Edit\r\n---\r\nb",
        "---\r\nname: a\r\n---\r\nb",
        "---\nname: a\r\n---\nb",
        "---\nname: a\0\n---\nb",
        "---\nname:\ta\n---\nb",
        "---\nname: a\n---",
        "---\nname: a\n",
        "---\n---\nb",
        "---\nname: a # permissionMode\n---\nb",
        "---\nname: a\n\n---\nb",
        "---\nname: a \n---\nb",
        "---\nname: a\u{7f}b\n---\nb",
        "---\nname:  a\n---\nb",
        "---\nname: a:\n---\nb",
        "---\nname: -a\n---\nb",
        "---\nname: ?a\n---\nb",
        "---\nname: :a\n---\nb",
        "---\nname: ,a\n---\nb",
        "---\nname: %a\n---\nb",
        "---\nname: @a\n---\nb",
        "---\nname: it's\n---\nb",
        "---\nname: \n---\nb",
        "---\nname: a\u{a0}b\n---\nb",
        "---\nname: caf\u{e9}\n---\nb",
        "---\nname: a\u{200b}b\n---\nb",
    ];
    for body in hostile {
        assert_eq!(
            subagent_outcome(body),
            Err(ApplyError::Subagent),
            "{body:?}"
        );
    }
}

#[test]
fn the_subagent_allowlist_accepts_plain_frontmatter_and_the_parser_agrees() -> TestResult {
    let accepted = [
        "---\nname: a\ndescription: review a diff, quickly\ncolor: blue\ntools: Read, Grep, Bash\n---\nb",
        "---\nname: a\n---\npermissionMode: x\ntools: Edit\n",
        "no frontmatter permissionMode: x\n",
        "# Title\n---\nb",
        "---\nname: a\ntools: mcp__srv-1__t, Read\n---\nb",
    ];
    for body in accepted {
        assert_eq!(subagent_outcome(body), Ok(()), "{body:?}");
        assert_parser_sees_nothing_banned(body)?;
    }
    Ok(())
}

#[test]
fn every_accepted_line_combination_is_clean_under_the_real_parser() -> TestResult {
    let lines = [
        "name: a",
        "name: b",
        "description: x y",
        "model: sonnet",
        "color: red",
        "tools: Read, Grep",
        "tools: Edit",
        "tools: Bash",
        "permissionMode: x",
        "hooks: x",
        "mcpServers: x",
        "PermissionMode: x",
        "name: a: b",
        "name: a #c",
        "name: &x y",
        "name: |",
        "name: [Edit]",
        "  name: a",
        "---",
        "",
    ];
    let mut accepted = 0;
    for a in lines {
        for b in lines {
            for c in lines {
                let body = format!("---\n{a}\n{b}\n{c}\n---\nx");
                if subagent_outcome(&body).is_ok() {
                    accepted += 1;
                    assert_parser_sees_nothing_banned(&body)?;
                }
            }
        }
    }
    assert!(accepted > 20, "{accepted}");
    Ok(())
}
