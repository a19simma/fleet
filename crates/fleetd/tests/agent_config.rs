//! The per-job config bundle: the embedded default, the operator directory checks and the
//! job directory lifecycle.

use std::os::unix::fs::symlink;
use std::path::Path;

use fleetd::agent_config::{
    AGENT_PROTOCOL, Bundle, BundleError, JobDir, MAX_BYTES, MAX_ENTRIES, protocol_for,
};
use fleetd::jobsock::ServiceName;
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
    for quiet in [
        &[ServiceName::Broker][..],
        &[ServiceName::EgressProxy],
        &[ServiceName::Broker, ServiceName::EgressProxy],
    ] {
        assert_eq!(protocol_for(quiet), AGENT_PROTOCOL, "{quiet:?}");
    }
    let with = protocol_for(&[ServiceName::Fetch]);
    assert!(with.starts_with(AGENT_PROTOCOL));
    assert!(with.contains("fleetd fetch <url>"));
    assert_eq!(
        protocol_for(&[ServiceName::Fetch, ServiceName::Fetch]),
        with
    );
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
