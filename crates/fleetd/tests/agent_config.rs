//! The per-job config bundle: the embedded default, the operator directory checks and the
//! job directory lifecycle.

use std::os::unix::fs::symlink;
use std::path::Path;

use fleetd::agent_config::{Bundle, BundleError, JobDir, MAX_BYTES, MAX_ENTRIES};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn settings(dir: &Path, json: &str) -> TestResult {
    std::fs::write(dir.join("settings.json"), json)?;
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
    assert_eq!(
        list("allow"),
        [
            "Bash(git add *)",
            "Bash(git commit *)",
            "Bash(git status *)",
            "Bash(git diff *)",
            "Bash(git log *)",
            "Bash(git checkout -b *)"
        ]
    );
    assert_eq!(list("deny"), ["Bash(git push *)", "Bash(gh *)"]);
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
