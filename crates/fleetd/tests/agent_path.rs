//! The agent PATH builder: cache bin dirs in list order, the fixed system tail, refusals for a
//! miss, a hostile key or a PATH override, and the command environment that never inherits.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use fleetd::agent_exec::{
    AgentPathError, MAX_PATH_TOOLS, SYSTEM_PATH_TAIL, apply_agent_path, build_agent_path,
    refuse_path_override,
};
use fleetd::tools::ToolCache;
use tempfile::TempDir;

fn pair(name: &str, version: &str) -> (String, String) {
    (name.to_owned(), version.to_owned())
}

fn entry(root: &Path, name: &str, version: &str) {
    let bin = root.join(name).join(version).join("bin");
    fs::create_dir_all(&bin).unwrap();
    for dir in [root.join(name), root.join(name).join(version), bin] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn cache(root: &Path) -> ToolCache {
    ToolCache::new(root, fs::metadata(root).unwrap().uid())
}

fn setup() -> (TempDir, ToolCache) {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let cache = cache(dir.path());
    (dir, cache)
}

#[test]
fn an_empty_list_gives_the_fixed_tail_only() {
    let (_dir, cache) = setup();
    assert_eq!(build_agent_path(&cache, &[]).unwrap(), SYSTEM_PATH_TAIL);
    assert_eq!(SYSTEM_PATH_TAIL, "/usr/local/bin:/usr/bin:/bin");
}

#[test]
fn bin_dirs_come_in_list_order_before_the_tail() {
    let (dir, cache) = setup();
    entry(dir.path(), "node", "22.1.0");
    entry(dir.path(), "go", "1.23.0");
    let path = build_agent_path(&cache, &[pair("node", "22.1.0"), pair("go", "1.23.0")]).unwrap();
    let root = dir.path().display();
    assert_eq!(
        path,
        format!("{root}/node/22.1.0/bin:{root}/go/1.23.0/bin:{SYSTEM_PATH_TAIL}")
    );
    let flipped =
        build_agent_path(&cache, &[pair("go", "1.23.0"), pair("node", "22.1.0")]).unwrap();
    assert!(flipped.starts_with(&format!("{root}/go/")));
}

#[test]
fn a_miss_is_an_error_not_a_skip() {
    let (dir, cache) = setup();
    entry(dir.path(), "node", "22.1.0");
    assert_eq!(
        build_agent_path(&cache, &[pair("node", "22.1.0"), pair("go", "1.23.0")]),
        Err(AgentPathError::NotCached)
    );
}

#[test]
fn a_missing_bin_dir_is_an_error() {
    let (dir, cache) = setup();
    entry(dir.path(), "node", "22.1.0");
    fs::remove_dir(dir.path().join("node/22.1.0/bin")).unwrap();
    assert_eq!(
        build_agent_path(&cache, &[pair("node", "22.1.0")]),
        Err(AgentPathError::NotCached)
    );
}

#[test]
fn a_symlinked_or_writable_bin_dir_is_an_error() {
    let (dir, cache) = setup();
    entry(dir.path(), "node", "22.1.0");
    let bin = dir.path().join("node/22.1.0/bin");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        build_agent_path(&cache, &[pair("node", "22.1.0")]),
        Err(AgentPathError::NotCached)
    );
    fs::remove_dir(&bin).unwrap();
    fs::create_dir(dir.path().join("elsewhere")).unwrap();
    symlink(dir.path().join("elsewhere"), &bin).unwrap();
    assert_eq!(
        build_agent_path(&cache, &[pair("node", "22.1.0")]),
        Err(AgentPathError::NotCached)
    );
}

#[test]
fn a_failed_cache_check_is_an_error() {
    let (dir, _) = setup();
    entry(dir.path(), "node", "22.1.0");
    let other = ToolCache::new(dir.path(), fs::metadata(dir.path()).unwrap().uid() + 1);
    assert_eq!(
        build_agent_path(&other, &[pair("node", "22.1.0")]),
        Err(AgentPathError::NotCached)
    );
}

#[test]
fn duplicate_names_are_refused() {
    let (dir, cache) = setup();
    entry(dir.path(), "node", "22.1.0");
    entry(dir.path(), "node", "20.0.0");
    assert_eq!(
        build_agent_path(&cache, &[pair("node", "22.1.0"), pair("node", "20.0.0")]),
        Err(AgentPathError::DuplicateTool)
    );
    assert_eq!(
        build_agent_path(&cache, &[pair("node", "22.1.0"), pair("node", "22.1.0")]),
        Err(AgentPathError::DuplicateTool)
    );
}

#[test]
fn hostile_names_and_versions_are_refused() {
    let (dir, cache) = setup();
    entry(dir.path(), "node", "22.1.0");
    let long = "9".repeat(5000);
    let names = [
        "node:go", "node\n", "node\0", "..", "../node", "Node", "NODE", "node ", "", "no/de",
        "nodé",
    ];
    for name in names {
        assert_eq!(
            build_agent_path(&cache, &[pair(name, "22.1.0")]),
            Err(AgentPathError::InvalidTool),
            "name {name:?}"
        );
    }
    let versions = [
        "22.1.0:/tmp",
        "22.1.0\n",
        "22.1.0\0",
        "..",
        "../22.1.0",
        "",
        "latest",
        "22.1.0/bin",
        &long,
    ];
    for version in versions {
        assert_eq!(
            build_agent_path(&cache, &[pair("node", version)]),
            Err(AgentPathError::InvalidTool),
            "version {version:?}"
        );
    }
}

#[test]
fn an_over_long_list_is_refused() {
    let (_dir, cache) = setup();
    let list = vec![pair("node", "22.1.0"); MAX_PATH_TOOLS + 1];
    assert_eq!(
        build_agent_path(&cache, &list),
        Err(AgentPathError::TooMany)
    );
}

#[test]
fn a_path_key_in_the_env_is_refused_in_any_case() {
    for key in ["PATH", "path", "Path", "pAtH"] {
        assert_eq!(
            refuse_path_override([key, "HOME"]),
            Err(AgentPathError::PathOverride),
            "key {key}"
        );
    }
    assert_eq!(refuse_path_override(["HOME", "PATHS", "MYPATH"]), Ok(()));
    assert_eq!(refuse_path_override(std::iter::empty::<&str>()), Ok(()));
}

#[test]
fn the_command_never_inherits_path() {
    let mut command = Command::new("true");
    apply_agent_path(&mut command, "/a/bin:/usr/bin");
    let paths: Vec<_> = command
        .get_envs()
        .filter(|(key, _)| *key == "PATH")
        .collect();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].1.unwrap(), "/a/bin:/usr/bin");
    assert!(
        command
            .get_envs()
            .filter(|(key, _)| key.eq_ignore_ascii_case("PATH") && *key != "PATH")
            .all(|(_, value)| value.is_none())
    );
}
