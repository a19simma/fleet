//! Workspace git hardening and repo policy against a fake `git` that records every call.
//! Own test binary because it spawns children.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use fleetd::workspace::{RepoPolicy, Workspace, WorkspaceError};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GIT: &str = r#"#!/bin/sh
case "$HOME" in
/*) ;;
*) exit 97 ;;
esac
log="$(dirname "$HOME")/calls"
{
  echo "ARGS $*"
  env | sort
  echo END
} >> "$log"
case "$*" in
*"remote set-url"*) [ -e "$(dirname "$HOME")/seturl-fails" ] && exit 1 ;;
esac
exit 0
"#;

struct Call {
    args: String,
    env: BTreeMap<String, String>,
}

fn fake_git() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("git");
        std::fs::write(&path, GIT).unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        (dir, path)
    });
    path
}

fn workspace(root: &Path, policy: RepoPolicy) -> Workspace {
    Workspace::new(root)
        .with_policy(policy)
        .with_git(fake_git(), Duration::from_secs(60))
}

fn calls(root: &Path) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(root.join("calls"))?;
    let mut all = Vec::new();
    let mut current: Option<Call> = None;
    for line in text.lines() {
        if let Some(args) = line.strip_prefix("ARGS ") {
            current = Some(Call {
                args: args.to_owned(),
                env: BTreeMap::new(),
            });
        } else if line == "END" {
            all.extend(current.take());
        } else if let (Some(call), Some((name, value))) = (current.as_mut(), line.split_once('=')) {
            call.env.insert(name.to_owned(), value.to_owned());
        }
    }
    Ok(all)
}

async fn run(
    policy: RepoPolicy,
    repo: &str,
) -> Result<(TempDir, PathBuf, Vec<Call>), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let base = dir.path().to_path_buf();
    let root = base.join("jobs");
    workspace(&root, policy)
        .prepare("job1", repo, "main")
        .await?;
    let all = calls(&root)?;
    Ok((dir, root, all))
}

fn default_run() -> RepoPolicy {
    RepoPolicy::new(["github.com"])
}

const REPO: &str = "https://github.com/o/r.git";

#[tokio::test]
async fn every_call_runs_with_a_cleared_environment() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    assert_eq!(all.len(), 4);
    let expected = [
        "GIT_ALLOW_PROTOCOL",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "PATH",
        "XDG_CONFIG_HOME",
    ];
    for call in &all {
        let names: Vec<&str> = call
            .env
            .keys()
            .map(String::as_str)
            .filter(|n| !matches!(*n, "PWD" | "OLDPWD" | "SHLVL" | "_"))
            .collect();
        assert_eq!(names, expected, "{}", call.args);
    }
    Ok(())
}

#[tokio::test]
async fn every_call_gets_a_scratch_home_and_no_global_or_system_config() -> TestResult {
    let (dir, root, all) = run(default_run(), REPO).await?;
    let real = std::env::var("HOME").unwrap_or_default();
    for call in &all {
        let home = call.env.get("HOME").ok_or("HOME")?;
        assert!(Path::new(home).starts_with(&root), "{home}");
        assert!(Path::new(home).starts_with(dir.path()), "{home}");
        assert_ne!(*home, real);
        assert!(
            call.env
                .get("XDG_CONFIG_HOME")
                .ok_or("xdg")?
                .starts_with(home.as_str())
        );
        assert_eq!(
            call.env.get("GIT_CONFIG_GLOBAL").map(String::as_str),
            Some("/dev/null")
        );
        assert_eq!(
            call.env.get("GIT_CONFIG_NOSYSTEM").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            call.env.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_call_disables_hooks() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    for call in &all {
        assert!(
            call.args.contains(" -c core.hooksPath=/dev/null "),
            "{}",
            call.args
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_call_disables_redirect_following() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    for call in &all {
        assert!(
            call.args.contains(" -c http.followRedirects=false "),
            "{}",
            call.args
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_call_disables_fsmonitor() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    for call in &all {
        assert!(call.args.contains(" -c core.fsmonitor= "), "{}", call.args);
    }
    Ok(())
}

#[tokio::test]
async fn the_config_overrides_come_before_the_subcommand() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    for call in &all {
        let words: Vec<&str> = call.args.split(' ').collect();
        assert_eq!(words[0], "-C", "{}", call.args);
        assert_eq!(
            &words[2..8],
            [
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=",
                "-c",
                "http.followRedirects=false"
            ]
        );
    }
    Ok(())
}

#[tokio::test]
async fn git_is_limited_to_https_unless_the_test_policy_adds_file() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    for call in &all {
        assert_eq!(
            call.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str),
            Some("https")
        );
    }
    let local = RepoPolicy::new(Vec::<String>::new()).with_file_repos();
    let (_dir, _root, all) = run(local, "/some/origin.git").await?;
    for call in &all {
        assert_eq!(
            call.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str),
            Some("file:https")
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_mirror_origin_is_set_on_every_sync_and_added_when_set_url_fails() -> TestResult {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    let subs: Vec<&str> = all
        .iter()
        .filter_map(|c| c.args.split(' ').nth(8))
        .collect();
    assert_eq!(subs, ["init", "remote", "fetch", "worktree"]);
    assert!(
        all[1]
            .args
            .contains("remote set-url origin -- https://github.com/o/r.git")
    );
    assert!(!all.iter().any(|c| c.args.contains("remote add")));

    let dir = TempDir::new()?;
    let base = dir.path().to_path_buf();
    let root = base.join("jobs");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("seturl-fails"), "")?;
    workspace(&root, default_run())
        .prepare("job1", REPO, "main")
        .await?;
    let all = calls(&root)?;
    let adds = all
        .iter()
        .filter(|c| {
            c.args
                .contains("remote add origin -- https://github.com/o/r.git")
        })
        .count();
    assert_eq!(adds, 1);
    assert!(all.iter().any(|c| c.args.contains(" fetch ")));
    Ok(())
}

#[tokio::test]
async fn repos_outside_https_on_an_allowed_host_run_no_git() -> TestResult {
    let dir = TempDir::new()?;
    let root = dir.path().join("jobs");
    let ws = workspace(&root, default_run());
    let repos = [
        "https://attacker.example/x.git",
        "https://github.com.attacker.example/x.git",
        "https://attacker.example/github.com/x.git",
        "https://github.com@attacker.example/x.git",
        "https://user:pw@github.com/x.git",
        "https://github.com:8443/x.git",
        "https://github.com:443/x.git",
        "https://github.com.",
        "https://",
        "https:///x.git",
        "https://github.com\\@attacker.example/x.git",
        "https://g\u{456}thub.com/x.git",
        "https://\u{ff47}ithub.com/x.git",
        "https://github.com%40attacker.example/x.git",
        "https://github.com/x\ty.git",
        "https://github.com/x\ny.git",
        "https://github.com/x\0y.git",
        "//github.com/x.git",
        "https://evil.com\\@github.com/x.git",
        "http://github.com/x.git",
        "HTTP://github.com/x.git",
        "ssh://git@github.com/x.git",
        "git://github.com/x.git",
        "git@github.com:o/r.git",
        "file:///tmp/x.git",
        "/tmp/x.git",
        "./x.git",
        "ext::sh -c true",
        "fd::7",
        "--upload-pack=x",
        "https://github.com/x y.git",
        "",
    ];
    for repo in repos {
        let err = ws.prepare("job1", repo, "main").await;
        assert!(matches!(err, Err(WorkspaceError::InvalidRepo)), "{repo}");
        let err = ws.remove("job1", repo).await;
        assert!(matches!(err, Err(WorkspaceError::InvalidRepo)), "{repo}");
    }
    assert!(!root.exists());
    Ok(())
}

#[tokio::test]
async fn an_empty_host_list_rejects_every_https_repo() -> TestResult {
    let dir = TempDir::new()?;
    let root = dir.path().join("jobs");
    let ws = workspace(&root, RepoPolicy::new(Vec::<String>::new()));
    for repo in [REPO, "/tmp/x.git", "file:///tmp/x.git"] {
        let err = ws.prepare("job1", repo, "main").await;
        assert!(matches!(err, Err(WorkspaceError::InvalidRepo)), "{repo}");
    }
    Ok(())
}

#[tokio::test]
async fn allowed_hosts_match_whole_and_ignore_case() -> TestResult {
    let policy = RepoPolicy::new(["github.com", "git.example.com"]);
    for repo in [
        "https://github.com/o/r.git",
        "https://GitHub.com/o/r.git",
        "https://git.example.com/o/r.git",
        "https://github.com",
        "https://github.com?x=1",
    ] {
        let dir = TempDir::new()?;
        let base = dir.path().to_path_buf();
        let result = workspace(&base.join("jobs"), policy.clone())
            .prepare("job1", repo, "main")
            .await;
        assert!(result.is_ok(), "{repo}");
    }
    let dir = TempDir::new()?;
    let result = workspace(&dir.path().join("jobs"), policy)
        .prepare("job1", "https://example.com/r.git", "main")
        .await;
    assert!(matches!(result, Err(WorkspaceError::InvalidRepo)));
    Ok(())
}

#[tokio::test]
async fn local_repos_need_the_test_policy_and_still_reject_userinfo() -> TestResult {
    let dir = TempDir::new()?;
    let base = dir.path().to_path_buf();
    let ws = workspace(
        &base.join("jobs"),
        RepoPolicy::new(Vec::<String>::new()).with_file_repos(),
    );
    for repo in ["/tmp/x.git", "file:///tmp/x.git"] {
        assert!(ws.prepare("job1", repo, "main").await.is_ok(), "{repo}");
    }
    for repo in [
        "file://host/x.git",
        "file://u@/x.git",
        "relative.git",
        "http://x/y.git",
        "ssh://x/y.git",
    ] {
        let err = ws.prepare("job2", repo, "main").await;
        assert!(matches!(err, Err(WorkspaceError::InvalidRepo)), "{repo}");
    }
    Ok(())
}
