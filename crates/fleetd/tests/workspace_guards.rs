//! Workspace git hardening and repo policy against a fake `git` that records every call.
//! Own test binary because it spawns children.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use fleetd::workspace::{RepoPolicy, Workspace, WorkspaceError};
use tempfile::TempDir;

#[path = "common/bounded.rs"]
mod common;

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
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        assert_eq!(all.len(), 5);
        let expected = [
            "GIT_ALLOW_PROTOCOL",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "HOME",
            "PATH",
            "XDG_CONFIG_HOME",
        ];
        let pinned = [
            "GIT_ALLOW_PROTOCOL",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_DIR",
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
            let init = call.args.contains(" init ") || call.args.contains(" clone ");
            assert_eq!(
                names,
                if init { &expected[..] } else { &pinned[..] },
                "{}",
                call.args
            );
        }
        Ok(())
    }))
    .await
}

fn is_unpinned(args: &str) -> bool {
    args.contains(" init ") || args.contains(" clone ")
}

#[tokio::test]
async fn the_git_dir_pins_equal_the_absolute_mirror_path() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, root, all) = run(default_run(), REPO).await?;
        let mirror = root
            .join(".cache")
            .join("bc3fbd4dd8dbadfc9793e2a816228cf8fa84d7954992c487a510aced135fecdf.git");
        let mirror = mirror.to_str().ok_or("path")?;
        assert!(Path::new(mirror).is_absolute());
        let mut pinned = 0;
        let clone_git = root.join("job1").join(".git");
        let clone_git = clone_git.to_str().ok_or("path")?;
        for call in all.iter().filter(|c| !is_unpinned(&c.args)) {
            let want = if call.args.contains("--prune") {
                mirror
            } else {
                clone_git
            };
            assert_eq!(call.env.get("GIT_DIR").map(String::as_str), Some(want));
            assert_eq!(
                call.env.get("GIT_COMMON_DIR").map(String::as_str),
                Some(want)
            );
            pinned += 1;
        }
        assert_eq!(pinned, 3);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_git_dir_pins_are_absolute_for_a_relative_root() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let log = dir.path().join("calls");
        let script = dir.path().join("git");
        let body = format!(
            "#!/bin/sh\n{{\n  echo \"ARGS $*\"\n  env | sort\n  echo END\n}} >> '{}'\nexit 0\n",
            log.to_str().ok_or("path")?
        );
        std::fs::write(&script, body)?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        let cwd = std::env::current_dir()?;
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(dir.path().strip_prefix("/")?);
        relative.push("jobs");
        assert!(relative.is_relative());
        Workspace::new(&relative)
            .with_policy(default_run())
            .with_git(&script, Duration::from_secs(60))
            .prepare("job1", REPO, "main")
            .await?;
        std::fs::rename(&log, relative.join("calls"))?;
        let all = calls(&relative)?;
        let mirror = cwd
            .join(&relative)
            .join(".cache")
            .join("bc3fbd4dd8dbadfc9793e2a816228cf8fa84d7954992c487a510aced135fecdf.git");
        let mirror = mirror.to_str().ok_or("path")?;
        let mut pinned = 0;
        let clone_git = cwd.join(&relative).join("job1").join(".git");
        let clone_git = clone_git.to_str().ok_or("path")?;
        for call in all.iter().filter(|c| !is_unpinned(&c.args)) {
            let want = if call.args.contains("--prune") {
                mirror
            } else {
                clone_git
            };
            for name in ["GIT_DIR", "GIT_COMMON_DIR"] {
                let value = call.env.get(name).ok_or(name)?;
                assert!(Path::new(value).is_absolute(), "{name}={value}");
                assert_eq!(value, want, "{name}");
            }
            pinned += 1;
        }
        assert_eq!(pinned, 3);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn every_call_gets_a_scratch_home_and_no_global_or_system_config() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn every_call_disables_hooks() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        for call in &all {
            assert!(
                call.args.contains(" -c core.hooksPath=/dev/null "),
                "{}",
                call.args
            );
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn every_call_disables_redirect_following() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        for call in &all {
            assert!(
                call.args.contains(" -c http.followRedirects=false "),
                "{}",
                call.args
            );
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn every_call_disables_fsmonitor() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        for call in &all {
            assert!(call.args.contains(" -c core.fsmonitor= "), "{}", call.args);
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_config_overrides_come_before_the_subcommand() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        for call in &all {
            let words: Vec<&str> = call.args.split(' ').collect();
            assert_eq!(words[0], "-C", "{}", call.args);
            assert_eq!(
                &words[2..16],
                [
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "http.proxy=",
                    "-c",
                    "http.sslVerify=true",
                    "-c",
                    "http.curloptResolve=",
                    "-c",
                    "credential.helper="
                ]
            );
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn every_call_pins_proxy_tls_resolve_and_credential_helper() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        for pin in [
            "http.proxy=",
            "http.sslVerify=true",
            "http.curloptResolve=",
            "credential.helper=",
        ] {
            for call in &all {
                assert!(
                    call.args.contains(&format!(" -c {pin} ")),
                    "{pin} {}",
                    call.args
                );
            }
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn git_is_limited_to_https_unless_the_test_policy_adds_file() -> TestResult {
    common::bounded(Box::pin(async {
        let (_dir, _root, all) = run(default_run(), REPO).await?;
        for call in &all {
            let expected =
                if call.args.contains(" clone ") || call.args.contains("+refs/remotes/origin/*") {
                    "file"
                } else {
                    "https"
                };
            assert_eq!(
                call.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str),
                Some(expected)
            );
        }
        let local = RepoPolicy::new(Vec::<String>::new()).with_file_repos();
        let (_dir, _root, all) = run(local, "/some/origin.git").await?;
        for call in &all {
            let expected =
                if call.args.contains(" clone ") || call.args.contains("+refs/remotes/origin/*") {
                    "file"
                } else {
                    "file:https"
                };
            assert_eq!(
                call.env.get("GIT_ALLOW_PROTOCOL").map(String::as_str),
                Some(expected)
            );
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_mirror_fetches_by_explicit_url_and_configures_no_remote() -> TestResult {
    common::bounded(Box::pin(async {
    let (_dir, _root, all) = run(default_run(), REPO).await?;
    let subs: Vec<&str> = all
        .iter()
        .filter_map(|c| c.args.split(' ').nth(16))
        .collect();
    assert_eq!(subs, ["init", "fetch", "clone", "fetch", "checkout"]);
    assert!(
        all[1]
            .args
            .ends_with("fetch --prune --quiet -- https://github.com/o/r.git +refs/heads/*:refs/remotes/origin/*"),
        "{}",
        all[1].args
    );
    assert!(!all.iter().any(|c| c.args.contains(" remote ")));
    Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_mirror_is_named_by_the_sha256_of_the_repo_url() -> TestResult {
    common::bounded(Box::pin(async {
        let names = |all: &[Call]| -> Vec<String> {
            all.iter()
                .filter(|c| c.args.contains(" init "))
                .filter_map(|c| c.args.rsplit('/').next().map(str::to_owned))
                .collect()
        };
        let (_dir, _root, first) = run(default_run(), REPO).await?;
        let (_dir, _root, second) = run(default_run(), "https://github.com/o/s.git").await?;
        let (a, b) = (names(&first), names(&second));
        assert_eq!(a.len(), 1);
        assert_ne!(a, b);
        for name in a.iter().chain(&b) {
            let stem = name.strip_suffix(".git").ok_or("suffix")?;
            assert_eq!(stem.len(), 64, "{name}");
            assert!(stem.bytes().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
        assert_eq!(
            a[0],
            "bc3fbd4dd8dbadfc9793e2a816228cf8fa84d7954992c487a510aced135fecdf.git"
        );
        Ok(())
    }))
    .await
}

fn with_credential(root: &Path, policy: RepoPolicy) -> Workspace {
    workspace(root, policy).with_credential("/opt/fleetd bin/fleetd", "tok-for-fetch".to_owned())
}

#[tokio::test]
async fn only_the_fetch_child_carries_the_scoped_credential() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let root = dir.path().join("jobs");
        with_credential(&root, default_run())
            .prepare("job1", REPO, "main")
            .await?;
        let all = calls(&root)?;
        for call in &all {
            let fetch = call.args.contains(" fetch ") && call.args.contains("--prune");
            assert_eq!(call.env.contains_key("GH_TOKEN"), fetch, "{}", call.args);
            assert_eq!(call.env.contains_key("GIT_ASKPASS"), fetch, "{}", call.args);
            assert_eq!(
                call.env.contains_key("FLEETD_ASKPASS_HOST"),
                fetch,
                "{}",
                call.args
            );
        }
        let fetch = all
            .iter()
            .find(|c| c.args.contains(" fetch ") && c.args.contains("--prune"))
            .ok_or("fetch")?;
        assert_eq!(fetch.env["GH_TOKEN"], "tok-for-fetch");
        assert_eq!(fetch.env["FLEETD_ASKPASS_HOST"], "github.com");
        assert_eq!(fetch.env["GIT_ASKPASS"], "/opt/fleetd bin/fleetd");
        assert_eq!(fetch.env["FLEETD_ASKPASS"], "1");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_fetch_from_another_allowed_host_carries_no_credential() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let root = dir.path().join("jobs");
        let policy = RepoPolicy::new(["github.com", "gitlab.com"]);
        with_credential(&root, policy)
            .prepare("job1", "https://gitlab.com/o/r.git", "main")
            .await?;
        for call in calls(&root)? {
            for name in ["GH_TOKEN", "GIT_ASKPASS", "FLEETD_ASKPASS_HOST"] {
                assert!(!call.env.contains_key(name), "{name} {}", call.args);
            }
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn an_empty_token_or_no_token_host_gives_the_fetch_no_credential() -> TestResult {
    common::bounded(Box::pin(async {
        for (policy, token) in [
            (default_run(), ""),
            (RepoPolicy::new(["git.example.com"]), "tok"),
        ] {
            let dir = TempDir::new()?;
            let root = dir.path().join("jobs");
            let repo = if token.is_empty() {
                REPO
            } else {
                "https://git.example.com/o/r.git"
            };
            workspace(&root, policy)
                .with_credential("/bin/fleetd", token.to_owned())
                .prepare("job1", repo, "main")
                .await?;
            for call in calls(&root)? {
                assert!(!call.env.contains_key("GH_TOKEN"), "{}", call.args);
            }
        }
        Ok(())
    }))
    .await
}

#[test]
fn the_token_host_defaults_to_github_and_must_be_an_allowed_host() {
    assert_eq!(default_run().token_host(), Some("github.com"));
    assert_eq!(RepoPolicy::new(["git.example.com"]).token_host(), None);
    let two = RepoPolicy::new(["github.com", "gitlab.com"]);
    let moved = two.clone().with_token_host(Some("gitlab.com".to_owned()));
    assert_eq!(moved.token_host(), Some("gitlab.com"));
    let stray = two.with_token_host(Some("evil.example".to_owned()));
    assert_eq!(stray.token_host(), None);
}

#[test]
fn the_workspace_debug_output_hides_the_token() {
    let ws = Workspace::new("/x").with_credential("/bin/fleetd", "tok-for-fetch".to_owned());
    assert!(!format!("{ws:?}").contains("tok-for-fetch"));
}

#[tokio::test]
async fn repos_outside_https_on_an_allowed_host_run_no_git() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn an_empty_host_list_rejects_every_https_repo() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root, RepoPolicy::new(Vec::<String>::new()));
        for repo in [REPO, "/tmp/x.git", "file:///tmp/x.git"] {
            let err = ws.prepare("job1", repo, "main").await;
            assert!(matches!(err, Err(WorkspaceError::InvalidRepo)), "{repo}");
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn allowed_hosts_match_whole_and_ignore_case() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn local_repos_need_the_test_policy_and_still_reject_userinfo() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}
