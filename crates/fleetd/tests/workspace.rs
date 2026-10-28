//! Runs real git against a local bare repo. Own test binary because it spawns children.

use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::Job;
use fleetd::AgentLauncher;
use fleetd::broker::{
    Broker, BrokerError, Denial, ExecError, GH_PATH, GhCli, GhExecutor, GitExecutor, Limits,
    MAX_CHECKS, MAX_OUTPUT_BYTES, MirrorGit, PushTarget, Request, Response,
};
use fleetd::workspace::{RepoPolicy, Workspace, WorkspaceError};
use tempfile::TempDir;

#[path = "common/bounded.rs"]
mod common;
#[path = "common/reader.rs"]
mod reader;

use reader::hold_reader;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GIT_BAND: Duration = Duration::from_secs(2);

fn local_policy() -> RepoPolicy {
    RepoPolicy::new(Vec::<String>::new()).with_file_repos()
}

fn workspace(root: impl Into<PathBuf>) -> Workspace {
    Workspace::new(root).with_policy(local_policy())
}

fn git(dir: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(format!("git {args:?} failed").into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn fixture(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bare = dir.join("origin.git");
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed)?;
    git(
        dir,
        &["init", "--bare", "--quiet", "-b", "main", "origin.git"],
    )?;
    git(&seed, &["init", "--quiet", "-b", "main"])?;
    std::fs::write(seed.join("a.txt"), "one")?;
    git(&seed, &["add", "."])?;
    git(&seed, &["commit", "--quiet", "-m", "one"])?;
    git(
        &seed,
        &["push", "--quiet", bare.to_str().ok_or("path")?, "main"],
    )?;
    Ok(bare.to_str().ok_or("path")?.to_owned())
}

#[tokio::test]
async fn worktree_on_branch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let ws = workspace(dir.path().join("jobs"));

        let first = ws.prepare("job1", &repo, "main").await?;
        assert_eq!(first.branch, "swarm/job1");
        assert_eq!(first.path, dir.path().join("jobs").join("job1"));
        assert_eq!(std::fs::read_to_string(first.path.join("a.txt"))?, "one");
        assert_eq!(
            git(&first.path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
            "swarm/job1"
        );

        let seed = dir.path().join("seed");
        std::fs::write(seed.join("b.txt"), "two")?;
        git(&seed, &["add", "."])?;
        git(&seed, &["commit", "--quiet", "-m", "two"])?;
        git(&seed, &["push", "--quiet", &repo, "main"])?;

        let second = ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(second.path.join("b.txt"))?, "two");
        assert!(!first.path.join("b.txt").exists());
        assert_eq!(
            git(&first.path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
            "swarm/job1"
        );

        let cache = dir.path().join("jobs").join(".cache");
        assert_eq!(std::fs::read_dir(cache)?.count(), 1);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_checkout_is_a_clone_that_borrows_the_mirror_objects() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let checkout = workspace(&root).prepare("job1", &repo, "main").await?;
        assert!(checkout.path.join(".git").is_dir());
        let mirror = only_mirror(&root)?;
        let alternates =
            std::fs::read_to_string(checkout.path.join(".git/objects/info/alternates"))?;
        assert_eq!(
            std::fs::canonicalize(alternates.trim())?,
            std::fs::canonicalize(mirror.join("objects"))?
        );
        assert!(!mirror.join("worktrees").exists());
        assert!(
            git(
                &mirror,
                &["rev-parse", "--verify", "--quiet", "refs/heads/swarm/job1"]
            )
            .is_err()
        );
        assert_eq!(
            git(&checkout.path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
            "swarm/job1"
        );
        assert_eq!(git(&checkout.path, &["status", "--porcelain"])?, "");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_clone_holds_no_objects_and_links_none_from_the_mirror() -> TestResult {
    common::bounded(Box::pin(async {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let checkout = workspace(&root).prepare("job1", &repo, "main").await?;
        let mut names = std::fs::read_dir(checkout.path.join(".git/objects"))?
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        assert_eq!(names, ["info", "pack"]);
        let mirror = only_mirror(&root)?;
        let mut stack = vec![mirror.join("objects")];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    stack.push(entry.path());
                } else {
                    assert_eq!(entry.metadata()?.nlink(), 1, "{:?}", entry.path());
                }
            }
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_job_id_of_the_longest_accepted_length_prepares() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let id = format!("A_{}", "z9".repeat(31));
        assert_eq!(id.len(), 64);
        let checkout = workspace(dir.path().join("jobs"))
            .prepare(&id, &repo, "main")
            .await?;
        assert_eq!(checkout.branch, format!("swarm/{id}"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_job_group_shares_the_cache_and_worktree_and_unset_does_not() -> TestResult {
    use std::os::unix::fs::MetadataExt;
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let gid = std::fs::metadata(dir.path())?.gid();
        let mode = |p: &Path| std::fs::metadata(p).map(|m| m.mode() & 0o7777);
        let plain = dir.path().join("plain");
        let checkout = workspace(&plain).prepare("j1", &repo, "main").await?;
        assert_eq!(mode(&plain.join(".cache"))? & 0o2020, 0);
        assert_eq!(mode(&checkout.path)? & 0o2020, 0);
        let shared = dir.path().join("shared");
        let checkout = workspace(&shared)
            .with_job_group(Some(gid))
            .prepare("j1", &repo, "main")
            .await?;
        assert_eq!(mode(&shared.join(".cache"))?, 0o2750);
        let mirror = only_mirror(&shared)?;
        assert_eq!(mode(&mirror)? & 0o022, 0);
        assert_eq!(mode(&mirror.join("objects"))? & 0o022, 0);
        assert_eq!(mode(&checkout.path)?, 0o2770);
        assert_eq!(mode(&checkout.path.join("a.txt"))? & 0o070, 0o060);
        assert_eq!(mode(&shared.join(".git-home"))? & 0o2020, 0);
        Ok(())
    }))
    .await
}

fn only_mirror(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(std::fs::read_dir(root.join(".cache"))?
        .map(|entry| entry.map(|e| e.path()))
        .find(|path| {
            path.as_ref()
                .is_ok_and(|p| p.extension().is_some_and(|e| e == "git"))
        })
        .ok_or("no mirror")??)
}

#[tokio::test]
async fn a_mirror_with_a_stale_remote_still_fetches_the_job_repo() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        git(&mirror, &["remote", "add", "origin", "/nowhere.git"])?;
        let second = ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(second.path.join("a.txt"))?, "one");
        Ok(())
    }))
    .await
}

fn advance(dir: &Path, name: &str) -> TestResult {
    let seed = dir.join("seed");
    std::fs::write(seed.join(name), name)?;
    git(&seed, &["add", "."])?;
    git(&seed, &["commit", "--quiet", "-m", name])?;
    let bare = dir.join("origin.git");
    git(
        &seed,
        &["push", "--quiet", bare.to_str().ok_or("path")?, "main"],
    )?;
    Ok(())
}

fn inode(path: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::symlink_metadata(path)?.ino())
}

#[tokio::test]
async fn a_clean_mirror_is_not_rebuilt_by_a_second_prepare() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        std::fs::write(mirror.join("marker"), "kept")?;
        let before = inode(&mirror)?;
        ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(mirror.join("marker"))?, "kept");
        assert_eq!(inode(&mirror)?, before);
        assert_eq!(git(&mirror, &["config", "--get", "gc.auto"])?, "0");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn stale_locks_from_a_killed_fetch_do_not_wedge_the_next_prepare() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        advance(dir.path(), "b.txt")?;
        std::fs::write(mirror.join("refs/remotes/origin/main.lock"), "")?;
        std::fs::write(mirror.join("shallow.lock"), "")?;
        std::fs::write(mirror.join("packed-refs.lock"), "")?;
        let second = ws.prepare("job2", &repo, "main").await?;
        assert!(second.path.join("b.txt").is_file());
        assert!(!mirror.join("refs/remotes/origin/main.lock").exists());
        assert!(!mirror.join("shallow.lock").exists());
        assert!(!mirror.join("packed-refs.lock").exists());
        Ok(())
    }))
    .await
}

async fn assert_rebuilt(
    plant: impl FnOnce(&Path, &Path) -> TestResult,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let repo = fixture(dir.path())?;
    let root = dir.path().join("jobs");
    let ws = workspace(&root);
    ws.prepare("job1", &repo, "main").await?;
    let mirror = only_mirror(&root)?;
    std::fs::write(mirror.join("marker"), "old")?;
    plant(&mirror, dir.path())?;
    let second = ws.prepare("job2", &repo, "main").await?;
    assert!(second.path.join("a.txt").is_file());
    assert!(!mirror.join("marker").exists(), "mirror was not rebuilt");
    assert_eq!(git(&mirror, &["config", "--get", "gc.auto"])?, "0");
    assert!(!dir.path().join("pwned").exists());
    Ok(dir.keep())
}

fn append_config(mirror: &Path, text: &str) -> TestResult {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(mirror.join("config"))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

fn pwn_command(base: &Path) -> String {
    format!("!touch {}/pwned; true", base.display())
}

#[tokio::test]
async fn a_planted_alternates_file_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, base| {
            std::fs::write(
                mirror.join("objects/info/alternates"),
                format!("{}\n", base.display()),
            )?;
            Ok(())
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_alternate_refs_command_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, base| {
            std::fs::write(
                mirror.join("objects/info/alternates"),
                format!("{}\n", mirror.join("objects").display()),
            )?;
            append_config(
                mirror,
                &format!("[core]\n\talternateRefsCommand = {}\n", pwn_command(base)),
            )
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_cookie_file_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, base| {
            append_config(
                mirror,
                &format!(
                    "[http]\n\tcookieFile = {0}/pwned\n\tsaveCookies = true\n",
                    base.display()
                ),
            )
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_instead_of_rule_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, _| {
            append_config(mirror, "[url \"/nowhere.git\"]\n\tinsteadOf = origin.git\n")
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_include_path_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, base| {
            std::fs::write(
                mirror.join("extra"),
                format!("[core]\n\talternateRefsCommand = {}\n", pwn_command(base)),
            )?;
            append_config(mirror, "[include]\n\tpath = extra\n")
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_symlink_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, base| {
            std::os::unix::fs::symlink(base, mirror.join("objects/link"))?;
            Ok(())
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_group_writable_file_gets_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, _| {
            std::fs::set_permissions(mirror.join("HEAD"), std::fs::Permissions::from_mode(0o664))?;
            Ok(())
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_commondir_and_config_worktree_get_the_mirror_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, base| {
            std::fs::write(mirror.join("commondir"), format!("{}\n", base.display()))?;
            std::fs::write(mirror.join("config.worktree"), "")?;
            Ok(())
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_mirror_missing_its_gc_settings_is_repaired() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, _| {
            git(mirror, &["config", "--unset", "gc.pruneExpire"])?;
            Ok(())
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_mirror_dir_without_head_is_rebuilt() -> TestResult {
    common::bounded(Box::pin(async {
        assert_rebuilt(|mirror, _| {
            std::fs::remove_file(mirror.join("HEAD"))?;
            Ok(())
        })
        .await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_second_prepare_of_the_same_job_after_remove_succeeds_and_remove_deletes_the_branch()
-> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        ws.remove("job1", &repo).await?;
        let mirror = only_mirror(&root)?;
        assert!(
            git(
                &mirror,
                &["rev-parse", "--verify", "--quiet", "refs/heads/swarm/job1"]
            )
            .is_err()
        );
        assert!(!root.join("job1").exists());
        let again = ws.prepare("job1", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(again.path.join("a.txt"))?, "one");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_second_prepare_of_the_same_job_replaces_an_aborted_one() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        let first = ws.prepare("job1", &repo, "main").await?;
        std::fs::write(first.path.join("stray.txt"), "x")?;
        let again = ws.prepare("job1", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(again.path.join("a.txt"))?, "one");
        assert!(!again.path.join("stray.txt").exists());
        let mirror = only_mirror(&root)?;
        git(&mirror, &["branch", "swarm/job2", "origin/main"])?;
        let third = ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(third.path.join("a.txt"))?, "one");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_mirror_dir_is_a_sha256_hex_name() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        workspace(&root).prepare("job1", &repo, "main").await?;
        let name = only_mirror(&root)?
            .file_name()
            .ok_or("name")?
            .to_string_lossy()
            .into_owned();
        let stem = name.strip_suffix(".git").ok_or("suffix")?;
        assert_eq!(stem.len(), 64, "{name}");
        assert!(stem.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn remove_deletes_the_worktree_and_scratch_and_keeps_the_mirror() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        let checkout = ws.prepare("job1", &repo, "main").await?;
        std::fs::create_dir(root.join(".finish-job1"))?;
        std::fs::create_dir_all(root.join(".agent").join("job1"))?;
        std::fs::create_dir_all(root.join(".agent").join("job1.tmp"))?;
        std::fs::create_dir_all(root.join(".agent").join("job1b"))?;
        ws.remove("job1", &repo).await?;
        assert!(!checkout.path.exists());
        assert!(!root.join(".finish-job1").exists());
        assert!(!root.join(".agent").join("job1").exists());
        assert!(!root.join(".agent").join("job1.tmp").exists());
        assert!(root.join(".agent").join("job1b").exists());
        assert_eq!(std::fs::read_dir(root.join(".cache"))?.count(), 1);
        let mirror = std::fs::read_dir(root.join(".cache"))?
            .next()
            .ok_or("no mirror")??
            .path();
        let listed = git(&mirror, &["worktree", "list", "--porcelain"])?;
        assert!(!listed.contains("job1"), "{listed}");
        ws.remove("job1", &repo).await?;
        ws.prepare("job1b", &repo, "main").await?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn rejects_unsafe_inputs_before_running_git() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let root = dir.path().join("jobs");
        let ws =
            Workspace::new(&root).with_policy(RepoPolicy::new(["example.com"]).with_file_repos());
        let repos = [
            "--upload-pack=touch /tmp/x",
            "-oProxyCommand=x",
            "https://user:pw@example.com/r.git",
            "https://token@example.com/r.git",
            "git@example.com:r.git",
            "ext::sh -c true",
            "",
        ];
        for repo in repos {
            let err = ws.prepare("job1", repo, "main").await;
            assert!(matches!(err, Err(WorkspaceError::InvalidRepo)), "{repo}");
        }
        for name in ["-x", "", "a..b", "a b", "x:y", "a/"] {
            let err = ws.prepare("job1", "/repo.git", name).await;
            assert!(matches!(err, Err(WorkspaceError::InvalidRef)), "{name}");
        }
        let long = "a".repeat(65);
        for id in [
            "", "-x", "a/b", "a b", "../x", "a-b", "a.b", "a:b", "a~b", "a\u{e9}", "a\nb", &long,
        ] {
            let err = ws.prepare(id, "/repo.git", "main").await;
            assert!(matches!(err, Err(WorkspaceError::InvalidJobId)), "{id}");
        }
        assert!(!root.exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn errors_carry_no_input() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let ws = workspace(dir.path().join("jobs"));
        let secret = dir.path().join("missing-secret-name.git");
        let err = ws
            .prepare("job1", secret.to_str().ok_or("path")?, "main")
            .await
            .err()
            .ok_or("expected error")?;
        let text = err.to_string();
        assert!(!text.contains("missing-secret-name"));
        Ok(())
    }))
    .await
}

fn hanging_git() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("git");
        std::fs::write(&path, "#!/bin/sh\nexec sleep 300\n")
            .unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        (dir, path)
    });
    path
}

#[tokio::test]
async fn a_hung_git_command_is_killed_at_the_timeout() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let ws = workspace(dir.path().join("jobs")).with_git(hanging_git(), GIT_BAND);
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            ws.prepare("job1", "/missing.git", "main"),
        )
        .await?;
        assert!(matches!(result, Err(WorkspaceError::GitTimeout("init"))));
        Ok(())
    }))
    .await
}

fn forking_git() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("git");
        let script = "#!/bin/sh\nsub=\nfor a; do [ \"$a\" = init ] && sub=init; done\ncase \"$sub\" in\ninit)\nfor last; do :; done\nbase=$(dirname \"$last\")\nsleep 300 > \"$base/hold\" &\nread x < \"$base/ready\" ;;\nesac\nexit 0\n";
        std::fs::write(&path, script).unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        (dir, path)
    });
    path
}

#[tokio::test]
async fn a_background_descendant_of_a_clean_git_exit_is_killed() -> TestResult {
    common::bounded(Box::pin(async {
        use tokio::io::AsyncWriteExt;
        let dir = TempDir::new()?;
        let cache = dir.path().join("jobs").join(".cache");
        std::fs::create_dir_all(&cache)?;
        for name in ["hold", "ready"] {
            assert!(
                Command::new("mkfifo")
                    .arg(cache.join(name))
                    .status()?
                    .success()
            );
        }
        let mut reader = hold_reader(&cache.join("hold"));
        let ready = cache.join("ready");
        let ws =
            workspace(dir.path().join("jobs")).with_git(forking_git(), Duration::from_secs(60));
        let repo = "/missing.git";
        let (result, driven) = tokio::join!(ws.prepare("job1", repo, "main"), async {
            reader.wait_opened().await?;
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(ready)
                .await?;
            file.write_all(b"go\n").await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        driven?;
        result?;
        reader.wait_eof().await?;
        Ok(())
    }))
    .await
}

fn noisy_git(dir: &Path, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("noisy-git");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\nexit 1\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

#[tokio::test]
async fn a_failed_git_step_carries_the_step_and_the_stderr_tail() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let missing = dir.path().join("nowhere.git");
        let ws = workspace(dir.path().join("jobs"));
        let err = ws
            .prepare("job1", missing.to_str().ok_or("path")?, "main")
            .await
            .err()
            .ok_or("fetch succeeded")?;
        let WorkspaceError::Git(step, detail) = &err else {
            return Err(format!("unexpected {err:?}").into());
        };
        assert_eq!(*step, "fetch");
        assert!(detail.contains("fatal:"), "{detail}");
        assert_eq!(err.to_string(), "git fetch failed");
        assert_eq!(err.detail(), Some(detail.as_str()));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_detached_descendant_holding_stderr_cannot_stall_a_failed_git_step() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let git = noisy_git(
            dir.path(),
            "echo 'fatal: before detach' >&2\nready=\"$(dirname \"$0\")/detached\"\nperl -e 'use POSIX; POSIX::setsid(); open(F, \">\", shift); close(F); exec @ARGV' \"$ready\" sleep 60 &\nwhile [ ! -e \"$ready\" ]; do sleep 0.1; done",
        )?;
        let ws = workspace(dir.path().join("jobs")).with_git(git, Duration::from_secs(60));
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            ws.prepare("job1", "/nowhere.git", "main"),
        )
        .await?;
        assert!(matches!(result, Err(WorkspaceError::Git("init", _))));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn git_stderr_is_redacted_before_it_is_kept() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let secret = "ghp_not-a-real-secret-value";
        let git = noisy_git(
            dir.path(),
            &format!("echo 'fatal: auth {secret} rejected' >&2"),
        )?;
        let ws = workspace(dir.path().join("jobs"))
            .with_git(git, GIT_BAND)
            .with_redactor(Redactor::new([secret]));
        let err = ws
            .prepare("job1", "/nowhere.git", "main")
            .await
            .err()
            .ok_or("succeeded")?;
        let detail = err.detail().ok_or("no detail")?;
        assert!(detail.contains("fatal: auth"), "{detail}");
        assert!(!detail.contains(secret), "{detail}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn git_stderr_is_cut_to_a_tail_and_a_split_secret_does_not_leak() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let secret = "ghp_not-a-real-secret-value";
        let body = format!(
            "head -c 100000 /dev/zero | tr '\\0' 'a' >&2\necho '{secret}' >&2\nhead -c 489 /dev/zero | tr '\\0' 'b' >&2\necho tail-marker >&2"
        );
        let git = noisy_git(dir.path(), &body)?;
        let ws = workspace(dir.path().join("jobs"))
            .with_git(git, GIT_BAND)
            .with_redactor(Redactor::new([secret]));
        let err = ws
            .prepare("job1", "/nowhere.git", "main")
            .await
            .err()
            .ok_or("succeeded")?;
        let detail = err.detail().ok_or("no detail")?;
        assert!(detail.len() <= 512, "{}", detail.len());
        assert!(detail.ends_with("tail-marker\n"), "{detail}");
        assert!(!detail.contains("ghp_"), "{detail}");
        assert!(!detail.contains("value"), "{detail}");
        assert!(!detail.contains(&"a".repeat(64)), "{detail}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_sha_base_clones_that_commit_and_not_the_branch_tip() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let seed = dir.path().join("seed");
        let pinned = git(&seed, &["rev-parse", "HEAD"])?;
        std::fs::write(seed.join("b.txt"), "two")?;
        git(&seed, &["add", "."])?;
        git(&seed, &["commit", "--quiet", "-m", "two"])?;
        git(&seed, &["push", "--quiet", &repo, "main"])?;
        let tip = git(&seed, &["rev-parse", "HEAD"])?;
        assert_ne!(pinned, tip);

        let ws = workspace(dir.path().join("jobs"));
        let checkout = ws.prepare("job1", &repo, &pinned).await?;
        assert_eq!(checkout.branch, "swarm/job1");
        assert_eq!(git(&checkout.path, &["rev-parse", "HEAD"])?, pinned);
        assert_eq!(
            git(&checkout.path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
            "swarm/job1"
        );
        assert!(checkout.path.join("a.txt").exists());
        assert!(!checkout.path.join("b.txt").exists());

        let branch = ws.prepare("job2", &repo, "main").await?;
        assert_eq!(git(&branch.path, &["rev-parse", "HEAD"])?, tip);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_sha_the_repo_does_not_hold_fails_with_a_fixed_error() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let ws = workspace(dir.path().join("jobs"));
        let missing = "0123456789abcdef0123456789abcdef01234567";
        let err = ws
            .prepare("job1", &repo, missing)
            .await
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(err, WorkspaceError::Git(_, _)), "{err:?}");
        assert!(!dir.path().join("jobs").join("job1").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_branch_named_like_a_short_hex_is_still_a_branch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let seed = dir.path().join("seed");
        git(
            &seed,
            &["push", "--quiet", &repo, "main:refs/heads/abcdef0"],
        )?;
        let ws = workspace(dir.path().join("jobs"));
        let checkout = ws.prepare("job1", &repo, "abcdef0").await?;
        assert!(checkout.path.join("a.txt").exists());
        Ok(())
    }))
    .await
}

fn real_git() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::var_os("PATH").ok_or("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| "git".into())
}

const PRODUCTION_REPO: &str = "https://github.com/o/r.git";

#[tokio::test]
async fn a_production_policy_prepare_clones_from_a_local_mirror_end_to_end() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let origin = fixture(dir.path())?;
        let wrapper = dir.path().join("git-wrapper");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nn=$#\ni=0\nwhile [ $i -lt $n ]; do\n  a=$1\n  shift\n  if [ \"$a\" = \"{PRODUCTION_REPO}\" ]; then\n    a=\"{origin}\"\n    export GIT_ALLOW_PROTOCOL=file\n  fi\n  set -- \"$@\" \"$a\"\n  i=$((i+1))\ndone\nexec \"{}\" \"$@\"\n",
                real_git()?.display()
            ),
        )?;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))?;
        let root = dir.path().join("jobs");
        let checkout = Workspace::new(&root)
            .with_policy(RepoPolicy::new(["github.com"]))
            .with_git(&wrapper, Duration::from_secs(60))
            .prepare("job1", PRODUCTION_REPO, "main")
            .await?;
        assert_eq!(
            git(&checkout.path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
            "swarm/job1"
        );
        assert!(checkout.path.join("a.txt").is_file());
        assert!(checkout.path.join(".git/objects/info/alternates").is_file());
        Ok(())
    }))
    .await
}

fn relative_to_cwd(target: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let target = target.canonicalize()?;
    let shared = cwd
        .components()
        .zip(target.components())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in cwd.components().skip(shared) {
        out.push("..");
    }
    out.extend(target.components().skip(shared));
    Ok(out)
}

#[tokio::test]
async fn a_relative_jobs_root_prepares_a_checkout() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = relative_to_cwd(dir.path())?.join("jobs");
        assert!(root.is_relative());
        let checkout = workspace(&root).prepare("job1", &repo, "main").await?;
        assert_eq!(
            git(&checkout.path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
            "swarm/job1"
        );
        assert!(checkout.path.join("a.txt").is_file());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_clone_dir_is_removed_when_a_step_after_the_clone_fails() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let result = workspace(&root)
            .with_after_clone(|_| Err(std::io::Error::other("injected")))
            .prepare("job1", &repo, "main")
            .await;
        assert!(matches!(result, Err(WorkspaceError::Io(_))));
        assert!(!root.join("job1").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_mirror_config_turns_off_auto_gc_and_pruning() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        workspace(&root).prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        assert_eq!(git(&mirror, &["config", "--get", "gc.auto"])?, "0");
        assert_eq!(
            git(&mirror, &["config", "--get", "gc.pruneExpire"])?,
            "never"
        );
        Ok(())
    }))
    .await
}

async fn prepared_mirror()
-> Result<(TempDir, String, PathBuf, Workspace, PathBuf), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let repo = fixture(dir.path())?;
    let root = dir.path().join("jobs");
    let ws = workspace(&root);
    ws.prepare("job1", &repo, "main").await?;
    let mirror = only_mirror(&root)?;
    Ok((dir, repo, root, ws, mirror))
}

#[tokio::test]
async fn a_half_deleted_mirror_is_rebuilt_and_the_next_prepare_succeeds() -> TestResult {
    for gone in ["objects", "refs", "objects/pack", "objects/info"] {
        tokio::time::timeout(Duration::from_secs(60), async {
            let (_dir, repo, _root, ws, mirror) = prepared_mirror().await?;
            std::fs::write(mirror.join("marker"), "old")?;
            std::fs::remove_dir_all(mirror.join(gone))?;
            let second = ws.prepare("job2", &repo, "main").await?;
            assert!(second.path.join("a.txt").is_file(), "{gone}");
            assert!(!mirror.join("marker").exists(), "{gone} not rebuilt");
            assert!(mirror.join("refs").is_dir() && mirror.join("objects/pack").is_dir());
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn a_mirror_missing_head_or_config_is_rebuilt() -> TestResult {
    for gone in ["HEAD", "config"] {
        let (_dir, repo, _root, ws, mirror) = prepared_mirror().await?;
        std::fs::write(mirror.join("marker"), "old")?;
        std::fs::remove_file(mirror.join(gone))?;
        let second = ws.prepare("job2", &repo, "main").await?;
        assert!(second.path.join("a.txt").is_file(), "{gone}");
        assert!(!mirror.join("marker").exists(), "{gone} not rebuilt");
    }
    Ok(())
}

#[tokio::test]
async fn a_stale_old_directory_does_not_break_prepare() -> TestResult {
    let (_dir, repo, _root, ws, mirror) = prepared_mirror().await?;
    let old = mirror.with_extension("old");
    std::fs::create_dir_all(old.join("nested"))?;
    std::fs::write(old.join("nested/f"), "x")?;
    std::fs::write(mirror.join("marker"), "old")?;
    std::fs::remove_dir_all(mirror.join("objects"))?;
    ws.prepare("job2", &repo, "main").await?;
    assert!(!old.exists());
    assert!(!mirror.join("marker").exists());
    Ok(())
}

#[tokio::test]
async fn a_stale_old_file_does_not_break_prepare() -> TestResult {
    let (_dir, repo, _root, ws, mirror) = prepared_mirror().await?;
    let old = mirror.with_extension("old");
    std::fs::write(&old, "x")?;
    std::fs::write(mirror.join("marker"), "old")?;
    std::fs::remove_dir_all(mirror.join("refs"))?;
    ws.prepare("job2", &repo, "main").await?;
    assert!(!old.exists());
    assert!(!mirror.join("marker").exists());
    Ok(())
}

#[tokio::test]
async fn a_stale_old_symlink_is_removed_without_touching_its_target() -> TestResult {
    let (dir, repo, _root, ws, mirror) = prepared_mirror().await?;
    let target = dir.path().join("victim");
    std::fs::create_dir_all(&target)?;
    std::fs::write(target.join("keep"), "kept")?;
    std::os::unix::fs::symlink(&target, mirror.with_extension("old"))?;
    std::fs::remove_dir_all(mirror.join("refs"))?;
    ws.prepare("job2", &repo, "main").await?;
    assert_eq!(std::fs::read_to_string(target.join("keep"))?, "kept");
    assert!(std::fs::symlink_metadata(mirror.with_extension("old")).is_err());
    Ok(())
}

#[tokio::test]
async fn a_file_at_the_init_path_does_not_break_prepare() -> TestResult {
    let dir = TempDir::new()?;
    let repo = fixture(dir.path())?;
    let root = dir.path().join("jobs");
    let ws = workspace(&root);
    ws.prepare("job1", &repo, "main").await?;
    let mirror = only_mirror(&root)?;
    std::fs::remove_dir_all(&mirror)?;
    std::fs::write(mirror.with_extension("init"), "x")?;
    let second = ws.prepare("job2", &repo, "main").await?;
    assert!(second.path.join("a.txt").is_file());
    Ok(())
}

#[tokio::test]
async fn a_symlink_at_the_init_path_is_removed_without_touching_its_target() -> TestResult {
    let dir = TempDir::new()?;
    let repo = fixture(dir.path())?;
    let root = dir.path().join("jobs");
    let ws = workspace(&root);
    ws.prepare("job1", &repo, "main").await?;
    let mirror = only_mirror(&root)?;
    std::fs::remove_dir_all(&mirror)?;
    let target = dir.path().join("victim");
    std::fs::create_dir_all(&target)?;
    std::fs::write(target.join("keep"), "kept")?;
    std::os::unix::fs::symlink(&target, mirror.with_extension("init"))?;
    let second = ws.prepare("job2", &repo, "main").await?;
    assert!(second.path.join("a.txt").is_file());
    assert_eq!(std::fs::read_to_string(target.join("keep"))?, "kept");
    assert_eq!(std::fs::read_dir(&target)?.count(), 1);
    Ok(())
}

struct LoggedGit {
    wrapper: PathBuf,
    log: PathBuf,
}

fn logged_git(
    base: &Path,
    origin: &str,
    sleep: &str,
) -> Result<LoggedGit, Box<dyn std::error::Error>> {
    let wrapper = base.join("git-logged");
    let log = base.join("git.log");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nstep=\"$*\"\necho \"start allow=$GIT_ALLOW_PROTOCOL askpass=$GIT_ASKPASS $step\" >> \"{log}\"\nfor a in \"$@\"; do\n  shift\n  if [ \"$a\" = \"{PRODUCTION_REPO}\" ]; then\n    a=\"{origin}\"\n    export GIT_ALLOW_PROTOCOL=file\n  fi\n  set -- \"$@\" \"$a\"\ndone\nsleep {sleep}\n\"{real}\" \"$@\"\nrc=$?\necho \"end\" >> \"{log}\"\nexit $rc\n",
            log = log.display(),
            real = real_git()?.display()
        ),
    )?;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))?;
    Ok(LoggedGit { wrapper, log })
}

fn production(root: &Path, git: &LoggedGit) -> Workspace {
    Workspace::new(root)
        .with_policy(RepoPolicy::new(["github.com"]))
        .with_git(&git.wrapper, Duration::from_secs(60))
}

fn single_mirror(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut found = std::fs::read_dir(root.join(".cache"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    found.retain(|p| p.extension().is_some_and(|e| e == "git"));
    match found.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err("expected one mirror".into()),
    }
}

#[tokio::test]
async fn a_production_policy_mirror_refresh_fetches_new_commits_through_a_relative_root()
-> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let origin = fixture(dir.path())?;
        let git_wrapper = logged_git(dir.path(), &origin, "0")?;
        let root = relative_to_cwd(dir.path())?.join("jobs");
        assert!(root.is_relative());
        let ws = production(&root, &git_wrapper).with_credential("askpass-bin", "tok".to_owned());
        ws.prepare("job1", PRODUCTION_REPO, "main").await?;
        let seed = dir.path().join("seed");
        std::fs::write(seed.join("b.txt"), "two")?;
        git(&seed, &["add", "."])?;
        git(&seed, &["commit", "--quiet", "-m", "two"])?;
        git(&seed, &["push", "--quiet", &origin, "main"])?;
        let log_before = std::fs::read_to_string(&git_wrapper.log)?;
        ws.fetch_mirror(PRODUCTION_REPO).await?;
        let mirror = single_mirror(&root)?;
        assert_eq!(
            git(&mirror, &["rev-parse", "refs/remotes/origin/main"])?,
            git(&seed, &["rev-parse", "HEAD"])?
        );
        let log = std::fs::read_to_string(&git_wrapper.log)?;
        let new = &log[log_before.len()..];
        let fetch = new
            .lines()
            .find(|l| l.contains(" fetch ") && l.contains(PRODUCTION_REPO))
            .ok_or("no fetch logged")?;
        assert!(fetch.contains("allow=https "), "{fetch}");
        assert!(fetch.contains("askpass=askpass-bin"), "{fetch}");
        assert!(!log.contains("tok"), "token reached argv");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_mirror_refresh_rejects_a_repo_the_policy_refuses_before_git_runs() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let git_wrapper = logged_git(dir.path(), "unused", "0")?;
        let ws = production(&dir.path().join("jobs"), &git_wrapper);
        for repo in [
            "https://evil.example/o/r.git",
            "file:///etc",
            "ssh://github.com/o/r.git",
            "--upload-pack=x",
            "",
        ] {
            assert!(matches!(
                ws.fetch_mirror(repo).await,
                Err(WorkspaceError::InvalidRepo)
            ));
        }
        assert!(!git_wrapper.log.exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_hostile_mirror_is_rebuilt_before_a_broker_refresh() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let origin = fixture(dir.path())?;
        let git_wrapper = logged_git(dir.path(), &origin, "0")?;
        let root = dir.path().join("jobs");
        let ws = production(&root, &git_wrapper);
        ws.prepare("job1", PRODUCTION_REPO, "main").await?;
        let mirror = single_mirror(&root)?;
        std::fs::write(mirror.join("marker"), "old")?;
        std::fs::write(
            mirror.join("objects/info/alternates"),
            format!("{}\n", dir.path().display()),
        )?;
        ws.fetch_mirror(PRODUCTION_REPO).await?;
        assert!(!mirror.join("marker").exists(), "mirror was not rebuilt");
        assert!(!mirror.join("objects/info/alternates").exists());
        assert_eq!(
            git(&mirror, &["rev-parse", "refs/remotes/origin/main"])?,
            git(&dir.path().join("seed"), &["rev-parse", "HEAD"])?
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_broker_refresh_and_a_prepare_never_run_git_at_the_same_time() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let origin = fixture(dir.path())?;
        let git_wrapper = logged_git(dir.path(), &origin, "0.2")?;
        let root = dir.path().join("jobs");
        let ws = production(&root, &git_wrapper);
        ws.prepare("job0", PRODUCTION_REPO, "main").await?;
        std::fs::write(&git_wrapper.log, "")?;
        let other = ws.clone();
        let (prepared, fetched) = tokio::join!(
            ws.prepare("job1", PRODUCTION_REPO, "main"),
            other.fetch_mirror(PRODUCTION_REPO)
        );
        prepared?;
        fetched?;
        let log = std::fs::read_to_string(&git_wrapper.log)?;
        let mut open = false;
        let mut steps = 0;
        for line in log.lines() {
            if line.starts_with("start") {
                assert!(!open, "two git calls overlapped:\n{log}");
                open = true;
                steps += 1;
            } else {
                open = false;
            }
        }
        assert!(steps >= 4, "{log}");
        Ok(())
    }))
    .await
}

const GH_URL: &str = "https://github.com/o/r/pull/7";
const TOKEN: &str = "ghp_brokertoken1234";

fn script_dir() -> &'static Path {
    static DIR: OnceLock<TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        for (name, body) in [
            (
                "gh",
                "#!/bin/sh\nhere=$(pwd)\nprintf '%s\\n' \"$@\" > \"$here/gh.args\"\nenv > \"$here/gh.env\"\ncat \"$here/gh.out\"\ncode=0\n[ -f \"$here/gh.code\" ] && code=$(cat \"$here/gh.code\")\nexit \"$code\"\n",
            ),
            (
                "git",
                "#!/bin/sh\nlog=\"$HOME/../fake-git.log\"\n{ echo \"ARGS $*\"; echo \"ALLOW=$GIT_ALLOW_PROTOCOL\"; echo \"ASKPASS=$GIT_ASKPASS\"; echo \"ASKHOST=$FLEETD_ASKPASS_HOST\"; } >> \"$log\"\ncase \"$*\" in *\" fetch \"*) [ -f \"$HOME/../fake-git.fail\" ] && exit 1;; esac\nexit 0\n",
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, body).unwrap_or_else(|_| std::process::abort());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .unwrap_or_else(|_| std::process::abort());
        }
        dir
    })
    .path()
}

struct GhCase {
    _dir: TempDir,
    scratch: PathBuf,
    gh: GhCli,
}

impl GhCase {
    fn new(out: &str, code: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::on_host("github.com", out, code)
    }

    fn on_host(host: &str, out: &str, code: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let scratch = Workspace::new(dir.path().join("jobs")).create_broker_scratch("job1")?;
        std::fs::write(scratch.join("gh.out"), out)?;
        std::fs::write(scratch.join("gh.code"), code)?;
        let gh = GhCli::new(script_dir().join("gh"), host, TOKEN.to_owned(), &scratch)?;
        Ok(Self {
            _dir: dir,
            scratch,
            gh,
        })
    }

    fn target() -> PushTarget {
        PushTarget::Own("job1".to_owned())
    }

    async fn checks(&self, url: &str) -> Result<serde_json::Value, ExecError> {
        let out = self.gh.pr_checks(&Self::target(), url).await?;
        serde_json::from_str(&out).map_err(|_| ExecError)
    }
}

fn item(bucket: &str, name: &str, link: &str) -> String {
    serde_json::json!({"bucket": bucket, "name": name, "link": link, "state": "x", "workflow": "w"})
        .to_string()
}

#[tokio::test]
async fn pr_checks_runs_the_exact_gh_argv_with_the_token_only_on_the_child() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        let parent_token = std::env::var_os("GH_TOKEN");
        case.checks(GH_URL).await.map_err(|_| "pr_checks failed")?;
        assert_eq!(std::env::var_os("GH_TOKEN"), parent_token);
        let args = std::fs::read_to_string(case.scratch.join("gh.args"))?;
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            ["pr", "checks", GH_URL, "--json", "bucket,link,name"]
        );
        assert!(!args.contains(TOKEN));
        let env = std::fs::read_to_string(case.scratch.join("gh.env"))?;
        let names: Vec<&str> = env
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        let allowed = [
            "PATH",
            "HOME",
            "XDG_CONFIG_HOME",
            "GH_CONFIG_DIR",
            "GH_TOKEN",
            "GH_HOST",
            "GH_PROMPT_DISABLED",
            "GH_NO_UPDATE_NOTIFIER",
            "NO_COLOR",
            "PWD",
            "OLDPWD",
            "SHLVL",
            "_",
        ];
        for name in &names {
            assert!(allowed.contains(name), "child inherited {name}");
        }
        assert!(env.contains(&format!("GH_TOKEN={TOKEN}")));
        assert!(env.contains("GH_HOST=github.com"));
        assert!(!names.contains(&"GH_ENTERPRISE_TOKEN"));
        assert!(env.contains(&format!("HOME={}", case.scratch.display())));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn pr_checks_off_github_com_adds_the_enterprise_token() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::on_host("ghe.example", "[]", "0")?;
        case.checks("https://ghe.example/o/r/pull/7")
            .await
            .map_err(|_| "pr_checks failed")?;
        let env = std::fs::read_to_string(case.scratch.join("gh.env"))?;
        assert!(env.contains(&format!("GH_ENTERPRISE_TOKEN={TOKEN}")));
        assert!(env.contains("GH_HOST=ghe.example"));
        Ok(())
    }))
    .await
}

const SHELL_VARS: [&str; 4] = ["PWD", "OLDPWD", "SHLVL", "_"];

fn env_of_child(
    case: &GhCase,
) -> Result<std::collections::BTreeMap<String, String>, std::io::Error> {
    Ok(std::fs::read_to_string(case.scratch.join("gh.env"))?
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| !SHELL_VARS.contains(name))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect())
}

#[tokio::test]
async fn the_gh_child_env_is_exactly_the_fixed_set() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        case.checks(GH_URL).await.map_err(|_| "pr_checks failed")?;
        let env = env_of_child(&case)?;
        let home = case.scratch.display().to_string();
        let expected: std::collections::BTreeMap<String, String> = [
            ("GH_CONFIG_DIR", format!("{home}/gh")),
            ("GH_HOST", "github.com".to_owned()),
            ("GH_NO_UPDATE_NOTIFIER", "1".to_owned()),
            ("GH_PROMPT_DISABLED", "1".to_owned()),
            ("GH_TOKEN", TOKEN.to_owned()),
            ("HOME", home.clone()),
            ("NO_COLOR", "1".to_owned()),
            ("PATH", GH_PATH.to_owned()),
            ("XDG_CONFIG_HOME", format!("{home}/.config")),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        assert_eq!(env, expected);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_gh_child_env_off_github_com_adds_only_the_enterprise_token() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::on_host("ghe.example", "[]", "0")?;
        case.checks("https://ghe.example/o/r/pull/7")
            .await
            .map_err(|_| "pr_checks failed")?;
        let env = env_of_child(&case)?;
        let names: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "GH_CONFIG_DIR",
                "GH_ENTERPRISE_TOKEN",
                "GH_HOST",
                "GH_NO_UPDATE_NOTIFIER",
                "GH_PROMPT_DISABLED",
                "GH_TOKEN",
                "HOME",
                "NO_COLOR",
                "PATH",
                "XDG_CONFIG_HOME",
            ]
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some(GH_PATH));
        Ok(())
    }))
    .await
}

#[test]
fn a_relative_gh_bin_is_refused_at_construction() {
    let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
    for bin in ["gh", "./gh", "bin/gh", "../gh", ""] {
        let built = GhCli::new(bin, "github.com", TOKEN.to_owned(), dir.path());
        assert_eq!(built.err(), Some(BrokerError::RelativeGhBin), "{bin:?}");
    }
    assert!(GhCli::new("/usr/bin/gh", "github.com", TOKEN.to_owned(), dir.path()).is_ok());
}

#[tokio::test]
async fn a_gh_bin_that_is_missing_or_a_directory_fails_the_op_with_the_fixed_error() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        for bin in [
            case.scratch.join("no-such-gh"),
            case.scratch.clone(),
            PathBuf::from("/"),
        ] {
            let gh = GhCli::new(&bin, "github.com", TOKEN.to_owned(), &case.scratch)?;
            let got = gh.pr_checks(&GhCase::target(), GH_URL).await;
            assert!(got.is_err(), "{bin:?}");
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_scratch_that_is_not_private_is_refused_and_gh_never_runs() -> TestResult {
    common::bounded(Box::pin(async {
        for mode in [0o755, 0o770, 0o707, 0o2700, 0o500] {
            let case = GhCase::new("[]", "0")?;
            std::fs::set_permissions(&case.scratch, std::fs::Permissions::from_mode(mode))?;
            assert!(case.checks(GH_URL).await.is_err(), "{mode:o}");
            std::fs::set_permissions(&case.scratch, std::fs::Permissions::from_mode(0o700))?;
            assert!(!case.scratch.join("gh.env").exists(), "{mode:o}");
        }
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_symlink_or_a_missing_dir_at_the_scratch_path_is_refused() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        let target = case.scratch.with_file_name("victim");
        std::fs::create_dir(&target)?;
        std::fs::write(target.join("gh.out"), "[]")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
        std::fs::remove_dir_all(&case.scratch)?;
        std::os::unix::fs::symlink(&target, &case.scratch)?;
        assert!(case.checks(GH_URL).await.is_err());
        assert!(!target.join("gh.env").exists());
        std::fs::remove_file(&case.scratch)?;
        assert!(case.checks(GH_URL).await.is_err());
        assert!(!case.scratch.exists(), "the executor does not create it");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_scratch_is_checked_on_every_run_not_once() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        case.checks(GH_URL).await.map_err(|_| "first run")?;
        std::fs::set_permissions(&case.scratch, std::fs::Permissions::from_mode(0o755))?;
        assert!(case.checks(GH_URL).await.is_err());
        std::fs::set_permissions(&case.scratch, std::fs::Permissions::from_mode(0o700))?;
        case.checks(GH_URL).await.map_err(|_| "third run")?;
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn pr_checks_returns_a_redacted_subset_with_host_validated_links() -> TestResult {
    common::bounded(Box::pin(async {
        let good = "https://github.com/o/r/actions/runs/9/job/41";
        let items = [
            item("pass", "build", good),
            item(
                "weird",
                "ansi\u{1b}[31m\u{202e}name\nsecond",
                "http://github.com/x",
            ),
            item("fail", "other host", "https://evil.example/x"),
            item("pending", "userinfo", "https://github.com@evil.example/x"),
            item("cancel", "spaced", "https://github.com/a b"),
            item("skipping", &"n".repeat(500), ""),
        ];
        let case = GhCase::new(&format!("[{}]", items.join(",")), "0")?;
        let value = case.checks(GH_URL).await.map_err(|_| "pr_checks failed")?;
        let checks = value["checks"].as_array().ok_or("checks")?;
        assert_eq!(checks.len(), 6);
        assert_eq!(checks[0]["bucket"], "pass");
        assert_eq!(checks[0]["link"], good);
        assert_eq!(checks[1]["bucket"], "unknown");
        assert_eq!(checks[1]["name"], "ansi[31mnamesecond");
        for hostile in &checks[1..5] {
            assert!(hostile.get("link").is_none(), "{hostile}");
        }
        assert_eq!(
            checks[5]["name"].as_str().map(|n| n.chars().count()),
            Some(120)
        );
        for check in checks {
            let mut keys: Vec<_> = check.as_object().ok_or("object")?.keys().cloned().collect();
            keys.sort();
            assert!(
                keys == ["bucket", "link", "name"] || keys == ["bucket", "name"],
                "{keys:?}"
            );
        }
        assert_eq!(value["truncated"], false);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn pr_checks_caps_the_count_and_the_bytes() -> TestResult {
    common::bounded(Box::pin(async {
        let many: Vec<String> = (0..MAX_CHECKS * 2)
            .map(|i| item("pass", &format!("c{i}"), ""))
            .collect();
        let case = GhCase::new(&format!("[{}]", many.join(",")), "0")?;
        let value = case.checks(GH_URL).await.map_err(|_| "pr_checks failed")?;
        assert_eq!(value["checks"].as_array().map(Vec::len), Some(MAX_CHECKS));
        assert_eq!(value["truncated"], true);

        let link = format!("https://github.com/{}", "a".repeat(1900));
        let heavy: Vec<String> = (0..MAX_CHECKS)
            .map(|_| item("pass", &"n".repeat(120), &link))
            .collect();
        let case = GhCase::new(&format!("[{}]", heavy.join(",")), "0")?;
        let out = case
            .gh
            .pr_checks(&GhCase::target(), GH_URL)
            .await
            .map_err(|_| "pr_checks failed")?;
        assert!(out.len() <= MAX_OUTPUT_BYTES, "{}", out.len());
        let value: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(value["truncated"], true);
        assert!(
            value["checks"]
                .as_array()
                .is_some_and(|c| !c.is_empty() && c.len() < MAX_CHECKS)
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn pr_checks_fails_closed_on_bad_gh_output() -> TestResult {
    common::bounded(Box::pin(async {
        for out in ["", "not json", "{\"bucket\":\"pass\"}", "[1,2]", "null"] {
            let case = GhCase::new(out, "0")?;
            assert!(case.checks(GH_URL).await.is_err(), "{out}");
        }
        let huge = format!("[{}]", "0,".repeat(200 * 1024));
        let case = GhCase::new(&huge, "0")?;
        assert!(case.checks(GH_URL).await.is_err());
        let pending = GhCase::new(&format!("[{}]", item("pending", "a", "")), "8")?;
        assert!(pending.checks(GH_URL).await.is_ok());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn pr_checks_refuses_a_url_that_is_not_a_pull_request_of_the_host_without_running_gh()
-> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        for url in [
            "https://evil.example/o/r/pull/7",
            "https://github.com.evil.example/o/r/pull/7",
            "https://github.com@evil.example/o/r/pull/7",
            "http://github.com/o/r/pull/7",
            "https://github.com/o/r/pull/7?x=1",
            "https://github.com/o/r/pull/7#frag",
            "https://github.com/o/r/pull/7/files",
            "https://github.com/o/r/pull/x",
            "https://github.com/o/r/issues/7",
            "https://github.com/o/pull/7",
            "https://github.com/../r/pull/7",
            "https://github.com/o/r/pull/7 --repo x",
            "--json=x",
            "",
        ] {
            assert!(case.checks(url).await.is_err(), "{url}");
        }
        assert!(!case.scratch.join("gh.args").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_real_executors_refuse_push_and_pr_create() -> TestResult {
    common::bounded(Box::pin(async {
        let case = GhCase::new("[]", "0")?;
        assert!(
            case.gh
                .pr_create(&GhCase::target(), "t", "b")
                .await
                .is_err()
        );
        let git = MirrorGit::new(Workspace::new(case.scratch.join("jobs")), &Job::default());
        assert!(git.push(&GhCase::target()).await.is_err());
        Ok(())
    }))
    .await
}

fn job_for(repo: &str) -> Job {
    Job {
        job_id: "job1".to_owned(),
        repo: repo.to_owned(),
        base_ref: "main".to_owned(),
        ..Job::default()
    }
}

fn fake_git_workspace(root: &Path) -> Workspace {
    Workspace::new(root)
        .with_policy(RepoPolicy::new(["github.com"]))
        .with_git(script_dir().join("git"), Duration::from_secs(60))
        .with_credential("askpass-bin", TOKEN.to_owned())
}

#[tokio::test]
async fn a_fake_git_mirror_fetch_runs_pinned_with_https_and_askpass_for_the_job_repo() -> TestResult
{
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let root = dir.path().join("jobs");
        let git = MirrorGit::new(fake_git_workspace(&root), &job_for(PRODUCTION_REPO));
        assert_eq!(git.fetch().await.map_err(|_| "fetch failed")?, "fetched");
        let log = std::fs::read_to_string(root.join("fake-git.log"))?;
        let fetch = log
            .lines()
            .position(|l| l.starts_with("ARGS") && l.contains(" fetch "))
            .ok_or("no fetch")?;
        let lines: Vec<&str> = log.lines().collect();
        let args = lines[fetch];
        assert!(args.contains("core.hooksPath=/dev/null"), "{args}");
        assert!(args.contains("core.fsmonitor="), "{args}");
        assert!(args.contains(&format!("-- {PRODUCTION_REPO} ")), "{args}");
        assert_eq!(lines[fetch + 1], "ALLOW=https");
        assert_eq!(lines[fetch + 2], "ASKPASS=askpass-bin");
        assert_eq!(lines[fetch + 3], "ASKHOST=github.com");
        for init in lines
            .iter()
            .filter(|l| l.contains(" init ") || l.contains(" config "))
        {
            let at = lines.iter().position(|l| l == init).ok_or("pos")?;
            assert_eq!(lines[at + 2], "ASKPASS=", "{init}");
        }
        assert!(!log.contains(TOKEN));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_failing_fake_git_fetch_replies_with_the_fixed_failure() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let root = dir.path().join("jobs");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("fake-git.fail"), "")?;
        let git = MirrorGit::new(fake_git_workspace(&root), &job_for(PRODUCTION_REPO));
        assert!(git.fetch().await.is_err());
        let broker = Broker::new(
            AgentLauncher::Systemd,
            &job_for(PRODUCTION_REPO),
            git,
            GhCase::new("[]", "0")?.gh,
            Redactor::new([TOKEN]),
        )?;
        let reply = broker.handle(Request::Fetch {}).await;
        assert!(matches!(
            reply,
            Response::Denied {
                error: Denial::Failed,
                ..
            }
        ));
        Ok(())
    }))
    .await
}

#[derive(Clone)]
struct Recording {
    gh: GhCli,
}

impl GhExecutor for Recording {
    fn pr_create(
        &self,
        _: &PushTarget,
        _: &str,
        _: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        std::future::ready(Ok(GH_URL.to_owned()))
    }

    async fn pr_checks(&self, target: &PushTarget, pr_url: &str) -> Result<String, ExecError> {
        self.gh.pr_checks(target, pr_url).await
    }
}

#[tokio::test]
async fn the_broker_serves_checks_of_the_recorded_url_and_redacts_the_reply() -> TestResult {
    common::bounded(Box::pin(async {
        let out = format!("[{}]", item("pass", &format!("leak {TOKEN}"), ""));
        let case = GhCase::new(&out, "0")?;
        let dir = TempDir::new()?;
        let broker = Broker::new(
            AgentLauncher::Systemd,
            &job_for(PRODUCTION_REPO),
            MirrorGit::new(
                fake_git_workspace(&dir.path().join("jobs")),
                &job_for(PRODUCTION_REPO),
            ),
            Recording {
                gh: case.gh.clone(),
            },
            Redactor::new([TOKEN]),
        )?
        .with_limits(Limits::default());
        assert!(matches!(
            broker
                .handle_frame(br#"{"op":"pr_checks","url":"https://github.com/x/y/pull/1"}"#)
                .await,
            Response::Denied {
                error: Denial::InvalidRequest,
                ..
            }
        ));
        assert!(matches!(
            broker.handle(Request::PrChecks {}).await,
            Response::Denied {
                error: Denial::NoPullRequest,
                ..
            }
        ));
        broker
            .handle(Request::PrCreate {
                title: "t".to_owned(),
                body: "b".to_owned(),
            })
            .await;
        let Response::Done { output } = broker.handle(Request::PrChecks {}).await else {
            return Err("not done".into());
        };
        assert!(!output.contains(TOKEN), "{output}");
        assert!(output.contains("[REDACTED]"), "{output}");
        let args = std::fs::read_to_string(case.scratch.join("gh.args"))?;
        assert!(args.contains(GH_URL));
        assert!(matches!(
            broker.handle(Request::PrChecks {}).await,
            Response::Denied {
                error: Denial::RateLimited,
                ..
            }
        ));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_broker_fetch_refreshes_the_job_repo_mirror_and_ignores_a_repo_in_the_request()
-> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let origin = fixture(dir.path())?;
        let git_wrapper = logged_git(dir.path(), &origin, "0")?;
        let root = relative_to_cwd(dir.path())?.join("jobs");
        let ws = production(&root, &git_wrapper);
        ws.prepare("job1", PRODUCTION_REPO, "main").await?;
        let seed = dir.path().join("seed");
        std::fs::write(seed.join("c.txt"), "three")?;
        git(&seed, &["add", "."])?;
        git(&seed, &["commit", "--quiet", "-m", "three"])?;
        git(&seed, &["push", "--quiet", &origin, "main"])?;
        let broker = Broker::new(
            AgentLauncher::Systemd,
            &job_for(PRODUCTION_REPO),
            MirrorGit::new(ws.clone(), &job_for(PRODUCTION_REPO)),
            GhCase::new("[]", "0")?.gh,
            Redactor::default(),
        )?;
        assert!(matches!(
            broker
                .handle_frame(br#"{"op":"fetch","repo":"https://github.com/evil/x.git"}"#)
                .await,
            Response::Denied {
                error: Denial::InvalidRequest,
                ..
            }
        ));
        assert!(!std::fs::read_to_string(&git_wrapper.log)?.contains("evil"));
        assert!(matches!(
            broker.handle(Request::Fetch {}).await,
            Response::Done { .. }
        ));
        let mirror = single_mirror(&root)?;
        assert_eq!(
            git(&mirror, &["rev-parse", "refs/remotes/origin/main"])?,
            git(&seed, &["rev-parse", "HEAD"])?
        );
        assert!(matches!(
            broker.handle(Request::Fetch {}).await,
            Response::Denied {
                error: Denial::RateLimited,
                ..
            }
        ));
        Ok(())
    }))
    .await
}
