//! Runs real git against a local bare repo. Own test binary because it spawns children.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use fleetd::workspace::{Workspace, WorkspaceError};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    let dir = TempDir::new()?;
    let repo = fixture(dir.path())?;
    let ws = Workspace::new(dir.path().join("jobs"));

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
}

#[tokio::test]
async fn remove_deletes_the_worktree_and_scratch_and_keeps_the_mirror() -> TestResult {
    let dir = TempDir::new()?;
    let repo = fixture(dir.path())?;
    let root = dir.path().join("jobs");
    let ws = Workspace::new(&root);
    let checkout = ws.prepare("job1", &repo, "main").await?;
    std::fs::create_dir(root.join(".finish-job1"))?;
    ws.remove("job1", &repo).await?;
    assert!(!checkout.path.exists());
    assert!(!root.join(".finish-job1").exists());
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
}

#[tokio::test]
async fn rejects_unsafe_inputs_before_running_git() -> TestResult {
    let dir = TempDir::new()?;
    let root = dir.path().join("jobs");
    let ws = Workspace::new(&root);
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
    for id in ["", "-x", "a/b", "a b", "../x"] {
        let err = ws.prepare(id, "/repo.git", "main").await;
        assert!(matches!(err, Err(WorkspaceError::InvalidJobId)), "{id}");
    }
    assert!(!root.exists());
    Ok(())
}

#[tokio::test]
async fn errors_carry_no_input() -> TestResult {
    let dir = TempDir::new()?;
    let ws = Workspace::new(dir.path().join("jobs"));
    let secret = dir.path().join("missing-secret-name.git");
    let err = ws
        .prepare("job1", secret.to_str().ok_or("path")?, "main")
        .await
        .err()
        .ok_or("expected error")?;
    let text = format!("{err} {err:?}");
    assert!(!text.contains("missing-secret-name"));
    Ok(())
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
    let dir = TempDir::new()?;
    let ws =
        Workspace::new(dir.path().join("jobs")).with_git(hanging_git(), Duration::from_millis(200));
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        ws.prepare("job1", "https://example.invalid/r.git", "main"),
    )
    .await?;
    assert!(matches!(result, Err(WorkspaceError::GitTimeout("init"))));
    Ok(())
}

fn forking_git() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("git");
        let script = "#!/bin/sh\ncase \"$3\" in\ninit)\nfor last; do :; done\nbase=$(dirname \"$last\")\nsleep 300 > \"$base/hold\" &\nread x < \"$base/ready\" ;;\nesac\nexit 0\n";
        std::fs::write(&path, script).unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        (dir, path)
    });
    path
}

#[tokio::test]
async fn a_background_descendant_of_a_clean_git_exit_is_killed() -> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let hold = cache.join("hold");
    let ready = cache.join("ready");
    let (tx, opened) = tokio::sync::oneshot::channel();
    let eof = tokio::spawn(async move {
        let mut file = tokio::fs::File::open(hold).await?;
        let _ = tx.send(());
        let mut sink = Vec::new();
        file.read_to_end(&mut sink).await
    });
    let ws =
        Workspace::new(dir.path().join("jobs")).with_git(forking_git(), Duration::from_secs(60));
    let repo = "https://example.invalid/r.git";
    let (result, driven) = tokio::join!(ws.prepare("job1", repo, "main"), async {
        tokio::time::timeout(Duration::from_secs(20), opened).await??;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(ready)
            .await?;
        file.write_all(b"go\n").await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    driven?;
    result?;
    tokio::time::timeout(Duration::from_secs(20), eof).await???;
    Ok(())
}
