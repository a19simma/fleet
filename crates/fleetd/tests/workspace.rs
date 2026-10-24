//! Runs real git against a local bare repo. Own test binary because it spawns children.

use std::path::Path;
use std::process::Command;

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
