//! Runs real git against a local bare repo. Own test binary because it spawns children.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

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

fn only_mirror(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(std::fs::read_dir(root.join(".cache"))?
        .next()
        .ok_or("no mirror")??
        .path())
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

#[tokio::test]
async fn a_planted_url_rewrite_in_the_mirror_does_not_redirect_the_fetch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let decoy_dir = dir.path().join("decoy");
        std::fs::create_dir(&decoy_dir)?;
        let decoy = fixture(&decoy_dir)?;
        let decoy_seed = decoy_dir.join("seed");
        std::fs::write(decoy_seed.join("evil.txt"), "evil")?;
        git(&decoy_seed, &["add", "."])?;
        git(&decoy_seed, &["commit", "--quiet", "-m", "evil"])?;
        git(&decoy_seed, &["push", "--quiet", &decoy, "main"])?;

        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        git(
            &mirror,
            &["config", &format!("url.{decoy}.insteadOf"), &repo],
        )?;
        let second = ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(second.path.join("a.txt"))?, "one");
        assert!(!second.path.join("evil.txt").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn planted_http_credential_and_include_config_is_removed_before_the_fetch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        for (key, value) in [
            ("http.proxy", "http://127.0.0.1:9"),
            ("http.sslVerify", "false"),
            ("http.curloptResolve", "github.com:443:127.0.0.1"),
            ("http.https://github.com/.proxy", "http://127.0.0.1:9"),
            ("credential.helper", "!cat >/dev/null"),
            ("core.sshCommand", "false"),
            ("include.path", "/nowhere"),
            ("remote.origin.url", "/nowhere.git"),
        ] {
            git(&mirror, &["config", key, value])?;
        }
        ws.prepare("job2", &repo, "main").await?;
        let config = std::fs::read_to_string(mirror.join("config"))?;
        for gone in [
            "http",
            "credential",
            "sshCommand",
            "include",
            "remote",
            "url",
        ] {
            assert!(!config.contains(gone), "{gone} {config}");
        }
        assert!(config.contains("bare = true"), "{config}");
        let staged = std::fs::read_dir(&mirror)?
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("config.fleetd-new")
            })
            .count();
        assert_eq!(staged, 0);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_symlinked_mirror_config_is_replaced_not_followed() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep")?;
        std::fs::remove_file(mirror.join("config"))?;
        std::os::unix::fs::symlink(&victim, mirror.join("config"))?;
        ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(&victim)?, "keep");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_commondir_in_the_mirror_does_not_redirect_the_fetch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let decoy_dir = dir.path().join("decoy");
        std::fs::create_dir(&decoy_dir)?;
        let decoy = fixture(&decoy_dir)?;
        let decoy_seed = decoy_dir.join("seed");
        std::fs::write(decoy_seed.join("evil.txt"), "evil")?;
        git(&decoy_seed, &["add", "."])?;
        git(&decoy_seed, &["commit", "--quiet", "-m", "evil"])?;
        git(&decoy_seed, &["push", "--quiet", &decoy, "main"])?;
        let evil = dir.path().join("evil.git");
        git(
            dir.path(),
            &["clone", "--quiet", "--bare", &decoy, "evil.git"],
        )?;
        git(&evil, &["config", &format!("url.{decoy}.insteadOf"), &repo])?;

        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        std::fs::write(
            mirror.join("commondir"),
            evil.to_str().ok_or("path")?.as_bytes(),
        )?;
        let second = ws.prepare("job2", &repo, "main").await?;
        assert_eq!(std::fs::read_to_string(second.path.join("a.txt"))?, "one");
        assert!(!second.path.join("evil.txt").exists());
        assert!(!mirror.join("commondir").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_pin_holds_against_a_commondir_planted_after_the_cleanup() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let decoy_dir = dir.path().join("decoy");
        std::fs::create_dir(&decoy_dir)?;
        let decoy = fixture(&decoy_dir)?;
        let decoy_seed = decoy_dir.join("seed");
        std::fs::write(decoy_seed.join("evil.txt"), "evil")?;
        git(&decoy_seed, &["add", "."])?;
        git(&decoy_seed, &["commit", "--quiet", "-m", "evil"])?;
        git(&decoy_seed, &["push", "--quiet", &decoy, "main"])?;
        let evil = dir.path().join("evil.git");
        git(
            dir.path(),
            &["clone", "--quiet", "--bare", &decoy, "evil.git"],
        )?;
        git(&evil, &["config", &format!("url.{decoy}.insteadOf"), &repo])?;

        let root = dir.path().join("jobs");
        workspace(&root).prepare("job1", &repo, "main").await?;
        let evil_path = evil.to_str().ok_or("path")?.to_owned();
        let planting = workspace(&root).with_before_fetch(move |mirror| {
            let _ = std::fs::write(mirror.join("commondir"), evil_path.as_bytes());
        });
        let outcome = planting.prepare("job2", &repo, "main").await;
        assert!(matches!(outcome, Err(WorkspaceError::Git("fetch"))));
        assert!(
            git(
                &evil,
                &["rev-parse", "--verify", "refs/remotes/origin/main"]
            )
            .is_err()
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_planted_config_worktree_in_the_mirror_is_removed_before_the_fetch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        std::fs::write(mirror.join("config.worktree"), "[core]\n\tbare = false\n")?;
        ws.prepare("job2", &repo, "main").await?;
        assert!(!mirror.join("config.worktree").exists());
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
async fn stale_lock_files_in_the_mirror_are_cleared_before_the_fetch() -> TestResult {
    common::bounded(Box::pin(async {
        let dir = TempDir::new()?;
        let repo = fixture(dir.path())?;
        let root = dir.path().join("jobs");
        let ws = workspace(&root);
        ws.prepare("job1", &repo, "main").await?;
        let mirror = only_mirror(&root)?;
        let locks = [
            mirror.join("shallow.lock"),
            mirror.join("refs/remotes/origin/main.lock"),
            mirror.join("worktrees/job1/index.lock"),
        ];
        for lock in &locks {
            std::fs::write(lock, "")?;
        }
        std::fs::write(mirror.join("keep.txt"), "keep")?;
        ws.prepare("job2", &repo, "main").await?;
        for lock in &locks {
            assert!(!lock.exists(), "{lock:?}");
        }
        assert!(mirror.join("keep.txt").exists());
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
        let text = format!("{err} {err:?}");
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
