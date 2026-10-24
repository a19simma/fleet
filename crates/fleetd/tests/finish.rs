//! Push and pull request step against a local bare origin and a fake `gh`. Own test binary
//! because it spawns children.

use std::ffi::OsString;
use std::future::{Future, ready};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use fleet_core::Redactor;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest};
use fleetd::poller::Shutdown;
use fleetd::runner::{AgentRunner, FinishOutcome, Reporter, RunConfig};
use fleetd::workspace::Workspace;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tonic::Status;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GH: &str = r#"#!/bin/sh
root="$GIT_DIR/../.."
env > "$root/gh.env"
printf '%s\n' "$@" > "$root/gh.args"
if [ -f "$HOME/.config/gh/config.yml" ] || [ -f "$GH_CONFIG_DIR/config.yml" ]; then env > "$root/gh.sawconfig"; fi
case "$(cat "$root/mode")" in
ok) echo "created"; echo "https://example.invalid/pr/7"; exit 0 ;;
fail) echo "boom hunter2-hunter2 detail" >&2; exit 1 ;;
esac
"#;

const GIT: &str = r#"#!/bin/sh
sub=
for a in "$@"; do
  case "$a" in
  -c | core.* | credential.*) ;;
  *) sub=$a; break ;;
  esac
done
root="$GIT_DIR/.."
env > "$root/git-$sub.env"
if [ "$sub" = rev-list ] && [ -e "$root/emptycount" ]; then exit 0; fi
exec git "$@"
"#;

struct Fake(mpsc::UnboundedSender<ReportJobRequest>);

impl Reporter for Fake {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let _ = self.0.send(request);
        ready(Ok(ReportJobReply::default()))
    }
}

fn gh() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("gh");
        std::fs::write(&path, GH).unwrap_or_else(|_| std::process::abort());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| std::process::abort());
        (dir, path)
    });
    path
}

fn git_wrapper() -> &'static Path {
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

fn git(dir: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()?;
    assert!(out.status.success());
    Ok(String::from_utf8(out.stdout)?)
}

struct Rig {
    dir: TempDir,
    origin: PathBuf,
    worktree: PathBuf,
}

async fn rig(mode: &str) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let origin = dir.path().join("origin.git");
    let seed = dir.path().join("seed");
    std::fs::create_dir(&origin)?;
    std::fs::create_dir(&seed)?;
    git(&origin, &["init", "--bare", "--quiet", "-b", "main"])?;
    git(&seed, &["init", "--quiet", "-b", "main"])?;
    std::fs::write(seed.join("a.txt"), "a")?;
    git(&seed, &["add", "."])?;
    git(&seed, &["commit", "--quiet", "-m", "seed"])?;
    git(
        &seed,
        &["push", "--quiet", &origin.to_string_lossy(), "main"],
    )?;
    std::fs::write(dir.path().join("mode"), mode)?;
    let root = dir.path().join("work");
    let checkout = Workspace::new(&root)
        .prepare("job1", &origin.to_string_lossy(), "main")
        .await?;
    Ok(Rig {
        dir,
        origin,
        worktree: checkout.path,
    })
}

fn agent(rig: &Rig) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut config = RunConfig::new("claude", false);
    gh().clone_into(&mut config.gh_bin);
    git_wrapper().clone_into(&mut config.git_bin);
    let mut env: Vec<(OsString, OsString)> = vec![
        ("HOME".into(), rig.dir.path().into()),
        ("GH_TOKEN".into(), "not-a-real-gh-value".into()),
        ("GITHUB_TOKEN".into(), "not-a-real-github-value".into()),
        ("GH_ENTERPRISE_TOKEN".into(), "not-a-real-ent-value".into()),
        ("XDG_CONFIG_HOME".into(), rig.dir.path().join("xdg").into()),
        ("GH_CONFIG_DIR".into(), rig.dir.path().join("ghreal").into()),
        ("SSH_AUTH_SOCK".into(), "/not/a/sock".into()),
        ("GIT_SSH".into(), "/not/ssh".into()),
        ("GIT_SSH_COMMAND".into(), "/not/ssh".into()),
        ("GIT_PROXY_COMMAND".into(), "/not/proxy".into()),
        ("GIT_EXEC_PATH".into(), "/not/exec".into()),
        ("GIT_TEMPLATE_DIR".into(), "/not/tpl".into()),
        ("GIT_CONFIG_COUNT".into(), "1".into()),
        ("LD_PRELOAD".into(), "/not/lib.so".into()),
        ("DYLD_INSERT_LIBRARIES".into(), "/not/lib.dylib".into()),
        ("GIT_ASKPASS".into(), "/not/a/real/askpass".into()),
        ("FLEET_TOKEN".into(), "not-a-real-fleet-value".into()),
        ("KEPT_VALUE".into(), "kept".into()),
    ];
    env.extend(std::env::var_os("PATH").map(|path| ("PATH".into(), path)));
    config.base_env = env;
    (
        AgentRunner::new(config, Fake(tx), Redactor::new(["hunter2-hunter2"])),
        rx,
    )
}

fn job(rig: &Rig, open_pr: bool) -> Job {
    Job {
        repo: rig.origin.to_string_lossy().into_owned(),
        job_id: "job1".into(),
        attempt: 1,
        r#box: "boxa".into(),
        base_ref: "main".into(),
        open_pr,
        ..Job::default()
    }
}

fn commit(rig: &Rig) -> TestResult {
    std::fs::write(rig.worktree.join("b.txt"), "b")?;
    git(&rig.worktree, &["add", "."])?;
    git(&rig.worktree, &["commit", "--quiet", "-m", "work"])?;
    Ok(())
}

fn drain(rx: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> Vec<ReportJobRequest> {
    let mut all = Vec::new();
    while let Ok(request) = rx.try_recv() {
        all.push(request);
    }
    all
}

fn pushed(rig: &Rig) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(!git(&rig.origin, &["branch", "--list", "swarm/job1"])?
        .trim()
        .is_empty())
}

#[tokio::test]
async fn finish_pushes_and_opens_pr() -> TestResult {
    let rig = rig("ok").await?;
    commit(&rig)?;
    let (agent, mut rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    assert_eq!(
        outcome,
        FinishOutcome::Succeeded {
            branch: Some("swarm/job1".into()),
            pr_url: Some("https://example.invalid/pr/7".into()),
        }
    );
    assert!(pushed(&rig)?);
    let reports = drain(&mut rx);
    let last = reports.last().ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Succeeded.into()));
    assert_eq!(last.branch.as_deref(), Some("swarm/job1"));
    assert_eq!(last.pr_url.as_deref(), Some("https://example.invalid/pr/7"));
    let args = std::fs::read_to_string(rig.dir.path().join("gh.args"))?;
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        [
            "pr",
            "create",
            "--repo",
            &rig.origin.to_string_lossy(),
            "--head",
            "swarm/job1",
            "--base",
            "main",
            "--title",
            "work",
            "--body",
            "Fleet job job1",
        ]
    );
    let env = std::fs::read_to_string(rig.dir.path().join("gh.env"))?;
    assert!(env.contains("GH_TOKEN=not-a-real-gh-value"));
    assert!(!env.contains("FLEET_TOKEN"));
    assert!(!env.contains("KEPT_VALUE"));
    assert!(!env.contains("GIT_ASKPASS"));
    Ok(())
}

fn recorded(rig: &Rig, sub: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(
        rig.dir.path().join("work").join(format!("git-{sub}.env")),
    )?)
}

#[tokio::test]
async fn only_the_push_gets_the_askpass_and_no_helper_runs_with_tokens_in_the_agent_repo()
-> TestResult {
    let rig = rig("ok").await?;
    commit(&rig)?;
    let (agent, _rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    let push = recorded(&rig, "push")?;
    assert!(push.contains("GIT_ASKPASS=/not/a/real/askpass"));
    assert!(!push.contains("GH_TOKEN"));
    assert!(!push.contains("GITHUB_TOKEN"));
    assert!(!push.contains("GH_ENTERPRISE_TOKEN"));
    assert!(push.contains("GIT_CONFIG_GLOBAL=/dev/null"));
    assert!(push.contains("GIT_CONFIG_NOSYSTEM=1"));
    for sub in ["init", "fetch", "rev-list", "log"] {
        let env = recorded(&rig, sub)?;
        assert!(!env.contains("GH_TOKEN"), "{sub}");
        assert!(!env.contains("GIT_ASKPASS"), "{sub}");
        assert!(!env.contains("FLEET_TOKEN"), "{sub}");
        assert!(env.contains("GIT_CONFIG_GLOBAL=/dev/null"), "{sub}");
    }
    Ok(())
}

#[tokio::test]
async fn planted_agent_config_neither_runs_nor_redirects_the_push() -> TestResult {
    let rig = rig("ok").await?;
    commit(&rig)?;
    let marker = rig.dir.path().join("marker");
    let hook = format!("sh -c 'echo run >> {}'", marker.display());
    let origin = rig.origin.to_string_lossy().into_owned();
    let hooks = rig.dir.path().join("hooks");
    std::fs::create_dir(&hooks)?;
    let pre_push = hooks.join("pre-push");
    std::fs::write(
        &pre_push,
        format!("#!/bin/sh\necho run >> {}\n", marker.display()),
    )?;
    std::fs::set_permissions(&pre_push, std::fs::Permissions::from_mode(0o755))?;
    let redirected = rig.dir.path().join("redirected/");
    let plant = |dir: &Path| -> TestResult {
        git(dir, &["config", "core.sshCommand", &hook])?;
        git(dir, &["config", "credential.helper", &format!("!{hook}")])?;
        git(dir, &["config", "core.fsmonitor", &hook])?;
        git(dir, &["config", "core.hooksPath", &hooks.to_string_lossy()])?;
        git(dir, &["config", "remote.origin.pushurl", &hook])?;
        git(
            dir,
            &[
                "config",
                &format!("url.{}.insteadOf", redirected.display()),
                &origin,
            ],
        )?;
        Ok(())
    };
    plant(&rig.worktree)?;
    std::fs::write(
        rig.dir.path().join(".gitconfig"),
        format!(
            "[url \"{}\"]\n\tinsteadOf = {origin}\n[core]\n\tsshCommand = {hook}\n\thooksPath = {}\n",
            redirected.display(),
            hooks.display()
        ),
    )?;
    let (agent, _rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, false), &rig.worktree, shutdown)
        .await?;
    assert_eq!(
        outcome,
        FinishOutcome::Succeeded {
            branch: Some("swarm/job1".into()),
            pr_url: None,
        }
    );
    assert!(pushed(&rig)?);
    assert!(!marker.exists());
    assert!(!redirected.exists());
    Ok(())
}

#[tokio::test]
async fn an_empty_commit_count_fails_instead_of_meaning_zero() -> TestResult {
    let rig = rig("ok").await?;
    commit(&rig)?;
    std::fs::write(rig.dir.path().join("work").join("emptycount"), "")?;
    let (agent, mut rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    assert_eq!(
        outcome,
        FinishOutcome::Failed {
            error: "job commits could not be inspected"
        }
    );
    assert!(!pushed(&rig)?);
    let reports = drain(&mut rx);
    let last = reports.last().ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
    Ok(())
}

#[tokio::test]
async fn no_changes_succeeds() -> TestResult {
    let rig = rig("fail").await?;
    let (agent, mut rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    assert_eq!(
        outcome,
        FinishOutcome::Succeeded {
            branch: None,
            pr_url: None,
        }
    );
    assert!(!pushed(&rig)?);
    assert!(!rig.dir.path().join("gh.args").exists());
    let reports = drain(&mut rx);
    let last = reports.last().ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Succeeded.into()));
    assert_eq!(last.branch, None);
    assert_eq!(last.pr_url, None);
    Ok(())
}

#[tokio::test]
async fn a_job_without_a_pr_only_pushes() -> TestResult {
    let rig = rig("fail").await?;
    commit(&rig)?;
    let (agent, mut rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, false), &rig.worktree, shutdown)
        .await?;
    assert_eq!(
        outcome,
        FinishOutcome::Succeeded {
            branch: Some("swarm/job1".into()),
            pr_url: None,
        }
    );
    assert!(pushed(&rig)?);
    assert!(!rig.dir.path().join("gh.args").exists());
    let reports = drain(&mut rx);
    let last = reports.last().ok_or("no report")?;
    assert_eq!(last.pr_url, None);
    Ok(())
}

#[tokio::test]
async fn a_gh_failure_reports_a_fixed_error() -> TestResult {
    let rig = rig("fail").await?;
    commit(&rig)?;
    let (agent, mut rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    assert_eq!(
        outcome,
        FinishOutcome::Failed {
            error: "pull request could not be opened"
        }
    );
    let reports = drain(&mut rx);
    let last = reports.last().ok_or("no report")?;
    assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
    assert_eq!(
        last.error.as_deref(),
        Some("pull request could not be opened")
    );
    assert_eq!(last.pr_url, None);
    let text: String = reports
        .iter()
        .flat_map(|r| r.chunks.iter().map(|c| c.text.as_str()))
        .collect();
    assert!(text.contains("boom [REDACTED] detail"));
    assert!(!text.contains("hunter2"));
    Ok(())
}

fn keys(env: &str) -> std::collections::BTreeSet<String> {
    env.lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_owned()))
        .filter(|k| !matches!(k.as_str(), "PWD" | "SHLVL" | "_" | "OLDPWD"))
        .collect()
}

fn set(names: &[&str]) -> std::collections::BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[tokio::test]
async fn credentialed_children_get_only_their_credential_and_scratch_dirs() -> TestResult {
    let rig = rig("ok").await?;
    commit(&rig)?;
    let (agent, _rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    let common = [
        "PATH",
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "GIT_DIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "GH_PROMPT_DISABLED",
        "GIT_ALLOW_PROTOCOL",
    ];
    let mut push = set(&common);
    push.insert("GIT_ASKPASS".into());
    assert_eq!(keys(&recorded(&rig, "push")?), push);
    for sub in ["init", "fetch", "rev-list", "log"] {
        assert_eq!(keys(&recorded(&rig, sub)?), set(&common), "{sub}");
    }
    let mut gh = set(&common);
    gh.remove("GIT_ALLOW_PROTOCOL");
    gh.extend(
        [
            "GH_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GH_CONFIG_DIR",
            "GH_NO_UPDATE_NOTIFIER",
            "GH_BROWSER",
            "GH_EDITOR",
            "GH_PAGER",
            "PAGER",
        ]
        .map(String::from),
    );
    let env = std::fs::read_to_string(rig.dir.path().join("gh.env"))?;
    let mut seen = keys(&env);
    seen.remove("GIT_ALLOW_PROTOCOL");
    assert_eq!(seen, gh);
    let real = rig.dir.path().to_string_lossy().into_owned();
    for line in env
        .lines()
        .filter(|l| l.starts_with("HOME=") || l.starts_with("GH_CONFIG_DIR="))
    {
        assert!(line.contains(".finish-job1"), "{line}");
    }
    assert!(!env.contains(&format!("HOME={real}\n")));
    Ok(())
}

#[tokio::test]
async fn planted_real_home_config_is_never_read_by_gh_or_push() -> TestResult {
    let rig = rig("ok").await?;
    commit(&rig)?;
    let marker = rig.dir.path().join("marker");
    let hook = format!("sh -c 'echo run >> {}'", marker.display());
    let ssh = rig.dir.path().join(".ssh");
    std::fs::create_dir(&ssh)?;
    std::fs::write(
        ssh.join("config"),
        format!("Host *\n\tProxyCommand {hook}\n\tLocalCommand {hook}\n"),
    )?;
    for dir in [
        rig.dir.path().join(".config/gh"),
        rig.dir.path().join("xdg/gh"),
        rig.dir.path().join("ghreal"),
    ] {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("config.yml"),
            format!("http_unix_socket: /nonexistent\nbrowser: {hook}\neditor: {hook}\n"),
        )?;
    }
    let (agent, _rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    assert!(matches!(outcome, FinishOutcome::Succeeded { .. }));
    assert!(!marker.exists());
    assert!(!rig.dir.path().join("gh.sawconfig").exists());
    Ok(())
}

#[tokio::test]
async fn a_title_over_the_limit_is_cut_at_a_char_boundary() -> TestResult {
    let rig = rig("ok").await?;
    std::fs::write(rig.worktree.join("b.txt"), "b")?;
    git(&rig.worktree, &["add", "."])?;
    let subject = "é".repeat(300);
    git(&rig.worktree, &["commit", "--quiet", "-m", &subject])?;
    let (agent, _rx) = agent(&rig);
    let (_trigger, shutdown) = Shutdown::channel();
    agent
        .finish(&job(&rig, true), &rig.worktree, shutdown)
        .await?;
    let args = std::fs::read_to_string(rig.dir.path().join("gh.args"))?;
    let title = args.lines().nth(9).ok_or("no title")?;
    assert_eq!(title, "é".repeat(256));
    Ok(())
}
