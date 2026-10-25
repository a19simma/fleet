//! Push and pull request step against a local bare origin and a fake `gh`. Own test binary
//! because it spawns children.

use std::ffi::OsString;
use std::future::{Future, ready};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest};
use fleetd::poller::Shutdown;
use fleetd::runner::{AgentOutcome, AgentRunner, FinishOutcome, Reporter, RunConfig};
use fleetd::workspace::{RepoPolicy, Workspace};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tonic::Status;

#[path = "common/bounded.rs"]
mod common;
#[path = "common/logs.rs"]
mod logs;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GH: &str = r#"#!/bin/sh
root="$GIT_DIR/../.."
env > "$root/gh.env"
printf '%s\n' "$@" > "$root/gh.args"
if [ -f "$HOME/.config/gh/config.yml" ] || [ -f "$GH_CONFIG_DIR/config.yml" ]; then env > "$root/gh.sawconfig"; fi
case "$(cat "$root/mode")" in
ok) echo "created"; echo "https://example.invalid/pr/7"; exit 0 ;;
fail) echo "boom hunter2-hunter2 detail" >&2; exit 1 ;;
long) head -c 2000 /dev/zero | tr '\0' x >&2; echo " END hunter2-hunter2" >&2; exit 1 ;;
esac
"#;

const GIT: &str = r#"#!/bin/sh
sub=
for a in "$@"; do
  case "$a" in
  -c | core.* | credential.* | http.* | commit.* | gc.* | maintenance.* | filter.*) ;;
  *) sub=$a; break ;;
  esac
done
root="${GIT_DIR:-$PWD}/.."
env > "$root/git-$sub.env"
printf '%s\n' "$@" > "$root/git-$sub.args"
if [ "$sub" = rev-list ] && [ -e "$root/emptycount" ]; then exit 0; fi
if [ "$sub" = push ] && [ -e "$root/hold" ]; then
  i=0
  while [ ! -e "$root/release" ] && [ "$i" -lt 600 ]; do sleep 0.05; i=$((i + 1)); done
fi
exec git "$@"
"#;

#[derive(Clone, Copy, PartialEq)]
enum Reply {
    Ok,
    Stale,
    Cancel,
}

struct Fake(mpsc::UnboundedSender<ReportJobRequest>, Reply);

impl Reporter for Fake {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        let renewal = request.chunks.is_empty() && request.terminal_state.is_none();
        let _ = self.0.send(request);
        match self.1 {
            Reply::Stale if renewal => ready(Err(Status::failed_precondition("stale"))),
            Reply::Cancel if renewal => ready(Ok(ReportJobReply {
                cancel_requested: true,
                ..ReportJobReply::default()
            })),
            _ => ready(Ok(ReportJobReply::default())),
        }
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

const CLAUDE: &str = r#"#!/bin/sh
case "${2#*:}" in
write) echo agent > new.txt ;;
commit) echo agent > new.txt; git add -A; git commit -q -m "feat: by the agent" ;;
secret) echo "key hunter2-hunter2" > leak.txt ;;
trap)
  echo agent > new.txt
  printf '* filter=evil\n' > .gitattributes
  git config filter.evil.clean "touch '$FLEET_TEST_MARKS/filter'; cat"
  git config core.fsmonitor "touch '$FLEET_TEST_MARKS/fsmonitor'"
  hooks=$(git rev-parse --git-path hooks)
  mkdir -p "$hooks"
  printf '#!/bin/sh\ntouch "%s/hook"\n' "$FLEET_TEST_MARKS" > "$hooks/pre-commit"
  printf '#!/bin/sh\ntouch "%s/hook"\n' "$FLEET_TEST_MARKS" > "$hooks/commit-msg"
  chmod +x "$hooks/pre-commit" "$hooks/commit-msg"
  ;;
esac
exit 0
"#;

fn claude() -> &'static Path {
    static DIR: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_, path) = DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap_or_else(|_| std::process::abort());
        let path = dir.path().join("claude");
        std::fs::write(&path, CLAUDE).unwrap_or_else(|_| std::process::abort());
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
        .with_policy(test_policy())
        .prepare("job1", &origin.to_string_lossy(), "main")
        .await?;
    Ok(Rig {
        dir,
        origin,
        worktree: checkout.path,
    })
}

fn agent(rig: &Rig) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    agent_with(rig, PathBuf::from(env!("CARGO_BIN_EXE_fleetd")))
}

fn test_policy() -> RepoPolicy {
    RepoPolicy::new(Vec::<String>::new()).with_file_repos()
}

fn agent_with(
    rig: &Rig,
    askpass_bin: PathBuf,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    agent_with_policy(rig, askpass_bin, test_policy())
}

fn agent_with_policy(
    rig: &Rig,
    askpass_bin: PathBuf,
    policy: RepoPolicy,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    agent_build(rig, askpass_bin, policy, Duration::from_secs(30))
}

fn agent_paced(
    rig: &Rig,
    askpass_bin: PathBuf,
    report_interval: Duration,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    agent_build(rig, askpass_bin, test_policy(), report_interval)
}

fn agent_replying(
    rig: &Rig,
    reply: Reply,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    agent_assemble(
        rig,
        PathBuf::from(env!("CARGO_BIN_EXE_fleetd")),
        test_policy(),
        Duration::from_millis(100),
        reply,
    )
}

fn agent_build(
    rig: &Rig,
    askpass_bin: PathBuf,
    policy: RepoPolicy,
    report_interval: Duration,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    agent_assemble(rig, askpass_bin, policy, report_interval, Reply::Ok)
}

fn agent_assemble(
    rig: &Rig,
    askpass_bin: PathBuf,
    policy: RepoPolicy,
    report_interval: Duration,
    reply: Reply,
) -> (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut config = RunConfig::new("/bin/echo", false);
    config.repo_policy = policy;
    config.report_interval = report_interval;
    gh().clone_into(&mut config.gh_bin);
    git_wrapper().clone_into(&mut config.git_bin);
    config.askpass_bin = askpass_bin;
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
        AgentRunner::new(config, Fake(tx, reply), Redactor::new(["hunter2-hunter2"])),
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
    common::bounded(Box::pin(async {
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
    }))
    .await
}

fn recorded(rig: &Rig, sub: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(
        rig.dir.path().join("work").join(format!("git-{sub}.env")),
    )?)
}

#[tokio::test]
async fn only_the_push_gets_the_askpass_and_no_helper_runs_with_tokens_in_the_agent_repo()
-> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let (agent, _rx) = agent(&rig);
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .finish(&job(&rig, true), &rig.worktree, shutdown)
            .await?;
        let push = recorded(&rig, "push")?;
        assert!(push.contains(&format!("GIT_ASKPASS={}\n", env!("CARGO_BIN_EXE_fleetd"))));
        assert!(push.contains("FLEETD_ASKPASS=1\n"));
        assert!(!push.contains("/not/a/real/askpass"));
        assert!(push.contains("GH_TOKEN=not-a-real-gh-value\n"));
        let args = std::fs::read_to_string(rig.dir.path().join("work").join("git-push.args"))?;
        assert!(!args.contains("not-a-real-gh-value"));
        assert!(args.contains("push"));
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
    }))
    .await
}

#[tokio::test]
async fn planted_agent_config_neither_runs_nor_redirects_the_push() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn an_empty_commit_count_fails_instead_of_meaning_zero() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn no_changes_succeeds() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn a_job_without_a_pr_only_pushes() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn the_lease_is_renewed_while_the_push_runs() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        std::fs::write(rig.dir.path().join("work").join("hold"), "")?;
        let (agent, mut rx) = agent_paced(
            &rig,
            PathBuf::from(env!("CARGO_BIN_EXE_fleetd")),
            Duration::from_millis(100),
        );
        let (_trigger, shutdown) = Shutdown::channel();
        let release = rig.dir.path().join("work").join("release");
        let releaser = async {
            let mut renewals = 0;
            while renewals < 3 {
                let report = rx.recv().await.ok_or("reports ended")?;
                if report.chunks.is_empty() && report.terminal_state.is_none() {
                    renewals += 1;
                }
            }
            std::fs::write(&release, "")?;
            Ok::<_, Box<dyn std::error::Error>>(renewals)
        };
        let spec = job(&rig, true);
        let (finished, renewals) =
            tokio::join!(agent.finish(&spec, &rig.worktree, shutdown), releaser);
        finished?;
        assert!(renewals? >= 3);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_lost_lease_skips_the_push_and_the_terminal_report() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        std::fs::write(rig.dir.path().join("work").join("hold"), "")?;
        let (agent, mut rx) = agent_replying(&rig, Reply::Stale);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent
            .finish(&job(&rig, true), &rig.worktree, shutdown)
            .await?;
        assert_eq!(outcome, FinishOutcome::Lost);
        assert!(!pushed(&rig)?);
        assert!(drain(&mut rx).iter().all(|r| r.terminal_state.is_none()));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_cancel_reply_stops_the_push_and_reports_cancelled() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        std::fs::write(rig.dir.path().join("work").join("hold"), "")?;
        let (agent, mut rx) = agent_replying(&rig, Reply::Cancel);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = agent
            .finish(&job(&rig, true), &rig.worktree, shutdown)
            .await?;
        assert_eq!(outcome, FinishOutcome::Cancelled);
        let reports = drain(&mut rx);
        let last = reports.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Cancelled.into()));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn finish_continues_the_chunk_numbers_of_the_run() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("fail").await?;
        let (agent, mut rx) = agent(&rig);
        let (_trigger, shutdown) = Shutdown::channel();
        let ran = agent
            .run(&job(&rig, true), &rig.worktree, shutdown.clone())
            .await?;
        assert_eq!(ran, AgentOutcome::Succeeded);
        commit(&rig)?;
        agent
            .finish(&job(&rig, true), &rig.worktree, shutdown)
            .await?;
        let seqs: Vec<u64> = drain(&mut rx)
            .iter()
            .flat_map(|r| r.chunks.iter().map(|c| c.seq))
            .collect();
        assert_eq!(seqs, [1, 2]);
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_gh_failure_reports_a_fixed_error() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
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
    common::bounded(Box::pin(async {
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
        push.insert("FLEETD_ASKPASS".into());
        push.insert("GH_TOKEN".into());
        push.insert("FLEETD_ASKPASS_HOST".into());
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
    }))
    .await
}

#[tokio::test]
async fn planted_real_home_config_is_never_read_by_gh_or_push() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn a_title_over_the_limit_is_cut_at_a_char_boundary() -> TestResult {
    common::bounded(Box::pin(async {
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
    }))
    .await
}

#[tokio::test]
async fn an_askpass_path_with_quotes_and_substitutions_is_passed_verbatim() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let odd = rig.dir.path().join("it's $(touch pwned) x");
        std::fs::create_dir(&odd)?;
        let bin = odd.join("askpass");
        std::fs::write(&bin, "#!/bin/sh\necho ran\n")?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        let (agent, _rx) = agent_with(&rig, bin);
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .finish(&job(&rig, true), &rig.worktree, shutdown)
            .await?;
        let push = recorded(&rig, "push")?;
        let line = push
            .lines()
            .find_map(|line| line.strip_prefix("GIT_ASKPASS="))
            .ok_or("no askpass")?;
        let probe = TempDir::new()?;
        assert_eq!(line, odd.join("askpass").to_str().ok_or("path")?);
        let out = Command::new(line)
            .arg("prompt")
            .current_dir(probe.path())
            .output()?;
        assert!(out.status.success());
        assert_eq!(String::from_utf8(out.stdout)?, "ran\n");
        assert!(!probe.path().join("pwned").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_job_repo_outside_the_policy_never_reaches_a_push() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let policy = RepoPolicy::new(["github.com"]);
        let (agent, mut rx) =
            agent_with_policy(&rig, PathBuf::from(env!("CARGO_BIN_EXE_fleetd")), policy);
        for repo in [
            "https://attacker.example/x.git",
            "https://github.com@attacker.example/x.git",
            "https://github.com:8443/x.git",
            "http://github.com/x.git",
            "ssh://github.com/x.git",
            "git://github.com/x.git",
            "file:///tmp/x.git",
            "/tmp/x.git",
        ] {
            let (_trigger, shutdown) = Shutdown::channel();
            let mut bad = job(&rig, true);
            repo.clone_into(&mut bad.repo);
            let outcome = agent.finish(&bad, &rig.worktree, shutdown).await?;
            assert_eq!(
                outcome,
                FinishOutcome::Failed {
                    error: "git push failed"
                },
                "{repo}"
            );
            let reports = drain(&mut rx);
            let last = reports.last().ok_or("no report")?;
            assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        }
        assert!(!rig.dir.path().join("work").join("git-push.env").exists());
        assert!(!rig.dir.path().join("gh.env").exists());
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_push_disables_redirect_following() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let (agent, _rx) = agent(&rig);
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .finish(&job(&rig, false), &rig.worktree, shutdown)
            .await?;
        let args = std::fs::read_to_string(rig.dir.path().join("work").join("git-push.args"))?;
        let lines: Vec<&str> = args.lines().collect();
        assert!(
            lines
                .windows(2)
                .any(|w| w == ["-c", "http.followRedirects=false"]),
            "{args}"
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_push_allows_only_https_and_names_the_token_host() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let policy = RepoPolicy::new(["origin.test", "git.example"])
            .with_token_host(Some("origin.test".to_owned()));
        let (agent, _rx) =
            agent_with_policy(&rig, PathBuf::from(env!("CARGO_BIN_EXE_fleetd")), policy);
        let (_trigger, shutdown) = Shutdown::channel();
        let mut remote = job(&rig, false);
        "https://origin.test/x.git".clone_into(&mut remote.repo);
        let outcome = agent.finish(&remote, &rig.worktree, shutdown).await?;
        assert!(matches!(outcome, FinishOutcome::Failed { .. }));
        let push = recorded(&rig, "push")?;
        assert!(push.contains("GIT_ALLOW_PROTOCOL=https\n"), "{push}");
        assert!(push.contains("FLEETD_ASKPASS_HOST=origin.test\n"), "{push}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_second_repo_host_never_receives_the_token_host_credential() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let policy = RepoPolicy::new(["github.com", "gitlab.com"]);
        let (agent, _rx) =
            agent_with_policy(&rig, PathBuf::from(env!("CARGO_BIN_EXE_fleetd")), policy);
        let (_trigger, shutdown) = Shutdown::channel();
        let mut remote = job(&rig, false);
        "https://gitlab.com/o/x.git".clone_into(&mut remote.repo);
        agent.finish(&remote, &rig.worktree, shutdown).await?;
        let push = recorded(&rig, "push")?;
        assert!(push.contains("FLEETD_ASKPASS_HOST=github.com\n"), "{push}");
        assert!(!push.contains("gitlab.com"), "{push}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn the_test_policy_adds_the_file_transport_to_the_push() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        commit(&rig)?;
        let (agent, _rx) = agent(&rig);
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .finish(&job(&rig, false), &rig.worktree, shutdown)
            .await?;
        let push = recorded(&rig, "push")?;
        assert!(push.contains("GIT_ALLOW_PROTOCOL=file:https\n"), "{push}");
        assert!(push.contains("FLEETD_ASKPASS_HOST=\n"), "{push}");
        Ok(())
    }))
    .await
}

fn claude_agent(
    rig: &Rig,
) -> Result<
    (AgentRunner<Fake>, mpsc::UnboundedReceiver<ReportJobRequest>),
    Box<dyn std::error::Error>,
> {
    let marks = rig.dir.path().join("marks");
    std::fs::create_dir_all(&marks)?;
    let (tx, rx) = mpsc::unbounded_channel();
    let mut config = RunConfig::new(claude(), false);
    config.repo_policy = test_policy();
    gh().clone_into(&mut config.gh_bin);
    git_wrapper().clone_into(&mut config.git_bin);
    config.askpass_bin = PathBuf::from(env!("CARGO_BIN_EXE_fleetd"));
    config.jobs_dir = Some(rig.dir.path().join("work"));
    config.env_passthrough = vec!["FLEET_TEST_MARKS".into()];
    let mut env: Vec<(OsString, OsString)> = vec![
        ("HOME".into(), rig.dir.path().into()),
        ("FLEET_TEST_MARKS".into(), marks.into()),
    ];
    env.extend(std::env::var_os("PATH").map(|path| ("PATH".into(), path)));
    config.base_env = env;
    Ok((
        AgentRunner::new(
            config,
            Fake(tx, Reply::Ok),
            Redactor::new(["hunter2-hunter2"]),
        ),
        rx,
    ))
}

async fn run_then_finish(
    rig: &Rig,
    agent: &AgentRunner<Fake>,
    prompt: &str,
) -> Result<FinishOutcome, Box<dyn std::error::Error>> {
    let (_trigger, shutdown) = Shutdown::channel();
    let mut job = job(rig, true);
    job.prompt = prompt.to_owned();
    let ran = agent.run(&job, &rig.worktree, shutdown.clone()).await?;
    assert_eq!(ran, AgentOutcome::Succeeded);
    Ok(agent.finish(&job, &rig.worktree, shutdown).await?)
}

fn ahead(rig: &Rig) -> Result<String, Box<dyn std::error::Error>> {
    Ok(
        git(&rig.origin, &["rev-list", "--count", "main..swarm/job1"])?
            .trim()
            .to_owned(),
    )
}

#[tokio::test]
async fn uncommitted_agent_work_is_committed_once_and_published() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        let (agent, _rx) = claude_agent(&rig)?;
        let outcome = run_then_finish(&rig, &agent, "x:write").await?;
        assert_eq!(
            outcome,
            FinishOutcome::Succeeded {
                branch: Some("swarm/job1".into()),
                pr_url: Some("https://example.invalid/pr/7".into()),
            }
        );
        assert_eq!(ahead(&rig)?, "1");
        let log = git(&rig.origin, &["log", "-1", "--format=%s|%an|%ae|%cn", "swarm/job1"])?;
        assert_eq!(
            log.trim(),
            "chore: uncommitted job changes (fleet job job1)|Fleet Job|fleet-job@fleet.invalid|Fleet Job"
        );
        assert_eq!(git(&rig.origin, &["show", "swarm/job1:new.txt"])?, "agent\n");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn work_the_agent_committed_gets_no_extra_commit() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        let (agent, _rx) = claude_agent(&rig)?;
        let outcome = run_then_finish(&rig, &agent, "x:commit").await?;
        assert!(matches!(
            outcome,
            FinishOutcome::Succeeded {
                branch: Some(_),
                ..
            }
        ));
        assert_eq!(ahead(&rig)?, "1");
        let subject = git(&rig.origin, &["log", "-1", "--format=%s", "swarm/job1"])?;
        assert_eq!(subject.trim(), "feat: by the agent");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_clean_tree_with_no_commits_succeeds_with_a_no_changes_note() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("fail").await?;
        let (agent, mut rx) = claude_agent(&rig)?;
        let (logs, _guard) = logs::capture_logs();
        let outcome = run_then_finish(&rig, &agent, "x:none").await?;
        assert_eq!(
            outcome,
            FinishOutcome::Succeeded {
                branch: None,
                pr_url: None,
            }
        );
        assert!(!pushed(&rig)?);
        assert_eq!(
            git(&rig.worktree, &["rev-list", "--count", "origin/main..HEAD"])?.trim(),
            "0"
        );
        let reports = drain(&mut rx);
        let last = reports.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Succeeded.into()));
        let text: String = reports
            .iter()
            .flat_map(|r| r.chunks.iter().map(|c| c.text.as_str()))
            .collect();
        assert!(text.contains("no_changes"), "{text}");
        assert!(logs.text().contains("no changes"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_job_with_changes_carries_no_no_changes_note() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        let (agent, mut rx) = claude_agent(&rig)?;
        run_then_finish(&rig, &agent, "x:write").await?;
        let text: String = drain(&mut rx)
            .iter()
            .flat_map(|r| r.chunks.iter().map(|c| c.text.clone()))
            .collect();
        assert!(!text.contains("no_changes"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn planted_hooks_filters_and_fsmonitor_do_not_run_during_the_fallback() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        let (agent, _rx) = claude_agent(&rig)?;
        let outcome = run_then_finish(&rig, &agent, "x:trap").await?;
        assert!(matches!(
            outcome,
            FinishOutcome::Succeeded {
                branch: Some(_),
                ..
            }
        ));
        let marks: Vec<_> = std::fs::read_dir(rig.dir.path().join("marks"))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        assert!(marks.is_empty(), "ran: {marks:?}");
        assert_eq!(ahead(&rig)?, "1");
        assert_eq!(
            git(&rig.origin, &["show", "swarm/job1:new.txt"])?,
            "agent\n"
        );
        assert!(git(&rig.origin, &["show", "swarm/job1:.gitattributes"])?.contains("filter=evil"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_staged_secret_fails_the_job_and_nothing_is_committed() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("ok").await?;
        let (agent, mut rx) = claude_agent(&rig)?;
        let outcome = run_then_finish(&rig, &agent, "x:secret").await?;
        assert_eq!(
            outcome,
            FinishOutcome::Failed {
                error: "uncommitted changes held a secret value"
            }
        );
        assert!(!pushed(&rig)?);
        assert_eq!(
            git(&rig.worktree, &["rev-list", "--count", "origin/main..HEAD"])?.trim(),
            "0"
        );
        let reports = drain(&mut rx);
        let last = reports.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert_eq!(
            last.error.as_deref(),
            Some("uncommitted changes held a secret value")
        );
        let text: String = reports
            .iter()
            .flat_map(|r| r.chunks.iter().map(|c| c.text.as_str()))
            .collect();
        assert!(!text.contains("hunter2"));
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn a_publish_failure_logs_a_redacted_stderr_tail_of_at_most_512_bytes() -> TestResult {
    common::bounded(Box::pin(async {
        let rig = rig("long").await?;
        commit(&rig)?;
        let (agent, _rx) = agent(&rig);
        let (logs, _guard) = logs::capture_logs();
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .finish(&job(&rig, true), &rig.worktree, shutdown)
            .await?;
        let out = logs.text();
        assert!(out.contains("job publish step failed"), "{out}");
        assert!(out.contains("END [REDACTED]"), "{out}");
        assert!(!out.contains("hunter2"), "{out}");
        let line = out
            .lines()
            .find(|l| l.contains("job publish step failed"))
            .ok_or("no log line")?;
        let tail = line.split_once("stderr_tail=").ok_or("no tail")?.1;
        let tail_xs = tail.matches('x').count();
        assert!((400..=512).contains(&tail_xs), "{tail_xs}");
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn every_terminal_report_from_finish_carries_a_summary() -> TestResult {
    common::bounded(Box::pin(async {
        let ok = rig("ok").await?;
        commit(&ok)?;
        let (runner, mut rx) = agent(&ok);
        let (_trigger, shutdown) = Shutdown::channel();
        let outcome = runner
            .finish(&job(&ok, true), &ok.worktree, shutdown)
            .await?;
        assert!(matches!(outcome, FinishOutcome::Succeeded { .. }));
        let reports = drain(&mut rx);
        let last = reports.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Succeeded.into()));
        assert!(last.summary.as_ref().is_some_and(|s| !s.complete));

        let bad = rig("fail").await?;
        commit(&bad)?;
        let (runner, mut rx) = agent(&bad);
        let (_trigger, shutdown) = Shutdown::channel();
        runner
            .finish(&job(&bad, true), &bad.worktree, shutdown)
            .await?;
        let reports = drain(&mut rx);
        let last = reports.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Failed.into()));
        assert!(last.summary.is_some());

        let stopped = rig("ok").await?;
        commit(&stopped)?;
        std::fs::write(stopped.dir.path().join("work").join("hold"), "")?;
        let (agent, mut rx) = agent_replying(&stopped, Reply::Cancel);
        let (_trigger, shutdown) = Shutdown::channel();
        agent
            .finish(&job(&stopped, true), &stopped.worktree, shutdown)
            .await?;
        let reports = drain(&mut rx);
        let last = reports.last().ok_or("no report")?;
        assert_eq!(last.terminal_state, Some(JobState::Cancelled.into()));
        assert!(last.summary.is_some());
        Ok(())
    }))
    .await
}
