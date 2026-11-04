//! The runner resolves a Profile's tools before the agent starts: a cache hit skips the install,
//! a miss runs a fake mise through the installer seam and then the agent sees the tool bin first
//! on its `PATH`, a failed install ends the job with the one fixed message and no agent spawn,
//! and a Profile without tools keeps the environment it had. Own test binary because it spawns
//! children. Nothing here touches a real mise or a live box.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::ffi::OsString;
use std::fs;
use std::future::{Future, ready};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::tools::ToolSpec;
use fleet_core::{Profile, Redactor};
use fleet_proto::v1::{
    GetProfileBlobReply, GetProfileBlobRequest, Job, ProfileRef, ReportJobReply, ReportJobRequest,
};
use fleetd::poller::Shutdown;
use fleetd::runner::{
    AgentOutcome, AgentRunner, InstallFuture, Reporter, RunConfig, TOOL_PREFLIGHT_FAILED,
    ToolInstaller, ToolPreflight,
};
use fleetd::tools::ToolCache;
use tempfile::TempDir;
use tonic::Status;

const AGENT: &str = r#"#!/bin/sh
[ "$1" = --version ] && { echo '2.0.0 (Claude Code)'; exit 0; }
printf '%s' "$PATH" > "$PWD/seen-path"
"#;

const FAKE_MISE: &str = r#"#!/bin/sh
echo run >> "$FAKE_LOG"
[ -n "$FAKE_FAIL" ] && { echo "secret-stderr $FAKE_CACHE" >&2; exit 1; }
mkdir -p "$FAKE_CACHE/jq/1.7.1/bin"
chmod 755 "$FAKE_CACHE/jq" "$FAKE_CACHE/jq/1.7.1" "$FAKE_CACHE/jq/1.7.1/bin"
"#;

#[derive(Debug)]
struct FakeMise {
    program: PathBuf,
    cache: PathBuf,
    log: PathBuf,
    fail: bool,
    calls: AtomicUsize,
}

impl ToolInstaller for FakeMise {
    fn install<'a>(&'a self, _job_id: &'a str, _tools: &'a [ToolSpec]) -> InstallFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .env("FAKE_LOG", &self.log)
            .env("FAKE_CACHE", &self.cache);
        if self.fail {
            command.env("FAKE_FAIL", "1");
        }
        Box::pin(async move {
            let status = tokio::task::spawn_blocking(move || command.output())
                .await
                .map_err(std::io::Error::other)??
                .status;
            if status.success() {
                Ok(())
            } else {
                Err(std::io::Error::other("install exited nonzero"))
            }
        })
    }
}

struct Server {
    reports: Mutex<Vec<ReportJobRequest>>,
    profile: Profile,
}

#[derive(Clone)]
struct Handle(Arc<Server>);

impl Reporter for Handle {
    fn report(
        &self,
        request: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        self.0
            .reports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        ready(Ok(ReportJobReply::default()))
    }

    fn profile_blob(
        &self,
        request: GetProfileBlobRequest,
    ) -> impl Future<Output = Result<GetProfileBlobReply, Status>> + Send {
        let _ = request;
        ready(Ok(GetProfileBlobReply {
            profile: Some(reference(&self.0.profile)),
            content: self.0.profile.canonical_json(),
        }))
    }
}

fn reference(profile: &Profile) -> ProfileRef {
    ProfileRef {
        name: "p".into(),
        version: 1,
        hash: profile.hash().to_string(),
    }
}

fn job(profile: &Profile) -> Job {
    Job {
        job_id: "job1".into(),
        attempt: 1,
        r#box: "boxa".into(),
        prompt: "go".into(),
        profile: Some(reference(profile)),
        profile_tools_granted: true,
        ..Job::default()
    }
}

fn tool_profile() -> Profile {
    Profile {
        model: Some("opus".into()),
        tools: vec![ToolSpec::new("jq", "1.7.1").unwrap()],
        ..Profile::default()
    }
}

fn plain_profile() -> Profile {
    Profile {
        model: Some("opus".into()),
        ..Profile::default()
    }
}

fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

struct Rig {
    dir: TempDir,
    cache: PathBuf,
    mise: Arc<FakeMise>,
    server: Arc<Server>,
    runner: AgentRunner<Handle>,
}

fn rig(profile: Profile, fail: bool, preflight: bool) -> Rig {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let cache = dir.path().join("tools");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
    let agent = executable(dir.path(), "claude", AGENT);
    let mise = Arc::new(FakeMise {
        program: executable(dir.path(), "mise", FAKE_MISE),
        cache: cache.clone(),
        log: dir.path().join("mise.log"),
        fail,
        calls: AtomicUsize::new(0),
    });
    let server = Arc::new(Server {
        reports: Mutex::new(Vec::new()),
        profile,
    });
    let mut config = RunConfig::new(agent, true);
    config.base_env = vec![("PATH".into(), OsString::from("/inherited/bin"))];
    config.jobs_dir = Some(dir.path().join("jobs"));
    let installer: Arc<dyn ToolInstaller> = mise.clone();
    let mut runner = AgentRunner::new(config, Handle(Arc::clone(&server)), Redactor::default());
    if preflight {
        let owner = fs::metadata(&cache).unwrap().uid();
        runner = runner.with_tool_preflight(
            ToolPreflight::new(ToolCache::new(&cache, owner)).with_installer(installer),
        );
    }
    Rig {
        dir,
        cache,
        mise,
        server,
        runner,
    }
}

fn seed_hit(cache: &Path) {
    let bin = cache.join("jq").join("1.7.1").join("bin");
    fs::create_dir_all(&bin).unwrap();
    for dir in [cache.join("jq"), cache.join("jq").join("1.7.1"), bin] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

async fn run_agent(rig: &Rig, job: &Job) -> (AgentOutcome, Option<String>) {
    let cwd = rig.dir.path().join("work");
    fs::create_dir_all(&cwd).unwrap();
    let (_trigger, shutdown) = Shutdown::channel();
    let outcome = rig.runner.run(job, &cwd, shutdown).await.unwrap();
    (outcome, fs::read_to_string(cwd.join("seen-path")).ok())
}

#[tokio::test]
async fn unstamped_profile_tools_are_refused_before_any_install_or_workdir() {
    let rig = rig(tool_profile(), false, true);
    let mut job = job(&rig.server.profile);
    job.profile_tools_granted = false;
    let err = rig.runner.load_profile(&job, "boxa").await.unwrap_err();
    assert_eq!(err.reason(), fleetd::floor::TOOLS_DENIED_REASON);
    assert_eq!(rig.mise.calls.load(Ordering::SeqCst), 0);
    assert!(!rig.mise.log.exists());
    assert!(!rig.dir.path().join("jobs").exists());
    assert!(!rig.dir.path().join("work").exists());
}

#[tokio::test]
async fn a_cache_hit_skips_the_install_and_puts_the_tool_first_on_the_path() {
    let rig = rig(tool_profile(), false, true);
    seed_hit(&rig.cache);
    let job = job(&rig.server.profile);
    rig.runner.load_profile(&job, "boxa").await.unwrap();
    rig.runner.preflight_tools(&job).await.unwrap();
    assert_eq!(rig.mise.calls.load(Ordering::SeqCst), 0);
    let (outcome, seen) = run_agent(&rig, &job).await;
    assert!(matches!(outcome, AgentOutcome::Succeeded));
    let bin = rig.cache.join("jq/1.7.1/bin");
    assert_eq!(
        seen.unwrap(),
        format!("{}:/usr/local/bin:/usr/bin:/bin", bin.display())
    );
}

#[tokio::test]
async fn a_miss_installs_then_the_agent_runs_without_the_inherited_path() {
    let rig = rig(tool_profile(), false, true);
    let job = job(&rig.server.profile);
    rig.runner.load_profile(&job, "boxa").await.unwrap();
    rig.runner.preflight_tools(&job).await.unwrap();
    assert_eq!(rig.mise.calls.load(Ordering::SeqCst), 1);
    assert!(rig.mise.log.exists());
    let (outcome, seen) = run_agent(&rig, &job).await;
    assert!(matches!(outcome, AgentOutcome::Succeeded));
    let seen = seen.unwrap();
    assert!(seen.starts_with(&rig.cache.display().to_string()), "{seen}");
    assert!(!seen.contains("/inherited/bin"), "{seen}");
}

#[tokio::test]
async fn a_failed_install_gives_the_fixed_message_and_the_agent_never_runs() {
    let rig = rig(tool_profile(), true, true);
    let job = job(&rig.server.profile);
    rig.runner.load_profile(&job, "boxa").await.unwrap();
    assert_eq!(
        rig.runner.preflight_tools(&job).await,
        Err(TOOL_PREFLIGHT_FAILED)
    );
    assert_eq!(TOOL_PREFLIGHT_FAILED, "tool preflight failed");
    assert_eq!(rig.mise.calls.load(Ordering::SeqCst), 1);
    assert!(!rig.dir.path().join("work/seen-path").exists());
    assert!(!rig.cache.join("jq").exists());
}

#[tokio::test]
async fn a_miss_after_a_silent_install_still_fails() {
    let rig = rig(tool_profile(), false, true);
    fs::remove_file(rig.dir.path().join("mise")).unwrap();
    executable(rig.dir.path(), "mise", "#!/bin/sh\nexit 0\n");
    let job = job(&rig.server.profile);
    rig.runner.load_profile(&job, "boxa").await.unwrap();
    assert_eq!(
        rig.runner.preflight_tools(&job).await,
        Err(TOOL_PREFLIGHT_FAILED)
    );
}

#[tokio::test]
async fn a_profile_without_tools_keeps_the_inherited_environment_and_never_installs() {
    let with = rig(plain_profile(), false, true);
    let without = rig(plain_profile(), false, false);
    let job_with = job(&with.server.profile);
    let job_without = job(&without.server.profile);
    with.runner.load_profile(&job_with, "boxa").await.unwrap();
    without
        .runner
        .load_profile(&job_without, "boxa")
        .await
        .unwrap();
    with.runner.preflight_tools(&job_with).await.unwrap();
    without.runner.preflight_tools(&job_without).await.unwrap();
    let home = with.dir.path().join("home");
    let a = with.runner.agent_spec(&job_with, with.dir.path(), &home);
    let b = without
        .runner
        .agent_spec(&job_without, with.dir.path(), &home);
    assert_eq!(a.env, b.env);
    assert_eq!(a.argv[1..], b.argv[1..]);
    assert_eq!(
        a.env.get(&OsString::from("PATH")).unwrap(),
        "/inherited/bin"
    );
    assert_eq!(with.mise.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_tool_profile_without_a_preflight_fails_with_the_fixed_message() {
    let rig = rig(tool_profile(), false, false);
    let job = job(&rig.server.profile);
    rig.runner.load_profile(&job, "boxa").await.unwrap();
    assert_eq!(
        rig.runner.preflight_tools(&job).await,
        Err(TOOL_PREFLIGHT_FAILED)
    );
}

#[tokio::test]
async fn an_env_passthrough_of_path_in_any_case_fails_the_preflight() {
    let mut rig = rig(tool_profile(), false, true);
    seed_hit(&rig.cache);
    let owner = fs::metadata(&rig.cache).unwrap().uid();
    let installer: Arc<dyn ToolInstaller> = rig.mise.clone();
    let mut config = RunConfig::new(rig.dir.path().join("claude"), true);
    config.env_passthrough = vec!["Path".to_owned()];
    rig.runner = AgentRunner::new(config, Handle(Arc::clone(&rig.server)), Redactor::default())
        .with_tool_preflight(
            ToolPreflight::new(ToolCache::new(&rig.cache, owner)).with_installer(installer),
        );
    let job = job(&rig.server.profile);
    rig.runner.load_profile(&job, "boxa").await.unwrap();
    assert_eq!(
        rig.runner.preflight_tools(&job).await,
        Err(TOOL_PREFLIGHT_FAILED)
    );
}
