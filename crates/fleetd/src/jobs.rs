//! The daemon's job path: claim, prepare a worktree, run the agent, publish the result.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::path::{Path, PathBuf};

use fleet_core::Redactor;
use fleet_proto::v1::Job;
use tonic::transport::Channel;

use crate::Error;
use crate::agent_config::Bundle;
use crate::config::Config;
use crate::poller::{
    GrpcReporter, JobRunner, PollRandom, Poller, RunError, SERVER_URL_ENV, Shutdown, TOKEN_ENV,
    Token, channel,
};
use crate::runner::{AgentOutcome, AgentRunner, Interrupt, Reporter, RunConfig};
use crate::workspace::{RepoPolicy, Workspace};

const ERR_WORKSPACE: &str = "workspace could not be prepared";
const ERR_PREPARE_TIMEOUT: &str = "workspace preparation timed out";
const ERR_SHUTDOWN: &str = "agent stopped by daemon shutdown";

/// The poller the daemon runs.
pub(crate) type JobPoller = Poller<DaemonRunner<GrpcReporter>>;

/// Runs one claimed job from checkout to terminal report.
pub(crate) struct DaemonRunner<R> {
    workspace: Workspace,
    agent: AgentRunner<R>,
}

impl<R: Reporter> DaemonRunner<R> {
    fn new(workspace: Workspace, agent: AgentRunner<R>) -> Self {
        Self { workspace, agent }
    }

    async fn prepare(&self, job: &Job, mut shutdown: Shutdown) -> Result<PathBuf, RunError> {
        let work = tokio::time::timeout(
            self.agent.prepare_timeout(),
            self.workspace
                .prepare(&job.job_id, &job.repo, &job.base_ref),
        );
        let guarded = tokio::select! {
            guarded = self.agent.keep_alive(job, work) => guarded,
            () = shutdown.requested() => {
                self.agent.fail_job(job, ERR_SHUTDOWN).await;
                return Err(RunError);
            }
        };
        match guarded {
            Ok(Ok(Ok(checkout))) => Ok(checkout.path),
            Ok(Ok(Err(err))) => {
                tracing::warn!(
                    error = %err,
                    detail = err.detail().unwrap_or_default(),
                    "job workspace could not be prepared"
                );
                self.agent.fail_job(job, ERR_WORKSPACE).await;
                Err(RunError)
            }
            Ok(Err(_)) => {
                tracing::warn!("job workspace preparation timed out");
                self.agent.fail_job(job, ERR_PREPARE_TIMEOUT).await;
                Err(RunError)
            }
            Err(Interrupt::Cancelled) => {
                self.agent.cancel_job(job).await;
                Err(RunError)
            }
            Err(_) => Err(RunError),
        }
    }

    async fn execute(&self, job: &Job, path: &Path, shutdown: Shutdown) -> Result<(), RunError> {
        let outcome = self.agent.run(job, path, shutdown.clone()).await?;
        if matches!(outcome, AgentOutcome::Succeeded) {
            self.agent.finish(job, path, shutdown).await?;
        } else {
            tracing::info!(outcome = ?outcome, "job ended without a publish step");
        }
        Ok(())
    }
}

impl<R: Reporter + 'static> JobRunner for DaemonRunner<R> {
    async fn run(&self, job: Job, shutdown: Shutdown) -> Result<(), RunError> {
        let result = match self.prepare(&job, shutdown.clone()).await {
            Ok(path) => self.execute(&job, &path, shutdown).await,
            Err(stop) => Err(stop),
        };
        if self.workspace.remove(&job.job_id, &job.repo).await.is_err() {
            tracing::warn!("job workspace could not be removed");
        }
        result
    }
}

fn job_workspace(
    config: &Config,
    run: &mut RunConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> Workspace {
    let mut policy = RepoPolicy::new(config.repo_hosts.iter().cloned())
        .with_token_host(config.token_host.clone());
    if config.allow_file_repos {
        policy = policy.with_file_repos();
    }
    run.repo_policy = policy.clone();
    let mut workspace = Workspace::new(PathBuf::from(&config.jobs_dir)).with_policy(policy);
    if let Some(token) = env("GH_TOKEN") {
        workspace = workspace.with_credential(run.askpass_bin.clone(), token);
    }
    workspace
}

/// Builds the poller when `FLEET_SERVER_URL` is set and non-empty, else `None`.
///
/// # Errors
///
/// Fails when the URL or `FLEET_TOKEN` is unusable. The error never holds either value.
pub(crate) fn build(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
    box_name: &str,
    redactor: Redactor,
) -> Result<Option<JobPoller>, Error> {
    let Some(url) = env(SERVER_URL_ENV).filter(|url| !url.is_empty()) else {
        return Ok(None);
    };
    let token = env(TOKEN_ENV)
        .filter(|token| !token.is_empty())
        .map(Token::new)
        .ok_or(Error::InvalidValue {
            name: TOKEN_ENV,
            value: String::from("<redacted>"),
        })?;
    let channel: Channel = channel(&url)?;
    let reporter = GrpcReporter::new(channel.clone(), &token)?;
    let mut run = RunConfig::new(&config.claude_bin, config.disposable);
    run.gh_bin.clone_from(&config.gh_bin);
    run.jobs_dir = Some(config.jobs_dir.clone());
    run.env_passthrough
        .clone_from(&config.agent_env_passthrough);
    if let Some(dir) = &config.agent_config_dir {
        run.bundle = Bundle::from_dir(dir).map_err(|err| Error::InvalidValue {
            name: "agent_config_dir",
            value: err.to_string(),
        })?;
    }
    let workspace = job_workspace(config, &mut run, env).with_redactor(redactor.clone());
    let runner = DaemonRunner::new(workspace, AgentRunner::new(run, reporter, redactor));
    Poller::with_channel(
        channel,
        &token,
        box_name.to_owned(),
        runner,
        PollRandom::system(),
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use fleet_proto::v1::{ReportJobReply, ReportJobRequest};
    use tokio::sync::mpsc;
    use tonic::Status;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct Recorder(mpsc::UnboundedSender<ReportJobRequest>);

    impl Reporter for Recorder {
        fn report(
            &self,
            request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            let _ = self.0.send(request);
            std::future::ready(Ok(ReportJobReply::default()))
        }
    }

    #[tokio::test]
    async fn the_gh_token_env_value_reaches_the_mirror_fetch() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = dir.path().join("rec-git");
        std::fs::write(
            &git,
            "#!/bin/sh\ncase \"$*\" in\n*\" fetch \"*) printf %s \"$GH_TOKEN\" > \"$(dirname \"$HOME\")/tok\" ;;\nesac\nexit 0\n",
        )?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        let jobs = dir.path().join("jobs");
        let mut config = Config::resolve(None, &|_| None)?;
        config.jobs_dir.clone_from(&jobs);
        let mut run = RunConfig::new("claude", false);
        let env = |name: &str| (name == "GH_TOKEN").then(|| String::from("tok-wired"));
        let workspace =
            job_workspace(&config, &mut run, &env).with_git(&git, Duration::from_secs(10));
        workspace
            .prepare("job1", "https://github.com/o/r.git", "main")
            .await?;
        assert_eq!(std::fs::read_to_string(jobs.join("tok"))?, "tok-wired");
        Ok(())
    }

    #[tokio::test]
    async fn a_slow_prepare_renews_the_lease_before_it_returns() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = dir.path().join("slow-git");
        std::fs::write(&git, "#!/bin/sh\nsleep 1\nexit 1\n")?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.report_interval = Duration::from_millis(100);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            Workspace::new(dir.path().join("jobs"))
                .with_policy(RepoPolicy::new(Vec::<String>::new()).with_file_repos())
                .with_git(&git, Duration::from_secs(10)),
            AgentRunner::new(cfg, Recorder(tx), Redactor::default()),
        );
        let job = Job {
            job_id: "job1".into(),
            repo: "file:///nonexistent.git".into(),
            base_ref: "main".into(),
            attempt: 1,
            ..Job::default()
        };
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(runner.run(job, shutdown).await.is_err());
        let mut renewals = 0;
        let mut terminal = false;
        while let Ok(report) = rx.try_recv() {
            if report.terminal_state.is_some() {
                terminal = true;
            } else if report.chunks.is_empty() {
                assert!(!terminal);
                renewals += 1;
            }
        }
        assert!(terminal);
        assert!(renewals >= 2, "renewals: {renewals}");
        Ok(())
    }

    struct Stale(mpsc::UnboundedSender<ReportJobRequest>);

    impl Reporter for Stale {
        fn report(
            &self,
            request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            let _ = self.0.send(request);
            std::future::ready(Err(Status::failed_precondition("stale")))
        }
    }

    fn script(dir: &Path, body: &str) -> Result<PathBuf, std::io::Error> {
        let git = dir.join("fake-git");
        std::fs::write(&git, format!("#!/bin/sh\n{body}\n"))?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        Ok(git)
    }

    fn workspace(dir: &Path, git: &Path) -> Workspace {
        Workspace::new(dir.join("jobs"))
            .with_policy(RepoPolicy::new(Vec::<String>::new()).with_file_repos())
            .with_git(git, Duration::from_secs(60))
    }

    fn sample_job() -> Job {
        Job {
            job_id: "job1".into(),
            repo: "file:///nonexistent.git".into(),
            base_ref: "main".into(),
            attempt: 1,
            ..Job::default()
        }
    }

    #[tokio::test]
    async fn a_lost_lease_during_prepare_ends_the_job_without_a_terminal_report() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = script(dir.path(), "sleep 30")?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.report_interval = Duration::from_millis(100);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(cfg, Stale(tx), Redactor::default()),
        );
        let (_trigger, shutdown) = Shutdown::channel();
        let ended =
            tokio::time::timeout(Duration::from_secs(20), runner.run(sample_job(), shutdown))
                .await?;
        assert!(ended.is_err());
        while let Ok(report) = rx.try_recv() {
            assert!(report.terminal_state.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_prepare_past_its_deadline_reports_failed() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = script(dir.path(), "sleep 30")?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.prepare_timeout = Duration::from_millis(200);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(cfg, Recorder(tx), Redactor::default()),
        );
        let (_trigger, shutdown) = Shutdown::channel();
        let ended =
            tokio::time::timeout(Duration::from_secs(20), runner.run(sample_job(), shutdown))
                .await?;
        assert!(ended.is_err());
        let mut errors = Vec::new();
        while let Ok(report) = rx.try_recv() {
            errors.extend(report.error);
        }
        assert_eq!(errors, vec![ERR_PREPARE_TIMEOUT.to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_prepare_removes_what_it_left_behind() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = script(dir.path(), "exit 1")?;
        let leftover = dir.path().join("jobs").join("job1");
        std::fs::create_dir_all(&leftover)?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(
                RunConfig::new("claude", false),
                Recorder(tx),
                Redactor::default(),
            ),
        );
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(runner.run(sample_job(), shutdown).await.is_err());
        assert!(!leftover.exists());
        Ok(())
    }
}
