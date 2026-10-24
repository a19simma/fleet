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
use crate::config::Config;
use crate::poller::{
    GrpcReporter, JobRunner, PollRandom, Poller, RunError, SERVER_URL_ENV, Shutdown, TOKEN_ENV,
    Token, channel,
};
use crate::runner::{AgentOutcome, AgentRunner, Reporter, RunConfig};
use crate::workspace::Workspace;

const ERR_WORKSPACE: &str = "workspace could not be prepared";

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
        let mut prepare_stop = shutdown.clone();
        let prepared = tokio::select! {
            prepared = self.agent.keep_alive(
                &job,
                self.workspace.prepare(&job.job_id, &job.repo, &job.base_ref),
            ) => prepared,
            () = prepare_stop.requested() => {
                self.agent.fail_job(&job, "agent stopped by daemon shutdown").await;
                return Err(RunError);
            }
        };
        let Ok(checkout) = prepared else {
            tracing::warn!("job workspace could not be prepared");
            self.agent.fail_job(&job, ERR_WORKSPACE).await;
            return Err(RunError);
        };
        let result = self.execute(&job, &checkout.path, shutdown).await;
        if self.workspace.remove(&job.job_id, &job.repo).await.is_err() {
            tracing::warn!("job workspace could not be removed");
        }
        result
    }
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
    let runner = DaemonRunner::new(
        Workspace::new(PathBuf::from(&config.jobs_dir)),
        AgentRunner::new(run, reporter, redactor),
    );
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
    async fn a_slow_prepare_renews_the_lease_before_it_returns() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = dir.path().join("slow-git");
        std::fs::write(&git, "#!/bin/sh\nsleep 1\nexit 1\n")?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.report_interval = Duration::from_millis(100);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            Workspace::new(dir.path().join("jobs")).with_git(&git, Duration::from_secs(10)),
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
}
