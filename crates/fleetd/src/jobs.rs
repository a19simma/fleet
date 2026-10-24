//! The daemon's job path: claim, prepare a worktree, run the agent, publish the result.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::path::PathBuf;

use fleet_core::Redactor;
use fleet_proto::v1::Job;
use tonic::transport::Channel;

use crate::Error;
use crate::config::Config;
use crate::poller::{
    GrpcReporter, JobRunner, PollRandom, Poller, RunError, SERVER_URL_ENV, Shutdown, TOKEN_ENV,
    Token, channel,
};
use crate::runner::{AgentOutcome, AgentRunner, RunConfig};
use crate::workspace::Workspace;

const ERR_WORKSPACE: &str = "workspace could not be prepared";

/// The poller the daemon runs.
pub(crate) type JobPoller = Poller<DaemonRunner>;

/// Runs one claimed job from checkout to terminal report.
pub(crate) struct DaemonRunner {
    workspace: Workspace,
    agent: AgentRunner<GrpcReporter>,
}

impl JobRunner for DaemonRunner {
    async fn run(&self, job: Job, shutdown: Shutdown) -> Result<(), RunError> {
        let mut prepare_stop = shutdown.clone();
        let prepared = tokio::select! {
            prepared = self.workspace.prepare(&job.job_id, &job.repo, &job.base_ref) => prepared,
            () = prepare_stop.requested() => {
                self.agent.fail_job(&job, "agent stopped by daemon shutdown").await;
                return Err(RunError);
            }
        };
        let Ok(checkout) = prepared else {
            tracing::warn!("job workspace could not be prepared");
            self.agent.fail_job(&job, ERR_WORKSPACE).await;
            return Ok(());
        };
        let outcome = self
            .agent
            .run(&job, &checkout.path, shutdown.clone())
            .await?;
        if matches!(outcome, AgentOutcome::Succeeded) {
            self.agent.finish(&job, &checkout.path, shutdown).await?;
        } else {
            tracing::info!(outcome = ?outcome, "job ended without a publish step");
        }
        Ok(())
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
    let runner = DaemonRunner {
        workspace: Workspace::new(PathBuf::from(&config.jobs_dir)),
        agent: AgentRunner::new(run, reporter, redactor),
    };
    Poller::with_channel(
        channel,
        &token,
        box_name.to_owned(),
        runner,
        PollRandom::system(),
    )
    .map(Some)
}
