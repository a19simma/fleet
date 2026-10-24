//! `fleet watch`: follow one job until it ends.

use std::io::Write;
use std::time::Duration;

use fleet_proto::v1::{GetJobRequest, Job, JobState};

use super::{CliError, Config, connect, or_dash, sanitize, state_name};

/// Delay between polls of `GetJob`.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

fn is_terminal(job: &Job) -> bool {
    matches!(
        JobState::try_from(job.state),
        Ok(JobState::Succeeded | JobState::Failed | JobState::Cancelled | JobState::Lost)
    )
}

fn snapshot(job: &Job) -> (i32, String, String) {
    (job.state, job.phase.clone(), job.progress.clone())
}

fn write_change(out: &mut impl Write, job: &Job) -> std::io::Result<()> {
    writeln!(
        out,
        "{}\t{}\t{}",
        state_name(job),
        sanitize(&job.phase),
        sanitize(&job.progress)
    )
}

/// Polls job `id` until it ends, printing each state, phase or progress change.
///
/// A state that is unspecified or unknown to this client is not terminal, so the poll goes
/// on until a terminal state. A transient RPC error ends the watch with that error.
///
/// # Errors
/// Returns [`CliError::JobEnded`] unless the job succeeded, and [`CliError`] on connection
/// failure, a server error status or an output failure.
pub async fn watch(config: &Config, id: &str, out: &mut impl Write) -> Result<(), CliError> {
    let mut client = connect(config).await?;
    let mut last = None;
    loop {
        let job = client
            .get_job(GetJobRequest {
                job_id: id.to_owned(),
            })
            .await?
            .into_inner();
        let current = snapshot(&job);
        if last.as_ref() != Some(&current) {
            write_change(out, &job)?;
            last = Some(current);
        }
        if is_terminal(&job) {
            writeln!(out, "pr_url: {}", or_dash(job.pr_url.as_ref()))?;
            writeln!(out, "error: {}", or_dash(job.error.as_ref()))?;
            return if matches!(JobState::try_from(job.state), Ok(JobState::Succeeded)) {
                Ok(())
            } else {
                Err(CliError::JobEnded(state_name(&job)))
            };
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
