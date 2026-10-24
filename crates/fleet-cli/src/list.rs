//! `fleet list`: boxes and recent jobs.

use std::io::Write;

use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_query_client::FleetQueryClient;
use fleet_proto::v1::{BoxStatus, BoxView, ListFleetRequest, ListJobsRequest};

use super::{CliError, Config, bearer, open_channel, or_dash, sanitize, state_name};

const RECENT_JOBS: u32 = 20;

fn box_state(view: &BoxView) -> &'static str {
    match BoxStatus::try_from(view.status) {
        Ok(BoxStatus::Live) => "LIVE",
        Ok(BoxStatus::Stale) => "STALE",
        Ok(BoxStatus::Lost) => "LOST",
        Ok(BoxStatus::Unknown) => "UNKNOWN",
        Ok(BoxStatus::Unspecified) | Err(_) => "UNSPECIFIED",
    }
}

fn last_seen(view: &BoxView) -> String {
    view.heartbeat_age_s
        .map_or_else(|| "never".into(), |s| format!("{s}s ago"))
}

fn text_or_dash(text: &str) -> String {
    if text.is_empty() {
        "-".into()
    } else {
        sanitize(text)
    }
}

/// Writes the boxes and the most recent jobs to `out`.
///
/// # Errors
/// Returns [`CliError`] on connection failure, a server error status or an output failure.
pub async fn list(config: &Config, out: &mut impl Write) -> Result<(), CliError> {
    let channel = open_channel(config).await?;
    let token = bearer(config)?;
    let mut query = FleetQueryClient::with_interceptor(channel.clone(), token.clone());
    let mut jobs = FleetJobsClient::with_interceptor(channel, token);
    let fleet = query
        .list_fleet(ListFleetRequest { r#box: None })
        .await?
        .into_inner();
    let recent = jobs
        .list_jobs(ListJobsRequest {
            state: None,
            limit: RECENT_JOBS,
        })
        .await?
        .into_inner();
    writeln!(out, "boxes:")?;
    for view in &fleet.boxes {
        writeln!(
            out,
            "{}\t{}\t{}",
            sanitize(&view.r#box),
            box_state(view),
            last_seen(view)
        )?;
    }
    writeln!(out, "jobs:")?;
    for job in &recent.jobs {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            sanitize(&job.job_id),
            state_name(job),
            text_or_dash(&job.r#box),
            or_dash(job.branch.as_ref()),
            or_dash(job.pr_url.as_ref())
        )?;
    }
    Ok(())
}
