//! `fleet list`: boxes and recent jobs.

use std::io::Write;

use fleet_proto::v1::{BoxStatus, BoxView, Job, ListFleetRequest, ListJobsRequest};

use super::{CliError, Scrub, Session, state_name};

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

fn text_or_dash(scrub: &Scrub, text: &str) -> String {
    if text.is_empty() {
        "-".into()
    } else {
        scrub.ident(text)
    }
}

fn opt_or_dash(scrub: &Scrub, value: Option<&String>) -> String {
    value.map_or_else(|| "-".into(), |v| scrub.ident(v))
}

fn write_list(
    out: &mut impl Write,
    scrub: &Scrub,
    boxes: &[BoxView],
    jobs: &[Job],
) -> std::io::Result<()> {
    writeln!(out, "boxes:")?;
    for view in boxes {
        writeln!(
            out,
            "{}\t{}\t{}",
            scrub.ident(&view.r#box),
            box_state(view),
            last_seen(view)
        )?;
    }
    writeln!(out, "jobs:")?;
    for job in jobs {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            scrub.ident(&job.job_id),
            state_name(job),
            text_or_dash(scrub, &job.r#box),
            opt_or_dash(scrub, job.branch.as_ref()),
            opt_or_dash(scrub, job.pr_url.as_ref())
        )?;
    }
    Ok(())
}

/// Writes the boxes and the most recent jobs to `out`.
///
/// # Errors
/// Returns [`CliError`] on connection failure, a server error status or an output failure.
pub(crate) async fn list(session: &mut Session, out: &mut impl Write) -> Result<(), CliError> {
    let fleet = session
        .query
        .list_fleet(ListFleetRequest { r#box: None })
        .await?
        .into_inner();
    let recent = session
        .jobs
        .list_jobs(ListJobsRequest {
            state: None,
            limit: RECENT_JOBS,
        })
        .await?
        .into_inner();
    write_list(out, &session.scrub, &fleet.boxes, &recent.jobs)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "client-token-0123456789";

    fn laden() -> String {
        format!("v-{TOKEN}")
    }

    fn render(boxes: &[BoxView], jobs: &[Job]) -> String {
        let mut out = Vec::new();
        write_list(&mut out, &Scrub::new(Some(TOKEN)), boxes, jobs).expect("write to a Vec");
        String::from_utf8(out).expect("utf8")
    }

    fn job(set: impl FnOnce(&mut Job)) -> Job {
        let mut job = Job {
            job_id: "j".into(),
            r#box: "b".into(),
            ..Job::default()
        };
        set(&mut job);
        job
    }

    #[test]
    fn list_box_section_name_is_scrubbed_of_the_token() {
        let view = BoxView {
            r#box: laden(),
            ..BoxView::default()
        };
        let text = render(&[view], &[]);
        assert!(text.contains("\nv-[REDACTED]\t"), "{text}");
        assert!(!text.contains("client-token"), "{text}");
    }

    #[test]
    fn list_job_id_is_scrubbed_of_the_token() {
        let text = render(&[], &[job(|j| j.job_id = laden())]);
        assert!(text.contains("\nv-[REDACTED]\t"), "{text}");
        assert!(!text.contains("client-token"), "{text}");
    }

    #[test]
    fn list_job_box_is_scrubbed_of_the_token() {
        let text = render(&[], &[job(|j| j.r#box = laden())]);
        assert!(text.contains("\tv-[REDACTED]\t"), "{text}");
        assert!(!text.contains("client-token"), "{text}");
    }

    #[test]
    fn list_job_branch_is_scrubbed_of_the_token() {
        let text = render(&[], &[job(|j| j.branch = Some(laden()))]);
        assert!(text.contains("\tv-[REDACTED]\t-\n"), "{text}");
        assert!(!text.contains("client-token"), "{text}");
    }

    #[test]
    fn list_job_pr_url_userinfo_is_scrubbed_of_the_token() {
        let url = format!("https://{TOKEN}@host.example/x");
        let text = render(&[], &[job(|j| j.pr_url = Some(url))]);
        assert!(
            text.contains("\thttps://[REDACTED]@host.example/x\n"),
            "{text}"
        );
        assert!(!text.contains("client-token"), "{text}");
    }
}
