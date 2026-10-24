//! `fleet logs`: reads a job transcript, optionally following it to the end of the job.

use std::io::Write;
use std::time::Duration;

use fleet_proto::v1::{GetJobRequest, JobState, ReadTranscriptRequest, TranscriptChunk};
use tokio::time::sleep;

use crate::{CliError, Client, state_name};

/// Wait between polls when a follow read returns no chunks.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

const TRUNCATED_MARKER: &str = "-- transcript truncated --";

/// Drops control characters except newline and tab. Bidirectional override characters are
/// not control characters and pass through.
fn strip_controls(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

/// Writes one chunk, adding a newline when its text lacks one, then the truncation marker
/// when the chunk is flagged truncated.
fn write_chunk(out: &mut impl Write, chunk: &TranscriptChunk) -> std::io::Result<()> {
    let text = strip_controls(&chunk.text);
    if !text.is_empty() {
        out.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            out.write_all(b"\n")?;
        }
    }
    if chunk.truncated {
        writeln!(out, "{TRUNCATED_MARKER}")?;
    }
    Ok(())
}

/// Prints the transcript in `seq` order. Chunks at or below the highest `seq` printed in an
/// earlier page are skipped. Two chunks that share a `seq` inside one page both print.
pub(crate) async fn logs(
    client: &mut Client,
    id: String,
    follow: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut after_seq = 0;
    loop {
        let mut reply = client
            .read_transcript(ReadTranscriptRequest {
                job_id: id.clone(),
                after_seq,
                limit: 0,
            })
            .await?
            .into_inner();
        reply.chunks.sort_by_key(|c| c.seq);
        let mut printed = false;
        let floor = after_seq;
        for chunk in reply.chunks.iter().filter(|c| c.seq > floor) {
            write_chunk(out, chunk)?;
            after_seq = chunk.seq;
            printed = true;
        }
        out.flush()?;
        if reply.done {
            break;
        }
        if !printed {
            if !follow {
                return Ok(());
            }
            sleep(POLL_INTERVAL).await;
        }
    }
    if !follow {
        return Ok(());
    }
    let job = client
        .get_job(GetJobRequest { job_id: id })
        .await?
        .into_inner();
    if JobState::try_from(job.state) == Ok(JobState::Succeeded) {
        Ok(())
    } else {
        Err(CliError::JobEnded(state_name(&job)))
    }
}
