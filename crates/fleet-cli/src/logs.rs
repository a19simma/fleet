//! `fleet logs`: reads a job transcript, optionally following it to the end of the job.

use std::future::Future;
use std::io::Write;
use std::time::Duration;

use fleet_proto::v1::{GetJobRequest, ReadTranscriptRequest, TranscriptChunk};
use tokio::time::sleep;
use tonic::{Code, Response, Status};

use crate::{CliError, Client, Scrub, ScrubStream, require_success};

/// Wait between polls when a follow read returns no chunks.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Wait before retrying a call that failed with a transient status.
pub const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Attempts made for one call before a transient status is returned as the error.
pub const MAX_ATTEMPTS: u32 = 5;

const TRUNCATED_MARKER: &str = "-- transcript truncated --";

fn is_transient(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::Unavailable | Code::DeadlineExceeded | Code::Aborted
    )
}

/// Calls `call` until it succeeds, fails with a status that is not transient, or has failed
/// [`MAX_ATTEMPTS`] times in a row.
async fn with_retry<T, F, Fut>(mut call: F) -> Result<T, Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Response<T>, Status>>,
{
    let mut attempt = 1;
    loop {
        match call().await {
            Ok(reply) => return Ok(reply.into_inner()),
            Err(status) if is_transient(&status) && attempt < MAX_ATTEMPTS => {
                attempt += 1;
                sleep(RETRY_DELAY).await;
            }
            Err(status) => return Err(status),
        }
    }
}

fn write_text(out: &mut impl Write, text: &str) -> std::io::Result<()> {
    if !text.is_empty() {
        out.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            out.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Writes one chunk, adding a newline when its scrubbed text lacks one, then the truncation
/// marker when the chunk is flagged truncated. A text suffix that could start the token is
/// held for the next chunk, so a token split across chunks is redacted.
fn write_chunk(
    out: &mut impl Write,
    stream: &mut ScrubStream<'_>,
    chunk: &TranscriptChunk,
) -> std::io::Result<()> {
    write_text(out, &stream.push(&chunk.text))?;
    if chunk.truncated {
        write_text(out, &stream.finish_cut())?;
        writeln!(out, "{TRUNCATED_MARKER}")?;
    }
    Ok(())
}

/// Prints the transcript in `seq` order, retrying transient failures from the same
/// `after_seq`. Chunks at or below the highest `seq` printed in an
/// earlier page are skipped. Two chunks that share a `seq` inside one page both print.
pub(crate) async fn logs(
    client: &Client,
    scrub: &Scrub,
    id: String,
    follow: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut stream = scrub.stream();
    let read = pages(client, &mut stream, &id, follow, out).await;
    let tail = stream.finish();
    write_text(out, &tail)?;
    read?;
    if !follow {
        return Ok(());
    }
    let job = with_retry(|| {
        let mut client = client.clone();
        let request = GetJobRequest { job_id: id.clone() };
        async move { client.get_job(request).await }
    })
    .await?;
    require_success(&job)
}

async fn pages(
    client: &Client,
    stream: &mut ScrubStream<'_>,
    id: &str,
    follow: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut after_seq = 0;
    loop {
        let mut reply = with_retry(|| {
            let mut client = client.clone();
            let request = ReadTranscriptRequest {
                job_id: id.to_owned(),
                after_seq,
                limit: 0,
            };
            async move { client.read_transcript(request).await }
        })
        .await?;
        reply.chunks.sort_by_key(|c| c.seq);
        let mut printed = false;
        let floor = after_seq;
        for chunk in reply.chunks.iter().filter(|c| c.seq > floor) {
            write_chunk(out, stream, chunk)?;
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
    Ok(())
}
