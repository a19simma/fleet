//! The jobs pages: the signed-in user's job list and one job with its transcript.
//!
//! Reads go through the owner-scoped `*_for` store calls with the session's user id, so a
//! job of another user answers 404 exactly like an unknown id. Every stored string (prompt,
//! progress, error, transcript) is passed to the view as text, which escapes it, and the
//! transcript is cut at [`MAX_RENDER_BYTES`].

use std::sync::Arc;

use fleet_proto::v1::Job;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        error::{not_found, see_other},
        page, path_param,
    },
    view::{View, view},
};

use super::pages::{STYLE_PATH, auth, current, fail};
use super::passkeys::AuthError;
use crate::store::{Store, StoreError};

/// The most transcript text a job page renders, in bytes.
pub const MAX_RENDER_BYTES: usize = 256 * 1024;

const LIST_LIMIT: u32 = 100;
const CHUNK_LIMIT: u32 = 100;
const MS_PER_DAY: i64 = 86_400_000;

pub(super) struct ConsoleSlot(pub Option<Arc<Store>>);

path_param!(job_id);

fn store(cx: &Cx) -> Result<&Store> {
    app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn when(ms: u64) -> String {
    let ms = i64::try_from(ms).unwrap_or(i64::MAX);
    let (year, month, day) = civil(ms.div_euclid(MS_PER_DAY));
    let minutes = ms.rem_euclid(MS_PER_DAY) / 60_000;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minutes / 60,
        minutes % 60
    )
}

fn cut_at(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

struct Transcript {
    text: String,
    cut: bool,
}

fn assemble(chunks: &[String], more: bool) -> Transcript {
    let mut text = String::new();
    let mut cut = more;
    for chunk in chunks {
        let room = MAX_RENDER_BYTES - text.len();
        if chunk.len() > room {
            text.push_str(cut_at(chunk, room));
            cut = true;
            break;
        }
        text.push_str(chunk);
    }
    Transcript { text, cut }
}

struct Row {
    id: String,
    state: &'static str,
    repo: String,
    created: String,
}

fn row(job: &Job) -> Row {
    Row {
        id: job.job_id.clone(),
        state: job.state().as_str_name(),
        repo: job.repo.clone(),
        created: when(job.created_at_ms),
    }
}

fn internal(err: &StoreError) -> topcoat::Error {
    tracing::error!(error = %err, "jobs page store read failed");
    fail(AuthError::Internal)
}

#[page("/jobs")]
async fn jobs_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let jobs = store
        .list_jobs_for(Some(session.user_id), None, LIST_LIMIT)
        .await
        .map_err(|err| internal(&err))?;
    let rows: Vec<Row> = jobs.iter().map(row).collect();
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet jobs"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>"Jobs"</h1>
                <p><a href="/account">"Account"</a></p>
                <table>
                    <thead>
                        <tr>
                            <th>"Job"</th>
                            <th>"State"</th>
                            <th>"Repo"</th>
                            <th>"Created"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr>
                                <td><a href=(format!("/jobs/{}", row.id))>(row.id.as_str())</a></td>
                                <td>(row.state)</td>
                                <td>(row.repo)</td>
                                <td>(row.created)</td>
                            </tr>
                        }
                    </tbody>
                </table>
            </body>
        </html>
    })
}

#[page("/jobs/{job_id}")]
async fn job_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let id = path_param::<JobId>(cx);
    let owner = Some(session.user_id);
    let job = match store.get_job_with_summary_for(owner, id).await {
        Ok(job) => job,
        Err(StoreError::NotFound | StoreError::InvalidJob(_)) => return Err(not_found().into()),
        Err(err) => return Err(internal(&err)),
    };
    let reply = store
        .read_transcript_for(owner, id, 0, CHUNK_LIMIT)
        .await
        .map_err(|err| internal(&err))?;
    let more = !reply.done && reply.chunks.len() >= CHUNK_LIMIT as usize;
    let texts: Vec<String> = reply.chunks.into_iter().map(|c| c.text).collect();
    let transcript = assemble(&texts, more);
    let state = job.state().as_str_name();
    let created = when(job.created_at_ms);
    let branch = job.branch.clone().unwrap_or_default();
    let error = job.error.clone().unwrap_or_default();
    let pr_url = job.pr_url.clone().unwrap_or_default();
    let pr_link = pr_url.starts_with("https://");
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet job"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>(job.job_id.as_str())</h1>
                <p><a href="/jobs">"Jobs"</a></p>
                <dl>
                    <dt>"State"</dt><dd>(state)</dd>
                    <dt>"Repo"</dt><dd>(job.repo.as_str())</dd>
                    <dt>"Base ref"</dt><dd>(job.base_ref.as_str())</dd>
                    <dt>"Created"</dt><dd>(created)</dd>
                    <dt>"Phase"</dt><dd>(job.phase.as_str())</dd>
                    <dt>"Progress"</dt><dd>(job.progress.as_str())</dd>
                    <dt>"Branch"</dt><dd>(branch)</dd>
                    <dt>"Error"</dt><dd>(error)</dd>
                    <dt>"Pull request"</dt>
                    <dd>
                        if pr_link {
                            <a href=(pr_url.as_str())>(pr_url.as_str())</a>
                        } else {
                            (pr_url.as_str())
                        }
                    </dd>
                </dl>
                <h2>"Prompt"</h2>
                <pre id="prompt">(job.prompt.as_str())</pre>
                <h2>"Transcript"</h2>
                <pre id="transcript">(transcript.text.as_str())</pre>
                if transcript.cut {
                    <p id="cut">"transcript cut: the rest is not shown here."</p>
                }
            </body>
        </html>
    })
}
