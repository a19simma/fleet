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

use super::layout::{Nav, shell};
use super::pages::{auth, current, fail};
use super::passkeys::AuthError;
use crate::store::{Store, StoreError};

/// The most transcript text a job page renders, in bytes.
pub const MAX_RENDER_BYTES: usize = 256 * 1024;

const LIST_LIMIT: u32 = 100;
const CHUNK_LIMIT: u32 = 100;

pub(super) struct ConsoleSlot(pub Option<Arc<Store>>);

path_param!(job_id);

fn store(cx: &Cx) -> Result<&Store> {
    app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

pub(super) fn when(ms: u64) -> String {
    fleet_core::stamp::utc_stamp(ms)
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

fn badge_class(state: &str) -> &'static str {
    match state {
        "JOB_STATE_RUNNING" => "badge badge-sm badge-warning",
        "JOB_STATE_SUCCEEDED" => "badge badge-sm badge-success",
        "JOB_STATE_FAILED" | "JOB_STATE_LOST" => "badge badge-sm badge-error",
        _ => "badge badge-sm badge-ghost",
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
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet jobs", active: Nav::Jobs, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Jobs"</h1>
                    <a class="link link-hover ml-auto" href="/account">"Account"</a>
                </header>
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
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
                                    <td><a class="link link-primary" href=(format!("/jobs/{}", row.id))>(row.id.as_str())</a></td>
                                    <td><span class=(badge_class(row.state))>(row.state)</span></td>
                                    <td>(row.repo)</td>
                                    <td>(row.created)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            )
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
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet job", active: Nav::Jobs, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">(job.job_id.as_str())</h1>
                    <a class="link link-hover ml-auto" id="timing-link" href=(format!("/jobs/{}/timing", job.job_id))>"Timing"</a>
                    <a class="link link-hover" href="/jobs">"Jobs"</a>
                </header>
                <div class="grid gap-3 lg:grid-cols-[22rem_1fr]">
                    <section class="flex flex-col gap-3">
                        <dl class="grid grid-cols-[6rem_1fr] gap-y-1 border border-base-300 p-2 text-xs">
                            <dt class="text-base-content/60">"State"</dt>
                            <dd><span class=(badge_class(state))>(state)</span></dd>
                            <dt class="text-base-content/60">"Repo"</dt><dd class="break-all">(job.repo.as_str())</dd>
                            <dt class="text-base-content/60">"Base ref"</dt><dd class="break-all">(job.base_ref.as_str())</dd>
                            <dt class="text-base-content/60">"Created"</dt><dd>(created)</dd>
                            <dt class="text-base-content/60">"Phase"</dt><dd>(job.phase.as_str())</dd>
                            <dt class="text-base-content/60">"Progress"</dt><dd>(job.progress.as_str())</dd>
                            <dt class="text-base-content/60">"Branch"</dt><dd class="break-all">(branch)</dd>
                            <dt class="text-base-content/60">"Error"</dt><dd class="text-error">(error)</dd>
                            <dt class="text-base-content/60">"Pull request"</dt>
                            <dd class="break-all">
                                if pr_link {
                                    <a class="link link-primary" href=(pr_url.as_str())>(pr_url.as_str())</a>
                                } else {
                                    (pr_url.as_str())
                                }
                            </dd>
                        </dl>
                        <h2 class="text-xs font-bold uppercase text-base-content/60">"Prompt"</h2>
                        <pre id="prompt" class="overflow-auto whitespace-pre-wrap border border-base-300 bg-base-200 p-2 text-xs">(job.prompt.as_str())</pre>
                    </section>
                    <section>
                        <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60">"Transcript"</h2>
                        <pre id="transcript" class="h-[70vh] overflow-auto border border-base-300 bg-base-300 p-2 text-xs">(transcript.text.as_str())</pre>
                        if transcript.cut {
                            <p id="cut" class="mt-1 text-xs text-warning">"transcript cut: the rest is not shown here."</p>
                        }
                    </section>
                </div>
            )
    })
}
