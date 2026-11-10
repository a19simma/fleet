//! The job submit page (ADR-0067 decision 4): a form with an Environment select.
//!
//! Both routes need a session, and the POST also the session's CSRF token. The select lists
//! only the session user's Environments. One whose latest version holds a script is disabled
//! for a user without `env:scripts`. That is a courtesy: [`Store::submit_job_for`] checks the
//! grant again under a row lock, and the POST maps a refusal to a fixed notice. The idempotency
//! key is minted when the form renders and travels as a hidden field, so a double post stores
//! one job. Outcomes travel as fixed notice codes in the query string.

use std::collections::HashMap;

use fleet_core::EventId;
use fleet_proto::ENV_NONE;
use fleet_proto::v1::environment_entry_spec::Kind;
use fleet_proto::v1::{GetEnvironmentRequest, SubmitJobRequest};
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, forbidden, see_other},
        page,
        request::uri,
        route,
    },
    view::{View, view},
};

use super::catalog::pool;
use super::env::service;
use super::jobs::store;
use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail, signed_in};
use super::passkeys::AuthError;
use crate::cred::capability::{Capabilities, ENV_SCRIPTS};
use crate::store::StoreError;

pub(super) async fn holds_scripts(cx: &Cx, user_id: i64) -> Result<bool> {
    let pool = pool(cx)?;
    Capabilities::new(pool.clone())
        .has(user_id, ENV_SCRIPTS)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "capability read failed");
            fail(AuthError::Internal)
        })
}

fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "invalid" => "The job was refused: check the prompt, repository and base ref.",
        "env_missing" => "That environment was not found.",
        "env_empty" => "That environment has no version yet.",
        "env_scripts" => "That environment runs scripts and needs the env:scripts capability.",
        "conflict" => "That submission conflicts with an earlier one.",
        "failed" => "The request failed.",
        _ => return None,
    })
}

fn code_for(err: &StoreError) -> &'static str {
    match err {
        StoreError::InvalidJob(_) => "invalid",
        StoreError::UnknownEnvironment => "env_missing",
        StoreError::EnvironmentWithoutVersion => "env_empty",
        StoreError::EnvironmentScriptsNotGranted => "env_scripts",
        StoreError::KeyConflict => "conflict",
        _ => "failed",
    }
}

struct Choice {
    label: String,
    name: String,
    disabled: bool,
}

async fn choices(cx: &Cx, user_id: i64) -> Result<Vec<Choice>> {
    let Ok(service) = service(cx) else {
        return Ok(Vec::new());
    };
    let granted = holds_scripts(cx, user_id).await?;
    let listed = service.list(user_id).await.map_err(|status| {
        tracing::error!(code = ?status.code(), "environment list failed");
        fail(AuthError::Internal)
    })?;
    let mut out = Vec::new();
    for info in listed.environments {
        let detail = service
            .get(
                user_id,
                &GetEnvironmentRequest {
                    name: info.name.clone(),
                },
            )
            .await
            .map_err(|status| {
                tracing::error!(code = ?status.code(), "environment read failed");
                fail(AuthError::Internal)
            })?;
        let entries = detail.latest.map(|v| v.entries).unwrap_or_default();
        let scripts = entries
            .iter()
            .any(|entry| matches!(entry.kind, Some(Kind::Script(_))));
        let disabled = info.latest_version.is_none() || (scripts && !granted);
        let version = info
            .latest_version
            .map_or_else(|| "no version".to_owned(), |v| format!("v{v}"));
        let label = if info.latest_version.is_none() {
            format!("{} ({version}) - no version yet", info.name)
        } else if disabled {
            format!("{} ({version}) - needs env:scripts", info.name)
        } else {
            format!("{} ({version})", info.name)
        };
        out.push(Choice {
            label,
            name: info.name,
            disabled,
        });
    }
    Ok(out)
}

#[page("/submit")]
async fn submit_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let options = choices(cx, session.user_id).await?;
    let any_disabled = options.iter().any(|choice| choice.disabled);
    let none_owned = options.is_empty();
    let plain_hint = !any_disabled && !none_owned;
    let notice = uri(cx)
        .query()
        .and_then(|query| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix("notice="))
        })
        .and_then(notice_text);
    let key = EventId::generate().to_string();
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet submit", active: Nav::Jobs, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Submit a job"</h1>
                    <a class="link link-hover ml-auto" href="/jobs">"Jobs"</a>
                </header>
                if let Some(text) = notice {
                    <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
                }
                <form class="flex max-w-xl flex-col gap-2" method="post" action="/submit" autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <input type="hidden" name="key" value=(key.as_str())>
                    <fieldset class="fieldset">
                        <label class="label" for="job-prompt">"Prompt"</label>
                        <textarea class="textarea textarea-sm w-full" id="job-prompt" name="prompt" rows="6" required=""></textarea>
                    </fieldset>
                    <fieldset class="fieldset">
                        <label class="label" for="job-repo">"Repository URL"</label>
                        <input class="input input-sm w-full" id="job-repo" type="text" name="repo" placeholder="https://github.com/owner/name" required="">
                    </fieldset>
                    <fieldset class="fieldset">
                        <label class="label" for="job-base">"Base ref"</label>
                        <input class="input input-sm w-full" id="job-base" type="text" name="base_ref" value="main" required="">
                    </fieldset>
                    <fieldset class="fieldset">
                        <label class="label" for="job-environment">"Environment"</label>
                        <select class="select select-sm w-full" id="job-environment" name="environment" aria-describedby="job-environment-hint">
                            <option value="" selected="">"Default"</option>
                            <option value=(ENV_NONE)>"None"</option>
                            for choice in options {
                                if choice.disabled {
                                    <option value=(choice.name.as_str()) disabled="">(choice.label.as_str())</option>
                                } else {
                                    <option value=(choice.name.as_str())>(choice.label.as_str())</option>
                                }
                            }
                        </select>
                        if any_disabled {
                            <p id="job-environment-hint" class="label text-base-content/60">"Greyed environments run scripts and need the env:scripts capability, or have no version yet."</p>
                        }
                        if plain_hint {
                            <p id="job-environment-hint" class="label text-base-content/60">"An environment adds its secrets and scripts to the job."</p>
                        }
                        if none_owned {
                            <p id="job-environment-hint" class="label text-base-content/60"><a class="link link-hover" href="/environments">"Create an environment"</a></p>
                        }
                    </fieldset>
                    <label class="label flex items-center gap-2" for="job-pr">
                        <input class="checkbox checkbox-sm" id="job-pr" type="checkbox" name="open_pr" value="1">
                        "Open a pull request"
                    </label>
                    <div><button class="btn btn-sm btn-primary" type="submit">"Submit"</button></div>
                </form>
            )
    })
}

#[route(POST "/submit")]
async fn submit(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let request = SubmitJobRequest {
        idempotency_key: form.remove("key").unwrap_or_default(),
        prompt: form.remove("prompt").unwrap_or_default(),
        repo: form.remove("repo").unwrap_or_default(),
        base_ref: form.remove("base_ref").unwrap_or_default(),
        open_pr: form.remove("open_pr").is_some(),
        agent: String::new(),
        profile: String::new(),
        environment: form.remove("environment").unwrap_or_default(),
    };
    match store.submit_job_for(Some(session.user_id), &request).await {
        Ok(job) => Ok(see_other(format!("/jobs/{}", job.job_id))),
        Err(err) => {
            let code = code_for(&err);
            if code == "failed" {
                tracing::error!(error = %err, "web submit failed");
            }
            Ok(see_other(format!("/submit?notice={code}")))
        }
    }
}
