//! The environment pages (ADR-0067): list, create, inspect, set and delete secrets, delete.
//!
//! Every route needs a session and every POST also the session's CSRF token. Every read and
//! write goes through [`EnvironmentService`] with the session user's id, so a foreign name is
//! the same 404 as an unknown name, and a name outside the grammar is that 404 too. A secret
//! value is write-only: the form posts it to the service and no page, redirect or log line
//! carries it back. The page shows names, the fingerprint of each stored value and the latest
//! version structure. Outcomes travel as fixed notice codes in the query string.

use std::collections::HashMap;

use fleet_core::environment::EnvironmentName;
use fleet_proto::v1::environment_entry_spec::Kind;
use fleet_proto::v1::{
    CreateEnvironmentRequest, DeleteEnvironmentRequest, DeleteEnvironmentSecretRequest,
    EnvironmentDelivery, EnvironmentOnFail, GetEnvironmentRequest, PutEnvironmentSecretRequest,
};
use tonic::{Code, Status};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, forbidden, not_found, see_other},
        page, path_param,
        request::uri,
        route,
    },
    view::{View, component, view},
};

use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail, signed_in};
use super::passkeys::AuthError;
use crate::environments::EnvironmentService;

pub(super) struct EnvSlot(pub Option<EnvironmentService>);

path_param!(name);

pub(super) fn service(cx: &Cx) -> Result<&EnvironmentService> {
    app_context::<EnvSlot>(cx)
        .0
        .as_ref()
        .ok_or_else(|| not_found().into())
}

fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "created" => "Environment created.",
        "deleted" => "Environment deleted.",
        "secret_saved" => "Secret saved.",
        "secret_deleted" => "Secret deleted.",
        "invalid" => "Invalid name or value.",
        "exists" => "Environment already exists.",
        "limit" => "A limit was reached.",
        "missing" => "Not found.",
        "failed" => "The request failed.",
        _ => return None,
    })
}

fn notice_code(cx: &Cx) -> Option<&str> {
    uri(cx)
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix("notice="))
}

fn code_for(status: &Status) -> &'static str {
    match status.code() {
        Code::InvalidArgument => "invalid",
        Code::AlreadyExists => "exists",
        Code::ResourceExhausted => "limit",
        Code::NotFound => "missing",
        _ => "failed",
    }
}

fn internal(status: &Status) -> topcoat::Error {
    tracing::error!(code = ?status.code(), "environment page service call failed");
    fail(AuthError::Internal)
}

fn path_name(cx: &Cx) -> Result<EnvironmentName> {
    EnvironmentName::new(path_param::<Name>(cx)).map_err(|_| not_found().into())
}

fn back(code: &str) -> SeeOther {
    see_other(format!("/environments?notice={code}"))
}

fn back_to(name: &str, code: &str) -> SeeOther {
    see_other(format!("/environments/{name}?notice={code}"))
}

struct Gate<'a> {
    user_id: i64,
    service: &'a EnvironmentService,
}

async fn gate<'a>(cx: &'a Cx, form: &HashMap<String, String>) -> Result<Gate<'a>> {
    let auth = auth(cx)?;
    let service = service(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    Ok(Gate {
        user_id: session.user_id,
        service,
    })
}

struct ListRow {
    name: String,
    version: String,
    secrets: usize,
    scripts: bool,
}

#[page("/environments")]
async fn environments_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let service = service(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let listed = service
        .list(session.user_id)
        .await
        .map_err(|status| internal(&status))?;
    let mut rows = Vec::new();
    for info in listed.environments {
        let detail = service
            .get(
                session.user_id,
                &GetEnvironmentRequest {
                    name: info.name.clone(),
                },
            )
            .await
            .map_err(|status| internal(&status))?;
        let entries = detail.latest.map(|v| v.entries).unwrap_or_default();
        rows.push(ListRow {
            version: info
                .latest_version
                .map_or_else(|| "none".to_owned(), |v| format!("v{v}")),
            secrets: detail.secrets.len(),
            scripts: entries
                .iter()
                .any(|entry| matches!(entry.kind, Some(Kind::Script(_)))),
            name: info.name,
        });
    }
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    let empty = rows.is_empty();
    Ok(view! {
        shell(title: "fleet environments", active: Nav::Environments, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Environments"</h1>
                    <a class="link link-hover ml-auto" href="/submit">"Submit a job"</a>
                </header>
                if let Some(text) = notice {
                    <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
                }
                if empty {
                    <p class="border border-base-300 bg-base-200 p-2 text-xs">"No environments yet. Create one below."</p>
                } else {
                    <div class="overflow-x-auto">
                        <table class="table table-zebra table-xs">
                            <caption class="sr-only">"Your environments"</caption>
                            <thead>
                                <tr>
                                    <th>"Name"</th>
                                    <th>"Latest version"</th>
                                    <th>"Secrets"</th>
                                    <th>"Scripts"</th>
                                </tr>
                            </thead>
                            <tbody>
                                for row in rows {
                                    <tr>
                                        <td><a class="link link-primary" href=(format!("/environments/{}", row.name))>(row.name.as_str())</a></td>
                                        <td>(row.version)</td>
                                        <td>(row.secrets.to_string())</td>
                                        <td>
                                            if row.scripts {
                                                <span class="badge badge-sm badge-warning">"scripts"</span>
                                            } else {
                                                <span class="text-base-content/60">"none"</span>
                                            }
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                }
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Create an environment"</h2>
                <form class="mt-1 flex flex-wrap items-end gap-2" method="post" action="/environments/create" autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <fieldset class="fieldset">
                        <label class="label" for="env-name">"Name"</label>
                        <input class="input input-sm w-full sm:w-auto" id="env-name" type="text" name="name" required="" aria-describedby="env-name-hint">
                        <p id="env-name-hint" class="label text-base-content/60">"Start with a letter or digit, then letters, digits, dot, underscore or dash. Up to 64 bytes."</p>
                    </fieldset>
                    <button class="btn btn-sm btn-primary" type="submit">"Create"</button>
                </form>
            )
    })
}

#[route(POST "/environments/create")]
async fn create(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let gate = gate(cx, &form).await?;
    let request = CreateEnvironmentRequest {
        name: form.remove("name").unwrap_or_default(),
    };
    match gate.service.create(gate.user_id, &request).await {
        Ok(_) => Ok(back("created")),
        Err(status) => Ok(back(code_for(&status))),
    }
}

struct SecretRow {
    name: String,
    fingerprint: Option<String>,
    agent_visible: Option<bool>,
    delivery: &'static str,
}

struct ScriptRow {
    name: String,
    body: String,
    on_fail: &'static str,
    timeout: String,
}

fn delivery_text(value: i32) -> &'static str {
    match EnvironmentDelivery::try_from(value) {
        Ok(EnvironmentDelivery::Env) => "env",
        _ => "file",
    }
}

fn on_fail_text(value: i32) -> &'static str {
    match EnvironmentOnFail::try_from(value) {
        Ok(EnvironmentOnFail::Continue) => "continue",
        _ => "abort",
    }
}

#[component]
async fn secrets_table(
    rows: &[SecretRow],
    caption: &str,
    action: &str,
    csrf: &str,
) -> Result<impl View> {
    Ok(view! {
                    <div class="overflow-x-auto">
                        <table class="table table-zebra table-xs">
                            <caption class="sr-only">(caption)</caption>
                            <thead>
                                <tr>
                                    <th>"Name"</th>
                                    <th>"Fingerprint"</th>
                                    <th>"Agent-visible"</th>
                                    <th>"Delivery"</th>
                                    <th class="text-right">"Actions"</th>
                                </tr>
                            </thead>
                            <tbody>
                                for row in rows {
                                    <tr>
                                        <td>(row.name.as_str())</td>
                                        <td>
                                            if let Some(fp) = row.fingerprint.as_deref() {
                                                (fp)
                                            } else {
                                                <span class="badge badge-sm badge-ghost">"not set"</span>
                                            }
                                        </td>
                                        <td>
                                            if row.agent_visible == Some(true) {
                                                <span class="badge badge-sm badge-success">"yes"</span>
                                            }
                                            if row.agent_visible == Some(false) {
                                                <span class="badge badge-sm badge-warning">"no (setup only)"</span>
                                            }
                                            if row.agent_visible.is_none() {
                                                <span class="text-base-content/60">"not declared"</span>
                                            }
                                        </td>
                                        <td>(row.delivery)</td>
                                        <td class="whitespace-nowrap text-right">
                                            if row.fingerprint.is_some() {
                                                <form class="inline" method="post" action=(action)>
                                                    <input type="hidden" name="csrf" value=(csrf)>
                                                    <input type="hidden" name="name" value=(row.name.as_str())>
                                                    <button class="btn btn-xs btn-outline btn-error" type="submit" aria-label=(format!("Delete secret {}", row.name))>"Delete"</button>
                                                </form>
                                            }
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
    })
}

#[component]
async fn scripts_table(rows: &[ScriptRow], caption: &str) -> Result<impl View> {
    Ok(view! {
                        <div class="overflow-x-auto">
                            <table class="table table-zebra table-xs">
                                <caption class="sr-only">(caption)</caption>
                                <thead>
                                    <tr>
                                        <th>"Name"</th>
                                        <th>"On failure"</th>
                                        <th>"Timeout"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    for script in rows {
                                        <tr>
                                            <td>(script.name.as_str())</td>
                                            <td>(script.on_fail)</td>
                                            <td>(script.timeout.as_str())</td>
                                        </tr>
                                        <tr>
                                            <td colspan="3">
                                                <pre class="overflow-x-auto whitespace-pre bg-base-200 p-2 text-xs" tabindex="0" role="region" aria-label=(format!("Script body: {}", script.name))>(script.body.as_str())</pre>
                                            </td>
                                        </tr>
                                    }
                                </tbody>
                            </table>
                        </div>
    })
}

fn hidden_warning(hidden: &[String]) -> String {
    if hidden.len() == 1 {
        format!(
            "Warning: secret {} is not agent-visible. It reaches setup scripts only, and an environment whose secrets are all setup-only does nothing for the agent until you opt in.",
            hidden.join(", ")
        )
    } else {
        format!(
            "Warning: secrets {} are not agent-visible. They reach setup scripts only, and an environment whose secrets are all setup-only does nothing for the agent until you opt in.",
            hidden.join(", ")
        )
    }
}

#[component]
async fn secret_form(action: &str, csrf: &str) -> Result<impl View> {
    Ok(view! {
                <form class="mt-1 flex flex-wrap items-end gap-2" method="post" action=(action) autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf)>
                    <fieldset class="fieldset">
                        <label class="label" for="secret-name">"Name"</label>
                        <input class="input input-sm w-full sm:w-auto" id="secret-name" type="text" name="name" required="">
                    </fieldset>
                    <fieldset class="fieldset">
                        <label class="label" for="secret-value">"Value"</label>
                        <input class="input input-sm w-full sm:w-auto" id="secret-value" type="password" name="value" autocomplete="off" required="">
                    </fieldset>
                    <button class="btn btn-sm btn-primary" type="submit">"Save"</button>
                </form>
    })
}

#[component]
async fn delete_form(action: &str, label: &str, csrf: &str) -> Result<impl View> {
    Ok(view! {
                <form class="mt-1" method="post" action=(action)>
                    <input type="hidden" name="csrf" value=(csrf)>
                    <button class="btn btn-xs btn-outline btn-error" type="submit" aria-label=(label)>"Delete"</button>
                </form>
    })
}

#[component]
async fn hosts_list(hosts: &[String]) -> Result<impl View> {
    Ok(view! {
                    if hosts.is_empty() {
                        <p class="mb-2 text-xs text-base-content/60">"No egress hosts. Scripts get no network."</p>
                    } else {
                        <ul class="mb-2 text-xs">
                            for host in hosts {
                                <li>(host.as_str())</li>
                            }
                        </ul>
                    }
    })
}

struct Shaped {
    secrets: Vec<SecretRow>,
    scripts: Vec<ScriptRow>,
    hosts: Vec<String>,
    version_line: String,
}

fn shape(detail: fleet_proto::v1::EnvironmentDetail) -> Shaped {
    let mut secrets: Vec<SecretRow> = Vec::new();
    let mut scripts: Vec<ScriptRow> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut version_line = String::new();
    if let Some(latest) = detail.latest {
        version_line = format!(
            "Version {}, hash {}",
            latest.version,
            latest.hash.chars().take(8).collect::<String>()
        );
        hosts = latest.egress_hosts;
        for entry in latest.entries {
            match entry.kind {
                Some(Kind::Secret(spec)) => secrets.push(SecretRow {
                    fingerprint: detail
                        .secrets
                        .iter()
                        .find(|stored| stored.name == spec.name)
                        .map(|stored| stored.fingerprint.clone()),
                    name: spec.name,
                    agent_visible: Some(spec.agent_visible),
                    delivery: delivery_text(spec.delivery),
                }),
                Some(Kind::Script(spec)) => scripts.push(ScriptRow {
                    name: spec.name,
                    body: spec.body,
                    on_fail: on_fail_text(spec.on_fail),
                    timeout: spec
                        .timeout_s
                        .map_or_else(|| "default".to_owned(), |seconds| format!("{seconds} s")),
                }),
                None => {}
            }
        }
    }
    for stored in &detail.secrets {
        if !secrets.iter().any(|row| row.name == stored.name) {
            secrets.push(SecretRow {
                name: stored.name.clone(),
                fingerprint: Some(stored.fingerprint.clone()),
                agent_visible: None,
                delivery: "",
            });
        }
    }
    Shaped {
        secrets,
        scripts,
        hosts,
        version_line,
    }
}

#[page("/environments/{name}")]
async fn environment_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let service = service(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let name = path_name(cx)?;
    let detail = service
        .get(
            session.user_id,
            &GetEnvironmentRequest {
                name: name.as_str().to_owned(),
            },
        )
        .await
        .map_err(|status| match status.code() {
            Code::NotFound | Code::InvalidArgument => not_found().into(),
            _ => internal(&status),
        })?;
    let has_scripts_cap = super::submit::holds_scripts(cx, session.user_id).await?;
    let Shaped {
        secrets,
        scripts,
        hosts,
        version_line,
    } = shape(detail);
    let hidden: Vec<String> = secrets
        .iter()
        .filter(|row| row.agent_visible == Some(false))
        .map(|row| row.name.clone())
        .collect();
    let warn_hidden = !hidden.is_empty();
    let warn_text = hidden_warning(&hidden);
    let warn_scripts = !scripts.is_empty();
    let lacks_scripts = warn_scripts && !has_scripts_cap;
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    let shown = name.as_str().to_owned();
    let secrets_action = format!("/environments/{shown}/secrets/put");
    let delete_secret_action = format!("/environments/{shown}/secrets/delete");
    let delete_action = format!("/environments/{shown}/delete");
    let secrets_caption = format!("Secrets in environment {shown}");
    let scripts_caption = format!("Scripts in environment {shown}");
    let delete_label = format!("Delete environment {shown}");
    let no_secrets = secrets.is_empty();
    let has_version = !version_line.is_empty();
    Ok(view! {
        shell(title: "fleet environment", active: Nav::Environments, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">(shown.as_str())</h1>
                    <a class="link link-hover ml-auto" href="/environments">"All environments"</a>
                </header>
                if let Some(text) = notice {
                    <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
                }
                if warn_hidden {
                    <p role="status" class="mb-2 border border-warning bg-base-200 p-2 text-xs">(warn_text.as_str())</p>
                }
                if lacks_scripts {
                    <p role="alert" class="mb-2 border border-warning bg-base-200 p-2 text-xs">"You do not hold env:scripts, so jobs cannot use this environment."</p>
                }
                if warn_scripts {
                    <p role="status" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">"This version runs scripts before the agent starts, with your secrets. Using it needs the env:scripts capability."</p>
                }
                <h2 class="mb-1 mt-4 text-xs font-bold uppercase text-base-content/60">"Secrets"</h2>
                if no_secrets {
                    <p class="border border-base-300 bg-base-200 p-2 text-xs">"No secrets declared."</p>
                } else {
                    secrets_table(rows: secrets.as_slice(), caption: secrets_caption.as_str(), action: delete_secret_action.as_str(), csrf: csrf.as_str())
                }
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Set a secret"</h2>
                secret_form(action: secrets_action.as_str(), csrf: csrf.as_str())
                <p class="mt-1 text-xs text-base-content/60">"Write-only. Saving replaces the stored value and it cannot be read back. Only the fingerprint is shown."</p>
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Latest version"</h2>
                if has_version {
                    <p class="mb-2 text-xs">(version_line.as_str())</p>
                } else {
                    <p class="border border-base-300 bg-base-200 p-2 text-xs">"No version saved yet."</p>
                }
                if has_version {
                    <h3 class="mb-1 text-xs font-bold">"Egress hosts"</h3>
                    hosts_list(hosts: hosts.as_slice())
                    if warn_scripts {
                        <h3 class="mb-1 text-xs font-bold">"Scripts"</h3>
                        scripts_table(rows: scripts.as_slice(), caption: scripts_caption.as_str())
                    }
                }
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Delete environment"</h2>
                delete_form(action: delete_action.as_str(), label: delete_label.as_str(), csrf: csrf.as_str())
                <p class="mt-1 text-xs text-base-content/60">"Removes its secrets and versions."</p>
            )
    })
}

#[route(POST "/environments/{name}/secrets/put")]
async fn put_secret(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let gate = gate(cx, &form).await?;
    let name = path_name(cx)?;
    let request = PutEnvironmentSecretRequest {
        environment: name.as_str().to_owned(),
        name: form.remove("name").unwrap_or_default(),
        value: form.remove("value").unwrap_or_default(),
    };
    match gate.service.put_secret(gate.user_id, &request).await {
        Ok(_) => Ok(back_to(name.as_str(), "secret_saved")),
        Err(status) if status.code() == Code::NotFound => Err(not_found().into()),
        Err(status) => Ok(back_to(name.as_str(), code_for(&status))),
    }
}

#[route(POST "/environments/{name}/secrets/delete")]
async fn delete_secret(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let gate = gate(cx, &form).await?;
    let name = path_name(cx)?;
    let request = DeleteEnvironmentSecretRequest {
        environment: name.as_str().to_owned(),
        name: form.remove("name").unwrap_or_default(),
    };
    match gate.service.delete_secret(gate.user_id, &request).await {
        Ok(_) => Ok(back_to(name.as_str(), "secret_deleted")),
        Err(status) => Ok(back_to(name.as_str(), code_for(&status))),
    }
}

#[route(POST "/environments/{name}/delete")]
async fn delete(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let gate = gate(cx, &form).await?;
    let name = path_name(cx)?;
    let request = DeleteEnvironmentRequest {
        name: name.as_str().to_owned(),
    };
    match gate.service.delete(gate.user_id, &request).await {
        Ok(_) => Ok(back("deleted")),
        Err(status) if status.code() == Code::NotFound => Err(not_found().into()),
        Err(status) => Ok(back(code_for(&status))),
    }
}
