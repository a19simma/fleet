//! The repositories page: add, list and remove through [`RepoService`].
//!
//! Every route needs a session, and every POST also the session's CSRF token. The page answers
//! 404 when the server runs without a repository registry. Outcomes travel as fixed notice codes
//! in the query string, so a redirect never echoes user input. Form bodies are capped by the
//! app-wide `BodyLimit` layer at [`super::MAX_BODY_BYTES`].
//!
//! Topcoat escapes text and attribute values alike: only an `Unescaped` value bypasses it. The
//! remove form still carries the row as lowercase hex, never as text. That is defence in depth,
//! and it keeps the key inert if a later edit bypasses the escape. Text cells go through
//! [`fleet_core::repo::ascii_form`], so a host is always in punycode form and a stray code point
//! is visible. The verified time is [`fleet_core::stamp::utc_stamp`], the text `fleet repo list`
//! prints.

use std::collections::HashMap;

use fleet_core::repo::ascii_form;
use fleet_proto::CredentialNotice;
use fleet_proto::v1::{AddRepoRequest, RemoveRepoRequest};
use tonic::Status;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, not_found, see_other},
        page,
        request::uri,
        route,
    },
    view::{View, view},
};

use super::credentials::{Backend, CredentialSlot};
use super::jobs::when;
use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail, signed_in};
use super::passkeys::AuthError;
use crate::cred::RepoService;

fn registry(cx: &Cx) -> Result<&RepoService> {
    app_context::<CredentialSlot>(cx)
        .0
        .as_deref()
        .and_then(|backend: &Backend| backend.service.repos())
        .ok_or_else(|| not_found().into())
}

fn notice_text(code: &str) -> Option<&'static str> {
    CredentialNotice::from_code(code).map(CredentialNotice::text)
}

fn notice_code(cx: &Cx) -> Option<&str> {
    uri(cx)
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix("notice="))
}

fn notice_for(status: &Status) -> &'static str {
    CredentialNotice::for_repo_status(status).code()
}

fn back(code: &str) -> SeeOther {
    see_other(format!("/repos?notice={code}"))
}

const MAX_PART_HEX: usize = 2 * 253;

fn to_hex(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    for byte in text.bytes() {
        out.extend(char::from_digit(u32::from(byte >> 4), 16));
        out.extend(char::from_digit(u32::from(byte & 15), 16));
    }
    out
}

fn from_hex(text: &str) -> Option<String> {
    if text.len() > MAX_PART_HEX {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let bytes: Option<Vec<u8>> = text
        .as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => Some((nibble(*high)? << 4) | nibble(*low)?),
            _ => None,
        })
        .collect();
    String::from_utf8(bytes?).ok()
}

struct Row {
    key: String,
    host: String,
    path: String,
    forge: String,
    runnable: &'static str,
    push: &'static str,
    verified: String,
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[page("/repos")]
async fn repos_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let repos = registry(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let rows: Vec<Row> = repos
        .list(session.user_id)
        .await
        .map_err(|_| fail(AuthError::Internal))?
        .repos
        .into_iter()
        .map(|info| Row {
            key: format!("{}-{}", to_hex(&info.host), to_hex(&info.path)),
            host: ascii_form(&info.host),
            path: ascii_form(&info.path),
            forge: ascii_form(&info.forge_kind),
            runnable: yes_no(info.runnable),
            push: info.push.map_or("unknown", yes_no),
            verified: when(info.verified_at_ms),
        })
        .collect();
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet repositories", active: Nav::Repos, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Repositories"</h1>
                    <a class="link link-hover ml-auto" href="/credentials">"Credentials"</a>
                </header>
                if let Some(text) = notice {
                    <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
                }
                <div class="overflow-x-auto">
                <table class="table table-zebra table-xs">
                    <thead>
                        <tr>
                            <th>"Host"</th>
                            <th>"Path"</th>
                            <th>"Forge"</th>
                            <th>"Runnable"</th>
                            <th>"Push"</th>
                            <th>"Verified"</th>
                            <th class="text-right">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr>
                                <td>(row.host.as_str())</td>
                                <td>(row.path.as_str())</td>
                                <td>(row.forge)</td>
                                <td>(row.runnable)</td>
                                <td>(row.push)</td>
                                <td>(row.verified)</td>
                                <td class="text-right">
                                    <form class="inline" method="post" action="/repos/remove">
                                        <input type="hidden" name="csrf" value=(csrf.as_str())>
                                        <input type="hidden" name="repo" value=(row.key.as_str())>
                                        <button class="btn btn-xs btn-outline btn-error" type="submit">"Remove"</button>
                                    </form>
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
                </div>
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Add a repository"</h2>
                <form class="mt-1 flex items-end gap-2" method="post" action="/repos/add" autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <fieldset class="fieldset">
                        <label class="label" for="repo-ref">"Repository"</label>
                        <input class="input input-sm" id="repo-ref" type="text" name="repo" placeholder="github.com/owner/name" required="">
                    </fieldset>
                    <button class="btn btn-sm btn-primary" type="submit">"Add"</button>
                </form>
            )
    })
}

async fn gate<'a>(cx: &'a Cx, form: &HashMap<String, String>) -> Result<(i64, &'a RepoService)> {
    let auth = auth(cx)?;
    let repos = registry(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(topcoat::router::error::forbidden().into());
    }
    Ok((session.user_id, repos))
}

#[route(POST "/repos/add")]
async fn add(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (user_id, repos) = gate(cx, &form).await?;
    let request = AddRepoRequest {
        repo: form.remove("repo").unwrap_or_default(),
    };
    match repos.add(user_id, &request).await {
        Ok(_) => Ok(back("saved")),
        Err(status) => Ok(back(notice_for(&status))),
    }
}

#[route(POST "/repos/remove")]
async fn remove(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (user_id, repos) = gate(cx, &form).await?;
    let Some((host, path)) = form.remove("repo").and_then(|key| {
        let (host, path) = key.split_once('-')?;
        Some((from_hex(host)?, from_hex(path)?))
    }) else {
        return Ok(back(CredentialNotice::RepoMissing.code()));
    };
    let request = RemoveRepoRequest { host, path };
    match repos.remove(user_id, &request).await {
        Ok(_) => Ok(back("deleted")),
        Err(status) => Ok(back(notice_for(&status))),
    }
}
