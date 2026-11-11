//! The git remotes page: hosts, an add form, admin removal, pending private requests and the
//! registered repositories (ADR-0068).
//!
//! Every route needs a session, and every POST also the session's CSRF token. Add and list go
//! through the same [`HostService`] the `FleetHosts` RPCs use, so a refusal is the same fixed
//! [`CredentialNotice`] the CLI prints. Remove is admin-only and gated per request on the
//! database flag, never by hiding the button. Approve and revoke of a private host are admin-only
//! too, but a caller who is not an admin gets 404, as on the RPCs, and no service call happens.
//! The approve form names the addresses the pending request resolved to and posts them back, so
//! [`HostService::approve`] accepts only what the server resolves now. The pending requests and
//! the approved addresses of a host reach an admin only: [`HostService::list`] drops the
//! addresses for anyone else and the page leaves the column out. There is no deny button: a
//! pending request stays listed until an admin approves it. A host typed into a form goes through [`HostName::normalise`]
//! first, so a hostile value is refused with a fixed notice before any request and is never
//! echoed. Every server string is shown in [`ascii_form`]. The repository table is the one on
//! `/repos`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use fleet_core::host::HostName;
use fleet_core::repo::ascii_form;
use fleet_proto::v1::{
    AddHostRequest, ApproveHostPrivateRequest, RemoveHostRequest, RevokeHostPrivateRequest,
};
use fleet_proto::{CredentialNotice, MAX_HOST_APPROVED_IPS};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, forbidden, not_found, see_other},
        page,
        request::uri,
        route,
    },
    view::{View, component, view},
};

use super::catalog::admin_post_gate;
use super::jobs::when;
use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail, signed_in};
use super::passkeys::{AuthError, SessionInfo};
use super::repos::{Row as RepoRow, repo_rows, repo_table, repos_of};
use crate::hosts::HostService;

pub(super) struct HostSlot(pub Option<Arc<HostService>>);

fn service(cx: &Cx) -> Result<&HostService> {
    app_context::<HostSlot>(cx)
        .0
        .as_deref()
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

fn back(notice: CredentialNotice) -> SeeOther {
    see_other(format!("/hosts?notice={}", notice.code()))
}

struct HostLine {
    host: String,
    kind: String,
    private: &'static str,
    addresses: String,
    revoke: Option<String>,
}

struct RequestLine {
    host: String,
    user: String,
    resolved: String,
    requested: String,
    approve: Option<Approval>,
}

struct Approval {
    addresses: String,
    label: String,
}

#[component]
async fn host_table(csrf: &str, rows: &[HostLine], admin: bool) -> Result<impl View> {
    Ok(view! {
        <div class="overflow-x-auto">
        <table class="table table-zebra table-xs" id="hosts">
            <thead>
                <tr>
                    <th>"Host"</th>
                    <th>"Kind"</th>
                    <th>"Private"</th>
                    if admin {
                        <th>"Approved addresses"</th>
                        <th class="text-right">"Actions"</th>
                    }
                </tr>
            </thead>
            <tbody>
                for row in rows {
                    <tr data-host=(row.host.as_str())>
                        <td>(row.host.as_str())</td>
                        <td>(row.kind.as_str())</td>
                        <td>(row.private)</td>
                        if admin {
                            <td>(row.addresses.as_str())</td>
                            <td class="text-right">
                                <form class="inline" method="post" action="/hosts/remove">
                                    <input type="hidden" name="csrf" value=(csrf)>
                                    <input type="hidden" name="host" value=(row.host.as_str())>
                                    <button class="btn btn-xs btn-outline btn-error" type="submit">"Remove"</button>
                                </form>
                                if let Some(label) = &row.revoke {
                                    <form class="inline" method="post" action="/hosts/revoke">
                                        <input type="hidden" name="csrf" value=(csrf)>
                                        <input type="hidden" name="host" value=(row.host.as_str())>
                                        <button class="btn btn-xs btn-outline btn-warning" type="submit">"Revoke " (label.as_str())</button>
                                    </form>
                                }
                            </td>
                        }
                    </tr>
                }
            </tbody>
        </table>
        </div>
    })
}

#[component]
async fn request_table(csrf: &str, rows: &[RequestLine]) -> Result<impl View> {
    Ok(view! {
        <div class="overflow-x-auto">
        <table class="table table-zebra table-xs" id="host-requests">
            <thead>
                <tr>
                    <th>"Host"</th>
                    <th>"Requested by"</th>
                    <th>"Resolved addresses"</th>
                    <th>"Requested"</th>
                    <th class="text-right">"Actions"</th>
                </tr>
            </thead>
            <tbody>
                for row in rows {
                    <tr data-host=(row.host.as_str())>
                        <td>(row.host.as_str())</td>
                        <td>(row.user.as_str())</td>
                        <td>(row.resolved.as_str())</td>
                        <td>(row.requested.as_str())</td>
                        <td class="text-right">
                            if let Some(approval) = &row.approve {
                                <form class="inline" method="post" action="/hosts/approve">
                                    <input type="hidden" name="csrf" value=(csrf)>
                                    <input type="hidden" name="host" value=(row.host.as_str())>
                                    <input type="hidden" name="addresses" value=(approval.addresses.as_str())>
                                    <button class="btn btn-xs btn-outline btn-primary" type="submit">"Approve " (approval.label.as_str())</button>
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
async fn add_form(csrf: &str) -> Result<impl View> {
    Ok(view! {
        <form class="mt-1 flex items-end gap-2" method="post" action="/hosts/add" autocomplete="off">
            <input type="hidden" name="csrf" value=(csrf)>
            <fieldset class="fieldset">
                <label class="label" for="host-name">"Host"</label>
                <input class="input input-sm" id="host-name" type="text" name="host" placeholder="git.example.com" required="">
            </fieldset>
            <button class="btn btn-sm btn-primary" type="submit">"Add"</button>
        </form>
    })
}

fn join(items: &[String]) -> String {
    items
        .iter()
        .map(|item| ascii_form(item))
        .collect::<Vec<_>>()
        .join(", ")
}

fn approval(ips: &[String]) -> Option<Approval> {
    let parsed = ips
        .iter()
        .map(|ip| ip.parse::<IpAddr>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parsed.is_empty() {
        return None;
    }
    let texts: Vec<String> = parsed.iter().map(ToString::to_string).collect();
    Some(Approval {
        addresses: texts.join(","),
        label: texts.join(", "),
    })
}

async fn host_lines(svc: &HostService, admin: bool) -> Result<Vec<HostLine>> {
    Ok(svc
        .list(admin)
        .await
        .map_err(|_| fail(AuthError::Internal))?
        .hosts
        .into_iter()
        .map(|info| HostLine {
            host: ascii_form(&info.host),
            kind: ascii_form(&info.kind),
            private: if info.allow_private { "yes" } else { "no" },
            addresses: join(&info.approved_ips),
            revoke: info.allow_private.then(|| join(&info.approved_ips)),
        })
        .collect())
}

async fn request_lines(svc: &HostService) -> Result<Vec<RequestLine>> {
    Ok(svc
        .list_requests()
        .await
        .map_err(|_| fail(AuthError::Internal))?
        .requests
        .into_iter()
        .map(|info| RequestLine {
            host: ascii_form(&info.host),
            user: info.requested_by.to_string(),
            resolved: join(&info.resolved_ips),
            requested: when(info.requested_at_ms),
            approve: approval(&info.resolved_ips),
        })
        .collect())
}

#[page("/hosts")]
async fn hosts_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let svc = service(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let admin = auth.is_admin(session.user_id).await.map_err(fail)?;
    let hosts = host_lines(svc, admin).await?;
    let requests = if admin {
        request_lines(svc).await?
    } else {
        Vec::new()
    };
    let repos = repos_of(cx);
    let repo_lines: Vec<RepoRow> = match repos {
        Some(repos) => repo_rows(repos, session.user_id).await?,
        None => Vec::new(),
    };
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet git remotes", active: Nav::Hosts, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Git remotes"</h1>
                    <a class="link link-hover ml-auto" href="/credentials">"Credentials"</a>
                </header>
                if let Some(text) = notice {
                    <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
                }
                <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60">"Hosts"</h2>
                host_table(csrf: csrf.as_str(), rows: hosts.as_slice(), admin: admin)
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Add a host"</h2>
                add_form(csrf: csrf.as_str())
                if admin {
                    <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Pending private requests"</h2>
                    request_table(csrf: csrf.as_str(), rows: requests.as_slice())
                }
                if repos.is_some() {
                    <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Repositories"</h2>
                    repo_table(csrf: csrf.as_str(), rows: repo_lines.as_slice())
                }
            )
    })
}

fn host_field(form: &HashMap<String, String>) -> Option<HostName> {
    HostName::normalise(form.get("host").map_or("", String::as_str)).ok()
}

#[route(POST "/hosts/add")]
async fn add(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let auth = auth(cx)?;
    let svc = service(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let Some(host) = host_field(&form) else {
        return Ok(back(CredentialNotice::HostRefused));
    };
    let request = AddHostRequest {
        host: host.as_str().to_owned(),
    };
    match svc.add(session.user_id, &request).await {
        Ok(_) => Ok(back(CredentialNotice::HostAdded)),
        Err(status) => Ok(back(CredentialNotice::for_host_status(&status))),
    }
}

#[route(POST "/hosts/remove")]
async fn remove(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let svc = service(cx)?;
    let session = admin_post_gate(cx, &form).await?;
    let Some(host) = host_field(&form) else {
        return Ok(back(CredentialNotice::HostMissing));
    };
    let request = RemoveHostRequest {
        host: host.as_str().to_owned(),
    };
    match svc.remove(session.user_id, &request).await {
        Ok(_) => Ok(back(CredentialNotice::HostRemoved)),
        Err(status) => Ok(back(CredentialNotice::for_host_status(&status))),
    }
}

/// Longest accepted address list: [`MAX_HOST_APPROVED_IPS`] addresses of at most 45 characters
/// and the commas between them.
const ADDRESS_LIST_MAX: usize = MAX_HOST_APPROVED_IPS * 46;

fn address_field(form: &HashMap<String, String>) -> Option<Vec<IpAddr>> {
    let text = form.get("addresses")?;
    if text.len() > ADDRESS_LIST_MAX {
        return None;
    }
    let mut parsed = text
        .split(',')
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if parsed.len() > MAX_HOST_APPROVED_IPS {
        return None;
    }
    parsed.sort();
    parsed.dedup();
    Some(parsed)
}

/// Admin gate for the private-host posts: a caller who is not an admin gets 404, read from the
/// database on every request, then the CSRF token is checked.
async fn admin_or_missing(cx: &Cx, form: &HashMap<String, String>) -> Result<SessionInfo> {
    let auth = auth(cx)?;
    let session = signed_in(cx, auth).await?;
    if !auth.is_admin(session.user_id).await.map_err(fail)? {
        return Err(not_found().into());
    }
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    Ok(session)
}

#[route(POST "/hosts/approve")]
async fn approve(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let svc = service(cx)?;
    let session = admin_or_missing(cx, &form).await?;
    let Some(host) = host_field(&form) else {
        return Ok(back(CredentialNotice::HostMissing));
    };
    let Some(addresses) = address_field(&form) else {
        return Ok(back(CredentialNotice::HostInvalid));
    };
    let request = ApproveHostPrivateRequest {
        host: host.as_str().to_owned(),
        approved_ips: addresses.iter().map(ToString::to_string).collect(),
    };
    match svc.approve(session.user_id, &request).await {
        Ok(_) => Ok(back(CredentialNotice::HostApproved)),
        Err(status) => Ok(back(CredentialNotice::for_host_status(&status))),
    }
}

#[route(POST "/hosts/revoke")]
async fn revoke(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let svc = service(cx)?;
    let session = admin_or_missing(cx, &form).await?;
    let Some(host) = host_field(&form) else {
        return Ok(back(CredentialNotice::HostMissing));
    };
    let request = RevokeHostPrivateRequest {
        host: host.as_str().to_owned(),
    };
    match svc.revoke(session.user_id, &request).await {
        Ok(_) => Ok(back(CredentialNotice::HostRevoked)),
        Err(status) => Ok(back(CredentialNotice::for_host_status(&status))),
    }
}
