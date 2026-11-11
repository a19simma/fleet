//! The per-Box token page: issue, list and revoke the signed-in user's Box tokens.
//!
//! A new token is rendered in the response to the issuing POST and nowhere else. It never
//! enters a redirect URL, and later pages list only the Box, label and dates. Failures travel
//! as fixed notice codes in the query string. The Box name and label go through the same
//! validators the gRPC service uses.

use std::collections::HashMap;

use fleet_core::BoxName;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, forbidden, see_other},
        page, route,
    },
    view::{View, view},
};

use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail, signed_in};
use super::passkeys::{AuthError, SessionInfo};
use super::tokens::{Tokens, notice_code, tokens};
use crate::cred::UserError;
use crate::cred::users::{BoxTokenLabel, BoxTokenTtl};

const ENROLL_HINT: &str = "mise run tofu:enroll";

const LIST: &str = "\
SELECT id, box_name, label, \
to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), \
to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), \
to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), \
CASE WHEN revoked_at < expires_at THEN 'revoked' WHEN expires_at <= now() THEN 'expired' \
ELSE 'active' END FROM box_tokens WHERE user_id = $1 ORDER BY id DESC";

fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "revoked" => "Token revoked.",
        "invalid" => "The Box name, label or lifetime was refused.",
        "taken" => "An active token already holds that Box name.",
        "limit" => "Too many active Box tokens. Revoke one first.",
        "not_found" => "No such token.",
        _ => return None,
    })
}

fn back(code: &str) -> SeeOther {
    see_other(format!("/box-tokens?notice={code}"))
}

type Listed = (i64, String, String, String, String, Option<String>, String);

struct Row {
    id: String,
    box_name: String,
    label: String,
    created: String,
    expires: String,
    last_used: String,
    status: String,
}

async fn gate<'a>(cx: &'a Cx, form: &HashMap<String, String>) -> Result<(SessionInfo, &'a Tokens)> {
    let auth = auth(cx)?;
    let tokens = tokens(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    Ok((session, tokens))
}

#[page("/box-tokens")]
async fn box_tokens_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let tokens = tokens(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let listed: Vec<Listed> = sqlx::query_as(LIST)
        .bind(session.user_id)
        .fetch_all(&tokens.pool)
        .await
        .map_err(|_| fail(AuthError::Internal))?;
    let rows: Vec<Row> = listed
        .into_iter()
        .map(
            |(id, box_name, label, created, expires, last_used, status)| Row {
                id: id.to_string(),
                box_name,
                label,
                created,
                expires,
                last_used: last_used.unwrap_or_else(|| "never".to_owned()),
                status,
            },
        )
        .collect();
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet Box tokens", active: Nav::BoxTokens, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Box tokens"</h1>
                    <a class="link link-hover ml-auto" href="/tokens">"API tokens"</a>
                </header>
                if let Some(text) = notice {
                    <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
                }
                <p class="mb-2 text-xs text-base-content/60">"Enroll a Box from a shell with " <code>(ENROLL_HINT)</code></p>
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <thead>
                            <tr>
                                <th>"Box"</th>
                                <th>"Label"</th>
                                <th>"Created"</th>
                                <th>"Expires"</th>
                                <th>"Last used"</th>
                                <th>"Status"</th>
                                <th class="text-right">"Actions"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr>
                                    <td>(row.box_name)</td>
                                    <td>(row.label)</td>
                                    <td>(row.created)</td>
                                    <td>(row.expires)</td>
                                    <td>(row.last_used)</td>
                                    if row.status == "active" {
                                        <td><span class="badge badge-sm badge-success">"active"</span></td>
                                        <td class="text-right">
                                            <form method="post" action="/box-tokens/revoke">
                                                <input type="hidden" name="csrf" value=(csrf.as_str())>
                                                <input type="hidden" name="id" value=(row.id)>
                                                <button class="btn btn-xs btn-outline btn-error" type="submit">"Revoke"</button>
                                            </form>
                                        </td>
                                    } else {
                                        <td><span class="badge badge-sm badge-ghost">(row.status)</span></td>
                                        <td></td>
                                    }
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
                <h2 class="mb-1 mt-6 text-xs font-bold uppercase text-base-content/60">"Issue a token"</h2>
                <form class="mt-1 flex flex-wrap items-end gap-2" method="post" action="/box-tokens/issue" autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <fieldset class="fieldset">
                        <label class="label" for="box-name">"Box"</label>
                        <input class="input input-sm" id="box-name" name="box_name" required="" maxlength="63" autocomplete="off">
                    </fieldset>
                    <fieldset class="fieldset">
                        <label class="label" for="box-label">"Label"</label>
                        <input class="input input-sm" id="box-label" name="label" maxlength="64" autocomplete="off">
                    </fieldset>
                    <fieldset class="fieldset">
                        <label class="label" for="box-days">"Days"</label>
                        <input class="input input-sm" id="box-days" name="days" inputmode="numeric" maxlength="3" autocomplete="off">
                    </fieldset>
                    <button class="btn btn-sm btn-primary" type="submit">"Issue"</button>
                </form>
            )
    })
}

#[page(POST "/box-tokens/issue")]
async fn issue(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<impl View> {
    let (session, tokens) = gate(cx, &form).await?;
    let field = |key: &str| form.get(key).map_or("", |value| value.trim());
    let Ok(box_name) = field("box_name").parse::<BoxName>() else {
        return Err(back("invalid").into());
    };
    let Ok(label) = BoxTokenLabel::new(field("label")) else {
        return Err(back("invalid").into());
    };
    let ttl = match field("days") {
        "" => Ok(BoxTokenTtl::default()),
        text if text.bytes().all(|b| b.is_ascii_digit()) => text
            .parse::<u32>()
            .map_err(|_| UserError::InvalidTtl)
            .and_then(BoxTokenTtl::new),
        _ => Err(UserError::InvalidTtl),
    };
    let Ok(ttl) = ttl else {
        return Err(back("invalid").into());
    };
    let made = match tokens
        .users
        .issue_box_token(session.user_id, &box_name, &label, ttl)
        .await
    {
        Ok(made) => made,
        Err(UserError::BoxNameTaken) => return Err(back("taken").into()),
        Err(UserError::TooManyBoxTokens) => return Err(back("limit").into()),
        Err(_) => return Err(fail(AuthError::Internal)),
    };
    let token = String::from_utf8_lossy(made.token.expose()).into_owned();
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet Box token", active: Nav::BoxTokens, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Box token issued"</h1>
                    <a class="link link-hover ml-auto" href="/box-tokens">"Box tokens"</a>
                </header>
                <p class="mb-2 text-xs text-warning">"Copy it now. It is not shown again."</p>
                <pre id="token" class="overflow-auto border border-base-300 bg-base-300 p-2 text-xs">(token.as_str())</pre>
            )
    })
}

#[route(POST "/box-tokens/revoke")]
async fn revoke(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (session, tokens) = gate(cx, &form).await?;
    let Some(id) = form.get("id").and_then(|id| id.parse::<i64>().ok()) else {
        return Ok(back("not_found"));
    };
    match tokens.users.revoke_box_token(session.user_id, id).await {
        Ok(()) => Ok(back("revoked")),
        Err(UserError::NotFound) => Ok(back("not_found")),
        Err(_) => Err(fail(AuthError::Internal)),
    }
}
