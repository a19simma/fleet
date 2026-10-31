//! The API token page: create, list and revoke the signed-in user's bearer tokens.
//!
//! A new token is rendered in the response to the creating POST and nowhere else. It never
//! enters a redirect URL, and later pages list only the label and dates. Failures travel as
//! fixed notice codes in the query string.

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;
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
    view::{View, view},
};

use super::pages::{STYLE_PATH, auth, csrf_matches, current, fail, signed_in};
use super::passkeys::AuthError;
use crate::cred::{UserError, Users};

const MAX_LABEL_CHARS: usize = 64;

const LIST: &str = "\
SELECT id, label, \
to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), \
revoked_at IS NOT NULL FROM api_tokens WHERE user_id = $1 ORDER BY id DESC";

pub(super) struct TokenSlot(pub Option<Arc<Tokens>>);

pub(super) struct Tokens {
    pub users: Users,
    pub pool: PgPool,
}

fn tokens(cx: &Cx) -> Result<&Tokens> {
    app_context::<TokenSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "revoked" => "Token revoked.",
        "invalid" => "The label must be at most 64 characters with no control characters.",
        "not_found" => "No such token.",
        _ => return None,
    })
}

fn notice_code(cx: &Cx) -> Option<&str> {
    uri(cx)
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix("notice="))
}

fn back(code: &str) -> SeeOther {
    see_other(format!("/tokens?notice={code}"))
}

struct Row {
    id: String,
    label: String,
    created: String,
    revoked: bool,
}

fn label_ok(label: &str) -> bool {
    label.chars().count() <= MAX_LABEL_CHARS && !label.chars().any(char::is_control)
}

async fn gate<'a>(cx: &'a Cx, form: &HashMap<String, String>) -> Result<(i64, &'a Tokens)> {
    let auth = auth(cx)?;
    let tokens = tokens(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    Ok((session.user_id, tokens))
}

#[page("/tokens")]
async fn tokens_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let tokens = tokens(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let listed: Vec<(i64, String, Option<String>, bool)> = sqlx::query_as(LIST)
        .bind(session.user_id)
        .fetch_all(&tokens.pool)
        .await
        .map_err(|_| fail(AuthError::Internal))?;
    let rows: Vec<Row> = listed
        .into_iter()
        .map(|(id, label, created, revoked)| Row {
            id: id.to_string(),
            label,
            created: created.unwrap_or_default(),
            revoked,
        })
        .collect();
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet API tokens"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>"API tokens"</h1>
                <p><a href="/account">"Account"</a></p>
                if let Some(text) = notice {
                    <p id="notice">(text)</p>
                }
                <table>
                    <thead>
                        <tr>
                            <th>"Label"</th>
                            <th>"Created"</th>
                            <th>"Status"</th>
                            <th>"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr>
                                <td>(row.label)</td>
                                <td>(row.created)</td>
                                if row.revoked {
                                    <td>"revoked"</td>
                                    <td></td>
                                } else {
                                    <td>"active"</td>
                                    <td>
                                        <form method="post" action="/tokens/revoke">
                                            <input type="hidden" name="csrf" value=(csrf.as_str())>
                                            <input type="hidden" name="id" value=(row.id)>
                                            <button type="submit">"Revoke"</button>
                                        </form>
                                    </td>
                                }
                            </tr>
                        }
                    </tbody>
                </table>
                <h2>"Create a token"</h2>
                <form method="post" action="/tokens/create" autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <label>"Label"
                        <input name="label" maxlength="64" autocomplete="off">
                    </label>
                    <button type="submit">"Create"</button>
                </form>
            </body>
        </html>
    })
}

#[page(POST "/tokens/create")]
async fn create(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<impl View> {
    let (user_id, tokens) = gate(cx, &form).await?;
    let label = form.get("label").map_or("", |label| label.trim());
    if !label_ok(label) {
        return Err(back("invalid").into());
    }
    let made = tokens
        .users
        .create_api_token(user_id, label)
        .await
        .map_err(|_| fail(AuthError::Internal))?;
    let token = String::from_utf8_lossy(made.token.expose()).into_owned();
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet API token"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>"API token created"</h1>
                <p>"Copy it now. It is not shown again."</p>
                <pre id="token">(token.as_str())</pre>
                <p><a href="/tokens">"API tokens"</a></p>
            </body>
        </html>
    })
}

#[route(POST "/tokens/revoke")]
async fn revoke(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (user_id, tokens) = gate(cx, &form).await?;
    let Some(id) = form.get("id").and_then(|id| id.parse::<i64>().ok()) else {
        return Ok(back("not_found"));
    };
    match tokens.users.revoke_api_token(user_id, id).await {
        Ok(()) => Ok(back("revoked")),
        Err(UserError::NotFound) => Ok(back("not_found")),
        Err(_) => Err(fail(AuthError::Internal)),
    }
}
