//! The credentials page: list, put, delete and verify through [`CredentialService`].
//!
//! Every route needs a session, and every POST also the session's CSRF token. The value is
//! write-only: it goes from the form into the service and no response carries it back.
//! Outcomes travel as fixed notice codes in the query string, so a redirect never echoes
//! user input.

use std::collections::HashMap;
use std::sync::Arc;

use fleet_core::credential::{CredentialError, CredentialKind};
use fleet_proto::v1::{DeleteCredentialRequest, PutCredentialRequest, VerifyCredentialRequest};
use sqlx::PgPool;
use tonic::{Code, Status};
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

use super::pages::{STYLE_PATH, auth, csrf_matches, current, fail, signed_in};
use super::passkeys::AuthError;
use crate::cred::CredentialService;

const STATIC_SECRET: &str = "static_secret";

const EXTRAS: &str = "\
SELECT c.id, \
to_char(c.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), \
to_char(max(u.used_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"') \
FROM credentials c LEFT JOIN credential_use u ON u.credential_id = c.id \
WHERE c.user_id = $1 GROUP BY c.id";

pub(super) struct CredentialSlot(pub Option<Arc<Backend>>);

pub(super) struct Backend {
    pub service: CredentialService,
    pub pool: PgPool,
}

fn credentials(cx: &Cx) -> Result<&Backend> {
    app_context::<CredentialSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "saved" => "Saved.",
        "deleted" => "Deleted.",
        "verified" => "GitHub accepted the stored token.",
        "invalid_token" => "GitHub refused the stored token.",
        "github_classic" => {
            "A GitHub credential must be a fine-grained token starting with github_pat_."
        }
        "github_refused" => "GitHub refused the token.",
        "invalid" => "The credential was refused. Check the kind and the value.",
        "unavailable" => "A backing service is unavailable. Try again later.",
        "not_found" => "No such credential.",
        "no_verifier" => "This kind cannot be verified.",
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

fn notice_for(status: &Status) -> &'static str {
    match status.code() {
        Code::InvalidArgument
            if status.message() == CredentialError::GithubNotFineGrained.to_string() =>
        {
            "github_classic"
        }
        Code::InvalidArgument if status.message() == "github rejected the token" => {
            "github_refused"
        }
        Code::InvalidArgument => "invalid",
        Code::Unavailable => "unavailable",
        Code::NotFound => "not_found",
        Code::FailedPrecondition => "no_verifier",
        _ => "failed",
    }
}

fn back(code: &str) -> SeeOther {
    see_other(format!("/credentials?notice={code}"))
}

struct Row {
    kind: &'static str,
    id: Option<i64>,
    fingerprint: String,
    login: String,
    expires: String,
    last_used: String,
}

async fn rows(web: &Backend, user_id: i64) -> Result<Vec<Row>> {
    let listed = web
        .service
        .list(user_id)
        .await
        .map_err(|_| fail(AuthError::Internal))?
        .credentials;
    let extras: Vec<(i64, Option<String>, Option<String>)> = sqlx::query_as(EXTRAS)
        .bind(user_id)
        .fetch_all(&web.pool)
        .await
        .map_err(|_| fail(AuthError::Internal))?;
    Ok(CredentialKind::ALL
        .into_iter()
        .map(|kind| {
            let found = listed.iter().find(|c| c.kind == kind.wire_name());
            let id = found.and_then(|c| i64::try_from(c.id).ok());
            let extra = extras.iter().find(|(row, ..)| Some(*row) == id);
            Row {
                kind: kind.wire_name(),
                id,
                fingerprint: found.map(|c| c.fingerprint.clone()).unwrap_or_default(),
                login: found.and_then(|c| c.login.clone()).unwrap_or_default(),
                expires: extra
                    .and_then(|(_, expires, _)| expires.clone())
                    .unwrap_or_default(),
                last_used: extra
                    .and_then(|(.., used)| used.clone())
                    .unwrap_or_default(),
            }
        })
        .collect())
}

#[page("/credentials")]
async fn credentials_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let web = credentials(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let rows = rows(web, session.user_id).await?;
    let notice = notice_code(cx).and_then(notice_text);
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet credentials"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>"Credentials"</h1>
                <p><a href="/account">"Account"</a></p>
                if let Some(text) = notice {
                    <p id="notice">(text)</p>
                }
                <table>
                    <thead>
                        <tr>
                            <th>"Kind"</th>
                            <th>"Status"</th>
                            <th>"Login"</th>
                            <th>"Fingerprint"</th>
                            <th>"Expires"</th>
                            <th>"Last used"</th>
                            <th>"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr data-kind=(row.kind)>
                                <td>(row.kind)</td>
                                if let Some(id) = row.id {
                                    <td>"stored"</td>
                                    <td>(row.login)</td>
                                    <td>(row.fingerprint)</td>
                                    <td>(if row.expires.is_empty() { "none".to_owned() } else { row.expires })</td>
                                    <td>(if row.last_used.is_empty() { "never".to_owned() } else { row.last_used })</td>
                                    <td>
                                        <form method="post" action="/credentials/delete">
                                            <input type="hidden" name="csrf" value=(csrf.as_str())>
                                            <input type="hidden" name="id" value=(id.to_string())>
                                            <button type="submit">"Delete"</button>
                                        </form>
                                        if row.kind == CredentialKind::GithubPat.wire_name() {
                                            <form method="post" action="/credentials/verify">
                                                <input type="hidden" name="csrf" value=(csrf.as_str())>
                                                <input type="hidden" name="id" value=(id.to_string())>
                                                <button type="submit">"Verify"</button>
                                            </form>
                                        }
                                    </td>
                                } else {
                                    <td>"not set"</td>
                                    <td></td>
                                    <td></td>
                                    <td></td>
                                    <td></td>
                                    <td></td>
                                }
                            </tr>
                        }
                    </tbody>
                </table>
                <h2>"Set a credential"</h2>
                <form method="post" action="/credentials/put" autocomplete="off">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <label>"Kind"
                        <select name="kind">
                            for kind in CredentialKind::ALL {
                                <option value=(kind.wire_name())>(kind.wire_name())</option>
                            }
                        </select>
                    </label>
                    <label>"Value"
                        <input type="password" name="value" autocomplete="off" required="">
                    </label>
                    <button type="submit">"Save"</button>
                </form>
            </body>
        </html>
    })
}

async fn gate<'a>(cx: &'a Cx, form: &HashMap<String, String>) -> Result<(i64, &'a Backend)> {
    let auth = auth(cx)?;
    let web = credentials(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(topcoat::router::error::forbidden().into());
    }
    Ok((session.user_id, web))
}

fn row_id(form: &HashMap<String, String>) -> Option<u64> {
    form.get("id")?.parse().ok()
}

#[route(POST "/credentials/put")]
async fn put(cx: &Cx, Form(mut form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (user_id, web) = gate(cx, &form).await?;
    let request = PutCredentialRequest {
        kind: form.remove("kind").unwrap_or_default(),
        shape: STATIC_SECRET.to_owned(),
        value: form.remove("value").unwrap_or_default(),
        expires_at_ms: None,
    };
    match web.service.put(user_id, request).await {
        Ok(_) => Ok(back("saved")),
        Err(status) => Ok(back(notice_for(&status))),
    }
}

#[route(POST "/credentials/delete")]
async fn delete(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (user_id, web) = gate(cx, &form).await?;
    let Some(id) = row_id(&form) else {
        return Ok(back("not_found"));
    };
    match web
        .service
        .delete(user_id, &DeleteCredentialRequest { id })
        .await
    {
        Ok(_) => Ok(back("deleted")),
        Err(status) => Ok(back(notice_for(&status))),
    }
}

#[route(POST "/credentials/verify")]
async fn verify(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let (user_id, web) = gate(cx, &form).await?;
    let Some(id) = row_id(&form) else {
        return Ok(back("not_found"));
    };
    match web
        .service
        .verify(user_id, &VerifyCredentialRequest { id })
        .await
    {
        Ok(reply) if reply.valid => Ok(back("verified")),
        Ok(_) => Ok(back("invalid_token")),
        Err(status) => Ok(back(notice_for(&status))),
    }
}
