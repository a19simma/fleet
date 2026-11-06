//! Admin capability page: show whether one user holds each capability and toggle each one.
//!
//! Both routes start with [`admin_gate`] or [`admin_post_gate`], which read `users.is_admin`
//! on that request, and the POST checks the session's CSRF token. The user id in the path must
//! be plain ASCII digits that parse as an `i64` before any SQL runs; anything else is the same
//! 404 as a missing user. The form names one capability and an action. The name must parse as
//! a [`Capability`] exactly, else the POST is a 400 and nothing is written. A write goes
//! through [`Capabilities`], which re-reads the acting admin under a row lock. Every stored
//! string is passed to the view as text, which escapes it.

use std::collections::HashMap;

use fleet_core::capability::Capability;
use fleet_proto::capability_from_wire;
use sqlx::{PgPool, Row as _};
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, bad_request, not_found, see_other},
        page, path_param, route,
    },
    view::{View, view},
};

use super::catalog::{admin_gate, admin_post_gate, internal, pool, refusal};
use super::layout::{Nav, shell};
use crate::cred::capability::Capabilities;

const USERNAME: &str = "SELECT username FROM users WHERE id = $1";
const GRANT: &str = "SELECT u.username, \
     to_char(c.granted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') \
     FROM user_capabilities c JOIN users u ON u.id = c.granted_by \
     WHERE c.user_id = $1 AND c.capability = $2";

path_param!(user_id);

struct Row {
    name: &'static str,
    held: Option<Held>,
}

struct Held {
    by: String,
    at: String,
}

fn user_path(cx: &Cx) -> Result<i64> {
    let raw = path_param::<UserId>(cx);
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(not_found().into());
    }
    raw.parse().map_err(|_| not_found().into())
}

async fn username(pool: &PgPool, id: i64) -> Result<String> {
    sqlx::query_scalar(USERNAME)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|err| internal(&err))?
        .ok_or_else(|| not_found().into())
}

async fn held(pool: &PgPool, id: i64, capability: Capability) -> Result<Option<Held>> {
    let row = sqlx::query(GRANT)
        .bind(id)
        .bind(capability.as_str())
        .fetch_optional(pool)
        .await
        .map_err(|err| internal(&err))?;
    row.map(|row| {
        Ok(Held {
            by: row.try_get(0).map_err(|err| internal(&err))?,
            at: row.try_get(1).map_err(|err| internal(&err))?,
        })
    })
    .transpose()
}

#[page("/users/{user_id}/capabilities")]
async fn capabilities_page(cx: &Cx) -> Result<impl View> {
    let session = admin_gate(cx).await?;
    let pool = pool(cx)?;
    let id = user_path(cx)?;
    let name = username(pool, id).await?;
    let mut rows = Vec::new();
    for capability in Capability::ALL {
        rows.push(Row {
            name: capability.as_str(),
            held: held(pool, id, *capability).await?,
        });
    }
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    let action = format!("/users/{id}/capabilities");
    Ok(view! {
        shell(title: "fleet capabilities", active: Nav::Catalog, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">(name.as_str())</h1>
                </header>
                <p class="mb-3 text-xs"><span class="text-base-content/60">"User id "</span>(id.to_string())</p>
                for row in rows {
                    <section class="mb-3 max-w-xl border border-base-300 p-2 text-xs">
                        <dl class="mb-2 grid grid-cols-[8rem_1fr] gap-y-1">
                            <dt class="text-base-content/60">(row.name)</dt>
                            <dd>
                                if row.held.is_some() {
                                    <span class="badge badge-sm badge-success">"granted"</span>
                                }
                                if row.held.is_none() {
                                    <span class="badge badge-sm badge-ghost">"not granted"</span>
                                }
                            </dd>
                            if let Some(grant) = row.held.as_ref() {
                                <dt class="text-base-content/60">"Granted by"</dt><dd>(grant.by.as_str())</dd>
                                <dt class="text-base-content/60">"Granted at"</dt><dd>(grant.at.as_str())" UTC"</dd>
                            }
                        </dl>
                        <form method="post" action=(action.as_str())>
                            <input type="hidden" name="csrf" value=(csrf.as_str())>
                            <input type="hidden" name="capability" value=(row.name)>
                            if row.held.is_some() {
                                <input type="hidden" name="action" value="revoke">
                                <button class="btn btn-outline btn-xs" type="submit">"Revoke "(row.name)</button>
                            }
                            if row.held.is_none() {
                                <input type="hidden" name="action" value="grant">
                                <button class="btn btn-primary btn-xs" type="submit">"Grant "(row.name)</button>
                            }
                        </form>
                    </section>
                }
            )
    })
}

#[route(POST "/users/{user_id}/capabilities")]
async fn capabilities_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let session = admin_post_gate(cx, &form).await?;
    let pool = pool(cx)?;
    let id = user_path(cx)?;
    username(pool, id).await?;
    let capability = form
        .get("capability")
        .and_then(|raw| capability_from_wire(raw))
        .ok_or_else(|| bad_request("the capability is unknown"))?;
    let caps = Capabilities::new(pool.clone());
    match form.get("action").map(String::as_str) {
        Some("grant") => caps
            .grant(session.user_id, id, capability.as_str())
            .await
            .map(drop),
        Some("revoke") => caps
            .revoke(session.user_id, id, capability.as_str())
            .await
            .map(drop),
        _ => return Err(bad_request("the capability action is unknown").into()),
    }
    .map_err(|err| refusal(&(&err).into()))?;
    Ok(see_other(format!("/users/{id}/capabilities")))
}
