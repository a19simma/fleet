//! Admin catalog pages and the `admin_gate` every admin page starts with.
//!
//! Every route, GET and POST, starts with [`admin_gate`], which reads `users.is_admin` on that
//! request, and every POST then checks the session's CSRF token. A write goes through
//! [`crate::catalog::upsert_item`] or [`crate::catalog::set_enabled`], so the store layer
//! validates the item and takes the actor-row lock. The edit form can change content only: the
//! kind, name and id of an item are fixed at creation. Every stored string is passed to the
//! view as text, which escapes it.

use std::collections::HashMap;

use fleet_core::catalog::validate_id;
use fleet_proto::v1::{CatalogKind, SetCatalogItemEnabledRequest, UpsertCatalogItemRequest};
use sqlx::{PgPool, Row as _};
use tonic::{Code, Status};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, bad_request, forbidden, not_found, see_other},
        page, path_param,
        request::uri,
        route,
    },
    view::{View, view},
};

use super::jobs::ConsoleSlot;
use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail};
use super::passkeys::{AuthError, SessionInfo};
use crate::catalog;

/// Resolves the session and reads `is_admin` from the database on this request.
///
/// No session redirects to `/login`. A signed-in non-admin gets 403. The flag is never
/// cached on the session, so a demoted admin loses access on the next request.
pub(super) async fn admin_gate(cx: &Cx) -> Result<SessionInfo> {
    let auth = auth(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    if !auth.is_admin(session.user_id).await.map_err(fail)? {
        return Err(forbidden().into());
    }
    Ok(session)
}

/// [`admin_gate`] plus the session's CSRF token from the form, for every admin POST.
pub(super) async fn admin_post_gate(
    cx: &Cx,
    form: &HashMap<String, String>,
) -> Result<SessionInfo> {
    let session = admin_gate(cx).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    Ok(session)
}

const PAGE: i64 = 500;

const LIST: &str = "SELECT id, kind, name, admin_enabled FROM catalog_items \
     WHERE id > $1 ORDER BY id LIMIT $2";
const DETAIL: &str = "SELECT id, kind, name, content, admin_enabled FROM catalog_items \
     WHERE id = $1";

const KINDS: [(&str, CatalogKind); 4] = [
    ("skill", CatalogKind::Skill),
    ("subagent", CatalogKind::Subagent),
    ("tool", CatalogKind::Tool),
    ("context", CatalogKind::Context),
];

path_param!(item_id);

struct Entry {
    id: String,
    kind: String,
    name: String,
    content: String,
    enabled: bool,
}

fn pool(cx: &Cx) -> Result<&PgPool> {
    app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .map(crate::store::Store::pool)
        .ok_or_else(|| not_found().into())
}

fn internal(err: &dyn std::fmt::Display) -> topcoat::Error {
    tracing::error!(error = %err, "catalog page store call failed");
    fail(AuthError::Internal)
}

fn refusal(status: &Status) -> topcoat::Error {
    match status.code() {
        Code::PermissionDenied => forbidden().into(),
        Code::NotFound => not_found().into(),
        Code::InvalidArgument | Code::FailedPrecondition | Code::AlreadyExists => {
            bad_request(status.message().to_owned()).into()
        }
        _ => internal(&status.message()),
    }
}

fn kind_of(name: &str) -> Result<CatalogKind> {
    KINDS
        .iter()
        .find(|(word, _)| *word == name)
        .map(|(_, kind)| *kind)
        .ok_or_else(|| bad_request("the catalog item kind is unknown").into())
}

fn item_path(cx: &Cx) -> Result<String> {
    let raw = path_param::<ItemId>(cx);
    validate_id(raw)
        .map(|id| id.as_str().to_owned())
        .map_err(|_| not_found().into())
}

fn entry(row: &sqlx::postgres::PgRow, with_content: bool) -> Result<Entry, sqlx::Error> {
    Ok(Entry {
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        content: if with_content {
            row.try_get("content")?
        } else {
            String::new()
        },
        enabled: row.try_get("admin_enabled")?,
    })
}

fn badge_class(enabled: bool) -> &'static str {
    if enabled {
        "badge badge-sm badge-success"
    } else {
        "badge badge-sm badge-ghost"
    }
}

fn state_word(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

fn field<'a>(form: &'a HashMap<String, String>, key: &str) -> &'a str {
    form.get(key).map_or("", String::as_str)
}

fn after_cursor(cx: &Cx) -> Result<String> {
    let after = uri(cx)
        .query()
        .and_then(|query| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix("after="))
        })
        .unwrap_or_default();
    catalog::validate_after_id(after).map_err(|status| refusal(&status))?;
    Ok(after.to_owned())
}

/// Reads one page of at most `limit` items with an id above `after`, in id order, the cursor
/// order of the store's list. The second value is the id to pass as `after` for the next page,
/// set only when more items exist past this one.
async fn list_page(
    pool: &PgPool,
    after: &str,
    limit: i64,
) -> Result<(Vec<Entry>, Option<String>), sqlx::Error> {
    let rows = sqlx::query(LIST)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(pool)
        .await?;
    let mut entries = rows
        .iter()
        .map(|row| entry(row, false))
        .collect::<Result<Vec<_>, _>>()?;
    let more = i64::try_from(entries.len()).is_ok_and(|len| len > limit);
    if more {
        entries.truncate(usize::try_from(limit).unwrap_or(0));
    }
    let next = more
        .then(|| entries.last().map(|last| last.id.clone()))
        .flatten();
    Ok((entries, next))
}

#[page("/catalog")]
async fn catalog_page(cx: &Cx) -> Result<impl View> {
    let session = admin_gate(cx).await?;
    let pool = pool(cx)?;
    let after = after_cursor(cx)?;
    let (entries, next) = list_page(pool, &after, PAGE)
        .await
        .map_err(|err| internal(&err))?;
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet catalog", active: Nav::Account, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Catalog"</h1>
                </header>
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <thead>
                            <tr>
                                <th>"Id"</th>
                                <th>"Kind"</th>
                                <th>"Name"</th>
                                <th>"State"</th>
                                <th>"Action"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for entry in entries {
                                <tr>
                                    <td><a class="link link-primary" href=(format!("/catalog/{}", entry.id))>(entry.id.as_str())</a></td>
                                    <td>(entry.kind.as_str())</td>
                                    <td>(entry.name.as_str())</td>
                                    <td><span class=(badge_class(entry.enabled))>(state_word(entry.enabled))</span></td>
                                    <td>
                                        <form method="post" action=(format!("/catalog/{}/{}", entry.id, if entry.enabled { "disable" } else { "enable" }))>
                                            <input type="hidden" name="csrf" value=(csrf.as_str())>
                                            <button class="btn btn-outline btn-xs" type="submit">
                                                if entry.enabled {
                                                    "Disable"
                                                } else {
                                                    "Enable"
                                                }
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
                if let Some(next) = next {
                    <p class="mt-2 text-xs"><a class="link link-primary" href=(format!("/catalog?after={next}"))>"Next"</a></p>
                }
                <h2 class="mb-1 mt-4 text-xs font-bold uppercase text-base-content/60">"Add item"</h2>
                <form id="add" method="post" action="/catalog" class="flex max-w-xl flex-col gap-2 text-xs">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <input class="input input-bordered input-xs" name="id" placeholder="id">
                    <select class="select select-bordered select-xs" name="kind">
                        for kind in KINDS {
                            <option value=(kind.0)>(kind.0)</option>
                        }
                    </select>
                    <input class="input input-bordered input-xs" name="name" placeholder="name">
                    <textarea class="textarea textarea-bordered text-xs" name="content" rows="8"></textarea>
                    <button class="btn btn-primary btn-xs" type="submit">"Add"</button>
                </form>
            )
    })
}

/// Adds a new item from the add form.
///
/// The web add refuses an id that already exists with 400, where the CLI upsert replaces the
/// content of that item. A kind and name already held under another id is refused with 400 too.
#[route(POST "/catalog")]
async fn catalog_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let session = admin_post_gate(cx, &form).await?;
    let pool = pool(cx)?;
    let kind = kind_of(field(&form, "kind"))?;
    let request = UpsertCatalogItemRequest {
        kind: kind as i32,
        id: field(&form, "id").to_owned(),
        name: field(&form, "name").to_owned(),
        content: field(&form, "content").to_owned(),
    };
    let known = sqlx::query(DETAIL)
        .bind(&request.id)
        .fetch_optional(pool)
        .await
        .map_err(|err| internal(&err))?;
    if known.is_some() {
        return Err(bad_request(catalog::REASON_NAME_TAKEN).into());
    }
    catalog::upsert_item(pool, session.user_id, &request)
        .await
        .map_err(|status| refusal(&status))?;
    Ok(see_other("/catalog"))
}

#[page("/catalog/{item_id}")]
async fn item_page(cx: &Cx) -> Result<impl View> {
    let session = admin_gate(cx).await?;
    let pool = pool(cx)?;
    let id = item_path(cx)?;
    let row = sqlx::query(DETAIL)
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|err| internal(&err))?
        .ok_or_else(|| topcoat::Error::from(not_found()))?;
    let found = entry(&row, true).map_err(|err| internal(&err))?;
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    let action = format!("/catalog/{}", found.id);
    Ok(view! {
        shell(title: "fleet catalog item", active: Nav::Account, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">(found.name.as_str())</h1>
                    <a class="link link-hover ml-auto" href="/catalog">"Catalog"</a>
                </header>
                <dl class="mb-3 grid max-w-xl grid-cols-[6rem_1fr] gap-y-1 border border-base-300 p-2 text-xs">
                    <dt class="text-base-content/60">"Id"</dt><dd class="break-all">(found.id.as_str())</dd>
                    <dt class="text-base-content/60">"Kind"</dt><dd>(found.kind.as_str())</dd>
                    <dt class="text-base-content/60">"State"</dt>
                    <dd><span class=(badge_class(found.enabled))>(state_word(found.enabled))</span></dd>
                </dl>
                <form id="edit" method="post" action=(action.as_str()) class="flex max-w-xl flex-col gap-2 text-xs">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <textarea id="content" class="textarea textarea-bordered text-xs" name="content" rows="12">(found.content.as_str())</textarea>
                    <button class="btn btn-primary btn-xs" type="submit">"Save"</button>
                </form>
            )
    })
}

#[route(POST "/catalog/{item_id}")]
async fn item_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let session = admin_post_gate(cx, &form).await?;
    let pool = pool(cx)?;
    let id = item_path(cx)?;
    let row = sqlx::query(DETAIL)
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|err| internal(&err))?
        .ok_or_else(|| topcoat::Error::from(not_found()))?;
    let found = entry(&row, true).map_err(|err| internal(&err))?;
    let request = UpsertCatalogItemRequest {
        kind: kind_of(&found.kind)? as i32,
        id: found.id,
        name: found.name,
        content: field(&form, "content").to_owned(),
    };
    catalog::upsert_item(pool, session.user_id, &request)
        .await
        .map_err(|status| refusal(&status))?;
    Ok(see_other(format!("/catalog/{}", request.id)))
}

async fn switch(cx: &Cx, form: &HashMap<String, String>, enabled: bool) -> Result<SeeOther> {
    let session = admin_post_gate(cx, form).await?;
    let pool = pool(cx)?;
    let id = item_path(cx)?;
    catalog::set_enabled(
        pool,
        session.user_id,
        &SetCatalogItemEnabledRequest { id, enabled },
    )
    .await
    .map_err(|status| refusal(&status))?;
    Ok(see_other("/catalog"))
}

#[route(POST "/catalog/{item_id}/enable")]
async fn enable_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    switch(cx, &form, true).await
}

#[route(POST "/catalog/{item_id}/disable")]
async fn disable_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    switch(cx, &form, false).await
}

#[cfg(test)]
mod tests {
    use super::list_page;
    use crate::store::Store;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn a_shrunk_page_hands_out_a_cursor_that_reaches_the_rest(pool: PgPool) {
        Store::new(pool.clone()).migrate().await.unwrap();
        sqlx::query(
            "INSERT INTO catalog_items (id, kind, name, content, digest) \
             SELECT 'i' || n, 'skill', 'i' || n, 'x', sha256('x'::bytea) \
             FROM generate_series(1, 3) n",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (first, next) = list_page(&pool, "", 2).await.unwrap();
        let ids: Vec<_> = first.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["i1", "i2"]);
        assert_eq!(next.as_deref(), Some("i2"));
        let (second, next) = list_page(&pool, "i2", 2).await.unwrap();
        let ids: Vec<_> = second.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["i3"]);
        assert_eq!(next, None);
        let (exact, next) = list_page(&pool, "", 3).await.unwrap();
        assert_eq!((exact.len(), next), (3, None));
    }
}
