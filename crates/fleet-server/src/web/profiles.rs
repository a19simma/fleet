//! The profile pages: the signed-in user's own and shared profiles, one profile read-only,
//! and the owner's share and unshare buttons.
//!
//! A profile is addressed by `profile.id`. A private profile of another user answers 404
//! exactly like an absent id. A POST names only the profile id and the session's CSRF
//! token: the owner is always the session user, and a non-owner of a shared profile gets
//! 403 with nothing written. Every stored string is passed to the view as text, which
//! escapes it.
//!
//! The owner's page also holds the selection editor: per catalog kind, one checkbox per item
//! (checked means on), admin-disabled items greyed and not togglable, a note on items a Kimi
//! job drops, and a textarea for the authored prompt. The save posts to
//! `/profiles/{id}/selection` and writes a new version through
//! [`profiles::update_owned`], which re-checks the selection against the catalog.

use std::collections::{HashMap, HashSet};

use fleet_core::catalog::{CatalogKind, RunnerKind};
use fleet_core::{Profile, PromptText, Selection};
use sqlx::{PgPool, Row as _};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, bad_request, forbidden, not_found, see_other},
        page, path_param, route,
    },
    view::{View, view},
};

use super::jobs::ConsoleSlot;
use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, current, fail, signed_in};
use super::passkeys::AuthError;
use crate::profiles::{self, ProfileContent, ProfileFault};
use crate::store::StoreError;

const LIST_LIMIT: i64 = 200;
const ITEM_LIMIT: i64 = 2000;
const ITEMS: &str = "SELECT id, kind, name, admin_enabled FROM catalog_items \
     ORDER BY kind, name, id LIMIT $1";
const KIND_ORDER: [CatalogKind; 4] = [
    CatalogKind::Skill,
    CatalogKind::Subagent,
    CatalogKind::Tool,
    CatalogKind::Context,
];
const KIMI_NOTE: &str = "A Kimi job drops this item: Kimi has no subagent mechanism.";

const LIST: &str = "SELECT p.id, p.name, u.username, p.owner_user_id = $1 AS mine, \
     p.visibility = 'shared' AS shared, \
     p.latest_version AS latest \
     FROM profile p JOIN users u ON u.id = p.owner_user_id \
     WHERE p.owner_user_id = $1 OR p.visibility = 'shared' \
     ORDER BY mine DESC, p.name, p.id LIMIT $2";
const DETAIL: &str = "SELECT p.id, p.name, u.username, p.owner_user_id = $1 AS mine, \
     p.visibility = 'shared' AS shared, v.version AS latest, b.content \
     FROM profile p JOIN users u ON u.id = p.owner_user_id \
     LEFT JOIN profile_version v ON v.profile_id = p.id AND v.version = p.latest_version \
     LEFT JOIN profile_blob b ON b.hash = v.hash \
     WHERE p.id = $2 AND (p.owner_user_id = $1 OR p.visibility = 'shared')";

path_param!(profile_id);

struct Entry {
    id: i64,
    name: String,
    owner: String,
    mine: bool,
    shared: bool,
    latest: String,
    content: String,
}

fn entry(row: &sqlx::postgres::PgRow, with_content: bool) -> Result<Entry, sqlx::Error> {
    let latest: Option<i32> = row.try_get("latest")?;
    let content = if with_content {
        row.try_get::<Option<Vec<u8>>, _>("content")?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Entry {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        owner: row.try_get("username")?,
        mine: row.try_get("mine")?,
        shared: row.try_get("shared")?,
        latest: latest.map_or_else(String::new, |v| v.to_string()),
        content,
    })
}

struct Row {
    id: String,
    name: String,
    admin_enabled: bool,
    on: bool,
    note: Option<&'static str>,
}

struct Group {
    kind: &'static str,
    rows: Vec<Row>,
}

fn editor_state(content: &str) -> Option<(HashSet<String>, String)> {
    let profile = Profile::from_json(content.as_bytes()).ok()?;
    let off = profile.selection.ids().map(ToString::to_string).collect();
    let prompt = profile
        .authored_prompt
        .map(|text| text.as_str().to_owned())
        .unwrap_or_default();
    Some((off, prompt))
}

async fn groups(pool: &PgPool, off: &HashSet<String>) -> Result<Vec<Group>> {
    let rows = sqlx::query(ITEMS)
        .bind(ITEM_LIMIT)
        .fetch_all(pool)
        .await
        .map_err(|err| internal(&err))?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let kind: String = row.try_get("kind").map_err(|err| internal(&err))?;
        let id: String = row.try_get("id").map_err(|err| internal(&err))?;
        let name: String = row.try_get("name").map_err(|err| internal(&err))?;
        let admin_enabled: bool = row.try_get("admin_enabled").map_err(|err| internal(&err))?;
        items.push((kind, id, name, admin_enabled));
    }
    let mut out = Vec::new();
    for kind in KIND_ORDER {
        let note = (!RunnerKind::Kimi.supports(kind)).then_some(KIMI_NOTE);
        let rows: Vec<Row> = items
            .iter()
            .filter(|(word, ..)| word == kind.as_str())
            .map(|(_, id, name, admin_enabled)| Row {
                on: !off.contains(id),
                id: id.clone(),
                name: name.clone(),
                admin_enabled: *admin_enabled,
                note,
            })
            .collect();
        if !rows.is_empty() {
            out.push(Group {
                kind: kind.as_str(),
                rows,
            });
        }
    }
    Ok(out)
}

fn pool(cx: &Cx) -> Result<&PgPool> {
    app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .map(crate::store::Store::pool)
        .ok_or_else(|| not_found().into())
}

fn internal(err: &dyn std::fmt::Display) -> topcoat::Error {
    tracing::error!(error = %err, "profile page store call failed");
    fail(AuthError::Internal)
}

fn visibility_word(shared: bool) -> &'static str {
    if shared { "shared" } else { "private" }
}

fn badge_class(shared: bool) -> &'static str {
    if shared {
        "badge badge-sm badge-info"
    } else {
        "badge badge-sm badge-ghost"
    }
}

async fn load(pool: &PgPool, user_id: i64, id: i64) -> Result<Entry> {
    let row = sqlx::query(DETAIL)
        .bind(user_id)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|err| internal(&err))?
        .ok_or_else(|| topcoat::Error::from(not_found()))?;
    entry(&row, true).map_err(|err| internal(&err))
}

#[page("/profiles")]
async fn profiles_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let pool = pool(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let rows = sqlx::query(LIST)
        .bind(session.user_id)
        .bind(LIST_LIMIT)
        .fetch_all(pool)
        .await
        .map_err(|err| internal(&err))?;
    let entries = rows
        .iter()
        .map(|row| entry(row, false))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| internal(&err))?;
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet profiles", active: Nav::Profiles, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Profiles"</h1>
                </header>
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <thead>
                            <tr>
                                <th>"Name"</th>
                                <th>"Owner"</th>
                                <th>"Visibility"</th>
                                <th>"Version"</th>
                                <th>"Access"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for entry in entries {
                                <tr>
                                    <td><a class="link link-primary" href=(format!("/profiles/{}", entry.id))>(entry.name.as_str())</a></td>
                                    <td>(entry.owner.as_str())</td>
                                    <td><span class=(badge_class(entry.shared))>(visibility_word(entry.shared))</span></td>
                                    <td>(entry.latest.as_str())</td>
                                    <td>
                                        if entry.mine {
                                            "owner"
                                        } else {
                                            "read-only"
                                        }
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            )
    })
}

#[page("/profiles/{profile_id}")]
async fn profile_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let pool = pool(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let id = path_param::<ProfileId>(cx)
        .parse::<i64>()
        .map_err(|_| topcoat::Error::from(not_found()))?;
    let found = load(pool, session.user_id, id).await?;
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    let editor = if found.mine {
        match editor_state(&found.content) {
            Some((off, prompt)) => Some((groups(pool, &off).await?, prompt)),
            None => None,
        }
    } else {
        None
    };
    let selection_action = format!("/profiles/{}/selection", found.id);
    let share_action = format!("/profiles/{}/share", found.id);
    let unshare_action = format!("/profiles/{}/unshare", found.id);
    Ok(view! {
        shell(title: "fleet profile", active: Nav::Profiles, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">(found.name.as_str())</h1>
                    <a class="link link-hover ml-auto" href="/profiles">"Profiles"</a>
                </header>
                <dl class="mb-3 grid max-w-xl grid-cols-[6rem_1fr] gap-y-1 border border-base-300 p-2 text-xs">
                    <dt class="text-base-content/60">"Owner"</dt><dd class="break-all">(found.owner.as_str())</dd>
                    <dt class="text-base-content/60">"Visibility"</dt>
                    <dd><span class=(badge_class(found.shared))>(visibility_word(found.shared))</span></dd>
                    <dt class="text-base-content/60">"Version"</dt><dd>(found.latest.as_str())</dd>
                </dl>
                if found.mine {
                    if found.shared {
                        <form method="post" action=(unshare_action.as_str()) class="mb-3">
                            <input type="hidden" name="csrf" value=(csrf.as_str())>
                            <button id="unshare" class="btn btn-outline btn-xs" type="submit">"Unshare"</button>
                        </form>
                    } else {
                        <form method="post" action=(share_action.as_str()) class="mb-3">
                            <input type="hidden" name="csrf" value=(csrf.as_str())>
                            <button id="share" class="btn btn-primary btn-xs" type="submit">"Share"</button>
                        </form>
                    }
                } else {
                    <p id="read-only" class="mb-3 text-xs text-base-content/60">"Read-only: shared by its owner."</p>
                }
                if let Some((groups, prompt)) = editor {
                    <form id="selection" method="post" action=(selection_action.as_str()) class="mb-3 max-w-xl text-xs">
                        <input type="hidden" name="csrf" value=(csrf.as_str())>
                        for group in groups {
                            <fieldset id=(format!("kind-{}", group.kind)) class="mb-2 border border-base-300 p-2">
                                <legend class="px-1 font-bold uppercase text-base-content/60">(group.kind)</legend>
                                for row in group.rows {
                                    if row.admin_enabled {
                                        <label class="flex items-center gap-2">
                                            if row.on {
                                                <input type="checkbox" class="toggle toggle-xs" name=(format!("on_{}", row.id)) value="1" checked="checked">
                                            } else {
                                                <input type="checkbox" class="toggle toggle-xs" name=(format!("on_{}", row.id)) value="1">
                                            }
                                            <span>(row.name.as_str())</span>
                                        </label>
                                    } else {
                                        <label class="flex items-center gap-2 opacity-50">
                                            <input type="checkbox" class="toggle toggle-xs" name=(format!("on_{}", row.id)) value="1" disabled="disabled">
                                            <span>(row.name.as_str())</span>
                                            <span class="badge badge-sm badge-ghost">"disabled by admin"</span>
                                        </label>
                                    }
                                    if let Some(note) = row.note {
                                        <p id=(format!("note-{}", row.id)) class="ml-8 text-base-content/60">(note)</p>
                                    }
                                }
                            </fieldset>
                        }
                        <label class="mb-1 block font-bold uppercase text-base-content/60" for="prompt">"Authored prompt"</label>
                        <textarea id="prompt" class="textarea textarea-bordered w-full text-xs" name="prompt" rows="8">(prompt.as_str())</textarea>
                        <button id="save-selection" class="btn btn-primary btn-xs mt-2" type="submit">"Save"</button>
                    </form>
                }
                <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60">"Content"</h2>
                <pre id="content" class="overflow-auto whitespace-pre-wrap border border-base-300 bg-base-200 p-2 text-xs">(found.content.as_str())</pre>
            )
    })
}

async fn change(cx: &Cx, form: &HashMap<String, String>, share: bool) -> Result<SeeOther> {
    let auth = auth(cx)?;
    let pool = pool(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let id = path_param::<ProfileId>(cx)
        .parse::<i64>()
        .map_err(|_| topcoat::Error::from(not_found()))?;
    let found = load(pool, session.user_id, id).await?;
    if !found.mine {
        return Err(forbidden().into());
    }
    let owner = Some(session.user_id);
    let done = if share {
        profiles::share_owned(pool, owner, &found.name).await
    } else {
        profiles::unshare_owned(pool, owner, &found.name).await
    };
    match done {
        Ok(_) => Ok(see_other(format!("/profiles/{}", found.id))),
        Err(StoreError::NotFound) => Err(not_found().into()),
        Err(StoreError::InvalidProfile(ProfileFault::NotOwner)) => Err(forbidden().into()),
        Err(err) => Err(internal(&err)),
    }
}

#[route(POST "/profiles/{profile_id}/share")]
async fn share_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    change(cx, &form, true).await
}

#[route(POST "/profiles/{profile_id}/unshare")]
async fn unshare_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    change(cx, &form, false).await
}

/// Rebuilds the profile text from the stored one: `off` are the switched-off ids and `prompt`
/// is the authored prompt, where empty text removes it.
fn rebuilt(stored: &str, off: &[String], prompt: &str) -> Result<String> {
    let mut profile = Profile::from_json(stored.as_bytes())
        .map_err(|_| topcoat::Error::from(bad_request("this profile cannot be edited here")))?;
    let entries: Vec<_> = off
        .iter()
        .map(|id| serde_json::json!({ "item_id": id, "enabled": false }))
        .collect();
    let raw = serde_json::to_vec(&entries).map_err(|err| internal(&err))?;
    profile.selection = Selection::from_json(&raw)
        .map_err(|err| topcoat::Error::from(bad_request(err.to_string())))?;
    profile.authored_prompt = PromptText::new(prompt)
        .map_err(|err| topcoat::Error::from(bad_request(err.to_string())))?;
    String::from_utf8(profile.canonical_json()).map_err(|err| internal(&err))
}

#[route(POST "/profiles/{profile_id}/selection")]
async fn selection_post(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let auth = auth(cx)?;
    let pool = pool(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let id = path_param::<ProfileId>(cx)
        .parse::<i64>()
        .map_err(|_| topcoat::Error::from(not_found()))?;
    let found = load(pool, session.user_id, id).await?;
    let rows = sqlx::query(ITEMS)
        .bind(ITEM_LIMIT)
        .fetch_all(pool)
        .await
        .map_err(|err| internal(&err))?;
    let mut off = Vec::new();
    for row in &rows {
        let item: String = row.try_get("id").map_err(|err| internal(&err))?;
        let enabled: bool = row.try_get("admin_enabled").map_err(|err| internal(&err))?;
        if enabled && !form.contains_key(&format!("on_{item}")) {
            off.push(item);
        }
    }
    let prompt = form
        .get("prompt")
        .map(|text| text.replace("\r\n", "\n"))
        .unwrap_or_default();
    let text = rebuilt(&found.content, &off, &prompt)?;
    let store = app_context::<ConsoleSlot>(cx).0.as_deref();
    let allowlist = store.and_then(crate::store::Store::model_allowlist);
    match profiles::update_owned(
        pool,
        Some(session.user_id),
        allowlist,
        found.id,
        ProfileContent::Json(&text),
    )
    .await
    {
        Ok(_) => Ok(see_other(format!("/profiles/{}", found.id))),
        Err(
            StoreError::InvalidProfile(ProfileFault::NotOwner)
            | StoreError::ToolsNotGranted
            | StoreError::ModelDenied(_),
        ) => Err(forbidden().into()),
        Err(err) => Err(internal(&err)),
    }
}
