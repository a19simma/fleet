//! Admin catalog pages and the `admin_gate` every admin page starts with.

use std::collections::HashMap;

use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode,
        content::Form,
        error::{forbidden, see_other},
        route,
    },
};

use super::pages::{auth, csrf_matches, current, fail};
use super::passkeys::SessionInfo;

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

#[route(GET "/catalog")]
async fn catalog_page(cx: &Cx) -> Result<(StatusCode, &'static str)> {
    admin_gate(cx).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "the catalog page is not implemented",
    ))
}

#[route(POST "/catalog")]
async fn catalog_post(
    cx: &Cx,
    Form(form): Form<HashMap<String, String>>,
) -> Result<(StatusCode, &'static str)> {
    admin_post_gate(cx, &form).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "the catalog page is not implemented",
    ))
}
