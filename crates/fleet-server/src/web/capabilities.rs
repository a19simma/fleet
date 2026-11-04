//! Admin capability pages.

use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, error::see_other, route},
};

use super::pages::{auth, current};

#[route(GET "/users/{user_id}/capabilities")]
async fn capabilities_page(cx: &Cx) -> Result<(StatusCode, &'static str)> {
    let auth = auth(cx)?;
    if current(cx, auth).await?.is_none() {
        return Err(see_other("/login").into());
    }
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "the capability page is not implemented",
    ))
}
