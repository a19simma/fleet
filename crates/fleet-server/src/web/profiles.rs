//! Profile pages.

use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, error::see_other, route},
};

use super::pages::{auth, current};

#[route(GET "/profiles")]
async fn profiles_page(cx: &Cx) -> Result<(StatusCode, &'static str)> {
    let auth = auth(cx)?;
    if current(cx, auth).await?.is_none() {
        return Err(see_other("/login").into());
    }
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "profile pages are not implemented",
    ))
}
