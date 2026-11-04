//! Admin catalog pages.

use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, error::see_other, route},
};

use super::pages::{auth, current};

#[route(GET "/catalog")]
async fn catalog_page(cx: &Cx) -> Result<(StatusCode, &'static str)> {
    let auth = auth(cx)?;
    if current(cx, auth).await?.is_none() {
        return Err(see_other("/login").into());
    }
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "the catalog page is not implemented",
    ))
}
