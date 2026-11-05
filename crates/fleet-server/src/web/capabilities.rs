//! Admin capability pages.

use std::collections::HashMap;

use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, route},
};

use super::catalog::{admin_gate, admin_post_gate};

#[route(GET "/users/{user_id}/capabilities")]
async fn capabilities_page(cx: &Cx) -> Result<(StatusCode, &'static str)> {
    admin_gate(cx).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "the capability page is not implemented",
    ))
}

#[route(POST "/users/{user_id}/capabilities")]
async fn capabilities_post(
    cx: &Cx,
    Form(form): Form<HashMap<String, String>>,
) -> Result<(StatusCode, &'static str)> {
    admin_post_gate(cx, &form).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "the capability page is not implemented",
    ))
}
