//! The Topcoat side: a page, an embedded asset and passkey JSON routes.

use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        OriginPolicy, Router, RouterBuilderDiscoverExt, content::Json, error::bad_request, header,
        page, route,
    },
    view::{View, view},
};
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::passkey::Passkeys;

/// Stylesheet compiled into the binary with `include_str!`.
pub const STYLE_CSS: &str = include_str!("../assets/style.css");

/// URL path of the embedded stylesheet.
pub const STYLE_PATH: &str = "/static/style.css";

/// Marker text rendered by the home page.
pub const HOME_MARKER: &str = "fleet web spike";

/// Names the user of a ceremony.
#[derive(Deserialize)]
pub struct NameBody {
    /// User name.
    pub name: String,
}

/// Registration finish body.
#[derive(Deserialize)]
pub struct RegisterFinish {
    /// User name.
    pub name: String,
    /// Credential produced by the authenticator.
    pub credential: RegisterPublicKeyCredential,
}

/// Login finish body.
#[derive(Deserialize)]
pub struct LoginFinish {
    /// User name.
    pub name: String,
    /// Assertion produced by the authenticator.
    pub credential: PublicKeyCredential,
}

/// Result of a completed login.
#[derive(Serialize)]
pub struct LoginOk {
    /// Always true on success.
    pub ok: bool,
    /// Signature counter reported by the authenticator.
    pub counter: u32,
}

#[page("/")]
async fn home() -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>(HOME_MARKER)</h1>
            </body>
        </html>
    })
}

#[route(GET "/static/style.css")]
async fn style() -> Result<([(header::HeaderName, &'static str); 1], &'static str)> {
    Ok(([(header::CONTENT_TYPE, "text/css")], STYLE_CSS))
}

#[route(POST "/passkey/register/start")]
async fn register_start(
    cx: &Cx,
    Json(body): Json<NameBody>,
) -> Result<Json<CreationChallengeResponse>> {
    let passkeys: &Passkeys = app_context(cx);
    let challenge = passkeys
        .start_register(&body.name)
        .map_err(|_| bad_request("registration refused"))?;
    Ok(Json(challenge))
}

#[route(POST "/passkey/register/finish")]
async fn register_finish(cx: &Cx, Json(body): Json<RegisterFinish>) -> Result<&'static str> {
    let passkeys: &Passkeys = app_context(cx);
    passkeys
        .finish_register(&body.name, &body.credential)
        .map_err(|_| bad_request("registration refused"))?;
    Ok("registered")
}

#[route(POST "/passkey/login/start")]
async fn login_start(
    cx: &Cx,
    Json(body): Json<NameBody>,
) -> Result<Json<RequestChallengeResponse>> {
    let passkeys: &Passkeys = app_context(cx);
    let challenge = passkeys
        .start_login(&body.name)
        .map_err(|_| bad_request("login refused"))?;
    Ok(Json(challenge))
}

#[route(POST "/passkey/login/finish")]
async fn login_finish(cx: &Cx, Json(body): Json<LoginFinish>) -> Result<Json<LoginOk>> {
    let passkeys: &Passkeys = app_context(cx);
    let result = passkeys
        .finish_login(&body.name, &body.credential)
        .map_err(|_| bad_request("login refused"))?;
    Ok(Json(LoginOk {
        ok: true,
        counter: result.counter(),
    }))
}

/// Builds the Topcoat router around `passkeys`, trusting `origin` for form posts.
#[must_use]
pub fn router(passkeys: Passkeys, origin: &str) -> Router {
    Router::builder()
        .discover()
        .origin_policy(OriginPolicy::new().trust_origins([origin]))
        .app_context(passkeys)
        .build()
}
