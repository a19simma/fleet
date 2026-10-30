//! The Topcoat router: pages, the embedded assets and the passkey routes.

use std::collections::HashMap;
use std::sync::Arc;

use fleet_core::constant_time_eq;
use serde_json::{Value, json};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        BodyLimit, HeaderMap, HeaderValue, OriginPolicy, Router, RouterBuilderDiscoverExt,
        content::{Form, Json},
        error::{bad_request, forbidden, internal_server_error, not_found, see_other},
        header, page,
        request::headers,
        response::response_headers,
        route,
    },
    view::{View, view},
};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use super::passkeys::{AuthError, SESSION_COOKIE, SESSION_TTL_SECS, SessionInfo, WebAuth};

/// Stylesheet compiled into the binary, since Topcoat's `asset!` writes beside the binary.
pub const STYLE_CSS: &str = include_str!("../../assets/style.css");

/// URL path of the embedded stylesheet.
pub const STYLE_PATH: &str = "/static/style.css";

/// Script that drives the browser's `WebAuthn` calls, compiled into the binary.
pub const PASSKEY_JS: &str = include_str!("../../assets/passkey.js");

/// URL path of the embedded script.
pub const SCRIPT_PATH: &str = "/static/passkey.js";

/// Heading rendered by the home page.
pub const HOME_MARKER: &str = "fleet";

/// The largest request body any web route reads, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

const CSRF_HEADER: &str = "x-csrf-token";
const SESSION_ID_LEN: usize = 64;

struct AuthSlot(Option<Arc<WebAuth>>);

fn auth(cx: &Cx) -> Result<&WebAuth> {
    app_context::<AuthSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

fn fail(err: AuthError) -> topcoat::Error {
    match err {
        AuthError::Refused => bad_request("request refused").into(),
        AuthError::Internal => internal_server_error(err).into(),
    }
}

fn field<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("invalid request").into())
}

fn registration(body: &Value) -> Result<RegisterPublicKeyCredential> {
    body.get("credential")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .ok_or_else(|| bad_request("invalid request").into())
}

fn assertion(body: &Value) -> Result<PublicKeyCredential> {
    body.get("credential")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .ok_or_else(|| bad_request("invalid request").into())
}

fn session_cookie(map: &HeaderMap) -> Option<&str> {
    let prefix = format!("{SESSION_COOKIE}=");
    map.get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(prefix.as_str()))
        .filter(|id| id.len() == SESSION_ID_LEN && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

async fn current(cx: &Cx, auth: &WebAuth) -> Result<Option<SessionInfo>> {
    match session_cookie(headers(cx)) {
        Some(id) => auth.session(id.as_bytes()).await.map_err(fail),
        None => Ok(None),
    }
}

async fn signed_in(cx: &Cx, auth: &WebAuth) -> Result<SessionInfo> {
    current(cx, auth).await?.ok_or_else(|| forbidden().into())
}

fn csrf_matches(expected: &SessionInfo, presented: Option<&str>) -> bool {
    presented.is_some_and(|token| constant_time_eq(expected.csrf.expose(), token.as_bytes()))
}

fn set_cookie(cx: &Cx, value: &str, max_age: i64) {
    let cookie = format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
    );
    if let Ok(cookie) = HeaderValue::from_str(&cookie) {
        response_headers(cx).append(header::SET_COOKIE, cookie);
    }
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
                <p><a href="/account">"Account"</a></p>
            </body>
        </html>
    })
}

#[page("/login")]
async fn login_page(cx: &Cx) -> Result<impl View> {
    auth(cx)?;
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet sign in"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body data-mode="login">
                <h1>"Sign in"</h1>
                <form id="passkey-form">
                    <label>"Username"
                        <input id="username" name="username" autocomplete="username webauthn" required="">
                    </label>
                    <button type="submit">"Sign in with a passkey"</button>
                </form>
                <p id="status"></p>
                <script src=(SCRIPT_PATH) defer=""></script>
            </body>
        </html>
    })
}

#[page("/setup/{code}")]
async fn setup_page(cx: &Cx) -> Result<impl View> {
    auth(cx)?;
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet setup"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body data-mode="setup">
                <h1>"Create the admin"</h1>
                <form id="passkey-form">
                    <label>"Username"
                        <input id="username" name="username" autocomplete="username" required="">
                    </label>
                    <button type="submit">"Register a passkey"</button>
                </form>
                <p id="status"></p>
                <script src=(SCRIPT_PATH) defer=""></script>
            </body>
        </html>
    })
}

#[page("/account")]
async fn account(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    let name = session.username;
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet account"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body data-mode="add" data-csrf=(csrf.as_str())>
                <h1>(name)</h1>
                <form id="passkey-form">
                    <button type="submit">"Add a passkey"</button>
                </form>
                <p id="status"></p>
                <form method="post" action="/logout">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <button type="submit">"Sign out"</button>
                </form>
                <script src=(SCRIPT_PATH) defer=""></script>
            </body>
        </html>
    })
}

#[route(GET "/static/style.css")]
async fn style() -> Result<([(header::HeaderName, &'static str); 1], &'static str)> {
    Ok(([(header::CONTENT_TYPE, "text/css")], STYLE_CSS))
}

#[route(GET "/static/passkey.js")]
async fn script() -> Result<([(header::HeaderName, &'static str); 1], &'static str)> {
    Ok(([(header::CONTENT_TYPE, "text/javascript")], PASSKEY_JS))
}

#[route(POST "/passkey/setup/start")]
async fn setup_start(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let (ceremony, options) = auth(cx)?
        .setup_start(field(&body, "code")?, field(&body, "username")?)
        .await
        .map_err(fail)?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[route(POST "/passkey/setup/finish")]
async fn setup_finish(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let session = auth(cx)?
        .setup_finish(field(&body, "ceremony")?, &registration(&body)?)
        .await
        .map_err(fail)?;
    set_cookie(
        cx,
        &String::from_utf8_lossy(session.id.expose()),
        SESSION_TTL_SECS,
    );
    Ok(Json(json!({ "ok": true })))
}

#[route(POST "/passkey/login/start")]
async fn login_start(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let (ceremony, options) = auth(cx)?
        .login_start(field(&body, "username")?)
        .await
        .map_err(fail)?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[route(POST "/passkey/login/finish")]
async fn login_finish(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let session = auth(cx)?
        .login_finish(
            field(&body, "ceremony")?,
            &assertion(&body)?,
            session_cookie(headers(cx)).map(str::as_bytes),
        )
        .await
        .map_err(fail)?;
    set_cookie(
        cx,
        &String::from_utf8_lossy(session.id.expose()),
        SESSION_TTL_SECS,
    );
    Ok(Json(json!({ "ok": true })))
}

#[route(POST "/passkey/add/start")]
async fn add_start(cx: &Cx, Json(_body): Json<Value>) -> Result<Json<Value>> {
    let auth = auth(cx)?;
    let session = signed_in(cx, auth).await?;
    let presented = headers(cx)
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf_matches(&session, presented) {
        return Err(forbidden().into());
    }
    let (ceremony, options) = auth.add_start(session.user_id).await.map_err(fail)?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[route(POST "/passkey/add/finish")]
async fn add_finish(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let auth = auth(cx)?;
    let session = signed_in(cx, auth).await?;
    let presented = headers(cx)
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if !csrf_matches(&session, presented) {
        return Err(forbidden().into());
    }
    auth.add_finish(
        session.user_id,
        field(&body, "ceremony")?,
        &registration(&body)?,
    )
    .await
    .map_err(fail)?;
    Ok(Json(json!({ "ok": true })))
}

#[route(POST "/logout")]
async fn logout(
    cx: &Cx,
    Form(form): Form<HashMap<String, String>>,
) -> Result<topcoat::router::error::SeeOther> {
    let auth = auth(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    if let Some(id) = session_cookie(headers(cx)) {
        auth.logout(id.as_bytes()).await.map_err(fail)?;
    }
    set_cookie(cx, "", 0);
    Ok(see_other("/login"))
}

/// The web side of the server: a shared Topcoat router.
#[derive(Clone)]
pub struct Web {
    router: Arc<Router>,
}

fn builder(auth: Option<Arc<WebAuth>>, origins: &[String]) -> Router {
    Router::builder()
        .discover()
        .origin_policy(OriginPolicy::new().trust_origins(origins.iter().cloned()))
        .layer(BodyLimit::max(MAX_BODY_BYTES))
        .app_context(AuthSlot(auth))
        .build()
}

impl Web {
    /// Builds the router with login turned off: pages render and the auth routes answer 404.
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: Arc::new(builder(None, &[])),
        }
    }

    /// Builds the router with passkey login, trusting the origin of `auth` for browser posts.
    #[must_use]
    pub fn with_auth(auth: WebAuth) -> Self {
        let origins = [auth.origin().to_owned()];
        Self {
            router: Arc::new(builder(Some(Arc::new(auth)), &origins)),
        }
    }

    pub(super) fn router(&self) -> &Router {
        &self.router
    }
}

impl Default for Web {
    fn default() -> Self {
        Self::new()
    }
}
