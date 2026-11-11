//! The Topcoat router: pages, the embedded assets and the passkey routes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::cred::{CredentialService, Users};
use crate::environments::EnvironmentService;
use crate::store::Store;
use fleet_core::constant_time_eq;
use serde_json::{Value, json};
use tonic::transport::server::TcpConnectInfo;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        BodyLimit, HeaderMap, HeaderValue, OriginPolicy, Router, RouterBuilderDiscoverExt,
        content::{Form, Json},
        error::{bad_request, forbidden, internal_server_error, not_found, see_other},
        header, page,
        request::{extensions, headers},
        response::response_headers,
        route,
    },
    view::{View, view},
};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use super::clientip::client_ip;
use super::credentials::{Backend, CredentialSlot};
use super::env::EnvSlot;
use super::hosts::HostSlot;
use super::jobs::ConsoleSlot;
use super::layout::{Nav, bare, shell};
use super::passkeys::{AuthError, SESSION_COOKIE, SESSION_TTL_SECS, SessionInfo, WebAuth};
use super::tokens::{TokenSlot, Tokens};
use crate::hosts::HostService;

/// Stylesheet compiled into the binary, since Topcoat's `asset!` writes beside the binary.
pub const STYLE_CSS: &str = include_str!("../../assets/ui.css");

/// URL path of the embedded stylesheet.
pub const STYLE_PATH: &str = "/static/style.css";

/// Script that drives the browser's `WebAuthn` calls, compiled into the binary.
pub const PASSKEY_JS: &str = include_str!("../../assets/passkey.js");

/// URL path of the embedded script.
pub const SCRIPT_PATH: &str = "/static/passkey.js";

/// Script that scrolls a focused top bar link clear of the right-edge fade.
pub const NAV_FOCUS_JS: &str = r#"(function () {
  var nav = document.querySelector('nav[aria-label="Main mobile"]');
  if (!nav) { return; }
  var CLEAR = 48;
  var EDGE = 16;
  nav.addEventListener("focusin", function (event) {
    var target = event.target;
    if (!(target instanceof Element)) { return; }
    var bar = nav.getBoundingClientRect();
    var box = target.getBoundingClientRect();
    var over = box.right - (bar.left + nav.clientWidth - CLEAR);
    if (over > 0) {
      nav.scrollLeft += over;
      return;
    }
    var under = bar.left + EDGE - box.left;
    if (under > 0) { nav.scrollLeft -= under; }
  });
})();
"#;

/// URL path of the top bar focus script.
pub(super) const NAV_SCRIPT_PATH: &str = "/static/navfocus.js";

/// Heading rendered by the home page.
pub const HOME_MARKER: &str = "fleet";

/// The largest request body any web route reads, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

const CSRF_HEADER: &str = "x-csrf-token";
const SESSION_ID_LEN: usize = 64;

struct AuthSlot(Option<Arc<WebAuth>>);

pub(super) fn auth(cx: &Cx) -> Result<&WebAuth> {
    app_context::<AuthSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

pub(super) fn fail(err: AuthError) -> topcoat::Error {
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

fn client(cx: &Cx, auth: &WebAuth) -> IpAddr {
    let peer = extensions(cx)
        .get::<TcpConnectInfo>()
        .and_then(TcpConnectInfo::remote_addr)
        .map(|addr| addr.ip());
    let forwarded: Vec<&str> = headers(cx)
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    client_ip(peer, &forwarded, auth.trusted_hops())
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

pub(super) async fn current(cx: &Cx, auth: &WebAuth) -> Result<Option<SessionInfo>> {
    match session_cookie(headers(cx)) {
        Some(id) => auth.session(id.as_bytes()).await.map_err(fail),
        None => Ok(None),
    }
}

pub(super) async fn signed_in(cx: &Cx, auth: &WebAuth) -> Result<SessionInfo> {
    current(cx, auth).await?.ok_or_else(|| forbidden().into())
}

pub(super) fn csrf_matches(expected: &SessionInfo, presented: Option<&str>) -> bool {
    presented.is_some_and(|token| constant_time_eq(expected.csrf.expose(), token.as_bytes()))
}

/// A session cookie value outside the cookie-octet grammar (RFC 6265 section 4.1.1).
#[derive(Debug, PartialEq, Eq)]
struct CookieValueError;

fn cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

fn cookie_header(value: &str, max_age: i64) -> Result<HeaderValue, CookieValueError> {
    if !value.bytes().all(cookie_octet) {
        return Err(CookieValueError);
    }
    let cookie = format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
    );
    HeaderValue::from_str(&cookie).map_err(|_| CookieValueError)
}

fn set_cookie(cx: &Cx, value: &str, max_age: i64) -> Result<()> {
    let cookie = cookie_header(value, max_age).map_err(|_| fail(AuthError::Internal))?;
    response_headers(cx).append(header::SET_COOKIE, cookie);
    Ok(())
}

#[page("/")]
async fn home() -> Result<impl View> {
    Ok(view! {
        bare(title: "fleet", mode: "home",
            <h1 class="mb-3 text-sm font-bold"><span class="text-primary">"$"</span> " "(HOME_MARKER)</h1>
            <ul class="menu menu-sm w-full">
                <li><a href="/account">"Account"</a></li>
                <li><a href="/credentials">"Credentials"</a></li>
                <li><a href="/jobs">"Jobs"</a></li>
                <li><a href="/tokens">"Tokens"</a></li>
            </ul>
        )
    })
}

#[page("/login")]
async fn login_page(cx: &Cx) -> Result<impl View> {
    auth(cx)?;
    Ok(view! {
        bare(title: "fleet sign in", mode: "login",
            <h1 class="mb-3 text-sm font-bold"><span class="text-primary">"$"</span> " Sign in"</h1>
            <form class="flex flex-col gap-3" id="passkey-form">
                <fieldset class="fieldset">
                    <label class="label" for="username">"Username"</label>
                    <input class="input input-sm w-full" id="username" name="username" autocomplete="username webauthn" required="">
                </fieldset>
                <button class="btn btn-primary btn-sm" type="submit">"Sign in"</button>
            </form>
            <p class="mt-3 text-xs" id="status" role="status"></p>
            <script src=(SCRIPT_PATH) defer=""></script>
        )
    })
}

#[page("/setup/{code}")]
async fn setup_page(cx: &Cx) -> Result<impl View> {
    auth(cx)?;
    Ok(view! {
        bare(title: "fleet setup", mode: "setup",
            <h1 class="mb-3 text-sm font-bold"><span class="text-primary">"$"</span> " Create the admin"</h1>
            <form class="flex flex-col gap-3" id="passkey-form">
                <fieldset class="fieldset">
                    <label class="label" for="username">"Username"</label>
                    <input class="input input-sm w-full" id="username" name="username" autocomplete="username" required="">
                </fieldset>
                <button class="btn btn-primary btn-sm" type="submit">"Create a passkey"</button>
            </form>
            <p class="mt-3 text-xs" id="status" role="status"></p>
            <script src=(SCRIPT_PATH) defer=""></script>
        )
    })
}

#[page("/setup")]
async fn setup_password_page(cx: &Cx) -> Result<impl View> {
    auth(cx)?;
    Ok(view! {
        bare(title: "fleet setup", mode: "setup-password",
            <h1 class="mb-3 text-sm font-bold"><span class="text-primary">"$"</span> " Create the admin"</h1>
            <form class="flex flex-col gap-3" id="passkey-form" autocomplete="off">
                <fieldset class="fieldset">
                    <label class="label" for="username">"Username"</label>
                    <input class="input input-sm w-full" id="username" name="username" autocomplete="username" required="">
                </fieldset>
                <fieldset class="fieldset">
                    <label class="label" for="password">"Setup password"</label>
                    <input class="input input-sm w-full" id="password" name="password" type="password" autocomplete="off" required="">
                </fieldset>
                <button class="btn btn-primary btn-sm" type="submit">"Create a passkey"</button>
            </form>
            <p class="mt-3 text-xs" id="status" role="status"></p>
            <script src=(SCRIPT_PATH) defer=""></script>
        )
    })
}

#[page("/enroll/{code}")]
async fn enroll_page(cx: &Cx) -> Result<impl View> {
    auth(cx)?;
    Ok(view! {
        bare(title: "fleet enrollment", mode: "enroll",
            <h1 class="mb-3 text-sm font-bold"><span class="text-primary">"$"</span> " Create a passkey"</h1>
            <form class="flex flex-col gap-3" id="passkey-form">
                <button class="btn btn-primary btn-sm" type="submit">"Create a passkey"</button>
            </form>
            <p class="mt-3 text-xs" id="status" role="status"></p>
            <script src=(SCRIPT_PATH) defer=""></script>
        )
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
    let rows: Vec<PasskeyView> = auth
        .list_passkeys(session.user_id)
        .await
        .map_err(fail)?
        .into_iter()
        .enumerate()
        .map(|(index, row)| PasskeyView {
            label: format!("Passkey {}", index + 1),
            id: row.id.to_string(),
            created: row.created,
            last_used: row.last_used.unwrap_or_else(|| "never".to_owned()),
        })
        .collect();
    Ok(view! {
        shell(title: "fleet account", active: Nav::Account, user: name.as_str(), csrf: csrf.as_str(), mode: "add",
            <h1 class="mb-3 border-b border-base-300 pb-2 text-sm font-bold"><span class="text-primary">"$"</span> " "(name.as_str())</h1>
            <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60">"Passkeys"</h2>
            <div class="overflow-x-auto">
                <table class="table table-zebra table-xs">
                    <thead>
                        <tr>
                            <th>"Name"</th>
                            <th>"Created"</th>
                            <th>"Last used"</th>
                            <th>"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr>
                                <td>(row.label)</td>
                                <td>(row.created)</td>
                                <td>(row.last_used)</td>
                                <td>
                                    <form method="post" action="/account/passkeys/delete">
                                        <input type="hidden" name="csrf" value=(csrf.as_str())>
                                        <input type="hidden" name="id" value=(row.id)>
                                        <button class="btn btn-outline btn-error btn-xs" type="submit">"Delete"</button>
                                    </form>
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
            </div>
            <div class="mt-3 flex flex-wrap items-center gap-2">
                <form id="passkey-form">
                    <button class="btn btn-secondary btn-sm" type="submit">"Create a passkey"</button>
                </form>
                <form method="post" action="/account/device-code">
                    <input type="hidden" name="csrf" value=(csrf.as_str())>
                    <button class="btn btn-outline btn-sm" type="submit">"Create a code for a new device"</button>
                </form>
            </div>
            <p class="mt-3 text-xs" id="status" role="status"></p>
            <script src=(SCRIPT_PATH) defer=""></script>
        )
    })
}

struct PasskeyView {
    label: String,
    id: String,
    created: String,
    last_used: String,
}

#[route(POST "/account/passkeys/delete")]
async fn delete_passkey(
    cx: &Cx,
    Form(form): Form<HashMap<String, String>>,
) -> Result<topcoat::router::error::SeeOther> {
    let auth = auth(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let id = form
        .get("id")
        .and_then(|id| id.parse::<i64>().ok())
        .ok_or_else(|| fail(AuthError::Refused))?;
    auth.delete_passkey(session.user_id, id)
        .await
        .map_err(fail)?;
    Ok(see_other("/account"))
}

#[page(POST "/account/device-code")]
async fn device_code(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<impl View> {
    let auth = auth(cx)?;
    let session = signed_in(cx, auth).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let Some(cookie) = session_cookie(headers(cx)) else {
        return Err(forbidden().into());
    };
    let code = auth
        .new_device_code(session.user_id, cookie.as_bytes())
        .await
        .map_err(fail)?;
    let url = format!(
        "{}/enroll/{}",
        auth.origin(),
        String::from_utf8_lossy(code.expose())
    );
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet new device", active: Nav::Account, user: session.username.as_str(), csrf: csrf.as_str(), mode: "device",
            <h1 class="mb-3 border-b border-base-300 pb-2 text-sm font-bold"><span class="text-primary">"$"</span> " New device code"</h1>
            <p class="mb-3 text-xs">"Open this address on the new device. It works once and expires in 10 minutes."</p>
            <pre class="overflow-x-auto border border-base-300 bg-base-200 p-2 text-xs" id="enroll-url">(url.as_str())</pre>
            <p class="mt-3 text-xs"><a class="link link-primary" href="/account">"Account"</a></p>
        )
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

#[route(GET "/static/navfocus.js")]
async fn nav_script() -> Result<([(header::HeaderName, &'static str); 1], &'static str)> {
    Ok(([(header::CONTENT_TYPE, "text/javascript")], NAV_FOCUS_JS))
}

#[route(POST "/passkey/setup/start")]
async fn setup_start(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let auth = auth(cx)?;
    let username = field(&body, "username")?;
    let (ceremony, options) = if body.get("password").is_some() {
        auth.setup_password_start(field(&body, "password")?, username, client(cx, auth))
            .await
    } else {
        auth.setup_start(field(&body, "code")?, username).await
    }
    .map_err(fail)?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[route(POST "/passkey/setup/finish")]
async fn setup_finish(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let auth = auth(cx)?;
    let session = auth
        .setup_finish(
            field(&body, "ceremony")?,
            &registration(&body)?,
            client(cx, auth),
        )
        .await
        .map_err(fail)?;
    set_cookie(
        cx,
        &String::from_utf8_lossy(session.id.expose()),
        SESSION_TTL_SECS,
    )?;
    Ok(Json(json!({ "ok": true })))
}

#[route(POST "/passkey/enroll/start")]
async fn enroll_start(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let (ceremony, options) = auth(cx)?
        .enroll_start(field(&body, "code")?)
        .await
        .map_err(fail)?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[route(POST "/passkey/enroll/finish")]
async fn enroll_finish(cx: &Cx, Json(body): Json<Value>) -> Result<Json<Value>> {
    let session = auth(cx)?
        .enroll_finish(field(&body, "ceremony")?, &registration(&body)?)
        .await
        .map_err(fail)?;
    set_cookie(
        cx,
        &String::from_utf8_lossy(session.id.expose()),
        SESSION_TTL_SECS,
    )?;
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
    )?;
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
    let Some(cookie) = session_cookie(headers(cx)) else {
        return Err(forbidden().into());
    };
    auth.add_finish(
        session.user_id,
        cookie.as_bytes(),
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
    set_cookie(cx, "", 0)?;
    Ok(see_other("/login"))
}

/// The web side of the server: a shared Topcoat router.
#[derive(Clone)]
pub struct Web {
    router: Arc<Router>,
}

fn builder(
    auth: Option<Arc<WebAuth>>,
    credentials: Option<Arc<Backend>>,
    console: Option<(Arc<Store>, Arc<Tokens>)>,
    environments: Option<EnvironmentService>,
    hosts: Option<Arc<HostService>>,
    origins: &[String],
) -> Router {
    let (store, tokens) = console.unzip();
    Router::builder()
        .discover()
        .origin_policy(OriginPolicy::new().trust_origins(origins.iter().cloned()))
        .layer(BodyLimit::max(MAX_BODY_BYTES))
        .app_context(AuthSlot(auth))
        .app_context(CredentialSlot(credentials))
        .app_context(ConsoleSlot(store))
        .app_context(TokenSlot(tokens))
        .app_context(EnvSlot(environments))
        .app_context(HostSlot(hosts))
        .build()
}

impl Web {
    /// Builds the router with login turned off: pages render and the auth routes answer 404.
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: Arc::new(builder(None, None, None, None, None, &[])),
        }
    }

    /// Builds the router with passkey login, trusting the origin of `auth` for browser posts.
    #[must_use]
    pub fn with_auth(auth: WebAuth) -> Self {
        let origins = [auth.origin().to_owned()];
        Self {
            router: Arc::new(builder(
                Some(Arc::new(auth)),
                None,
                None,
                None,
                None,
                &origins,
            )),
        }
    }

    /// Builds the router with passkey login, the jobs and API token pages over `store`, and
    /// the credentials page when `credentials` is set.
    #[must_use]
    pub fn with_console(
        auth: WebAuth,
        credentials: Option<CredentialService>,
        store: Store,
    ) -> Self {
        Self::with_environments(auth, credentials, None, store)
    }

    /// Builds the router like [`Web::with_console`] and serves the environment pages from
    /// `environments` (ADR 0067). Without it those routes answer 404.
    #[must_use]
    pub fn with_environments(
        auth: WebAuth,
        credentials: Option<CredentialService>,
        environments: Option<EnvironmentService>,
        store: Store,
    ) -> Self {
        let hosts = match HostService::system(auth.pool().clone()) {
            Ok(hosts) => Some(hosts),
            Err(error) => {
                tracing::error!(%error, "git remotes page disabled");
                None
            }
        };
        Self::with_hosts(auth, credentials, environments, hosts, store)
    }

    /// Builds the router like [`Web::with_environments`] and serves the git remotes page from
    /// `hosts` (ADR 0068). Without it `/hosts` answers 404.
    #[must_use]
    pub fn with_hosts(
        auth: WebAuth,
        credentials: Option<CredentialService>,
        environments: Option<EnvironmentService>,
        hosts: Option<HostService>,
        store: Store,
    ) -> Self {
        let origins = [auth.origin().to_owned()];
        let pool = auth.pool().clone();
        let backend = credentials.map(|service| {
            Arc::new(Backend {
                service,
                pool: pool.clone(),
            })
        });
        let tokens = Tokens {
            users: Users::new(pool.clone()),
            pool,
        };
        Self {
            router: Arc::new(builder(
                Some(Arc::new(auth)),
                backend,
                Some((Arc::new(store), Arc::new(tokens))),
                environments,
                hosts.map(Arc::new),
                &origins,
            )),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_cookie_values_are_refused() {
        for value in [
            "a\rb",
            "a\nb",
            "a\r\nSet-Cookie: x=y",
            "a\0b",
            "caf\u{e9}",
            "a\u{85}b",
            "a b",
            "a;b",
            "a,b",
            "a\"b",
            "a\\b",
            "a\tb",
            "a\x7fb",
        ] {
            assert_eq!(cookie_header(value, 1), Err(CookieValueError), "{value:?}");
        }
    }

    #[test]
    fn valid_cookie_values_are_built() {
        let hex = "0123456789abcdefABCDEF";
        let header = cookie_header(hex, 60).expect("hex value");
        assert_eq!(
            header.to_str().expect("ascii"),
            format!(
                "{SESSION_COOKIE}={hex}; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Strict"
            )
        );
        assert!(cookie_header("", 0).is_ok());
    }
}
