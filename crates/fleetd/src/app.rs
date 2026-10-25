use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use fleet_core::{Envelope, HookAllowlist, Identity, Redactor, normalize_hook};
use serde_json::{Value, json};

use crate::events::Enqueued;
use crate::store::Store;
use crate::system::{fresh_id, now_ms};
use crate::toolhook::{HookHub, ToolReport, is_tool_event};

const MAX_RECENT: usize = 4096;
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Shared handler state.
#[derive(Debug)]
pub struct AppState {
    store: Store,
    identity: Identity,
    allow: HookAllowlist,
    redactor: Redactor,
    dedupe_window: Duration,
    hub: Arc<HookHub>,
    recent: Mutex<HashMap<u64, Instant>>,
}

impl AppState {
    /// Builds state from the store, box identity, hook allowlist, redactor and the
    /// window in which an identical hook body counts as a repeat.
    ///
    /// Repeat detection is lossy. It lives in memory, so a restart forgets it. It keeps
    /// at most 4096 keys, evicting the oldest first. It hashes the event name and raw
    /// body with a non-cryptographic hasher, so a collision can drop a distinct event.
    /// A key is recorded only after the event is stored, and a hit does not extend the
    /// window.
    pub fn new(
        store: Store,
        identity: Identity,
        allow: HookAllowlist,
        redactor: Redactor,
        dedupe_window: Duration,
    ) -> Arc<Self> {
        Self::with_hub(
            store,
            identity,
            allow,
            redactor,
            dedupe_window,
            HookHub::new(),
        )
    }

    /// Builds state like [`AppState::new`], routing `PostToolUse` and `PostToolUseFailure`
    /// hooks to the running jobs registered in `hub`.
    ///
    /// Those two events never enter the queue: they only reach a job's telemetry, and only
    /// while the event name is on the allowlist.
    pub fn with_hub(
        store: Store,
        identity: Identity,
        allow: HookAllowlist,
        redactor: Redactor,
        dedupe_window: Duration,
        hub: Arc<HookHub>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            identity,
            allow,
            redactor,
            dedupe_window,
            hub,
            recent: Mutex::new(HashMap::new()),
        })
    }

    fn repeat_key(&self, event: &str, body: &[u8]) -> Option<u64> {
        if self.dedupe_window.is_zero() {
            return None;
        }
        let mut hasher = DefaultHasher::new();
        event.hash(&mut hasher);
        body.hash(&mut hasher);
        Some(hasher.finish())
    }

    fn is_repeat(&self, key: u64) -> bool {
        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        recent.retain(|_, seen| now.duration_since(*seen) < self.dedupe_window);
        recent.contains_key(&key)
    }

    fn remember(&self, key: u64) {
        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        if recent.len() >= MAX_RECENT && !recent.contains_key(&key) {
            let oldest = recent
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(oldest, _)| *oldest);
            if let Some(oldest) = oldest {
                recent.remove(&oldest);
            }
        }
        recent.entry(key).or_insert(now);
    }

    async fn store(&self, mut envelope: Envelope) -> Result<Enqueued, crate::Error> {
        self.redactor.redact_envelope(&mut envelope);
        self.store.enqueue(&envelope, now_ms()).await
    }
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    json_response(StatusCode::BAD_REQUEST, &json!({ "error": message }))
}

fn server_error(err: &crate::Error) -> Response {
    tracing::error!(%err, "enqueue failed");
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({ "error": "queue write failed" }),
    )
}

async fn healthz() -> &'static str {
    "ok"
}

const JOB_HEADER: &str = "x-fleet-job";
const MAX_JOB_BYTES: usize = 128;

fn tool_hook(state: &AppState, event: &str, headers: &HeaderMap, body: &[u8]) -> Response {
    if !state.allow.contains(event) {
        tracing::debug!(event, "hook event not recorded");
        return json_response(StatusCode::OK, &json!({}));
    }
    let job = headers
        .get(JOB_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|job| !job.is_empty() && job.len() <= MAX_JOB_BYTES);
    if let (Some(job), Some(report)) = (job, ToolReport::from_reduced(body)) {
        if !state.hub.deliver(job, report) {
            tracing::debug!(event, "tool report dropped");
        }
    } else {
        state.hub.note_dropped();
        tracing::debug!(event, "tool hook payload unusable");
    }
    json_response(StatusCode::OK, &json!({}))
}

async fn hook(
    State(state): State<Arc<AppState>>,
    Path(event): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if is_tool_event(&event) {
        return tool_hook(&state, &event, &headers, &body);
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("body is not valid JSON");
    };
    let ts = now_ms();
    let normalized = normalize_hook(
        &state.identity,
        &state.allow,
        &event,
        &parsed,
        ts,
        fresh_id(ts),
    );
    let envelope = match normalized {
        Ok(Some(envelope)) => envelope,
        Ok(None) => {
            tracing::debug!(event, "hook event not recorded");
            return json_response(StatusCode::OK, &json!({}));
        }
        Err(err) => return bad_request(&err.to_string()),
    };
    let key = state.repeat_key(&event, &body);
    if key.is_some_and(|key| state.is_repeat(key)) {
        tracing::debug!(event, "dropped repeated hook body");
        return json_response(StatusCode::OK, &json!({}));
    }
    match state.store(envelope).await {
        Ok(outcome) => {
            if let Some(key) = key.filter(|_| outcome != Enqueued::Dropped) {
                state.remember(key);
            }
            tracing::debug!(event, "hook accepted");
            json_response(StatusCode::OK, &json!({}))
        }
        Err(err) => server_error(&err),
    }
}

async fn event(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let envelope = match serde_json::from_slice::<Envelope>(&body) {
        Ok(envelope) => envelope,
        Err(err) => return bad_request(&format!("invalid envelope: {err}")),
    };
    if !envelope.payload.is_object() {
        return bad_request("payload must be a JSON object");
    }
    if envelope.kind.is_empty() {
        return bad_request("kind must not be empty");
    }
    match state.store(envelope).await {
        Ok(Enqueued::Stored { seq }) => {
            json_response(StatusCode::OK, &json!({ "seq": seq, "duplicate": false }))
        }
        Ok(Enqueued::Duplicate { seq }) => {
            json_response(StatusCode::OK, &json!({ "seq": seq, "duplicate": true }))
        }
        Ok(Enqueued::Dropped) => json_response(
            StatusCode::OK,
            &json!({ "seq": null, "duplicate": false, "dropped": true }),
        ),
        Err(err) => server_error(&err),
    }
}

fn host_is_loopback(host: Option<&HeaderValue>) -> bool {
    let Some(host) = host else { return true };
    let Ok(host) = host.to_str() else {
        return false;
    };
    let name = if host.starts_with('[') {
        host.find(']').map_or(host, |end| &host[..=end])
    } else {
        host.split_once(':').map_or(host, |(name, _)| name)
    };
    ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

async fn loopback_guard(request: Request, next: Next) -> Response {
    let headers = request.headers();
    if headers.contains_key(header::ORIGIN) || !host_is_loopback(headers.get(header::HOST)) {
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({ "error": "browser and non-loopback requests are refused" }),
        );
    }
    next.run(request).await
}

fn hook_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/hook/{event}", post(hook))
}

/// Routes for the loopback TCP listener: `GET /healthz` and `POST /hook/{event}`.
///
/// Bodies are capped at 1 MiB. A request is refused with 403 when it carries an
/// `Origin` header, which a browser adds to cross-site requests, or when its `Host`
/// names anything but `127.0.0.1`, `localhost` or `[::1]`, which blocks DNS rebinding.
/// A missing `Host` passes. The guard is no authentication: any local process can post.
pub fn hook_router(state: Arc<AppState>) -> Router {
    hook_routes()
        .with_state(state)
        .layer(middleware::from_fn(loopback_guard))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Routes for the unix socket.
///
/// Adds `POST /event`, which takes an envelope as JSON, to the hook routes. Bodies are capped at 1 MiB. Access is gated by the socket's file
/// mode, so the Origin and Host checks of [`hook_router`] do not apply.
pub fn socket_router(state: Arc<AppState>) -> Router {
    hook_routes()
        .route("/event", post(event))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}
