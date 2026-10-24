use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::{Envelope, Error, EventId, Identity, Source, kind};

const DEFAULT_EVENTS: [&str; 5] = [
    "SessionStart",
    "UserPromptSubmit",
    "Stop",
    "Notification",
    "SessionEnd",
];
const COMMON_FIELDS: [&str; 4] = ["session_id", "transcript_path", "cwd", "hook_event_name"];
const SYNTHETIC_PREFIX: &str = "<agent-message from=";

/// The hook event names fleetd records. Every other name is dropped.
///
/// The default allowlist is `SessionStart`, `UserPromptSubmit`, `Stop`, `Notification`
/// and `SessionEnd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookAllowlist(BTreeSet<String>);

impl HookAllowlist {
    /// Builds an allowlist from event names such as `Stop`.
    pub fn new<I, S>(events: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(events.into_iter().map(Into::into).collect())
    }

    /// True when the event is recorded.
    pub fn contains(&self, event: &str) -> bool {
        self.0.contains(event)
    }
}

/// The default allowlist of five session lifecycle events.
impl Default for HookAllowlist {
    fn default() -> Self {
        Self::new(DEFAULT_EVENTS)
    }
}

fn event_kind(event: &str) -> String {
    let known = match event {
        "SessionStart" => kind::HOOK_SESSION_START,
        "UserPromptSubmit" => kind::HOOK_USER_PROMPT_SUBMIT,
        "PreToolUse" => kind::HOOK_PRE_TOOL_USE,
        "PostToolUse" => kind::HOOK_POST_TOOL_USE,
        "Stop" => kind::HOOK_STOP,
        "Notification" => kind::HOOK_NOTIFICATION,
        "SessionEnd" => kind::HOOK_SESSION_END,
        other => {
            let safe: String = other
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            return format!("{}{safe}", kind::HOOK_PREFIX);
        }
    };
    known.to_owned()
}

fn copy_fields(from: &Map<String, Value>, to: &mut Map<String, Value>, keys: &[&str]) {
    for key in keys {
        if let Some(value) = from.get(*key).filter(|v| !v.is_null()) {
            to.insert((*key).to_owned(), value.clone());
        }
    }
}

/// Turns the body of a Claude Code hook POST into an [`Envelope`].
///
/// The event name comes from the URL path. The body carries it as `hook_event_name`, but
/// that field is not trusted for routing. Known events map to fixed kinds. Any other
/// allowlisted name becomes `hook.` plus its lowercased ASCII letters and digits, with
/// other characters turned into `_`.
/// Returns `Ok(None)` when the event is not on the allowlist. The payload keeps the
/// verbatim body under `raw` beside the normalized subset from the plan. A missing
/// `prompt_id` is tolerated.
///
/// # Errors
///
/// Returns [`Error::NotAnObject`] when the body is not a JSON object.
pub fn normalize_hook(
    identity: &Identity,
    allow: &HookAllowlist,
    event: &str,
    body: &Value,
    ts: u64,
    id: EventId,
) -> Result<Option<Envelope>, Error> {
    let object = body.as_object().ok_or(Error::NotAnObject)?;
    if !allow.contains(event) {
        return Ok(None);
    }
    let mut envelope = Envelope::new(identity, id, Source::Hook, &event_kind(event), ts);
    let text = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    envelope.session_id = text("session_id");
    envelope.prompt_id = text("prompt_id");

    let mut payload = Map::new();
    copy_fields(object, &mut payload, &COMMON_FIELDS);
    match event {
        "UserPromptSubmit" => {
            copy_fields(object, &mut payload, &["prompt", "permission_mode"]);
            let synthetic = object
                .get("prompt")
                .and_then(Value::as_str)
                .is_some_and(|p| p.starts_with(SYNTHETIC_PREFIX));
            payload.insert("synthetic".to_owned(), Value::Bool(synthetic));
        }
        "Stop" => copy_fields(
            object,
            &mut payload,
            &[
                "last_assistant_message",
                "stop_hook_active",
                "permission_mode",
                "effort",
                "background_tasks",
                "session_crons",
            ],
        ),
        "Notification" => copy_fields(object, &mut payload, &["message", "notification_type"]),
        "SessionEnd" => copy_fields(object, &mut payload, &["reason"]),
        _ => {}
    }
    payload.insert("raw".to_owned(), body.clone());
    envelope.payload = Value::Object(payload);
    Ok(Some(envelope))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn identity() -> Identity {
        Identity {
            box_name: "alpha".into(),
            hostname: "host".into(),
            machine_id: "mid".into(),
            boot_id: "bid".into(),
        }
    }

    fn run(event: &str, body: &Value) -> Option<Envelope> {
        normalize_hook(
            &identity(),
            &HookAllowlist::default(),
            event,
            body,
            1_790_000_000_000,
            EventId::new(1, 1),
        )
        .unwrap()
    }

    fn user_prompt(prompt: &str) -> Value {
        json!({
            "cwd": "/work/wd",
            "hook_event_name": "UserPromptSubmit",
            "permission_mode": "auto",
            "prompt": prompt,
            "prompt_id": "p-1",
            "session_id": "s-1",
            "transcript_path": "/work/.claude/projects/wd/s-1.jsonl"
        })
    }

    #[test]
    fn user_prompt_submit_maps_fields() {
        let body = user_prompt("reply with ok");
        let env = run("UserPromptSubmit", &body).unwrap();
        assert_eq!(env.kind, "hook.user_prompt_submit");
        assert_eq!(env.source, Source::Hook);
        assert_eq!(env.session_id.as_deref(), Some("s-1"));
        assert_eq!(env.prompt_id.as_deref(), Some("p-1"));
        assert_eq!(env.box_name, "alpha");
        assert_eq!(env.ts, 1_790_000_000_000);
        assert_eq!(env.payload["prompt"], "reply with ok");
        assert_eq!(env.payload["permission_mode"], "auto");
        assert_eq!(env.payload["cwd"], "/work/wd");
        assert_eq!(env.payload["synthetic"], false);
        assert_eq!(env.payload["raw"], body);
    }

    #[test]
    fn hand_back_prompt_is_synthetic_and_kept() {
        let body = user_prompt("<agent-message from=\"reviewer\">done</agent-message>");
        let env = run("UserPromptSubmit", &body).unwrap();
        assert_eq!(env.payload["synthetic"], true);
        assert_eq!(env.payload["raw"]["prompt"], body["prompt"]);
    }

    #[test]
    fn stop_maps_fields() {
        let body = json!({
            "session_id": "s-1",
            "transcript_path": "/t.jsonl",
            "cwd": "/work/wd",
            "prompt_id": "p-1",
            "permission_mode": "auto",
            "effort": {"level": "low"},
            "hook_event_name": "Stop",
            "stop_hook_active": false,
            "last_assistant_message": "ok",
            "background_tasks": [],
            "session_crons": []
        });
        let env = run("Stop", &body).unwrap();
        assert_eq!(env.kind, "hook.stop");
        assert_eq!(env.payload["last_assistant_message"], "ok");
        assert_eq!(env.payload["effort"], json!({"level": "low"}));
        assert_eq!(env.payload["stop_hook_active"], false);
        assert_eq!(env.payload["background_tasks"], json!([]));
        assert_eq!(env.payload["transcript_path"], "/t.jsonl");
    }

    #[test]
    fn notification_maps_fields() {
        let body = json!({
            "cwd": "/work/wd",
            "hook_event_name": "Notification",
            "message": "Claude needs your permission",
            "notification_type": "permission_prompt",
            "prompt_id": "p-1",
            "session_id": "s-1",
            "transcript_path": "/t.jsonl"
        });
        let env = run("Notification", &body).unwrap();
        assert_eq!(env.kind, "hook.notification");
        assert_eq!(env.payload["message"], "Claude needs your permission");
        assert_eq!(env.payload["notification_type"], "permission_prompt");
    }

    #[test]
    fn session_end_tolerates_missing_prompt_id() {
        let body = json!({
            "cwd": "/work/wd",
            "hook_event_name": "SessionEnd",
            "reason": "other",
            "session_id": "s-1",
            "transcript_path": "/t.jsonl"
        });
        let env = run("SessionEnd", &body).unwrap();
        assert_eq!(env.kind, "hook.session_end");
        assert_eq!(env.prompt_id, None);
        assert_eq!(env.payload["reason"], "other");
        assert_eq!(env.payload["raw"], body);
    }

    #[test]
    fn unlisted_events_are_dropped_and_allowlist_extends() {
        let body = json!({"session_id": "s-1", "tool_name": "Bash"});
        assert!(run("PreToolUse", &body).is_none());
        let allow = HookAllowlist::new(["PreToolUse"]);
        let env = normalize_hook(
            &identity(),
            &allow,
            "PreToolUse",
            &body,
            1,
            EventId::new(1, 1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(env.kind, "hook.pre_tool_use");
        assert_eq!(env.payload["raw"], body);
    }

    #[test]
    fn rejects_non_object_bodies() {
        let err = normalize_hook(
            &identity(),
            &HookAllowlist::default(),
            "Stop",
            &json!([1]),
            1,
            EventId::new(1, 1),
        );
        assert_eq!(err, Err(Error::NotAnObject));
    }

    #[test]
    fn event_kind_maps_known_and_sanitizes_unknown() {
        assert_eq!(event_kind("UserPromptSubmit"), "hook.user_prompt_submit");
        assert_eq!(event_kind("PostToolUse"), "hook.post_tool_use");
        assert_eq!(event_kind("Weird/Event.X"), "hook.weird_event_x");
    }

    #[test]
    fn empty_ids_become_none() {
        let env = run("Stop", &json!({"session_id": "", "prompt_id": ""})).unwrap();
        assert_eq!(env.session_id, None);
        assert_eq!(env.prompt_id, None);
    }
}
