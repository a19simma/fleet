//! Maps events to the session rows they change. Pure: no IO.

use fleet_core::{Envelope, kind};
use serde_json::Value;

const DEFAULT_SESSION_KIND: &str = "claude";

/// Lifecycle state of a session row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Seen alive, no prompt running.
    Active,
    /// A prompt is running.
    Working,
    /// The last turn stopped.
    Idle,
    /// No progress for the stall window.
    Stalled,
    /// The session ended.
    Ended,
    /// The session died without ending. No event kind sets it yet.
    Crashed,
}

impl State {
    /// The lowercase name stored in `sessions.state`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Working => "working",
            Self::Idle => "idle",
            Self::Stalled => "stalled",
            Self::Ended => "ended",
            Self::Crashed => "crashed",
        }
    }

    /// Parses a stored name, or `None` for an unknown one.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "working" => Some(Self::Working),
            "idle" => Some(Self::Idle),
            "stalled" => Some(Self::Stalled),
            "ended" => Some(Self::Ended),
            "crashed" => Some(Self::Crashed),
            _ => None,
        }
    }
}

/// How one new event changes its session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    /// Session the event belongs to.
    pub session_id: String,
    /// Session kind, `claude` unless the payload names one.
    pub session_kind: String,
    /// State the event sets.
    pub state: State,
    /// Whether the event may create the session row when none exists.
    pub creates_row: bool,
    /// Whether `state` applies to an existing row. False leaves an existing row's state.
    pub apply_state: bool,
    /// Whether the event may move an `ended` row out of `ended`.
    pub reopen: bool,
    /// Working directory to record.
    pub workdir: Option<String>,
    /// Prompt text to record as the last prompt.
    pub prompt: Option<String>,
    /// Assistant text to record as the last message.
    pub message: Option<String>,
    /// Notification text to record.
    pub notification: Option<String>,
}

fn text(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn is_synthetic(payload: &Value) -> bool {
    payload.get("synthetic").and_then(Value::as_bool) == Some(true)
}

/// Maps an event to its session projection, or `None` when the event touches no session.
///
/// A row that is `ended` reopens only on `hook.session_start` or a non-synthetic
/// `hook.user_prompt_submit`. `session.discovered` sets state only when no row exists.
/// `hook.notification` records its text on an existing row and never creates one.
pub fn project(env: &Envelope) -> Option<Projection> {
    let session_id = env.session_id.as_deref().filter(|id| !id.is_empty())?;
    let payload = &env.payload;
    let mut projection = Projection {
        session_id: session_id.to_owned(),
        session_kind: text(payload, "kind").unwrap_or_else(|| DEFAULT_SESSION_KIND.to_owned()),
        state: State::Active,
        creates_row: true,
        apply_state: true,
        reopen: false,
        workdir: env.workdir.clone().or_else(|| text(payload, "cwd")),
        prompt: None,
        message: None,
        notification: None,
    };
    match env.kind.as_str() {
        kind::HOOK_SESSION_START => projection.reopen = true,
        kind::HOOK_USER_PROMPT_SUBMIT => {
            if is_synthetic(payload) {
                return None;
            }
            projection.state = State::Working;
            projection.reopen = true;
            projection.prompt = text(payload, "prompt");
        }
        kind::HOOK_STOP => {
            projection.state = State::Idle;
            projection.message = text(payload, "last_assistant_message");
        }
        kind::HOOK_SESSION_END | "session.ended_unseen" => {
            projection.state = State::Ended;
            projection.message = text(payload, "last_assistant_message");
        }
        kind::HOOK_NOTIFICATION => {
            projection.apply_state = false;
            projection.creates_row = false;
            projection.notification = text(payload, "message");
        }
        "session.stalled" => projection.state = State::Stalled,
        "session.discovered" => projection.apply_state = false,
        _ => return None,
    }
    Some(projection)
}

#[cfg(test)]
mod tests {
    use fleet_core::{EventId, Identity, Source};
    use serde_json::json;

    use super::*;

    fn event(event_kind: &str, payload: Value) -> Envelope {
        let identity = Identity {
            box_name: format!("box-{}", 1),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "b".into(),
        };
        let mut env = Envelope::new(
            &identity,
            EventId::derive(event_kind, &["x"]),
            Source::Hook,
            event_kind,
            1,
        );
        env.session_id = Some("s".into());
        env.payload = payload;
        env
    }

    #[test]
    fn prompt_sets_working_and_last_prompt() {
        let got = project(&event(
            "hook.user_prompt_submit",
            json!({"prompt": "do it", "synthetic": false}),
        ))
        .unwrap();
        assert_eq!(got.state, State::Working);
        assert!(got.apply_state && got.reopen);
        assert_eq!(got.prompt.as_deref(), Some("do it"));
    }

    #[test]
    fn synthetic_prompt_changes_nothing() {
        let env = event(
            "hook.user_prompt_submit",
            json!({"prompt": "<agent-message from=\"a\">x</agent-message>", "synthetic": true}),
        );
        assert_eq!(project(&env), None);
    }

    #[test]
    fn stop_sets_idle_without_reopening() {
        let got = project(&event("hook.stop", json!({"last_assistant_message": "ok"}))).unwrap();
        assert_eq!(got.state, State::Idle);
        assert!(got.apply_state && !got.reopen);
        assert_eq!(got.message.as_deref(), Some("ok"));
    }

    #[test]
    fn notification_never_touches_state() {
        let got = project(&event("hook.notification", json!({"message": "needs you"}))).unwrap();
        assert!(!got.apply_state && !got.creates_row);
        assert_eq!(got.notification.as_deref(), Some("needs you"));
    }

    #[test]
    fn discovered_applies_state_only_on_insert() {
        let got = project(&event("session.discovered", json!({"cwd": "/w"}))).unwrap();
        assert!(!got.apply_state);
        assert_eq!(got.state, State::Active);
        assert_eq!(got.workdir.as_deref(), Some("/w"));
    }

    #[test]
    fn derived_and_lifecycle_kinds_map_to_states() {
        let cases = [
            ("hook.session_start", State::Active, true),
            ("hook.session_end", State::Ended, false),
            ("session.ended_unseen", State::Ended, false),
            ("session.stalled", State::Stalled, false),
        ];
        for (event_kind, state, reopen) in cases {
            let got = project(&event(event_kind, json!({}))).unwrap();
            assert_eq!((got.state, got.reopen), (state, reopen), "{event_kind}");
        }
    }

    #[test]
    fn unrelated_kinds_and_missing_session_are_skipped() {
        assert_eq!(project(&event("hook.pre_tool_use", json!({}))), None);
        let mut env = event("hook.stop", json!({}));
        env.session_id = None;
        assert_eq!(project(&env), None);
        env.session_id = Some(String::new());
        assert_eq!(project(&env), None);
    }

    #[test]
    fn state_names_roundtrip() {
        for state in [
            State::Active,
            State::Working,
            State::Idle,
            State::Stalled,
            State::Ended,
            State::Crashed,
        ] {
            assert_eq!(State::parse(state.as_str()), Some(state));
        }
        assert_eq!(State::parse("other"), None);
    }
}
