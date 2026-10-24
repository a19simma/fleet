use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::EventId;

/// Envelope schema version emitted by this build.
pub const SCHEMA_VERSION: u32 = 1;

const fn schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Event kind names shared by the normalizer and the priority rules.
pub mod kind {
    /// Claude Code `SessionStart` hook.
    pub const HOOK_SESSION_START: &str = "hook.session_start";
    /// Claude Code `UserPromptSubmit` hook.
    pub const HOOK_USER_PROMPT_SUBMIT: &str = "hook.user_prompt_submit";
    /// Claude Code `PreToolUse` hook.
    pub const HOOK_PRE_TOOL_USE: &str = "hook.pre_tool_use";
    /// Claude Code `PostToolUse` hook.
    pub const HOOK_POST_TOOL_USE: &str = "hook.post_tool_use";
    /// Claude Code `Stop` hook.
    pub const HOOK_STOP: &str = "hook.stop";
    /// Claude Code `Notification` hook.
    pub const HOOK_NOTIFICATION: &str = "hook.notification";
    /// Claude Code `SessionEnd` hook.
    pub const HOOK_SESSION_END: &str = "hook.session_end";
    /// Prefix of every kind a hook produces.
    pub const HOOK_PREFIX: &str = "hook.";
    /// A workmux agent changed status.
    pub const WORKMUX_STATUS_CHANGED: &str = "workmux.status_changed";
    /// A pueue task finished.
    pub const PUEUE_TASK_FINISHED: &str = "pueue.task_finished";
    /// A Fleet job reported its result.
    pub const JOB_RESULT: &str = "job.result";
    /// Prefix of derived session events.
    pub const SESSION_PREFIX: &str = "session.";
}

/// Who produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The event came from a Claude Code hook.
    Hook,
    /// The event came from the workmux watcher.
    Workmux,
    /// The event came from pueue.
    Pueue,
    /// The event came from a Fleet job wrapper.
    Job,
    /// The event came from fleetd itself.
    Fleetd,
    /// The event came from the registry reconciler.
    Reconcile,
}

/// Identity of the box an event came from.
///
/// This crate does no IO. The caller reads the hostname, `/etc/machine-id` and the boot id
/// once at start and passes them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Configured box name.
    pub box_name: String,
    /// Box hostname.
    pub hostname: String,
    /// Contents of `/etc/machine-id`.
    pub machine_id: String,
    /// Contents of `/proc/sys/kernel/random/boot_id`.
    pub boot_id: String,
}

/// Queue priority. Lower values drop first when the queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Tool use events.
    Tool = 0,
    /// Repeated status changes.
    Status = 1,
    /// Everything else.
    Normal = 2,
    /// `Stop`, `SessionEnd`, pueue task and job results and derived session events.
    Terminal = 3,
}

impl Priority {
    /// Ranks an event kind per the backpressure rules in the plan.
    ///
    /// Every `workmux.status_changed` ranks as [`Priority::Status`]. Only `hook.stop`,
    /// `hook.session_end`, `pueue.task_finished`, `job.result` and `session.*` kinds rank
    /// as [`Priority::Terminal`]. Pre and post tool use hooks rank as [`Priority::Tool`].
    pub fn of_kind(event_kind: &str) -> Self {
        match event_kind {
            kind::WORKMUX_STATUS_CHANGED => Self::Status,
            kind::HOOK_STOP
            | kind::HOOK_SESSION_END
            | kind::PUEUE_TASK_FINISHED
            | kind::JOB_RESULT => Self::Terminal,
            kind::HOOK_PRE_TOOL_USE | kind::HOOK_POST_TOOL_USE => Self::Tool,
            other if other.starts_with(kind::SESSION_PREFIX) => Self::Terminal,
            _ => Self::Normal,
        }
    }
}

/// The one record every event source produces. It carries no sequence number: fleetd
/// assigns `seq` when the event commits to the disk queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Event id, unique per event.
    pub id: EventId,
    /// Schema version of this envelope.
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// Configured box name.
    #[serde(rename = "box")]
    pub box_name: String,
    /// Box hostname at capture.
    pub hostname: String,
    /// Machine id.
    pub machine_id: String,
    /// Boot id.
    pub boot_id: String,
    /// Producer of the event.
    pub source: Source,
    /// Event kind such as `hook.stop`.
    pub kind: String,
    /// Box clock at capture, milliseconds since the Unix epoch.
    pub ts: u64,
    /// Claude session id when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Claude prompt id, the correlation id of one turn, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_id: Option<String>,
    /// Working directory of the session when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Time the source says the event happened, milliseconds since the Unix epoch, when
    /// known. Advisory: the box clock `ts` is the capture time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<u64>,
    /// Kind specific JSON object.
    pub payload: Value,
}

impl Envelope {
    /// Builds an envelope from the box identity and event fields.
    ///
    /// The schema version is [`SCHEMA_VERSION`], `session_id`, `prompt_id`, `workdir` and
    /// `occurred_at` are `None` and the payload is an empty JSON object.
    pub fn new(identity: &Identity, id: EventId, source: Source, kind: &str, ts: u64) -> Self {
        Self {
            id,
            schema_version: SCHEMA_VERSION,
            box_name: identity.box_name.clone(),
            hostname: identity.hostname.clone(),
            machine_id: identity.machine_id.clone(),
            boot_id: identity.boot_id.clone(),
            source,
            kind: kind.to_owned(),
            ts,
            session_id: None,
            prompt_id: None,
            workdir: None,
            occurred_at: None,
            payload: Value::Object(serde_json::Map::new()),
        }
    }

    /// Queue priority of this event.
    pub fn priority(&self) -> Priority {
        Priority::of_kind(&self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ranks_kinds() {
        assert_eq!(Priority::of_kind("hook.pre_tool_use"), Priority::Tool);
        assert_eq!(Priority::of_kind("hook.post_tool_use"), Priority::Tool);
        assert_eq!(
            Priority::of_kind("workmux.status_changed"),
            Priority::Status
        );
        assert_eq!(
            Priority::of_kind("hook.user_prompt_submit"),
            Priority::Normal
        );
        assert_eq!(Priority::of_kind("hook.stop"), Priority::Terminal);
        assert_eq!(Priority::of_kind("hook.session_end"), Priority::Terminal);
        assert_eq!(
            Priority::of_kind("session.ended_unseen"),
            Priority::Terminal
        );
        assert_eq!(Priority::of_kind("pueue.task_finished"), Priority::Terminal);
        assert!(Priority::Tool < Priority::Status && Priority::Status < Priority::Terminal);
    }

    #[test]
    fn envelope_roundtrips_and_renames_box() {
        let identity = Identity {
            box_name: "alpha".into(),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "b".into(),
        };
        let env = Envelope::new(
            &identity,
            EventId::new(1, 2),
            Source::Fleetd,
            "fleetd.started",
            5,
        );
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["box"], "alpha");
        assert_eq!(json["source"], "fleetd");
        assert!(json.get("session_id").is_none());
        assert_eq!(serde_json::from_value::<Envelope>(json).unwrap(), env);
    }

    #[test]
    fn new_fields_roundtrip_when_set() {
        let identity = Identity {
            box_name: "alpha".into(),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "b".into(),
        };
        let mut env = Envelope::new(&identity, EventId::new(1, 2), Source::Hook, "hook.stop", 5);
        env.workdir = Some("/work/repo".into());
        env.occurred_at = Some(4);
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["workdir"], "/work/repo");
        assert_eq!(json["occurred_at"], 4);
        assert_eq!(serde_json::from_value::<Envelope>(json).unwrap(), env);
    }

    #[test]
    fn old_json_without_new_fields_deserializes() {
        let json = serde_json::json!({
            "id": EventId::new(1, 2).to_string(),
            "schema_version": 1,
            "box": "alpha",
            "hostname": "h",
            "machine_id": "m",
            "boot_id": "b",
            "source": "hook",
            "kind": "hook.stop",
            "ts": 9,
            "payload": {}
        });
        let env = serde_json::from_value::<Envelope>(json).unwrap();
        assert_eq!(env.workdir, None);
        assert_eq!(env.occurred_at, None);
    }
}
