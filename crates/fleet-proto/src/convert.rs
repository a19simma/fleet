use std::fmt;

use fleet_core::capability::Capability;
use fleet_core::catalog::{CatalogEntry, CatalogError, CatalogItem, CatalogKind};
use fleet_core::model_allowlist::{ModelAllowlist, ModelAllowlistError};
use fleet_core::timing::{Interval, Span, SpanKind, Summary};
use fleet_core::{
    BoxName, Envelope, EventId, MAX_SELECTION, Selection, SelectionError, Source, Visibility,
};
use serde_json::Value;

use crate::{
    MAX_COMMAND_BYTES, MAX_COMMAND_ID_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SPANS,
    MAX_TIMING_NAME_BYTES, v1,
};

/// Why a wire envelope could not become a [`fleet_core::Envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConvertError {
    /// The `box` field is not a valid box name. The raw value is not kept, so an error
    /// message never echoes client input.
    InvalidBox,
    /// The `id` field is not a valid event id.
    InvalidId(String),
    /// The `source` field names no known source.
    InvalidSource(String),
    /// The `payload_json` field is not valid JSON.
    InvalidPayload(String),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBox => f.write_str("invalid box name"),
            Self::InvalidId(raw) => write!(f, "invalid event id: {raw:?}"),
            Self::InvalidSource(raw) => write!(f, "unknown source: {raw:?}"),
            Self::InvalidPayload(why) => write!(f, "payload is not valid JSON: {why}"),
        }
    }
}

impl std::error::Error for ConvertError {}

impl From<&Envelope> for v1::Envelope {
    fn from(env: &Envelope) -> Self {
        Self {
            id: env.id.to_string(),
            schema_version: env.schema_version,
            r#box: env.box_name.clone(),
            hostname: env.hostname.clone(),
            machine_id: env.machine_id.clone(),
            boot_id: env.boot_id.clone(),
            source: env.source.as_str().to_owned(),
            kind: env.kind.clone(),
            ts_ms: env.ts,
            session_id: env.session_id.clone(),
            prompt_id: env.prompt_id.clone(),
            workdir: env.workdir.clone(),
            occurred_at_ms: env.occurred_at,
            payload_json: env.payload.to_string(),
        }
    }
}

/// Validates a client-supplied box name.
///
/// This is the one place a raw box string is checked, for envelopes and heartbeats
/// alike. The error never carries the raw value.
///
/// # Errors
///
/// Returns [`ConvertError::InvalidBox`] when `raw` is not a valid box name.
pub fn validate_box(raw: &str) -> Result<BoxName, ConvertError> {
    BoxName::new(raw).map_err(|_| ConvertError::InvalidBox)
}

impl TryFrom<v1::Envelope> for Envelope {
    type Error = ConvertError;

    fn try_from(wire: v1::Envelope) -> Result<Self, Self::Error> {
        validate_box(&wire.r#box)?;
        let id = wire
            .id
            .parse::<EventId>()
            .map_err(|_| ConvertError::InvalidId(wire.id.clone()))?;
        let source = wire
            .source
            .parse::<Source>()
            .map_err(|_| ConvertError::InvalidSource(wire.source.clone()))?;
        let payload = serde_json::from_str::<Value>(&wire.payload_json)
            .map_err(|err| ConvertError::InvalidPayload(err.to_string()))?;
        Ok(Self {
            id,
            schema_version: wire.schema_version,
            box_name: wire.r#box,
            hostname: wire.hostname,
            machine_id: wire.machine_id,
            boot_id: wire.boot_id,
            source,
            kind: wire.kind,
            ts: wire.ts_ms,
            session_id: wire.session_id,
            prompt_id: wire.prompt_id,
            workdir: wire.workdir,
            occurred_at: wire.occurred_at_ms,
            payload,
        })
    }
}

/// Wraps an envelope and its queue sequence number as a wire [`v1::QueuedEvent`].
pub fn queued_event(seq: u64, envelope: &Envelope) -> v1::QueuedEvent {
    v1::QueuedEvent {
        seq,
        envelope: Some(envelope.into()),
    }
}

/// Why a wire timing message could not become a core timing value. No variant keeps the
/// input, so an error message never echoes client text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimingConvertError {
    /// The span kind is unspecified or unknown to this build.
    UnknownSpanKind,
    /// A millisecond field exceeds the largest value the store keeps, `i64::MAX`.
    OutOfRange(&'static str),
    /// An end lies before its start.
    Reversed(&'static str),
    /// The summary `wall_ms` differs from the sum of its five parts.
    WallMismatch,
    /// A required text field is empty.
    Empty(&'static str),
    /// A text field is over its byte cap.
    TooLong(&'static str),
    /// A text field holds a character it may not: a control character, U+2028 or U+2029, or
    /// for a command id a byte outside `[A-Za-z0-9_.:-]`.
    InvalidText(&'static str),
    /// A list is over its cap.
    TooMany(&'static str),
}

impl fmt::Display for TimingConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSpanKind => f.write_str("unknown timing span kind"),
            Self::OutOfRange(field) => write!(f, "timing field {field} is out of range"),
            Self::Reversed(field) => write!(f, "timing field {field} ends before it starts"),
            Self::WallMismatch => f.write_str("timing wall time differs from the sum of its parts"),
            Self::Empty(field) => write!(f, "timing field {field} is empty"),
            Self::TooLong(field) => write!(f, "timing field {field} is too long"),
            Self::InvalidText(field) => write!(f, "timing field {field} has an illegal character"),
            Self::TooMany(field) => write!(f, "too many timing {field}"),
        }
    }
}

impl std::error::Error for TimingConvertError {}

/// A validated timing span: the core [`Span`] plus its name and optional tool use id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingSpanRecord {
    /// Kind and interval.
    pub span: Span,
    /// Span name, 1 to [`MAX_TIMING_NAME_BYTES`] bytes of single-line text.
    pub name: String,
    /// Tool use id when known, same rules as `name`.
    pub tool_use_id: Option<String>,
}

/// A validated shell command record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommandRecord {
    /// Command id, [`crate::validate_shell_log_command_id`] rules.
    pub id: String,
    /// Redacted command line, 1 to [`MAX_COMMAND_BYTES`] bytes.
    pub command: String,
    /// True for a background command.
    pub background: bool,
    /// Start in milliseconds on the job clock.
    pub started_ms: u64,
    /// End in milliseconds, never before `started_ms`.
    pub ended_ms: Option<u64>,
    /// Run time in milliseconds.
    pub duration_ms: u64,
    /// Exit code when known.
    pub exit_code: Option<i32>,
    /// Redacted log, at most [`MAX_SHELL_LOG_BYTES`] bytes.
    pub log: String,
    /// True when the log was cut.
    pub log_truncated: bool,
    /// Why a command ended without an exit code, same rules as a span name.
    pub ended_by: Option<String>,
}

fn stored_ms(field: &'static str, value: u64) -> Result<u64, TimingConvertError> {
    if i64::try_from(value).is_ok() {
        Ok(value)
    } else {
        Err(TimingConvertError::OutOfRange(field))
    }
}

fn bounded(field: &'static str, text: &str, max: usize) -> Result<(), TimingConvertError> {
    if text.is_empty() {
        return Err(TimingConvertError::Empty(field));
    }
    if text.len() > max {
        return Err(TimingConvertError::TooLong(field));
    }
    Ok(())
}

fn single_line(field: &'static str, text: &str) -> Result<(), TimingConvertError> {
    bounded(field, text, MAX_TIMING_NAME_BYTES)?;
    if text
        .chars()
        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
    {
        return Err(TimingConvertError::InvalidText(field));
    }
    Ok(())
}

fn command_id(field: &'static str, text: &str) -> Result<(), TimingConvertError> {
    bounded(field, text, MAX_COMMAND_ID_BYTES)?;
    if crate::validate_shell_log_command_id(text) {
        Ok(())
    } else {
        Err(TimingConvertError::InvalidText(field))
    }
}

fn wire_kind(kind: SpanKind) -> Result<v1::TimingSpanKind, TimingConvertError> {
    match kind {
        SpanKind::ApiWait => Ok(v1::TimingSpanKind::Api),
        SpanKind::Tool => Ok(v1::TimingSpanKind::Tool),
        SpanKind::Shell => Ok(v1::TimingSpanKind::Shell),
        SpanKind::BgShell => Ok(v1::TimingSpanKind::BgShell),
        _ => Err(TimingConvertError::UnknownSpanKind),
    }
}

fn core_kind(raw: i32) -> Result<SpanKind, TimingConvertError> {
    match v1::TimingSpanKind::try_from(raw) {
        Ok(v1::TimingSpanKind::Api) => Ok(SpanKind::ApiWait),
        Ok(v1::TimingSpanKind::Tool) => Ok(SpanKind::Tool),
        Ok(v1::TimingSpanKind::Shell) => Ok(SpanKind::Shell),
        Ok(v1::TimingSpanKind::BgShell) => Ok(SpanKind::BgShell),
        Ok(v1::TimingSpanKind::Unspecified) | Err(_) => Err(TimingConvertError::UnknownSpanKind),
    }
}

impl From<&Summary> for v1::TimingSummary {
    fn from(summary: &Summary) -> Self {
        Self {
            wall_ms: summary.total_ms(),
            api_wait_ms: summary.api_wait_ms,
            tool_ms: summary.tool_ms,
            shell_ms: summary.shell_ms,
            idle_ms: summary.idle_ms,
            overhead_ms: summary.overhead_ms,
        }
    }
}

impl TryFrom<v1::TimingSummary> for Summary {
    type Error = TimingConvertError;

    fn try_from(wire: v1::TimingSummary) -> Result<Self, Self::Error> {
        let summary = Self {
            api_wait_ms: stored_ms("api_wait_ms", wire.api_wait_ms)?,
            tool_ms: stored_ms("tool_ms", wire.tool_ms)?,
            shell_ms: stored_ms("shell_ms", wire.shell_ms)?,
            idle_ms: stored_ms("idle_ms", wire.idle_ms)?,
            overhead_ms: stored_ms("overhead_ms", wire.overhead_ms)?,
        };
        let wall = stored_ms("wall_ms", wire.wall_ms)?;
        if summary.total_ms() != wall {
            return Err(TimingConvertError::WallMismatch);
        }
        Ok(summary)
    }
}

impl TryFrom<&TimingSpanRecord> for v1::TimingSpan {
    type Error = TimingConvertError;

    fn try_from(record: &TimingSpanRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: wire_kind(record.span.kind)? as i32,
            start_ms: record.span.interval.start_ms(),
            end_ms: record.span.interval.end_ms(),
            name: record.name.clone(),
            tool_use_id: record.tool_use_id.clone(),
        })
    }
}

impl TryFrom<v1::TimingSpan> for TimingSpanRecord {
    type Error = TimingConvertError;

    fn try_from(wire: v1::TimingSpan) -> Result<Self, Self::Error> {
        let kind = core_kind(wire.kind)?;
        let start = stored_ms("start_ms", wire.start_ms)?;
        let end = stored_ms("end_ms", wire.end_ms)?;
        let interval =
            Interval::new(start, end).map_err(|_| TimingConvertError::Reversed("end_ms"))?;
        single_line("name", &wire.name)?;
        if let Some(id) = &wire.tool_use_id {
            single_line("tool_use_id", id)?;
        }
        Ok(Self {
            span: Span { kind, interval },
            name: wire.name,
            tool_use_id: wire.tool_use_id,
        })
    }
}

impl From<&ShellCommandRecord> for v1::ShellCommand {
    fn from(record: &ShellCommandRecord) -> Self {
        Self {
            id: record.id.clone(),
            command: record.command.clone(),
            background: record.background,
            started_ms: record.started_ms,
            ended_ms: record.ended_ms,
            duration_ms: record.duration_ms,
            exit_code: record.exit_code,
            log: record.log.clone(),
            log_truncated: record.log_truncated,
            ended_by: record.ended_by.clone(),
        }
    }
}

impl TryFrom<v1::ShellCommand> for ShellCommandRecord {
    type Error = TimingConvertError;

    fn try_from(wire: v1::ShellCommand) -> Result<Self, Self::Error> {
        command_id("id", &wire.id)?;
        bounded("command", &wire.command, MAX_COMMAND_BYTES)?;
        if wire.log.len() > MAX_SHELL_LOG_BYTES {
            return Err(TimingConvertError::TooLong("log"));
        }
        let started_ms = stored_ms("started_ms", wire.started_ms)?;
        let ended_ms = wire
            .ended_ms
            .map(|ended| stored_ms("ended_ms", ended))
            .transpose()?;
        if ended_ms.is_some_and(|ended| ended < started_ms) {
            return Err(TimingConvertError::Reversed("ended_ms"));
        }
        stored_ms("duration_ms", wire.duration_ms)?;
        if let Some(by) = &wire.ended_by {
            single_line("ended_by", by)?;
        }
        Ok(Self {
            id: wire.id,
            command: wire.command,
            background: wire.background,
            started_ms,
            ended_ms: wire.ended_ms,
            duration_ms: wire.duration_ms,
            exit_code: wire.exit_code,
            log: wire.log,
            log_truncated: wire.log_truncated,
            ended_by: wire.ended_by,
        })
    }
}

/// Converts a wire span list, refusing more than [`MAX_SPANS`] and any bad span.
///
/// # Errors
///
/// Returns [`TimingConvertError::TooMany`] over the cap, else the first span error.
pub fn spans_from_wire(
    wire: Vec<v1::TimingSpan>,
) -> Result<Vec<TimingSpanRecord>, TimingConvertError> {
    if wire.len() > MAX_SPANS {
        return Err(TimingConvertError::TooMany("spans"));
    }
    wire.into_iter().map(TimingSpanRecord::try_from).collect()
}

/// Converts a wire shell command list, refusing more than [`MAX_SHELL_COMMANDS`] and any bad
/// command.
///
/// # Errors
///
/// Returns [`TimingConvertError::TooMany`] over the cap, else the first command error.
pub fn shell_commands_from_wire(
    wire: Vec<v1::ShellCommand>,
) -> Result<Vec<ShellCommandRecord>, TimingConvertError> {
    if wire.len() > MAX_SHELL_COMMANDS {
        return Err(TimingConvertError::TooMany("shell commands"));
    }
    wire.into_iter().map(ShellCommandRecord::try_from).collect()
}

/// Why a wire profile, catalog, capability or allowlist value could not become a core value.
/// No variant keeps the input, so an error message never echoes client text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileConvertError {
    /// The visibility is unspecified or unknown to this build.
    UnknownVisibility,
    /// The catalog kind is unspecified or unknown to this build.
    UnknownCatalogKind,
    /// The text is not the canonical text of a capability.
    UnknownCapability,
    /// A selection failed the core rules.
    Selection(SelectionError),
    /// A catalog item failed the core rules.
    Catalog(CatalogError),
    /// A model allowlist failed the core rules.
    ModelAllowlist(ModelAllowlistError),
}

impl fmt::Display for ProfileConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVisibility => f.write_str("unknown profile visibility"),
            Self::UnknownCatalogKind => f.write_str("unknown catalog kind"),
            Self::UnknownCapability => f.write_str("unknown capability"),
            Self::Selection(e) => e.fmt(f),
            Self::Catalog(e) => e.fmt(f),
            Self::ModelAllowlist(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ProfileConvertError {}

/// Reads a wire visibility. Unspecified and unknown values are refused.
///
/// # Errors
///
/// Returns [`ProfileConvertError::UnknownVisibility`] for unspecified and unknown values.
pub fn visibility_from_wire(raw: i32) -> Result<Visibility, ProfileConvertError> {
    match v1::ProfileVisibility::try_from(raw) {
        Ok(v1::ProfileVisibility::Private) => Ok(Visibility::Private),
        Ok(v1::ProfileVisibility::Shared) => Ok(Visibility::Shared),
        Ok(v1::ProfileVisibility::Unspecified) | Err(_) => {
            Err(ProfileConvertError::UnknownVisibility)
        }
    }
}

/// The wire visibility of a core one.
pub fn visibility_to_wire(visibility: Visibility) -> v1::ProfileVisibility {
    match visibility {
        Visibility::Private => v1::ProfileVisibility::Private,
        Visibility::Shared => v1::ProfileVisibility::Shared,
    }
}

/// Reads wire selection entries through [`Selection::from_json`], the one core matcher.
/// An enabled entry, a repeated id, a bad id and a list over the core cap are refused.
///
/// # Errors
///
/// Returns [`ProfileConvertError::Selection`] with the core reason.
pub fn selection_from_wire(
    entries: &[v1::SelectionEntry],
) -> Result<Selection, ProfileConvertError> {
    if entries.len() > MAX_SELECTION {
        return Err(ProfileConvertError::Selection(SelectionError::TooMany));
    }
    let json = Value::Array(
        entries
            .iter()
            .map(|e| serde_json::json!({"item_id": e.item_id, "enabled": e.enabled}))
            .collect(),
    );
    let bytes = serde_json::to_vec(&json)
        .map_err(|_| ProfileConvertError::Selection(SelectionError::Malformed))?;
    Selection::from_json(&bytes).map_err(ProfileConvertError::Selection)
}

/// The wire entries of a selection: sorted, each with `enabled = false`.
pub fn selection_to_wire(selection: &Selection) -> Vec<v1::SelectionEntry> {
    selection
        .ids()
        .map(|id| v1::SelectionEntry {
            item_id: id.as_str().to_owned(),
            enabled: false,
        })
        .collect()
}

/// Reads a wire catalog kind. Unspecified and unknown values are refused.
///
/// # Errors
///
/// Returns [`ProfileConvertError::UnknownCatalogKind`] for unspecified and unknown values.
pub fn catalog_kind_from_wire(raw: i32) -> Result<CatalogKind, ProfileConvertError> {
    match v1::CatalogKind::try_from(raw) {
        Ok(v1::CatalogKind::Skill) => Ok(CatalogKind::Skill),
        Ok(v1::CatalogKind::Subagent) => Ok(CatalogKind::Subagent),
        Ok(v1::CatalogKind::Tool) => Ok(CatalogKind::Tool),
        Ok(v1::CatalogKind::Context) => Ok(CatalogKind::Context),
        Ok(v1::CatalogKind::Unspecified) | Err(_) => Err(ProfileConvertError::UnknownCatalogKind),
    }
}

/// The wire kind of a core one.
pub fn catalog_kind_to_wire(kind: CatalogKind) -> v1::CatalogKind {
    match kind {
        CatalogKind::Skill => v1::CatalogKind::Skill,
        CatalogKind::Subagent => v1::CatalogKind::Subagent,
        CatalogKind::Tool => v1::CatalogKind::Tool,
        CatalogKind::Context => v1::CatalogKind::Context,
    }
}

/// Reads a wire catalog item through [`CatalogItem::new`]. The wire digest is ignored, as the
/// proto says; `admin_enabled` becomes the entry flag.
///
/// # Errors
///
/// Returns [`ProfileConvertError::UnknownCatalogKind`] or [`ProfileConvertError::Catalog`] with the core reason.
pub fn catalog_entry_from_wire(
    item: &v1::CatalogItem,
) -> Result<CatalogEntry, ProfileConvertError> {
    let kind = catalog_kind_from_wire(item.kind)?;
    let core = CatalogItem::new(kind, &item.id, &item.name, &item.content)
        .map_err(ProfileConvertError::Catalog)?;
    Ok(CatalogEntry::new(core, item.admin_enabled))
}

/// The wire item of a catalog entry, with the core digest.
pub fn catalog_entry_to_wire(entry: &CatalogEntry) -> v1::CatalogItem {
    let item = entry.item();
    v1::CatalogItem {
        id: item.id().as_str().to_owned(),
        kind: catalog_kind_to_wire(item.kind()) as i32,
        name: item.name().to_owned(),
        content: item.body().to_owned(),
        digest: item.digest().to_vec(),
        admin_enabled: entry.enabled(),
    }
}

/// Reads the exact canonical text of a capability.
///
/// # Errors
///
/// Returns [`ProfileConvertError::UnknownCapability`] for anything but canonical text.
pub fn capability_from_text(raw: &str) -> Result<Capability, ProfileConvertError> {
    Capability::parse(raw).map_err(|_| ProfileConvertError::UnknownCapability)
}

/// The canonical wire text of a capability.
pub fn capability_to_text(capability: Capability) -> &'static str {
    capability.as_str()
}

/// Reads wire model ids through [`ModelAllowlist::new`].
///
/// # Errors
///
/// Returns [`ProfileConvertError::ModelAllowlist`] with the core reason.
pub fn model_allowlist_from_wire(
    entries: &[String],
) -> Result<ModelAllowlist, ProfileConvertError> {
    ModelAllowlist::new(entries.iter().map(String::as_str))
        .map_err(ProfileConvertError::ModelAllowlist)
}

/// The wire model ids of an allowlist, in configured order.
pub fn model_allowlist_to_wire(allowlist: &ModelAllowlist) -> Vec<String> {
    allowlist.entries().to_vec()
}

#[cfg(test)]
mod tests {
    use fleet_core::Identity;

    use super::*;

    fn box_name() -> String {
        format!("box-{}", 7)
    }

    fn sample() -> Envelope {
        let identity = Identity {
            box_name: box_name(),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "b".into(),
        };
        let mut env = Envelope::new(
            &identity,
            EventId::derive("k", &["a"]),
            Source::Hook,
            "hook.stop",
            42,
        );
        env.payload = serde_json::json!({"last_assistant_message": "ok", "n": [1, 2]});
        env
    }

    #[test]
    fn roundtrip_with_every_optional_set() {
        let mut env = sample();
        env.session_id = Some("s".into());
        env.prompt_id = Some("p".into());
        env.workdir = Some("/w".into());
        env.occurred_at = Some(40);
        let wire = v1::Envelope::from(&env);
        assert_eq!(wire.occurred_at_ms, Some(40));
        assert_eq!(Envelope::try_from(wire).unwrap(), env);
    }

    #[test]
    fn roundtrip_with_no_optionals() {
        let env = sample();
        let wire = v1::Envelope::from(&env);
        assert_eq!(wire.session_id, None);
        assert_eq!(wire.workdir, None);
        assert_eq!(Envelope::try_from(wire).unwrap(), env);
    }

    #[test]
    fn empty_string_optional_stays_distinct_from_none() {
        let mut env = sample();
        env.session_id = Some(String::new());
        env.workdir = None;
        let wire = v1::Envelope::from(&env);
        assert_eq!(wire.session_id, Some(String::new()));
        let back = Envelope::try_from(wire).unwrap();
        assert_eq!(back.session_id, Some(String::new()));
        assert_eq!(back.workdir, None);
    }

    #[test]
    fn optionals_survive_protobuf_encoding() {
        use prost::Message;

        let mut env = sample();
        env.session_id = Some(String::new());
        let bytes = v1::Envelope::from(&env).encode_to_vec();
        let wire = v1::Envelope::decode(bytes.as_slice()).unwrap();
        assert_eq!(wire.session_id, Some(String::new()));
        assert_eq!(wire.prompt_id, None);
    }

    #[test]
    fn rejects_bad_fields() {
        let good = v1::Envelope::from(&sample());

        let mut wire = good.clone();
        wire.r#box = "other".into();
        assert_eq!(Envelope::try_from(wire), Err(ConvertError::InvalidBox));

        let mut wire = good.clone();
        wire.id = "nope".into();
        assert_eq!(
            Envelope::try_from(wire),
            Err(ConvertError::InvalidId("nope".into()))
        );

        let mut wire = good.clone();
        wire.source = "other".into();
        assert_eq!(
            Envelope::try_from(wire),
            Err(ConvertError::InvalidSource("other".into()))
        );

        let mut wire = good;
        wire.payload_json = "{".into();
        assert!(matches!(
            Envelope::try_from(wire),
            Err(ConvertError::InvalidPayload(_))
        ));
    }

    #[test]
    fn invalid_box_message_does_not_echo_the_input() {
        let mut wire = v1::Envelope::from(&sample());
        wire.r#box = "secret-raw-input".into();
        let message = match Envelope::try_from(wire) {
            Err(err) => err.to_string(),
            Ok(_) => String::new(),
        };
        assert!(message.contains("invalid box name"), "{message}");
        assert!(!message.contains("secret-raw-input"), "{message}");
    }

    #[test]
    fn validate_box_accepts_good_names_and_hides_bad_ones() {
        assert_eq!(
            validate_box(&box_name()).map(|name| name.to_string()),
            Ok(box_name())
        );
        assert_eq!(
            validate_box("secret-raw-input"),
            Err(ConvertError::InvalidBox)
        );
    }

    #[test]
    fn queued_event_carries_seq_and_envelope() {
        let env = sample();
        let queued = queued_event(9, &env);
        assert_eq!(queued.seq, 9);
        assert_eq!(queued.envelope, Some(v1::Envelope::from(&env)));
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;
    use crate::{MAX_COMMAND_BYTES, MAX_SHELL_LOG_BYTES, MAX_SPANS};

    fn span(kind: SpanKind, start: u64, end: u64) -> TimingSpanRecord {
        TimingSpanRecord {
            span: Span {
                kind,
                interval: Interval::new(start, end).unwrap(),
            },
            name: "n".into(),
            tool_use_id: Some("t".into()),
        }
    }

    fn command() -> ShellCommandRecord {
        ShellCommandRecord {
            id: "c-1".into(),
            command: "ls".into(),
            background: false,
            started_ms: 10,
            ended_ms: Some(20),
            duration_ms: 10,
            exit_code: Some(0),
            log: "out".into(),
            log_truncated: false,
            ended_by: None,
        }
    }

    fn wire_span() -> v1::TimingSpan {
        v1::TimingSpan::try_from(&span(SpanKind::Tool, 1, 2)).unwrap()
    }

    fn wire_command() -> v1::ShellCommand {
        v1::ShellCommand::from(&command())
    }

    fn wire_summary() -> v1::TimingSummary {
        v1::TimingSummary {
            wall_ms: 15,
            api_wait_ms: 1,
            tool_ms: 2,
            shell_ms: 3,
            idle_ms: 4,
            overhead_ms: 5,
        }
    }

    #[test]
    fn span_kind_table_roundtrips_every_kind() {
        let rows: [(v1::TimingSpanKind, SpanKind, &str); 4] = [
            (v1::TimingSpanKind::Api, SpanKind::ApiWait, "wire api"),
            (v1::TimingSpanKind::Tool, SpanKind::Tool, "wire tool"),
            (v1::TimingSpanKind::Shell, SpanKind::Shell, "wire shell"),
            (
                v1::TimingSpanKind::BgShell,
                SpanKind::BgShell,
                "wire bg_shell",
            ),
        ];
        for (wire_kind, core, label) in rows {
            let record = span(core, 5, 9);
            let wire = v1::TimingSpan::try_from(&record).unwrap();
            assert_eq!(wire.kind, wire_kind as i32, "{label}");
            assert_eq!(TimingSpanRecord::try_from(wire).unwrap(), record, "{label}");
        }
    }

    #[test]
    fn every_wire_kind_is_classified() {
        for raw in 0..=4 {
            let kind = v1::TimingSpanKind::try_from(raw).unwrap();
            let classified = match kind {
                v1::TimingSpanKind::Unspecified => false,
                v1::TimingSpanKind::Api
                | v1::TimingSpanKind::Tool
                | v1::TimingSpanKind::Shell
                | v1::TimingSpanKind::BgShell => true,
            };
            assert_eq!(core_kind(raw).is_ok(), classified, "{kind:?}");
        }
        assert!(v1::TimingSpanKind::try_from(5).is_err());
    }

    #[test]
    fn unknown_span_kind_is_a_typed_error() {
        for raw in [0, 5, 99, -1, i32::MAX, i32::MIN] {
            let mut wire = wire_span();
            wire.kind = raw;
            assert_eq!(
                TimingSpanRecord::try_from(wire),
                Err(TimingConvertError::UnknownSpanKind),
                "{raw}"
            );
        }
    }

    #[test]
    fn unknown_kind_message_does_not_echo_the_value() {
        let mut wire = wire_span();
        wire.kind = 424_242;
        let message = TimingSpanRecord::try_from(wire).unwrap_err().to_string();
        assert!(message.contains("unknown timing span kind"), "{message}");
        assert!(!message.contains("424242"), "{message}");
    }

    #[test]
    fn summary_roundtrips_and_wall_is_the_sum() {
        let summary = Summary::try_from(wire_summary()).unwrap();
        assert_eq!(summary.total_ms(), 15);
        assert_eq!(v1::TimingSummary::from(&summary), wire_summary());
        assert_eq!(
            Summary::try_from(v1::TimingSummary::from(&Summary::default())).unwrap(),
            Summary::default()
        );
    }

    #[test]
    fn summary_rejects_a_wall_that_is_not_the_sum() {
        for wall in [0, 14, 16, u64::MAX >> 1] {
            let mut wire = wire_summary();
            wire.wall_ms = wall;
            assert_eq!(
                Summary::try_from(wire),
                Err(TimingConvertError::WallMismatch),
                "{wall}"
            );
        }
    }

    #[test]
    fn summary_rejects_each_field_above_the_stored_maximum() {
        let over = i64::MAX as u64 + 1;
        let rows: [(&str, SummarySetter); 6] = [
            ("wall_ms", |w, v| w.wall_ms = v),
            ("api_wait_ms", |w, v| w.api_wait_ms = v),
            ("tool_ms", |w, v| w.tool_ms = v),
            ("shell_ms", |w, v| w.shell_ms = v),
            ("idle_ms", |w, v| w.idle_ms = v),
            ("overhead_ms", |w, v| w.overhead_ms = v),
        ];
        for (field, set) in rows {
            let mut wire = wire_summary();
            set(&mut wire, over);
            assert_eq!(
                Summary::try_from(wire),
                Err(TimingConvertError::OutOfRange(field)),
                "{field}"
            );
            let mut wire = wire_summary();
            set(&mut wire, u64::MAX);
            assert_eq!(
                Summary::try_from(wire),
                Err(TimingConvertError::OutOfRange(field)),
                "{field} max"
            );
        }
    }

    #[test]
    fn span_rejects_reversed_times() {
        for (start, end) in [(2, 1), (10, 0), (i64::MAX as u64, 0)] {
            let mut wire = wire_span();
            wire.start_ms = start;
            wire.end_ms = end;
            assert_eq!(
                TimingSpanRecord::try_from(wire),
                Err(TimingConvertError::Reversed("end_ms")),
                "{start} {end}"
            );
        }
    }

    #[test]
    fn span_accepts_an_empty_interval_and_the_stored_maximum() {
        let mut wire = wire_span();
        wire.start_ms = 7;
        wire.end_ms = 7;
        assert!(TimingSpanRecord::try_from(wire).is_ok());
        let mut wire = wire_span();
        wire.start_ms = i64::MAX as u64;
        wire.end_ms = i64::MAX as u64;
        assert!(TimingSpanRecord::try_from(wire).is_ok());
    }

    #[test]
    fn span_rejects_negative_times() {
        let over = i64::MAX as u64 + 1;
        let mut wire = wire_span();
        wire.start_ms = over;
        wire.end_ms = u64::MAX;
        assert_eq!(
            TimingSpanRecord::try_from(wire),
            Err(TimingConvertError::OutOfRange("start_ms"))
        );
        let mut wire = wire_span();
        wire.start_ms = 1;
        wire.end_ms = over;
        assert_eq!(
            TimingSpanRecord::try_from(wire),
            Err(TimingConvertError::OutOfRange("end_ms"))
        );
    }

    #[test]
    fn span_tool_use_id_none_stays_distinct_from_empty() {
        let mut record = span(SpanKind::Tool, 1, 2);
        record.tool_use_id = None;
        let wire = v1::TimingSpan::try_from(&record).unwrap();
        assert_eq!(wire.tool_use_id, None);
        assert_eq!(TimingSpanRecord::try_from(wire).unwrap(), record);
        let mut wire = wire_span();
        wire.tool_use_id = Some(String::new());
        assert_eq!(
            TimingSpanRecord::try_from(wire),
            Err(TimingConvertError::Empty("tool_use_id"))
        );
    }

    type Setter = fn(&mut TimingFixture, String);
    type SummarySetter = fn(&mut v1::TimingSummary, u64);

    struct TimingFixture {
        span: v1::TimingSpan,
        command: v1::ShellCommand,
    }

    fn check(fixture: &TimingFixture, field: &str) -> Result<(), TimingConvertError> {
        match field {
            "name" | "tool_use_id" => TimingSpanRecord::try_from(fixture.span.clone()).map(|_| ()),
            _ => ShellCommandRecord::try_from(fixture.command.clone()).map(|_| ()),
        }
    }

    fn strict_fields() -> [(&'static str, Setter); 4] {
        [
            ("name", |f, v| f.span.name = v),
            ("tool_use_id", |f, v| f.span.tool_use_id = Some(v)),
            ("id", |f, v| f.command.id = v),
            ("ended_by", |f, v| f.command.ended_by = Some(v)),
        ]
    }

    #[test]
    fn hostile_text_table_for_single_line_fields() {
        let over = "a".repeat(129);
        let at_cap = "a".repeat(128);
        let rows: Vec<(&str, String, Option<TimingConvertError>)> = vec![
            ("empty", String::new(), Some(TimingConvertError::Empty("F"))),
            (
                "cr",
                "a\rb".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "crlf",
                "a\r\nb".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "lf",
                "a\nb".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "tab",
                "a\tb".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "nul",
                "a\0b".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "nel",
                "a\u{85}b".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "line separator",
                "a\u{2028}b".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            (
                "paragraph separator",
                "a\u{2029}b".into(),
                Some(TimingConvertError::InvalidText("F")),
            ),
            ("over-long", over, Some(TimingConvertError::TooLong("F"))),
            ("at cap", at_cap, None),
        ];
        for (field, set) in strict_fields() {
            for (label, value, expected) in &rows {
                let mut fixture = TimingFixture {
                    span: wire_span(),
                    command: wire_command(),
                };
                set(&mut fixture, value.clone());
                let want = expected.map(|e| match e {
                    TimingConvertError::Empty(_) => TimingConvertError::Empty(field),
                    TimingConvertError::InvalidText(_) => TimingConvertError::InvalidText(field),
                    TimingConvertError::TooLong(_) => TimingConvertError::TooLong(field),
                    other => other,
                });
                let got = check(&fixture, field).err();
                let want = if field == "id" && label == &"at cap" {
                    None
                } else {
                    want
                };
                assert_eq!(got, want, "{field} {label}");
            }
        }
    }

    #[test]
    fn command_id_is_ascii_only_while_names_allow_unicode() {
        for value in ["a b", "a/b", "a\\b", "é", "a@b", "[::1]"] {
            let mut wire = wire_command();
            wire.id = value.into();
            assert_eq!(
                ShellCommandRecord::try_from(wire),
                Err(TimingConvertError::InvalidText("id")),
                "{value}"
            );
        }
        let mut wire = wire_span();
        wire.name = "é tool".into();
        assert!(TimingSpanRecord::try_from(wire).is_ok());
    }

    #[test]
    fn shell_command_roundtrips_every_optional_shape() {
        let mut open = command();
        open.ended_ms = None;
        open.exit_code = None;
        open.background = true;
        open.ended_by = Some("job_exit".into());
        open.log_truncated = true;
        let mut negative_exit = command();
        negative_exit.exit_code = Some(-9);
        for record in [command(), open, negative_exit] {
            let wire = v1::ShellCommand::from(&record);
            assert_eq!(ShellCommandRecord::try_from(wire).unwrap(), record);
        }
    }

    #[test]
    fn shell_command_text_caps() {
        let mut wire = wire_command();
        wire.command = "c".repeat(MAX_COMMAND_BYTES);
        assert!(ShellCommandRecord::try_from(wire).is_ok());
        let mut wire = wire_command();
        wire.command = "c".repeat(MAX_COMMAND_BYTES + 1);
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::TooLong("command"))
        );
        let mut wire = wire_command();
        wire.command = String::new();
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::Empty("command"))
        );
        let mut wire = wire_command();
        wire.log = "l".repeat(MAX_SHELL_LOG_BYTES);
        assert!(ShellCommandRecord::try_from(wire).is_ok());
        let mut wire = wire_command();
        wire.log = "l".repeat(MAX_SHELL_LOG_BYTES + 1);
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::TooLong("log"))
        );
        let mut wire = wire_command();
        wire.log = String::new();
        assert!(ShellCommandRecord::try_from(wire).is_ok());
    }

    #[test]
    fn shell_command_keeps_control_characters_in_command_and_log() {
        let mut wire = wire_command();
        wire.command = "a\r\nb\u{2028}c\u{85}".into();
        wire.log = "x\r\ny\u{2029}".into();
        let record = ShellCommandRecord::try_from(wire.clone()).unwrap();
        assert_eq!(v1::ShellCommand::from(&record), wire);
    }

    #[test]
    fn shell_command_rejects_reversed_and_out_of_range_times() {
        let mut wire = wire_command();
        wire.started_ms = 20;
        wire.ended_ms = Some(19);
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::Reversed("ended_ms"))
        );
        let mut wire = wire_command();
        wire.started_ms = 20;
        wire.ended_ms = Some(20);
        assert!(ShellCommandRecord::try_from(wire).is_ok());
        let over = i64::MAX as u64 + 1;
        let mut wire = wire_command();
        wire.started_ms = over;
        wire.ended_ms = None;
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::OutOfRange("started_ms"))
        );
        let mut wire = wire_command();
        wire.ended_ms = Some(over);
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::OutOfRange("ended_ms"))
        );
        let mut wire = wire_command();
        wire.duration_ms = over;
        assert_eq!(
            ShellCommandRecord::try_from(wire),
            Err(TimingConvertError::OutOfRange("duration_ms"))
        );
    }

    #[test]
    fn list_conversions_enforce_the_shared_caps() {
        let spans = vec![wire_span(); MAX_SPANS];
        assert_eq!(spans_from_wire(spans).unwrap().len(), MAX_SPANS);
        let spans = vec![wire_span(); MAX_SPANS + 1];
        assert_eq!(
            spans_from_wire(spans),
            Err(TimingConvertError::TooMany("spans"))
        );
        let commands = vec![wire_command(); MAX_SHELL_COMMANDS];
        assert_eq!(
            shell_commands_from_wire(commands).unwrap().len(),
            MAX_SHELL_COMMANDS
        );
        let commands = vec![wire_command(); MAX_SHELL_COMMANDS + 1];
        assert_eq!(
            shell_commands_from_wire(commands),
            Err(TimingConvertError::TooMany("shell commands"))
        );
        let mut bad = vec![wire_span(); 3];
        bad[2].kind = 0;
        assert_eq!(
            spans_from_wire(bad),
            Err(TimingConvertError::UnknownSpanKind)
        );
    }

    #[test]
    fn timing_messages_survive_protobuf_encoding() {
        use prost::Message;

        let wire = v1::ShellCommand::from(&command());
        let back = v1::ShellCommand::decode(wire.encode_to_vec().as_slice()).unwrap();
        assert_eq!(ShellCommandRecord::try_from(back).unwrap(), command());
        let wire = v1::TimingSpan::try_from(&span(SpanKind::BgShell, 3, 4)).unwrap();
        let back = v1::TimingSpan::decode(wire.encode_to_vec().as_slice()).unwrap();
        assert_eq!(
            TimingSpanRecord::try_from(back).unwrap(),
            span(SpanKind::BgShell, 3, 4)
        );
    }
}
