//! Wire types shared by fleetd, the server and the CLI.
//!
//! The `fleet.v1` package is generated from `proto/fleet/v1/fleet.proto`. [`convert`]
//! maps its [`v1::Envelope`] to and from [`fleet_core::Envelope`].

mod convert;

pub use convert::{
    ConvertError, ProfileConvertError, ShellCommandRecord, TimingConvertError, TimingSpanRecord,
    capability_from_text, capability_to_text, catalog_entry_from_wire, catalog_entry_to_wire,
    catalog_kind_from_wire, catalog_kind_to_wire, model_allowlist_from_wire,
    model_allowlist_to_wire, queued_event, selection_from_wire, selection_to_wire,
    shell_commands_from_wire, spans_from_wire, validate_box, visibility_from_wire,
    visibility_to_wire,
};

/// Wire protocol version fleetd reports in `HeartbeatRequest.protocol_version`. Changes are
/// additive only, so a new server serves an old fleetd. An old fleetd sends 0.
pub const PROTOCOL_VERSION: u32 = 1;

/// Longest signed update manifest, in bytes, in `HeartbeatReply.update_manifest`. The server
/// relays no more and fleetd reads no more.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;

/// Longest update signature, in bytes, in `HeartbeatReply.update_signature`.
pub const MAX_SIGNATURE_BYTES: usize = 1024;

/// Whether the update fields of `reply` fit the caps and come as a pair: both set or both
/// unset. A reply with no update is within the caps.
#[must_use]
pub fn update_within_caps(reply: &v1::HeartbeatReply) -> bool {
    match (&reply.update_manifest, &reply.update_signature) {
        (None, None) => true,
        (Some(manifest), Some(signature)) => {
            manifest.len() <= MAX_MANIFEST_BYTES && signature.len() <= MAX_SIGNATURE_BYTES
        }
        _ => false,
    }
}

/// Longest accepted profile JSON, in bytes. Escapes make the JSON longer than its text, so
/// this sits above the 4 MiB text cap of the validator.
pub const MAX_PROFILE_JSON_BYTES: usize = 8 * 1024 * 1024;

/// Refusal text when a profile with tools is created while the server gate is off.
pub const ERR_PROFILE_TOOLS_DISABLED: &str = "profile tools are disabled on this server";

/// Refusal text when a create request sets both or neither of `content_json` and
/// `content_toml`.
pub const ERR_PROFILE_CONTENT_CHOICE: &str = "set exactly one of content_json and content_toml";

/// Largest profile-carrying message either side encodes or decodes, in bytes: the profile
/// JSON, a full catalog snapshot ([`MAX_BLOB_CATALOG_WIRE_BYTES`]) and 1 MiB for the rest of
/// the message.
///
/// It applies to `FleetProfiles` on the server, to the `FleetWorker` reply of
/// `GetProfileBlob` on the server (encode) and on every `FleetWorker` client (decode), and to
/// the `FleetProfiles` client. The tonic client default of 4 MiB is below the largest profile.
/// It also bounds the `GetJobTranscript` reply on the same server and clients: the transcript
/// text plus 2 MiB for the per-chunk fields of up to 50 000 rows stays below it.
pub const MAX_PROFILE_MESSAGE_BYTES: usize =
    MAX_PROFILE_JSON_BYTES + MAX_BLOB_CATALOG_WIRE_BYTES + 1024 * 1024;

/// Transcript bytes stored per job. Chunks past this are dropped after one marker row. The
/// server enforces it on ingest and on the `GetJobTranscript` reply, and fleetd on the reply it
/// receives.
pub const MAX_TRANSCRIPT_BYTES: usize = 4 * 1024 * 1024;

const _: () = assert!(MAX_TRANSCRIPT_BYTES + 2 * 1024 * 1024 <= MAX_PROFILE_MESSAGE_BYTES);

/// Longest judge verdict reason, in bytes, after redaction. fleetd cuts to it and the server
/// rejects more.
pub const MAX_VERDICT_REASON_BYTES: usize = 1024;

/// Highest judge verdict score.
pub const MAX_VERDICT_SCORE: u32 = 100;

/// Longest stored CI failure log, in bytes. fleetd keeps the last bytes of the redacted log of
/// the failed checks and the server rejects more.
pub const MAX_CI_LOG_BYTES: usize = 16 * 1024;

/// Longest CI url, in bytes.
pub const MAX_CI_URL_BYTES: usize = 2048;

/// Highest accepted `max_ci_retries`, the most fix Jobs one failed pull request may start.
pub const MAX_CI_RETRIES: u32 = 5;

/// Default `max_ci_retries`: 0, so the server starts no fix Job until an operator opts in.
pub const DEFAULT_CI_RETRIES: u32 = 0;

/// Idempotency key prefix the server reserves for the fix Jobs it submits. A client submit
/// with a key that starts with it is refused, so a client cannot occupy a fix Job's key.
pub const CI_RETRY_KEY_PREFIX: &str = "ci-retry:";

/// The idempotency key of the fix Job that follows attempt `attempt` of `parent_job_id`.
///
/// One value per `(parent, attempt)`, so a repeated decision for one failure maps to one key.
#[must_use]
pub fn ci_retry_key(parent_job_id: &str, attempt: u32) -> String {
    format!("{CI_RETRY_KEY_PREFIX}{parent_job_id}:{attempt}")
}

/// True when `text` is `swarm/` and a job id of 1 to 64 ASCII letters or digits.
///
/// fleetd checks it before a fix Job pushes to a branch it did not create, so no fix Job can
/// push outside the `swarm/` namespace.
#[must_use]
pub fn is_swarm_branch(text: &str) -> bool {
    text.strip_prefix("swarm/").is_some_and(|id| {
        (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// Longest credential value a client may put and a box may receive, in bytes.
pub const MAX_CREDENTIAL_VALUE_BYTES: usize = fleet_core::credential::MAX_CREDENTIAL_LEN;

/// Path prefix of `FleetCapabilityAdmin`, with the trailing slash the auth layer matches on.
/// No bearer token scope covers it.
pub const CAPABILITY_ADMIN_PATH: &str = "/fleet.v1.FleetCapabilityAdmin/";

/// Reads the wire text of a capability: exactly the canonical text, nothing trimmed or folded.
pub fn capability_from_wire(raw: &str) -> Option<fleet_core::capability::Capability> {
    fleet_core::capability::Capability::parse(raw).ok()
}

/// Reads a wire user id as the signed id the database stores: 1 to `i64::MAX`.
pub fn user_id_from_wire(raw: u64) -> Option<i64> {
    i64::try_from(raw).ok().filter(|id| *id > 0)
}

/// Longest catalog item content in bytes. The `catalog_items.content` CHECK of migration 0024
/// carries the same number, and a test pins the two equal.
pub const MAX_CATALOG_CONTENT_BYTES: usize = fleet_core::catalog::MAX_BODY_BYTES;

/// Whether `content` is a legal catalog item content length: 1 to [`MAX_CATALOG_CONTENT_BYTES`]
/// bytes.
pub fn validate_catalog_content(content: &str) -> bool {
    (1..=MAX_CATALOG_CONTENT_BYTES).contains(&content.len())
}

/// Page size a catalog list uses when the request asks for 0.
pub const DEFAULT_CATALOG_PAGE: u32 = 50;

/// Largest catalog list page. The server cuts a larger `page_size` to this.
pub const MAX_CATALOG_PAGE: u32 = 200;

/// Longest catalog list cursor in bytes: the longest item id.
pub const MAX_CATALOG_CURSOR_BYTES: usize = fleet_core::ItemId::MAX_LEN;

/// Whether `after_id` is a legal catalog list cursor: empty, or at most
/// [`MAX_CATALOG_CURSOR_BYTES`] bytes of ASCII lowercase letters, digits, `_` and `-`.
pub fn validate_catalog_cursor(after_id: &str) -> bool {
    after_id.len() <= MAX_CATALOG_CURSOR_BYTES
        && after_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// Most catalog items a `GetProfileBlobReply` snapshot carries.
pub const MAX_BLOB_CATALOG_ITEMS: usize = 256;

/// Most total catalog item content bytes a `GetProfileBlobReply` snapshot carries.
pub const MAX_BLOB_CATALOG_BYTES: usize = 4 * 1024 * 1024;

const BLOB_CATALOG_ITEM_OVERHEAD_BYTES: usize = 1024;

/// Largest encoded catalog snapshot in a `GetProfileBlobReply`, in bytes: the content cap plus
/// the per-item fields of [`MAX_BLOB_CATALOG_ITEMS`] items.
pub const MAX_BLOB_CATALOG_WIRE_BYTES: usize =
    MAX_BLOB_CATALOG_BYTES + MAX_BLOB_CATALOG_ITEMS * BLOB_CATALOG_ITEM_OVERHEAD_BYTES;

const _: () =
    assert!(MAX_PROFILE_JSON_BYTES + MAX_BLOB_CATALOG_WIRE_BYTES <= MAX_PROFILE_MESSAGE_BYTES);

/// Whether a catalog snapshot fits `max_items` items and `max_bytes` total content bytes.
pub fn blob_catalog_within(items: &[v1::CatalogItem], max_items: usize, max_bytes: usize) -> bool {
    items.len() <= max_items
        && items
            .iter()
            .try_fold(0usize, |sum, item| sum.checked_add(item.content.len()))
            .is_some_and(|total| total <= max_bytes)
}

/// Whether a catalog snapshot fits [`MAX_BLOB_CATALOG_ITEMS`] and [`MAX_BLOB_CATALOG_BYTES`].
pub fn validate_blob_catalog(items: &[v1::CatalogItem]) -> bool {
    blob_catalog_within(items, MAX_BLOB_CATALOG_ITEMS, MAX_BLOB_CATALOG_BYTES)
}

/// Longest credential login, in bytes.
pub const MAX_CREDENTIAL_LOGIN_BYTES: usize = 256;

/// Most credentials one user may store, and so the most one list or job reply carries.
pub const MAX_CREDENTIALS_PER_USER: usize = 64;

/// `FAILED_PRECONDITION` message: the job owner stored no GitHub credential.
pub const PRECONDITION_NO_GITHUB: &str = "no github credential";

/// `FAILED_PRECONDITION` message: the job owner stored no credential for the job's agent.
pub const PRECONDITION_NO_AGENT: &str = "no agent credential";

/// `FAILED_PRECONDITION` message: a credential the job needs has expired.
pub const PRECONDITION_EXPIRED: &str = "credential expired";

/// `FAILED_PRECONDITION` message: the server runs without a credential store.
pub const PRECONDITION_NOT_CONFIGURED: &str = "credentials are not configured";

/// Most transcript chunks one report may carry. The server rejects more.
pub const MAX_CHUNKS_PER_REPORT: usize = 256;

/// Most telemetry events one report may carry. The server rejects a larger report whole
/// as gRPC `INVALID_ARGUMENT` (`StoreError::TelemetryTooLarge`) and stores none of it.
pub const MAX_EVENTS_PER_REPORT: usize = 256;

/// Telemetry events stored per job. The server drops events with a `seq` at or above this.
pub const MAX_EVENTS_PER_JOB: u32 = 2000;

/// Longest stored `cmd` of a telemetry event, in bytes.
pub const MAX_EVENT_CMD_BYTES: usize = 512;

/// Longest stored `detail` of a telemetry event, in bytes.
pub const MAX_EVENT_DETAIL_BYTES: usize = 1024;

/// Longest stored `bundle_sha` of a job summary, in characters.
pub const MAX_BUNDLE_SHA_CHARS: usize = 64;

/// Longest stored `claude_version` of a job summary, in characters.
pub const MAX_CLAUDE_VERSION_CHARS: usize = 64;

/// Longest stored `model` of a job summary, in bytes.
pub const MAX_MODEL_BYTES: usize = 128;

/// Most timing spans stored per job. Migration 0022 checks `seq BETWEEN 0 AND MAX_SPANS - 1`.
pub const MAX_SPANS: usize = 4096;

/// Most shell commands stored per job. Migration 0022 checks
/// `seq BETWEEN 0 AND MAX_SHELL_COMMANDS - 1`.
pub const MAX_SHELL_COMMANDS: usize = 256;

/// Longest stored shell log of one command, in bytes. Migration 0022 checks it.
pub const MAX_SHELL_LOG_BYTES: usize = 16 * 1024;

/// Longest stored shell command line, in bytes. Migration 0022 checks it.
pub const MAX_COMMAND_BYTES: usize = 2048;

/// Longest stored span name, tool use id, shell command id or `ended_by`, in bytes. Migration
/// 0022 checks each.
pub const MAX_TIMING_NAME_BYTES: usize = 128;

/// Longest shell command id in a live log chunk, in bytes. Migration 0025 checks it.
pub const MAX_COMMAND_ID_BYTES: usize = MAX_TIMING_NAME_BYTES;

/// Longest `bytes` of one live shell log chunk. Migration 0025 checks it.
pub const MAX_SHELL_LOG_CHUNK_BYTES: usize = 4096;

/// Most chunks stored per shell command. Migration 0025 checks `seq BETWEEN 0 AND
/// MAX_SHELL_LOG_CHUNKS - 1`.
pub const MAX_SHELL_LOG_CHUNKS: usize = 64;

/// Whether `id` is a legal live log command id: 1 to [`MAX_COMMAND_ID_BYTES`] bytes of ASCII
/// letters, digits and `_ . : -`.
pub fn validate_shell_log_command_id(id: &str) -> bool {
    (1..=MAX_COMMAND_ID_BYTES).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// Whether `seq` is a legal live log chunk number: below [`MAX_SHELL_LOG_CHUNKS`].
pub fn validate_shell_log_seq(seq: u32) -> bool {
    usize::try_from(seq).is_ok_and(|n| n < MAX_SHELL_LOG_CHUNKS)
}

/// Whether `bytes` fits one chunk. An empty chunk is legal: it carries a status change alone.
pub fn validate_shell_log_bytes(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_SHELL_LOG_CHUNK_BYTES
}

/// Reads a wire status, refusing `UNSPECIFIED` and any value this build does not know.
pub fn validate_shell_log_status(raw: i32) -> Option<v1::ShellStatus> {
    match v1::ShellStatus::try_from(raw).ok()? {
        v1::ShellStatus::Unspecified => None,
        known => Some(known),
    }
}

/// The `job_shell_log_chunks.status` text of `status`, or `None` for `UNSPECIFIED`.
pub fn shell_status_name(status: v1::ShellStatus) -> Option<&'static str> {
    match status {
        v1::ShellStatus::Unspecified => None,
        v1::ShellStatus::Queued => Some("queued"),
        v1::ShellStatus::Running => Some("running"),
        v1::ShellStatus::Done => Some("done"),
        v1::ShellStatus::Failed => Some("failed"),
    }
}

/// Largest stored phase or queue duration of a job summary: seven days, in milliseconds.
pub const MAX_PHASE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The in-memory value of a version stamp field that is not known.
///
/// It never crosses the wire and is never stored: an unknown field is unset on the wire and
/// `NULL` in the database (ADR-0030).
pub const UNKNOWN_STAMP: &str = "unknown";

/// True when `text` is non-empty and holds no control or format character.
///
/// Format characters are the bidirectional override, embedding and isolate controls, the
/// zero-width space, the word joiner and invisible operators, the soft hyphen, the byte order mark, the tag
/// characters and the line and paragraph separators. They can reorder or hide text on a
/// terminal.
///
/// The zero-width joiner and non-joiner (U+200D, U+200C) and the left-to-right and
/// right-to-left marks (U+200E, U+200F) are allowed. Emoji sequences and Persian, Hindi and
/// Hebrew text need them, and the marks only set the direction of neutral characters, so they
/// cannot override or embed a run the way the rejected controls do.
///
/// Agent and tool output is untrusted, so a value that reaches storage or a terminal must
/// pass this, on the sending side and again on the receiving side.
#[must_use]
pub fn is_plain_text(text: &str) -> bool {
    !text.is_empty() && !text.chars().any(|c| c.is_control() || is_format(c))
}

fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{110bd}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// True when `text` is a CI failure log the server may store: within [`MAX_CI_LOG_BYTES`],
/// non-empty and holding no control or format character except newline and tab.
#[must_use]
pub fn is_ci_log(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CI_LOG_BYTES
        && text
            .chars()
            .all(|c| matches!(c, '\n' | '\t') || is_plain_text(c.encode_utf8(&mut [0; 4])))
}

/// True when `url` is a CI check link the server may store.
///
/// It must be `https` with a non-empty authority and no userinfo or backslash, hold only ASCII
/// graphic characters and be at most [`MAX_CI_URL_BYTES`] bytes. The host is not parsed, so an
/// authority with no host such as `https://:443/` passes. fleetd and the server both call it,
/// so a link one side keeps the other accepts.
#[must_use]
pub fn is_ci_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    url.len() <= MAX_CI_URL_BYTES
        && url.bytes().all(|b| b.is_ascii_graphic())
        && !authority.is_empty()
        && !authority.contains('@')
        && !url.contains('\\')
}

impl v1::CiState {
    /// True for the states that end a CI check: `success`, `failure` and `timeout`. `pending`
    /// and the unspecified value are not final.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Success | Self::Failure | Self::Timeout)
    }
}

impl std::fmt::Debug for v1::PutCredentialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutCredentialRequest")
            .field("kind", &self.kind)
            .field("shape", &self.shape)
            .field("value", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl std::fmt::Debug for v1::JobCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobCredential")
            .field("kind", &self.kind)
            .field("shape", &self.shape)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Generated `fleet.v1` messages and services.
#[expect(
    missing_docs,
    unused_qualifications,
    clippy::pedantic,
    clippy::nursery,
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    reason = "generated by tonic-prost-build from fleet.proto"
)]
pub mod v1 {
    tonic::include_proto!("fleet.v1");
}
