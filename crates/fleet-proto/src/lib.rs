//! Wire types shared by fleetd, the server and the CLI.
//!
//! The `fleet.v1` package is generated from `proto/fleet/v1/fleet.proto`. [`convert`]
//! maps its [`v1::Envelope`] to and from [`fleet_core::Envelope`].

mod classify;
mod convert;

mod notice;
pub use classify::{Reason, classify};
pub use convert::{
    ConvertError, ProfileConvertError, ShellCommandRecord, TimingConvertError, TimingSpanRecord,
    capability_from_text, capability_to_text, catalog_entry_from_wire, catalog_entry_to_wire,
    catalog_kind_from_wire, catalog_kind_to_wire, model_allowlist_from_wire,
    model_allowlist_to_wire, queued_event, selection_from_wire, selection_to_wire,
    shell_commands_from_wire, spans_from_wire, validate_box, visibility_from_wire,
    visibility_to_wire,
};
pub use notice::CredentialNotice;

/// Wire protocol version fleetd reports in `HeartbeatRequest.protocol_version`. Changes are
/// additive only, so a new server serves an old fleetd. An old fleetd sends 0.
pub const PROTOCOL_VERSION: u32 = 1;

/// The only host of the first hop of a release download.
pub const UPDATE_FIRST_HOP_HOST: &str = "github.com";

/// The asset hosts a redirect may name, besides the first-hop host [`UPDATE_FIRST_HOP_HOST`]. Exact names only.
pub const UPDATE_REDIRECT_HOSTS: [&str; 2] = [
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

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

/// The longest one `GetJobCredentials` call may take, as both sides plan it.
///
/// fleetd sets it as the channel timeout, which tonic sends as the `grpc-timeout` deadline, so the
/// server drops the handler at this mark. The server fits its GitHub installation lookup and
/// token mint inside it with headroom to record the outcome, so a mint never straddles the
/// deadline (ADR-0058, SEC-010).
pub const CALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Wire kind of the minted GitHub App installation token in a `GetJobCredentials` reply
/// (ADR-0058). It is never a stored kind.
pub const GITHUB_INSTALLATION_TOKEN_KIND: &str = "github_installation_token";

/// `FAILED_PRECONDITION` message: the GitHub App token could not be minted. One text covers
/// every cause.
pub const PRECONDITION_APP_MINT: &str = "github app token unavailable";

/// `FAILED_PRECONDITION` message: the Job reached its mint cap (ADR-0058, SEC-004, SEC-011).
/// Terminal: the Job or step fails and never falls back to a PAT.
pub const PRECONDITION_APP_MINT_CAP: &str = "github app token limit reached";

/// `FAILED_PRECONDITION` message: the User reached the per-minute mint limit (ADR-0058,
/// SEC-003).
///
/// The limit counts every scope. It is retryable: fleetd waits and asks again because the
/// limit lifts within a minute. It never falls back to a PAT.
pub const PRECONDITION_APP_MINT_RATE: &str = "github app token rate limited";

/// `FAILED_PRECONDITION` message: the installation is refused.
///
/// It is off the operator allowlist, or GitHub reports it suspended, owned by another App or
/// installed on another account (ADR-0058, SEC-001, SEC-013). It applies at `PutCredential`,
/// at verify and at release.
pub const PRECONDITION_APP_INSTALLATION: &str = "github app installation is not allowed";

/// `FAILED_PRECONDITION` message: the Job repository is refused.
///
/// It is outside the operator repository allowlist or its owner is not the configured account
/// (ADR-0058, SEC-002, SEC-009, SEC-014). The Job or step fails and never falls back to a PAT.
pub const PRECONDITION_APP_REPO: &str = "repository is not allowed for the github app";

/// `FAILED_PRECONDITION` message: a `github_app` verify has no Job repository to scope its mint to.
pub const PRECONDITION_NO_VERIFY_REPO: &str = "no job to verify the github app against";

/// `FAILED_PRECONDITION` message: a `PutCredential` hit a credential that was deleted and kept as
/// a tombstone because it has mint history (ADR-0058, SEC-022).
pub const PRECONDITION_CREDENTIAL_TOMBSTONED: &str =
    "credential was deleted and cannot be replaced";

/// `FAILED_PRECONDITION` message: `AddRepo` named a host outside the operator host list, or a host
/// with no verifier (ADR-0059).
pub const PRECONDITION_REPO_NOT_ALLOWED_HOST: &str = "repository host is not allowed";

/// `FAILED_PRECONDITION` message: `AddRepo` found no credential of the User for the host
/// (ADR-0059).
pub const PRECONDITION_REPO_NO_CREDENTIAL: &str = "no credential for the repository host";

/// `FAILED_PRECONDITION` message: the forge answered 404 or 403, which collapse into one reason so
/// a caller cannot probe for private repositories (ADR-0059).
pub const PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS: &str = "repository not found or no access";

/// `FAILED_PRECONDITION` message: the forge could not be reached or its reply was unusable.
/// Upstream bodies and addresses go to server logs only (ADR-0059).
pub const PRECONDITION_REPO_UPSTREAM_UNAVAILABLE: &str = "repository host unavailable";

/// `FAILED_PRECONDITION` message: the repository check ran out of its time budget (ADR-0059).
pub const PRECONDITION_REPO_TIMEOUT: &str = "repository check timed out";

/// Most repositories one User may register, and so the most one `ListRepos` reply carries
/// (ADR-0059).
pub const MAX_REPOS_PER_USER: usize = 100;

/// `RESOURCE_EXHAUSTED` message: the User holds [`MAX_REPOS_PER_USER`] repositories.
pub const ERR_REPO_LIMIT: &str = "too many repositories";

/// `RESOURCE_EXHAUSTED` message: the User started too many repository checks in the last window.
pub const ERR_REPO_RATE_LIMITED: &str = "too many repository checks, retry later";

/// `RESOURCE_EXHAUSTED` message: the server runs its most concurrent repository checks.
pub const ERR_REPO_BUSY: &str = "repository checks are busy, retry later";

/// `NOT_FOUND` message of `RemoveRepo`. A missing row and another User's row give this one text.
pub const ERR_REPO_NOT_FOUND: &str = "repository not found";

/// `FAILED_PRECONDITION` message: the server runs without a credential store.
pub const PRECONDITION_NOT_CONFIGURED: &str = "credentials are not configured";

/// `PERMISSION_DENIED` message: the credential kind needs a capability the user lacks.
pub const ERR_CAPABILITY_NOT_GRANTED: &str = "credential kind needs a capability the user lacks";

/// `PERMISSION_DENIED` message: no running job holds the lease the caller named.
///
/// A wrong box, a wrong attempt, a job that is not running, an expired lease and an unknown job
/// all give this one text. fleetd maps every `PERMISSION_DENIED` credential answer to a lease
/// mismatch.
pub const ERR_LEASE_MISMATCH: &str = "lease does not match";

/// `PERMISSION_DENIED` message: credentials need a per-user token.
pub const ERR_NEEDS_USER_TOKEN: &str = "credentials need a user token";

/// `INVALID_ARGUMENT` message: GitHub refused the token on save.
pub const ERR_GITHUB_REJECTED: &str = "github rejected the token";

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

/// True when `text` is non-empty and holds no hostile character.
///
/// Hostile is [`fleet_core::text::is_hostile_allowing_joiners`]: control characters, every
/// Unicode format character, the line and paragraph separators and the tag block, minus the
/// zero-width non-joiner and joiner (U+200C, U+200D) and the left-to-right and right-to-left
/// marks (U+200E, U+200F). Emoji sequences and Persian, Hindi and Hebrew text need those four,
/// and the marks only set the direction of neutral characters, so they cannot override or
/// embed a run the way the rejected controls do.
///
/// Agent and tool output is untrusted, so a value that reaches storage or a terminal must
/// pass this, on the sending side and again on the receiving side.
#[must_use]
pub fn is_plain_text(text: &str) -> bool {
    !text.is_empty()
        && !text
            .chars()
            .any(fleet_core::text::is_hostile_allowing_joiners)
}

/// True when `text` is a CI failure log the server may store: within [`MAX_CI_LOG_BYTES`],
/// non-empty and holding no hostile character except newline and tab.
#[must_use]
pub fn is_ci_log(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CI_LOG_BYTES
        && text
            .chars()
            .all(|c| matches!(c, '\n' | '\t') || !fleet_core::text::is_hostile_allowing_joiners(c))
}

/// True when `url` is a CI check link the server may store.
///
/// It must be `https` with a non-empty authority and no userinfo or backslash, hold only ASCII
/// graphic characters and be at most [`MAX_CI_URL_BYTES`] bytes. The host is not parsed, so an
/// authority with no host such as `https://:443/` passes. fleetd and the server both call it,
/// so a link one side keeps the other accepts. Any `https` host passes, so a consumer renders
/// the link as text or with `rel=noopener`.
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
            .field("expires_at_ms", &self.expires_at_ms)
            .field("git_identity", &self.git_identity)
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

/// Longest suggested edit payload, in bytes. The server refuses more, and the `suggested_edit`
/// table CHECK (migration 0038) holds the same number.
pub const MAX_EDIT_PAYLOAD_BYTES: usize = 65_536;

/// Most `pending` suggested edits one Work project holds. Filing past it is refused.
pub const MAX_PENDING_EDITS_PER_PROJECT: usize = 100;
