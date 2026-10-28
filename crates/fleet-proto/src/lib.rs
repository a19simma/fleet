//! Wire types shared by fleetd, the server and the CLI.
//!
//! The `fleet.v1` package is generated from `proto/fleet/v1/fleet.proto`. [`convert`]
//! maps its [`v1::Envelope`] to and from [`fleet_core::Envelope`].

mod convert;

pub use convert::{ConvertError, queued_event, validate_box};

/// Longest accepted profile JSON, in bytes. Escapes make the JSON longer than its text, so
/// this sits above the 4 MiB text cap of the validator.
pub const MAX_PROFILE_JSON_BYTES: usize = 8 * 1024 * 1024;

/// Largest profile-carrying message either side encodes or decodes, in bytes: the profile
/// JSON plus 1 MiB for the rest of the message.
///
/// It applies to `FleetProfiles` on the server, to the `FleetWorker` reply of
/// `GetProfileBlob` on the server (encode) and on every `FleetWorker` client (decode), and to
/// the `FleetProfiles` client. The tonic client default of 4 MiB is below the largest profile.
/// It also bounds the `GetJobTranscript` reply on the same server and clients: the transcript
/// text plus 2 MiB for the per-chunk fields of up to 50 000 rows stays below it.
pub const MAX_PROFILE_MESSAGE_BYTES: usize = MAX_PROFILE_JSON_BYTES + 1024 * 1024;

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

/// Most transcript chunks one report may carry. The server rejects more.
pub const MAX_CHUNKS_PER_REPORT: usize = 256;

/// Most telemetry events one report may carry. The server rejects more.
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
/// It must be `https` with a host and no userinfo or backslash, hold only ASCII graphic
/// characters and be at most [`MAX_CI_URL_BYTES`] bytes. fleetd and the server both call it,
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
