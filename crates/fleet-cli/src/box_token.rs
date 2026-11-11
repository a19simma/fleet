//! `fleet box-token issue|list|revoke`: manage per-Box tokens (ADR-0069).
//!
//! `issue` writes the plaintext token alone on its own line to the output, the one deliberate
//! write that bypasses the scrubber, and only after the reply holds exactly one token. The token
//! is never an argument. Every other path prints through [`Scrub`], which masks the token shape.
//! A refusal prints fixed text and never a server message or an input. The caller needs a
//! per-user API token: the static client token names no person and is refused.

use std::io::Write;

use clap::Subcommand;
use fleet_core::box_token::{DEFAULT_DAYS, MAX_DAYS, MAX_LABEL_CHARS, days_are_valid};
use fleet_core::stamp::utc_stamp;
use fleet_proto::v1::fleet_box_tokens_client::FleetBoxTokensClient;
use fleet_proto::v1::{
    BoxTokenInfo, IssueBoxTokenRequest, ListBoxTokensRequest, RevokeBoxTokenRequest,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Status};

use super::{Bearer, CliError, Scrub};

/// A `FleetBoxTokens` client carrying the bearer token.
pub(crate) type BoxTokensClient = FleetBoxTokensClient<InterceptedService<Channel, Bearer>>;

const HEADER: &str = "id\tbox\tlabel\tcreated\texpires\tdays_left\tlast_used\tstatus";
const SECONDS_PER_DAY: i64 = 86_400;

/// A `fleet box-token` action.
#[derive(Debug, Subcommand)]
pub enum BoxTokenAction {
    /// Issue a token for a box and print it alone on stdout. It is shown once.
    ///
    /// Pipe stdout to where the token goes. Diagnostics go to stderr.
    Issue {
        /// Box name: `box-` followed by digits.
        #[arg(value_name = "BOX", allow_hyphen_values = true)]
        box_name: String,
        /// A label to tell the token apart: at most 64 characters, no control characters.
        #[arg(long, allow_hyphen_values = true)]
        label: Option<String>,
        /// Lifetime in days, 1 to 365. The default is 90.
        #[arg(long, value_name = "N", allow_hyphen_values = true)]
        ttl_days: Option<String>,
    },
    /// List your tokens: id, box, label, created, expires, days left, last used and status.
    List,
    /// Revoke a token by its id. A token of another user counts as not found.
    Revoke {
        /// Token id, as listed.
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
}

fn refuse(status: &Status) -> CliError {
    CliError::Refused(match status.code() {
        Code::AlreadyExists => "box name is not available",
        Code::ResourceExhausted => "too many active box tokens",
        Code::PermissionDenied => "a per-user API token is required to manage box tokens",
        Code::InvalidArgument => "the server refused the box name, label or lifetime",
        Code::NotFound => "token not found",
        Code::Unauthenticated => "the server refused the token",
        Code::Unavailable => "the server is unavailable",
        _ => "the request failed",
    })
}

/// A checked `issue` request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IssueArgs {
    box_name: String,
    label: String,
    ttl_days: Option<u32>,
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Checks the `issue` arguments before any request. The messages never repeat a value.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a box name that is not `box-` and digits, a label over
/// [`MAX_LABEL_CHARS`] characters or holding a control or hostile character, and a lifetime that
/// is not plain digits from 1 to [`MAX_DAYS`].
pub(crate) fn parse_issue(
    box_name: &str,
    label: Option<&str>,
    ttl_days: Option<&str>,
) -> Result<IssueArgs, CliError> {
    let name = fleet_proto::validate_box(box_name)
        .map_err(|_| CliError::Usage("box: expected box- followed by digits".into()))?;
    let label = label.unwrap_or_default();
    if !fleet_core::box_token::label_is_valid(label) {
        return Err(CliError::Usage(format!(
            "label: at most {MAX_LABEL_CHARS} characters and no control characters"
        )));
    }
    let days = ttl_days
        .map(|text| {
            text.bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| text.parse::<u32>().ok())
                .flatten()
                .filter(|days| days_are_valid(*days))
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "ttl-days: a whole number from 1 to {MAX_DAYS}, default {DEFAULT_DAYS}"
                    ))
                })
        })
        .transpose()?;
    Ok(IssueArgs {
        box_name: name.as_str().to_owned(),
        label: label.to_owned(),
        ttl_days: days,
    })
}

/// Checks a token id before any request.
///
/// # Errors
///
/// Returns [`CliError::Usage`] unless the text is plain digits that fit a positive `i64`.
pub(crate) fn parse_id(text: &str) -> Result<i64, CliError> {
    Some(text)
        .filter(|text| digits(text))
        .and_then(|text| text.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| CliError::Usage("id: a positive whole number".into()))
}

/// Issues a token and writes it alone to `out`.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with fixed text for a server refusal or a reply that does not
/// hold exactly one token, and [`CliError::TokenNotDelivered`] when writing the token fails after
/// the server committed it. Nothing is written on an error before the check.
pub(crate) async fn issue(
    client: &mut BoxTokensClient,
    scrub: &Scrub,
    args: IssueArgs,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .issue_box_token(IssueBoxTokenRequest {
            r#box: args.box_name,
            label: args.label,
            ttl_days: args.ttl_days,
        })
        .await
        .map_err(|s| refuse(&s))?
        .into_inner();
    if !fleet_core::box_token::is_token(&reply.token) {
        return Err(CliError::Refused("the server returned a malformed token"));
    }
    if writeln!(out, "{}", reply.token)
        .and_then(|()| out.flush())
        .is_err()
    {
        return Err(CliError::TokenNotDelivered { id: reply.id });
    }
    let _ = writeln!(
        std::io::stderr(),
        "fleet: issued box token {} for {}, expires {}; it is shown once",
        reply.id,
        scrub.ident(&reply.r#box),
        scrub.ident(&reply.expires_at),
    );
    Ok(())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn number(text: &str, width: usize) -> Option<i64> {
    (text.len() == width && digits(text))
        .then(|| text.parse().ok())
        .flatten()
}

fn zone_seconds(zone: &str) -> Option<i64> {
    let sign = match zone.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let body = &zone[1..];
    let (hours, minutes) = body.split_once(':').unwrap_or((body, "00"));
    Some(sign * (number(hours, 2)? * 3600 + number(minutes, 2)? * 60))
}

/// Seconds since the epoch of a Postgres `timestamptz` text such as
/// `2026-11-06 21:20:33.5+00`, or `None` for anything else.
fn parse_time(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once(' ')?;
    let mut parts = date.split('-');
    let year = number(parts.next()?, 4)?;
    let month = number(parts.next()?, 2)?;
    let day = number(parts.next()?, 2)?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let at = rest.find(['+', '-'])?;
    let (clock, zone) = rest.split_at(at);
    let (whole, fraction) = clock.split_once('.').unwrap_or((clock, "0"));
    if !digits(fraction) {
        return None;
    }
    let mut parts = whole.split(':');
    let hour = number(parts.next()?, 2)?;
    let minute = number(parts.next()?, 2)?;
    let second = number(parts.next()?, 2)?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let local =
        days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second;
    Some(local - zone_seconds(zone)?)
}

fn stamp(secs: i64) -> String {
    u64::try_from(secs).map_or_else(|_| "-".to_owned(), |s| utc_stamp(s.saturating_mul(1000)))
}

fn row(scrub: &Scrub, now: i64, info: &BoxTokenInfo) -> String {
    let created = parse_time(&info.created_at).map_or_else(|| "-".to_owned(), stamp);
    let expires = parse_time(&info.expires_at);
    let (status, days) = match (info.revoked_at.is_some(), expires) {
        (true, _) => ("revoked", "0".to_owned()),
        (false, None) => ("unknown", "-".to_owned()),
        (false, Some(end)) if end > now => ("active", ((end - now) / SECONDS_PER_DAY).to_string()),
        (false, Some(_)) => ("expired", "0".to_owned()),
    };
    let last_used = info.last_used_at.as_deref().map_or_else(
        || "never".to_owned(),
        |text| parse_time(text).map_or_else(|| "-".to_owned(), stamp),
    );
    format!(
        "{}\t{}\t{}\t{created}\t{}\t{days}\t{last_used}\t{status}",
        info.id,
        scrub.ident(&info.r#box),
        scrub.ident(&info.label),
        expires.map_or_else(|| "-".to_owned(), stamp),
    )
}

/// Prints the header and one line per token.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with fixed text for a server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn list(
    client: &mut BoxTokensClient,
    scrub: &Scrub,
    now: i64,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .list_box_tokens(ListBoxTokensRequest {})
        .await
        .map_err(|s| refuse(&s))?
        .into_inner();
    writeln!(out, "{HEADER}")?;
    for info in &reply.tokens {
        writeln!(out, "{}", row(scrub, now, info))?;
    }
    Ok(())
}

/// Revokes the token and prints `revoked`.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with fixed text for a server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn revoke(
    client: &mut BoxTokensClient,
    id: i64,
    out: &mut impl Write,
) -> Result<(), CliError> {
    client
        .revoke_box_token(RevokeBoxTokenRequest { id })
        .await
        .map_err(|s| refuse(&s))?;
    writeln!(out, "revoked")?;
    Ok(())
}
