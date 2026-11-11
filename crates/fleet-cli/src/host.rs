//! `fleet host add|list|remove|approve-private|revoke-private|requests`: manage git hosts and
//! the approval of their private addresses.
//!
//! `add` and `remove` normalise the argument with [`HostName::normalise`] for fast feedback and
//! send the punycode form. The server checks again and its answer decides. Every server refusal
//! is a fixed [`CredentialNotice`], so no server text or input reaches the terminal. A refusal of
//! a private or unlisted host is [`CredentialNotice::HostRefused`] for every cause, and its text
//! carries the ask-an-admin hint: the reply never says why a host was refused, so the hint is the
//! same for all of them and the command never tells a private name from any other refused name.
//! `remove` is admin-only: the server's fixed `admin required` denial prints [`ADMIN_ONLY`].
//! `approve-private`, `revoke-private` and `requests` are admin-only too. `revoke-private` and
//! `requests` print [`ADMIN_ONLY_PRIVATE`]. The shared `FLEET_CLIENT_TOKEN` acts as the
//! bootstrap user, which is never an admin, so the admin actions need a per-user API token. Each
//! address argument is parsed as an IP address before any request. The server answers
//! `approve-private` with `NOT_FOUND` for a non-admin and for an unknown host alike, so both print the same fixed
//! [`CredentialNotice::HostMissing`] text. Approval prints the addresses the server stored.
//! Hosts print through [`fleet_core::repo::ascii_form`], so a host is always shown in its ASCII
//! form.

use std::io::Write;
use std::net::IpAddr;

use clap::Subcommand;
use fleet_core::host::HostName;
use fleet_core::repo::ascii_form;
use fleet_proto::v1::fleet_hosts_client::FleetHostsClient;
use fleet_proto::v1::{
    AddHostRequest, ApproveHostPrivateRequest, HostInfo, HostRequestInfo, ListHostRequestsRequest,
    ListHostsRequest, RemoveHostRequest, RevokeHostPrivateRequest,
};
use fleet_proto::{CredentialNotice, MAX_HOST_APPROVED_IPS};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Status};

use super::{Bearer, CliError, Scrub};

/// A `FleetHosts` client carrying the bearer token.
pub(crate) type HostsClient = FleetHostsClient<InterceptedService<Channel, Bearer>>;

/// The text printed when a non-admin removes a host.
pub const ADMIN_ONLY: &str = "Only an admin can remove a host.";

/// The text printed when a non-admin revokes an approval or lists the pending requests.
pub const ADMIN_ONLY_PRIVATE: &str = "Only an admin can do this.";

const NO_STRAY: &str = "this action takes one host name";
const NO_ARGS: &str = "this action takes no arguments";
const ADMIN_REQUIRED: &str = "admin required";

/// A `fleet host` action.
#[derive(Debug, Subcommand)]
pub enum HostAction {
    /// Add a git host. A name that resolves to a private address needs an admin's approval.
    Add {
        /// Bare host name, without a scheme, port or path. An internationalised name is
        /// accepted and printed in punycode.
        #[arg(allow_hyphen_values = true)]
        host: String,
        /// Refused: this action takes one host.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// List the hosts: host, kind and whether an admin approved its private addresses.
    List {
        /// Refused: this action takes no arguments.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Remove a host that has no credentials or repositories. Admin only.
    Remove {
        /// Host name, as listed.
        #[arg(allow_hyphen_values = true)]
        host: String,
        /// Refused: this action takes one host.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Approve a pending host for its private addresses. Admin only.
    ///
    /// The addresses must equal what the host resolves to now; list them with `requests`.
    ApprovePrivate {
        /// Host name, as listed in a request.
        #[arg(allow_hyphen_values = true)]
        host: String,
        /// The IP addresses the host resolves to, at least one.
        #[arg(allow_hyphen_values = true, num_args = 1.., required = true)]
        addresses: Vec<String>,
    },
    /// Revoke the private approval of a host. Admin only.
    RevokePrivate {
        /// Host name, as listed.
        #[arg(allow_hyphen_values = true)]
        host: String,
        /// Refused: this action takes one host.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// List the pending requests for private hosts. Admin only.
    Requests {
        /// Refused: this action takes no arguments.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
}

impl HostAction {
    /// The stray arguments the action was given.
    pub(crate) fn rest(&self) -> &[String] {
        match self {
            Self::Add { rest, .. }
            | Self::List { rest }
            | Self::Remove { rest, .. }
            | Self::RevokePrivate { rest, .. }
            | Self::Requests { rest } => rest,
            Self::ApprovePrivate { .. } => &[],
        }
    }

    fn stray_text(&self) -> &'static str {
        match self {
            Self::List { .. } | Self::Requests { .. } => NO_ARGS,
            Self::Add { .. }
            | Self::Remove { .. }
            | Self::ApprovePrivate { .. }
            | Self::RevokePrivate { .. } => NO_STRAY,
        }
    }

    /// Refuses stray arguments with a fixed message that never repeats them.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] when the action was given arguments it does not take.
    pub(crate) fn no_stray(&self) -> Result<(), CliError> {
        if self.rest().is_empty() {
            Ok(())
        } else {
            Err(CliError::Usage(self.stray_text().into()))
        }
    }
}

fn notice(status: &Status) -> CliError {
    CliError::Credential(CredentialNotice::for_host_status(status))
}

fn admin_notice(status: &Status, text: &'static str) -> CliError {
    if status.code() == Code::PermissionDenied && status.message() == ADMIN_REQUIRED {
        CliError::Refused(text)
    } else {
        notice(status)
    }
}

/// Parses address arguments with the standard IP address parser, so a malformed value is refused
/// before any request. The result is sorted and free of duplicates.
///
/// # Errors
///
/// Returns [`CliError::Usage`] with a fixed text, never the value, for a value that is not an IP
/// address and for a list of more than [`MAX_HOST_APPROVED_IPS`] arguments, counted before
/// duplicates are dropped.
pub(crate) fn parse_addresses(texts: &[String]) -> Result<Vec<IpAddr>, CliError> {
    if texts.len() > MAX_HOST_APPROVED_IPS {
        return Err(CliError::Usage(format!(
            "address: at most {MAX_HOST_APPROVED_IPS} addresses"
        )));
    }
    let mut parsed = Vec::with_capacity(texts.len());
    for text in texts {
        let addr = text
            .parse::<IpAddr>()
            .map_err(|_| CliError::Usage("address: not an IP address".into()))?;
        parsed.push(addr);
    }
    parsed.sort();
    parsed.dedup();
    Ok(parsed)
}

/// Parses a host argument with [`HostName::normalise`], so a hostile value is refused before
/// any request.
///
/// # Errors
///
/// Returns [`CliError::Usage`] with the fixed text of the grammar row the value matches. The
/// text never repeats the value.
pub(crate) fn parse_host(text: &str) -> Result<HostName, CliError> {
    HostName::normalise(text).map_err(|err| CliError::Usage(format!("host: {err}")))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn row(scrub: &Scrub, info: &HostInfo) -> String {
    format!(
        "{}\t{}\t{}",
        scrub.ident(&ascii_form(&info.host)),
        scrub.ident(&info.kind),
        yes_no(info.allow_private),
    )
}

/// Adds `host` and prints the stored row, then the added notice.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn add(
    client: &mut HostsClient,
    scrub: &Scrub,
    host: &HostName,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let info = client
        .add_host(AddHostRequest {
            host: host.as_str().to_owned(),
        })
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    writeln!(out, "{}", row(scrub, &info))?;
    writeln!(out, "{}", CredentialNotice::HostAdded.text())?;
    Ok(())
}

/// Prints every host, one per line: host, kind and the private flag.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn list(
    client: &mut HostsClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .list_hosts(ListHostsRequest {})
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    for info in &reply.hosts {
        writeln!(out, "{}", row(scrub, info))?;
    }
    Ok(())
}

/// Removes `host` and prints the removed notice.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with [`ADMIN_ONLY`] for a caller who is not an admin,
/// [`CliError::Credential`] for any other server refusal and [`CliError::Io`] when writing
/// fails.
pub(crate) async fn remove(
    client: &mut HostsClient,
    host: &HostName,
    out: &mut impl Write,
) -> Result<(), CliError> {
    client
        .remove_host(RemoveHostRequest {
            host: host.as_str().to_owned(),
        })
        .await
        .map_err(|s| admin_notice(&s, ADMIN_ONLY))?;
    writeln!(out, "{}", CredentialNotice::HostRemoved.text())?;
    Ok(())
}

fn addresses(scrub: &Scrub, ips: &[String]) -> String {
    ips.iter()
        .map(|ip| scrub.ident(ip))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Approves `host` for `ips` and prints the stored row, the approved addresses and the approved
/// notice.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal, including `NOT_FOUND` for a
/// non-admin or an unknown host, and [`CliError::Io`] when writing fails.
pub(crate) async fn approve(
    client: &mut HostsClient,
    scrub: &Scrub,
    host: &HostName,
    ips: &[IpAddr],
    out: &mut impl Write,
) -> Result<(), CliError> {
    let info = client
        .approve_host_private(ApproveHostPrivateRequest {
            host: host.as_str().to_owned(),
            approved_ips: ips.iter().map(ToString::to_string).collect(),
        })
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    writeln!(out, "{}", row(scrub, &info))?;
    writeln!(out, "approved: {}", addresses(scrub, &info.approved_ips))?;
    writeln!(out, "{}", CredentialNotice::HostApproved.text())?;
    Ok(())
}

/// Revokes the private approval of `host` and prints the stored row, then the revoked notice.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with [`ADMIN_ONLY_PRIVATE`] for a caller who is not an admin,
/// [`CliError::Credential`] for any other server refusal and [`CliError::Io`] when writing
/// fails.
pub(crate) async fn revoke(
    client: &mut HostsClient,
    scrub: &Scrub,
    host: &HostName,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let info = client
        .revoke_host_private(RevokeHostPrivateRequest {
            host: host.as_str().to_owned(),
        })
        .await
        .map_err(|s| admin_notice(&s, ADMIN_ONLY_PRIVATE))?
        .into_inner();
    writeln!(out, "{}", row(scrub, &info))?;
    writeln!(out, "{}", CredentialNotice::HostRevoked.text())?;
    Ok(())
}

fn request_row(scrub: &Scrub, request: &HostRequestInfo) -> String {
    format!(
        "{}\t{}\t{}",
        scrub.ident(&ascii_form(&request.host)),
        request.requested_by,
        addresses(scrub, &request.resolved_ips),
    )
}

/// Prints every pending private request, one per line: host, requesting user and the resolved
/// addresses.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with [`ADMIN_ONLY_PRIVATE`] for a caller who is not an admin,
/// [`CliError::Credential`] for any other server refusal and [`CliError::Io`] when writing
/// fails.
pub(crate) async fn requests(
    client: &mut HostsClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .list_host_requests(ListHostRequestsRequest {})
        .await
        .map_err(|s| admin_notice(&s, ADMIN_ONLY_PRIVATE))?
        .into_inner();
    for request in &reply.requests {
        writeln!(out, "{}", request_row(scrub, request))?;
    }
    Ok(())
}
