//! `fleet credential`: list, put, delete and verify stored credentials of every kind.
//!
//! The secret is read from stdin and never from an argument. Every server refusal is a fixed
//! [`CredentialNotice`]: a server message is never printed, so nothing the server echoes
//! can reach the terminal. Usage, I/O and connect failures keep their own `CliError` variants.

use std::io::{Read, Write};

use clap::Subcommand;
use fleet_core::credential::{CredentialKind, GITHUB_HOST};
use fleet_core::host::HostName;
use fleet_proto::v1::fleet_credentials_client::FleetCredentialsClient;
use fleet_proto::v1::{
    CredentialInfo, DeleteCredentialRequest, ListCredentialsRequest, PutCredentialRequest,
    VerifyCredentialRequest,
};
use fleet_proto::{CredentialNotice, MAX_CREDENTIAL_VALUE_BYTES};
use tonic::Status;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use zeroize::Zeroizing;

use super::{Bearer, CliError, Scrub};

/// A `FleetCredentials` client carrying the bearer token.
pub(crate) type CredentialsClient = FleetCredentialsClient<InterceptedService<Channel, Bearer>>;

const STATIC_SECRET: &str = "static_secret";
const NO_ARGV_SECRET: &str = "the secret is read from stdin, never from arguments";
const HOST_REQUIRED: &str = "this kind needs --host";
const HOST_GITHUB_ONLY: &str = "this kind is stored for github.com only";

/// A `fleet credential` action.
#[derive(Debug, Subcommand)]
pub enum CredentialAction {
    /// List stored credentials: id, kind, fingerprint, login, expiry and host. Never the value.
    List {
        /// Show only credentials stored for this host.
        #[arg(long)]
        host: Option<String>,
        /// Refused: this action takes no arguments.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Store a credential. The secret is read from stdin.
    Put {
        /// Credential kind, such as `anthropic_api_key` or `github_pat`.
        #[arg(allow_hyphen_values = true)]
        kind: String,
        /// Host the credential is stored for. Required for `forgejo_pat`; every other kind
        /// belongs to `github.com`, the default.
        #[arg(long)]
        host: Option<String>,
        /// Refused: the secret is never an argument.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Delete a stored credential by id.
    Delete {
        /// Credential id from `fleet credential list`.
        #[arg(allow_hyphen_values = true)]
        id: String,
        /// Host the credential is stored for, from `fleet credential list`. Defaults to
        /// `github.com`.
        #[arg(long)]
        host: Option<String>,
        /// Refused: this action takes one id.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Check a stored credential with GitHub. Kinds without a verifier are refused.
    Verify {
        /// Credential id from `fleet credential list`.
        #[arg(allow_hyphen_values = true)]
        id: String,
        /// Refused: this action takes one id.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
}

impl CredentialAction {
    /// The stray arguments the action was given.
    pub(crate) fn rest(&self) -> &[String] {
        match self {
            Self::List { rest, .. }
            | Self::Put { rest, .. }
            | Self::Delete { rest, .. }
            | Self::Verify { rest, .. } => rest,
        }
    }
}

fn notice(status: &Status) -> CliError {
    CliError::Credential(CredentialNotice::for_status(status))
}

/// Parses a credential id. A value that is not an unsigned number names no credential.
///
/// # Errors
///
/// Returns [`CliError::Credential`] with [`CredentialNotice::NotFound`] for anything else.
pub(crate) fn parse_id(text: &str) -> Result<u64, CliError> {
    text.parse::<u64>()
        .map_err(|_| CliError::Credential(CredentialNotice::NotFound))
}

/// Checks the kind name against the closed set of kinds.
///
/// # Errors
///
/// Returns [`CliError::Credential`] with [`CredentialNotice::Invalid`] for an unknown kind.
pub(crate) fn parse_kind(text: &str) -> Result<CredentialKind, CliError> {
    CredentialKind::from_wire_name(text).ok_or(CliError::Credential(CredentialNotice::Invalid))
}

/// Parses a `--host` value with [`HostName::normalise`], so a hostile value is refused before
/// any request. The server stays the authority and checks again.
///
/// # Errors
///
/// Returns [`CliError::Usage`] with the fixed text of the grammar row the value matches. The
/// text never repeats the value.
pub(crate) fn parse_host(text: &str) -> Result<HostName, CliError> {
    HostName::normalise(text).map_err(|err| CliError::Usage(format!("--host: {err}")))
}

/// The host a `put` of `kind` stores for. No `--host` means `github.com` for every kind except
/// `forgejo_pat`, which must name its host. Any other kind accepts only `github.com`.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a missing host on `forgejo_pat`, for a value outside the host
/// grammar, and for another host on a kind that belongs to `github.com`.
pub(crate) fn put_host(kind: CredentialKind, host: Option<&str>) -> Result<HostName, CliError> {
    match host {
        None if kind.needs_host() => Err(CliError::Usage(HOST_REQUIRED.into())),
        None => parse_host(GITHUB_HOST),
        Some(text) => {
            let name = parse_host(text)?;
            if !kind.needs_host() && name.as_str() != GITHUB_HOST {
                return Err(CliError::Usage(HOST_GITHUB_ONLY.into()));
            }
            Ok(name)
        }
    }
}

/// Refuses stray arguments with a fixed message that never repeats them.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when `rest` is not empty.
pub(crate) fn no_stray(rest: &[String]) -> Result<(), CliError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(CliError::Usage(NO_ARGV_SECRET.into()))
    }
}

/// Reads the secret from `source`: at most [`MAX_CREDENTIAL_VALUE_BYTES`] of secret, followed
/// by line endings. Every trailing CR and LF is removed, so a pipe that adds `\r\n\r\n` stores
/// the same value as one that adds nothing. The read stops three bytes past the cap, so longer
/// input is refused without being held.
///
/// The buffer and the returned value zero when they drop.
///
/// # Errors
///
/// Returns [`CliError::Credential`] with [`CredentialNotice::Invalid`] for input over the
/// cap or not valid UTF-8, and [`CliError::Io`] when the read fails.
pub(crate) fn read_secret(source: &mut impl Read) -> Result<Zeroizing<String>, CliError> {
    let cap = MAX_CREDENTIAL_VALUE_BYTES as u64;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_VALUE_BYTES + 3));
    source.take(cap + 3).read_to_end(&mut bytes)?;
    while bytes.last().is_some_and(|b| matches!(b, b'\r' | b'\n')) {
        bytes.pop();
    }
    if bytes.len() as u64 > cap {
        return Err(CliError::Credential(CredentialNotice::Invalid));
    }
    std::str::from_utf8(&bytes)
        .map(|text| Zeroizing::new(text.to_owned()))
        .map_err(|_| CliError::Credential(CredentialNotice::Invalid))
}

fn row(scrub: &Scrub, info: &CredentialInfo) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        info.id,
        scrub.ident(&info.kind),
        scrub.ident(&info.fingerprint),
        info.login
            .as_deref()
            .map_or_else(|| "-".to_owned(), |l| scrub.ident(l)),
        info.expires_at_ms
            .map_or_else(|| "-".to_owned(), |ms| ms.to_string()),
        if info.host.is_empty() {
            "-".to_owned()
        } else {
            scrub.ident(&info.host)
        },
    )
}

/// Prints every stored credential, one per line, ending in its host. `only` keeps the rows of
/// one host.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn list(
    client: &mut CredentialsClient,
    scrub: &Scrub,
    only: Option<&HostName>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .list_credentials(ListCredentialsRequest {})
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    for info in reply
        .credentials
        .iter()
        .filter(|info| only.is_none_or(|host| info.host == host.as_str()))
    {
        writeln!(out, "{}", row(scrub, info))?;
    }
    Ok(())
}

/// Stores `value` under `kind` for `host` and prints the stored row.
///
/// The request takes the string out of `value`, so the zeroing buffer is left empty. The
/// request owns the plain copy until tonic has encoded and dropped it, which this crate cannot
/// zero.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn put(
    client: &mut CredentialsClient,
    scrub: &Scrub,
    kind: CredentialKind,
    host: &HostName,
    mut value: Zeroizing<String>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let info = client
        .put_credential(PutCredentialRequest {
            kind: kind.wire_name().to_owned(),
            shape: STATIC_SECRET.to_owned(),
            value: std::mem::take(&mut *value),
            expires_at_ms: None,
            host: host.as_str().to_owned(),
        })
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    writeln!(out, "{}", row(scrub, &info))?;
    Ok(())
}

/// Deletes credential `id` stored for `host`. No host means `github.com` on the server.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn delete(
    client: &mut CredentialsClient,
    id: u64,
    host: Option<&HostName>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    client
        .delete_credential(DeleteCredentialRequest {
            id,
            host: host.map_or_else(String::new, |h| h.as_str().to_owned()),
        })
        .await
        .map_err(|s| notice(&s))?;
    writeln!(out, "{}", CredentialNotice::Deleted.text())?;
    Ok(())
}

/// Verifies credential `id` and prints the result.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and for a reply with `valid: false`,
/// and [`CliError::Io`] when writing fails. The server answers `valid: false` for a PAT GitHub
/// refused and, for a `github_app` credential, for any mint failure: an absent lane, a
/// malformed installation id, a failed installation lookup, a signing failure, a refused mint
/// and a revoke GitHub refused.
pub(crate) async fn verify(
    client: &mut CredentialsClient,
    scrub: &Scrub,
    id: u64,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .verify_credential(VerifyCredentialRequest { id })
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    if !reply.valid {
        return Err(CliError::Credential(CredentialNotice::InvalidToken));
    }
    write!(out, "{}", CredentialNotice::Verified.text())?;
    if let Some(login) = &reply.login {
        write!(out, "\t{}", scrub.ident(login))?;
    }
    if let Some(ms) = reply.expires_at_ms {
        write!(out, "\t{ms}")?;
    }
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_that_is_not_an_unsigned_number_names_no_credential() {
        for bad in ["abc", "-1", "", " 1", "1.5", "18446744073709551616"] {
            assert!(
                matches!(
                    parse_id(bad),
                    Err(CliError::Credential(CredentialNotice::NotFound))
                ),
                "{bad}"
            );
        }
        assert!(matches!(parse_id("7"), Ok(7)));
    }

    const FORGEJO: &str = "forgejo_pat";

    fn usage(result: Result<HostName, CliError>) -> Option<String> {
        match result {
            Err(CliError::Usage(text)) => Some(text),
            _ => None,
        }
    }

    #[test]
    fn a_github_kind_defaults_to_github_com_and_forgejo_must_name_a_host() {
        for kind in CredentialKind::ALL {
            if kind.needs_host() {
                assert_eq!(usage(put_host(kind, None)).as_deref(), Some(HOST_REQUIRED));
            } else {
                let host = put_host(kind, None).ok();
                assert_eq!(host.as_ref().map(HostName::as_str), Some("github.com"));
            }
        }
    }

    #[test]
    fn an_explicit_host_is_normalised_and_kept_for_forgejo() {
        let kind = parse_kind(FORGEJO).unwrap();
        let host = put_host(kind, Some("Git.Example.COM.")).ok();
        assert_eq!(host.as_ref().map(HostName::as_str), Some("git.example.com"));
    }

    #[test]
    fn a_github_kind_refuses_another_host_and_accepts_github_com_in_any_case() {
        for kind in CredentialKind::ALL.into_iter().filter(|k| !k.needs_host()) {
            assert_eq!(
                usage(put_host(kind, Some("git.example.com"))).as_deref(),
                Some(HOST_GITHUB_ONLY)
            );
            let host = put_host(kind, Some("GitHub.com.")).ok();
            assert_eq!(host.as_ref().map(HostName::as_str), Some("github.com"));
        }
    }

    #[test]
    fn a_hostile_host_is_refused_for_every_kind_with_text_that_never_echoes_it() {
        let long = format!("{}.example.com", "a".repeat(300));
        let hostile = [
            "git.example.com\r",
            "git.example.com\n",
            "git.example.com\r\nx.example.com",
            "git\u{85}.example.com",
            "git\u{2028}.example.com",
            "git\u{2029}.example.com",
            "zqxuser@git.example.com",
            "zqxuser:zqxpw@git.example.com",
            "git.example.com\\x",
            "[::1]",
            "::1",
            "git..example.com",
            ".git.example.com",
            "",
            long.as_str(),
            " git.example.com",
            "git.example.com ",
            "git example.com",
            "gït\u{200b}.example.com",
            "https://git.example.com",
            "ssh://git.example.com",
            "//git.example.com",
            "git.example.com/path",
            "git.example.com?q=1",
            "git.example.com:8443",
            "git.example.com:443",
            "127.0.0.1",
            "*.example.com",
            "localhost",
            "git.local",
        ];
        for kind in CredentialKind::ALL {
            for text in hostile {
                let refused = usage(put_host(kind, Some(text)));
                let refused = refused.unwrap_or_else(|| panic!("{kind:?} {text:?} accepted"));
                assert!(refused.starts_with("--host: "), "{refused}");
                assert!(!refused.contains("zqx"), "{refused}");
                assert!(refused.len() < 60, "{refused}");
            }
        }
        assert!(parse_host("git.example.com").is_ok());
    }

    #[test]
    fn a_non_ascii_name_is_stored_in_punycode_form() {
        let host = parse_host("bücher.example").ok();
        assert_eq!(
            host.as_ref().map(HostName::as_str),
            Some("xn--bcher-kva.example")
        );
    }

    fn secret(input: &[u8]) -> Result<String, CliError> {
        read_secret(&mut &*input).map(|value| value.as_str().to_owned())
    }

    #[test]
    fn every_trailing_line_ending_is_trimmed_and_inner_ones_stay() {
        let cases: [(&[u8], &str); 9] = [
            (b"key\n", "key"),
            (b"key\r\n", "key"),
            (b"key\r\n\r\n", "key"),
            (b"key\n\n\n", "key"),
            (b"key\r", "key"),
            (b"key\n\r\n\r", "key"),
            (b"key", "key"),
            (b"", ""),
            (b"a\nb\r\n", "a\nb"),
        ];
        for (input, want) in cases {
            assert_eq!(secret(input).ok().as_deref(), Some(want), "{input:?}");
        }
    }

    #[test]
    fn the_cap_counts_the_secret_and_not_its_line_endings() {
        let cap = MAX_CREDENTIAL_VALUE_BYTES;
        let at_cap = "k".repeat(cap);
        for tail in ["", "\n", "\r\n", "\n\n\n"] {
            let input = format!("{at_cap}{tail}");
            assert_eq!(
                secret(input.as_bytes()).ok().as_deref(),
                Some(at_cap.as_str()),
                "{tail:?}"
            );
        }
        for input in [
            format!("{at_cap}k"),
            format!("{at_cap}k\n"),
            format!("{at_cap}kkk"),
        ] {
            assert!(
                matches!(
                    secret(input.as_bytes()),
                    Err(CliError::Credential(CredentialNotice::Invalid))
                ),
                "{}",
                input.len()
            );
        }
        assert!(matches!(
            secret(b"\xff\xfe"),
            Err(CliError::Credential(CredentialNotice::Invalid))
        ));
    }
}
