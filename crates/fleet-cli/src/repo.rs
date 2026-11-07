//! `fleet repo`: add, list and remove registered repositories.
//!
//! `add` parses the reference with [`RepoRef`] for fast feedback only: the server parses it again
//! with the grammar of the configured kind of the host, and its answer decides. `remove` applies
//! only the structural rules through [`RepoRef::locate`] and sends the host and path, because the
//! stored row was written under a grammar the client cannot know. Every server refusal is a fixed
//! [`CredentialNotice`], so no server text or input reaches the terminal. Hosts and paths print
//! through [`fleet_core::repo::ascii_form`], so a host is always shown in punycode form. The
//! verified time prints as the UTC stamp of [`fleet_core::stamp::utc_stamp`], `YYYY-MM-DD HH:MM
//! UTC`, the same text the repositories page shows.

use std::io::Write;

use clap::Subcommand;
use fleet_core::repo::{RepoRef, ascii_form};
use fleet_core::stamp::utc_stamp;
use fleet_proto::CredentialNotice;
use fleet_proto::v1::fleet_repos_client::FleetReposClient;
use fleet_proto::v1::{AddRepoRequest, ListReposRequest, RemoveRepoRequest, RepoInfo};
use tonic::Status;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, Scrub};

/// A `FleetRepos` client carrying the bearer token.
pub(crate) type ReposClient = FleetReposClient<InterceptedService<Channel, Bearer>>;

const NO_STRAY: &str = "this action takes one repository reference";

/// A `fleet repo` action.
#[derive(Debug, Subcommand)]
pub enum RepoAction {
    /// Verify and register a repository: host/owner/name or an https URL.
    Add {
        /// Repository reference. An internationalised host is written in punycode.
        #[arg(allow_hyphen_values = true)]
        repo: String,
        /// Refused: this action takes one reference.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// List registered repositories: host, path, forge, runnable, push and verified time (UTC).
    List {
        /// Refused: this action takes no arguments.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
    /// Remove a registered repository: host/owner/name or an https URL.
    Remove {
        /// Repository reference.
        #[arg(allow_hyphen_values = true)]
        repo: String,
        /// Refused: this action takes one reference.
        #[arg(hide = true, allow_hyphen_values = true, num_args = 0.., trailing_var_arg = true)]
        rest: Vec<String>,
    },
}

impl RepoAction {
    /// The stray arguments the action was given.
    pub(crate) fn rest(&self) -> &[String] {
        match self {
            Self::Add { rest, .. } | Self::List { rest } | Self::Remove { rest, .. } => rest,
        }
    }
}

fn notice(status: &Status) -> CliError {
    CliError::Credential(CredentialNotice::for_repo_status(status))
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
        Err(CliError::Usage(NO_STRAY.into()))
    }
}

/// Parses a repository reference. The server parses it again.
///
/// # Errors
///
/// Returns [`CliError::Credential`] with [`CredentialNotice::RepoInvalid`] for a reference
/// [`RepoRef::parse`] refuses.
pub(crate) fn parse_ref(text: &str) -> Result<RepoRef, CliError> {
    RepoRef::parse(text).map_err(|_| CliError::Credential(CredentialNotice::RepoInvalid))
}

/// Splits a reference into the host and path of a stored row, without a forge grammar.
///
/// # Errors
///
/// Returns [`CliError::Credential`] with [`CredentialNotice::RepoInvalid`] for a reference
/// [`RepoRef::locate`] refuses.
pub(crate) fn locate_ref(text: &str) -> Result<(String, String), CliError> {
    RepoRef::locate(text).map_err(|_| CliError::Credential(CredentialNotice::RepoInvalid))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn row(scrub: &Scrub, info: &RepoInfo) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        scrub.ident(&ascii_form(&info.host)),
        scrub.ident(&ascii_form(&info.path)),
        scrub.ident(&info.forge_kind),
        yes_no(info.runnable),
        info.push.map_or("unknown", yes_no),
        utc_stamp(info.verified_at_ms),
    )
}

/// Registers `repo` and prints the stored row, then the saved notice.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn add(
    client: &mut ReposClient,
    scrub: &Scrub,
    repo: &RepoRef,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let info = client
        .add_repo(AddRepoRequest {
            repo: format!("{}/{}", repo.host(), repo.display_path()),
        })
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    writeln!(out, "{}", row(scrub, &info))?;
    writeln!(out, "{}", CredentialNotice::Saved.text())?;
    Ok(())
}

/// Prints every registered repository, one per line.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn list(
    client: &mut ReposClient,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .list_repos(ListReposRequest {})
        .await
        .map_err(|s| notice(&s))?
        .into_inner();
    for info in &reply.repos {
        writeln!(out, "{}", row(scrub, info))?;
    }
    Ok(())
}

/// Removes the row at `host` and `path` and prints the deleted notice.
///
/// # Errors
///
/// Returns [`CliError::Credential`] for any server refusal, with
/// [`CredentialNotice::RepoMissing`] when the user has no such row, and [`CliError::Io`] when
/// writing fails.
pub(crate) async fn remove(
    client: &mut ReposClient,
    host: String,
    path: String,
    out: &mut impl Write,
) -> Result<(), CliError> {
    client
        .remove_repo(RemoveRepoRequest { host, path })
        .await
        .map_err(|s| notice(&s))?;
    writeln!(out, "{}", CredentialNotice::Deleted.text())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_outside_the_grammar_is_refused_without_an_echo() {
        let hostile = [
            "",
            "github.com",
            "github.com/owner",
            "github.com/a/b/c",
            "http://github.com/a/b",
            "ssh://github.com/a/b",
            "https://user@github.com/a/b",
            "github.com/a/b?x",
            "github.com/a/b#x",
            "github.com/a/%41",
            "github.com\\a/b",
            "github.com/a/b\r\n",
            "github.com/a/b\u{85}",
            "github.com/a/b\u{2028}",
            "github.com/a/b\u{202e}",
            "bücher.example/a/b",
            "[::1]/a/b",
            "exa mple.com/a/b",
            ".example.com/a/b",
            "example..com/a/b",
        ];
        for bad in hostile {
            assert!(
                matches!(
                    parse_ref(bad),
                    Err(CliError::Credential(CredentialNotice::RepoInvalid))
                ),
                "{bad:?}"
            );
        }
        let long = format!("github.com/{}/b", "o".repeat(5000));
        assert!(parse_ref(&long).is_err());
        assert_eq!(
            parse_ref("https://GitHub.com/Octo/Hello.git")
                .ok()
                .map(|repo| repo.path().to_owned())
                .as_deref(),
            Some("octo/hello")
        );
    }

    #[test]
    fn a_row_shows_a_punycode_host_and_escapes_anything_else() {
        let scrub = Scrub::default();
        let info = RepoInfo {
            host: "xn--bcher-kva.example".to_owned(),
            path: "o/r".to_owned(),
            forge_kind: "forgejo".to_owned(),
            runnable: false,
            verified_at_ms: 5,
            push: None,
        };
        assert_eq!(
            row(&scrub, &info),
            "xn--bcher-kva.example\to/r\tforgejo\tno\tunknown\t1970-01-01 00:00 UTC"
        );
        let hostile = RepoInfo {
            host: "b\u{fc}cher\u{202e}.example".to_owned(),
            push: Some(true),
            runnable: true,
            ..info
        };
        let shown = row(&scrub, &hostile);
        assert!(
            shown.starts_with("b\\u{fc}cher\\u{202e}.example\t"),
            "{shown}"
        );
        assert!(
            shown.ends_with("\tyes\tyes\t1970-01-01 00:00 UTC"),
            "{shown}"
        );
    }
}
