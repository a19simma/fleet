//! `fleet profile`: create, list and show named agent profiles.

use std::io::{Read, Write};

use fleet_proto::MAX_PROFILE_JSON_BYTES;
use fleet_proto::v1::fleet_profiles_client::FleetProfilesClient;
use fleet_proto::v1::{
    CreateProfileRequest, GetProfileRequest, ListProfilesRequest, ProfileSummary, ProfileVersion,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, sanitize};

/// A `FleetProfiles` client carrying the bearer token.
pub(crate) type ProfilesClient = FleetProfilesClient<InterceptedService<Channel, Bearer>>;

/// Profiles asked for per `ListProfiles` call. The server honours at most 200.
const LIST_PAGE: u32 = 200;

/// Most pages `list` follows: one million profiles at the page size. A server that keeps
/// returning new names past this is treated as hostile.
const MAX_LIST_PAGES: usize = 5_000;
const TOO_LARGE: &str = "profile JSON is larger than the allowed maximum";
const TOO_MANY_PAGES: &str = "server returned too many profile list pages";
const BAD_TARGET: &str =
    "invalid profile: use <name> or <name>@<version> with a version of 1 or more";

/// Splits `name` or `name@version` into the name and the optional version.
///
/// A profile name never holds `@`, so the first one separates the version. An empty name,
/// an empty or non-numeric version and version 0 are usage errors. The message never
/// repeats the input. The name itself is validated by the server.
///
/// # Errors
/// Returns [`CliError::Usage`] for any target outside that grammar.
pub(crate) fn split_target(target: &str) -> Result<(&str, Option<u32>), CliError> {
    let usage = || CliError::Usage(BAD_TARGET.into());
    let Some((name, version)) = target.split_once('@') else {
        return Ok((target, None));
    };
    if name.is_empty() || version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(usage());
    }
    match version.parse::<u32>() {
        Ok(v) if v >= 1 => Ok((name, Some(v))),
        _ => Err(usage()),
    }
}

/// Reads at most `MAX_PROFILE_JSON_BYTES` from `source`.
///
/// # Errors
/// Returns [`CliError::Usage`] with a fixed message when the source holds more bytes.
fn read_bounded(source: &mut impl Read) -> Result<String, CliError> {
    let mut text = String::new();
    source
        .take(MAX_PROFILE_JSON_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    if text.len() > MAX_PROFILE_JSON_BYTES {
        return Err(CliError::Usage(TOO_LARGE.into()));
    }
    Ok(text)
}

/// Reads the profile JSON from `path`, or from `stdin` when `path` is `-`.
///
/// The read stops one byte past `MAX_PROFILE_JSON_BYTES`, so no input is read unbounded.
pub(crate) fn read_source(path: &str, stdin: &mut impl Read) -> Result<String, CliError> {
    if path == "-" {
        read_bounded(stdin)
    } else {
        read_bounded(&mut std::fs::File::open(path)?)
    }
}

fn write_version(out: &mut impl Write, reply: &ProfileVersion) -> std::io::Result<()> {
    writeln!(out, "name: {}", sanitize(&reply.name))?;
    writeln!(out, "version: {}", reply.version)?;
    writeln!(out, "hash: {}", sanitize(&reply.hash))
}

/// `fleet profile create`: sends the raw JSON and prints the stored version.
pub(crate) async fn create(
    client: &mut ProfilesClient,
    name: String,
    content_json: String,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .create_profile(CreateProfileRequest { name, content_json })
        .await?
        .into_inner();
    write_version(out, &reply)?;
    writeln!(out, "created: {}", if reply.created { "yes" } else { "no" })?;
    Ok(())
}

/// `fleet profile list`: one row per profile, following `after_name` to the last page.
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "the call site hands over its one client mutably, like create and show"
)]
pub(crate) async fn list(
    client: &mut ProfilesClient,
    out: &mut impl Write,
) -> Result<(), CliError> {
    list_pages(
        |after_name| {
            let mut client = client.clone();
            async move {
                Ok(client
                    .list_profiles(ListProfilesRequest {
                        limit: LIST_PAGE,
                        after_name,
                    })
                    .await?
                    .into_inner()
                    .profiles)
            }
        },
        out,
    )
    .await
}

/// Follows pages from `fetch` until an empty one, a page that does not advance, or
/// `MAX_LIST_PAGES`.
async fn list_pages<F, Fut>(mut fetch: F, out: &mut impl Write) -> Result<(), CliError>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<Vec<ProfileSummary>, CliError>>,
{
    let mut after_name = None;
    for _ in 0..MAX_LIST_PAGES {
        let page = fetch(after_name.clone()).await?;
        let Some(last) = page.last() else {
            return Ok(());
        };
        if after_name.as_ref().is_some_and(|prev| last.name <= *prev) {
            return Err(CliError::Usage(
                "server returned a profile list that does not advance".into(),
            ));
        }
        for profile in &page {
            writeln!(
                out,
                "{}\t{}\t{}",
                sanitize(&profile.name),
                profile.latest_version,
                sanitize(&profile.hash)
            )?;
        }
        after_name = Some(last.name.clone());
    }
    Err(CliError::Usage(TOO_MANY_PAGES.into()))
}

/// `fleet profile show`: canonical content, version and hash of one profile version.
///
/// No job references a profile yet, so `used-by` prints `-`: the count is unknown, never zero.
pub(crate) async fn show(
    client: &mut ProfilesClient,
    name: String,
    version: Option<u32>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .get_profile(GetProfileRequest { name, version })
        .await?
        .into_inner();
    write_version(out, &reply)?;
    writeln!(out, "used-by: -")?;
    writeln!(out, "content: {}", sanitize(&reply.content_json))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_has_no_version() {
        assert_eq!(split_target("alpha").ok(), Some(("alpha", None)));
    }

    #[test]
    fn a_version_suffix_is_split_off() {
        assert_eq!(split_target("alpha@3").ok(), Some(("alpha", Some(3))));
        assert_eq!(split_target("a@10").ok(), Some(("a", Some(10))));
    }

    #[test]
    fn malformed_suffixes_are_usage_errors() {
        for bad in [
            "a@",
            "a@x",
            "a@0",
            "@1",
            "a@1@2",
            "a@-1",
            "a@+1",
            "a@1.5",
            "a@99999999999",
        ] {
            let err = split_target(bad).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{bad}");
            assert!(!err.to_string().contains(bad), "{bad}");
        }
    }

    #[test]
    fn dash_reads_stdin_and_a_path_reads_the_file() {
        let mut stdin = &b"{\"a\":1}"[..];
        assert_eq!(
            read_source("-", &mut stdin).ok().as_deref(),
            Some("{\"a\":1}")
        );
        assert!(read_source("/nonexistent/p.json", &mut &b""[..]).is_err());
    }

    #[test]
    fn exactly_the_cap_passes_and_one_more_byte_fails() {
        let cap = MAX_PROFILE_JSON_BYTES;
        let at = vec![b'a'; cap];
        assert_eq!(read_bounded(&mut &at[..]).unwrap().len(), cap);
        let over = vec![b'a'; cap + 1];
        let err = read_bounded(&mut &over[..]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn an_over_cap_stdin_is_a_usage_error() {
        let over = vec![b'a'; MAX_PROFILE_JSON_BYTES + 1];
        let err = read_source("-", &mut &over[..]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[tokio::test]
    async fn a_pager_that_never_ends_stops_at_the_page_cap() {
        let mut calls = 0usize;
        let mut out = Vec::new();
        let err = list_pages(
            |after| {
                calls += 1;
                let next = after.map_or(0, |n| n.parse::<usize>().unwrap() + 1);
                std::future::ready(Ok(vec![ProfileSummary {
                    name: format!("{next:08}"),
                    latest_version: 1,
                    hash: String::new(),
                }]))
            },
            &mut out,
        )
        .await
        .unwrap_err();
        assert_eq!(calls, MAX_LIST_PAGES);
        assert!(!matches!(err, CliError::Io(_)));
        assert_eq!(err.to_string(), TOO_MANY_PAGES);
    }
}
