//! `fleet profile`: create, list, show, share, unshare and edit named agent profiles.

use std::io::{Read, Write};

use fleet_core::{ItemId, Profile, PromptText, Selection};
use fleet_proto::MAX_PROFILE_JSON_BYTES;
use fleet_proto::v1::fleet_profiles_client::FleetProfilesClient;
use fleet_proto::v1::{
    CreateProfileRequest, GetProfileRequest, ListProfilesRequest, ProfileSummary, ProfileVersion,
    ProfileVisibility, ShareProfileRequest, UnshareProfileRequest,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, Scrub};

/// A `FleetProfiles` client carrying the bearer token.
pub(crate) type ProfilesClient = FleetProfilesClient<InterceptedService<Channel, Bearer>>;

/// Profiles asked for per `ListProfiles` call. The server honours at most 200.
const LIST_PAGE: u32 = 200;

/// Most pages `list` follows: one million profiles at the page size. A server that keeps
/// returning new names past this is treated as hostile.
const MAX_LIST_PAGES: usize = 5_000;
const TOO_LARGE: &str = "profile JSON is larger than the allowed maximum";
const TOO_MANY_PAGES: &str = "server returned too many profile list pages";
const BAD_ITEM: &str =
    "invalid item id: use 1 to 64 characters of a-z, 0-9, _ and -, starting with a letter or digit";
const BAD_PROMPT: &str = "invalid prompt: at most 65536 bytes, no control characters but newline and tab, no CR, U+2028, U+2029 or bidirectional control";
const BAD_STORED: &str = "server returned a profile this client cannot edit";
const BAD_RESULT: &str = "the edited profile is not valid";
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

/// Checks a catalog item id before any connection is opened. The message never repeats it.
///
/// # Errors
/// Returns [`CliError::Usage`] for an id outside `[a-z0-9][a-z0-9_-]{0,63}`.
pub(crate) fn item_id(raw: &str) -> Result<ItemId, CliError> {
    ItemId::new(raw).map_err(|_| CliError::Usage(BAD_ITEM.into()))
}

/// Reads an authored prompt from `path`, or from `stdin` when `path` is `-`, and checks it.
///
/// The read stops one byte past `PromptText::MAX_BYTES`. Empty input gives `None`, which
/// clears the prompt. A file that is not UTF-8 is an I/O error.
///
/// # Errors
/// Returns [`CliError::Usage`] with a fixed message for a refused character. An over-long
/// text is [`CliError::Usage`] too, except when the cap falls inside a multibyte character,
/// which is [`CliError::Io`] like any non-UTF-8 input. [`CliError::Io`] also covers a source
/// that cannot be read.
pub(crate) fn read_prompt(
    path: &str,
    stdin: &mut impl Read,
) -> Result<Option<PromptText>, CliError> {
    let limit = PromptText::MAX_BYTES as u64 + 1;
    let mut text = String::new();
    if path == "-" {
        stdin.take(limit).read_to_string(&mut text)?;
    } else {
        std::fs::File::open(path)?
            .take(limit)
            .read_to_string(&mut text)?;
    }
    PromptText::new(&text).map_err(|_| CliError::Usage(BAD_PROMPT.into()))
}

fn parse_stored(content_json: &str) -> Result<Profile, CliError> {
    Profile::from_stored_json(content_json.as_bytes())
        .map_err(|_| CliError::Usage(BAD_STORED.into()))
}

fn selection_with(profile: &Profile, id: &ItemId, off: bool) -> Result<Selection, CliError> {
    let mut ids: Vec<&str> = profile
        .selection
        .ids()
        .map(ItemId::as_str)
        .filter(|kept| *kept != id.as_str())
        .collect();
    if off {
        ids.push(id.as_str());
    }
    let entries: Vec<String> = ids
        .iter()
        .map(|id| format!("{{\"item_id\":\"{id}\",\"enabled\":false}}"))
        .collect();
    Selection::from_json(format!("[{}]", entries.join(",")).as_bytes())
        .map_err(|_| CliError::Usage(BAD_RESULT.into()))
}

/// Returns `content_json` with `id` switched on (`on`) or off in its selection.
///
/// Switching off an id that is already off, or on an id that is not off, changes nothing.
///
/// # Errors
/// Returns [`CliError::Usage`] when the stored content cannot be parsed or the result
/// breaks a selection rule such as the entry cap.
pub(crate) fn set_item(content_json: &str, id: &ItemId, on: bool) -> Result<String, CliError> {
    let mut profile = parse_stored(content_json)?;
    profile.selection = selection_with(&profile, id, !on)?;
    canonical(&profile)
}

/// Returns `content_json` with its authored prompt replaced by `text`, or cleared for `None`.
///
/// # Errors
/// Returns [`CliError::Usage`] when the stored content cannot be parsed.
pub(crate) fn set_prompt(content_json: &str, text: Option<PromptText>) -> Result<String, CliError> {
    let mut profile = parse_stored(content_json)?;
    profile.authored_prompt = text;
    canonical(&profile)
}

fn canonical(profile: &Profile) -> Result<String, CliError> {
    String::from_utf8(profile.canonical_json()).map_err(|_| CliError::Usage(BAD_RESULT.into()))
}

/// `fleet profile item` and `prompt`: reads the latest version, applies `change` to its
/// content and saves the result through `CreateProfile` with `edit` set, so the server checks the
/// selection, keeps the version when the content hash is unchanged and refuses a profile the
/// caller does not own instead of saving a copy under the caller's name. Prints the version.
/// An edit equal to an older version makes that version the latest again.
///
/// Selection is keyed by item id only: the kind is not part of the stored entry.
///
/// Another save between the read and the write is overwritten: the last writer wins.
///
/// A profile that sets `tools` cannot be saved as JSON, so the server refuses it.
///
/// # Errors
/// `CliError::Rpc` for `PERMISSION_DENIED` (a shared profile owned by another user) and
/// `NOT_FOUND` (an unknown name or someone else's private profile).
pub(crate) async fn edit(
    client: &mut ProfilesClient,
    scrub: &Scrub,
    name: String,
    change: impl FnOnce(&str) -> Result<String, CliError>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let current = client
        .get_profile(GetProfileRequest {
            name: name.clone(),
            version: None,
        })
        .await?
        .into_inner();
    let content_json = change(&current.content_json)?;
    let reply = client
        .create_profile(CreateProfileRequest {
            name,
            content_json,
            content_toml: String::new(),
            edit: true,
        })
        .await?
        .into_inner();
    write_version(out, scrub, &reply)?;
    writeln!(out, "created: {}", if reply.created { "yes" } else { "no" })?;
    Ok(())
}

fn write_version(
    out: &mut impl Write,
    scrub: &Scrub,
    reply: &ProfileVersion,
) -> std::io::Result<()> {
    writeln!(out, "name: {}", scrub.ident(&reply.name))?;
    writeln!(out, "version: {}", reply.version)?;
    writeln!(out, "hash: {}", scrub.ident(&reply.hash))
}

/// `fleet profile create`: sends the raw JSON and prints the stored version.
pub(crate) async fn create(
    client: &mut ProfilesClient,
    scrub: &Scrub,
    name: String,
    content_json: String,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .create_profile(CreateProfileRequest {
            name,
            content_json,
            content_toml: String::new(),
            edit: false,
        })
        .await?
        .into_inner();
    write_version(out, scrub, &reply)?;
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
    scrub: &Scrub,
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
        scrub,
        out,
    )
    .await
}

/// Follows pages from `fetch` until an empty one, a page that does not advance, or
/// `MAX_LIST_PAGES`.
async fn list_pages<F, Fut>(
    mut fetch: F,
    scrub: &Scrub,
    out: &mut impl Write,
) -> Result<(), CliError>
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
                "{}\t{}\t{}\t{}\t{}",
                scrub.ident(&profile.name),
                profile.latest_version,
                scrub.ident(&profile.hash),
                scrub.ident(&profile.owner),
                visibility_label(profile.visibility)
            )?;
        }
        after_name = Some(last.name.clone());
    }
    Err(CliError::Usage(TOO_MANY_PAGES.into()))
}

/// `fleet profile show`: canonical content, version and hash of one profile version.
///
/// Prints the version, hash and `used-by`, then the owner, visibility, selection (the disabled
/// item ids joined by `,`, or `-`) and authored prompt (or `-`), then the canonical content. The
/// server has no per-version job count, so `used-by` prints `-`: the count is unknown, never
/// zero.
pub(crate) async fn show(
    client: &mut ProfilesClient,
    scrub: &Scrub,
    name: String,
    version: Option<u32>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = client
        .get_profile(GetProfileRequest { name, version })
        .await?
        .into_inner();
    write_version(out, scrub, &reply)?;
    writeln!(out, "used-by: -")?;
    write_detail(out, scrub, &reply)?;
    write_content(out, scrub, &reply)?;
    Ok(())
}

/// `fleet profile share` and `unshare`: sets the visibility and prints the result.
///
/// An unknown or not-owned profile is an error and nothing is printed.
pub(crate) async fn set_shared(
    client: &mut ProfilesClient,
    scrub: &Scrub,
    name: String,
    shared: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reply = if shared {
        client.share_profile(ShareProfileRequest { name }).await
    } else {
        client.unshare_profile(UnshareProfileRequest { name }).await
    }?
    .into_inner();
    writeln!(out, "name: {}", scrub.ident(&reply.name))?;
    writeln!(out, "visibility: {}", visibility_label(reply.visibility))?;
    Ok(())
}

/// The lowercase word for a wire visibility, or `unknown` for any other value.
fn visibility_label(value: i32) -> &'static str {
    match ProfileVisibility::try_from(value) {
        Ok(ProfileVisibility::Private) => "private",
        Ok(ProfileVisibility::Shared) => "shared",
        _ => "unknown",
    }
}

fn write_detail(
    out: &mut impl Write,
    scrub: &Scrub,
    reply: &ProfileVersion,
) -> std::io::Result<()> {
    writeln!(out, "owner: {}", scrub.ident(&reply.owner))?;
    writeln!(out, "visibility: {}", visibility_label(reply.visibility))?;
    let items: Vec<String> = reply
        .selection
        .iter()
        .map(|entry| scrub.ident(&entry.item_id))
        .collect();
    writeln!(
        out,
        "selection: {}",
        if items.is_empty() {
            "-".to_owned()
        } else {
            items.join(",")
        }
    )?;
    let prompt = scrub.ident(&reply.authored_prompt);
    writeln!(
        out,
        "prompt: {}",
        if prompt.is_empty() { "-" } else { &prompt }
    )
}

fn write_content(
    out: &mut impl Write,
    scrub: &Scrub,
    reply: &ProfileVersion,
) -> std::io::Result<()> {
    writeln!(out, "content: {}", scrub.ident(&reply.content_json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::v1::SelectionEntry;

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
                    ..ProfileSummary::default()
                }]))
            },
            &Scrub::default(),
            &mut out,
        )
        .await
        .unwrap_err();
        assert_eq!(calls, MAX_LIST_PAGES);
        assert!(!matches!(err, CliError::Io(_)));
        assert_eq!(err.to_string(), TOO_MANY_PAGES);
    }

    const TOKEN: &str = "client-token-0123456789";

    fn detail_text(set: impl FnOnce(&mut ProfileVersion)) -> String {
        let mut reply = ProfileVersion::default();
        set(&mut reply);
        let mut out = Vec::new();
        write_detail(&mut out, &Scrub::new(Some(TOKEN)), &reply).expect("write to a Vec");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn detail_prints_owner_visibility_selection_and_prompt() {
        let text = detail_text(|r| {
            r.owner = "alice".into();
            r.visibility = ProfileVisibility::Shared as i32;
            r.selection = vec![
                SelectionEntry {
                    item_id: "skill:a".into(),
                    enabled: false,
                },
                SelectionEntry {
                    item_id: "tool:b".into(),
                    enabled: false,
                },
            ];
            r.authored_prompt = "do it".into();
        });
        assert_eq!(
            text,
            "owner: alice\nvisibility: shared\nselection: skill:a,tool:b\nprompt: do it\n"
        );
    }

    #[test]
    fn detail_marks_empty_selection_and_prompt_with_a_dash() {
        let text = detail_text(|r| r.visibility = ProfileVisibility::Private as i32);
        assert_eq!(
            text,
            "owner: \nvisibility: private\nselection: -\nprompt: -\n"
        );
    }

    #[test]
    fn detail_fields_are_scrubbed_of_the_token() {
        let text = detail_text(|r| {
            r.owner = laden();
            r.selection = vec![SelectionEntry {
                item_id: laden(),
                enabled: false,
            }];
            r.authored_prompt = laden();
        });
        assert!(!text.contains(TOKEN), "{text}");
        assert_eq!(text.matches("v-[REDACTED]").count(), 3, "{text}");
    }

    #[test]
    fn visibility_labels() {
        assert_eq!(
            visibility_label(ProfileVisibility::Private as i32),
            "private"
        );
        assert_eq!(visibility_label(ProfileVisibility::Shared as i32), "shared");
        assert_eq!(visibility_label(0), "unknown");
        assert_eq!(visibility_label(99), "unknown");
    }

    fn laden() -> String {
        format!("v-{TOKEN}")
    }

    fn version_text(set: impl FnOnce(&mut ProfileVersion)) -> String {
        let mut reply = ProfileVersion {
            name: "n".into(),
            hash: "h".into(),
            ..ProfileVersion::default()
        };
        set(&mut reply);
        let mut out = Vec::new();
        write_version(&mut out, &Scrub::new(Some(TOKEN)), &reply).expect("write to a Vec");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn profile_version_name_is_scrubbed_of_the_token() {
        let text = version_text(|r| r.name = laden());
        assert!(text.contains("name: v-[REDACTED]\n"), "{text}");
    }

    #[test]
    fn profile_version_hash_is_scrubbed_of_the_token() {
        let text = version_text(|r| r.hash = laden());
        assert!(text.contains("hash: v-[REDACTED]\n"), "{text}");
    }

    #[tokio::test]
    async fn profile_list_name_hash_and_owner_are_scrubbed_of_the_token() {
        let mut done = false;
        let mut out = Vec::new();
        list_pages(
            |_| {
                let page = if done {
                    vec![]
                } else {
                    vec![ProfileSummary {
                        name: laden(),
                        latest_version: 1,
                        hash: laden(),
                        owner: laden(),
                        ..ProfileSummary::default()
                    }]
                };
                done = true;
                std::future::ready(Ok(page))
            },
            &Scrub::new(Some(TOKEN)),
            &mut out,
        )
        .await
        .expect("list");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(
            text,
            "v-[REDACTED]\t1\tv-[REDACTED]\tv-[REDACTED]\tunknown\n"
        );
    }

    #[test]
    fn profile_show_content_is_scrubbed_of_the_token() {
        let reply = ProfileVersion {
            content_json: format!("{{\"k\":\"{TOKEN}\"}}"),
            ..ProfileVersion::default()
        };
        let mut out = Vec::new();
        write_content(&mut out, &Scrub::new(Some(TOKEN)), &reply).expect("write to a Vec");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text, "content: {\"k\":\"[REDACTED]\"}\n");
    }
}
