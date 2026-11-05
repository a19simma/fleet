//! The `fleet catalog` and `fleet user cap` commands.

use std::io::{Read, Write};

use clap::Subcommand;
use fleet_proto::v1::fleet_capability_admin_client::FleetCapabilityAdminClient;
use fleet_proto::v1::fleet_catalog_admin_client::FleetCatalogAdminClient;
use fleet_proto::v1::fleet_catalog_client::FleetCatalogClient;
use fleet_proto::v1::{
    CatalogItem, CatalogKind, GrantCapabilityRequest, ListCapabilitiesRequest, ListCatalogRequest,
    RevokeCapabilityRequest, SetCatalogItemEnabledRequest, UpsertCatalogItemRequest,
    UserCapability,
};
use fleet_proto::{DEFAULT_CATALOG_PAGE, MAX_CATALOG_CONTENT_BYTES, validate_catalog_content};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::{Bearer, CliError, MAX_DECODE_BYTES, Resolution, Scrub, bearer, open_channel};

/// A `FleetCatalog` client carrying the bearer token.
pub(crate) type CatalogClient = FleetCatalogClient<InterceptedService<Channel, Bearer>>;

/// A `FleetCatalogAdmin` client carrying the bearer token.
pub(crate) type CatalogAdminClient = FleetCatalogAdminClient<InterceptedService<Channel, Bearer>>;

/// A `FleetCapabilityAdmin` client carrying the bearer token.
pub(crate) type CapabilityClient = FleetCapabilityAdminClient<InterceptedService<Channel, Bearer>>;

/// Most pages `list` follows. A server that keeps returning new cursors past this is treated
/// as hostile.
const MAX_LIST_PAGES: usize = 5_000;
const TOO_MANY_PAGES: &str = "server returned too many catalog pages";
const TOO_LARGE: &str = "catalog item content is larger than the allowed maximum";
const EMPTY_CONTENT: &str = "catalog item content is empty";
const BAD_KIND: &str = "invalid kind: use skill, subagent, tool or context";

/// A `fleet catalog` action.
#[derive(Debug, Subcommand)]
pub enum CatalogAction {
    /// List the catalog items.
    List {
        /// Only items of this kind: skill, subagent, tool or context.
        #[arg(long)]
        kind: Option<String>,
    },
    /// Create an item or add a version of one. Admin only.
    Upsert {
        /// Item kind: skill, subagent, tool or context.
        kind: String,
        /// Item id.
        id: String,
        /// Item name.
        name: String,
        /// File holding the item content, or `-` to read it from stdin.
        #[arg(long)]
        file: String,
    },
    /// Switch an item on for every profile. Admin only.
    Enable {
        /// Item id.
        id: String,
    },
    /// Switch an item off for every profile. Admin only.
    Disable {
        /// Item id.
        id: String,
    },
}

/// A `fleet user` area.
#[derive(Debug, Subcommand)]
pub enum UserArea {
    /// Grant, revoke and list the capabilities of a user. Admin only.
    Cap {
        /// The capability action.
        #[command(subcommand)]
        action: CapAction,
    },
}

/// A `fleet user cap` action.
#[derive(Debug, Subcommand)]
pub enum CapAction {
    /// List the capabilities a user holds, in the order the server returns them.
    List {
        /// User id.
        user: u64,
    },
    /// Grant a capability to a user.
    Grant {
        /// User id.
        user: u64,
        /// Capability name, such as `profile:tools`.
        capability: String,
    },
    /// Revoke a capability from a user.
    Revoke {
        /// User id.
        user: u64,
        /// Capability name, such as `profile:tools`.
        capability: String,
    },
}

async fn connect(env: &Resolution, timeouts: bool) -> Result<(Channel, Bearer, Scrub), CliError> {
    let resolved = env.as_ref().map_err(Clone::clone)?;
    let config = &resolved.config;
    if let Some(warning) = config.token_warning() {
        let _ = writeln!(std::io::stderr(), "fleet: warning: {warning}");
    }
    let channel = open_channel(config, timeouts).await?;
    Ok((channel, bearer(config)?, resolved.scrub.clone()))
}

async fn reader(env: &Resolution, timeouts: bool) -> Result<(CatalogClient, Scrub), CliError> {
    let (channel, token, scrub) = connect(env, timeouts).await?;
    let client = FleetCatalogClient::with_interceptor(channel, token)
        .max_decoding_message_size(MAX_DECODE_BYTES);
    Ok((client, scrub))
}

async fn admin(env: &Resolution, timeouts: bool) -> Result<(CatalogAdminClient, Scrub), CliError> {
    let (channel, token, scrub) = connect(env, timeouts).await?;
    let client = FleetCatalogAdminClient::with_interceptor(channel, token)
        .max_decoding_message_size(MAX_DECODE_BYTES);
    Ok((client, scrub))
}

fn parse_kind(raw: &str) -> Result<CatalogKind, CliError> {
    match raw {
        "skill" => Ok(CatalogKind::Skill),
        "subagent" => Ok(CatalogKind::Subagent),
        "tool" => Ok(CatalogKind::Tool),
        "context" => Ok(CatalogKind::Context),
        _ => Err(CliError::Usage(BAD_KIND.into())),
    }
}

fn kind_name(raw: i32) -> &'static str {
    match CatalogKind::try_from(raw) {
        Ok(CatalogKind::Skill) => "skill",
        Ok(CatalogKind::Subagent) => "subagent",
        Ok(CatalogKind::Tool) => "tool",
        Ok(CatalogKind::Context) => "context",
        Ok(CatalogKind::Unspecified) | Err(_) => "unknown",
    }
}

fn read_content(path: &str, stdin: &mut impl Read) -> Result<String, CliError> {
    let mut text = String::new();
    let limit = MAX_CATALOG_CONTENT_BYTES as u64 + 1;
    if path == "-" {
        stdin.take(limit).read_to_string(&mut text)?;
    } else {
        std::fs::File::open(path)?
            .take(limit)
            .read_to_string(&mut text)?;
    }
    if !validate_catalog_content(&text) {
        let message = if text.is_empty() {
            EMPTY_CONTENT
        } else {
            TOO_LARGE
        };
        return Err(CliError::Usage(message.into()));
    }
    Ok(text)
}

fn write_item(out: &mut impl Write, scrub: &Scrub, item: &CatalogItem) -> std::io::Result<()> {
    let state = if item.admin_enabled {
        "enabled"
    } else {
        "disabled"
    };
    writeln!(
        out,
        "{}\t{}\t{}\t{state}",
        scrub.ident(&item.id),
        kind_name(item.kind),
        scrub.free(&item.name),
    )
}

async fn list(
    client: &mut CatalogClient,
    scrub: &Scrub,
    kind: CatalogKind,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut after_id = String::new();
    for _ in 0..MAX_LIST_PAGES {
        let reply = client
            .list_catalog(ListCatalogRequest {
                kind: kind as i32,
                page_size: DEFAULT_CATALOG_PAGE,
                after_id: after_id.clone(),
            })
            .await?
            .into_inner();
        for item in &reply.items {
            write_item(out, scrub, item)?;
        }
        if reply.items.is_empty() || reply.next_id.is_empty() {
            return Ok(());
        }
        after_id = reply.next_id;
    }
    Err(CliError::Usage(TOO_MANY_PAGES.into()))
}

async fn set_enabled(
    client: &mut CatalogAdminClient,
    scrub: &Scrub,
    id: String,
    enabled: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let item = client
        .set_catalog_item_enabled(SetCatalogItemEnabledRequest { id, enabled })
        .await?
        .into_inner();
    write_item(out, scrub, &item)?;
    Ok(())
}

/// Runs a `fleet catalog` action.
///
/// # Errors
/// Returns [`CliError::Usage`] for a bad kind or content, [`CliError::Io`] when the content
/// cannot be read or the output cannot be written, and [`CliError::Rpc`] for a server refusal
/// such as `admin required`.
pub(crate) async fn run(
    action: CatalogAction,
    env: &Resolution,
    timeouts: bool,
    stdin: &mut impl Read,
    out: &mut impl Write,
) -> Result<(), CliError> {
    match action {
        CatalogAction::List { kind } => {
            let kind = kind
                .as_deref()
                .map_or(Ok(CatalogKind::Unspecified), parse_kind)?;
            let (mut client, scrub) = reader(env, timeouts).await?;
            list(&mut client, &scrub, kind, out).await
        }
        CatalogAction::Upsert {
            kind,
            id,
            name,
            file,
        } => {
            let kind = parse_kind(&kind)?;
            let content = read_content(&file, stdin)?;
            let (mut client, scrub) = admin(env, timeouts).await?;
            let item = client
                .upsert_catalog_item(UpsertCatalogItemRequest {
                    id,
                    kind: kind as i32,
                    name,
                    content,
                })
                .await?
                .into_inner();
            write_item(out, &scrub, &item)?;
            Ok(())
        }
        CatalogAction::Enable { id } => {
            let (mut client, scrub) = admin(env, timeouts).await?;
            set_enabled(&mut client, &scrub, id, true, out).await
        }
        CatalogAction::Disable { id } => {
            let (mut client, scrub) = admin(env, timeouts).await?;
            set_enabled(&mut client, &scrub, id, false, out).await
        }
    }
}

async fn capability(
    env: &Resolution,
    timeouts: bool,
) -> Result<(CapabilityClient, Scrub), CliError> {
    let (channel, token, scrub) = connect(env, timeouts).await?;
    let client = FleetCapabilityAdminClient::with_interceptor(channel, token)
        .max_decoding_message_size(MAX_DECODE_BYTES);
    Ok((client, scrub))
}

fn write_capability(
    out: &mut impl Write,
    scrub: &Scrub,
    row: &UserCapability,
) -> std::io::Result<()> {
    writeln!(
        out,
        "{}\t{}\t{}\t{}",
        row.user_id,
        scrub.ident(&row.capability),
        row.granted_by,
        row.granted_at_ms,
    )
}

/// Runs a `fleet user` area.
///
/// `list` and `grant` print one `user, capability, granted_by, granted_at_ms` row per
/// capability, tab separated, in the order the server returns them. `revoke` prints
/// `revoked` or `not held`, a tab, the user id and the capability. The acting admin is the
/// caller's token.
///
/// # Errors
/// Returns [`CliError::Io`] when the output cannot be written and [`CliError::Rpc`] for a
/// server refusal such as `admin required`, an unknown user or an unknown capability.
pub(crate) async fn run_user(
    area: UserArea,
    env: &Resolution,
    timeouts: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let UserArea::Cap { action } = area;
    let (mut client, scrub) = capability(env, timeouts).await?;
    match action {
        CapAction::List { user } => {
            let reply = client
                .list_capabilities(ListCapabilitiesRequest { user_id: user })
                .await?
                .into_inner();
            for row in &reply.capabilities {
                write_capability(out, &scrub, row)?;
            }
        }
        CapAction::Grant { user, capability } => {
            let row = client
                .grant_capability(GrantCapabilityRequest {
                    user_id: user,
                    capability,
                })
                .await?
                .into_inner();
            write_capability(out, &scrub, &row)?;
        }
        CapAction::Revoke { user, capability } => {
            let reply = client
                .revoke_capability(RevokeCapabilityRequest {
                    user_id: user,
                    capability: capability.clone(),
                })
                .await?
                .into_inner();
            let verdict = if reply.removed { "revoked" } else { "not held" };
            writeln!(out, "{verdict}\t{user}\t{}", scrub.ident(&capability))?;
        }
    }
    Ok(())
}
