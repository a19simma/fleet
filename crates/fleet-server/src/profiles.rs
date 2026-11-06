//! Profile storage: insert-only blobs and named versions behind `FleetProfiles`.

use std::fmt::{self, Write};
use std::str::FromStr;

use fleet_core::catalog::{CatalogEntry, CatalogItem, MAX_CATALOG, RunnerKind, resolve};
use fleet_core::model_allowlist::ModelAllowlist;
use fleet_core::{Profile, ProfileError, ProfileHash, ProfileInvalid, Visibility};
use fleet_proto::v1::{
    GetProfileBlobReply, ListProfilesReply, Profile as WireProfile, ProfileRef, ProfileSummary,
    ProfileVersion, ProfileVisibility,
};
use fleet_proto::{
    ERR_PROFILE_CONTENT_CHOICE, MAX_PROFILE_JSON_BYTES, selection_to_wire, visibility_to_wire,
};
use sqlx::{PgConnection, PgPool, Row};

use crate::cred::capability::PROFILE_TOOLS;
use crate::jobs::{JobInvalid, Snapshot, kind_of};
use crate::store::{DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, StoreError};

/// Longest accepted profile name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// The refusal text for a create without a stored user, shared by the handler and
/// [`ProfileFault::Unowned`].
pub const ERR_PROFILE_UNOWNED: &str = "profile create needs a user token";

/// Who reads a profile: one user's own and shared profiles, or shared profiles only.
///
/// A required type instead of `Option<i64>`, so a caller that has a user id cannot pass the
/// shared-only view by leaving the id out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Viewer {
    /// Shared profiles only.
    Shared,
    /// This user's own profiles first, then shared ones.
    User(i64),
}

impl Viewer {
    pub(crate) fn id(self) -> Option<i64> {
        match self {
            Self::Shared => None,
            Self::User(id) => Some(id),
        }
    }
}

impl From<Option<i64>> for Viewer {
    fn from(caller: Option<i64>) -> Self {
        caller.map_or(Self::Shared, Self::User)
    }
}

/// The refusal text for a profile submit without a stored user, shared by the handler and
/// [`ProfileFault::Unowned`].
pub const ERR_PROFILE_SUBMIT_UNOWNED: &str = "profile submit needs a user token";

/// The refusal text for a save, submit or blob serve of a profile with `tools` by a user without
/// `profile:tools`.
pub const ERR_PROFILE_TOOLS_NOT_GRANTED: &str = "profile tools need the profile:tools capability";

const LOCK_OWN_PROFILE_FOR_UPDATE: &str =
    "SELECT id, visibility FROM profile WHERE owner_user_id = $1 AND name = $2 FOR UPDATE";
const SET_VISIBILITY: &str = "UPDATE profile SET visibility = $2 WHERE id = $1";
const FOREIGN_SHARED_EXISTS: &str = "SELECT EXISTS (SELECT 1 FROM profile \
     WHERE name = $1 AND owner_user_id <> $2 AND visibility = 'shared')";

async fn set_visibility(
    pool: &PgPool,
    caller: Option<i64>,
    name: &str,
    shared: bool,
) -> Result<WireProfile, StoreError> {
    let caller = caller.ok_or(ProfileFault::Unowned)?;
    validate_name(name)?;
    let (word, wire) = if shared {
        ("shared", ProfileVisibility::Shared)
    } else {
        ("private", ProfileVisibility::Private)
    };
    let mut tx = pool.begin().await?;
    let Some(row) = sqlx::query(LOCK_OWN_PROFILE_FOR_UPDATE)
        .bind(caller)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?
    else {
        let foreign: bool = sqlx::query_scalar(FOREIGN_SHARED_EXISTS)
            .bind(name)
            .bind(caller)
            .fetch_one(&mut *tx)
            .await?;
        return Err(if foreign {
            ProfileFault::NotOwner.into()
        } else {
            StoreError::NotFound
        });
    };
    if row.try_get::<String, _>("visibility")? != word {
        sqlx::query(SET_VISIBILITY)
            .bind(row.try_get::<i64, _>("id")?)
            .bind(word)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(WireProfile {
        name: name.to_owned(),
        owner_user_id: u64::try_from(caller).map_err(|_| StoreError::OutOfRange("user id"))?,
        visibility: wire as i32,
        selection: Vec::new(),
        authored_prompt: String::new(),
    })
}

/// Makes the caller's own profile `name` visible to every user. Sharing a shared profile
/// changes nothing and succeeds.
///
/// The profile row is locked `FOR UPDATE` before the visibility is read and written. Jobs
/// keep their own snapshot of the version and hash, so a change here never alters a job.
///
/// # Errors
/// Returns [`ProfileFault::Unowned`] for a `None` caller, [`ProfileFault::Name`] for a bad
/// name, [`StoreError::NotFound`] when the caller owns no such profile and no one else
/// shares one by that name, [`ProfileFault::NotOwner`] when only someone else's shared
/// profile has that name, and a database error. Every refusal writes nothing.
pub async fn share_owned(
    pool: &PgPool,
    caller: Option<i64>,
    name: &str,
) -> Result<WireProfile, StoreError> {
    set_visibility(pool, caller, name, true).await
}

/// Takes the caller's own profile `name` back from the shared list. Unsharing a private
/// profile changes nothing and succeeds.
///
/// Locking, snapshots and errors are those of [`share_owned`]. A queued or running job that
/// uses the profile keeps its stored version and hash and still runs.
///
/// # Errors
/// As [`share_owned`].
pub async fn unshare_owned(
    pool: &PgPool,
    caller: Option<i64>,
    name: &str,
) -> Result<WireProfile, StoreError> {
    set_visibility(pool, caller, name, false).await
}

const INSERT_BLOB: &str = "INSERT INTO profile_blob (hash, content, size) VALUES ($1, $2, $3) \
     ON CONFLICT (hash) DO NOTHING";
const LOCK_OWNER: &str = "SELECT id FROM users WHERE id = $1 FOR SHARE";
const INSERT_PROFILE: &str = "INSERT INTO profile (owner_user_id, name, visibility) \
     VALUES ($1, $2, $3) ON CONFLICT (owner_user_id, name) DO NOTHING";
const LOCK_PROFILE: &str =
    "SELECT id FROM profile WHERE owner_user_id = $1 AND name = $2 FOR SHARE";
const LOCK_PROFILE_FOR_WRITE: &str =
    "SELECT owner_user_id, visibility, name FROM profile WHERE id = $1 FOR UPDATE";
const PROFILE_HAS_VERSIONS: &str =
    "SELECT EXISTS (SELECT 1 FROM profile_version WHERE profile_id = $1)";
const DELETE_PROFILE: &str = "DELETE FROM profile WHERE id = $1";
const LOCK_PROFILE_ID: &str = "SELECT pg_advisory_xact_lock($1)";
const SELECT_VERSION_BY_HASH: &str =
    "SELECT version FROM profile_version WHERE profile_id = $1 AND hash = $2";
const INSERT_VERSION: &str = "INSERT INTO profile_version (profile_id, version, hash) \
     SELECT $1, COALESCE(MAX(version), 0) + 1, $2 FROM profile_version WHERE profile_id = $1 \
     RETURNING version";
const SELECT_VISIBLE: &str = "SELECT v.version, v.hash, b.content, p.visibility, \
     u.username AS owner FROM \
     (SELECT id, owner_user_id, visibility FROM profile \
      WHERE name = $1 AND (owner_user_id = $2 OR visibility = 'shared') \
      ORDER BY (owner_user_id = $2) DESC NULLS LAST, id LIMIT 1) p \
     JOIN users u ON u.id = p.owner_user_id \
     JOIN profile_version v ON v.profile_id = p.id \
     JOIN profile_blob b ON b.hash = v.hash \
     WHERE $3::int IS NULL OR v.version = $3 ORDER BY v.version DESC LIMIT 1";
const SELECT_PINNED_FOR_SUBMIT: &str = "SELECT p.id, v.version, v.hash, b.content FROM \
     (SELECT id FROM profile WHERE name = $1 AND (owner_user_id = $2 OR visibility = 'shared') \
      ORDER BY (owner_user_id = $2) DESC NULLS LAST, id LIMIT 1 FOR SHARE) p \
     JOIN profile_version v ON v.profile_id = p.id \
     JOIN profile_blob b ON b.hash = v.hash \
     ORDER BY v.version DESC LIMIT 1";
const READ_TOOLS_GRANT: &str =
    "SELECT user_id FROM user_capabilities WHERE user_id = $1 AND capability = $2 FOR SHARE";
const LOCK_CATALOG: &str = "SELECT id, kind, name, content, admin_enabled FROM catalog_items \
     ORDER BY id LIMIT $1 FOR SHARE";
const SELECT_LEASED_BLOB: &str = "SELECT j.profile_name, j.profile_version, j.profile_hash, \
     j.snapshot_catalog::text AS snapshot_catalog, j.snapshot_notes::text AS snapshot_notes, \
     j.snapshot_hash, j.user_id, v.hash AS version_hash, b.content FROM jobs j \
     LEFT JOIN profile_version v ON v.profile_id = j.profile_id AND v.version = j.profile_version \
     LEFT JOIN profile_blob b ON b.hash = j.profile_hash \
     WHERE j.job_id = $1 AND j.attempt = $2 AND j.box = $3 AND j.state = 'RUNNING' \
     AND j.lease_expires_at > now()";
const LIST: &str = "SELECT DISTINCT ON (p.name) p.name, v.version, v.hash, p.visibility, \
     u.username AS owner FROM profile p \
     JOIN users u ON u.id = p.owner_user_id \
     JOIN profile_version v ON v.profile_id = p.id \
     WHERE ($1::text IS NULL OR p.name > $1) \
     AND (p.owner_user_id = $3 OR p.visibility = 'shared') \
     ORDER BY p.name, (p.owner_user_id = $3) DESC NULLS LAST, v.version DESC LIMIT $2";

/// Why a profile request was refused. The variants carry no client input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileFault {
    /// The name is empty, too long or has characters outside `[A-Za-z0-9_-]`.
    Name,
    /// The JSON is longer than [`MAX_PROFILE_JSON_BYTES`].
    TooLarge,
    /// The JSON is not a Profile.
    Malformed(ProfileError),
    /// The Profile breaks a validation rule.
    Invalid(ProfileInvalid),
    /// The request set both or neither of the JSON and TOML content.
    ContentChoice,
    /// The caller is not a stored user. The handler maps this to `PERMISSION_DENIED`.
    Unowned,
    /// The caller can read this shared profile but does not own it. The handler maps this
    /// to `PERMISSION_DENIED`. A private foreign profile is [`StoreError::NotFound`] instead.
    NotOwner,
    /// The profile has versions, which are insert-only, so the row cannot be removed.
    HasVersions,
}

impl fmt::Display for ProfileFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => f.write_str("invalid profile name"),
            Self::TooLarge => f.write_str("profile json is too large"),
            Self::Malformed(err) => err.fmt(f),
            Self::Invalid(err) => err.fmt(f),
            Self::ContentChoice => f.write_str(ERR_PROFILE_CONTENT_CHOICE),
            Self::Unowned => f.write_str(ERR_PROFILE_UNOWNED),
            Self::NotOwner => f.write_str("only the owner can change this profile"),
            Self::HasVersions => f.write_str("profile has versions and cannot be deleted"),
        }
    }
}

impl std::error::Error for ProfileFault {}

/// The profile text of a create request and the grammar it is read with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileContent<'a> {
    /// JSON text; `tools` is refused.
    Json(&'a str),
    /// TOML text; the only form that accepts `tools`.
    Toml(&'a str),
}

impl<'a> ProfileContent<'a> {
    /// Picks the one non-empty field of a request.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileFault::ContentChoice`] when both or neither are set.
    pub fn select(json: &'a str, toml: &'a str) -> Result<Self, ProfileFault> {
        match (json.is_empty(), toml.is_empty()) {
            (false, true) => Ok(Self::Json(json)),
            (true, false) => Ok(Self::Toml(toml)),
            _ => Err(ProfileFault::ContentChoice),
        }
    }

    fn text(self) -> &'a str {
        match self {
            Self::Json(text) | Self::Toml(text) => text,
        }
    }
}

/// A validated create request: the name and the canonical Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProfile {
    name: String,
    canonical: Vec<u8>,
    hash: ProfileHash,
    has_tools: bool,
    model: Option<String>,
}

/// A validated Profile body without a name: the canonical JSON and its hash.
struct Body {
    canonical: Vec<u8>,
    hash: ProfileHash,
    has_tools: bool,
    model: Option<String>,
}

/// Validates a profile name.
///
/// # Errors
///
/// Returns [`ProfileFault::Name`] without the offending value.
pub fn validate_name(name: &str) -> Result<(), ProfileFault> {
    if !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Ok(())
    } else {
        Err(ProfileFault::Name)
    }
}

/// Validates a create request. This is the only check on these fields. Tools are not gated
/// here: the store checks the `profile:tools` capability of the saving user inside its
/// transaction.
///
/// # Errors
///
/// Returns the [`ProfileFault`] of the first rule that fails. It never carries the input.
pub fn validate_create(
    name: &str,
    content: ProfileContent<'_>,
) -> Result<NewProfile, ProfileFault> {
    validate_name(name)?;
    let Body {
        canonical,
        hash,
        has_tools,
        model,
    } = validate_body(content)?;
    Ok(NewProfile {
        name: name.to_owned(),
        canonical,
        hash,
        has_tools,
        model,
    })
}

fn validate_body(content: ProfileContent<'_>) -> Result<Body, ProfileFault> {
    if content.text().len() > MAX_PROFILE_JSON_BYTES {
        return Err(ProfileFault::TooLarge);
    }
    let profile = match content {
        ProfileContent::Json(text) => Profile::from_json(text.as_bytes()),
        ProfileContent::Toml(text) => Profile::from_toml(text),
    }
    .map_err(ProfileFault::Malformed)?;
    profile.validate().map_err(ProfileFault::Invalid)?;
    Ok(Body {
        canonical: profile.canonical_json(),
        hash: profile.hash(),
        has_tools: !profile.tools.is_empty(),
        model: profile.model,
    })
}

/// Refuses a model outside `allowlist` with [`StoreError::ModelDenied`].
///
/// With no allowlist every model passes, and a profile with no model passes too: it names no
/// model for a Box to run. The allowlist is process configuration, fixed for the life of the
/// process, so a read inside or outside a transaction sees the same list. The save paths check
/// before opening a transaction. The submit paths and [`blob_for_lease`] check after reading
/// the pinned blob, so a job queued before the list changed is refused at lease time.
pub(crate) fn require_model(
    allowlist: Option<&ModelAllowlist>,
    model: Option<&str>,
) -> Result<(), StoreError> {
    match (allowlist, model) {
        (Some(list), Some(model)) => list.check(model).map_err(StoreError::ModelDenied),
        _ => Ok(()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn version_of(raw: i32) -> Result<u32, StoreError> {
    u32::try_from(raw).map_err(|_| StoreError::OutOfRange("profile version"))
}

fn text_of(bytes: Vec<u8>) -> Result<String, StoreError> {
    String::from_utf8(bytes).map_err(|_| StoreError::OutOfRange("profile content"))
}

/// Stores a profile for the authenticated caller and records the caller as owner.
///
/// `caller` is the user id [`crate::auth::Caller`] carries. The owner is never read from the
/// request. A `None` caller (the box token, or no user store) is refused before validation
/// or any query. The owner row is locked `FOR SHARE` for the transaction, so a user deleted
/// meanwhile cannot gain a profile, and a caller that is not a stored user is refused. The
/// first create of a name by this owner inserts the private `profile` row; a repeat leaves
/// it as is. Versions are keyed by that profile's id, so two owners of one name keep
/// separate streams even for identical content.
///
/// # Errors
///
/// Returns [`ProfileFault::Unowned`] with nothing written when `caller` is `None` or not a
/// stored user, any validation fault of [`validate_create`], [`StoreError::ToolsNotGranted`]
/// when the profile has tools and the owner lacks `profile:tools`,
/// [`StoreError::ModelDenied`] when `allowlist` is set and the profile model is outside it, and
/// a database error.
pub async fn create_owned(
    pool: &PgPool,
    caller: Option<i64>,
    allowlist: Option<&ModelAllowlist>,
    name: &str,
    content: ProfileContent<'_>,
) -> Result<ProfileVersion, StoreError> {
    let owner = caller.ok_or(ProfileFault::Unowned)?;
    let new = validate_create(name, content)?;
    require_model(allowlist, new.model.as_deref())?;
    store_version(pool, owner, new).await
}

async fn store_version(
    pool: &PgPool,
    owner: i64,
    new: NewProfile,
) -> Result<ProfileVersion, StoreError> {
    let size = i32::try_from(new.canonical.len())
        .map_err(|_| StoreError::OutOfRange("profile content"))?;
    let mut tx = pool.begin().await?;
    sqlx::query(LOCK_OWNER)
        .bind(owner)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ProfileFault::Unowned)?;
    if new.has_tools {
        require_tools_grant(&mut tx, owner).await?;
    }
    sqlx::query(INSERT_BLOB)
        .bind(new.hash.as_bytes().as_slice())
        .bind(new.canonical.as_slice())
        .bind(size)
        .execute(&mut *tx)
        .await?;
    sqlx::query(INSERT_PROFILE)
        .bind(owner)
        .bind(&new.name)
        .bind("private")
        .execute(&mut *tx)
        .await?;
    let profile_id: i64 = sqlx::query_scalar(LOCK_PROFILE)
        .bind(owner)
        .bind(&new.name)
        .fetch_one(&mut *tx)
        .await?;
    let NewProfile {
        name,
        canonical,
        hash,
        has_tools,
        model,
    } = new;
    let stored = push_version(
        &mut tx,
        profile_id,
        Body {
            canonical,
            hash,
            has_tools,
            model,
        },
    )
    .await?;
    tx.commit().await?;
    version_reply(name, stored)
}

struct Stored {
    version: i32,
    created: bool,
    body: Body,
}

fn version_reply(name: String, stored: Stored) -> Result<ProfileVersion, StoreError> {
    Ok(ProfileVersion {
        name,
        version: version_of(stored.version)?,
        hash: stored.body.hash.to_string(),
        content_json: text_of(stored.body.canonical)?,
        created: stored.created,
        ..ProfileVersion::default()
    })
}

async fn push_version(
    tx: &mut PgConnection,
    profile_id: i64,
    body: Body,
) -> Result<Stored, StoreError> {
    sqlx::query(LOCK_PROFILE_ID)
        .bind(profile_id)
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query(SELECT_VERSION_BY_HASH)
        .bind(profile_id)
        .bind(body.hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    let (version, created) = if let Some(row) = existing {
        (row.try_get::<i32, _>("version")?, false)
    } else {
        let row = sqlx::query(INSERT_VERSION)
            .bind(profile_id)
            .bind(body.hash.as_bytes().as_slice())
            .fetch_one(&mut *tx)
            .await?;
        (row.try_get::<i32, _>("version")?, true)
    };
    Ok(Stored {
        version,
        created,
        body,
    })
}

struct Locked {
    name: String,
}

async fn lock_for_owner(
    tx: &mut PgConnection,
    caller: i64,
    profile_id: i64,
) -> Result<Locked, StoreError> {
    let row = sqlx::query(LOCK_PROFILE_FOR_WRITE)
        .bind(profile_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
    if row.try_get::<i64, _>("owner_user_id")? != caller {
        return Err(if row.try_get::<String, _>("visibility")? == "shared" {
            ProfileFault::NotOwner.into()
        } else {
            StoreError::NotFound
        });
    }
    Ok(Locked {
        name: row.try_get("name")?,
    })
}

/// Adds a version to the profile `profile_id`, which only its owner may do.
///
/// The content is validated before any query. The profile row is then locked `FOR UPDATE`
/// inside the transaction and its owner compared with `caller`. Identical content returns
/// the existing version with `created` false.
///
/// # Errors
///
/// Returns [`ProfileFault::Unowned`] for a `None` caller, any validation fault of the
/// content, [`StoreError::NotFound`] for an absent profile or a private one owned by someone
/// else, [`ProfileFault::NotOwner`] for a shared one owned by someone else,
/// [`StoreError::ToolsNotGranted`] when the content has tools and `caller` lacks
/// `profile:tools`, [`StoreError::ModelDenied`] when `allowlist` is set and the model is outside
/// it, and a database error. Every refusal writes nothing.
pub async fn update_owned(
    pool: &PgPool,
    caller: Option<i64>,
    allowlist: Option<&ModelAllowlist>,
    profile_id: i64,
    content: ProfileContent<'_>,
) -> Result<ProfileVersion, StoreError> {
    let caller = caller.ok_or(ProfileFault::Unowned)?;
    let body = validate_body(content)?;
    require_model(allowlist, body.model.as_deref())?;
    let size = i32::try_from(body.canonical.len())
        .map_err(|_| StoreError::OutOfRange("profile content"))?;
    let mut tx = pool.begin().await?;
    let locked = lock_for_owner(&mut tx, caller, profile_id).await?;
    if body.has_tools {
        require_tools_grant(&mut tx, caller).await?;
    }
    sqlx::query(INSERT_BLOB)
        .bind(body.hash.as_bytes().as_slice())
        .bind(body.canonical.as_slice())
        .bind(size)
        .execute(&mut *tx)
        .await?;
    let stored = push_version(&mut tx, profile_id, body).await?;
    tx.commit().await?;
    version_reply(locked.name, stored)
}

/// Removes the profile `profile_id`, which only its owner may do.
///
/// The profile row is locked `FOR UPDATE` before the owner check. Versions are insert-only,
/// so a profile that has any is refused with [`ProfileFault::HasVersions`].
///
/// # Errors
///
/// Returns [`ProfileFault::Unowned`] for a `None` caller, [`StoreError::NotFound`] for an
/// absent profile or a private one owned by someone else, [`ProfileFault::NotOwner`] for a
/// shared one owned by someone else, [`ProfileFault::HasVersions`] and a database error.
/// Every refusal writes nothing.
pub async fn delete_owned(
    pool: &PgPool,
    caller: Option<i64>,
    profile_id: i64,
) -> Result<(), StoreError> {
    let caller = caller.ok_or(ProfileFault::Unowned)?;
    let mut tx = pool.begin().await?;
    lock_for_owner(&mut tx, caller, profile_id).await?;
    let has_versions: bool = sqlx::query_scalar(PROFILE_HAS_VERSIONS)
        .bind(profile_id)
        .fetch_one(&mut *tx)
        .await?;
    if has_versions {
        return Err(ProfileFault::HasVersions.into());
    }
    sqlx::query(DELETE_PROFILE)
        .bind(profile_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Reads a profile version as `viewer`, or the latest one when `version` is `None`.
///
/// The name resolves to the viewer's own profile first, then to a shared one. A profile
/// owned by someone else and private is [`StoreError::NotFound`], the same as an absent name.
/// [`Viewer::Shared`] sees shared profiles only.
///
/// # Errors
///
/// [`StoreError::InvalidProfile`] for a bad name, [`StoreError::NotFound`] and a database error.
pub async fn get_for(
    pool: &PgPool,
    viewer: Viewer,
    name: &str,
    version: Option<u32>,
) -> Result<ProfileVersion, StoreError> {
    validate_name(name)?;
    let wanted = version
        .map(|v| i32::try_from(v).map_err(|_| StoreError::NotFound))
        .transpose()?;
    let row = sqlx::query(SELECT_VISIBLE)
        .bind(name)
        .bind(viewer.id())
        .bind(wanted)
        .fetch_optional(pool)
        .await?
        .ok_or(StoreError::NotFound)?;
    let content = row.try_get::<Vec<u8>, _>("content")?;
    let stored = Profile::from_stored_json(&content)
        .map_err(|_| StoreError::OutOfRange("profile content"))?;
    Ok(ProfileVersion {
        name: name.to_owned(),
        version: version_of(row.try_get("version")?)?,
        hash: hex(&row.try_get::<Vec<u8>, _>("hash")?),
        content_json: text_of(content)?,
        created: false,
        owner: row.try_get("owner")?,
        visibility: wire_visibility(&row.try_get::<String, _>("visibility")?)?,
        selection: selection_to_wire(&stored.selection),
        authored_prompt: stored
            .authored_prompt
            .map(|text| text.as_str().to_owned())
            .unwrap_or_default(),
    })
}

fn wire_visibility(text: &str) -> Result<i32, StoreError> {
    Visibility::from_str(text)
        .map(|visibility| visibility_to_wire(visibility) as i32)
        .map_err(|_| StoreError::OutOfRange("profile visibility"))
}

/// Reads the profile blob a leased job pins.
///
/// A blob with `tools` is served only while the job owner (`jobs.user_id`, the user who
/// submitted and was checked at submit) holds `profile:tools`. The grant is read live in the
/// same transaction as the blob, under `FOR SHARE`. The profile owner's grant does not count.
/// The pinned model is checked against `allowlist` too, so a job queued before the list was set
/// or narrowed is refused here. The list is process configuration and takes no lock.
pub(crate) async fn blob_for_lease(
    pool: &PgPool,
    job_id: &str,
    attempt: u32,
    box_name: &str,
    allowlist: Option<&ModelAllowlist>,
) -> Result<GetProfileBlobReply, StoreError> {
    let attempt = i32::try_from(attempt).map_err(|_| StoreError::LeaseDenied)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(SELECT_LEASED_BLOB)
        .bind(job_id)
        .bind(attempt)
        .bind(box_name)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::LeaseDenied)?;
    let Some(name) = row.try_get::<Option<String>, _>("profile_name")? else {
        return Err(StoreError::UnknownProfile);
    };
    let corrupt = || StoreError::OutOfRange("profile blob");
    let version = row
        .try_get::<Option<i32>, _>("profile_version")?
        .ok_or_else(corrupt)?;
    let pinned = row
        .try_get::<Option<Vec<u8>>, _>("profile_hash")?
        .ok_or_else(corrupt)?;
    let version_hash = row
        .try_get::<Option<Vec<u8>>, _>("version_hash")?
        .ok_or_else(corrupt)?;
    let content = row
        .try_get::<Option<Vec<u8>>, _>("content")?
        .ok_or_else(corrupt)?;
    if version_hash != pinned {
        return Err(corrupt());
    }
    let profile = serde_json::from_slice::<Profile>(&content).map_err(|_| corrupt())?;
    if profile.hash().as_bytes().as_slice() != pinned.as_slice()
        || profile.canonical_json() != content
    {
        return Err(corrupt());
    }
    if !profile.tools.is_empty() {
        require_tools_grant(&mut tx, row.try_get("user_id")?).await?;
    }
    require_model(allowlist, profile.model.as_deref())?;
    let catalog = match (
        row.try_get::<Option<String>, _>("snapshot_catalog")?,
        row.try_get::<Option<String>, _>("snapshot_notes")?,
        row.try_get::<Option<Vec<u8>>, _>("snapshot_hash")?,
    ) {
        (None, None, None) => Vec::new(),
        (Some(catalog), Some(notes), Some(hash)) => Snapshot::from_stored(&catalog, &notes, &hash)
            .ok_or_else(corrupt)?
            .wire_items(),
        _ => return Err(corrupt()),
    };
    tx.commit().await?;
    Ok(GetProfileBlobReply {
        profile: Some(ProfileRef {
            name,
            version: version_of(version)?,
            hash: hex(&pinned),
        }),
        content,
        catalog,
    })
}

/// The profile version a job pins, with the effective catalog set frozen for it.
pub(crate) struct Pinned {
    pub(crate) profile_id: i64,
    pub(crate) version: i32,
    pub(crate) hash: Vec<u8>,
    pub(crate) snapshot: Snapshot,
    pub(crate) tools_granted: bool,
}

/// Reports whether `owner` holds `profile:tools`, reading the `users` row and the grant row
/// `FOR SHARE` on `conn`. A missing user row reads as no grant.
///
/// # Errors
///
/// [`StoreError::Database`] when a query fails.
pub(crate) async fn read_tools_grant(
    conn: &mut PgConnection,
    owner: i64,
) -> Result<bool, StoreError> {
    sqlx::query(LOCK_OWNER)
        .bind(owner)
        .fetch_optional(&mut *conn)
        .await?;
    let held = sqlx::query(READ_TOOLS_GRANT)
        .bind(owner)
        .bind(PROFILE_TOOLS)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(held.is_some())
}

/// Refuses with [`StoreError::ToolsNotGranted`] unless `user` holds `profile:tools` now.
///
/// The `users` row and the `user_capabilities` row are read `FOR SHARE` on `conn`, so a revoke
/// in flight finishes first and a later one waits for the caller's transaction.
async fn require_tools_grant(conn: &mut PgConnection, user: i64) -> Result<(), StoreError> {
    if read_tools_grant(conn, user).await? {
        Ok(())
    } else {
        Err(StoreError::ToolsNotGranted)
    }
}

/// Refuses with [`StoreError::ToolsNotGranted`] when `profile` has tools and `granted` is false.
///
/// Single and batch submit share this rule, so the two paths cannot drift.
pub(crate) fn check_profile_tools(profile: &Profile, granted: bool) -> Result<(), StoreError> {
    if profile.tools.is_empty() || granted {
        Ok(())
    } else {
        Err(StoreError::ToolsNotGranted)
    }
}

async fn lock_catalog(conn: &mut PgConnection) -> Result<Vec<CatalogEntry>, StoreError> {
    let corrupt = || StoreError::OutOfRange("catalog item");
    let limit = i64::try_from(MAX_CATALOG + 1).map_err(|_| corrupt())?;
    let rows = sqlx::query(LOCK_CATALOG)
        .bind(limit)
        .fetch_all(conn)
        .await?;
    rows.iter()
        .map(|row| {
            let kind = kind_of(&row.try_get::<String, _>("kind")?).ok_or_else(corrupt)?;
            let item = CatalogItem::new(
                kind,
                &row.try_get::<String, _>("id")?,
                &row.try_get::<String, _>("name")?,
                &row.try_get::<String, _>("content")?,
            )
            .map_err(|_| corrupt())?;
            Ok(CatalogEntry::new(item, row.try_get("admin_enabled")?))
        })
        .collect()
}

/// Reads the latest version of the profile `name` as the user `caller` and freezes the
/// catalog set it resolves to for `runner`, in the caller's transaction.
///
/// The name resolves like [`get_for`]: the caller's own profile first, then a shared one. The
/// chosen profile row and every catalog row are locked `FOR SHARE` until the transaction ends,
/// so a concurrent unshare, version rewrite or catalog edit waits for the job insert.
///
/// # Errors
///
/// [`StoreError::UnknownProfile`] when the caller cannot read a profile of that name, whether
/// it is absent or someone else's private one. [`JobInvalid::Snapshot`] when the selection
/// names an item the catalog lacks or the set passes the blob catalog caps. A stored profile
/// or catalog row that fails its own validation is [`StoreError::OutOfRange`].
/// [`StoreError::ModelDenied`] when `allowlist` is set and the pinned model is outside it. A
/// database error.
pub(crate) async fn pin_for_submit(
    conn: &mut PgConnection,
    caller: i64,
    allowlist: Option<&ModelAllowlist>,
    name: &str,
    runner: RunnerKind,
) -> Result<Pinned, StoreError> {
    validate_name(name)?;
    let row = sqlx::query(SELECT_PINNED_FOR_SUBMIT)
        .bind(name)
        .bind(caller)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::UnknownProfile)?;
    let corrupt = || StoreError::OutOfRange("profile blob");
    let hash: Vec<u8> = row.try_get("hash")?;
    let content: Vec<u8> = row.try_get("content")?;
    let profile = Profile::from_stored_json(&content).map_err(|_| corrupt())?;
    if profile.hash().as_bytes().as_slice() != hash.as_slice() {
        return Err(corrupt());
    }
    let tools_granted = read_tools_grant(conn, caller).await?;
    check_profile_tools(&profile, tools_granted)?;
    require_model(allowlist, profile.model.as_deref())?;
    let entries = lock_catalog(conn).await?;
    let set = resolve(runner, &profile.selection, &entries).map_err(|_| JobInvalid::Snapshot)?;
    Ok(Pinned {
        profile_id: row.try_get("id")?,
        version: row.try_get("version")?,
        hash,
        snapshot: Snapshot::freeze(&set)?,
        tools_granted,
    })
}

/// Lists the profiles `viewer` may read: their own and shared ones, own first on a name clash.
///
/// A zero `limit` means the default and a larger one is cut. `after_name` is passed to the
/// query as is: a NUL byte fails in Postgres and surfaces as `UNAVAILABLE`, and a long value
/// is accepted up to the message cap.
///
/// # Errors
///
/// A database error.
pub async fn list_for(
    pool: &PgPool,
    viewer: Viewer,
    limit: u32,
    after_name: Option<&str>,
) -> Result<ListProfilesReply, StoreError> {
    let limit = match limit {
        0 => DEFAULT_LIST_LIMIT,
        n => n.min(MAX_LIST_LIMIT),
    };
    let rows = sqlx::query(LIST)
        .bind(after_name)
        .bind(i64::from(limit))
        .bind(viewer.id())
        .fetch_all(pool)
        .await?;
    let profiles = rows
        .iter()
        .map(|row| {
            Ok(ProfileSummary {
                name: row.try_get("name")?,
                latest_version: version_of(row.try_get("version")?)?,
                hash: hex(&row.try_get::<Vec<u8>, _>("hash")?),
                owner: row.try_get("owner")?,
                visibility: wire_visibility(&row.try_get::<String, _>("visibility")?)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    Ok(ListProfilesReply { profiles })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOOLS_TOML: &str = "[[tools]]\nname = \"node\"\nversion = \"20.11.1\"\n";

    fn json(text: &str) -> ProfileContent<'_> {
        ProfileContent::Json(text)
    }

    #[test]
    fn tools_are_flagged_and_only_toml_carries_them() {
        let on = validate_create("p", ProfileContent::Toml(TOOLS_TOML)).unwrap();
        assert!(on.has_tools);
        assert!(
            String::from_utf8(on.canonical)
                .unwrap()
                .contains("\"tools\"")
        );
        let plain = validate_create("p", ProfileContent::Toml("model = \"m\"\n")).unwrap();
        assert!(!plain.has_tools);
        let err = validate_create(
            "p",
            json(r#"{"tools":[{"name":"node","version":"20.11.1"}]}"#),
        );
        assert!(matches!(err, Err(ProfileFault::Malformed(_))));
    }

    #[test]
    fn exactly_one_content_field_is_chosen() {
        assert_eq!(
            ProfileContent::select("{}", ""),
            Ok(ProfileContent::Json("{}"))
        );
        assert_eq!(
            ProfileContent::select("", "a = 1"),
            Ok(ProfileContent::Toml("a = 1"))
        );
        for (j, t) in [("", ""), ("{}", "a = 1")] {
            assert_eq!(
                ProfileContent::select(j, t),
                Err(ProfileFault::ContentChoice)
            );
        }
        assert_eq!(
            ProfileFault::ContentChoice.to_string(),
            ERR_PROFILE_CONTENT_CHOICE
        );
    }

    #[test]
    fn names_are_bounded_and_charset_limited() {
        assert_eq!(validate_name("a"), Ok(()));
        assert_eq!(validate_name("Mixed_case-1"), Ok(()));
        assert_eq!(validate_name(&"a".repeat(MAX_NAME_BYTES)), Ok(()));
        for bad in ["", "a b", "a@1", "a.b", "a/b", "\u{e9}", "a\0"] {
            assert_eq!(validate_name(bad), Err(ProfileFault::Name), "{bad:?}");
        }
        assert_eq!(
            validate_name(&"a".repeat(MAX_NAME_BYTES + 1)),
            Err(ProfileFault::Name)
        );
    }

    #[test]
    fn create_canonicalises_and_hashes() {
        let a =
            validate_create("p", json(r#"{"model": "m", "max_turns": 3}"#)).unwrap_or_else(|e| {
                panic!("{e}");
            });
        let b = validate_create("p", json(r#"{"max_turns":3,"model":"m"}"#)).unwrap_or_else(|e| {
            panic!("{e}");
        });
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.canonical, b.canonical);
    }

    #[test]
    fn faults_do_not_echo_input() {
        let secret = "zzz-private-input";
        let err =
            validate_create("p", ProfileContent::Json(&format!("{{\"{secret}\":1}}"))).unwrap_err();
        assert!(!err.to_string().contains(secret));
        let bad_name = "zzz private input";
        let err = validate_create(bad_name, json("{}")).unwrap_err();
        assert!(!err.to_string().contains("private"));
    }
}
