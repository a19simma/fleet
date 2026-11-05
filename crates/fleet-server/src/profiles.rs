//! Profile storage: insert-only blobs and named versions behind `FleetProfiles`.

use std::fmt::{self, Write};

use fleet_core::{Profile, ProfileError, ProfileHash, ProfileInvalid};
use fleet_proto::v1::{
    GetProfileBlobReply, ListProfilesReply, Profile as WireProfile, ProfileRef, ProfileSummary,
    ProfileVersion, ProfileVisibility,
};
use fleet_proto::{ERR_PROFILE_CONTENT_CHOICE, ERR_PROFILE_TOOLS_DISABLED, MAX_PROFILE_JSON_BYTES};
use sqlx::{PgPool, Row};

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
    fn id(self) -> Option<i64> {
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
const SELECT_VISIBLE: &str = "SELECT v.version, v.hash, b.content FROM \
     (SELECT id FROM profile WHERE name = $1 AND (owner_user_id = $2 OR visibility = 'shared') \
      ORDER BY (owner_user_id = $2) DESC NULLS LAST, id LIMIT 1) p \
     JOIN profile_version v ON v.profile_id = p.id \
     JOIN profile_blob b ON b.hash = v.hash \
     WHERE $3::int IS NULL OR v.version = $3 ORDER BY v.version DESC LIMIT 1";
const SELECT_LEASED_BLOB: &str = "SELECT j.profile_name, j.profile_version, j.profile_hash, \
     v.hash AS version_hash, b.content FROM jobs j \
     LEFT JOIN profile_version v ON v.profile_id = j.profile_id AND v.version = j.profile_version \
     LEFT JOIN profile_blob b ON b.hash = j.profile_hash \
     WHERE j.job_id = $1 AND j.attempt = $2 AND j.box = $3 AND j.state = 'RUNNING' \
     AND j.lease_expires_at > now()";
const LIST: &str = "SELECT DISTINCT ON (p.name) p.name, v.version, v.hash FROM profile p \
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
    /// The Profile has tools and the server gate is off.
    ToolsDisabled,
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
            Self::ToolsDisabled => f.write_str(ERR_PROFILE_TOOLS_DISABLED),
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
}

/// A validated Profile body without a name: the canonical JSON and its hash.
struct Body {
    canonical: Vec<u8>,
    hash: ProfileHash,
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

/// Validates a create request. This is the only check on these fields.
///
/// # Errors
///
/// Returns the [`ProfileFault`] of the first rule that fails. It never carries the input.
pub fn validate_create(
    name: &str,
    content: ProfileContent<'_>,
    allow_tools: bool,
) -> Result<NewProfile, ProfileFault> {
    validate_name(name)?;
    let Body { canonical, hash } = validate_body(content, allow_tools)?;
    Ok(NewProfile {
        name: name.to_owned(),
        canonical,
        hash,
    })
}

fn validate_body(content: ProfileContent<'_>, allow_tools: bool) -> Result<Body, ProfileFault> {
    if content.text().len() > MAX_PROFILE_JSON_BYTES {
        return Err(ProfileFault::TooLarge);
    }
    let profile = match content {
        ProfileContent::Json(text) => Profile::from_json(text.as_bytes()),
        ProfileContent::Toml(text) => Profile::from_toml(text),
    }
    .map_err(ProfileFault::Malformed)?;
    if !allow_tools && !profile.tools.is_empty() {
        return Err(ProfileFault::ToolsDisabled);
    }
    profile.validate().map_err(ProfileFault::Invalid)?;
    Ok(Body {
        canonical: profile.canonical_json(),
        hash: profile.hash(),
    })
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
/// stored user, any validation fault of [`validate_create`], and a database error.
pub async fn create_owned(
    pool: &PgPool,
    caller: Option<i64>,
    name: &str,
    content: ProfileContent<'_>,
    allow_tools: bool,
) -> Result<ProfileVersion, StoreError> {
    let owner = caller.ok_or(ProfileFault::Unowned)?;
    let new = validate_create(name, content, allow_tools)?;
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
    } = new;
    let stored = push_version(&mut tx, profile_id, Body { canonical, hash }).await?;
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
    })
}

async fn push_version(
    tx: &mut sqlx::PgConnection,
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
    tx: &mut sqlx::PgConnection,
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
/// else, [`ProfileFault::NotOwner`] for a shared one owned by someone else, and a database
/// error. Every refusal writes nothing.
pub async fn update_owned(
    pool: &PgPool,
    caller: Option<i64>,
    profile_id: i64,
    content: ProfileContent<'_>,
    allow_tools: bool,
) -> Result<ProfileVersion, StoreError> {
    let caller = caller.ok_or(ProfileFault::Unowned)?;
    let body = validate_body(content, allow_tools)?;
    let size = i32::try_from(body.canonical.len())
        .map_err(|_| StoreError::OutOfRange("profile content"))?;
    let mut tx = pool.begin().await?;
    let locked = lock_for_owner(&mut tx, caller, profile_id).await?;
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
    Ok(ProfileVersion {
        name: name.to_owned(),
        version: version_of(row.try_get("version")?)?,
        hash: hex(&row.try_get::<Vec<u8>, _>("hash")?),
        content_json: text_of(row.try_get("content")?)?,
        created: false,
    })
}

pub(crate) async fn blob_for_lease(
    pool: &PgPool,
    job_id: &str,
    attempt: u32,
    box_name: &str,
    allow_tools: bool,
) -> Result<GetProfileBlobReply, StoreError> {
    let attempt = i32::try_from(attempt).map_err(|_| StoreError::LeaseDenied)?;
    let row = sqlx::query(SELECT_LEASED_BLOB)
        .bind(job_id)
        .bind(attempt)
        .bind(box_name)
        .fetch_optional(pool)
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
    if (!allow_tools && !profile.tools.is_empty())
        || profile.hash().as_bytes().as_slice() != pinned.as_slice()
        || profile.canonical_json() != content
    {
        return Err(corrupt());
    }
    Ok(GetProfileBlobReply {
        profile: Some(ProfileRef {
            name,
            version: version_of(version)?,
            hash: hex(&pinned),
        }),
        content,
        catalog: Vec::new(),
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
    fn tools_need_the_gate_and_toml() {
        let toml = ProfileContent::Toml(TOOLS_TOML);
        assert_eq!(
            validate_create("p", toml, false),
            Err(ProfileFault::ToolsDisabled)
        );
        let on = validate_create("p", toml, true).unwrap();
        assert!(
            String::from_utf8(on.canonical)
                .unwrap()
                .contains("\"tools\"")
        );
        let plain = ProfileContent::Toml("model = \"m\"\n");
        assert!(validate_create("p", plain, false).is_ok());
        assert!(validate_create("p", plain, true).is_ok());
        for allow in [false, true] {
            let err = validate_create(
                "p",
                json(r#"{"tools":[{"name":"node","version":"20.11.1"}]}"#),
                allow,
            );
            assert!(matches!(err, Err(ProfileFault::Malformed(_))), "{allow}");
        }
        assert_eq!(
            ProfileFault::ToolsDisabled.to_string(),
            ERR_PROFILE_TOOLS_DISABLED
        );
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
        let a = validate_create("p", json(r#"{"model": "m", "max_turns": 3}"#), false)
            .unwrap_or_else(|e| {
                panic!("{e}");
            });
        let b = validate_create("p", json(r#"{"max_turns":3,"model":"m"}"#), false).unwrap_or_else(
            |e| {
                panic!("{e}");
            },
        );
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.canonical, b.canonical);
    }

    #[test]
    fn faults_do_not_echo_input() {
        let secret = "zzz-private-input";
        let err = validate_create(
            "p",
            ProfileContent::Json(&format!("{{\"{secret}\":1}}")),
            false,
        )
        .unwrap_err();
        assert!(!err.to_string().contains(secret));
        let bad_name = "zzz private input";
        let err = validate_create(bad_name, json("{}"), false).unwrap_err();
        assert!(!err.to_string().contains("private"));
    }
}
