//! Profile storage: insert-only blobs and named versions behind `FleetProfiles`.

use std::fmt::{self, Write};

use fleet_core::{Profile, ProfileError, ProfileHash, ProfileInvalid};
use fleet_proto::v1::{ListProfilesReply, ProfileSummary, ProfileVersion};
use sqlx::{PgPool, Row};

use crate::store::{DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, StoreError};

/// Longest accepted profile name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// Longest accepted profile JSON, in bytes. Escapes make the JSON longer than its text, so
/// this sits above the 4 MiB text cap of the validator.
pub const MAX_PROFILE_JSON_BYTES: usize = 8 * 1024 * 1024;

const INSERT_BLOB: &str = "INSERT INTO profile_blob (hash, content, size) VALUES ($1, $2, $3) \
     ON CONFLICT (hash) DO NOTHING";
const LOCK_NAME: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
const SELECT_VERSION_BY_HASH: &str =
    "SELECT version FROM profile_version WHERE name = $1 AND hash = $2";
const INSERT_VERSION: &str = "INSERT INTO profile_version (name, version, hash) \
     SELECT $1, COALESCE(MAX(version), 0) + 1, $2 FROM profile_version WHERE name = $1 \
     RETURNING version";
const SELECT_LATEST: &str = "SELECT v.version, v.hash, b.content FROM profile_version v \
     JOIN profile_blob b ON b.hash = v.hash WHERE v.name = $1 \
     ORDER BY v.version DESC LIMIT 1";
const SELECT_EXACT: &str = "SELECT v.version, v.hash, b.content FROM profile_version v \
     JOIN profile_blob b ON b.hash = v.hash WHERE v.name = $1 AND v.version = $2";
const LIST: &str = "SELECT DISTINCT ON (name) name, version, hash FROM profile_version \
     WHERE ($1::text IS NULL OR name > $1) ORDER BY name, version DESC LIMIT $2";

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
}

impl fmt::Display for ProfileFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => f.write_str("invalid profile name"),
            Self::TooLarge => f.write_str("profile json is too large"),
            Self::Malformed(err) => err.fmt(f),
            Self::Invalid(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ProfileFault {}

/// A validated create request: the name and the canonical Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProfile {
    name: String,
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
pub fn validate_create(name: &str, content_json: &str) -> Result<NewProfile, ProfileFault> {
    validate_name(name)?;
    if content_json.len() > MAX_PROFILE_JSON_BYTES {
        return Err(ProfileFault::TooLarge);
    }
    let profile = Profile::from_json(content_json.as_bytes()).map_err(ProfileFault::Malformed)?;
    profile.validate().map_err(ProfileFault::Invalid)?;
    Ok(NewProfile {
        name: name.to_owned(),
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

pub(crate) async fn create(
    pool: &PgPool,
    name: &str,
    content_json: &str,
) -> Result<ProfileVersion, StoreError> {
    let new = validate_create(name, content_json)?;
    let size = i32::try_from(new.canonical.len())
        .map_err(|_| StoreError::OutOfRange("profile content"))?;
    let mut tx = pool.begin().await?;
    sqlx::query(INSERT_BLOB)
        .bind(new.hash.as_bytes().as_slice())
        .bind(new.canonical.as_slice())
        .bind(size)
        .execute(&mut *tx)
        .await?;
    sqlx::query(LOCK_NAME)
        .bind(&new.name)
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query(SELECT_VERSION_BY_HASH)
        .bind(&new.name)
        .bind(new.hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    let (version, created) = if let Some(row) = existing {
        (row.try_get::<i32, _>("version")?, false)
    } else {
        let row = sqlx::query(INSERT_VERSION)
            .bind(&new.name)
            .bind(new.hash.as_bytes().as_slice())
            .fetch_one(&mut *tx)
            .await?;
        (row.try_get::<i32, _>("version")?, true)
    };
    tx.commit().await?;
    Ok(ProfileVersion {
        name: new.name,
        version: version_of(version)?,
        hash: new.hash.to_string(),
        content_json: text_of(new.canonical)?,
        created,
    })
}

pub(crate) async fn get(
    pool: &PgPool,
    name: &str,
    version: Option<u32>,
) -> Result<ProfileVersion, StoreError> {
    validate_name(name)?;
    let row = match version {
        None => {
            sqlx::query(SELECT_LATEST)
                .bind(name)
                .fetch_optional(pool)
                .await?
        }
        Some(wanted) => {
            let wanted = i32::try_from(wanted).map_err(|_| StoreError::NotFound)?;
            sqlx::query(SELECT_EXACT)
                .bind(name)
                .bind(wanted)
                .fetch_optional(pool)
                .await?
        }
    }
    .ok_or(StoreError::NotFound)?;
    Ok(ProfileVersion {
        name: name.to_owned(),
        version: version_of(row.try_get("version")?)?,
        hash: hex(&row.try_get::<Vec<u8>, _>("hash")?),
        content_json: text_of(row.try_get("content")?)?,
        created: false,
    })
}

pub(crate) async fn list(
    pool: &PgPool,
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
        let a = validate_create("p", r#"{"model": "m", "max_turns": 3}"#).unwrap_or_else(|e| {
            panic!("{e}");
        });
        let b = validate_create("p", r#"{"max_turns":3,"model":"m"}"#).unwrap_or_else(|e| {
            panic!("{e}");
        });
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.canonical, b.canonical);
    }

    #[test]
    fn faults_do_not_echo_input() {
        let secret = "zzz-private-input";
        let err = validate_create("p", &format!("{{\"{secret}\":1}}")).unwrap_err();
        assert!(!err.to_string().contains(secret));
        let bad_name = "zzz private input";
        let err = validate_create(bad_name, "{}").unwrap_err();
        assert!(!err.to_string().contains("private"));
    }
}
