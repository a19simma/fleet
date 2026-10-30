//! Passkey ceremonies, stored passkeys and browser sessions over Postgres (ADR-0042).
//!
//! Challenge state lives in memory and is single-use: finishing a ceremony removes it, so a
//! replayed response finds nothing to verify against. The signature counter is stored with
//! the passkey and checked by webauthn-rs, so a cloned authenticator that falls behind the
//! stored counter is refused.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore;
use fleet_core::credential::Secret;
use sqlx::PgPool;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
    WebauthnError,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::cred::users::{UserError, Users, validate_username};

/// Name of the session cookie. The `__Host-` prefix pins it to the host, `Path=/` and HTTPS.
pub const SESSION_COOKIE: &str = "__Host-fleet_session";

/// How long a browser session lives, in seconds.
pub const SESSION_TTL_SECS: i64 = 12 * 60 * 60;

/// How long a browser session may sit unused before it expires, in seconds.
pub const SESSION_IDLE_SECS: i64 = 30 * 60;

const CEREMONY_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING_PER_KIND: usize = 256;
const RANDOM_BYTES: usize = 32;

const USER_BY_NAME: &str = "SELECT id FROM users WHERE lower(username) = $1";
const KEYS_FOR_USER: &str = "SELECT public_key FROM passkeys WHERE user_id = $1 ORDER BY id";
const KEYS_LOCKED: &str =
    "SELECT credential_id, public_key FROM passkeys WHERE user_id = $1 FOR UPDATE";
const UPDATE_KEY: &str = "UPDATE passkeys SET public_key = $2 WHERE credential_id = $1";
const INSERT_KEY: &str =
    "INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)";
const DELETE_USER: &str = "DELETE FROM users WHERE id = $1";
const USERNAME_OF: &str = "SELECT username FROM users WHERE id = $1";
const INSERT_SESSION: &str = "\
INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
VALUES (sha256($1::bytea), $2, $3, now() + ($4::bigint * interval '1 second'))";
const PURGE_SESSIONS: &str = "\
DELETE FROM web_sessions \
WHERE expires_at <= now() OR last_seen <= now() - ($1::bigint * interval '1 second')";
const FIND_SESSION: &str = "\
UPDATE web_sessions s SET last_seen = now() FROM users u \
WHERE u.id = s.user_id AND s.id_hash = sha256($1::bytea) AND s.expires_at > now() \
AND s.last_seen > now() - ($2::bigint * interval '1 second') \
RETURNING s.user_id, u.username, s.csrf";
const DELETE_SESSION: &str = "DELETE FROM web_sessions WHERE id_hash = sha256($1::bytea)";

/// Why a web auth step failed. Messages are fixed text and never echo client input.
#[derive(Debug)]
pub enum AuthError {
    /// The request was refused: bad input, unknown user, failed verification or no pending
    /// ceremony. Callers answer all of these alike.
    Refused,
    /// The database or the server's own state failed.
    Internal,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused => "request refused",
            Self::Internal => "internal error",
        })
    }
}

impl std::error::Error for AuthError {}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(%e, "web auth database error");
        Self::Internal
    }
}

impl From<UserError> for AuthError {
    fn from(e: UserError) -> Self {
        match e {
            UserError::Db(e) => Self::from(e),
            _ => Self::Refused,
        }
    }
}

impl From<WebauthnError> for AuthError {
    fn from(e: WebauthnError) -> Self {
        tracing::debug!(error = ?e, "webauthn ceremony refused");
        Self::Refused
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(_: serde_json::Error) -> Self {
        Self::Internal
    }
}

/// A session just created at login. The id goes into the cookie, the token into forms.
pub struct NewSession {
    /// The opaque cookie value. Only its SHA-256 is stored.
    pub id: Secret,
    /// The CSRF token tied to this session.
    pub csrf: Secret,
}

impl fmt::Debug for NewSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewSession(..)")
    }
}

/// The user behind a valid session cookie.
pub struct SessionInfo {
    /// Owner of the session.
    pub user_id: i64,
    /// Their username.
    pub username: String,
    /// The CSRF token a state-changing request must present.
    pub csrf: Secret,
}

impl fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionInfo")
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("csrf", &"<redacted>")
            .finish()
    }
}

enum Pending {
    Setup {
        state: PasskeyRegistration,
        username: String,
        code: Secret,
    },
    Add {
        state: PasskeyRegistration,
        user_id: i64,
    },
    Login {
        state: PasskeyAuthentication,
        user_id: i64,
    },
}

fn random_hex() -> String {
    use fmt::Write as _;

    let mut bytes = [0_u8; RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(RANDOM_BYTES * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn fold(username: &str) -> Result<String, AuthError> {
    validate_username(username)?;
    Ok(username.to_ascii_lowercase())
}

/// Passkey registration, passkey login and sessions for the web UI.
pub struct WebAuth {
    webauthn: Webauthn,
    pool: PgPool,
    users: Users,
    origin: String,
    pending: Mutex<HashMap<String, (Instant, Pending)>>,
}

impl Pending {
    fn kind(&self) -> u8 {
        match self {
            Self::Setup { .. } => 0,
            Self::Add { .. } => 1,
            Self::Login { .. } => 2,
        }
    }
}

impl fmt::Debug for WebAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebAuth(..)")
    }
}

impl WebAuth {
    /// Builds the relying party for `origin`; `rp_id` defaults to the host of the origin.
    ///
    /// `users` must be the instance that issued the setup code, so both share the one code.
    ///
    /// # Errors
    ///
    /// Returns the webauthn-rs error when the origin is not a URL with a host, or that host
    /// is not within `rp_id`.
    pub fn new(
        pool: PgPool,
        users: Users,
        origin: &str,
        rp_id: Option<&str>,
    ) -> Result<Self, WebauthnError> {
        let origin = Url::parse(origin).map_err(|_| WebauthnError::Configuration)?;
        let rp_id = match rp_id {
            Some(id) => id,
            None => origin.host_str().ok_or(WebauthnError::Configuration)?,
        };
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?
            .rp_name("fleet")
            .build()?;
        Ok(Self {
            webauthn,
            pool,
            users,
            origin: origin.origin().ascii_serialization(),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// The serialized origin browsers send in the `Origin` header.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    fn stash(&self, pending: Pending) -> String {
        let id = random_hex();
        let now = Instant::now();
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, (made, _)| now.duration_since(*made) < CEREMONY_TTL);
        let kind = pending.kind();
        if map.values().filter(|(_, p)| p.kind() == kind).count() >= MAX_PENDING_PER_KIND
            && let Some(oldest) = map
                .iter()
                .filter(|(_, (_, p))| p.kind() == kind)
                .min_by_key(|(_, (made, _))| *made)
                .map(|(key, _)| key.clone())
        {
            map.remove(&oldest);
        }
        map.insert(id.clone(), (now, pending));
        drop(map);
        id
    }

    fn take(&self, ceremony: &str) -> Result<Pending, AuthError> {
        let taken = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(ceremony);
        match taken {
            Some((made, pending)) if made.elapsed() < CEREMONY_TTL => Ok(pending),
            _ => Err(AuthError::Refused),
        }
    }

    /// Starts the first-admin registration. The setup code is checked here without being
    /// spent, so a wrong code stashes no ceremony, and again when the ceremony finishes.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for a bad or reserved username, a wrong setup code, or
    /// once a user exists.
    pub async fn setup_start(
        &self,
        code: &str,
        username: &str,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let username = fold(username)?;
        if self.users.has_real_users().await? {
            return Err(AuthError::Refused);
        }
        self.users.check_setup(code.as_bytes()).await?;
        let (challenge, state) =
            self.webauthn
                .start_passkey_registration(Uuid::new_v4(), &username, &username, None)?;
        let ceremony = self.stash(Pending::Setup {
            state,
            username,
            code: Secret::new(code.to_owned()),
        });
        Ok((ceremony, challenge))
    }

    /// Finishes the first-admin registration: verifies the passkey, spends the setup code,
    /// creates the admin and stores the passkey, then opens a session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] when the ceremony is unknown or replayed, verification
    /// fails or the setup code is wrong or already spent.
    pub async fn setup_finish(
        &self,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<NewSession, AuthError> {
        let Pending::Setup {
            state,
            username,
            code,
        } = self.take(ceremony)?
        else {
            return Err(AuthError::Refused);
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)?;
        let user_id = self.users.redeem_setup(code.expose(), &username).await?;
        if let Err(err) = self.store_key(user_id, &passkey).await {
            if let Err(cleanup) = sqlx::query(DELETE_USER)
                .bind(user_id)
                .execute(&self.pool)
                .await
            {
                tracing::error!(%cleanup, "could not remove the admin left without a passkey");
            }
            return Err(err);
        }
        self.open_session(user_id).await
    }

    /// Starts adding a passkey to the signed-in user `user_id`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] when the user is unknown, or [`AuthError::Internal`]
    /// for a database failure.
    pub async fn add_start(
        &self,
        user_id: i64,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let username: String = sqlx::query_scalar(USERNAME_OF)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AuthError::Refused)?;
        let existing: Vec<_> = self
            .keys(user_id)
            .await?
            .iter()
            .map(|key| key.cred_id().clone())
            .collect();
        let (challenge, state) = self.webauthn.start_passkey_registration(
            Uuid::new_v4(),
            &username,
            &username,
            Some(existing),
        )?;
        let ceremony = self.stash(Pending::Add { state, user_id });
        Ok((ceremony, challenge))
    }

    /// Finishes adding a passkey. `user_id` must be the user who started the ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an unknown or replayed ceremony, another user's
    /// ceremony or a failed verification.
    pub async fn add_finish(
        &self,
        user_id: i64,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<(), AuthError> {
        let Pending::Add {
            state,
            user_id: owner,
        } = self.take(ceremony)?
        else {
            return Err(AuthError::Refused);
        };
        if owner != user_id {
            return Err(AuthError::Refused);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)?;
        self.store_key(user_id, &passkey).await
    }

    /// Starts a login for `username`, matched without regard to letter case.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an invalid or unknown username or a user with no
    /// passkey.
    pub async fn login_start(
        &self,
        username: &str,
    ) -> Result<(String, RequestChallengeResponse), AuthError> {
        let username = fold(username)?;
        let user_id: i64 = sqlx::query_scalar(USER_BY_NAME)
            .bind(&username)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AuthError::Refused)?;
        let keys = self.keys(user_id).await?;
        if keys.is_empty() {
            return Err(AuthError::Refused);
        }
        let (challenge, state) = self.webauthn.start_passkey_authentication(&keys)?;
        let ceremony = self.stash(Pending::Login { state, user_id });
        Ok((ceremony, challenge))
    }

    /// Finishes a login: verifies the assertion, re-checks the signature counter against the
    /// locked row, stores the new counter and opens a session in the same transaction.
    ///
    /// `previous` is the session cookie the browser sent, if any. Its session is deleted in
    /// that transaction, so the id rotates on every login.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an unknown or replayed ceremony, a wrong origin or
    /// relying party, a bad signature or a counter that did not advance past the stored one.
    pub async fn login_finish(
        &self,
        ceremony: &str,
        credential: &PublicKeyCredential,
        previous: Option<&[u8]>,
    ) -> Result<NewSession, AuthError> {
        let Pending::Login { state, user_id } = self.take(ceremony)? else {
            return Err(AuthError::Refused);
        };
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &state)?;
        let mut tx = self.pool.begin().await?;
        let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(KEYS_LOCKED)
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await?;
        let mut matched = false;
        for (credential_id, blob) in rows {
            let mut key: Passkey = serde_json::from_slice(&blob)?;
            if key.cred_id() == result.cred_id() {
                let stored = stored_counter(&blob)?;
                if counter_regressed(result.counter(), stored) {
                    return Err(AuthError::Refused);
                }
            }
            match key.update_credential(&result) {
                Some(true) => {
                    sqlx::query(UPDATE_KEY)
                        .bind(credential_id)
                        .bind(serde_json::to_vec(&key)?)
                        .execute(&mut *tx)
                        .await?;
                    matched = true;
                }
                Some(false) => matched = true,
                None => {}
            }
        }
        if !matched {
            return Err(AuthError::Refused);
        }
        let session = insert_session(&mut tx, user_id, previous).await?;
        tx.commit().await?;
        Ok(session)
    }

    /// Resolves a session cookie value to its user, or `None` when unknown or expired.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] for a database failure.
    pub async fn session(&self, cookie: &[u8]) -> Result<Option<SessionInfo>, AuthError> {
        let row: Option<(i64, String, String)> = sqlx::query_as(FIND_SESSION)
            .bind(cookie)
            .bind(SESSION_IDLE_SECS)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(user_id, username, csrf)| SessionInfo {
            user_id,
            username,
            csrf: Secret::new(csrf),
        }))
    }

    /// Deletes the session behind a cookie value.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] for a database failure.
    pub async fn logout(&self, cookie: &[u8]) -> Result<(), AuthError> {
        sqlx::query(DELETE_SESSION)
            .bind(cookie)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn keys(&self, user_id: i64) -> Result<Vec<Passkey>, AuthError> {
        let blobs: Vec<Vec<u8>> = sqlx::query_scalar(KEYS_FOR_USER)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        blobs
            .iter()
            .map(|blob| serde_json::from_slice(blob).map_err(AuthError::from))
            .collect()
    }

    async fn store_key(&self, user_id: i64, key: &Passkey) -> Result<(), AuthError> {
        sqlx::query(INSERT_KEY)
            .bind(user_id)
            .bind(key.cred_id().as_ref())
            .bind(serde_json::to_vec(key)?)
            .execute(&self.pool)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => AuthError::Refused,
                _ => AuthError::from(e),
            })?;
        Ok(())
    }

    async fn open_session(&self, user_id: i64) -> Result<NewSession, AuthError> {
        let mut tx = self.pool.begin().await?;
        let session = insert_session(&mut tx, user_id, None).await?;
        tx.commit().await?;
        Ok(session)
    }
}

/// Whether an assertion counter fails to advance past the stored one. An authenticator that
/// always reports zero never advances, so a zero beside a zero is allowed.
fn counter_regressed(presented: u32, stored: u32) -> bool {
    (presented > 0 || stored > 0) && presented <= stored
}

fn stored_counter(blob: &[u8]) -> Result<u32, AuthError> {
    let value: serde_json::Value = serde_json::from_slice(blob)?;
    Ok(value
        .pointer("/cred/counter")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0))
}

async fn insert_session(
    conn: &mut sqlx::PgConnection,
    user_id: i64,
    previous: Option<&[u8]>,
) -> Result<NewSession, AuthError> {
    sqlx::query(PURGE_SESSIONS)
        .bind(SESSION_IDLE_SECS)
        .execute(&mut *conn)
        .await?;
    if let Some(old) = previous {
        sqlx::query(DELETE_SESSION)
            .bind(old)
            .execute(&mut *conn)
            .await?;
    }
    let id = Secret::new(random_hex());
    let csrf = Secret::new(random_hex());
    sqlx::query(INSERT_SESSION)
        .bind(id.expose())
        .bind(user_id)
        .bind(String::from_utf8_lossy(csrf.expose()).into_owned())
        .bind(SESSION_TTL_SECS)
        .execute(&mut *conn)
        .await?;
    Ok(NewSession { id, csrf })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_equal_non_zero_counter_regressed() {
        assert!(counter_regressed(7, 7));
        assert!(counter_regressed(1, 1));
    }

    #[test]
    fn a_lower_counter_regressed() {
        assert!(counter_regressed(6, 7));
        assert!(counter_regressed(0, 7));
    }

    #[test]
    fn a_higher_counter_advanced() {
        assert!(!counter_regressed(8, 7));
        assert!(!counter_regressed(1, 0));
    }

    #[test]
    fn a_zero_counter_authenticator_may_log_in_repeatedly() {
        assert!(!counter_regressed(0, 0));
        assert!(!counter_regressed(0, 0));
    }

    fn auth(pool: &PgPool, users: &Users) -> WebAuth {
        WebAuth::new(
            pool.clone(),
            users.clone(),
            "https://fleet.example.com",
            None,
        )
        .unwrap()
    }

    fn pending_len(web: &WebAuth) -> usize {
        web.pending.lock().unwrap().len()
    }

    #[sqlx::test]
    async fn a_wrong_setup_code_stashes_nothing(pool: PgPool) {
        let users = Users::new(pool.clone());
        let web = auth(&pool, &users);
        let real = users.issue_setup_code().await.unwrap().unwrap();
        let wrong = "0".repeat(64);
        assert!(matches!(
            web.setup_start(&wrong, "admin").await,
            Err(AuthError::Refused)
        ));
        assert_eq!(pending_len(&web), 0);
        let code = String::from_utf8(real.expose().to_vec()).unwrap();
        web.setup_start(&code, "admin").await.unwrap();
        assert_eq!(pending_len(&web), 1);
        users.check_setup(code.as_bytes()).await.unwrap();
    }

    fn registration(web: &WebAuth) -> PasskeyRegistration {
        web.webauthn
            .start_passkey_registration(Uuid::new_v4(), "u", "u", None)
            .unwrap()
            .1
    }

    #[sqlx::test]
    async fn one_kind_of_ceremony_cannot_evict_another(pool: PgPool) {
        let users = Users::new(pool.clone());
        let web = auth(&pool, &users);
        let setup = web.stash(Pending::Setup {
            state: registration(&web),
            username: "admin".to_owned(),
            code: Secret::new("code".to_owned()),
        });
        for _ in 0..MAX_PENDING_PER_KIND + 5 {
            web.stash(Pending::Add {
                state: registration(&web),
                user_id: 1,
            });
        }
        assert!(web.pending.lock().unwrap().contains_key(&setup));
        assert_eq!(pending_len(&web), MAX_PENDING_PER_KIND + 1);
    }
}
