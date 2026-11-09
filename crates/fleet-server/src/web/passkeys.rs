//! Passkey ceremonies, stored passkeys and browser sessions over Postgres (ADR-0042).
//!
//! Challenge state lives in memory and is single-use: finishing a ceremony removes it, so a
//! replayed response finds nothing to verify against. The signature counter is stored with
//! the passkey and checked by webauthn-rs, so a cloned authenticator that falls behind the
//! stored counter is refused.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
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

use crate::cred::limiter::Limiter;
use crate::cred::password::BootstrapPassword;
use crate::cred::users::{UserError, Users, random_hex as code_hex, validate_username};

/// Name of the session cookie. The `__Host-` prefix pins it to the host, `Path=/` and HTTPS.
pub const SESSION_COOKIE: &str = "__Host-fleet_session";

/// How long a browser session lives, in seconds.
pub const SESSION_TTL_SECS: i64 = 12 * 60 * 60;

/// How long a browser session may sit unused before it expires, in seconds.
pub const SESSION_IDLE_SECS: i64 = 30 * 60;

const CEREMONY_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING_PER_KIND: usize = 256;
const RANDOM_BYTES: usize = 32;

/// How long a code made on the account page stays valid, in minutes.
pub(super) const NEW_DEVICE_CODE_TTL_MINUTES: i32 = 10;

const USER_BY_NAME: &str = "SELECT id FROM users WHERE lower(username) = $1";
const KEYS_FOR_USER: &str = "SELECT public_key FROM passkeys WHERE user_id = $1 ORDER BY id";
const KEYS_LOCKED: &str =
    "SELECT credential_id, public_key FROM passkeys WHERE user_id = $1 FOR UPDATE";
const UPDATE_KEY: &str = "UPDATE passkeys SET public_key = $2 WHERE credential_id = $1";
const INSERT_KEY: &str =
    "INSERT INTO passkeys (user_id, credential_id, public_key) VALUES ($1, $2, $3)";
const LIST_KEYS: &str = "\
SELECT id, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), \
to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"') \
FROM passkeys WHERE user_id = $1 ORDER BY id";
const COUNT_KEYS: &str = "SELECT count(*) FROM passkeys WHERE user_id = $1";
const DELETE_KEY: &str = "DELETE FROM passkeys WHERE id = $1 AND user_id = $2";
const MARK_USED: &str = "UPDATE passkeys SET last_used_at = now() WHERE credential_id = $1";
const DELETE_OPEN_CODES: &str = "DELETE FROM setup_codes WHERE user_id = $1 AND used_at IS NULL";
const INSERT_CODE: &str = "\
INSERT INTO setup_codes (user_id, hash, expires_at) \
VALUES ($1, sha256($2::bytea), now() + make_interval(mins => $3))";
const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR UPDATE";
const LIVE_SESSION: &str = "\
SELECT 1 FROM web_sessions WHERE id_hash = sha256($1::bytea) AND user_id = $2 \
AND expires_at > now() AND last_seen > now() - ($3::bigint * interval '1 second')";
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
    SetupPassword {
        state: PasskeyRegistration,
        username: String,
        password: Secret,
    },
    Add {
        state: PasskeyRegistration,
        user_id: i64,
    },
    Enroll {
        state: PasskeyRegistration,
        user_id: i64,
        code: Secret,
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
    bootstrap: Bootstrap,
    pending: Mutex<HashMap<String, (Instant, Pending)>>,
}

struct Bootstrap {
    password: BootstrapPassword,
    limiter: Arc<Limiter>,
    hops: usize,
}

/// One passkey as listed on the account page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRow {
    /// Row id, used to delete.
    pub id: i64,
    /// When it was created, in UTC.
    pub created: String,
    /// When it last signed in, in UTC, or `None` when it never has.
    pub last_used: Option<String>,
}

impl Pending {
    fn kind(&self) -> u8 {
        match self {
            Self::Setup { .. } => 0,
            Self::Add { .. } => 1,
            Self::Login { .. } => 2,
            Self::Enroll { .. } => 3,
            Self::SetupPassword { .. } => 4,
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
            bootstrap: Bootstrap {
                password: BootstrapPassword::disarmed(),
                limiter: Arc::new(Limiter::system()),
                hops: 0,
            },
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Turns on the bootstrap password for the first admin's setup.
    ///
    /// `hops` is the number of trusted proxies in front of the server, see
    /// [`client_ip`](super::client_ip). `limiter` counts failed password attempts.
    #[must_use]
    pub fn with_bootstrap(
        mut self,
        password: BootstrapPassword,
        limiter: Arc<Limiter>,
        hops: usize,
    ) -> Self {
        self.bootstrap = Bootstrap {
            password,
            limiter,
            hops,
        };
        self
    }

    /// The trusted proxy hop count that [`client_ip`](super::client_ip) takes.
    #[must_use]
    pub const fn trusted_hops(&self) -> usize {
        self.bootstrap.hops
    }

    async fn password_gate(&self, candidate: &str, ip: IpAddr) -> Result<(), AuthError> {
        let Some(reservation) = self.bootstrap.limiter.reserve(ip) else {
            return Err(AuthError::Refused);
        };
        let armed = match self.users.bootstrap_password_armed().await {
            Ok(armed) => armed,
            Err(error) => {
                self.bootstrap.limiter.release(reservation);
                return Err(error.into());
            }
        };
        if self.bootstrap.password.verify(candidate, armed).await {
            self.bootstrap.limiter.release(reservation);
            Ok(())
        } else {
            Err(AuthError::Refused)
        }
    }

    /// Starts the first-admin registration with the bootstrap password. Wrong, revoked and
    /// rate-limited attempts all answer [`AuthError::Refused`]. A wrong password costs a full
    /// hash; a rate-limited, malformed or busy refusal skips hashing.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for a refused password or a bad or reserved username,
    /// and [`AuthError::Internal`] for a database failure.
    pub async fn setup_password_start(
        &self,
        password: &str,
        username: &str,
        ip: IpAddr,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        self.password_gate(password, ip).await?;
        let username = fold(username)?;
        let (challenge, state) =
            self.webauthn
                .start_passkey_registration(Uuid::new_v4(), &username, &username, None)?;
        let ceremony = self.stash(Pending::SetupPassword {
            state,
            username,
            password: Secret::new(password.to_owned()),
        });
        Ok((ceremony, challenge))
    }

    /// Lists the user's passkeys in creation order.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] for a database failure.
    pub async fn list_passkeys(&self, user_id: i64) -> Result<Vec<PasskeyRow>, AuthError> {
        let rows: Vec<(i64, Option<String>, Option<String>)> = sqlx::query_as(LIST_KEYS)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, created, last_used)| PasskeyRow {
                id,
                created: created.unwrap_or_default(),
                last_used,
            })
            .collect())
    }

    /// Deletes one of the user's passkeys, never the last one.
    ///
    /// The user row is locked first, so two concurrent deletes cannot leave the user with
    /// none.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an unknown id, another user's passkey, or the
    /// user's only passkey.
    pub async fn delete_passkey(&self, user_id: i64, passkey_id: i64) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AuthError::Refused)?;
        let held: i64 = sqlx::query_scalar(COUNT_KEYS)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if held <= 1 {
            return Err(AuthError::Refused);
        }
        let done = sqlx::query(DELETE_KEY)
            .bind(passkey_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() == 0 {
            return Err(AuthError::Refused);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Issues a single-use code for registering a passkey on a new device. It expires after
    /// [`NEW_DEVICE_CODE_TTL_MINUTES`] and replaces the user's other open codes. `cookie`
    /// must still name a live session of `user_id` under the user lock.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for a missing user or an ended session.
    pub async fn new_device_code(&self, user_id: i64, cookie: &[u8]) -> Result<Secret, AuthError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AuthError::Refused)?;
        sqlx::query(LIVE_SESSION)
            .bind(cookie)
            .bind(user_id)
            .bind(SESSION_IDLE_SECS)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AuthError::Refused)?;
        sqlx::query(DELETE_OPEN_CODES)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        let code = Secret::new(code_hex());
        sqlx::query(INSERT_CODE)
            .bind(user_id)
            .bind(code.expose())
            .bind(NEW_DEVICE_CODE_TTL_MINUTES)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(code)
    }

    pub(super) const fn pool(&self) -> &PgPool {
        &self.pool
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
    /// A ceremony started with the bootstrap password checks the password again, then in
    /// one transaction takes the setup lock, creates the admin, stores the passkey,
    /// revokes the password and opens the session. `ip` keys the failure limiter.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] when the ceremony is unknown or replayed, verification
    /// fails or the setup code is wrong or already spent.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "commit consumes the redemption; the lint cannot see the move"
    )]
    pub async fn setup_finish(
        &self,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
        ip: IpAddr,
    ) -> Result<NewSession, AuthError> {
        let (state, username, code) = match self.take(ceremony)? {
            Pending::Setup {
                state,
                username,
                code,
            } => (state, username, code),
            Pending::SetupPassword {
                state,
                username,
                password,
            } => {
                return self
                    .setup_password_finish(&state, &username, &password, credential, ip)
                    .await;
            }
            _ => return Err(AuthError::Refused),
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)?;
        let mut redemption = self
            .users
            .begin_redeem_setup(code.expose(), &username)
            .await?;
        let user_id = redemption.user_id();
        store_key_on(redemption.conn(), user_id, &passkey).await?;
        let session = insert_session(redemption.conn(), user_id, None).await?;
        redemption.commit().await?;
        Ok(session)
    }

    async fn setup_password_finish(
        &self,
        state: &PasskeyRegistration,
        username: &str,
        password: &Secret,
        credential: &RegisterPublicKeyCredential,
        ip: IpAddr,
    ) -> Result<NewSession, AuthError> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, state)?;
        self.password_gate(&String::from_utf8_lossy(password.expose()), ip)
            .await?;
        self.redeem_password(username, &passkey).await
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "commit consumes the redemption; the lint cannot see the move"
    )]
    async fn redeem_password(
        &self,
        username: &str,
        passkey: &Passkey,
    ) -> Result<NewSession, AuthError> {
        let mut redemption = self.users.begin_redeem_password(username).await?;
        let user_id = redemption.user_id();
        store_key_on(redemption.conn(), user_id, passkey).await?;
        let session = insert_session(redemption.conn(), user_id, None).await?;
        redemption.commit().await?;
        Ok(session)
    }

    /// Starts passkey registration for the user an admin issued `code` to. The code is
    /// checked here without being spent, so a bad code stashes no ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an unknown, used or expired code, or
    /// [`AuthError::Internal`] for a database failure.
    pub async fn enroll_start(
        &self,
        code: &str,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let user_id = self.users.check_user_setup(code.as_bytes()).await?;
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
        let ceremony = self.stash(Pending::Enroll {
            state,
            user_id,
            code: Secret::new(code.to_owned()),
        });
        Ok((ceremony, challenge))
    }

    /// Finishes enrollment: verifies the passkey, then in one transaction locks the user,
    /// spends the setup code, stores the passkey and opens a session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an unknown or replayed ceremony, a failed
    /// verification, or a code that is spent, expired, voided by a reset or no longer
    /// issued to the user who started the ceremony.
    pub async fn enroll_finish(
        &self,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<NewSession, AuthError> {
        let Pending::Enroll {
            state,
            user_id,
            code,
        } = self.take(ceremony)?
        else {
            return Err(AuthError::Refused);
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)?;
        let mut tx = self.pool.begin().await?;
        let redeemed = Users::redeem_user_setup_in(&mut tx, code.expose()).await?;
        if redeemed != user_id {
            return Err(AuthError::Refused);
        }
        store_key_on(&mut tx, user_id, &passkey).await?;
        let session = insert_session(&mut tx, user_id, None).await?;
        tx.commit().await?;
        Ok(session)
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
    /// The user row is locked in one transaction with the insert, and `cookie` must still
    /// name a live session of that user under the lock, so a reset that ran after the
    /// ceremony started cannot be undone by this insert.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Refused`] for an unknown or replayed ceremony, another user's
    /// ceremony, a failed verification, a missing user or a session that ended.
    pub async fn add_finish(
        &self,
        user_id: i64,
        cookie: &[u8],
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
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AuthError::Refused)?;
        sqlx::query(LIVE_SESSION)
            .bind(cookie)
            .bind(user_id)
            .bind(SESSION_IDLE_SECS)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AuthError::Refused)?;
        store_key_on(&mut tx, user_id, &passkey).await?;
        tx.commit().await?;
        Ok(())
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
                sqlx::query(MARK_USED)
                    .bind(&credential_id)
                    .execute(&mut *tx)
                    .await?;
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

    /// Reads the admin flag of `user_id` from the database, never from a session row.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] for a database failure.
    pub(super) async fn is_admin(&self, user_id: i64) -> Result<bool, AuthError> {
        self.users
            .is_admin(user_id)
            .await
            .map_err(|_| AuthError::Internal)
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

async fn store_key_on(
    conn: &mut sqlx::PgConnection,
    user_id: i64,
    key: &Passkey,
) -> Result<(), AuthError> {
    sqlx::query(INSERT_KEY)
        .bind(user_id)
        .bind(key.cred_id().as_ref())
        .bind(serde_json::to_vec(key)?)
        .execute(conn)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => AuthError::Refused,
            _ => AuthError::from(e),
        })?;
    Ok(())
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
