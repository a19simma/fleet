//! In-memory passkey registration and login on top of webauthn-rs.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, WebauthnError,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

/// Failure of a passkey ceremony step.
#[derive(Debug)]
pub enum PasskeyError {
    /// The user has no registered passkey.
    UnknownUser,
    /// A finish call arrived without a matching start call.
    NoPendingChallenge,
    /// The relying party configuration is invalid.
    Config(WebauthnError),
    /// webauthn-rs rejected the ceremony.
    Webauthn(WebauthnError),
}

impl fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUser => f.write_str("unknown user"),
            Self::NoPendingChallenge => f.write_str("no pending challenge"),
            Self::Config(_) => f.write_str("invalid relying party configuration"),
            Self::Webauthn(_) => f.write_str("webauthn ceremony failed"),
        }
    }
}

impl std::error::Error for PasskeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) | Self::Webauthn(e) => Some(e),
            Self::UnknownUser | Self::NoPendingChallenge => None,
        }
    }
}

struct UserRecord {
    id: Uuid,
    keys: Vec<Passkey>,
    registering: Option<PasskeyRegistration>,
    authenticating: Option<PasskeyAuthentication>,
}

/// Passkey ceremonies for named users, held in memory.
pub struct Passkeys {
    webauthn: Webauthn,
    users: Mutex<HashMap<String, UserRecord>>,
}

impl Passkeys {
    /// Builds a relying party for `origin`, using the origin host as the RP id.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::Config`] when the origin has no host or webauthn-rs
    /// rejects the pair.
    pub fn new(origin: &Url) -> Result<Self, PasskeyError> {
        let rp_id = origin.host_str().unwrap_or_default();
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .and_then(|b| b.rp_name("fleet spike").build())
            .map_err(PasskeyError::Config)?;
        Ok(Self {
            webauthn,
            users: Mutex::new(HashMap::new()),
        })
    }

    fn with_users<T>(&self, f: impl FnOnce(&mut HashMap<String, UserRecord>) -> T) -> T {
        let mut guard = self
            .users
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// Starts registering a passkey for `name`.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::Webauthn`] when webauthn-rs cannot build the challenge.
    pub fn start_register(&self, name: &str) -> Result<CreationChallengeResponse, PasskeyError> {
        self.with_users(|users| {
            let record = users.entry(name.to_owned()).or_insert_with(|| UserRecord {
                id: Uuid::new_v4(),
                keys: Vec::new(),
                registering: None,
                authenticating: None,
            });
            let exclude = record
                .keys
                .iter()
                .map(|k| k.cred_id().clone())
                .collect::<Vec<_>>();
            let (challenge, state) = self
                .webauthn
                .start_passkey_registration(record.id, name, name, Some(exclude))
                .map_err(PasskeyError::Webauthn)?;
            record.registering = Some(state);
            Ok(challenge)
        })
    }

    /// Completes registration and stores the passkey.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::NoPendingChallenge`] without a prior start, or
    /// [`PasskeyError::Webauthn`] when verification fails.
    pub fn finish_register(
        &self,
        name: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<(), PasskeyError> {
        self.with_users(|users| {
            let record = users.get_mut(name).ok_or(PasskeyError::UnknownUser)?;
            let state = record
                .registering
                .take()
                .ok_or(PasskeyError::NoPendingChallenge)?;
            let key = self
                .webauthn
                .finish_passkey_registration(credential, &state)
                .map_err(PasskeyError::Webauthn)?;
            record.keys.push(key);
            Ok(())
        })
    }

    /// Starts a login for `name`.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::UnknownUser`] when `name` has no passkey.
    pub fn start_login(&self, name: &str) -> Result<RequestChallengeResponse, PasskeyError> {
        self.with_users(|users| {
            let record = users.get_mut(name).ok_or(PasskeyError::UnknownUser)?;
            if record.keys.is_empty() {
                return Err(PasskeyError::UnknownUser);
            }
            let (challenge, state) = self
                .webauthn
                .start_passkey_authentication(&record.keys)
                .map_err(PasskeyError::Webauthn)?;
            record.authenticating = Some(state);
            Ok(challenge)
        })
    }

    /// Completes a login and updates the stored counters.
    ///
    /// # Errors
    ///
    /// Returns [`PasskeyError::NoPendingChallenge`] without a prior start, or
    /// [`PasskeyError::Webauthn`] when verification fails.
    pub fn finish_login(
        &self,
        name: &str,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticationResult, PasskeyError> {
        self.with_users(|users| {
            let record = users.get_mut(name).ok_or(PasskeyError::UnknownUser)?;
            let state = record
                .authenticating
                .take()
                .ok_or(PasskeyError::NoPendingChallenge)?;
            let result = self
                .webauthn
                .finish_passkey_authentication(credential, &state)
                .map_err(PasskeyError::Webauthn)?;
            for key in &mut record.keys {
                key.update_credential(&result);
            }
            Ok(result)
        })
    }
}
