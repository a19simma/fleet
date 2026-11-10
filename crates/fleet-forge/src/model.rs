use std::fmt;

use fleet_core::host::HostName;
use zeroize::Zeroize;

use crate::ForgeError;

const MAX_NAME_BYTES: usize = 100;
const MAX_BRANCH_BYTES: usize = 255;
const MAX_TOKEN_BYTES: usize = 255;

/// A forge credential secret. `Debug` never prints it and drop wipes it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Wraps a token.
    ///
    /// # Errors
    ///
    /// [`ForgeError::Malformed`] when the text is empty, over 255 bytes, or holds whitespace or a
    /// control character.
    pub fn new(text: String) -> Result<Self, ForgeError> {
        let bad = text.is_empty()
            || text.len() > MAX_TOKEN_BYTES
            || text.chars().any(|c| c.is_whitespace() || c.is_control());
        if bad {
            return Err(ForgeError::Malformed);
        }
        Ok(Self(text))
    }

    /// The secret text. Pass it to the wire and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A repository on a host, as `owner/repo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    host: HostName,
    owner: String,
    repo: String,
}

fn valid_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME_BYTES
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl RepoRef {
    /// A repository reference.
    ///
    /// # Errors
    ///
    /// [`ForgeError::Malformed`] when the owner or repo is empty, over 100 bytes, `.` or `..`,
    /// or holds a byte outside ASCII letters, digits, `.`, `_` and `-`.
    pub fn new(host: HostName, owner: &str, repo: &str) -> Result<Self, ForgeError> {
        if !valid_name(owner) || !valid_name(repo) {
            return Err(ForgeError::Malformed);
        }
        Ok(Self {
            host,
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    /// The host.
    #[must_use]
    pub const fn host(&self) -> &HostName {
        &self.host
    }

    /// The owner segment.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The repository segment.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }
}

/// A token stored for one host. It is selected by the exact `(user, host)` pair upstream and
/// carries the host it was stored for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    host: HostName,
    token: Token,
}

impl Credential {
    /// A credential for `host`.
    #[must_use]
    pub const fn new(host: HostName, token: Token) -> Self {
        Self { host, token }
    }

    /// The host the token was stored for.
    #[must_use]
    pub const fn host(&self) -> &HostName {
        &self.host
    }
}

/// A repository and the credential used on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoAccess {
    repo: RepoRef,
    credential: Credential,
}

impl RepoAccess {
    /// Pairs a repository with a credential. The pair is not checked here: an adapter calls
    /// [`RepoAccess::bind`] before its first request.
    #[must_use]
    pub const fn new(repo: RepoRef, credential: Credential) -> Self {
        Self { repo, credential }
    }

    /// The repository.
    #[must_use]
    pub const fn repo(&self) -> &RepoRef {
        &self.repo
    }

    /// The repository and its token, only when the credential was stored for the repository's
    /// host. Every adapter call that sends a token goes through this check first.
    ///
    /// # Errors
    ///
    /// [`ForgeError::HostMismatch`] when the hosts differ.
    pub fn bind(&self) -> Result<(&RepoRef, &Token), ForgeError> {
        if self.credential.host == self.repo.host {
            Ok((&self.repo, &self.credential.token))
        } else {
            Err(ForgeError::HostMismatch)
        }
    }
}

/// What `push` and `create_pr` act on: the access, the Job branch and the base branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    access: RepoAccess,
    branch: String,
    base: String,
}

fn valid_branch(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_BRANCH_BYTES
        && !text.starts_with(['-', '/'])
        && !text.ends_with(['/', '.'])
        && !text.contains("..")
        && !text.contains("//")
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

impl PushTarget {
    /// A push target.
    ///
    /// # Errors
    ///
    /// [`ForgeError::Malformed`] when a branch is empty, over 255 bytes, starts with `-` or `/`,
    /// ends with `/` or `.`, holds `..` or `//`, or holds a byte outside ASCII letters, digits,
    /// `.`, `_`, `-` and `/`.
    pub fn new(access: RepoAccess, branch: &str, base: &str) -> Result<Self, ForgeError> {
        if !valid_branch(branch) || !valid_branch(base) {
            return Err(ForgeError::Malformed);
        }
        Ok(Self {
            access,
            branch: branch.to_owned(),
            base: base.to_owned(),
        })
    }

    /// The repository and credential.
    #[must_use]
    pub const fn access(&self) -> &RepoAccess {
        &self.access
    }

    /// The Job branch.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// The base branch of the pull request.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }
}

/// Whether the credential can push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// The forge reported push permission.
    Granted,
    /// The forge reported no push permission.
    Denied,
    /// The forge did not report permissions.
    Unknown,
}

/// A successful `verify`: the repository is readable and the forge said this about push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// Push permission as the forge reported it.
    pub push: Permission,
}
