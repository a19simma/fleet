use std::fmt;

/// Why a forge operation failed. The set is closed and carries no upstream text, so no token,
/// address or reply body reaches a caller through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeError {
    /// The host does not answer as the expected forge kind.
    WrongKind,
    /// The repository or pull request is missing, or the credential has no access to it.
    NotFound,
    /// The forge answered 5xx or the connection reset.
    Unavailable,
    /// The reply did not finish within the budget.
    Timeout,
    /// The reply body went over the cap. Fail closed.
    TooLarge,
    /// The forge answered with a redirect. It was not followed.
    Redirected,
    /// The forge refused the request.
    Rejected,
    /// The push is not a fast-forward of the remote branch.
    NonFastForward,
    /// The credential was refused by the forge.
    Unauthorized,
    /// The credential belongs to another host than the repository. Refused before any request.
    HostMismatch,
    /// An input or a reply was malformed.
    Malformed,
}

impl fmt::Display for ForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongKind => "host is not the expected forge",
            Self::NotFound => "repository not found or no access",
            Self::Unavailable => "forge unavailable",
            Self::Timeout => "forge request timed out",
            Self::TooLarge => "forge reply too large",
            Self::Redirected => "forge answered with a redirect",
            Self::Rejected => "forge rejected the request",
            Self::NonFastForward => "push is not a fast-forward",
            Self::Unauthorized => "credential refused by the forge",
            Self::HostMismatch => "credential is for another host",
            Self::Malformed => "malformed forge input or reply",
        })
    }
}

impl std::error::Error for ForgeError {}
