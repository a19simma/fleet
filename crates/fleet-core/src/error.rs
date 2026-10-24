use std::fmt;

/// Errors from the core crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An event id string is not 26 Crockford base32 characters or overflows 128 bits.
    InvalidId(String),
    /// A hook body is not a JSON object.
    NotAnObject,
    /// A box name is not `box-` followed by one or more ASCII digits.
    InvalidBoxName(String),
    /// An event source name is not one of the known sources.
    InvalidSource(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(raw) => write!(f, "invalid event id: {raw:?}"),
            Self::NotAnObject => write!(f, "hook body is not a JSON object"),
            Self::InvalidBoxName(raw) => write!(f, "invalid box name: {raw:?}"),
            Self::InvalidSource(raw) => write!(f, "unknown source: {raw:?}"),
        }
    }
}

impl std::error::Error for Error {}
