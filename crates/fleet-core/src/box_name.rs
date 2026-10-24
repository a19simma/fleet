use std::fmt;
use std::str::FromStr;

use crate::Error;

const PREFIX: &str = "box-";

/// A validated box name: `box-` followed by one or more ASCII digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoxName(String);

impl BoxName {
    /// Validates and wraps a box name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBoxName`] when the name lacks the `box-` prefix, has no
    /// digits after it, or holds anything but ASCII digits after it.
    pub fn new(raw: &str) -> Result<Self, Error> {
        match raw.strip_prefix(PREFIX) {
            Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                Ok(Self(raw.to_owned()))
            }
            _ => Err(Error::InvalidBoxName(raw.to_owned())),
        }
    }

    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for BoxName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for BoxName {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(suffix: &str) -> String {
        format!("{PREFIX}{suffix}")
    }

    #[test]
    fn accepts_prefix_and_digits() {
        let raw = name("12");
        let parsed = BoxName::new(&raw).unwrap();
        assert_eq!(parsed.as_str(), raw);
        assert_eq!(parsed.to_string(), raw);
        assert_eq!(raw.parse::<BoxName>().unwrap(), parsed);
    }

    #[test]
    fn rejects_other_shapes() {
        let cases = [
            String::new(),
            name(""),
            "box".to_owned(),
            "alpha".to_owned(),
            name("1a"),
            name("-1"),
            name("1 "),
            format!(" {}", name("1")),
            format!("x{}", name("1")),
            format!("B{}", name("1").trim_start_matches('b')),
        ];
        for raw in cases {
            assert_eq!(
                BoxName::new(&raw),
                Err(Error::InvalidBoxName(raw.clone())),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn rejects_non_ascii_digits() {
        assert!(BoxName::new(&name("\u{0663}")).is_err());
    }
}
