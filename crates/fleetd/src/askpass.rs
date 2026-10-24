//! The `GIT_ASKPASS` answer for the finish step's push.
//!
//! git runs the helper with the prompt as its only argument. The token comes from the
//! helper's own environment, never from argv, and nothing here logs or formats it.

/// The fixed username GitHub accepts for a token over https.
pub const USERNAME: &str = "x-access-token";

/// The text to print for `prompt`, or `None` when it is not a credential prompt or the
/// token is missing or empty.
#[must_use]
pub fn answer(prompt: &str, token: Option<&str>) -> Option<String> {
    if prompt.starts_with("Username") {
        Some(USERNAME.to_owned())
    } else if prompt.starts_with("Password") {
        token.filter(|t| !t.is_empty()).map(str::to_owned)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_prompt_gets_the_token() {
        let prompt = "Password for 'https://x-access-token@github.com': ";
        assert_eq!(answer(prompt, Some("tok")).as_deref(), Some("tok"));
    }

    #[test]
    fn a_username_prompt_gets_the_fixed_username() {
        let prompt = "Username for 'https://github.com': ";
        assert_eq!(answer(prompt, Some("tok")).as_deref(), Some(USERNAME));
        assert_eq!(answer(prompt, None).as_deref(), Some(USERNAME));
    }

    #[test]
    fn anything_else_gets_nothing() {
        assert_eq!(answer("Passphrase for key: ", Some("tok")), None);
        assert_eq!(answer("", Some("tok")), None);
        assert_eq!(answer("Enter token", Some("tok")), None);
    }

    #[test]
    fn a_missing_or_empty_token_gets_nothing() {
        assert_eq!(answer("Password for 'x': ", None), None);
        assert_eq!(answer("Password for 'x': ", Some("")), None);
    }
}
