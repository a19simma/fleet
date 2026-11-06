//! The installation, owner and repository allowlists of the GitHub App lane (ADR-0058).
//!
//! The operator sets the allowed installation ids (SEC-001), the one account the App serves
//! (SEC-014) and the repositories a token may be scoped to (SEC-002, SEC-009). Every list
//! denies by default: an unset or empty list allows nothing. Input is checked against a closed
//! grammar before any comparison, and a compare is exact on the lowercased `owner` and `name`.

use std::collections::BTreeSet;
use std::fmt;

/// Most installation ids the allowlist holds.
pub const MAX_INSTALLATIONS: usize = 64;

/// Most entries the repository allowlist holds.
pub const MAX_REPO_ENTRIES: usize = 1024;

/// Longest GitHub account login, in bytes.
pub const MAX_OWNER_BYTES: usize = 39;

/// Longest GitHub repository name, in bytes.
pub const MAX_NAME_BYTES: usize = 100;

const GITHUB_PREFIX: &str = "https://github.com/";
const GIT_SUFFIX: &str = ".git";
const WILDCARD: &str = "*";

/// Why a policy value was refused. The text names the field and never echoes the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The account is not a GitHub login.
    Account,
    /// The installation list holds an entry that is not an id, an empty entry, or too many.
    Installations,
    /// The repository list holds an entry outside the grammar, an entry whose owner is not the
    /// account, an empty entry, or too many.
    Repositories,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Account => "must be a GitHub login: 1 to 39 ASCII letters, digits or `-`, with no leading or trailing `-`",
            Self::Installations => "must be a comma-separated list of at most 64 installation ids, each 1 to 20 ASCII digits without a leading zero, within u64",
            Self::Repositories => "must be a comma-separated list of at most 1024 entries `owner/name` or `owner/*` whose owner is the configured account",
        })
    }
}

impl std::error::Error for PolicyError {}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= MAX_OWNER_BYTES
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A repository as `owner` and `name`, both ASCII-lowercased and inside the GitHub grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    owner: String,
    name: String,
}

impl RepoRef {
    /// Reads a Job repository: `https://github.com/owner/name`, with an optional `.git` suffix,
    /// or the bare `owner/name`. Anything else is `None`: another host, a port, userinfo, a
    /// query, a fragment, a trailing slash, an extra or empty segment, a backslash, whitespace,
    /// a control character, a non-ASCII byte, or an owner or name over its length cap.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let path = text.strip_prefix(GITHUB_PREFIX).unwrap_or(text);
        let path = path.strip_suffix(GIT_SUFFIX).unwrap_or(path);
        let (owner, name) = path.split_once('/')?;
        (valid_owner(owner) && valid_name(name)).then(|| Self {
            owner: owner.to_ascii_lowercase(),
            name: name.to_ascii_lowercase(),
        })
    }

    /// The lowercased owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The lowercased repository name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoPattern {
    owner: String,
    name: Option<String>,
}

impl RepoPattern {
    fn parse(entry: &str) -> Option<Self> {
        let (owner, name) = entry.split_once('/')?;
        if !valid_owner(owner) {
            return None;
        }
        let name = if name == WILDCARD {
            None
        } else if valid_name(name) && !name.ends_with(GIT_SUFFIX) {
            Some(name.to_ascii_lowercase())
        } else {
            return None;
        };
        Some(Self {
            owner: owner.to_ascii_lowercase(),
            name,
        })
    }

    fn allows(&self, repo: &RepoRef) -> bool {
        self.owner == repo.owner && self.name.as_ref().is_none_or(|name| *name == repo.name)
    }
}

/// The operator allowlists: installation ids, the one account, and the repositories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPolicy {
    account: String,
    installations: BTreeSet<u64>,
    repos: Vec<RepoPattern>,
}

fn split_list(text: Option<&str>) -> Vec<&str> {
    match text {
        None | Some("") => Vec::new(),
        Some(text) => text.split(',').collect(),
    }
}

fn installation_id(entry: &str) -> Option<u64> {
    let digits = !entry.is_empty()
        && entry.len() <= 20
        && !entry.starts_with('0')
        && entry.bytes().all(|b| b.is_ascii_digit());
    digits.then(|| entry.parse().ok()).flatten()
}

impl AppPolicy {
    /// Builds the policy from the three operator values. `installations` and `repos` are
    /// comma-separated with no trimming; an unset or empty list allows nothing.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Account`] when `account` is not a login,
    /// [`PolicyError::Installations`] when an installation entry is not a `u64` without a
    /// leading zero, is empty, or the list is over [`MAX_INSTALLATIONS`], and
    /// [`PolicyError::Repositories`] when a repository entry is outside the grammar (`owner/name`
    /// or `owner/*`, no other glob, no `.git` suffix), names an owner other than `account`, is
    /// empty, or the list is over [`MAX_REPO_ENTRIES`].
    pub fn parse(
        account: &str,
        installations: Option<&str>,
        repos: Option<&str>,
    ) -> Result<Self, PolicyError> {
        if !valid_owner(account) {
            return Err(PolicyError::Account);
        }
        let account = account.to_ascii_lowercase();
        let ids = split_list(installations);
        if ids.len() > MAX_INSTALLATIONS {
            return Err(PolicyError::Installations);
        }
        let installations = ids
            .into_iter()
            .map(|entry| installation_id(entry).ok_or(PolicyError::Installations))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let entries = split_list(repos);
        if entries.len() > MAX_REPO_ENTRIES {
            return Err(PolicyError::Repositories);
        }
        let repos = entries
            .into_iter()
            .map(|entry| {
                RepoPattern::parse(entry)
                    .filter(|pattern| pattern.owner == account)
                    .ok_or(PolicyError::Repositories)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            account,
            installations,
            repos,
        })
    }

    /// Whether `id` is on the installation allowlist.
    #[must_use]
    pub fn installation_allowed(&self, id: u64) -> bool {
        self.installations.contains(&id)
    }

    /// Whether `login` is the configured account, compared after ASCII lowercasing.
    #[must_use]
    pub fn account_matches(&self, login: &str) -> bool {
        login.to_ascii_lowercase() == self.account
    }

    /// Whether a Job repository passes the owner binding (its owner is the account) and the
    /// repository allowlist. A repository the grammar refuses is not allowed.
    #[must_use]
    pub fn repo_allowed(&self, repo: &str) -> bool {
        RepoRef::parse(repo)
            .is_some_and(|repo| self.repos.iter().any(|pattern| pattern.allows(&repo)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(installations: Option<&str>, repos: Option<&str>) -> AppPolicy {
        AppPolicy::parse("Acme", installations, repos).unwrap()
    }

    #[test]
    fn nothing_is_allowed_by_default() {
        for p in [
            policy(None, None),
            policy(Some(""), Some("")),
            AppPolicy::parse("acme", None, None).unwrap(),
        ] {
            assert!(!p.installation_allowed(1));
            assert!(!p.repo_allowed("acme/widget"));
            assert!(!p.repo_allowed("https://github.com/acme/widget"));
        }
    }

    #[test]
    fn an_exact_entry_allows_that_repository_in_every_accepted_form() {
        let p = policy(None, Some("acme/widget"));
        for ok in [
            "acme/widget",
            "ACME/Widget",
            "https://github.com/acme/widget",
            "https://github.com/Acme/WIDGET.git",
            "acme/widget.git",
        ] {
            assert!(p.repo_allowed(ok), "{ok}");
        }
        for no in ["acme/gadget", "acme/widget2", "acme/widge", "acme/idget"] {
            assert!(!p.repo_allowed(no), "{no}");
        }
    }

    #[test]
    fn an_owner_wildcard_allows_the_owner_only() {
        let p = policy(None, Some("acme/*"));
        assert!(p.repo_allowed("acme/anything"));
        assert!(p.repo_allowed("https://github.com/ACME/x.git"));
        assert!(!p.repo_allowed("acme2/anything"));
        assert!(!p.repo_allowed("acm/anything"));
        assert!(!p.repo_allowed("other/anything"));
    }

    #[test]
    fn hostile_job_repositories_are_refused_before_any_match() {
        let p = policy(None, Some("acme/*"));
        let hostile = [
            "acme/widget\r",
            "acme/widget\n",
            "acme/widget\r\n",
            "acme/widget\u{85}",
            "acme/widget\u{2028}",
            "acme/widget\0",
            "acme/widget ",
            " acme/widget",
            "acme/wid get",
            "acme\\widget",
            "acme/wid\\get",
            "https://github.com\\acme/widget",
            "https://user@github.com/acme/widget",
            "https://acme@github.com/acme/widget",
            "https://github.com@evil.example/acme/widget",
            "https://github.com:443/acme/widget",
            "https://github.com.evil.example/acme/widget",
            "https://evil.example/acme/widget",
            "http://github.com/acme/widget",
            "HTTPS://github.com/acme/widget",
            "https://GITHUB.COM/acme/widget",
            "https://github.com/acme/widget/",
            "https://github.com/acme/widget?x=1",
            "https://github.com/acme/widget#x",
            "https://github.com/acme/widget/extra",
            "https://github.com/acme/widget.git.git/x",
            "https://github.com//acme/widget",
            "https://github.com/acme//widget",
            "https://github.com/acme/",
            "https://github.com/",
            "https://[::1]/acme/widget",
            "https://github.com/acme/%77idget",
            "git@github.com:acme/widget.git",
            "ssh://git@github.com/acme/widget",
            "file:///acme/widget",
            "acme/widget/",
            "/acme/widget",
            "acme//widget",
            "acme/",
            "/widget",
            "acme",
            "",
            "/",
            "acme/..",
            "acme/.",
            "../widget",
            "acme/../widget",
            "acme/.git",
            "-acme/widget",
            "acme-/widget",
            "ac me/widget",
            "acme/w\u{e9}",
            "\u{e9}cme/widget",
            "acme/\u{ff57}idget",
            "acme/widget\u{200b}",
            "acme/wid*",
            "acme/*",
            "*/widget",
        ];
        for bad in hostile {
            assert!(!p.repo_allowed(bad), "{bad:?}");
            assert!(RepoRef::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn over_long_repositories_are_refused() {
        let p = policy(None, Some("acme/*"));
        let name = "a".repeat(MAX_NAME_BYTES);
        assert!(p.repo_allowed(&format!("acme/{name}")));
        assert!(!p.repo_allowed(&format!("acme/{name}a")));
        let owner = "a".repeat(MAX_OWNER_BYTES);
        let long = AppPolicy::parse(&owner, None, Some(&format!("{owner}/*"))).unwrap();
        assert!(long.repo_allowed(&format!("{owner}/x")));
        assert!(!long.repo_allowed(&format!("{owner}a/x")));
    }

    #[test]
    fn a_job_repository_of_another_owner_is_refused_even_on_a_wildcard_of_that_owner() {
        let p = policy(None, Some("acme/*"));
        assert!(!p.repo_allowed("evil/widget"));
        assert!(!p.repo_allowed("acme-evil/widget"));
        assert!(!p.repo_allowed("https://github.com/evil/acme"));
    }

    #[test]
    fn repo_ref_lowercases_and_strips_one_git_suffix() {
        let repo = RepoRef::parse("https://github.com/Acme/Widget.git").unwrap();
        assert_eq!((repo.owner(), repo.name()), ("acme", "widget"));
        let twice = RepoRef::parse("acme/widget.git.git").unwrap();
        assert_eq!(twice.name(), "widget.git");
    }

    #[test]
    fn hostile_allowlist_entries_are_refused_at_load() {
        let bad = [
            "acme/widget ",
            " acme/widget",
            "acme/widget\n",
            "acme/widget\r",
            "acme/wid*",
            "acme/*idget",
            "acme/**",
            "*/widget",
            "*",
            "acme",
            "acme/",
            "/widget",
            "acme/widget/",
            "acme//widget",
            "acme/../widget",
            "acme/..",
            "acme/widget.git",
            "acme\\widget",
            "user@acme/widget",
            "acme/w\u{e9}",
            "\u{e9}/widget",
            "other/widget",
            "other/*",
            "acme/widget,",
            ",acme/widget",
            "acme/widget,,acme/gadget",
            "acme/widget, acme/gadget",
            "https://github.com/acme/widget",
        ];
        for entry in bad {
            assert_eq!(
                AppPolicy::parse("acme", None, Some(entry)).unwrap_err(),
                PolicyError::Repositories,
                "{entry:?}"
            );
        }
        let long = format!("acme/{}", "a".repeat(MAX_NAME_BYTES + 1));
        assert_eq!(
            AppPolicy::parse("acme", None, Some(&long)).unwrap_err(),
            PolicyError::Repositories
        );
    }

    #[test]
    fn the_repository_list_is_capped() {
        let fits = vec!["acme/*"; MAX_REPO_ENTRIES].join(",");
        assert!(AppPolicy::parse("acme", None, Some(&fits)).is_ok());
        let over = vec!["acme/*"; MAX_REPO_ENTRIES + 1].join(",");
        assert_eq!(
            AppPolicy::parse("acme", None, Some(&over)).unwrap_err(),
            PolicyError::Repositories
        );
    }

    #[test]
    fn installation_ids_are_exact_u64_values() {
        let p = policy(Some("1,42,18446744073709551615"), None);
        assert!(p.installation_allowed(1));
        assert!(p.installation_allowed(42));
        assert!(p.installation_allowed(u64::MAX));
        assert!(!p.installation_allowed(2));
        assert!(!p.installation_allowed(0));
        assert!(!p.installation_allowed(u64::MAX - 1));
    }

    #[test]
    fn hostile_installation_entries_are_refused_at_load() {
        let bad = [
            "0",
            "01",
            "-1",
            "+1",
            "1 ",
            " 1",
            "1\n",
            "1,",
            ",1",
            "1,,2",
            "1, 2",
            "1.5",
            "1e3",
            "0x10",
            "abc",
            "18446744073709551616",
            "100000000000000000000",
            "1/2",
            "../1",
            "1%2f2",
            "\u{661}",
        ];
        for entry in bad {
            assert_eq!(
                AppPolicy::parse("acme", Some(entry), None).unwrap_err(),
                PolicyError::Installations,
                "{entry:?}"
            );
        }
        let fits = (1..=MAX_INSTALLATIONS)
            .map(|n| n.to_string())
            .collect::<Vec<_>>();
        assert!(AppPolicy::parse("acme", Some(&fits.join(",")), None).is_ok());
        let over = (1..=MAX_INSTALLATIONS + 1)
            .map(|n| n.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            AppPolicy::parse("acme", Some(&over.join(",")), None).unwrap_err(),
            PolicyError::Installations
        );
    }

    #[test]
    fn hostile_accounts_are_refused() {
        for bad in [
            "",
            " ",
            "acme ",
            "ac me",
            "ac/me",
            "acme\n",
            "-acme",
            "acme-",
            "a\u{e9}",
            "acme\\",
            "acme,evil",
        ] {
            assert_eq!(
                AppPolicy::parse(bad, None, None).unwrap_err(),
                PolicyError::Account,
                "{bad:?}"
            );
        }
        let long = "a".repeat(MAX_OWNER_BYTES + 1);
        assert_eq!(
            AppPolicy::parse(&long, None, None).unwrap_err(),
            PolicyError::Account
        );
    }

    #[test]
    fn the_account_matches_after_lowercasing_only() {
        let p = policy(None, None);
        assert!(p.account_matches("acme"));
        assert!(p.account_matches("ACME"));
        assert!(!p.account_matches("acme2"));
        assert!(!p.account_matches("acm"));
        assert!(!p.account_matches("acme "));
        assert!(!p.account_matches(""));
        assert!(!p.account_matches("acme\n"));
    }

    #[test]
    fn error_texts_name_the_rule_without_input() {
        for err in [
            PolicyError::Account,
            PolicyError::Installations,
            PolicyError::Repositories,
        ] {
            assert_ne!(err.to_string(), "");
        }
    }
}
