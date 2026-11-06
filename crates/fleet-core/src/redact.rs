use std::borrow::Cow;

use serde_json::{Map, Value};

use crate::Envelope;
use crate::credential::GITHUB_INSTALLATION_TOKEN_PREFIX;

/// Secrets shorter than this many bytes are ignored, since replacing them would shred
/// ordinary text.
pub const MIN_SECRET_LEN: usize = 8;

/// Fewest characters after the installation token prefix that count as a token.
///
/// [`Redactor::with_installation_tokens`] treats a run of this many letters, digits or
/// underscores after the prefix as a token. With the prefix it makes the shortest accepted
/// credential, 20 bytes.
pub const INSTALLATION_TOKEN_MIN_BODY: usize = 16;

/// Text that replaces a scrubbed value.
pub const PLACEHOLDER: &str = "[REDACTED]";

/// Scrubs exact secret values out of strings.
///
/// Redaction is exact-match and best effort, plus an opt-in shape mode,
/// [`Redactor::with_installation_tokens`], for GitHub App installation tokens. It does not
/// catch base64, URL-encoded or split forms of a secret. It covers the payload and the
/// free-form `session_id` and `prompt_id` of an envelope. It leaves `kind`, `box`, `hostname`,
/// `machine_id` and `boot_id` alone.
///
/// Replacement runs in one pass over the original text: the match ranges of all secrets
/// are merged where they overlap and each merged range becomes one [`PLACEHOLDER`], so
/// overlapping secrets cannot leak a fragment and a placeholder is never matched again.
///
/// When scrubbing an object key makes two keys equal, the later ones get a `#2`, `#3`
/// suffix instead of overwriting the earlier value.
#[derive(Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
    skipped: Vec<String>,
    installation_tokens: bool,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("secrets", &self.secrets.len())
            .field("skipped_keys", &self.skipped)
            .field("installation_tokens", &self.installation_tokens)
            .finish()
    }
}

fn usable(value: &str) -> bool {
    if value.len() < MIN_SECRET_LEN || value.trim().is_empty() {
        return false;
    }
    let mut chars = value.chars();
    let first = chars.next();
    chars.any(|c| Some(c) != first)
}

impl Redactor {
    /// Builds a redactor from secret values, dropping unusable and duplicate ones.
    ///
    /// A value is unusable when it is shorter than [`MIN_SECRET_LEN`], blank, or one
    /// character repeated.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::from_entries(values.into_iter().map(|v| (String::new(), v.into())))
    }

    fn from_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut secrets = Vec::new();
        let mut skipped = Vec::new();
        for (key, value) in entries {
            if usable(&value) {
                secrets.push(value);
            } else if !key.is_empty() && !value.is_empty() {
                skipped.push(key);
            }
        }
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        Self {
            secrets,
            skipped,
            installation_tokens: false,
        }
    }

    /// The same redactor, also masking every GitHub App installation token by its shape: the
    /// [`GITHUB_INSTALLATION_TOKEN_PREFIX`] followed by at least
    /// [`INSTALLATION_TOKEN_MIN_BODY`] letters, digits or underscores.
    ///
    /// A job that holds an installation token gets a new one every hour. A copy of the redactor
    /// made before a refresh holds only the old value, so it matches by shape and masks the new
    /// token too. The flag survives [`Redactor::merged`] and a clone.
    #[must_use]
    pub const fn with_installation_tokens(mut self) -> Self {
        self.installation_tokens = true;
        self
    }

    /// Builds a redactor from the text of an env file.
    ///
    /// Reads `KEY=value` lines, tolerating `export `, blank lines and `#` comment lines.
    /// An unquoted value ends at the first ` #`. A quoted value runs to its matching
    /// closing quote and anything after is ignored. Double quotes understand `\"`, `\\`
    /// and `\n`. Values that are blank, shorter than [`MIN_SECRET_LEN`] or one repeated
    /// character are skipped; their keys are listed by [`Redactor::skipped_keys`].
    pub fn from_env_file(text: &str) -> Self {
        Self::from_entries(text.lines().filter_map(parse_env_line))
    }

    /// A redactor over the secrets of both, so one pass masks every value of either.
    ///
    /// The skipped key names of both are kept. Neither input changes.
    #[must_use]
    pub fn merged(&self, other: &Self) -> Self {
        let mut secrets: Vec<String> = self.secrets.iter().chain(&other.secrets).cloned().collect();
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        let mut skipped = self.skipped.clone();
        skipped.extend(other.skipped.iter().cloned());
        Self {
            secrets,
            skipped,
            installation_tokens: self.installation_tokens || other.installation_tokens,
        }
    }

    /// Names of env file keys whose values were skipped as too short or trivial.
    ///
    /// Holds key names only, never values, so callers can log it.
    pub fn skipped_keys(&self) -> &[String] {
        &self.skipped
    }

    /// Number of distinct secrets loaded.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether no secrets are loaded.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Returns the string with every secret replaced.
    pub fn redact_str<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for secret in &self.secrets {
            let mut from = 0;
            while let Some(found) = input
                .get(from..)
                .and_then(|rest| rest.find(secret.as_str()))
            {
                let start = from + found;
                ranges.push((start, start + secret.len()));
                from = start
                    + input
                        .get(start..)
                        .and_then(|s| s.chars().next())
                        .map_or(1, char::len_utf8);
            }
        }
        if self.installation_tokens {
            installation_token_ranges(input, &mut ranges);
        }
        if ranges.is_empty() {
            return Cow::Borrowed(input);
        }
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        let mut out = String::with_capacity(input.len());
        let mut cursor = 0;
        for (start, end) in merged {
            out.push_str(input.get(cursor..start).unwrap_or_default());
            out.push_str(PLACEHOLDER);
            cursor = end;
        }
        out.push_str(input.get(cursor..).unwrap_or_default());
        Cow::Owned(out)
    }

    /// Replaces every secret in the string in place.
    pub fn scrub(&self, text: &mut String) {
        if let Cow::Owned(clean) = self.redact_str(text) {
            *text = clean;
        }
    }

    /// Scrubs every string, object key included, in a JSON value.
    pub fn redact_value(&self, value: &mut Value) {
        if self.secrets.is_empty() && !self.installation_tokens {
            return;
        }
        match value {
            Value::String(text) => self.scrub(text),
            Value::Array(items) => items.iter_mut().for_each(|v| self.redact_value(v)),
            Value::Object(map) => {
                let entries = std::mem::take(map);
                for (key, mut inner) in entries {
                    self.redact_value(&mut inner);
                    let key = free_key(map, self.redact_str(&key).into_owned());
                    map.insert(key, inner);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Scrubs the payload and the free-form id fields of an envelope.
    pub fn redact_envelope(&self, envelope: &mut Envelope) {
        self.redact_value(&mut envelope.payload);
        for text in [&mut envelope.session_id, &mut envelope.prompt_id]
            .into_iter()
            .flatten()
        {
            self.scrub(text);
        }
    }
}

fn installation_token_ranges(input: &str, ranges: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(found) = input
        .get(from..)
        .and_then(|rest| rest.find(GITHUB_INSTALLATION_TOKEN_PREFIX))
    {
        let body = from + found + GITHUB_INSTALLATION_TOKEN_PREFIX.len();
        let run = input.get(body..).map_or(0, |rest| {
            rest.bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count()
        });
        if run >= INSTALLATION_TOKEN_MIN_BODY {
            ranges.push((from + found, body + run));
        }
        from = body + run;
    }
}

fn free_key(map: &Map<String, Value>, key: String) -> String {
    if !map.contains_key(&key) {
        return key;
    }
    (2..=usize::MAX)
        .map(|n| format!("{key}#{n}"))
        .find(|candidate| !map.contains_key(candidate))
        .unwrap_or(key)
}

fn parse_env_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    Some((key.trim().to_owned(), parse_env_value(value.trim())))
}

fn parse_env_value(value: &str) -> String {
    match value.chars().next() {
        Some('"') => parse_double_quoted(value.get(1..).unwrap_or_default()),
        Some('\'') => value
            .get(1..)
            .unwrap_or_default()
            .split('\'')
            .next()
            .unwrap_or_default()
            .to_owned(),
        _ => {
            let end = [" #", "\t#"]
                .iter()
                .filter_map(|marker| value.find(marker))
                .min()
                .unwrap_or(value.len());
            value.get(..end).unwrap_or_default().trim_end().to_owned()
        }
    }
}

fn parse_double_quoted(rest: &str) -> String {
    {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') | None => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                },
                other => out.push(other),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_merged_redactor_masks_both_sets_and_overlaps_in_one_pass() {
        let a = Redactor::new(["alpha-secret-aaaa", "shared-secret-1"]);
        let b = Redactor::new(["shared-secret-1", "beta-secret-bbbb"]);
        let both = a.merged(&b);
        assert_eq!(both.len(), 3);
        let out = both.redact_str("alpha-secret-aaaa beta-secret-bbbb shared-secret-1");
        assert_eq!(out, format!("{PLACEHOLDER} {PLACEHOLDER} {PLACEHOLDER}"));
        let overlap = Redactor::new(["abcdefgh-one"]).merged(&Redactor::new(["gh-one-ijklmn"]));
        assert_eq!(overlap.redact_str("abcdefgh-one-ijklmn"), PLACEHOLDER);
        assert_eq!(a.len(), 2);
        assert!(Redactor::default().merged(&Redactor::default()).is_empty());
    }

    const APP: &str = "ghs_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const NEWER: &str = "ghs_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210";

    #[test]
    fn the_installation_token_mode_masks_any_token_by_its_shape() {
        let r = Redactor::default().with_installation_tokens();
        assert_eq!(
            r.redact_str(&format!("a {APP} b {NEWER} c")),
            format!("a {PLACEHOLDER} b {PLACEHOLDER} c")
        );
        let under = format!("{GITHUB_INSTALLATION_TOKEN_PREFIX}ab_cd_ef_gh_ij_kl_mn");
        assert_eq!(r.redact_str(&under), PLACEHOLDER);
        let shortest = format!(
            "{GITHUB_INSTALLATION_TOKEN_PREFIX}{}",
            "a".repeat(INSTALLATION_TOKEN_MIN_BODY)
        );
        assert_eq!(r.redact_str(&shortest), PLACEHOLDER);
        let one_short = format!(
            "{GITHUB_INSTALLATION_TOKEN_PREFIX}{}",
            "a".repeat(INSTALLATION_TOKEN_MIN_BODY - 1)
        );
        assert_eq!(r.redact_str(&one_short), one_short);
        assert_eq!(r.redact_str("ghs_"), "ghs_");
        assert_eq!(r.redact_str("ghs_ghs_"), "ghs_ghs_");
    }

    #[test]
    fn the_installation_token_mode_stops_at_the_first_foreign_byte() {
        let r = Redactor::default().with_installation_tokens();
        assert_eq!(
            r.redact_str(&format!("{APP}-tail {APP}\u{e9}")),
            format!("{PLACEHOLDER}-tail {PLACEHOLDER}\u{e9}")
        );
        assert_eq!(r.redact_str(&format!("x{APP}")), format!("x{PLACEHOLDER}"));
        assert_eq!(
            r.redact_str(&format!("{APP}{APP}")),
            PLACEHOLDER,
            "back to back tokens read as one run"
        );
    }

    #[test]
    fn a_redactor_without_the_mode_leaves_a_token_alone_and_the_mode_survives_merge_and_clone() {
        assert_eq!(Redactor::default().redact_str(APP), APP);
        let on = Redactor::new(["other-secret-1"]).with_installation_tokens();
        let text = format!("{APP} other-secret-1");
        let want = format!("{PLACEHOLDER} {PLACEHOLDER}");
        let copy = on.clone();
        assert_eq!(copy.redact_str(&text), want);
        assert_eq!(on.merged(&Redactor::default()).redact_str(&text), want);
        assert_eq!(Redactor::default().merged(&on).redact_str(&text), want);
        assert_eq!(
            Redactor::default()
                .merged(&Redactor::default())
                .redact_str(APP),
            APP
        );
    }

    #[test]
    fn the_installation_token_mode_reaches_json_values_keys_and_envelopes() {
        let r = Redactor::default().with_installation_tokens();
        let mut value = json!({ (APP): [NEWER, { "k": format!("x {APP}") }] });
        r.redact_value(&mut value);
        assert_eq!(
            value,
            json!({ PLACEHOLDER: [PLACEHOLDER, { "k": format!("x {PLACEHOLDER}") }] })
        );
        assert!(r.is_empty());
    }

    #[test]
    fn debug_prints_the_count_and_skipped_keys_only() {
        let r = Redactor::from_env_file("LONG=correct-horse-battery\nSHORT=ab\n");
        let shown = format!("{r:?}");
        assert!(!shown.contains("correct-horse"));
        assert!(shown.contains("SHORT"));
        assert!(shown.contains("secrets: 1"));
    }

    #[test]
    fn len_counts_distinct_usable_secrets() {
        let r = Redactor::new([
            "token-abcdefgh",
            "token-abcdefgh",
            "short",
            "other-secret-1",
        ]);
        assert_eq!(r.len(), 2);
        assert!(!r.is_empty());
        assert!(Redactor::default().is_empty());
    }

    #[test]
    fn longest_value_goes_first() {
        let r = Redactor::new(["token-abcdefgh", "token-abcdefgh-extra"]);
        assert_eq!(r.redact_str("x token-abcdefgh-extra y"), "x [REDACTED] y");
    }

    #[test]
    fn short_blank_and_repeated_values_are_skipped() {
        let r = Redactor::new(["short", "1234567", "        ", "aaaaaaaaaa"]);
        assert_eq!(
            r.redact_str("short 1234567 aaaaaaaaaa"),
            "short 1234567 aaaaaaaaaa"
        );
    }

    #[test]
    fn scrubs_nested_values_twice_and_keys() {
        let r = Redactor::new(["s3cr3t-value"]);
        let mut v = json!({
            "a": "pre s3cr3t-value post",
            "s3cr3t-value": 1,
            "n": {"list": ["s3cr3t-value", 7, null, true]}
        });
        r.redact_value(&mut v);
        let text = v.to_string();
        assert!(!text.contains("s3cr3t-value"));
        assert_eq!(v["a"], "pre [REDACTED] post");
        assert_eq!(v["n"]["list"][0], "[REDACTED]");
        assert_eq!(v["[REDACTED]"], 1);
    }

    #[test]
    fn key_collisions_are_suffixed() {
        let r = Redactor::new(["s3cr3t-one", "s3cr3t-two"]);
        let mut v = json!({"s3cr3t-one": 1, "s3cr3t-two": 2, "x": 3});
        r.redact_value(&mut v);
        let map = v.as_object().unwrap();
        assert_eq!(map.len(), 3);
        let mut values: Vec<i64> = ["[REDACTED]", "[REDACTED]#2"]
            .iter()
            .map(|k| map[*k].as_i64().unwrap())
            .collect();
        values.sort_unstable();
        assert_eq!(values, [1, 2]);
    }

    #[test]
    fn overlapping_secrets_merge_into_one_placeholder() {
        let r = Redactor::new(["abcdefgh", "defghijk"]);
        assert_eq!(r.redact_str("x abcdefghijk y"), "x [REDACTED] y");
    }

    #[test]
    fn placeholder_text_is_not_rematched() {
        let r = Redactor::new(["secret-AAAA", "[REDACTED]"]);
        assert_eq!(r.redact_str("secret-AAAA"), "[REDACTED]");
    }

    #[test]
    fn scrub_edits_in_place() {
        let r = Redactor::new(["tok-123456789"]);
        let mut s = String::from("a tok-123456789 b");
        r.scrub(&mut s);
        assert_eq!(s, "a [REDACTED] b");
    }

    #[test]
    fn parses_env_files() {
        let text = "# comment\n\nFLEET_TOKEN=abcdefghij\nexport OTHER=\"quoted-value-1\"\nQ='single-quoted'\nNOEQUALS\nSHORT=abc\n";
        let r = Redactor::from_env_file(text);
        assert_eq!(r.secrets.len(), 3);
        assert_eq!(r.skipped_keys(), ["SHORT"]);
        assert_eq!(
            r.redact_str("abcdefghij quoted-value-1 single-quoted"),
            "[REDACTED] [REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn unquoted_values_stop_at_space_hash() {
        let r = Redactor::from_env_file("A=abcdefghij # note\nB=abc#defghij\n");
        assert_eq!(
            r.redact_str("abcdefghij abc#defghij"),
            "[REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn quoted_values_ignore_trailing_comments_and_unescape() {
        let text = "A=\"abc\\\"defgh\" # note\nB='single-value' # note\nC=\"line1\\nline2\"\n";
        let r = Redactor::from_env_file(text);
        assert_eq!(r.redact_str("abc\"defgh"), "[REDACTED]");
        assert_eq!(r.redact_str("single-value"), "[REDACTED]");
        assert_eq!(r.redact_str("line1\nline2"), "[REDACTED]");
        assert_eq!(r.redact_str("note"), "note");
    }

    #[test]
    fn trivial_env_values_are_reported_by_key() {
        let r = Redactor::from_env_file("A=\"          \"\nB=xxxxxxxxxxxx\nC=\nD=real-secret-1\n");
        assert_eq!(r.skipped_keys(), ["A", "B"]);
        assert_eq!(r.secrets, ["real-secret-1"]);
    }

    #[test]
    fn redacts_envelope_fields() {
        use crate::{EventId, Identity, Source};
        let identity = Identity {
            box_name: "b".into(),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "o".into(),
        };
        let mut env = Envelope::new(&identity, EventId::new(0, 0), Source::Hook, "hook.stop", 1);
        env.payload = json!({"raw": {"prompt": "use tok-123456789 now"}});
        env.session_id = Some("tok-123456789".into());
        Redactor::new(["tok-123456789"]).redact_envelope(&mut env);
        assert_eq!(env.payload["raw"]["prompt"], "use [REDACTED] now");
        assert_eq!(env.session_id.as_deref(), Some("[REDACTED]"));
    }
}
