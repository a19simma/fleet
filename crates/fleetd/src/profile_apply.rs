//! A validated Profile laid over the default [`Bundle`], as a pure function.
//!
//! No IO, clock or environment is read here. [`apply_profile`] returns the effective bundle,
//! the argv pieces and the final prompt (ADR-0034). Nothing calls it yet.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use fleet_core::Profile;
use serde_json::{Map, Value, json};

use crate::agent_config::{Bundle, BundleError};
use crate::floor::{self, BoxCeilings};

const CLAUDE_MD: &str = "CLAUDE.md";
const SETTINGS: &str = "settings.json";
const CTX_DIR: &str = ".claude/ctx";
const SKILLS_DIR: &str = "skills";
const PLACEHOLDER: &str = "{prompt}";

/// Why a Profile could not be laid over the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyError {
    /// Two overlay paths are equal when compared without case.
    Collision,
    /// A context file path holds whitespace, which an `@` import line cannot carry.
    ImportPath,
    /// The assembled files were rejected by [`Bundle::from_files`].
    Bundle(BundleError),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collision => f.write_str("profile paths collide when compared without case"),
            Self::ImportPath => f.write_str("profile context file path holds whitespace"),
            Self::Bundle(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<BundleError> for ApplyError {
    fn from(err: BundleError) -> Self {
        Self::Bundle(err)
    }
}

/// The result of laying a Profile over the default bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The effective bundle.
    pub bundle: Bundle,
    /// The Profile-driven flags: `--model`, `--allowedTools`, `--disallowedTools`,
    /// `--max-turns` and `--max-budget-usd`. `--model` and `--allowedTools` are omitted when
    /// they hold no value.
    pub argv: Vec<String>,
    /// The Profile prefix followed by the template with the job prompt substituted once.
    pub prompt: String,
    /// The allow entries the Floor removed, without repeats.
    pub dropped_allows: Vec<String>,
}

fn dollars(cents: u64) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

fn default_allow(default: &Bundle) -> Vec<String> {
    default
        .files()
        .get(std::path::Path::new(SETTINGS))
        .and_then(|raw| serde_json::from_slice::<Value>(raw).ok())
        .and_then(|value| value.pointer("/permissions/allow").cloned())
        .and_then(|allow| serde_json::from_value(allow).ok())
        .unwrap_or_default()
}

fn settings_json(
    default: &Bundle,
    profile: &Profile,
    allow: &[String],
    deny: &[String],
) -> Vec<u8> {
    let mut root: Map<String, Value> = default
        .files()
        .get(std::path::Path::new(SETTINGS))
        .and_then(|raw| serde_json::from_slice(raw).ok())
        .unwrap_or_default();
    root.insert(
        "permissions".to_owned(),
        json!({ "allow": allow, "deny": deny }),
    );
    if let Some(model) = &profile.model {
        root.insert("model".to_owned(), json!(model));
    }
    if let Some(attribution) = profile
        .settings
        .as_ref()
        .and_then(|s| s.attribution.as_ref())
    {
        root.insert("attribution".to_owned(), json!(attribution));
    }
    let mut out = serde_json::to_vec_pretty(&Value::Object(root)).unwrap_or_default();
    out.push(b'\n');
    out
}

fn claude_md(default: &Bundle, profile: &Profile) -> Vec<u8> {
    let mut text = profile.claude_md.clone().unwrap_or_else(|| {
        default
            .files()
            .get(std::path::Path::new(CLAUDE_MD))
            .map(|raw| String::from_utf8_lossy(raw).into_owned())
            .unwrap_or_default()
    });
    if !profile.context_files.is_empty() && !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for file in &profile.context_files {
        text.push('@');
        text.push_str(CTX_DIR);
        text.push('/');
        text.push_str(&file.path);
        text.push('\n');
    }
    text.into_bytes()
}

fn overlay(
    default: &Bundle,
    profile: &Profile,
    settings: Vec<u8>,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, ApplyError> {
    if profile
        .context_files
        .iter()
        .any(|file| file.path.chars().any(char::is_whitespace))
    {
        return Err(ApplyError::ImportPath);
    }
    let mut added: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for file in &profile.context_files {
        added.push((
            PathBuf::from(format!("{CTX_DIR}/{}", file.path)),
            file.text.clone().into_bytes(),
        ));
    }
    for skill in &profile.skills {
        for file in &skill.files {
            added.push((
                PathBuf::from(format!("{SKILLS_DIR}/{}/{}", skill.name, file.path)),
                file.text.clone().into_bytes(),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for (path, _) in &added {
        if !seen.insert(path.to_string_lossy().to_lowercase()) {
            return Err(ApplyError::Collision);
        }
    }
    let mut files: BTreeMap<PathBuf, Vec<u8>> = default
        .files()
        .iter()
        .map(|(path, data)| (path.clone(), data.clone()))
        .collect();
    files.insert(PathBuf::from(CLAUDE_MD), claude_md(default, profile));
    files.insert(PathBuf::from(SETTINGS), settings);
    files.extend(added);
    Ok(files)
}

/// Lays `profile` over `default` and derives the argv pieces and the prompt for `job_prompt`.
///
/// `CLAUDE.md` is replaced by the Profile text when present, then one `@.claude/ctx/<path>`
/// line per context file is appended. Context files land at `.claude/ctx/<path>` and skill
/// files at `skills/<name>/<path>`, both inside the bundle root, so the import resolves from
/// `CLAUDE.md`. `settings.json` is generated: permissions from [`floor::apply`], the Profile
/// model and attribution. Rules in `settings.permissions` join `allow` and `deny` before the
/// Floor. A Profile with no allow rules keeps the default bundle's allow list.
///
/// # Errors
///
/// Returns [`ApplyError`] when two overlay paths collide without case, a context path holds
/// whitespace, or [`Bundle::from_files`] rejects the files.
pub fn apply_profile(
    profile: &Profile,
    default: &Bundle,
    ceilings: &BoxCeilings,
    job_prompt: &str,
) -> Result<Applied, ApplyError> {
    let mut merged = profile.clone();
    if let Some(perms) = profile
        .settings
        .as_ref()
        .and_then(|s| s.permissions.as_ref())
    {
        merged.allow.extend(perms.allow.iter().cloned());
        merged.deny.extend(perms.deny.iter().cloned());
    }
    let mut effective = floor::apply(&merged, ceilings);
    if effective.allow.is_empty() {
        effective.allow = default_allow(default);
    }
    let settings = settings_json(default, profile, &effective.allow, &effective.deny);
    let bundle = Bundle::from_files(overlay(default, profile, settings)?)?;
    let mut argv = Vec::new();
    if let Some(model) = &effective.model {
        argv.extend(["--model".to_owned(), model.clone()]);
    }
    if !effective.allow.is_empty() {
        argv.push("--allowedTools".to_owned());
        argv.extend(effective.allow.iter().cloned());
    }
    argv.push("--disallowedTools".to_owned());
    argv.extend(effective.deny.iter().cloned());
    argv.extend([
        "--max-turns".to_owned(),
        effective.max_turns.to_string(),
        "--max-budget-usd".to_owned(),
        dollars(effective.max_budget_cents),
    ]);
    let template = profile.prompt_template.as_deref().unwrap_or(PLACEHOLDER);
    let prompt = format!(
        "{}{}",
        profile.prompt_prefix.as_deref().unwrap_or(""),
        template.replacen(PLACEHOLDER, job_prompt, 1)
    );
    Ok(Applied {
        bundle,
        argv,
        prompt,
        dropped_allows: effective.dropped_allows,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use fleet_core::{ContextFile, Skill};

    use super::*;

    fn ceilings() -> BoxCeilings {
        BoxCeilings {
            default_max_turns: 30,
            max_turns: 50,
            default_max_budget_cents: 500,
            max_budget_cents: 1000,
        }
    }

    fn file(path: &str, text: &str) -> ContextFile {
        ContextFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    fn run(profile: &Profile) -> Result<Applied, ApplyError> {
        apply_profile(profile, &Bundle::default(), &ceilings(), "fix it")
    }

    fn body(applied: &Applied, path: &str) -> Option<String> {
        applied
            .bundle
            .files()
            .get(Path::new(path))
            .map(|raw| String::from_utf8_lossy(raw).into_owned())
    }

    fn full() -> Profile {
        Profile {
            claude_md: Some("be brief".to_owned()),
            context_files: vec![file("a/x.md", "X"), file("y.md", "Y")],
            prompt_prefix: Some("PRE ".to_owned()),
            prompt_template: Some("do: {prompt}!".to_owned()),
            skills: vec![Skill {
                name: "lint".to_owned(),
                files: vec![file("SKILL.md", "S"), file("ref/r.md", "R")],
            }],
            allow: vec!["Read".to_owned(), "Bash(git push*)".to_owned()],
            deny: vec!["Bash(rm *)".to_owned()],
            model: Some("opus".to_owned()),
            max_turns: Some(900),
            max_budget_usd: Some(250),
            ..Profile::default()
        }
    }

    #[test]
    fn argv_and_prompt_match_the_spec() -> Result<(), ApplyError> {
        let applied = run(&full())?;
        let mut want: Vec<String> = ["--model", "opus", "--allowedTools", "Read"]
            .map(str::to_owned)
            .to_vec();
        want.push("--disallowedTools".to_owned());
        want.extend(floor::FLOOR_DENY.iter().map(|d| (*d).to_owned()));
        want.push("Bash(rm *)".to_owned());
        want.extend(["--max-turns", "50", "--max-budget-usd", "2.50"].map(str::to_owned));
        assert_eq!(applied.argv, want);
        assert_eq!(applied.prompt, "PRE do: fix it!");
        assert_eq!(applied.dropped_allows, vec!["Bash(git push*)".to_owned()]);
        Ok(())
    }

    #[test]
    fn the_job_prompt_is_substituted_once_and_not_rescanned() -> Result<(), ApplyError> {
        let profile = Profile {
            prompt_template: Some("{prompt}".to_owned()),
            ..Profile::default()
        };
        let applied = apply_profile(
            &profile,
            &Bundle::default(),
            &ceilings(),
            "{prompt}{prompt}",
        )?;
        assert_eq!(applied.prompt, "{prompt}{prompt}");
        Ok(())
    }

    #[test]
    fn an_empty_profile_passes_the_prompt_and_clamped_defaults() -> Result<(), ApplyError> {
        let applied = run(&Profile::default())?;
        assert_eq!(applied.prompt, "fix it");
        assert!(!applied.argv.iter().any(|a| a == "--model"));
        assert!(applied.argv.windows(2).any(|w| w == ["--max-turns", "30"]));
        assert!(
            applied
                .argv
                .windows(2)
                .any(|w| w == ["--max-budget-usd", "5.00"])
        );
        Ok(())
    }

    #[test]
    fn the_bundle_sha_differs_from_the_default() -> Result<(), ApplyError> {
        let default = Bundle::default().sha256();
        assert_ne!(run(&full())?.bundle.sha256(), default);
        assert_ne!(run(&Profile::default())?.bundle.sha256(), default);
        Ok(())
    }

    #[test]
    fn claude_md_is_replaced_when_present_and_kept_otherwise() -> Result<(), ApplyError> {
        assert_eq!(
            body(&run(&full())?, "CLAUDE.md").as_deref(),
            Some("be brief\n@.claude/ctx/a/x.md\n@.claude/ctx/y.md\n")
        );
        let kept = body(&run(&Profile::default())?, "CLAUDE.md");
        let default = Bundle::default();
        let want = default
            .files()
            .get(Path::new("CLAUDE.md"))
            .map(|raw| String::from_utf8_lossy(raw).into_owned());
        assert_eq!(kept, want);
        Ok(())
    }

    #[test]
    fn context_and_skill_files_land_under_their_roots() -> Result<(), ApplyError> {
        let applied = run(&full())?;
        assert_eq!(body(&applied, ".claude/ctx/a/x.md").as_deref(), Some("X"));
        assert_eq!(body(&applied, ".claude/ctx/y.md").as_deref(), Some("Y"));
        assert_eq!(body(&applied, "skills/lint/SKILL.md").as_deref(), Some("S"));
        assert_eq!(body(&applied, "skills/lint/ref/r.md").as_deref(), Some("R"));
        Ok(())
    }

    #[test]
    fn settings_carry_the_floor_deny_and_the_model() -> Result<(), ApplyError> {
        let applied = run(&full())?;
        let raw = body(&applied, "settings.json").unwrap_or_default();
        let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        assert_eq!(value["model"], json!("opus"));
        assert_eq!(value["permissions"]["allow"], json!(["Read"]));
        let deny = value["permissions"]["deny"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for entry in floor::FLOOR_DENY {
            assert!(deny.contains(&json!(entry)));
        }
        assert!(deny.contains(&json!("Bash(rm *)")));
        Ok(())
    }

    #[test]
    fn no_profile_allow_keeps_the_default_allow_list() -> Result<(), ApplyError> {
        let applied = run(&Profile::default())?;
        assert!(
            applied
                .argv
                .windows(2)
                .any(|w| w == ["--allowedTools", "Read"])
        );
        Ok(())
    }

    #[test]
    fn dropped_allows_have_no_repeats() -> Result<(), ApplyError> {
        let profile = Profile {
            allow: vec!["Edit".to_owned(), "Edit".to_owned()],
            ..Profile::default()
        };
        assert_eq!(run(&profile)?.dropped_allows, vec!["Edit".to_owned()]);
        Ok(())
    }

    #[test]
    fn paths_that_differ_only_in_case_collide() {
        let profile = Profile {
            context_files: vec![file("A.md", "1"), file("a.md", "2")],
            ..Profile::default()
        };
        assert_eq!(run(&profile), Err(ApplyError::Collision));
        let skills = Profile {
            skills: vec![
                Skill {
                    name: "Lint".to_owned(),
                    files: vec![file("SKILL.md", "1")],
                },
                Skill {
                    name: "lint".to_owned(),
                    files: vec![file("SKILL.md", "2")],
                },
            ],
            ..Profile::default()
        };
        assert_eq!(run(&skills), Err(ApplyError::Collision));
    }

    #[test]
    fn a_context_path_with_whitespace_is_refused() {
        let profile = Profile {
            context_files: vec![file("a b.md", "1")],
            ..Profile::default()
        };
        assert_eq!(run(&profile), Err(ApplyError::ImportPath));
    }

    #[test]
    fn bundle_caps_still_apply() {
        let profile = Profile {
            context_files: (0..70).map(|i| file(&format!("f{i}.md"), "x")).collect(),
            ..Profile::default()
        };
        assert_eq!(run(&profile), Err(ApplyError::Bundle(BundleError::TooMany)));
    }
}
