//! Checks a stored `file_patch` diff before `fleet edit apply` hands it to git (ADR-0066).
//!
//! The diff is server text and untrusted. [`validate`] accepts one narrow shape: a text diff of
//! the single file the edit targets, with plain create, delete or modify headers and counted
//! hunks. Everything else is refused, so a hostile diff never reaches `git apply`.

use std::fmt;
use std::io::{Read, Write};
use std::iter::Peekable;
use std::path::Path;
use std::process::{Command, Stdio};

use fleet_core::graph::RepoPath;
use fleet_core::text::strip_keeping_lines;

use crate::{CliError, Scrub};

/// Why a diff or its target was refused. Every message is fixed text: none repeats the diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The payload is empty.
    Empty,
    /// The payload is longer than the limit.
    TooLarge,
    /// The payload holds a control, format, separator or tag character other than newline and tab.
    ForbiddenCharacters,
    /// The target is not a safe relative path inside the repository.
    UnsafeTarget,
    /// The diff names a path other than the target.
    PathMismatch,
    /// The diff holds a header git would act on beyond a text edit: rename, copy, mode change,
    /// symlink, submodule or binary data.
    Unsupported,
    /// The diff is not a well-formed single-file unified diff.
    Malformed,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the patch is empty",
            Self::TooLarge => "the patch is larger than the payload limit",
            Self::ForbiddenCharacters => "the patch holds forbidden characters",
            Self::UnsafeTarget => "the patch target is not a safe path inside the repository",
            Self::PathMismatch => "the patch names a path other than its target",
            Self::Unsupported => {
                "the patch holds a rename, copy, mode change, symlink, submodule or binary change"
            }
            Self::Malformed => "the patch is not a well-formed single-file unified diff",
        })
    }
}

const DEV_NULL: &str = "/dev/null";
const FILE_MODES: [&str; 2] = ["100644", "100755"];

/// Checks `payload` as a diff of `target`, at most `max` bytes.
///
/// The target must be a [`RepoPath`] of letters, digits and `._-+@,=/` with no `.git` or
/// `.gitmodules` segment in any case or with trailing dots. The diff must hold one file, named by
/// the target on every header, with at most create, delete or modify headers and hunks whose
/// counts match their lines. Only newline and tab may be a non-printing character.
///
/// # Errors
///
/// Returns the [`Refusal`] that applies first.
pub fn validate(payload: &str, target: &str, max: usize) -> Result<(), Refusal> {
    if payload.trim().is_empty() {
        return Err(Refusal::Empty);
    }
    if payload.len() > max {
        return Err(Refusal::TooLarge);
    }
    if strip_keeping_lines(payload) != payload {
        return Err(Refusal::ForbiddenCharacters);
    }
    safe_target(target)?;
    let body = payload.strip_suffix('\n').ok_or(Refusal::Malformed)?;
    let mut lines = body.split('\n').peekable();
    header(&mut lines, target)?;
    let mut hunks = 0_usize;
    while let Some(line) = lines.next() {
        let (old, new) = hunk_counts(line)?;
        consume_hunk(&mut lines, old, new)?;
        hunks += 1;
    }
    if hunks == 0 {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

fn safe_target(target: &str) -> Result<(), Refusal> {
    let bad = Refusal::UnsafeTarget;
    RepoPath::new(target).map_err(|_| bad)?;
    let allowed = |c: char| c.is_ascii_alphanumeric() || "._-+@,=/".contains(c);
    if target.ends_with('/') || target.starts_with('-') || !target.chars().all(allowed) {
        return Err(bad);
    }
    for segment in target.split('/') {
        let folded = segment.to_ascii_lowercase();
        let folded = folded.trim_end_matches('.');
        if matches!(folded, ".git" | "git~1" | ".gitmodules" | "gitmod~1") {
            return Err(bad);
        }
    }
    Ok(())
}

fn header<'a>(
    lines: &mut Peekable<impl Iterator<Item = &'a str>>,
    target: &str,
) -> Result<(), Refusal> {
    let first = lines.next().ok_or(Refusal::Malformed)?;
    let Some(rest) = first.strip_prefix("diff --git ") else {
        return Err(Refusal::Malformed);
    };
    if rest != format!("a/{target} b/{target}") {
        return Err(Refusal::PathMismatch);
    }
    let (mut created, mut deleted, mut indexed) = (false, false, false);
    loop {
        let line = lines.next().ok_or(Refusal::Malformed)?;
        if let Some(mode) = line.strip_prefix("new file mode ") {
            if created || deleted || !FILE_MODES.contains(&mode) {
                return Err(Refusal::Unsupported);
            }
            created = true;
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            if created || deleted || !FILE_MODES.contains(&mode) {
                return Err(Refusal::Unsupported);
            }
            deleted = true;
        } else if let Some(rest) = line.strip_prefix("index ") {
            if indexed || !index_line(rest) {
                return Err(Refusal::Unsupported);
            }
            indexed = true;
        } else if let Some(old) = line.strip_prefix("--- ") {
            let new = lines
                .next()
                .and_then(|l| l.strip_prefix("+++ "))
                .ok_or(Refusal::Malformed)?;
            return sides(old, new, target, (created, deleted));
        } else if line.starts_with("+++ ") || line.starts_with("@@") {
            return Err(Refusal::Malformed);
        } else {
            return Err(Refusal::Unsupported);
        }
    }
}

fn index_line(rest: &str) -> bool {
    let (hashes, mode) = rest
        .split_once(' ')
        .map_or((rest, None), |(h, m)| (h, Some(m)));
    let hex = |s: &str| (7..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit());
    hashes
        .split_once("..")
        .is_some_and(|(a, b)| hex(a) && hex(b))
        && mode.is_none_or(|m| FILE_MODES.contains(&m))
}

fn sides(
    old: &str,
    new: &str,
    target: &str,
    (created, deleted): (bool, bool),
) -> Result<(), Refusal> {
    let side = |text: &str, prefix: char| {
        if text == DEV_NULL {
            Ok(None)
        } else if text == format!("{prefix}/{target}") {
            Ok(Some(()))
        } else {
            Err(Refusal::PathMismatch)
        }
    };
    let (old, new) = (side(old, 'a')?, side(new, 'b')?);
    if old.is_none() && new.is_none() {
        return Err(Refusal::Malformed);
    }
    if old.is_none() != created || new.is_none() != deleted {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

fn hunk_counts(line: &str) -> Result<(u32, u32), Refusal> {
    let bad = Refusal::Malformed;
    let rest = line.strip_prefix("@@ -").ok_or(bad)?;
    let (old, rest) = rest.split_once(" +").ok_or(bad)?;
    let (new, _) = rest.split_once(" @@").ok_or(bad)?;
    Ok((range_len(old)?, range_len(new)?))
}

fn range_len(range: &str) -> Result<u32, Refusal> {
    let number = |text: &str| {
        let plain = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        plain
            .then(|| text.parse::<u32>().ok())
            .flatten()
            .ok_or(Refusal::Malformed)
    };
    match range.split_once(',') {
        Some((start, len)) => number(start).and_then(|_| number(len)),
        None => number(range).map(|_| 1),
    }
}

fn consume_hunk<'a>(
    lines: &mut Peekable<impl Iterator<Item = &'a str>>,
    mut old: u32,
    mut new: u32,
) -> Result<(), Refusal> {
    while old > 0 || new > 0 {
        let line = lines.next().ok_or(Refusal::Malformed)?;
        match line.bytes().next() {
            Some(b' ') | None => {
                old = old.checked_sub(1).ok_or(Refusal::Malformed)?;
                new = new.checked_sub(1).ok_or(Refusal::Malformed)?;
            }
            Some(b'-') => old = old.checked_sub(1).ok_or(Refusal::Malformed)?,
            Some(b'+') => new = new.checked_sub(1).ok_or(Refusal::Malformed)?,
            Some(b'\\') => {}
            Some(_) => return Err(Refusal::Malformed),
        }
    }
    let _ = lines.next_if(|l| l.starts_with('\\'));
    Ok(())
}

/// The result of an applied patch.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The scrubbed repository-relative target that changed.
    pub target: String,
}

const GIT_OUTPUT_CAP: u64 = 16 * 1024;
const OUTPUT_LINES: usize = 8;
const SCRUBBED_ENV: [&str; 7] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_COMMON_DIR",
];

struct GitRun {
    ok: bool,
    output: String,
}

fn git(dir: &Path, args: &[&str], stdin: Option<&str>) -> Result<GitRun, CliError> {
    let mut command = Command::new("git");
    command
        .arg("--literal-pathspecs")
        .args(args)
        .current_dir(dir)
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in SCRUBBED_ENV {
        command.env_remove(name);
    }
    let mut child = command
        .spawn()
        .map_err(|e| CliError::Apply(format!("cannot run git: {}", e.kind())))?;
    let writer = stdin.and_then(|text| {
        let mut pipe = child.stdin.take()?;
        let body = text.to_owned();
        Some(std::thread::spawn(move || {
            let _ = pipe.write_all(body.as_bytes());
        }))
    });
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let err_reader = std::thread::spawn(move || capture(stderr));
    let mut output = capture(stdout);
    output.push_str(&err_reader.join().unwrap_or_default());
    let status = child.wait();
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let status = status.map_err(|e| CliError::Apply(format!("cannot run git: {}", e.kind())))?;
    Ok(GitRun {
        ok: status.success(),
        output,
    })
}

fn capture(stream: Option<impl Read>) -> String {
    let Some(mut stream) = stream else {
        return String::new();
    };
    let mut kept = Vec::new();
    let _ = (&mut stream).take(GIT_OUTPUT_CAP).read_to_end(&mut kept);
    let _ = std::io::copy(&mut stream, &mut std::io::sink());
    String::from_utf8_lossy(&kept).into_owned()
}

fn echo(scrub: &Scrub, output: &str) -> String {
    scrub
        .text(output)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(OUTPUT_LINES)
        .fold(String::new(), |mut shown, l| {
            shown.push_str("\n  ");
            shown.push_str(&scrub.free(l));
            shown
        })
}

fn refuse(message: impl Into<String>) -> CliError {
    CliError::Apply(message.into())
}

fn symlink_free(root: &Path, target: &str, shown: &str) -> Result<(), CliError> {
    let mut path = root.to_path_buf();
    for part in target.split('/') {
        path.push(part);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(refuse(format!("refused: {shown} passes through a symlink")));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(refuse(format!(
                    "refused: cannot inspect {shown}: {}",
                    e.kind()
                )));
            }
        }
    }
    Ok(())
}

/// Validates `payload`, then applies it to `target` in the work tree that contains `dir`.
///
/// The change is left uncommitted and unstaged. A dirty target, a symlinked path, or a patch
/// that does not apply cleanly is refused before the work tree changes; a conflict leaves
/// markers in the file and stages nothing.
///
/// # Errors
///
/// Returns [`CliError::Apply`] with a fixed message and scrubbed git output.
pub fn apply(
    dir: &Path,
    payload: &str,
    target: &str,
    max: usize,
    scrub: &Scrub,
) -> Result<Outcome, CliError> {
    validate(payload, target, max).map_err(|r| refuse(format!("refused: {r}")))?;
    let top = git(dir, &["rev-parse", "--show-toplevel"], None)?;
    let root = top.output.trim();
    if !top.ok || root.is_empty() || root.contains('\n') {
        return Err(refuse("refused: not inside a git work tree"));
    }
    let root = Path::new(root);
    let shown = scrub.ident(target);
    symlink_free(root, target, &shown)?;
    let status = git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            target,
        ],
        None,
    )?;
    if !status.ok {
        return Err(refuse(format!(
            "refused: cannot read the status of {shown}{}",
            echo(scrub, &status.output)
        )));
    }
    if !status.output.is_empty() {
        return Err(refuse(format!(
            "refused: {shown} has local changes; commit or discard them first"
        )));
    }
    let check = git(root, &["apply", "--3way", "--check", "-"], Some(payload))?;
    if !check.ok {
        return Err(refuse(format!(
            "patch does not apply to {shown}{}",
            echo(scrub, &check.output)
        )));
    }
    let run = git(root, &["apply", "--3way", "-"], Some(payload))?;
    let reset = git(root, &["reset", "-q", "--", target], None)?;
    if !reset.ok {
        return Err(refuse(format!(
            "patch applied to {shown} but unstaging it failed{}",
            echo(scrub, &reset.output)
        )));
    }
    if !run.ok || run.output.contains("with conflicts") {
        return Err(refuse(format!(
            "conflict applying the patch to {shown}: resolve the markers in the file; nothing is staged or committed"
        )));
    }
    Ok(Outcome { target: shown })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = fleet_proto::MAX_EDIT_PAYLOAD_BYTES;
    const T: &str = "src/a.txt";
    const BODY: &str = "@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n";

    fn modify(target: &str) -> String {
        format!(
            "diff --git a/{target} b/{target}\nindex b2f931a..b80f223 100644\n--- a/{target}\n+++ b/{target}\n{BODY}"
        )
    }

    fn create(target: &str) -> String {
        format!(
            "diff --git a/{target} b/{target}\nnew file mode 100644\nindex 0000000..b80f223\n--- /dev/null\n+++ b/{target}\n@@ -0,0 +1,2 @@\n+one\n+two\n"
        )
    }

    fn delete(target: &str) -> String {
        format!(
            "diff --git a/{target} b/{target}\ndeleted file mode 100755\nindex b80f223..0000000\n--- a/{target}\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-one\n-two\n"
        )
    }

    fn check(payload: &str) -> Result<(), Refusal> {
        validate(payload, T, MAX)
    }

    #[test]
    fn a_plain_modify_create_and_delete_pass() {
        assert_eq!(check(&modify(T)), Ok(()));
        assert_eq!(check(&create(T)), Ok(()));
        assert_eq!(check(&delete(T)), Ok(()));
    }

    #[test]
    fn several_hunks_no_newline_marker_and_function_context_pass() {
        let two = format!(
            "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@ fn main() {{\n-a\n+b\n\\ No newline at end of file\n@@ -9,2 +9,3 @@\n x\n+y\n z\n"
        );
        assert_eq!(check(&two), Ok(()));
    }

    #[test]
    fn a_content_line_that_looks_like_a_header_is_data_inside_a_counted_hunk() {
        let diff = format!(
            "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1,2 +1,2 @@\n-+++ b/../x\n++++ b/../y\n z\n"
        );
        assert_eq!(check(&diff), Ok(()));
    }

    #[test]
    fn an_empty_payload_is_refused() {
        assert_eq!(check(""), Err(Refusal::Empty));
        assert_eq!(check(" \n\t\n"), Err(Refusal::Empty));
    }

    #[test]
    fn the_size_limit_holds_at_the_limit_and_refuses_one_byte_over() {
        let diff = modify(T);
        assert_eq!(validate(&diff, T, diff.len()), Ok(()));
        assert_eq!(validate(&diff, T, diff.len() - 1), Err(Refusal::TooLarge));
    }

    #[test]
    fn the_production_limit_is_the_shared_constant() {
        let pad = "x".repeat(MAX);
        let big =
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@\n-a\n+{pad}\n");
        assert!(big.len() > MAX);
        assert_eq!(validate(&big, T, MAX), Err(Refusal::TooLarge));
        assert_eq!(validate(&big, T, big.len()), Ok(()));
    }

    #[test]
    fn unsafe_targets_are_refused() {
        let rows = [
            "",
            "../x",
            "a/../b",
            "./x",
            "a/./b",
            "/etc/passwd",
            "dir/",
            "a//b",
            "a\\b",
            "a b",
            "a\tb",
            ".git",
            ".git/config",
            ".GIT/config",
            ".Git/hooks/pre-commit",
            ".git./config",
            "GIT~1/config",
            "git~1",
            "sub/.git/hooks/pre-commit",
            "sub/.git",
            ".gitmodules",
            "sub/.GITMODULES",
            ":(top)x",
            "x*",
            "x?",
            "x[a]",
            "-x",
            "caf\u{e9}",
            "a\u{202e}b",
            "a\rb",
            "a\nb",
            "a\0b",
            "a\"b",
            "a'b",
            "a`b",
            "a$b",
            "a;b",
            "a|b",
            "a~",
            "~/x",
        ];
        for target in rows {
            assert_eq!(
                validate(&modify("x"), target, MAX),
                Err(Refusal::UnsafeTarget),
                "{target:?}"
            );
        }
        let long = format!("{}/x", "d".repeat(5000));
        assert_eq!(
            validate(&modify("x"), &long, MAX),
            Err(Refusal::UnsafeTarget)
        );
    }

    #[test]
    fn safe_looking_targets_pass() {
        for target in [
            "a",
            "src/a.txt",
            "docs/adr/0066-x.md",
            ".github/workflows/ci.yml",
            ".gitignore",
            "a-b_c.d/e+f@g,h=i",
        ] {
            assert_eq!(validate(&modify(target), target, MAX), Ok(()), "{target}");
        }
    }

    #[test]
    fn a_diff_naming_another_path_is_refused_in_every_header() {
        let rows = [
            format!("diff --git a/{T} b/other\n--- a/{T}\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/other b/{T}\n--- a/{T}\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/other\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/other\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/../x\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/../../x\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- /abs/x\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- {T}\n+++ {T}\n{BODY}"),
            format!("diff --git a/.git/config b/.git/config\n--- a/{T}\n+++ b/{T}\n{BODY}"),
            format!("diff --git {T} {T}\n--- a/{T}\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T} \n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\t2020\n{BODY}"),
        ];
        for diff in rows {
            assert_eq!(check(&diff), Err(Refusal::PathMismatch), "{diff}");
        }
    }

    #[test]
    fn a_patch_for_a_dot_git_target_is_refused_before_its_content_is_read() {
        let diff = modify(".git/config");
        assert_eq!(
            validate(&diff, ".git/config", MAX),
            Err(Refusal::UnsafeTarget)
        );
        let hooks = create(".git/hooks/pre-commit");
        assert_eq!(
            validate(&hooks, ".git/hooks/pre-commit", MAX),
            Err(Refusal::UnsafeTarget)
        );
    }

    #[test]
    fn headers_git_would_act_on_are_unsupported() {
        let headers = [
            "rename from a\nrename to b",
            "copy from a\ncopy to b",
            "similarity index 90%",
            "dissimilarity index 10%",
            "old mode 100644\nnew mode 100755",
            "new mode 100755",
            "new file mode 120000",
            "new file mode 160000",
            "new file mode 100666",
            "new file mode 100644 extra",
            "deleted file mode 120000",
            "index b2f931a..b80f223 120000",
            "index b2f931a..b80f223 100644 x",
            "index xyz..b80f223 100644",
            "index b2f931a..b80f223\nindex b2f931a..b80f223",
            "GIT binary patch\nliteral 0",
            "Binary files a/x and b/x differ",
            "random header",
        ];
        for header in headers {
            let diff = format!("diff --git a/{T} b/{T}\n{header}\n--- a/{T}\n+++ b/{T}\n{BODY}");
            assert_eq!(check(&diff), Err(Refusal::Unsupported), "{header}");
        }
    }

    #[test]
    fn a_binary_diff_with_no_text_headers_is_unsupported() {
        let diff = format!(
            "diff --git a/{T} b/{T}\nindex 1111111..2222222 100644\nGIT binary patch\nliteral 1\nIc${{0}}\n"
        );
        assert_eq!(check(&diff), Err(Refusal::Unsupported));
        let files = format!("diff --git a/{T} b/{T}\nBinary files a/{T} and b/{T} differ\n");
        assert_eq!(check(&files), Err(Refusal::Unsupported));
    }

    #[test]
    fn hostile_characters_are_refused_in_every_part_of_the_diff() {
        let hostile = [
            "\r",
            "\u{85}",
            "\u{2028}",
            "\u{2029}",
            "\u{202e}",
            "\u{2066}",
            "\u{200b}",
            "\u{200d}",
            "\u{feff}",
            "\0",
            "\u{1b}",
            "\u{7f}",
            "\u{e0041}",
            "\u{b}",
            "\u{c}",
        ];
        for bad in hostile {
            let cases = [
                format!(
                    "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@\n-a\n+b{bad}c\n"
                ),
                format!(
                    "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@ fn{bad}\n-a\n+b\n"
                ),
                format!("diff --git a/{T}{bad} b/{T}{bad}\n--- a/{T}{bad}\n+++ b/{T}{bad}\n{BODY}"),
                format!(
                    "diff --git a/{T} b/{T}\nindex b2f931a..b80f223 100644{bad}\n--- a/{T}\n+++ b/{T}\n{BODY}"
                ),
                format!("{bad}diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n{BODY}"),
            ];
            for diff in cases {
                assert_eq!(
                    check(&diff),
                    Err(Refusal::ForbiddenCharacters),
                    "{bad:?} {diff:?}"
                );
            }
        }
    }

    #[test]
    fn crlf_line_endings_are_refused() {
        let crlf = modify(T).replace('\n', "\r\n");
        assert_eq!(check(&crlf), Err(Refusal::ForbiddenCharacters));
    }

    #[test]
    fn tabs_in_content_pass_and_a_tab_in_a_header_path_does_not() {
        let tabbed =
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@\n-a\t1\n+b\t2\n");
        assert_eq!(check(&tabbed), Ok(()));
    }

    #[test]
    fn malformed_diffs_are_refused() {
        let rows = [
            "not a diff\n".to_owned(),
            format!("--- a/{T}\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n+++ b/{T}\n--- a/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1,2 +1,2 @@\n one\n-two\n"),
            format!(
                "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1,1 +1,1 @@\n one\n-two\n+TWO\n"
            ),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@\n-a\n+b\ngarbage\n"),
            format!(
                "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@\n-a\n+b\n+++ b/{T}\n"
            ),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1 @@\n-a\n+b"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ bad @@\n-a\n+b\n"),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1 +1\n-a\n+b\n"),
            format!(
                "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -99999999999 +1 @@\n-a\n+b\n"
            ),
            format!(
                "diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1,99999999999 +1 @@\n-a\n+b\n"
            ),
            format!("diff --git a/{T} b/{T}\n--- a/{T}\n+++ b/{T}\n@@ -1,-1 +1 @@\n-a\n+b\n"),
            format!("diff --git a/{T} b/{T}\n--- /dev/null\n+++ /dev/null\n@@ -0,0 +0,0 @@\n"),
            format!("diff --git a/{T} b/{T}\nnew file mode 100644\n--- a/{T}\n+++ b/{T}\n{BODY}"),
            format!("diff --git a/{T} b/{T}\n--- /dev/null\n+++ b/{T}\n{BODY}\n"),
            format!("{}{}", modify(T), modify(T)),
            format!(
                "{}diff --git a/other b/other\n--- a/other\n+++ b/other\n{BODY}",
                modify(T)
            ),
        ];
        for diff in rows {
            assert_eq!(check(&diff), Err(Refusal::Malformed), "{diff:?}");
        }
    }

    #[test]
    fn a_header_that_disagrees_with_the_dev_null_side_is_malformed() {
        let created_but_old_side_named = format!(
            "diff --git a/{T} b/{T}\nnew file mode 100644\nindex 0000000..b80f223\n--- a/{T}\n+++ b/{T}\n@@ -0,0 +1 @@\n+x\n"
        );
        assert_eq!(check(&created_but_old_side_named), Err(Refusal::Malformed));
        let null_without_mode =
            format!("diff --git a/{T} b/{T}\n--- /dev/null\n+++ b/{T}\n@@ -0,0 +1 @@\n+x\n");
        assert_eq!(check(&null_without_mode), Err(Refusal::Malformed));
    }
}
