//! Files and modes that let a launcher hand a job to another uid.
//!
//! The jobs directory is meant to be `fleetd:fleet-work` mode 3770. With a job group set,
//! the per-job directories are group-writable for that group, and `.finish-<id>` stays 0700.
//! `.git-home` is made by `create_dir_all` and follows the process umask. Nothing here talks to
//! systemd.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use rustix::fs::OFlags;

use crate::runner::AgentSpec;

const ENV_FILE_MODE: u32 = 0o600;
const FIFO_MODE: u32 = 0o660;
const SHARED_DIR_MODE: u32 = 0o2770;

/// Why an environment could not be rendered as an `EnvironmentFile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvFileError {
    /// A name outside `[A-Za-z_][A-Za-z0-9_]*`.
    InvalidKey,
    /// A value that is not UTF-8 or holds a control byte other than LF, CR or TAB.
    InvalidValue,
}

impl fmt::Display for EnvFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "environment name is not a valid identifier",
            Self::InvalidValue => "environment value is not UTF-8 or holds a NUL byte",
        })
    }
}

impl Error for EnvFileError {}

/// Why telemetry capture may not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TelemetryRefused {
    /// `host_netns_attested` is not `true` in the config.
    HostNetnsUnattested,
}

impl fmt::Display for TelemetryRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostNetnsUnattested => {
                "telemetry needs host_netns_attested = true in the fleetd config"
            }
        })
    }
}

impl Error for TelemetryRefused {}

/// Longest environment name a Profile or Job may supply.
pub const MAX_ENV_NAME: usize = 128;
const TELEMETRY_PREFIX: &str = "OTEL_";
const TELEMETRY_SWITCH: &str = "CLAUDE_CODE_ENABLE_TELEMETRY";

/// Why [`build_job_env`] refused a supplied name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuppliedEnvError {
    /// Not `[A-Za-z_][A-Za-z0-9_]*`, empty, over [`MAX_ENV_NAME`] or not UTF-8.
    InvalidName,
    /// An `OTEL_` name in any case, or `CLAUDE_CODE_ENABLE_TELEMETRY`.
    Reserved,
    /// A name fleetd already set.
    Shadows,
}

impl fmt::Display for SuppliedEnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "supplied environment name is not allowed",
            Self::Reserved => "environment name is reserved for fleetd telemetry",
            Self::Shadows => "supplied environment name shadows a fleetd value",
        })
    }
}

impl Error for SuppliedEnvError {}

/// True for an `OTEL_` name in any ASCII case and for `CLAUDE_CODE_ENABLE_TELEMETRY`.
#[must_use]
pub fn reserved_telemetry_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with(TELEMETRY_PREFIX) || upper == TELEMETRY_SWITCH
}

/// Merges names a Profile or Job supplies into the environment fleetd built.
///
/// The fleetd-set values, telemetry ones included, pass through unchanged. A supplied name is
/// checked before anything merges: a reserved telemetry name is [`SuppliedEnvError::Reserved`]
/// and any other name outside the identifier grammar is [`SuppliedEnvError::InvalidName`], so
/// a padded, NUL-bearing or lookalike spelling of a reserved name fails closed. A supplied name
/// equal to a fleetd-set one is [`SuppliedEnvError::Shadows`].
///
/// # Errors
///
/// Returns the first refusal; nothing is merged then.
pub fn build_job_env(
    fleet: BTreeMap<OsString, OsString>,
    supplied: &[(OsString, OsString)],
) -> Result<BTreeMap<OsString, OsString>, SuppliedEnvError> {
    let mut env = fleet;
    for (name, value) in supplied {
        let name = name.to_str().ok_or(SuppliedEnvError::InvalidName)?;
        if reserved_telemetry_name(name) {
            return Err(SuppliedEnvError::Reserved);
        }
        if name.len() > MAX_ENV_NAME || !valid_key(name) {
            return Err(SuppliedEnvError::InvalidName);
        }
        if env.contains_key(OsStr::new(name)) {
            return Err(SuppliedEnvError::Shadows);
        }
        env.insert(OsString::from(name), value.clone());
    }
    Ok(env)
}

fn valid_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn quote(value: &str) -> Result<String, EnvFileError> {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' | '\r' | '\t' => out.push(c),
            c if c.is_ascii_control() => return Err(EnvFileError::InvalidValue),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Renders `spec.env` as a systemd `EnvironmentFile` body, one `KEY="value"` line per name in
/// sorted order.
///
/// Each value is double-quoted. Only `\` and `"` are escaped, as `\\` and `\"`. Newline,
/// carriage return and tab stay raw, which systemd allows inside a quoted value. `$` and `%`
/// stay literal. Any other control byte is an error.
///
/// # Errors
///
/// Returns [`EnvFileError`] for an invalid name or value. Nothing is dropped silently.
pub fn render_env_file(spec: &AgentSpec) -> Result<String, EnvFileError> {
    let mut body = String::new();
    for (key, value) in &spec.env {
        let key = key
            .to_str()
            .filter(|key| valid_key(key))
            .ok_or(EnvFileError::InvalidKey)?;
        let value = value.to_str().ok_or(EnvFileError::InvalidValue)?;
        body.push_str(key);
        body.push('=');
        body.push_str(&quote(value)?);
        body.push('\n');
    }
    Ok(body)
}

/// Writes `body` to a new file at `path` with mode 0600 set at open.
///
/// # Errors
///
/// Fails with `AlreadyExists` when `path` exists, so an old file is never reused.
pub fn write_env_file(path: &Path, body: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ENV_FILE_MODE)
        .open(path)?;
    let written = file.write_all(body.as_bytes());
    if written.is_err() {
        let _ = fs::remove_file(path);
    }
    written
}

/// Creates a named pipe at `path` with mode 0660 and, when `gid` is set, that group.
///
/// The pipe starts at 0600, so it is never wider than the final mode. `std` has no `mkfifo`
/// and the crate forbids `unsafe`, so the pipe comes from the `mkfifo` program.
///
/// # Errors
///
/// Fails when `path` exists or the group cannot be set. A pipe left by a failed step is
/// removed first.
pub fn create_stdout_fifo(path: &Path, gid: Option<u32>) -> io::Result<()> {
    let made = Command::new("mkfifo")
        .args(["-m", "600", "--"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !made.success() {
        return Err(if path.symlink_metadata().is_ok() {
            io::Error::from(io::ErrorKind::AlreadyExists)
        } else {
            io::Error::other("mkfifo failed")
        });
    }
    let tuned = gid
        .map_or(Ok(()), |gid| {
            std::os::unix::fs::chown(path, None, Some(gid))
        })
        .and_then(|()| fs::set_permissions(path, fs::Permissions::from_mode(FIFO_MODE)));
    if tuned.is_err() {
        let _ = fs::remove_file(path);
    }
    tuned
}

/// Opens the pipe at `path` for reading without waiting for a writer.
///
/// A read returns zero while no writer has the pipe open, `WouldBlock` while a writer is open
/// and silent, and zero again once every writer has closed.
///
/// # Errors
///
/// Fails when the pipe cannot be opened.
pub fn open_fifo_reader(path: &Path) -> io::Result<File> {
    let flags = i32::try_from(OFlags::NONBLOCK.bits())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

/// Gives `path` to `gid` with mode 2770.
///
/// # Errors
///
/// Returns the chown or chmod error.
pub fn share_dir(path: &Path, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, None, Some(gid))?;
    fs::set_permissions(path, fs::Permissions::from_mode(SHARED_DIR_MODE))
}

/// Gives `path` to `gid` with mode 2750: the group reads and searches, never writes.
///
/// # Errors
///
/// Returns the chown or chmod error.
pub fn share_dir_read_only(path: &Path, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, None, Some(gid))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o2750))
}

/// Gives `path` to `gid` with mode 2710: the group searches but cannot list or write.
///
/// # Errors
///
/// Returns the chown or chmod error.
pub fn share_dir_search_only(path: &Path, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, None, Some(gid))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o2710))
}

/// Gives the tree at `path` to `gid` read-only: directories become 2750 and a file keeps its
/// owner bits, gains the group read and execute bits the owner has, and loses every other
/// bit. Symlinks are skipped.
///
/// # Errors
///
/// Returns the first I/O error.
pub fn share_tree_read_only(path: &Path, gid: u32) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        share_dir_read_only(path, gid)?;
        for entry in fs::read_dir(path)? {
            share_tree_read_only(&entry?.path(), gid)?;
        }
    } else if meta.is_file() {
        std::os::unix::fs::chown(path, None, Some(gid))?;
        let owner = meta.permissions().mode() & 0o700;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(owner | ((owner >> 3) & 0o050)),
        )?;
    }
    Ok(())
}

/// Gives the tree at `path` to `gid`: directories become 2770 and a file gets its owner bits
/// copied to the group. Symlinks are skipped.
///
/// # Errors
///
/// Returns the first I/O error.
pub fn share_tree(path: &Path, gid: u32) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        share_dir(path, gid)?;
        for entry in fs::read_dir(path)? {
            share_tree(&entry?.path(), gid)?;
        }
    } else if meta.is_file() {
        std::os::unix::fs::chown(path, None, Some(gid))?;
        let mode = meta.permissions().mode();
        let owner = (mode >> 6) & 0o7;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode((mode & 0o7707) | (owner << 3)),
        )?;
    }
    Ok(())
}

/// The gid for `spec`, a number or a name looked up in `groups` in `/etc/group` format.
#[must_use]
pub fn group_id(spec: &str, groups: &str) -> Option<u32> {
    spec.parse().ok().or_else(|| {
        groups.lines().find_map(|line| {
            let mut fields = line.split(':');
            (fields.next() == Some(spec))
                .then(|| fields.nth(1)?.parse().ok())
                .flatten()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        EnvFileError, SuppliedEnvError, build_job_env, create_stdout_fifo, open_fifo_reader,
        render_env_file, share_tree, write_env_file,
    };
    use crate::runner::AgentSpec;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn spec(pairs: &[(&str, &str)]) -> AgentSpec {
        AgentSpec {
            env: pairs
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect(),
            ..AgentSpec::default()
        }
    }

    fn fleet_set() -> std::collections::BTreeMap<OsString, OsString> {
        [
            (
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "http://127.0.0.1:4318/v1/logs",
            ),
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "1"),
            ("HOME", "/h"),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
    }

    fn supplied(names: &[&str]) -> Vec<(OsString, OsString)> {
        names
            .iter()
            .map(|name| (OsString::from(name), OsString::from("x")))
            .collect()
    }

    #[test]
    fn the_headers_value_quotes_each_hostile_byte_exactly() -> TestResult {
        let table = [
            (",", ","),
            ("=", "="),
            ("\"", "\\\""),
            ("\\", "\\\\"),
            ("$", "$"),
            ("'", "'"),
            ("%", "%"),
            ("a b", "a b"),
        ];
        for (raw, quoted) in table {
            let value = format!("Authorization=Bearer x{raw}y");
            let body = render_env_file(&spec(&[("OTEL_EXPORTER_OTLP_HEADERS", value.as_str())]))?;
            assert_eq!(
                body,
                format!("OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer x{quoted}y\"\n"),
                "{raw:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn fleet_set_telemetry_values_pass_through_unchanged() -> TestResult {
        let built = build_job_env(fleet_set(), &supplied(&["FOO", "ANTHROPIC_BASE_URL"]))?;
        assert_eq!(
            built.get(&OsString::from("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")),
            Some(&OsString::from("http://127.0.0.1:4318/v1/logs"))
        );
        assert_eq!(
            built.get(&OsString::from("CLAUDE_CODE_ENABLE_TELEMETRY")),
            Some(&OsString::from("1"))
        );
        assert_eq!(
            built.get(&OsString::from("FOO")),
            Some(&OsString::from("x"))
        );
        Ok(())
    }

    #[test]
    fn supplied_telemetry_names_are_refused_with_a_named_error() {
        let reserved = [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "otel_exporter_otlp_endpoint",
            "Otel_Sdk_Disabled",
            "OTEL_",
            "CLAUDE_CODE_ENABLE_TELEMETRY",
            "claude_code_enable_telemetry",
        ];
        for name in reserved {
            assert_eq!(
                build_job_env(fleet_set(), &supplied(&[name])),
                Err(SuppliedEnvError::Reserved),
                "{name}"
            );
        }
        assert_eq!(
            SuppliedEnvError::Reserved.to_string(),
            "environment name is reserved for fleetd telemetry"
        );
    }

    #[test]
    fn hostile_supplied_names_fail_closed() {
        let long = "A".repeat(super::MAX_ENV_NAME + 1);
        let hostile = [
            " OTEL_X",
            "OTEL_X ",
            "\tOTEL_X",
            "\u{0}OTEL_X",
            "OTEL_X\u{0}",
            "OTEL_X\r",
            "OTEL_X\n",
            "OTEL_X=1",
            "\u{ff2f}TEL_X",
            "OTEL\u{ff3f}X",
            "\u{2028}OTEL_X",
            "\u{85}OTEL_X",
            "",
            "1X",
            "A B",
            "caf\u{e9}",
            long.as_str(),
        ];
        for name in hostile {
            assert!(
                matches!(
                    build_job_env(fleet_set(), &supplied(&[name])),
                    Err(SuppliedEnvError::InvalidName | SuppliedEnvError::Reserved)
                ),
                "{name:?}"
            );
        }
        assert_eq!(
            build_job_env(fleet_set(), &supplied(&[" OTEL_X"])),
            Err(SuppliedEnvError::InvalidName)
        );
        let raw = vec![(OsString::from_vec(vec![0xff]), OsString::from("x"))];
        assert_eq!(
            build_job_env(fleet_set(), &raw),
            Err(SuppliedEnvError::InvalidName)
        );
    }

    #[test]
    fn a_supplied_name_cannot_shadow_a_fleet_set_one() {
        assert_eq!(
            build_job_env(fleet_set(), &supplied(&["HOME"])),
            Err(SuppliedEnvError::Shadows)
        );
    }

    #[test]
    fn hostile_values_stay_one_quoted_line_each() {
        let cases = [
            ("a\nB=1", "A=\"a\nB=1\"\n"),
            ("q\"x", "A=\"q\\\"x\"\n"),
            ("b\\", "A=\"b\\\\\"\n"),
            ("$HOME ${X} $(id)", "A=\"$HOME ${X} $(id)\"\n"),
            ("%h %n", "A=\"%h %n\"\n"),
            ("", "A=\"\"\n"),
            ("h\u{e9}llo \u{1f980}", "A=\"h\u{e9}llo \u{1f980}\"\n"),
            ("t\tr\rb", "A=\"t\tr\rb\"\n"),
            ("a\\nb", "A=\"a\\\\nb\"\n"),
        ];
        for (value, expected) in cases {
            assert_eq!(
                render_env_file(&spec(&[("A", value)])).as_deref(),
                Ok(expected),
                "{value:?}"
            );
        }
    }

    #[test]
    fn control_bytes_other_than_lf_cr_tab_are_rejected() {
        for value in ["a\u{7}b", "a\u{1b}b", "a\u{7f}b", "a\u{1}"] {
            assert_eq!(
                render_env_file(&spec(&[("A", value)])),
                Err(EnvFileError::InvalidValue),
                "{value:?}"
            );
        }
    }

    #[test]
    fn names_render_sorted_and_valid_ones_pass() {
        let body = render_env_file(&spec(&[("_z9", "1"), ("A_b", "2"), ("B", "3")]));
        assert_eq!(body.as_deref(), Ok("A_b=\"2\"\nB=\"3\"\n_z9=\"1\"\n"));
        assert_eq!(render_env_file(&spec(&[])).as_deref(), Ok(""));
    }

    #[test]
    fn an_invalid_key_or_value_is_an_error() {
        for key in ["", "1A", "A-B", "A B", "A=B", "A\nB", "\u{e9}"] {
            assert_eq!(
                render_env_file(&spec(&[("OK", "1"), (key, "v")])),
                Err(EnvFileError::InvalidKey),
                "{key:?}"
            );
        }
        assert_eq!(
            render_env_file(&spec(&[("A", "a\0b")])),
            Err(EnvFileError::InvalidValue)
        );
        let mut raw = spec(&[]);
        raw.env
            .insert("A".into(), OsString::from_vec(vec![0xff, 0xfe]));
        assert_eq!(render_env_file(&raw), Err(EnvFileError::InvalidValue));
        let mut raw = spec(&[]);
        raw.env.insert(OsString::from_vec(vec![0xff]), "v".into());
        assert_eq!(render_env_file(&raw), Err(EnvFileError::InvalidKey));
    }

    #[test]
    fn the_env_file_is_0600_and_never_overwritten() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("job.env");
        write_env_file(&path, "A=\"1\"\n")?;
        assert_eq!(std::fs::metadata(&path)?.mode() & 0o7777, 0o600);
        let err = write_env_file(&path, "B=\"2\"\n").err().map(|e| e.kind());
        assert_eq!(err, Some(std::io::ErrorKind::AlreadyExists));
        assert_eq!(std::fs::read_to_string(&path)?, "A=\"1\"\n");
        Ok(())
    }

    #[test]
    fn the_fifo_is_0660_carries_the_group_and_streams_to_a_reader() -> TestResult {
        let dir = tempfile::tempdir()?;
        let gid = std::fs::metadata(dir.path())?.gid();
        let path = dir.path().join("out");
        create_stdout_fifo(&path, Some(gid))?;
        let meta = std::fs::metadata(&path)?;
        assert!(meta.file_type().is_fifo());
        assert_eq!((meta.mode() & 0o7777, meta.gid()), (0o660, gid));
        let mut reader = open_fifo_reader(&path)?;
        let mut buf = [0_u8; 8];
        assert_eq!(reader.read(&mut buf)?, 0);
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path)?;
        let idle = reader.read(&mut buf).err().map(|e| e.kind());
        assert_eq!(idle, Some(std::io::ErrorKind::WouldBlock));
        writer.write_all(b"hi\n")?;
        drop(writer);
        assert_eq!(drain(reader)?, b"hi\n");
        let again = create_stdout_fifo(&path, None).err().map(|e| e.kind());
        assert_eq!(again, Some(std::io::ErrorKind::AlreadyExists));
        let plain = dir.path().join("plain");
        create_stdout_fifo(&plain, None)?;
        assert_eq!(std::fs::metadata(&plain)?.mode() & 0o7777, 0o660);
        Ok(())
    }

    fn drain(mut reader: std::fs::File) -> std::io::Result<Vec<u8>> {
        rustix::fs::fcntl_setfl(&reader, rustix::fs::OFlags::empty())?;
        let mut got = Vec::new();
        reader.read_to_end(&mut got)?;
        Ok(got)
    }

    #[test]
    fn a_drain_waits_for_a_writer_copy_held_by_a_forked_child() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out");
        create_stdout_fifo(&path, None)?;
        let reader = open_fifo_reader(&path)?;
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path)?;
        let child_copy = writer.try_clone()?;
        writer.write_all(b"hi\n")?;
        drop(writer);
        let child = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(child_copy);
        });
        assert_eq!(drain(reader)?, b"hi\n");
        child.join().map_err(|_| "child thread panicked")?;
        Ok(())
    }

    #[test]
    fn a_failed_group_change_removes_the_fifo() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out");
        let own = std::fs::metadata(dir.path())?.gid();
        let other = u32::from(own == 0);
        if create_stdout_fifo(&path, Some(other)).is_err() {
            assert!(!path.exists());
        }
        Ok(())
    }

    #[test]
    fn share_tree_makes_dirs_2770_and_copies_owner_bits_but_skips_symlinks() -> TestResult {
        let dir = tempfile::tempdir()?;
        let gid = std::fs::metadata(dir.path())?.gid();
        let root = dir.path().join("job");
        std::fs::create_dir_all(root.join("sub"))?;
        std::fs::write(root.join("sub/f"), "x")?;
        std::fs::write(root.join("run.sh"), "x")?;
        std::fs::set_permissions(root.join("sub/f"), std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(root.join("run.sh"), std::fs::Permissions::from_mode(0o700))?;
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "x")?;
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::symlink(&outside, root.join("link"))?;
        share_tree(&root, gid)?;
        let mode = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.mode() & 0o7777);
        assert_eq!(mode(&root)?, 0o2770);
        assert_eq!(mode(&root.join("sub"))?, 0o2770);
        assert_eq!(mode(&root.join("sub/f"))?, 0o660);
        assert_eq!(mode(&root.join("run.sh"))?, 0o770);
        assert_eq!(mode(&outside)?, 0o600);
        Ok(())
    }
}
