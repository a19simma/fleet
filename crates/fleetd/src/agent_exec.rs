//! The job spec handoff between the launcher and `fleetd agent-exec`.
//!
//! The launcher writes `spec.json` into the job's run directory. The unit runs
//! `fleetd agent-exec <id>` as the job uid, which reads that file, changes into the working
//! directory and replaces itself with the agent. The environment comes from the unit's
//! `EnvironmentFile`, so the spec file never holds it.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::runner::AgentSpec;
use crate::workspace::validate_job_id;

/// File name of the spec inside a job's run directory.
pub const SPEC_FILE: &str = "spec.json";

const MAX_SPEC_BYTES: u64 = 1024 * 1024;
const SPEC_MODE: u32 = 0o600;
const SPEC_SHARED_MODE: u32 = 0o640;

#[derive(Debug, Serialize, Deserialize)]
struct SpecFile {
    id: String,
    argv: Vec<String>,
    cwd: PathBuf,
}

/// Why `agent-exec` could not start the agent. No variant carries an argument or an
/// environment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentExecError {
    /// The job id is not `[A-Za-z0-9_]{1,64}`.
    InvalidId,
    /// The spec file is missing or unreadable.
    MissingSpec,
    /// The spec file is too large or is not a valid spec.
    MalformedSpec,
    /// The spec names a different job than the argument.
    IdMismatch,
    /// The spec holds no program.
    EmptyArgv,
    /// The program could not be executed in the working directory.
    Exec(io::ErrorKind),
}

impl fmt::Display for AgentExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId => f.write_str("job id is not valid"),
            Self::MissingSpec => f.write_str("job spec is missing or unreadable"),
            Self::MalformedSpec => f.write_str("job spec is malformed or too large"),
            Self::IdMismatch => f.write_str("job spec belongs to a different job"),
            Self::EmptyArgv => f.write_str("job spec has an empty command line"),
            Self::Exec(kind) => write!(f, "agent could not be executed: {kind}"),
        }
    }
}

impl std::error::Error for AgentExecError {}

/// Writes the spec for job `id` to `path` with mode 0600, or 0640 and group `gid` when it is
/// set. Never writes the environment.
///
/// # Errors
///
/// Fails when `path` exists, an argument is not UTF-8, or the file cannot be written. A
/// partial file is removed.
pub fn write_spec(path: &Path, id: &str, spec: &AgentSpec, gid: Option<u32>) -> io::Result<()> {
    let argv = spec
        .argv
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let body = serde_json::to_vec(&SpecFile {
        id: id.to_owned(),
        argv,
        cwd: spec.cwd.clone(),
    })
    .map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SPEC_MODE)
        .open(path)?;
    let written = file.write_all(&body).and_then(|()| {
        gid.map_or(Ok(()), |gid| {
            std::os::unix::fs::chown(path, None, Some(gid))?;
            fs::set_permissions(path, fs::Permissions::from_mode(SPEC_SHARED_MODE))
        })
    });
    if written.is_err() {
        let _ = fs::remove_file(path);
    }
    written
}

fn read_spec(path: &Path) -> Result<SpecFile, AgentExecError> {
    let mut body = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_SPEC_BYTES + 1).read_to_end(&mut body))
        .map_err(|_| AgentExecError::MissingSpec)?;
    if u64::try_from(body.len()).map_or(true, |len| len > MAX_SPEC_BYTES) {
        return Err(AgentExecError::MalformedSpec);
    }
    serde_json::from_slice(&body).map_err(|_| AgentExecError::MalformedSpec)
}

/// Replaces this process with the agent for job `id` described by `run_dir/<id>/spec.json`,
/// run in the spec's working directory with the inherited environment.
///
/// Only returns on failure, with the reason.
pub fn exec_job(run_dir: &Path, id: &str) -> AgentExecError {
    if validate_job_id(id).is_err() {
        return AgentExecError::InvalidId;
    }
    let spec = match read_spec(&run_dir.join(id).join(SPEC_FILE)) {
        Ok(spec) => spec,
        Err(err) => return err,
    };
    if spec.id != id {
        return AgentExecError::IdMismatch;
    }
    let Some((program, args)) = spec.argv.split_first() else {
        return AgentExecError::EmptyArgv;
    };
    let err = Command::new(program)
        .args(args)
        .current_dir(&spec.cwd)
        .exec();
    AgentExecError::Exec(err.kind())
}
