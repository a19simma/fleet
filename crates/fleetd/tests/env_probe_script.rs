//! Static checks of `deploy/probe-env-setup.sh` against `deploy/fleet-env@.service`: every
//! directive of the unit has a probe or a recorded reason it has none, and every probe names a
//! directive the unit sets. Own test binary: it spawns `bash`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REQUIRED_PROBES: [&str; 10] = [
    "net-lo-only",
    "net-external-unreachable",
    "proxy-path",
    "etc-swarm-inaccessible",
    "run-fleet-hidden",
    "no-cap-net-raw",
    "runtime-max-kills-sleeper",
    "protect-proc-invisible",
    "private-tmp",
    "env-dir-unreadable-from-agent",
];

const REQUIRED_OUT_PROBE: &str = "env-out-writable-visible";

const UNPROBED: [(&str, &str); 7] = [
    (
        "ExecStart",
        "the shim entry point, replaced by the probe command",
    ),
    ("Type", "oneshot lifecycle, replaced by systemd-run --wait"),
    (
        "RemainAfterExit",
        "lifecycle read by the launcher, not a sandbox",
    ),
    ("Restart", "lifecycle, a transient run ends once"),
    (
        "TimeoutStopSec",
        "stop grace, no observable effect in a probe",
    ),
    ("KillMode", "stop behaviour, covered by the sleeper kill"),
    ("Environment", "HOME only, replaced by the shim environment"),
];

fn deploy() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy")
}

fn service_keys(text: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[Service]";
        } else if inside && let Some((key, _)) = line.split_once('=') {
            keys.insert(key.to_owned());
        }
    }
    keys
}

fn probe_list() -> Result<BTreeMap<String, BTreeSet<String>>, Box<dyn std::error::Error>> {
    let out = Command::new("bash")
        .arg(deploy().join("probe-env-setup.sh"))
        .arg("--list")
        .output()?;
    assert!(
        out.status.success(),
        "--list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut map = BTreeMap::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        let (name, rest) = line.split_once(' ').ok_or("list line has no directives")?;
        let set = rest
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        assert!(
            map.insert(name.to_owned(), set).is_none(),
            "duplicate probe {name}"
        );
    }
    Ok(map)
}

#[test]
fn parser_reads_the_unit_keys() -> TestResult {
    let keys = service_keys(&fs::read_to_string(deploy().join("fleet-env@.service"))?);
    assert!(keys.contains("PrivateNetwork"));
    assert!(keys.contains("InaccessiblePaths"));
    assert!(!keys.contains("Description"));
    Ok(())
}

#[test]
fn every_unit_directive_has_a_probe_or_a_reason() -> TestResult {
    let keys = service_keys(&fs::read_to_string(deploy().join("fleet-env@.service"))?);
    let list = probe_list()?;
    let probed: BTreeSet<&String> = list.values().flatten().collect();
    let exempt: BTreeSet<&str> = UNPROBED.iter().map(|(key, _)| *key).collect();
    for key in &keys {
        assert!(
            probed.contains(key) || exempt.contains(key.as_str()),
            "directive {key} has no probe"
        );
        assert!(
            !(probed.contains(key) && exempt.contains(key.as_str())),
            "directive {key} is both probed and exempt"
        );
    }
    for key in exempt {
        assert!(
            keys.contains(key),
            "exempt directive {key} is not in the unit"
        );
    }
    Ok(())
}

#[test]
fn every_probe_names_only_unit_directives() -> TestResult {
    let keys = service_keys(&fs::read_to_string(deploy().join("fleet-env@.service"))?);
    for (name, set) in probe_list()? {
        assert!(!set.is_empty(), "probe {name} names no directive");
        for key in set {
            assert!(
                keys.contains(&key),
                "probe {name} names {key}, not in the unit"
            );
        }
    }
    Ok(())
}

#[test]
fn the_required_probes_exist() -> TestResult {
    let list = probe_list()?;
    for name in REQUIRED_PROBES.iter().chain([&REQUIRED_OUT_PROBE]) {
        assert!(list.contains_key(*name), "missing probe {name}");
    }
    Ok(())
}

#[test]
fn script_has_no_comments_below_the_header() -> TestResult {
    let text = fs::read_to_string(deploy().join("probe-env-setup.sh"))?;
    let mut lines = text.lines().skip(1).peekable();
    while lines.next_if(|l| l.starts_with('#')).is_some() {}
    for line in lines {
        let t = line.trim_start();
        assert!(!t.starts_with('#'), "comment below the header: {line}");
        assert!(!line.contains(" # "), "inline comment: {line}");
    }
    Ok(())
}

#[test]
fn list_touches_no_host_state() -> TestResult {
    let out = Command::new("bash")
        .arg(deploy().join("probe-env-setup.sh"))
        .arg("--list")
        .env("PATH", "/nonexistent")
        .output();
    let out = out.or_else(|_| {
        Command::new("/bin/bash")
            .arg(deploy().join("probe-env-setup.sh"))
            .arg("--list")
            .env("PATH", "/nonexistent")
            .output()
    })?;
    assert!(out.status.success(), "--list needs a tool outside bash");
    Ok(())
}

/// The `[Service]` values of `key` in `text`, in file order.
fn service_values(text: &str, key: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[Service]";
        } else if inside
            && let Some((name, value)) = line.split_once('=')
            && name == key
        {
            values.push(value.to_owned());
        }
    }
    values
}

#[test]
fn agent_unit_hides_the_setup_run_root() -> TestResult {
    let text = fs::read_to_string(deploy().join("fleet-agent@.service"))?;
    let hidden = service_values(&text, "TemporaryFileSystem");
    assert!(
        hidden.iter().any(|v| v == "/run/fleet-env:ro"),
        "fleet-agent@.service must set TemporaryFileSystem=/run/fleet-env:ro, has {hidden:?}"
    );
    Ok(())
}
