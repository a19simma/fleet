use std::hash::{BuildHasher, Hasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fleet_core::{EventId, Identity};

const UNKNOWN: &str = "unknown";
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Milliseconds since the Unix epoch on the box clock.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A fresh random event id stamped with `ts`.
///
/// Entropy comes from the std hasher seed, which the OS randomizes per process, mixed
/// with a counter so ids made in one process never repeat.
pub fn fresh_id(ts: u64) -> EventId {
    let high = RandomState::new().build_hasher().finish();
    let low = RandomState::new().build_hasher().finish();
    let entropy = (u128::from(high) << 64) | u128::from(low);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    EventId::new(ts, entropy ^ u128::from(count))
}

fn read_trimmed(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn hostname() -> String {
    read_trimmed("/proc/sys/kernel/hostname")
        .or_else(|| read_trimmed("/etc/hostname"))
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()))
        .or_else(|| {
            let out = std::process::Command::new("hostname").output().ok()?;
            let name = String::from_utf8(out.stdout).ok()?;
            let name = name.trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .unwrap_or_else(|| UNKNOWN.to_owned())
}

/// Reads the box identity. `box_name` defaults to the hostname. A missing machine id
/// reads `unknown`, and a missing boot id becomes a random id fixed for this process.
pub fn read_identity(box_name: Option<&str>) -> Identity {
    let hostname = hostname();
    Identity {
        box_name: box_name.map_or_else(|| hostname.clone(), str::to_owned),
        hostname,
        machine_id: read_trimmed("/etc/machine-id").unwrap_or_else(|| UNKNOWN.to_owned()),
        boot_id: read_trimmed("/proc/sys/kernel/random/boot_id")
            .unwrap_or_else(|| fresh_id(now_ms()).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_ids_are_unique() {
        let ids: std::collections::HashSet<_> = (0..1000).map(|_| fresh_id(5)).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn box_name_override_wins() {
        assert_eq!(read_identity(Some("alpha")).box_name, "alpha");
    }
}
