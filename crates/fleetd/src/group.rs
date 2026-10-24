//! Kills a child's whole process group so no descendant outlives it.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use rustix::process::{Pid, Signal, kill_process_group};

/// Sends `SIGKILL` to a child's process group on drop unless already killed.
///
/// The child must be spawned with `process_group(0)`, so its pid is the group id.
#[derive(Debug)]
pub(crate) struct GroupGuard(Option<Pid>);

impl GroupGuard {
    pub(crate) fn new(child_id: Option<u32>) -> Self {
        Self(
            child_id
                .and_then(|id| i32::try_from(id).ok())
                .and_then(Pid::from_raw),
        )
    }

    pub(crate) fn kill(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}
