//! Outer deadline for tests that spawn processes, so a hang fails fast.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::future::Future;
use std::time::Duration;

/// Longest a process test may run before it fails.
pub(crate) const TEST_BOUND: Duration = Duration::from_secs(60);

/// Runs `test` and fails it when it outlives [`TEST_BOUND`].
///
/// # Errors
///
/// Returns the test's own error, or the elapsed deadline.
pub(crate) async fn bounded(
    test: impl Future<Output = Result<(), Box<dyn std::error::Error>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(TEST_BOUND, test).await?
}
