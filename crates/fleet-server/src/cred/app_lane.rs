//! The admit-and-mint tail that a release and a probe share (ADR-0058).

use std::future::Future;
use std::sync::Arc;

use super::{
    AppLane, Armed, AttemptGuard, COUNT_ATTEMPTS, COUNT_USER_ATTEMPTS, CredentialStore,
    DENIED_DEDUPE_SECS, DENIED_RECENTLY, InstallationToken, MAX_APP_MINTS_PER_JOB,
    MAX_APP_MINTS_PER_USER_PER_MINUTE, MINT_RATE_WINDOW_SECS, MintRecord, REASON_CAP,
    REASON_USER_RATE, RevokeGuard, StoreError, refusal_reason,
};

/// Which gate an `attempt` row is counted against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MintScope {
    /// A release or refresh row; it counts toward the per-Job cap and the per-User rate.
    Job,
    /// A `VerifyCredential` probe row; it counts toward the per-User rate only.
    Probe,
}

impl MintScope {
    pub(super) const fn wire(self) -> &'static str {
        match self {
            Self::Job => "job",
            Self::Probe => "probe",
        }
    }

    pub(super) const fn counts_toward_job_cap(self) -> bool {
        matches!(self, Self::Job)
    }
}

/// The mint limits of a [`CredentialStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintPolicy {
    /// Most `attempt` rows one Job may hold, [`MAX_APP_MINTS_PER_JOB`] by default.
    pub mint_cap: u32,
    /// Most `attempt` rows one User may start per minute, [`MAX_APP_MINTS_PER_USER_PER_MINUTE`]
    /// by default.
    pub user_rate: u32,
    /// The `denied` row dedupe window in seconds, [`DENIED_DEDUPE_SECS`] by default. Zero writes
    /// every denial.
    pub denied_dedupe_secs: i64,
}

impl Default for MintPolicy {
    fn default() -> Self {
        Self {
            mint_cap: MAX_APP_MINTS_PER_JOB,
            user_rate: MAX_APP_MINTS_PER_USER_PER_MINUTE,
            denied_dedupe_secs: DENIED_DEDUPE_SECS,
        }
    }
}

/// A token minted under a write-ahead `attempt` row, held by its revoke guard.
pub(super) struct MintedToken {
    pub(super) guard: RevokeGuard,
    pub(super) attempt_id: String,
    pub(super) expires_at: u64,
}

impl CredentialStore {
    /// Checks the allowlists, admits the attempt under the caps, runs `minting` and arms the
    /// revoke guard over the token.
    ///
    /// The `attempt` row commits before `minting` is polled, and a dropped future closes it as
    /// `failed`. A failed mint writes its outcome row before the error returns.
    #[expect(clippy::too_many_arguments, reason = "one tail for both scopes")]
    pub(super) async fn admit_and_mint(
        &self,
        tx: sqlx::Transaction<'_, sqlx::Postgres>,
        record: &MintRecord,
        lane: &Arc<AppLane>,
        user_id: i64,
        installation: u64,
        repo: &str,
        minting: impl Future<Output = Result<InstallationToken, StoreError>>,
    ) -> Result<MintedToken, StoreError> {
        if let Err(err) = lane
            .allow_installation(installation)
            .and_then(|()| lane.allow_repo(repo))
        {
            return Err(self.refuse(tx, record, err).await);
        }
        let attempt_id = self.admit(tx, record, user_id).await?;
        let mut open = AttemptGuard::open(&self.pool, record, &attempt_id);
        let minted = minting.await;
        open.close();
        let token = match minted {
            Ok(token) => token,
            Err(err) => {
                let (outcome, reason) = err.audit();
                record
                    .outcome_pooled(&self.pool, &attempt_id, outcome, Some(reason))
                    .await;
                return Err(err);
            }
        };
        let expires_at = token.expires_at();
        let guard = RevokeGuard {
            armed: Some(Armed {
                lane: Arc::clone(lane),
                pool: self.pool.clone(),
                record: record.clone(),
                attempt_id: attempt_id.clone(),
                token,
            }),
        };
        Ok(MintedToken {
            guard,
            attempt_id,
            expires_at,
        })
    }

    async fn refuse(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        record: &MintRecord,
        err: StoreError,
    ) -> StoreError {
        let written = async {
            self.deny(&mut tx, record, refusal_reason(&err)).await?;
            tx.commit().await
        }
        .await;
        match written {
            Ok(()) => err,
            Err(db) => StoreError::Db(db),
        }
    }

    async fn admit(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        record: &MintRecord,
        user_id: i64,
    ) -> Result<String, StoreError> {
        let attempts: i64 = if record.scope.counts_toward_job_cap() {
            sqlx::query_scalar(COUNT_ATTEMPTS)
                .bind(&record.job_id)
                .fetch_one(&mut *tx)
                .await?
        } else {
            0
        };
        if attempts >= i64::from(self.policy.mint_cap) {
            self.deny(&mut tx, record, REASON_CAP).await?;
            tx.commit().await?;
            return Err(StoreError::MintCapReached);
        }
        let recent: i64 = sqlx::query_scalar(COUNT_USER_ATTEMPTS)
            .bind(user_id)
            .bind(MINT_RATE_WINDOW_SECS)
            .fetch_one(&mut *tx)
            .await?;
        if recent >= i64::from(self.policy.user_rate) {
            self.deny(&mut tx, record, REASON_USER_RATE).await?;
            tx.commit().await?;
            return Err(StoreError::MintRateLimited);
        }
        let attempt_id = record.root(&mut tx, "attempt", None).await?;
        tx.commit().await?;
        Ok(attempt_id)
    }

    async fn deny(
        &self,
        tx: &mut sqlx::PgConnection,
        record: &MintRecord,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        let recent: bool = sqlx::query_scalar(DENIED_RECENTLY)
            .bind(&record.job_id)
            .bind(reason)
            .bind(self.policy.denied_dedupe_secs)
            .bind(record.scope.wire())
            .bind(record.credential_id)
            .fetch_one(&mut *tx)
            .await?;
        if !recent {
            record.root(tx, "denied", Some(reason)).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_scope_has_its_wire_name_and_cap_membership() {
        assert_eq!(MintScope::Job.wire(), "job");
        assert!(MintScope::Job.counts_toward_job_cap());
        assert_eq!(MintScope::Probe.wire(), "probe");
        assert!(!MintScope::Probe.counts_toward_job_cap());
    }

    #[test]
    fn the_default_policy_is_the_shipped_limits() {
        let policy = MintPolicy::default();
        assert_eq!(policy.mint_cap, MAX_APP_MINTS_PER_JOB);
        assert_eq!(policy.user_rate, MAX_APP_MINTS_PER_USER_PER_MINUTE);
        assert_eq!(policy.denied_dedupe_secs, DENIED_DEDUPE_SECS);
    }
}
