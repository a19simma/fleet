use std::future::{self, Future};

use super::{CiResult, Forge, ForgeError};
use crate::broker::PushTarget;

/// The Gitea family slot of ADR-0045. It is specified and not built: every operation answers
/// [`ForgeError::Unsupported`].
#[derive(Debug, Clone, Copy, Default)]
pub struct GiteaForge;

impl Forge for GiteaForge {
    fn push(
        &self,
        _target: &PushTarget,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        future::ready(Err(ForgeError::Unsupported))
    }

    fn create_pr(
        &self,
        _target: &PushTarget,
        _title: &str,
        _body: &str,
    ) -> impl Future<Output = Result<String, ForgeError>> + Send {
        future::ready(Err(ForgeError::Unsupported))
    }

    fn ci_result(
        &self,
        _target: &PushTarget,
        _pr_url: &str,
    ) -> impl Future<Output = Result<CiResult, ForgeError>> + Send {
        future::ready(Err(ForgeError::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_operation_is_unsupported() {
        let forge = GiteaForge;
        let target = PushTarget::Own("job1".to_owned());
        assert_eq!(forge.push(&target).await, Err(ForgeError::Unsupported));
        assert_eq!(
            forge.create_pr(&target, "t", "b").await,
            Err(ForgeError::Unsupported)
        );
        assert_eq!(
            forge.ci_result(&target, "https://x/o/r/pull/1").await,
            Err(ForgeError::Unsupported)
        );
    }
}
