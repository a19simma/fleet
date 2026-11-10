ALTER TABLE jobs DROP CONSTRAINT jobs_ci_retry_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_ci_retry_check
    CHECK (ci_retry IN ('submitted', 'exhausted', 'disabled', 'no_log', 'ineligible', 'env_unavailable'));
