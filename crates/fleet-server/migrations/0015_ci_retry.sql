ALTER TABLE jobs
    ADD COLUMN parent_job_id text REFERENCES jobs (job_id),
    ADD COLUMN ci_retry_attempt integer NOT NULL DEFAULT 0 CHECK (ci_retry_attempt BETWEEN 0 AND 5),
    ADD COLUMN ci_retry text CHECK (ci_retry IN ('submitted', 'exhausted', 'disabled', 'no_log', 'ineligible')),
    ADD CONSTRAINT jobs_ci_retry_parent CHECK ((ci_retry_attempt > 0) = (parent_job_id IS NOT NULL)),
    ADD CONSTRAINT jobs_ci_retry_needs_failure CHECK (ci_retry IS NULL OR ci_state = 'failure');

CREATE UNIQUE INDEX jobs_one_fix_per_parent ON jobs (parent_job_id) WHERE parent_job_id IS NOT NULL;
