ALTER TABLE jobs
    ADD COLUMN ci_state text CHECK (ci_state IN ('pending', 'success', 'failure', 'timeout')),
    ADD COLUMN ci_checked_at timestamptz,
    ADD COLUMN ci_url text CHECK (octet_length(ci_url) BETWEEN 1 AND 2048),
    ADD CONSTRAINT jobs_ci_stamp CHECK ((ci_state IS NULL) = (ci_checked_at IS NULL)),
    ADD CONSTRAINT jobs_ci_url_needs_state CHECK (ci_url IS NULL OR ci_state IS NOT NULL);

CREATE TABLE job_ci_log (
    job_id text PRIMARY KEY REFERENCES jobs (job_id) ON DELETE CASCADE,
    log text NOT NULL CHECK (octet_length(log) BETWEEN 1 AND 16384),
    created_at timestamptz NOT NULL DEFAULT now()
);
