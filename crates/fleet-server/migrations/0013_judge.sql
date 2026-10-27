ALTER TABLE jobs
    ADD COLUMN kind text NOT NULL DEFAULT 'agent' CHECK (kind IN ('agent', 'judge')),
    ADD COLUMN target_job_id text REFERENCES jobs (job_id),
    ADD CONSTRAINT jobs_judge_target CHECK ((kind = 'judge') = (target_job_id IS NOT NULL));

CREATE TABLE job_verdict (
    job_id text PRIMARY KEY REFERENCES jobs (job_id),
    target_job_id text NOT NULL REFERENCES jobs (job_id),
    score smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 1024),
    judge_model text NOT NULL CHECK (octet_length(judge_model) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (target_job_id, judge_model)
);
