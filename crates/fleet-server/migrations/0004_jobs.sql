CREATE TABLE jobs (
    job_id text PRIMARY KEY,
    idempotency_key text UNIQUE,
    prompt text NOT NULL,
    repo text NOT NULL,
    base_ref text NOT NULL,
    branch text NOT NULL,
    open_pr boolean NOT NULL,
    state text NOT NULL DEFAULT 'QUEUED'
        CHECK (state IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'LOST')),
    box text NOT NULL DEFAULT '',
    attempt integer NOT NULL DEFAULT 0,
    lease_expires_at timestamptz,
    phase text NOT NULL DEFAULT '',
    progress text NOT NULL DEFAULT '',
    pr_url text,
    error text,
    exit_code integer,
    cancel_requested boolean NOT NULL DEFAULT false,
    transcript_bytes bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz,
    finished_at timestamptz
);

CREATE INDEX jobs_queued_created_idx ON jobs (created_at) WHERE state = 'QUEUED';

CREATE TABLE job_transcript (
    job_id text NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    seq bigint NOT NULL,
    ts_ms bigint NOT NULL,
    chunk text NOT NULL,
    PRIMARY KEY (job_id, seq)
);
