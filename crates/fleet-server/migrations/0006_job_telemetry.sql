CREATE TABLE job_event (
    job_id text NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    seq integer NOT NULL,
    ts_ms bigint NOT NULL,
    kind text NOT NULL
        CHECK (kind IN ('tool', 'denial', 'api_retry', 'phase', 'stuck')),
    tool_use_id text,
    tool text,
    ok boolean,
    exit_code integer,
    dur_ms bigint,
    out_bytes bigint,
    out_hash text,
    cmd text,
    detail text,
    PRIMARY KEY (job_id, seq)
);

CREATE TABLE job_summary (
    job_id text PRIMARY KEY REFERENCES jobs (job_id) ON DELETE CASCADE,
    turns bigint,
    duration_ms bigint,
    duration_api_ms bigint,
    stop_reason text,
    result_subtype text,
    cost_est_usd double precision,
    tokens_in bigint,
    tokens_out bigint,
    tokens_cache_read bigint,
    tokens_cache_write bigint,
    tool_calls bigint,
    tool_errors bigint,
    bash_calls bigint,
    bash_nonzero bigint,
    denials bigint,
    api_retries bigint,
    first_edit_ms bigint,
    complete boolean NOT NULL,
    missing text[] NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
