CREATE TABLE job_shell_log_chunks (
    job_id text NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    command_id text NOT NULL CHECK (command_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    seq integer NOT NULL CHECK (seq BETWEEN 0 AND 63),
    bytes bytea NOT NULL CHECK (octet_length(bytes) <= 4096),
    status text NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, command_id, seq)
);
