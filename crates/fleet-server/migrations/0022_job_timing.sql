CREATE TABLE job_timing (
    job_id text PRIMARY KEY REFERENCES jobs (job_id) ON DELETE CASCADE,
    wall_ms bigint NOT NULL CHECK (wall_ms >= 0),
    api_wait_ms bigint NOT NULL CHECK (api_wait_ms >= 0),
    tool_ms bigint NOT NULL CHECK (tool_ms >= 0),
    shell_ms bigint NOT NULL CHECK (shell_ms >= 0),
    idle_ms bigint NOT NULL CHECK (idle_ms >= 0),
    overhead_ms bigint NOT NULL CHECK (overhead_ms >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE job_timing_spans (
    job_id text NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    seq integer NOT NULL CHECK (seq BETWEEN 0 AND 4095),
    kind text NOT NULL CHECK (kind IN ('api', 'tool', 'shell', 'bg_shell')),
    start_ms bigint NOT NULL CHECK (start_ms >= 0),
    end_ms bigint NOT NULL CHECK (end_ms >= start_ms),
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    tool_use_id text CHECK (octet_length(tool_use_id) BETWEEN 1 AND 128),
    PRIMARY KEY (job_id, seq)
);

CREATE TABLE job_shell_commands (
    job_id text NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    seq integer NOT NULL CHECK (seq BETWEEN 0 AND 255),
    id text NOT NULL CHECK (octet_length(id) BETWEEN 1 AND 128),
    command text NOT NULL CHECK (octet_length(command) BETWEEN 1 AND 2048),
    background boolean NOT NULL,
    started_ms bigint NOT NULL CHECK (started_ms >= 0),
    ended_ms bigint CHECK (ended_ms >= started_ms),
    duration_ms bigint NOT NULL CHECK (duration_ms >= 0),
    exit_code integer,
    log text NOT NULL CHECK (octet_length(log) <= 16384),
    log_truncated boolean NOT NULL,
    ended_by text CHECK (octet_length(ended_by) BETWEEN 1 AND 128),
    PRIMARY KEY (job_id, seq)
);
