CREATE INDEX jobs_created_idx ON jobs (created_at);

CREATE INDEX jobs_terminal_finished_idx ON jobs ((COALESCE(finished_at, created_at)))
    WHERE state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'LOST');
