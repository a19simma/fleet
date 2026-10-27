ALTER TABLE job_summary
    ADD COLUMN clone_ms bigint CHECK (clone_ms >= 0 AND clone_ms <= 604800000),
    ADD COLUMN push_ms bigint CHECK (push_ms >= 0 AND push_ms <= 604800000),
    ADD COLUMN pr_ms bigint CHECK (pr_ms >= 0 AND pr_ms <= 604800000),
    ADD COLUMN queue_wait_ms bigint CHECK (queue_wait_ms >= 0);
