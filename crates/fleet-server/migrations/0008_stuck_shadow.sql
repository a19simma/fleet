ALTER TABLE job_summary
    ADD COLUMN stuck_rule text
        CHECK (stuck_rule IN ('repeat_action_observation', 'repeat_error', 'alternating', 'monologue')),
    ADD COLUMN stuck_at_seq bigint,
    ADD COLUMN stuck_at_ms bigint;
