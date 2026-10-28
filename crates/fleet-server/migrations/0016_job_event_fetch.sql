ALTER TABLE job_event DROP CONSTRAINT job_event_kind_check;
ALTER TABLE job_event
    ADD CONSTRAINT job_event_kind_check
    CHECK (kind IN ('tool', 'denial', 'api_retry', 'phase', 'stuck', 'fetch'));
