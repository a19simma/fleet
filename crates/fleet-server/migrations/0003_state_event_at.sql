ALTER TABLE sessions ADD COLUMN state_event_at timestamptz;
UPDATE sessions SET state_event_at = state_at;
ALTER TABLE sessions ALTER COLUMN state_event_at SET NOT NULL;
