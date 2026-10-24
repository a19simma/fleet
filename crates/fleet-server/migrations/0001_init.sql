CREATE TABLE boxes (
    box text PRIMARY KEY,
    hostname text NOT NULL,
    machine_id text NOT NULL,
    boot_id text NOT NULL,
    fleetd_version text NOT NULL DEFAULT '',
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_event_at timestamptz,
    last_heartbeat_at timestamptz,
    state jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE events (
    box text NOT NULL,
    id text NOT NULL,
    boot_id text NOT NULL,
    seq bigint NOT NULL,
    schema_version integer NOT NULL,
    source text NOT NULL,
    kind text NOT NULL,
    captured_at_ms bigint NOT NULL,
    occurred_at_ms bigint,
    received_at timestamptz NOT NULL DEFAULT now(),
    session_id text,
    prompt_id text,
    workdir text,
    payload jsonb NOT NULL,
    PRIMARY KEY (box, id)
);

CREATE INDEX events_box_boot_seq_idx ON events (box, boot_id, seq);
CREATE INDEX events_box_received_idx ON events (box, received_at DESC);
CREATE INDEX events_session_idx ON events (session_id) WHERE session_id IS NOT NULL;

CREATE TABLE sessions (
    box text NOT NULL,
    session_id text NOT NULL,
    kind text NOT NULL DEFAULT 'claude',
    state text NOT NULL,
    state_at timestamptz NOT NULL,
    workdir text,
    last_prompt text,
    last_message text,
    last_notification text,
    last_event_at timestamptz NOT NULL,
    last_event_kind text NOT NULL,
    PRIMARY KEY (box, session_id)
);
