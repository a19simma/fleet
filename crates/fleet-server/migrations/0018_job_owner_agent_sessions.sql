CREATE FUNCTION bootstrap_user_id() RETURNS bigint
    LANGUAGE plpgsql AS $$
DECLARE
    found bigint;
BEGIN
    INSERT INTO users (username) VALUES ('bootstrap')
    ON CONFLICT (lower(username)) DO NOTHING;
    SELECT id INTO found FROM users WHERE lower(username) = 'bootstrap';
    RETURN found;
END;
$$;

ALTER TABLE jobs ADD COLUMN user_id bigint REFERENCES users (id);
UPDATE jobs SET user_id = bootstrap_user_id();
ALTER TABLE jobs ALTER COLUMN user_id SET DEFAULT bootstrap_user_id();
ALTER TABLE jobs ALTER COLUMN user_id SET NOT NULL;
CREATE INDEX jobs_user_id_idx ON jobs (user_id);

ALTER TABLE jobs ADD COLUMN agent text NOT NULL DEFAULT 'claude'
    CHECK (agent IN ('claude', 'codex', 'kimi'));

CREATE TABLE passkeys (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);

CREATE TABLE web_sessions (
    id_hash bytea PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf text NOT NULL,
    expires_at timestamptz NOT NULL,
    last_seen timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX web_sessions_user_id_idx ON web_sessions (user_id);
CREATE INDEX web_sessions_expires_at_idx ON web_sessions (expires_at);
