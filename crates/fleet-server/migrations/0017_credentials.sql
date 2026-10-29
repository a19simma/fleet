CREATE TABLE users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username text NOT NULL CHECK (username <> '' AND octet_length(username) <= 64),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_username_key ON users (lower(username));

CREATE TABLE api_tokens (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id),
    hash bytea NOT NULL UNIQUE CHECK (octet_length(hash) = 32),
    label text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX api_tokens_user_id_idx ON api_tokens (user_id);

CREATE TABLE credentials (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id),
    kind text NOT NULL CHECK (kind IN (
        'anthropic_api_key',
        'claude_subscription_token',
        'github_pat',
        'kimi_membership_key',
        'kimi_platform_key',
        'codex_api_key'
    )),
    shape text NOT NULL CHECK (shape IN ('static_secret', 'refreshing_file')),
    ciphertext bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    login text,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, kind)
);

CREATE TABLE credential_use (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credential_id bigint NOT NULL REFERENCES credentials (id),
    job_id text NOT NULL,
    used_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_use_credential_id_idx ON credential_use (credential_id, used_at);

CREATE FUNCTION credential_use_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'credential_use is insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER credential_use_insert_only
    BEFORE UPDATE OR DELETE ON credential_use
    FOR EACH ROW EXECUTE FUNCTION credential_use_insert_only();

CREATE TRIGGER credential_use_no_truncate
    BEFORE TRUNCATE ON credential_use
    FOR EACH STATEMENT EXECUTE FUNCTION credential_use_insert_only();
