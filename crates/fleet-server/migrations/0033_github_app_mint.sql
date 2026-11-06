ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN (
    'anthropic_api_key',
    'claude_subscription_token',
    'github_pat',
    'github_app',
    'kimi_membership_key',
    'kimi_platform_key',
    'codex_api_key'
));

ALTER TABLE credentials ADD COLUMN tombstoned_at timestamptz;

CREATE TABLE github_app_mint (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mint_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    credential_id bigint NOT NULL REFERENCES credentials (id) ON DELETE NO ACTION,
    job_id text NOT NULL CHECK (char_length(job_id) BETWEEN 1 AND 64),
    repo text NOT NULL CHECK (char_length(repo) BETWEEN 1 AND 140),
    installation_id text NOT NULL CHECK (
        CASE WHEN installation_id ~ '^[1-9][0-9]{0,19}$'
            THEN installation_id::numeric <= 18446744073709551615
            ELSE false
        END
    ),
    requested_permissions text NOT NULL CHECK (char_length(requested_permissions) BETWEEN 1 AND 512),
    outcome text NOT NULL CHECK (outcome IN (
        'attempt', 'minted', 'failed', 'denied', 'revoked', 'revoke_failed'
    )),
    reason text CHECK (reason IS NULL OR char_length(reason) <= 200),
    expires_at timestamptz CHECK (expires_at IS NULL OR outcome = 'minted'),
    at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (attempt_id, outcome)
);

CREATE INDEX github_app_mint_credential_id_idx ON github_app_mint (credential_id, at);

CREATE FUNCTION github_app_mint_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'github_app_mint is insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER github_app_mint_insert_only
    BEFORE UPDATE OR DELETE ON github_app_mint
    FOR EACH ROW EXECUTE FUNCTION github_app_mint_insert_only();

CREATE TRIGGER github_app_mint_no_truncate
    BEFORE TRUNCATE ON github_app_mint
    FOR EACH STATEMENT EXECUTE FUNCTION github_app_mint_insert_only();

CREATE FUNCTION credentials_keep_mint_history() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM github_app_mint WHERE credential_id = OLD.id) THEN
        RAISE EXCEPTION 'credential has mint history, tombstone it instead'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER credentials_keep_mint_history
    BEFORE DELETE ON credentials
    FOR EACH ROW EXECUTE FUNCTION credentials_keep_mint_history();

CREATE FUNCTION credentials_keep_tombstone() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a tombstoned credential cannot be restored'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER credentials_keep_tombstone
    BEFORE UPDATE OF tombstoned_at ON credentials
    FOR EACH ROW
    WHEN (OLD.tombstoned_at IS NOT NULL AND NEW.tombstoned_at IS NULL)
    EXECUTE FUNCTION credentials_keep_tombstone();
