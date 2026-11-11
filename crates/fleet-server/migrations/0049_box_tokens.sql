CREATE TABLE box_tokens (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id),
    box_name text NOT NULL CONSTRAINT box_tokens_box_name_check CHECK (box_name ~ '^box-[0-9]+$' AND octet_length(box_name) <= 64),
    hash bytea NOT NULL UNIQUE CHECK (octet_length(hash) = 32),
    label text NOT NULL DEFAULT '' CONSTRAINT box_tokens_label_check CHECK (octet_length(label) <= 256),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT box_tokens_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX box_tokens_user_id_idx ON box_tokens (user_id);

CREATE UNIQUE INDEX box_tokens_active_box_key ON box_tokens (box_name) WHERE revoked_at IS NULL;

CREATE TABLE box_token_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_id bigint NOT NULL,
    user_id bigint NOT NULL,
    box_name text NOT NULL,
    action text NOT NULL CONSTRAINT box_token_audit_action_check CHECK (action IN ('issue', 'revoke', 'reset')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX box_token_audit_user_idx ON box_token_audit (user_id, created_at);

CREATE FUNCTION box_token_audit_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'box_token_audit is insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER box_token_audit_insert_only
    BEFORE UPDATE OR DELETE ON box_token_audit
    FOR EACH ROW EXECUTE FUNCTION box_token_audit_insert_only();

CREATE TRIGGER box_token_audit_no_truncate
    BEFORE TRUNCATE ON box_token_audit
    FOR EACH STATEMENT EXECUTE FUNCTION box_token_audit_insert_only();
