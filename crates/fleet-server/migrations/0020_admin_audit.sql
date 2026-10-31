CREATE TABLE setup_codes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    hash bytea NOT NULL UNIQUE CHECK (octet_length(hash) = 32),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX setup_codes_user_id_idx ON setup_codes (user_id);

CREATE TABLE admin_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action text NOT NULL CHECK (action IN ('user_create', 'passkey_reset')),
    user_id bigint NOT NULL,
    username text NOT NULL,
    passkeys_removed integer NOT NULL DEFAULT 0,
    sessions_revoked integer NOT NULL DEFAULT 0,
    operator text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX admin_audit_user_id_idx ON admin_audit (user_id, created_at);
