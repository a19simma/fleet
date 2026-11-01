CREATE TABLE bootstrap_password (
    user_id bigint PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    hash text NOT NULL,
    revoked_at timestamptz
);

ALTER TABLE passkeys ADD COLUMN last_used_at timestamptz;

ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_action_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_action_check
    CHECK (action IN ('user_create', 'passkey_reset', 'bootstrap_password_revoked'));
