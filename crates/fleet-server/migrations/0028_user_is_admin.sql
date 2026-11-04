ALTER TABLE users ADD COLUMN is_admin boolean NOT NULL DEFAULT false;

ALTER TABLE users ADD CONSTRAINT users_bootstrap_not_admin
    CHECK (NOT is_admin OR lower(username) <> 'bootstrap');

ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_action_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_action_check
    CHECK (action IN (
        'user_create',
        'passkey_reset',
        'bootstrap_password_revoked',
        'admin_grant',
        'admin_revoke'
    ));
