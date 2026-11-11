ALTER TABLE box_token_audit DROP CONSTRAINT box_token_audit_action_check;

ALTER TABLE box_token_audit ADD CONSTRAINT box_token_audit_action_check
    CHECK (action IN ('issue', 'revoke', 'reset', 'expired'));
