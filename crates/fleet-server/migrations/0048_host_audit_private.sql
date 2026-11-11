ALTER TABLE host_audit DROP CONSTRAINT host_audit_action_outcome_check;
ALTER TABLE host_audit DROP CONSTRAINT host_audit_action_check;
ALTER TABLE host_audit DROP CONSTRAINT host_audit_outcome_check;

ALTER TABLE host_audit ADD CONSTRAINT host_audit_action_check
    CHECK (action IN ('add', 'remove', 'approve_private', 'revoke_private'));
ALTER TABLE host_audit ADD CONSTRAINT host_audit_outcome_check
    CHECK (outcome IN ('added', 'exists', 'removed', 'refused', 'approved', 'revoked'));
ALTER TABLE host_audit ADD CONSTRAINT host_audit_action_outcome_check CHECK (
    (action = 'add' AND outcome IN ('added', 'exists', 'refused'))
    OR (action = 'remove' AND outcome IN ('removed', 'refused'))
    OR (action = 'approve_private' AND outcome IN ('approved', 'refused'))
    OR (action = 'revoke_private' AND outcome IN ('revoked', 'refused'))
);

ALTER TABLE host_audit ADD COLUMN addresses inet[] NOT NULL DEFAULT '{}';

CREATE UNIQUE INDEX git_host_requests_pending_key
    ON git_host_requests (user_id, host) WHERE status = 'pending';
