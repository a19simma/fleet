CREATE TABLE credential_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL,
    host text NOT NULL CONSTRAINT credential_audit_host_check CHECK (host <> '' AND octet_length(host) <= 253),
    kind text NOT NULL,
    action text NOT NULL CONSTRAINT credential_audit_action_check CHECK (action IN ('put', 'delete')),
    outcome text NOT NULL CONSTRAINT credential_audit_outcome_check CHECK (outcome IN ('stored', 'removed', 'tombstoned')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_audit_user_idx ON credential_audit (user_id, created_at);

CREATE FUNCTION credential_audit_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'credential_audit is insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER credential_audit_insert_only
    BEFORE UPDATE OR DELETE ON credential_audit
    FOR EACH ROW EXECUTE FUNCTION credential_audit_insert_only();

CREATE TRIGGER credential_audit_no_truncate
    BEFORE TRUNCATE ON credential_audit
    FOR EACH STATEMENT EXECUTE FUNCTION credential_audit_insert_only();
