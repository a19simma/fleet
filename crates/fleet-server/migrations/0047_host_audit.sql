CREATE TABLE host_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL,
    host text NOT NULL CONSTRAINT host_audit_host_check CHECK (host <> '' AND octet_length(host) <= 253),
    action text NOT NULL CONSTRAINT host_audit_action_check CHECK (action IN ('add', 'remove')),
    outcome text NOT NULL CONSTRAINT host_audit_outcome_check CHECK (outcome IN ('added', 'exists', 'removed', 'refused')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT host_audit_action_outcome_check CHECK (
        (action = 'add' AND outcome IN ('added', 'exists', 'refused'))
        OR (action = 'remove' AND outcome IN ('removed', 'refused'))
    )
);

CREATE INDEX host_audit_user_idx ON host_audit (user_id, created_at);

CREATE FUNCTION host_audit_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'host_audit is insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER host_audit_insert_only
    BEFORE UPDATE OR DELETE ON host_audit
    FOR EACH ROW EXECUTE FUNCTION host_audit_insert_only();

CREATE TRIGGER host_audit_no_truncate
    BEFORE TRUNCATE ON host_audit
    FOR EACH STATEMENT EXECUTE FUNCTION host_audit_insert_only();
