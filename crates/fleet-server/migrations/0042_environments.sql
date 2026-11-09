CREATE TABLE environment (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id),
    name text NOT NULL CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX environment_user_name_key ON environment (user_id, lower(name));

CREATE FUNCTION environment_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE FUNCTION environment_use_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'environment_use is insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TABLE environment_version (
    environment_id bigint NOT NULL,
    user_id bigint NOT NULL REFERENCES users (id),
    version integer NOT NULL CHECK (version >= 1),
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    egress_hosts text[] NOT NULL CHECK (cardinality(egress_hosts) <= 16),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (environment_id, version)
);

CREATE TRIGGER environment_version_immutable
    BEFORE UPDATE OR DELETE ON environment_version
    FOR EACH ROW EXECUTE FUNCTION environment_immutable();

CREATE TRIGGER environment_version_no_truncate
    BEFORE TRUNCATE ON environment_version
    FOR EACH STATEMENT EXECUTE FUNCTION environment_immutable();

CREATE TABLE environment_entry (
    environment_id bigint NOT NULL,
    version integer NOT NULL,
    position integer NOT NULL CHECK (position >= 0 AND position < 64),
    name text NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,63}$'),
    kind text NOT NULL CHECK (kind IN ('secret', 'script')),
    body text,
    agent_visible boolean,
    delivery text CHECK (delivery IN ('file', 'env')),
    on_fail text CHECK (on_fail IN ('abort', 'continue')),
    timeout_s integer CHECK (timeout_s BETWEEN 1 AND 600),
    PRIMARY KEY (environment_id, version, position),
    FOREIGN KEY (environment_id, version) REFERENCES environment_version (environment_id, version),
    CHECK (
        (kind = 'secret' AND body IS NULL AND agent_visible IS NOT NULL AND delivery IS NOT NULL
            AND on_fail IS NULL AND timeout_s IS NULL)
        OR (kind = 'script' AND body IS NOT NULL AND agent_visible IS NULL AND delivery IS NULL
            AND on_fail IS NOT NULL AND timeout_s IS NOT NULL)
    )
);

CREATE UNIQUE INDEX environment_entry_name_key
    ON environment_entry (environment_id, version, lower(name));

CREATE TRIGGER environment_entry_immutable
    BEFORE UPDATE OR DELETE ON environment_entry
    FOR EACH ROW EXECUTE FUNCTION environment_immutable();

CREATE TRIGGER environment_entry_no_truncate
    BEFORE TRUNCATE ON environment_entry
    FOR EACH STATEMENT EXECUTE FUNCTION environment_immutable();

CREATE TABLE environment_secret (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    environment_id bigint NOT NULL REFERENCES environment (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,63}$'),
    ciphertext bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX environment_secret_name_key ON environment_secret (environment_id, lower(name));

CREATE TABLE environment_use (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    environment_id bigint NOT NULL,
    version integer NOT NULL,
    job_id text NOT NULL,
    name text NOT NULL,
    fingerprint text NOT NULL,
    used_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX environment_use_job_id_idx ON environment_use (job_id);
CREATE INDEX environment_use_environment_idx ON environment_use (environment_id, used_at);

CREATE TRIGGER environment_use_insert_only
    BEFORE UPDATE OR DELETE ON environment_use
    FOR EACH ROW EXECUTE FUNCTION environment_use_insert_only();

CREATE TRIGGER environment_use_no_truncate
    BEFORE TRUNCATE ON environment_use
    FOR EACH STATEMENT EXECUTE FUNCTION environment_use_insert_only();

ALTER TABLE jobs
    ADD COLUMN environment_id bigint,
    ADD COLUMN environment_version integer,
    ADD CONSTRAINT jobs_environment_pin_both_or_neither
        CHECK ((environment_id IS NULL) = (environment_version IS NULL));
