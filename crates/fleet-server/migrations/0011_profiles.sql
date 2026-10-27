CREATE TABLE profile_blob (
    hash bytea PRIMARY KEY CHECK (octet_length(hash) = 32),
    content bytea NOT NULL,
    size integer NOT NULL CHECK (size > 0 AND size = octet_length(content)),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE profile_version (
    name text NOT NULL CHECK (name ~ '^[A-Za-z0-9_-]{1,64}$'),
    version integer NOT NULL CHECK (version >= 1),
    hash bytea NOT NULL REFERENCES profile_blob (hash),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name, version),
    UNIQUE (name, hash)
);

CREATE FUNCTION profile_insert_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'profile tables are insert-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER profile_blob_insert_only
    BEFORE UPDATE OR DELETE ON profile_blob
    FOR EACH ROW EXECUTE FUNCTION profile_insert_only();

CREATE TRIGGER profile_blob_no_truncate
    BEFORE TRUNCATE ON profile_blob
    FOR EACH STATEMENT EXECUTE FUNCTION profile_insert_only();

CREATE TRIGGER profile_version_insert_only
    BEFORE UPDATE OR DELETE ON profile_version
    FOR EACH ROW EXECUTE FUNCTION profile_insert_only();

CREATE TRIGGER profile_version_no_truncate
    BEFORE TRUNCATE ON profile_version
    FOR EACH STATEMENT EXECUTE FUNCTION profile_insert_only();
