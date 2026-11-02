CREATE FUNCTION system_user_id() RETURNS bigint
    LANGUAGE plpgsql AS $$
DECLARE
    found bigint;
BEGIN
    INSERT INTO users (username) VALUES ('system')
    ON CONFLICT (lower(username)) DO NOTHING;
    SELECT id INTO found FROM users WHERE lower(username) = 'system';
    RETURN found;
END;
$$;

CREATE TABLE profile (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES users (id),
    name text NOT NULL CHECK (name ~ '^[A-Za-z0-9_-]{1,64}$'),
    visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'shared')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_user_id, name)
);

CREATE INDEX profile_name_idx ON profile (name);

INSERT INTO profile (owner_user_id, name, visibility)
SELECT system_user_id(), name, 'shared' FROM profile_version GROUP BY name;
