CREATE TABLE user_capabilities (
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    capability text NOT NULL CHECK (capability IN ('profile:tools')),
    granted_by bigint NOT NULL REFERENCES users (id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, capability)
);
