CREATE TABLE catalog_items (
    id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    kind text NOT NULL CHECK (kind IN ('skill', 'subagent', 'tool', 'context')),
    name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    content text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 262144),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    admin_enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, name)
);
