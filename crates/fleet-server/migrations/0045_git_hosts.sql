CREATE TABLE git_hosts (
    host text PRIMARY KEY CHECK (host <> '' AND octet_length(host) <= 253),
    kind text NOT NULL CONSTRAINT git_hosts_kind_check CHECK (kind IN ('github', 'forgejo')),
    allow_private boolean NOT NULL DEFAULT false,
    approved_ips inet[] NOT NULL DEFAULT '{}',
    added_by bigint REFERENCES users (id),
    approved_by bigint REFERENCES users (id),
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT git_hosts_approved_ips_need_allow_private
        CHECK (allow_private OR cardinality(approved_ips) = 0)
);

INSERT INTO git_hosts (host, kind) VALUES ('github.com', 'github');

ALTER TABLE credentials ADD COLUMN host text NOT NULL DEFAULT 'github.com';

ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK (kind IN (
    'anthropic_api_key',
    'claude_subscription_token',
    'github_pat',
    'github_app',
    'forgejo_pat',
    'kimi_membership_key',
    'kimi_platform_key',
    'codex_api_key'
));

ALTER TABLE credentials DROP CONSTRAINT credentials_user_id_kind_key;
ALTER TABLE credentials ADD CONSTRAINT credentials_user_kind_host_key UNIQUE (user_id, kind, host);

CREATE TABLE git_host_requests (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host text NOT NULL CHECK (host <> '' AND octet_length(host) <= 253),
    user_id bigint NOT NULL REFERENCES users (id),
    resolved inet[] NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'pending'
        CONSTRAINT git_host_requests_status_check CHECK (status IN ('pending', 'approved', 'denied')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX git_host_requests_status_idx ON git_host_requests (status, created_at);
