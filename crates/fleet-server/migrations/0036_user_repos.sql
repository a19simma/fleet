CREATE TABLE user_repos (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    path text NOT NULL CHECK (char_length(path) BETWEEN 1 AND 141),
    forge_kind text NOT NULL CHECK (forge_kind IN ('github', 'forgejo')),
    push boolean,
    verified_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, host, path)
);

ALTER TABLE github_app_mint ALTER COLUMN job_id DROP NOT NULL;

ALTER TABLE github_app_mint ADD CONSTRAINT github_app_mint_scope_job_id CHECK (scope <> 'job' OR job_id IS NOT NULL);
