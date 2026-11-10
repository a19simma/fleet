ALTER TABLE environment ADD CONSTRAINT environment_id_user_id_key UNIQUE (id, user_id);

CREATE TABLE environment_default (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id),
    environment_id bigint NOT NULL,
    repo_id bigint,
    profile_id bigint REFERENCES profile (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((repo_id IS NULL) <> (profile_id IS NULL)),
    FOREIGN KEY (environment_id, user_id) REFERENCES environment (id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, repo_id) REFERENCES user_repos (user_id, id) ON DELETE CASCADE,
    UNIQUE (user_id, repo_id),
    UNIQUE (user_id, profile_id)
);

CREATE INDEX environment_default_environment_idx ON environment_default (environment_id);
