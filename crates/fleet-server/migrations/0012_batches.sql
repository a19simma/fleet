CREATE TABLE batch (
    batch_id text PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    prompt text NOT NULL,
    repo text NOT NULL,
    base_sha text NOT NULL CHECK (base_sha ~ '^[0-9a-f]{40}$'),
    repeats integer NOT NULL DEFAULT 1 CHECK (repeats = 1),
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE jobs
    ADD COLUMN batch_id text REFERENCES batch (batch_id),
    ADD COLUMN repeat_idx integer CHECK (repeat_idx >= 0),
    ADD COLUMN batch_pos integer CHECK (batch_pos >= 0),
    ADD COLUMN profile_name text,
    ADD COLUMN profile_version integer,
    ADD COLUMN profile_hash bytea,
    ADD CONSTRAINT jobs_batch_columns_together CHECK (
        (batch_id IS NULL AND repeat_idx IS NULL AND batch_pos IS NULL AND profile_name IS NULL
            AND profile_version IS NULL AND profile_hash IS NULL)
        OR (batch_id IS NOT NULL AND repeat_idx IS NOT NULL AND batch_pos IS NOT NULL
            AND profile_name IS NOT NULL AND profile_version IS NOT NULL
            AND profile_hash IS NOT NULL)
    ),
    ADD CONSTRAINT jobs_batch_profile_repeat_unique UNIQUE (batch_id, profile_name, repeat_idx),
    ADD CONSTRAINT jobs_batch_pos_unique UNIQUE (batch_id, batch_pos),
    ADD CONSTRAINT jobs_profile_version_fk FOREIGN KEY (profile_name, profile_version)
        REFERENCES profile_version (name, version),
    ADD CONSTRAINT jobs_profile_hash_fk FOREIGN KEY (profile_name, profile_hash)
        REFERENCES profile_version (name, hash);

CREATE INDEX jobs_batch_idx ON jobs (batch_id) WHERE batch_id IS NOT NULL;
