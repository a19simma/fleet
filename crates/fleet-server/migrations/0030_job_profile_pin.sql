ALTER TABLE jobs
    DROP CONSTRAINT jobs_batch_columns_together,
    ADD CONSTRAINT jobs_batch_columns_together CHECK (
        (batch_id IS NULL AND repeat_idx IS NULL AND batch_pos IS NULL)
        OR (batch_id IS NOT NULL AND repeat_idx IS NOT NULL AND batch_pos IS NOT NULL
            AND profile_name IS NOT NULL AND profile_id IS NOT NULL
            AND profile_version IS NOT NULL AND profile_hash IS NOT NULL)
    ),
    ADD CONSTRAINT jobs_profile_columns_together CHECK (
        (profile_name IS NULL AND profile_id IS NULL
            AND profile_version IS NULL AND profile_hash IS NULL)
        OR (profile_name IS NOT NULL AND profile_id IS NOT NULL
            AND profile_version IS NOT NULL AND profile_hash IS NOT NULL)
    );
