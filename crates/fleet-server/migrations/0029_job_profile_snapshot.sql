ALTER TABLE jobs
    ADD COLUMN snapshot_catalog jsonb,
    ADD COLUMN snapshot_notes jsonb,
    ADD COLUMN snapshot_hash bytea,
    ADD CONSTRAINT jobs_snapshot_columns_together CHECK (
        (snapshot_catalog IS NULL AND snapshot_notes IS NULL AND snapshot_hash IS NULL)
        OR (snapshot_catalog IS NOT NULL AND snapshot_notes IS NOT NULL AND snapshot_hash IS NOT NULL)
    ),
    ADD CONSTRAINT jobs_snapshot_catalog_shape CHECK (
        snapshot_catalog IS NULL
        OR (jsonb_typeof(snapshot_catalog) = 'array' AND jsonb_array_length(snapshot_catalog) <= 256)
    ),
    ADD CONSTRAINT jobs_snapshot_notes_shape CHECK (
        snapshot_notes IS NULL OR jsonb_typeof(snapshot_notes) = 'array'
    ),
    ADD CONSTRAINT jobs_snapshot_hash_len CHECK (
        snapshot_hash IS NULL OR octet_length(snapshot_hash) = 32
    );
