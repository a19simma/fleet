CREATE TABLE profile_version_v2 (
    profile_id bigint NOT NULL REFERENCES profile (id),
    version integer NOT NULL CHECK (version >= 1),
    hash bytea NOT NULL REFERENCES profile_blob (hash),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, version),
    UNIQUE (profile_id, hash)
);

DO $$
DECLARE
    old_rows bigint;
    new_rows bigint;
    unpinned bigint;
BEGIN
    INSERT INTO profile (owner_user_id, name, visibility)
    SELECT system_user_id(), name, 'shared'
    FROM (
        SELECT name FROM profile_version
        UNION
        SELECT profile_name FROM jobs WHERE profile_name IS NOT NULL
    ) legacy
    ON CONFLICT (owner_user_id, name) DO NOTHING;

    SELECT count(*) INTO old_rows FROM profile_version;
    IF old_rows > 0 THEN
        INSERT INTO profile_version_v2 (profile_id, version, hash, created_at)
        SELECT p.id, v.version, v.hash, v.created_at
        FROM profile_version v
        JOIN profile p ON p.name = v.name AND p.owner_user_id = system_user_id();
    END IF;
    SELECT count(*) INTO new_rows FROM profile_version_v2;
    IF new_rows <> old_rows THEN
        RAISE EXCEPTION 'profile_version backfill kept % of % rows: a name has no system-owned profile',
            new_rows, old_rows;
    END IF;

    ALTER TABLE jobs ADD COLUMN profile_id bigint REFERENCES profile (id);
    IF EXISTS (SELECT 1 FROM jobs WHERE profile_name IS NOT NULL) THEN
        UPDATE jobs j SET profile_id = p.id
        FROM profile p
        WHERE j.profile_name IS NOT NULL
            AND p.name = j.profile_name
            AND p.owner_user_id = system_user_id();
    END IF;
    SELECT count(*) INTO unpinned FROM jobs WHERE profile_name IS NOT NULL AND profile_id IS NULL;
    IF unpinned > 0 THEN
        RAISE EXCEPTION 'jobs backfill left % pinned jobs without profile_id', unpinned;
    END IF;
END;
$$;

ALTER TABLE jobs
    DROP CONSTRAINT jobs_profile_version_fk,
    DROP CONSTRAINT jobs_profile_hash_fk,
    DROP CONSTRAINT jobs_batch_columns_together,
    ADD CONSTRAINT jobs_batch_columns_together CHECK (
        (batch_id IS NULL AND repeat_idx IS NULL AND batch_pos IS NULL AND profile_name IS NULL
            AND profile_id IS NULL AND profile_version IS NULL AND profile_hash IS NULL)
        OR (batch_id IS NOT NULL AND repeat_idx IS NOT NULL AND batch_pos IS NOT NULL
            AND profile_name IS NOT NULL AND profile_id IS NOT NULL
            AND profile_version IS NOT NULL AND profile_hash IS NOT NULL)
    ),
    ADD CONSTRAINT jobs_profile_version_fk FOREIGN KEY (profile_id, profile_version)
        REFERENCES profile_version_v2 (profile_id, version),
    ADD CONSTRAINT jobs_profile_hash_fk FOREIGN KEY (profile_id, profile_hash)
        REFERENCES profile_version_v2 (profile_id, hash);

DROP TABLE profile_version;
ALTER TABLE profile_version_v2 RENAME TO profile_version;
ALTER INDEX profile_version_v2_pkey RENAME TO profile_version_pkey;
ALTER INDEX profile_version_v2_profile_id_hash_key RENAME TO profile_version_profile_id_hash_key;

CREATE TRIGGER profile_version_insert_only
    BEFORE UPDATE OR DELETE ON profile_version
    FOR EACH ROW EXECUTE FUNCTION profile_insert_only();

CREATE TRIGGER profile_version_no_truncate
    BEFORE TRUNCATE ON profile_version
    FOR EACH STATEMENT EXECUTE FUNCTION profile_insert_only();
