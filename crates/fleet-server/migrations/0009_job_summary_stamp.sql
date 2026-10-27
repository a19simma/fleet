ALTER TABLE job_summary
    ADD COLUMN bundle_sha text
        CHECK (bundle_sha <> '' AND bundle_sha <> 'unknown' AND char_length(bundle_sha) <= 64),
    ADD COLUMN claude_version text
        CHECK (claude_version <> '' AND claude_version <> 'unknown' AND char_length(claude_version) <= 64),
    ADD COLUMN model text
        CHECK (model <> '' AND model <> 'unknown' AND octet_length(model) <= 128);
