ALTER TABLE github_app_mint
    ADD COLUMN scope text NOT NULL DEFAULT 'job' CHECK (scope IN ('job', 'probe'));
