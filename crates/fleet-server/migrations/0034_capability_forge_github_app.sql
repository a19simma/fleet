ALTER TABLE user_capabilities DROP CONSTRAINT user_capabilities_capability_check;
ALTER TABLE user_capabilities ADD CONSTRAINT user_capabilities_capability_check
    CHECK (capability IN ('profile:tools', 'forge:github_app'));
