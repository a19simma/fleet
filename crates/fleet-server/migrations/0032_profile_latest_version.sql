ALTER TABLE profile ADD COLUMN latest_version integer;

UPDATE profile p
SET latest_version = (SELECT max(v.version) FROM profile_version v WHERE v.profile_id = p.id);

ALTER TABLE profile
    ADD CONSTRAINT profile_latest_version_fk FOREIGN KEY (id, latest_version)
        REFERENCES profile_version (profile_id, version);

CREATE FUNCTION profile_version_sets_latest() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    UPDATE profile SET latest_version = NEW.version WHERE id = NEW.profile_id;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER profile_version_latest
    AFTER INSERT ON profile_version
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION profile_version_sets_latest();
