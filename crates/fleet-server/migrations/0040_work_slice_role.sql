ALTER TABLE work_slice
    ADD COLUMN role text NOT NULL DEFAULT '' CHECK (char_length(role) <= 500);
