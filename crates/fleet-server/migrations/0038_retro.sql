ALTER TABLE work_project ADD UNIQUE (user_id, id);

CREATE TABLE retro (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    span_from_item_id bigint,
    span_to_item_id bigint,
    opened_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    UNIQUE (project_id, id),
    CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
    FOREIGN KEY (project_id, span_from_item_id) REFERENCES work_item (project_id, id)
        ON DELETE SET NULL (span_from_item_id),
    FOREIGN KEY (project_id, span_to_item_id) REFERENCES work_item (project_id, id)
        ON DELETE SET NULL (span_to_item_id)
);

CREATE INDEX retro_by_project ON retro (project_id, id);

CREATE TABLE improvement (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    retro_id bigint,
    item_id bigint,
    vertical text NOT NULL CHECK (char_length(vertical) BETWEEN 1 AND 128),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body text NOT NULL DEFAULT '' CHECK (octet_length(body) <= 16384),
    kind text NOT NULL CHECK (kind IN ('process', 'tooling', 'docs', 'test', 'pitfall', 'other')),
    occurrences integer NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    disposition text CHECK (disposition IN ('accepted', 'rejected', 'deferred', 'applied')),
    disposition_reason text CHECK (char_length(disposition_reason) BETWEEN 1 AND 2000),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, title),
    UNIQUE (project_id, id),
    CHECK ((disposition IS NULL) = (disposition_reason IS NULL)),
    FOREIGN KEY (project_id, retro_id) REFERENCES retro (project_id, id)
        ON DELETE SET NULL (retro_id),
    FOREIGN KEY (project_id, item_id) REFERENCES work_item (project_id, id)
        ON DELETE SET NULL (item_id)
);

CREATE INDEX improvement_by_retro ON improvement (retro_id) WHERE disposition IS NULL;
CREATE INDEX improvement_by_vertical ON improvement (project_id, vertical, occurrences DESC);

CREATE TABLE improvement_occurrence (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL,
    improvement_id bigint NOT NULL,
    attempt_id bigint,
    retro_id bigint,
    note text NOT NULL DEFAULT '' CHECK (octet_length(note) <= 4096),
    at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (project_id, improvement_id) REFERENCES improvement (project_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (project_id, attempt_id) REFERENCES work_attempt (project_id, id)
        ON DELETE SET NULL (attempt_id),
    FOREIGN KEY (project_id, retro_id) REFERENCES retro (project_id, id)
        ON DELETE SET NULL (retro_id)
);

CREATE INDEX improvement_occurrence_by_improvement ON improvement_occurrence (improvement_id, id);

CREATE TABLE pitfall (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    project_id bigint,
    symptom text NOT NULL CHECK (char_length(symptom) BETWEEN 1 AND 500),
    cause text NOT NULL CHECK (char_length(cause) BETWEEN 1 AND 1000),
    fix text NOT NULL CHECK (char_length(fix) BETWEEN 1 AND 1000),
    hits integer NOT NULL DEFAULT 0 CHECK (hits >= 0),
    last_hit_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id, project_id) REFERENCES work_project (user_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX pitfall_user_symptom ON pitfall (user_id, symptom) WHERE project_id IS NULL;
CREATE UNIQUE INDEX pitfall_project_symptom ON pitfall (project_id, symptom)
    WHERE project_id IS NOT NULL;

CREATE TABLE suggested_edit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    attempt_id bigint,
    retro_id bigint,
    kind text NOT NULL CHECK (kind IN ('slice_op', 'pitfall', 'file_patch')),
    state text NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'accepted', 'rejected', 'stale')
    ),
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 512),
    base_hash text NOT NULL CHECK (char_length(base_hash) BETWEEN 1 AND 128),
    payload text NOT NULL CHECK (octet_length(payload) <= 65536),
    filed_by text NOT NULL CHECK (char_length(filed_by) BETWEEN 1 AND 128),
    decided_by bigint REFERENCES users (id) ON DELETE SET NULL,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((state IN ('accepted', 'rejected')) = (decided_at IS NOT NULL)),
    FOREIGN KEY (project_id, attempt_id) REFERENCES work_attempt (project_id, id)
        ON DELETE SET NULL (attempt_id),
    FOREIGN KEY (project_id, retro_id) REFERENCES retro (project_id, id)
        ON DELETE SET NULL (retro_id)
);

CREATE INDEX suggested_edit_by_state ON suggested_edit (project_id, state, id);
