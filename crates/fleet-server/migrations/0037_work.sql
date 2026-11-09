CREATE TABLE work_project (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    repo_id bigint REFERENCES user_repos (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, name)
);

CREATE TABLE work_slice (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    UNIQUE (project_id, name),
    UNIQUE (project_id, id)
);

CREATE TABLE work_slice_path (
    slice_id bigint NOT NULL REFERENCES work_slice (id) ON DELETE CASCADE,
    path text NOT NULL CHECK (
        char_length(path) BETWEEN 1 AND 512
        AND path !~ '[^ -~]'
        AND position(E'\\' IN path) = 0
        AND path !~ '^/'
        AND path !~ '/$'
        AND path !~ '(^|/)\.{0,2}(/|$)'
    ),
    PRIMARY KEY (slice_id, path)
);

CREATE TABLE work_mergeable_path (
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    path text NOT NULL CHECK (
        char_length(path) BETWEEN 1 AND 512
        AND path !~ '[^ -~]'
        AND position(E'\\' IN path) = 0
        AND path !~ '^/'
        AND path !~ '/$'
        AND path !~ '(^|/)\.{0,2}(/|$)'
    ),
    PRIMARY KEY (project_id, path)
);

CREATE TABLE work_item (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    key text NOT NULL CHECK (char_length(key) BETWEEN 1 AND 128),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body text NOT NULL DEFAULT '' CHECK (octet_length(body) <= 16384),
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'blocked', 'cancelled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, key),
    UNIQUE (project_id, id)
);

CREATE TABLE work_item_slice (
    project_id bigint NOT NULL,
    item_id bigint NOT NULL,
    slice_id bigint NOT NULL,
    PRIMARY KEY (item_id, slice_id),
    FOREIGN KEY (project_id, item_id) REFERENCES work_item (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, slice_id) REFERENCES work_slice (project_id, id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX work_item_slice_by_slice ON work_item_slice (slice_id);

CREATE TABLE work_dep (
    project_id bigint NOT NULL,
    item_id bigint NOT NULL,
    depends_on_id bigint NOT NULL,
    why text NOT NULL CHECK (char_length(why) BETWEEN 1 AND 500),
    PRIMARY KEY (item_id, depends_on_id),
    CHECK (item_id <> depends_on_id),
    FOREIGN KEY (project_id, item_id) REFERENCES work_item (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, depends_on_id) REFERENCES work_item (project_id, id) ON DELETE CASCADE
);

CREATE INDEX work_dep_by_target ON work_dep (depends_on_id);

CREATE TABLE work_attempt (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL,
    item_id bigint NOT NULL,
    holder text NOT NULL CHECK (char_length(holder) BETWEEN 1 AND 128),
    claimed_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    verdict text CHECK (verdict IN ('pass', 'fail', 'lost')),
    note text CHECK (octet_length(note) <= 4096),
    evidence text CHECK (octet_length(evidence) <= 8192),
    closed_at timestamptz,
    UNIQUE (project_id, id),
    CHECK ((verdict IS NULL) = (closed_at IS NULL)),
    CHECK (verdict IN ('pass', 'fail') OR evidence IS NULL),
    FOREIGN KEY (project_id, item_id) REFERENCES work_item (project_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX work_attempt_one_open ON work_attempt (item_id) WHERE verdict IS NULL;
CREATE INDEX work_attempt_by_item ON work_attempt (item_id, verdict);
CREATE INDEX work_attempt_expiry ON work_attempt (expires_at) WHERE verdict IS NULL;

CREATE TABLE work_slice_lease (
    slice_id bigint PRIMARY KEY,
    project_id bigint NOT NULL,
    attempt_id bigint NOT NULL,
    FOREIGN KEY (project_id, slice_id) REFERENCES work_slice (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, attempt_id) REFERENCES work_attempt (project_id, id) ON DELETE CASCADE
);

CREATE INDEX work_slice_lease_by_attempt ON work_slice_lease (attempt_id);

CREATE TABLE work_event (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    item_id bigint REFERENCES work_item (id) ON DELETE CASCADE,
    attempt_id bigint REFERENCES work_attempt (id) ON DELETE SET NULL,
    kind text NOT NULL CHECK (kind IN (
        'created', 'updated', 'dep_added', 'dep_removed', 'claimed', 'renewed', 'passed',
        'failed', 'lost', 'cancelled', 'blocked', 'unblocked', 'note', 'deferred', 'imported'
    )),
    actor text NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 128),
    note text NOT NULL DEFAULT '' CHECK (octet_length(note) <= 4096),
    at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX work_event_by_item ON work_event (item_id, id);
CREATE INDEX work_event_by_project ON work_event (project_id, id);

CREATE TABLE work_defer (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    item_id bigint REFERENCES work_item (id) ON DELETE SET NULL,
    attempt_id bigint REFERENCES work_attempt (id) ON DELETE SET NULL,
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 2000),
    vertical text NOT NULL CHECK (char_length(vertical) BETWEEN 1 AND 128),
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'promoted', 'dropped')),
    promoted_item_id bigint REFERENCES work_item (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (state = 'promoted' OR promoted_item_id IS NULL)
);

CREATE INDEX work_defer_by_vertical ON work_defer (project_id, vertical, id);

CREATE TABLE work_request_key (
    project_id bigint NOT NULL REFERENCES work_project (id) ON DELETE CASCADE,
    key text NOT NULL CHECK (char_length(key) BETWEEN 1 AND 128),
    rpc text NOT NULL CHECK (char_length(rpc) BETWEEN 1 AND 64),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, key)
);
