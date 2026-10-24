CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    priority INTEGER NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS events_drop_order ON events (priority, seq);

CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
