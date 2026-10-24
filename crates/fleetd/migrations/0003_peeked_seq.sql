CREATE TABLE queue_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    peeked_seq INTEGER NOT NULL
);

INSERT INTO queue_state (id, peeked_seq) VALUES (1, 0);
