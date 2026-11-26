CREATE TABLE IF NOT EXISTS store (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    device BLOB NOT NULL,
    wake_clock BLOB
) STRICT;
CREATE TABLE IF NOT EXISTS channels (
    channel BLOB PRIMARY KEY,
    epoch BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS sequences (
    stream BLOB PRIMARY KEY,
    last BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    stream BLOB NOT NULL,
    message BLOB NOT NULL,
    sequence BLOB NOT NULL,
    epoch BLOB NOT NULL,
    expires BLOB NOT NULL,
    digest BLOB NOT NULL,
    frame BLOB,
    UNIQUE (stream, sequence)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS outbox_message ON outbox(substr(stream, 1, 96), message);
CREATE TABLE IF NOT EXISTS recipients (
    envelope INTEGER NOT NULL REFERENCES outbox(id),
    device BLOB NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    due BLOB,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (envelope, device)
) STRICT;
CREATE TABLE IF NOT EXISTS peer_routes (
    device BLOB PRIMARY KEY,
    address TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS recipients_due ON recipients(due) WHERE acknowledged = 0;
CREATE TABLE IF NOT EXISTS inbox (
    id INTEGER PRIMARY KEY,
    stream BLOB NOT NULL,
    message BLOB NOT NULL,
    sequence BLOB NOT NULL,
    epoch BLOB NOT NULL,
    received BLOB NOT NULL,
    expires BLOB NOT NULL,
    digest BLOB NOT NULL,
    frame BLOB,
    kind INTEGER NOT NULL,
    target BLOB,
    body TEXT,
    UNIQUE (stream, sequence)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS inbox_message ON inbox(substr(stream, 1, 96), message);
CREATE VIRTUAL TABLE IF NOT EXISTS chat_search USING fts5(body);
CREATE TABLE IF NOT EXISTS conflicts (
    inbox_id INTEGER NOT NULL REFERENCES inbox(id),
    digest BLOB NOT NULL,
    frame BLOB NOT NULL,
    PRIMARY KEY (inbox_id, digest)
) STRICT;
