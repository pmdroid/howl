CREATE TABLE IF NOT EXISTS ongoing_threads (
    scope BLOB PRIMARY KEY,
    channel BLOB NOT NULL,
    peer BLOB NOT NULL,
    epoch BLOB NOT NULL,
    cursor INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS ongoing_schedules (
    scope BLOB NOT NULL REFERENCES ongoing_threads(scope),
    schedule BLOB NOT NULL,
    due INTEGER NOT NULL,
    PRIMARY KEY (scope, schedule)
) STRICT;
CREATE TABLE IF NOT EXISTS ongoing_turns (
    id INTEGER PRIMARY KEY,
    scope BLOB NOT NULL REFERENCES ongoing_threads(scope),
    source BLOB NOT NULL,
    scheduled INTEGER NOT NULL CHECK (scheduled IN (0, 1)),
    input TEXT NOT NULL,
    finished INTEGER NOT NULL DEFAULT 0 CHECK (finished IN (0, 1)),
    result TEXT,
    sent BLOB,
    UNIQUE (scope, source)
) STRICT;
CREATE INDEX IF NOT EXISTS ongoing_turns_by_scope ON ongoing_turns(scope, id DESC);
