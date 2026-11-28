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
CREATE TABLE IF NOT EXISTS ongoing_work (
    id BLOB PRIMARY KEY,
    scope BLOB NOT NULL REFERENCES ongoing_threads(scope),
    request_key TEXT NOT NULL,
    queued_at INTEGER NOT NULL DEFAULT (unixepoch()),
    instruction TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    cancelled INTEGER NOT NULL DEFAULT 0,
    feedback TEXT,
    result TEXT,
    reported INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scope, request_key)
) STRICT;
CREATE TABLE IF NOT EXISTS ongoing_work_grants (
    run BLOB PRIMARY KEY REFERENCES ongoing_work(id),
    policy BLOB NOT NULL CHECK (length(policy) = 32),
    revision TEXT NOT NULL,
    selection BLOB NOT NULL CHECK (length(selection) = 32)
) STRICT;
CREATE TABLE IF NOT EXISTS ongoing_peer_requests (
    scope BLOB NOT NULL REFERENCES ongoing_threads(scope),
    message BLOB NOT NULL,
    peer BLOB NOT NULL,
    expires INTEGER NOT NULL,
    PRIMARY KEY (scope, message)
) STRICT;

CREATE TABLE IF NOT EXISTS ongoing_turn_context (
    turn INTEGER PRIMARY KEY REFERENCES ongoing_turns(id),
    shared BLOB,
    sender BLOB NOT NULL CHECK(length(sender) = 32),
    parent INTEGER REFERENCES ongoing_turns(id)
) STRICT;
CREATE INDEX IF NOT EXISTS ongoing_shared_history ON ongoing_turn_context(shared, turn);
CREATE TABLE IF NOT EXISTS ongoing_peer_parents (
    scope BLOB NOT NULL,
    message BLOB NOT NULL,
    turn INTEGER NOT NULL REFERENCES ongoing_turns(id),
    PRIMARY KEY(scope, message),
    FOREIGN KEY(scope, message) REFERENCES ongoing_peer_requests(scope, message) ON DELETE CASCADE
) STRICT;

CREATE VIEW IF NOT EXISTS ongoing_history AS
SELECT t.id, t.scope, c.shared, t.input, t.result, t.finished,
       lower(hex(coalesce(c.sender, substr(s.peer, 33, 32)))) AS sender
FROM ongoing_turns t
JOIN ongoing_threads s ON s.scope = t.scope
LEFT JOIN ongoing_turn_context c ON c.turn = t.id
WHERE t.input <> '';

CREATE TABLE IF NOT EXISTS ongoing_checkpoints (
    audience BLOB NOT NULL CHECK(length(audience) = 32),
    is_shared INTEGER NOT NULL CHECK(is_shared IN (0, 1)),
    through_turn INTEGER NOT NULL REFERENCES ongoing_turns(id),
    summary TEXT NOT NULL CHECK(summary <> ''),
    PRIMARY KEY(audience, is_shared, through_turn)
) STRICT;
