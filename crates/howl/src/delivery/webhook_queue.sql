CREATE TABLE IF NOT EXISTS webhook_events (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    channel BLOB NOT NULL CHECK (length(channel) = 32),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 6),
    created INTEGER NOT NULL DEFAULT (unixepoch()),
    inbox_cursor INTEGER REFERENCES inbox(id),
    run_id BLOB REFERENCES integration_runs(id),
    CHECK ((inbox_cursor IS NULL) <> (run_id IS NULL)),
    UNIQUE (kind, inbox_cursor),
    UNIQUE (kind, run_id)
) STRICT;
CREATE INDEX IF NOT EXISTS webhook_event_age ON webhook_events(created);
CREATE TRIGGER IF NOT EXISTS webhook_inbox_event AFTER INSERT ON channel_event_addresses
BEGIN
    INSERT INTO webhook_events (channel, kind, inbox_cursor)
    SELECT substr(stream, 1, 32), 1, id FROM inbox
    WHERE id = new.cursor AND kind = 1 AND new.outbound = 0;
    INSERT INTO webhook_events (channel, kind, inbox_cursor)
    SELECT substr(stream, 1, 32), 2, id FROM inbox
    WHERE id = new.cursor AND kind = 3;
    INSERT INTO webhook_events (channel, kind, inbox_cursor)
    SELECT substr(stream, 1, 32), 5, id FROM inbox
    WHERE id = new.cursor AND kind = 1 AND new.outbound = 0 AND instr(body, '@') > 0;
END;
CREATE TRIGGER IF NOT EXISTS webhook_approval_event AFTER INSERT ON wake_queue WHEN new.state = 0
BEGIN
    INSERT INTO webhook_events (channel, kind, inbox_cursor)
    SELECT substr(stream, 1, 32), 6, id FROM inbox WHERE id = new.cursor;
END;
CREATE TRIGGER IF NOT EXISTS webhook_terminal_run AFTER UPDATE OF state ON integration_runs
WHEN old.state = 0 AND new.state IN (1, 2)
BEGIN
    INSERT INTO webhook_events (channel, kind, created, run_id)
    VALUES (new.channel, CASE new.state WHEN 1 THEN 3 ELSE 4 END, new.updated_at, new.id);
END;
CREATE TABLE IF NOT EXISTS webhook_destinations (
    name TEXT PRIMARY KEY NOT NULL,
    revision BLOB NOT NULL CHECK (length(revision) = 32),
    cursor INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS webhook_outbox (
    endpoint TEXT NOT NULL,
    revision BLOB NOT NULL CHECK (length(revision) = 32),
    event_id BLOB NOT NULL CHECK (length(event_id) = 32),
    channel BLOB NOT NULL CHECK (length(channel) = 32),
    body TEXT,
    expires INTEGER NOT NULL,
    available INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease BLOB CHECK (length(lease) = 16),
    state INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 2),
    outcome TEXT,
    PRIMARY KEY (endpoint, revision, event_id),
    CHECK (state <> 0 OR body IS NOT NULL)
) STRICT;
CREATE INDEX IF NOT EXISTS webhook_ready ON webhook_outbox(available) WHERE state = 0;
CREATE INDEX IF NOT EXISTS webhook_terminal ON webhook_outbox(state, expires) WHERE state <> 0;
