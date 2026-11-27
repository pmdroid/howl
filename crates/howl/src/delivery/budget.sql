CREATE TABLE IF NOT EXISTS budget_policy (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    human_key BLOB NOT NULL CHECK (length(human_key) = 32),
    limits BLOB NOT NULL,
    clock BLOB
) STRICT;
CREATE TABLE IF NOT EXISTS budget_controls (
    nonce BLOB PRIMARY KEY CHECK (length(nonce) = 32)
) STRICT;
CREATE TABLE IF NOT EXISTS budget_roots (
    root BLOB PRIMARY KEY CHECK (length(root) = 32),
    expires BLOB NOT NULL CHECK (length(expires) = 8),
    ceiling INTEGER NOT NULL CHECK (ceiling > 0),
    paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1))
) STRICT;
CREATE TABLE IF NOT EXISTS budget_turns (
    id BLOB PRIMARY KEY CHECK (length(id) = 32),
    root BLOB NOT NULL REFERENCES budget_roots(root),
    cause BLOB REFERENCES budget_turns(id),
    agent BLOB NOT NULL CHECK (length(agent) = 32),
    hop INTEGER NOT NULL CHECK (hop >= 0),
    started BLOB NOT NULL CHECK (length(started) = 8),
    state INTEGER NOT NULL DEFAULT 1 CHECK (state BETWEEN 0 AND 2)
) STRICT;
CREATE INDEX IF NOT EXISTS budget_turns_root ON budget_turns(root);
CREATE INDEX IF NOT EXISTS budget_turns_cause ON budget_turns(cause);
CREATE INDEX IF NOT EXISTS budget_turns_started ON budget_turns(started);
CREATE INDEX IF NOT EXISTS budget_turns_agent ON budget_turns(agent, started);
CREATE INDEX IF NOT EXISTS budget_turns_active ON budget_turns(state) WHERE state = 1;
