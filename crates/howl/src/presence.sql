CREATE TABLE IF NOT EXISTS presence_runtime (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    token BLOB NOT NULL CHECK (length(token) = 16)
) STRICT;

CREATE TABLE IF NOT EXISTS presence_nodes (
    node BLOB PRIMARY KEY NOT NULL CHECK (length(node) = 64),
    runtime BLOB NOT NULL CHECK (length(runtime) = 16),
    link BLOB NOT NULL CHECK (length(link) = 16),
    observed BLOB NOT NULL CHECK (length(observed) = 8),
    connected INTEGER NOT NULL CHECK (connected IN (0, 1))
) STRICT;

CREATE TABLE IF NOT EXISTS presence_agents (
    node BLOB NOT NULL REFERENCES presence_nodes(node),
    agent BLOB NOT NULL CHECK (length(agent) = 32),
    link BLOB NOT NULL CHECK (length(link) = 16),
    observed BLOB NOT NULL CHECK (length(observed) = 8),
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    kind INTEGER NOT NULL CHECK (kind IN (0, 1)),
    readiness INTEGER NOT NULL CHECK (readiness BETWEEN 0 AND 3),
    harness TEXT NOT NULL CHECK (length(harness) BETWEEN 1 AND 128),
    version TEXT CHECK (length(version) BETWEEN 1 AND 128),
    capabilities INTEGER NOT NULL CHECK (capabilities BETWEEN 0 AND 63 AND (kind = 0 OR capabilities = 1)),
    PRIMARY KEY (node, agent)
) STRICT;

CREATE TABLE IF NOT EXISTS presence_sessions (
    node BLOB NOT NULL,
    agent BLOB NOT NULL,
    session BLOB NOT NULL CHECK (length(session) = 32),
    link BLOB NOT NULL CHECK (length(link) = 16),
    observed BLOB NOT NULL CHECK (length(observed) = 8),
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    lifecycle INTEGER NOT NULL CHECK (lifecycle BETWEEN 0 AND 3),
    execution INTEGER NOT NULL CHECK (execution BETWEEN 0 AND 5),
    PRIMARY KEY (node, agent, session),
    FOREIGN KEY (node, agent) REFERENCES presence_agents(node, agent)
) STRICT;
