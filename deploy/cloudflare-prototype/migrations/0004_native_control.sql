CREATE TABLE control_networks (
  github_id INTEGER PRIMARY KEY NOT NULL,
  channel TEXT NOT NULL UNIQUE,
  founder TEXT NOT NULL,
  snapshot TEXT,
  signer TEXT,
  revision INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE control_members (
  github_id INTEGER NOT NULL REFERENCES control_networks(github_id),
  device TEXT NOT NULL,
  peer TEXT NOT NULL,
  name TEXT,
  requested_at INTEGER,
  approved_at INTEGER,
  PRIMARY KEY (github_id, device)
) STRICT;

CREATE TABLE control_sessions (
  id TEXT PRIMARY KEY NOT NULL,
  github_id INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  signing_key TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
) STRICT;

CREATE TABLE control_tokens (
  digest TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES control_sessions(id) ON DELETE CASCADE,
  refresh INTEGER NOT NULL CHECK (refresh IN (0, 1)),
  expires_at INTEGER NOT NULL,
  rotation TEXT
) STRICT;

CREATE INDEX control_token_session ON control_tokens (session_id);

CREATE TABLE control_challenges (
  nonce TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES control_sessions(id) ON DELETE CASCADE,
  operation TEXT NOT NULL,
  token_digest TEXT NOT NULL REFERENCES control_tokens(digest) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE control_route_hints (
  github_id INTEGER NOT NULL,
  device TEXT NOT NULL,
  payload BLOB NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (github_id, device),
  FOREIGN KEY (github_id, device) REFERENCES control_members(github_id, device)
) STRICT;

CREATE TABLE control_policy (
  github_id INTEGER PRIMARY KEY NOT NULL REFERENCES control_networks(github_id),
  offline_mailbox INTEGER NOT NULL DEFAULT 0 CHECK (offline_mailbox IN (0, 1))
) STRICT;

CREATE TABLE control_mesh_status (
  github_id INTEGER NOT NULL,
  device TEXT NOT NULL,
  seen_at INTEGER NOT NULL,
  paths TEXT NOT NULL,
  PRIMARY KEY (github_id, device),
  FOREIGN KEY (github_id, device) REFERENCES control_members(github_id, device)
) STRICT;

ALTER TABLE owners ADD COLUMN github_id INTEGER;
ALTER TABLE owners ADD COLUMN github_login TEXT;
CREATE UNIQUE INDEX owner_github_id ON owners (github_id);
ALTER TABLE device_links ADD COLUMN native_nonce TEXT;
ALTER TABLE device_links ADD COLUMN native_account TEXT REFERENCES owners(account);
ALTER TABLE device_links ADD COLUMN native_credentials TEXT;
ALTER TABLE device_links ADD COLUMN requested_at INTEGER;
ALTER TABLE device_links ADD COLUMN approved_at INTEGER;
