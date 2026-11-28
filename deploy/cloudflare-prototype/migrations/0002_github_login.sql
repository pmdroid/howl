CREATE TABLE web_logins (
  state_digest TEXT PRIMARY KEY NOT NULL,
  verifier_digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE web_sessions (
  token_digest TEXT PRIMARY KEY NOT NULL,
  account TEXT NOT NULL REFERENCES owners(account),
  expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX web_login_expiry ON web_logins (expires_at);
CREATE INDEX web_session_expiry ON web_sessions (expires_at);
