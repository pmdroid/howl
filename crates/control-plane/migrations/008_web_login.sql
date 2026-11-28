CREATE TABLE IF NOT EXISTS howl_control.web_logins (
    state_digest bytea PRIMARY KEY CHECK (octet_length(state_digest) = 32),
    verifier_digest bytea NOT NULL CHECK (octet_length(verifier_digest) = 32),
    expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS howl_control.web_sessions (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    github_id bigint NOT NULL CHECK (github_id > 0),
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS howl_control_web_login_expiry ON howl_control.web_logins (expires_at);
CREATE INDEX IF NOT EXISTS howl_control_web_session_expiry ON howl_control.web_sessions (expires_at);

GRANT SELECT, INSERT, DELETE ON howl_control.web_logins, howl_control.web_sessions TO howl_control_runtime;
