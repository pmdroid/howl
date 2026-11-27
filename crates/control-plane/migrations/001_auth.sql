CREATE SCHEMA IF NOT EXISTS howl_control;
REVOKE ALL ON SCHEMA howl_control FROM PUBLIC;

CREATE TABLE IF NOT EXISTS howl_control.pending_logins (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    device_id bytea NOT NULL CHECK (octet_length(device_id) = 32),
    signing_key bytea NOT NULL CHECK (octet_length(signing_key) = 32),
    provider_code bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    next_poll timestamptz NOT NULL,
    poll_interval integer NOT NULL CHECK (poll_interval BETWEEN 1 AND 900),
    poll_lease timestamptz,
    poll_attempt bytea CHECK (octet_length(poll_attempt) = 32)
);

CREATE TABLE IF NOT EXISTS howl_control.proofs (
    nonce bytea PRIMARY KEY CHECK (octet_length(nonce) = 32),
    subject bytea NOT NULL CHECK (octet_length(subject) = 32),
    operation text NOT NULL,
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS howl_control.pending_sessions (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    github_id bigint NOT NULL CHECK (github_id > 0),
    device_id bytea NOT NULL CHECK (octet_length(device_id) = 32),
    signing_key bytea NOT NULL CHECK (octet_length(signing_key) = 32),
    expires_at timestamptz NOT NULL,
    revoked boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS howl_control.tokens (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    session_id bytea NOT NULL REFERENCES howl_control.pending_sessions(id) ON DELETE CASCADE,
    refresh boolean NOT NULL,
    expires_at timestamptz NOT NULL,
    spent boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS howl_control_tokens_session ON howl_control.tokens (session_id);
CREATE INDEX IF NOT EXISTS howl_control_login_expiry ON howl_control.pending_logins (expires_at);
CREATE INDEX IF NOT EXISTS howl_control_proof_expiry ON howl_control.proofs (expires_at);
CREATE INDEX IF NOT EXISTS howl_control_session_expiry ON howl_control.pending_sessions (expires_at);

GRANT USAGE ON SCHEMA howl_control TO howl_control_runtime;
GRANT SELECT, INSERT, DELETE ON howl_control.pending_logins TO howl_control_runtime;
GRANT UPDATE (next_poll, poll_interval, poll_lease, poll_attempt) ON howl_control.pending_logins TO howl_control_runtime;
GRANT SELECT, INSERT, DELETE ON howl_control.proofs TO howl_control_runtime;
GRANT SELECT, INSERT, DELETE ON howl_control.pending_sessions TO howl_control_runtime;
GRANT UPDATE (revoked) ON howl_control.pending_sessions TO howl_control_runtime;
GRANT SELECT, INSERT ON howl_control.tokens TO howl_control_runtime;
GRANT UPDATE (spent) ON howl_control.tokens TO howl_control_runtime;
