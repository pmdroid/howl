CREATE TABLE IF NOT EXISTS howl_control.device_links (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    secret_digest bytea UNIQUE NOT NULL CHECK (octet_length(secret_digest) = 32),
    peer bytea NOT NULL CHECK (octet_length(peer) = 257),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    github_id bigint REFERENCES howl_control.networks(github_id),
    channel bytea CHECK (octet_length(channel) = 32),
    designation bytea CHECK (octet_length(designation) = 32),
    sealed_credentials bytea CHECK (sealed_credentials IS NULL OR github_id IS NOT NULL),
    expires_at timestamptz NOT NULL,
    CHECK (num_nonnulls(github_id,channel,designation) IN (0,3))
);

CREATE TABLE IF NOT EXISTS howl_control.device_link_requests (
    github_id bigint NOT NULL REFERENCES howl_control.networks(github_id),
    device_id bytea NOT NULL CHECK (octet_length(device_id) = 32),
    peer bytea NOT NULL CHECK (octet_length(peer) = 257),
    decision text CHECK (decision IN ('approved','denied')),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (github_id,device_id)
);

CREATE INDEX IF NOT EXISTS howl_control_link_expiry ON howl_control.device_links(expires_at);
CREATE INDEX IF NOT EXISTS howl_control_link_request_expiry ON howl_control.device_link_requests(expires_at) WHERE decision IS DISTINCT FROM 'denied';

GRANT SELECT, INSERT, DELETE ON howl_control.device_links, howl_control.device_link_requests TO howl_control_runtime;
GRANT UPDATE (github_id,channel,designation,nonce,sealed_credentials) ON howl_control.device_links TO howl_control_runtime;
GRANT UPDATE (decision,expires_at) ON howl_control.device_link_requests TO howl_control_runtime;
