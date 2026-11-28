CREATE TABLE IF NOT EXISTS howl_control.networks (
    github_id bigint PRIMARY KEY CHECK (github_id > 0),
    channel bytea NOT NULL UNIQUE CHECK (octet_length(channel) = 32),
    founder bytea NOT NULL CHECK (octet_length(founder) = 32),
    founder_signing bytea NOT NULL CHECK (octet_length(founder_signing) = 32),
    snapshot jsonb,
    account_id bytea CHECK (octet_length(account_id) = 32),
    authority_head bytea CHECK (octet_length(authority_head) = 32),
    designation_digest bytea CHECK (octet_length(designation_digest) = 32),
    CHECK (num_nonnulls(snapshot, account_id, authority_head, designation_digest) IN (0, 4))
);

CREATE TABLE IF NOT EXISTS howl_control.network_requests (
    github_id bigint NOT NULL REFERENCES howl_control.networks(github_id),
    device_id bytea NOT NULL CHECK (octet_length(device_id) = 32),
    candidate jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (github_id, device_id)
);

GRANT SELECT, INSERT ON howl_control.networks TO howl_control_runtime;
GRANT UPDATE (snapshot, account_id, authority_head, designation_digest) ON howl_control.networks TO howl_control_runtime;
GRANT SELECT, INSERT, DELETE ON howl_control.network_requests TO howl_control_runtime;
GRANT UPDATE (expires_at) ON howl_control.network_requests TO howl_control_runtime;

CREATE OR REPLACE FUNCTION howl_control.pin_new_network(target bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    WITH inserted AS (
        INSERT INTO howl_control.enrollment_pins (github_id, account_id, authority_head, designation_digest)
        SELECT github_id, account_id, authority_head, designation_digest
        FROM howl_control.networks WHERE github_id = target AND snapshot IS NOT NULL
        ON CONFLICT DO NOTHING RETURNING 1
    )
    SELECT EXISTS(SELECT FROM inserted);
$$;
REVOKE ALL ON FUNCTION howl_control.pin_new_network(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION howl_control.pin_new_network(bigint) TO howl_control_runtime;
