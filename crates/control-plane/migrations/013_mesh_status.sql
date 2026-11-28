CREATE TABLE IF NOT EXISTS howl_control.mesh_status (
    account_id bytea NOT NULL,
    device_id bytea NOT NULL,
    device_sequence bytea NOT NULL CHECK (octet_length(device_sequence) = 8),
    authority_head bytea NOT NULL CHECK (octet_length(authority_head) = 32),
    designation_digest bytea NOT NULL CHECK (octet_length(designation_digest) = 32),
    seen_at timestamptz NOT NULL,
    paths jsonb NOT NULL,
    PRIMARY KEY (account_id, device_id),
    FOREIGN KEY (account_id, device_id) REFERENCES howl_control.enrolled_devices(account_id, device_id)
);

GRANT SELECT, INSERT ON howl_control.mesh_status TO howl_control_runtime;
GRANT UPDATE (device_sequence, authority_head, designation_digest, seen_at, paths)
    ON howl_control.mesh_status TO howl_control_runtime;
