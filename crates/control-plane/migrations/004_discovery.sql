CREATE TABLE IF NOT EXISTS howl_control.route_hints (
    account_id bytea NOT NULL,
    device_id bytea NOT NULL,
    device_sequence bytea NOT NULL CHECK (octet_length(device_sequence) = 8),
    authority_head bytea NOT NULL CHECK (octet_length(authority_head) = 32),
    designation_digest bytea NOT NULL CHECK (octet_length(designation_digest) = 32),
    issued_millis bigint NOT NULL CHECK (issued_millis >= 0),
    expires_millis bigint NOT NULL CHECK (expires_millis > issued_millis),
    hint bytea NOT NULL CHECK (octet_length(hint) = 164),
    PRIMARY KEY (account_id, device_id),
    FOREIGN KEY (account_id, device_id) REFERENCES howl_control.enrolled_devices(account_id, device_id)
);

GRANT SELECT, INSERT ON howl_control.route_hints TO howl_control_runtime;
GRANT UPDATE (device_sequence, authority_head, designation_digest, issued_millis, expires_millis, hint)
    ON howl_control.route_hints TO howl_control_runtime;
