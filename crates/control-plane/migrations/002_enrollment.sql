CREATE TABLE IF NOT EXISTS howl_control.enrollment_pins (
    github_id bigint PRIMARY KEY CHECK (github_id > 0),
    account_id bytea NOT NULL UNIQUE CHECK (octet_length(account_id) = 32),
    authority_head bytea NOT NULL CHECK (octet_length(authority_head) = 32),
    designation_digest bytea NOT NULL CHECK (octet_length(designation_digest) = 32)
);

CREATE TABLE IF NOT EXISTS howl_control.enrolled_devices (
    account_id bytea NOT NULL REFERENCES howl_control.enrollment_pins(account_id),
    device_id bytea NOT NULL CHECK (octet_length(device_id) = 32),
    signing_key bytea NOT NULL CHECK (octet_length(signing_key) = 32),
    authority_head bytea NOT NULL CHECK (octet_length(authority_head) = 32),
    designation_digest bytea NOT NULL CHECK (octet_length(designation_digest) = 32),
    sequence bytea NOT NULL CHECK (octet_length(sequence) = 8),
    records jsonb NOT NULL,
    PRIMARY KEY (account_id, device_id)
);

GRANT SELECT ON howl_control.enrollment_pins TO howl_control_runtime;
GRANT SELECT, INSERT ON howl_control.enrolled_devices TO howl_control_runtime;
GRANT UPDATE (signing_key, authority_head, designation_digest, sequence, records)
    ON howl_control.enrolled_devices TO howl_control_runtime;
