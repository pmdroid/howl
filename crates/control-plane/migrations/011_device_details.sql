ALTER TABLE howl_control.device_links
    ADD COLUMN IF NOT EXISTS suggested_name text CHECK (char_length(suggested_name) BETWEEN 1 AND 80);

ALTER TABLE howl_control.device_link_requests
    ADD COLUMN IF NOT EXISTS requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE howl_control.device_link_requests ALTER COLUMN requested_at SET DEFAULT clock_timestamp();
GRANT UPDATE (approved_at) ON howl_control.device_link_requests TO howl_control_runtime;

ALTER TABLE howl_control.network_requests ADD COLUMN IF NOT EXISTS requested_at timestamptz;
ALTER TABLE howl_control.network_requests ALTER COLUMN requested_at SET DEFAULT clock_timestamp();

CREATE TABLE IF NOT EXISTS howl_control.device_details (
    github_id bigint NOT NULL REFERENCES howl_control.networks(github_id),
    device_id bytea NOT NULL CHECK (octet_length(device_id) = 32),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    name text CHECK (char_length(name) BETWEEN 1 AND 80),
    requested_at timestamptz,
    approved_at timestamptz,
    PRIMARY KEY (github_id, device_id)
);

GRANT SELECT, INSERT ON howl_control.device_details TO howl_control_runtime;
GRANT UPDATE (name, requested_at, approved_at) ON howl_control.device_details TO howl_control_runtime;
