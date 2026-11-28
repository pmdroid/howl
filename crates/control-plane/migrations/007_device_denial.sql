ALTER TABLE howl_control.network_requests
    ADD COLUMN IF NOT EXISTS denied boolean NOT NULL DEFAULT false;

GRANT UPDATE (denied) ON howl_control.network_requests TO howl_control_runtime;
