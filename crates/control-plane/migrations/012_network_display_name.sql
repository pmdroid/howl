ALTER TABLE howl_control.networks ADD COLUMN IF NOT EXISTS github_login text;
GRANT UPDATE (github_login) ON howl_control.networks TO howl_control_runtime;
