ALTER TABLE howl_control.pending_logins
    ADD COLUMN IF NOT EXISTS join_network boolean NOT NULL DEFAULT false;
