ALTER TABLE howl_control.networks
    ADD COLUMN IF NOT EXISTS account_signer bytea
    CHECK (account_signer IS NULL OR (octet_length(account_signer) = 60 AND snapshot IS NOT NULL));

GRANT UPDATE (account_signer) ON howl_control.networks TO howl_control_runtime;
