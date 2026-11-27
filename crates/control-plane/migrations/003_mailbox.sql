CREATE SCHEMA IF NOT EXISTS howl_mailbox;
REVOKE ALL ON SCHEMA howl_mailbox FROM PUBLIC;

CREATE TABLE IF NOT EXISTS howl_mailbox.inboxes (
    recipient_account bytea NOT NULL CHECK (octet_length(recipient_account) = 32),
    recipient_device bytea NOT NULL CHECK (octet_length(recipient_device) = 32),
    cursor bigint NOT NULL DEFAULT 0 CHECK (cursor >= 0),
    PRIMARY KEY (recipient_account, recipient_device)
);

CREATE TABLE IF NOT EXISTS howl_mailbox.envelopes (
    cursor bigint NOT NULL CHECK (cursor > 0),
    recipient_account bytea NOT NULL CHECK (octet_length(recipient_account) = 32),
    recipient_device bytea NOT NULL CHECK (octet_length(recipient_device) = 32),
    channel bytea NOT NULL CHECK (octet_length(channel) = 32),
    epoch bytea NOT NULL CHECK (octet_length(epoch) = 8),
    sender_account bytea NOT NULL CHECK (octet_length(sender_account) = 32),
    sender_device bytea NOT NULL CHECK (octet_length(sender_device) = 32),
    sequence bytea NOT NULL CHECK (octet_length(sequence) = 8),
    message bytea NOT NULL CHECK (octet_length(message) = 32),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    sent_at bigint NOT NULL,
    expires_at bigint NOT NULL CHECK (expires_at > sent_at),
    ciphertext bytea CHECK (octet_length(ciphertext) BETWEEN 1 AND 77112),
    PRIMARY KEY (recipient_account, recipient_device, cursor),
    UNIQUE (recipient_account, recipient_device, message),
    UNIQUE (recipient_account, recipient_device, channel, epoch, sender_account, sender_device, sequence)
);

CREATE INDEX IF NOT EXISTS mailbox_inbox ON howl_mailbox.envelopes (recipient_account, recipient_device, cursor)
    WHERE ciphertext IS NOT NULL;
CREATE INDEX IF NOT EXISTS mailbox_expiry ON howl_mailbox.envelopes (expires_at, cursor);

GRANT USAGE ON SCHEMA howl_mailbox TO howl_control_runtime;
GRANT SELECT, INSERT ON howl_mailbox.inboxes TO howl_control_runtime;
GRANT UPDATE (cursor) ON howl_mailbox.inboxes TO howl_control_runtime;
GRANT SELECT, INSERT, DELETE ON howl_mailbox.envelopes TO howl_control_runtime;
GRANT UPDATE (ciphertext) ON howl_mailbox.envelopes TO howl_control_runtime;
