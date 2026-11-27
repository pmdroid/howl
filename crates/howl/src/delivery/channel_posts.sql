ALTER TABLE channel_event_addresses RENAME TO channel_event_addresses_v0;
CREATE TABLE channel_event_addresses (
    cursor INTEGER PRIMARY KEY REFERENCES inbox(id),
    outbound INTEGER NOT NULL CHECK (outbound IN (0, 1)),
    recipient BLOB CHECK (length(recipient) = 64)
) STRICT;
INSERT INTO channel_event_addresses SELECT * FROM channel_event_addresses_v0;
DROP TABLE channel_event_addresses_v0;
PRAGMA user_version = 1;
