CREATE TABLE control_mailbox_inboxes (
  github_id INTEGER NOT NULL,
  recipient TEXT NOT NULL,
  cursor INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (github_id, recipient),
  FOREIGN KEY (github_id, recipient) REFERENCES control_members(github_id, device)
) STRICT;

CREATE TABLE control_mailbox_envelopes (
  github_id INTEGER NOT NULL,
  recipient TEXT NOT NULL,
  cursor INTEGER NOT NULL,
  channel TEXT NOT NULL,
  epoch TEXT NOT NULL,
  sender_account TEXT NOT NULL,
  sender_device TEXT NOT NULL,
  sequence TEXT NOT NULL,
  message TEXT NOT NULL,
  sent_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  digest TEXT NOT NULL,
  ciphertext BLOB,
  PRIMARY KEY (github_id, recipient, cursor),
  UNIQUE (github_id, recipient, message),
  UNIQUE (github_id, recipient, channel, epoch, sender_account, sender_device, sequence),
  FOREIGN KEY (github_id, recipient) REFERENCES control_mailbox_inboxes(github_id, recipient)
) STRICT;

CREATE INDEX control_mailbox_expiry ON control_mailbox_envelopes (expires_at);
