CREATE TABLE owners (
  account TEXT PRIMARY KEY NOT NULL,
  token_digest TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE device_links (
  id TEXT PRIMARY KEY NOT NULL,
  secret_digest TEXT NOT NULL UNIQUE,
  device TEXT NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  name TEXT NOT NULL,
  account TEXT REFERENCES owners(account),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied')),
  expires_at INTEGER NOT NULL,
  UNIQUE (account, device)
) STRICT;

CREATE INDEX device_link_expiry ON device_links (state, expires_at);

CREATE TABLE device_proofs (
  account TEXT NOT NULL,
  device TEXT NOT NULL,
  nonce TEXT NOT NULL,
  attempt TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (account, device, nonce),
  FOREIGN KEY (account, device) REFERENCES device_links(account, device)
) STRICT;

CREATE INDEX device_proof_expiry ON device_proofs (expires_at);

CREATE TABLE inboxes (
  account TEXT NOT NULL,
  recipient TEXT NOT NULL,
  last_cursor INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account, recipient),
  FOREIGN KEY (account, recipient) REFERENCES device_links(account, device)
) STRICT;

CREATE TABLE envelopes (
  account TEXT NOT NULL,
  recipient TEXT NOT NULL,
  cursor INTEGER NOT NULL,
  message TEXT NOT NULL,
  sender TEXT NOT NULL,
  digest TEXT NOT NULL,
  ciphertext BLOB,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (account, recipient, message),
  UNIQUE (account, recipient, cursor),
  FOREIGN KEY (account, recipient) REFERENCES inboxes(account, recipient),
  FOREIGN KEY (account, sender) REFERENCES device_links(account, device)
) STRICT;

CREATE INDEX envelope_expiry ON envelopes (expires_at);
