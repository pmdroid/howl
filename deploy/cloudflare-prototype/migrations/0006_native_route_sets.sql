CREATE TABLE control_route_sets (
  github_id INTEGER NOT NULL,
  device TEXT NOT NULL,
  payload BLOB NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (github_id, device),
  FOREIGN KEY (github_id, device) REFERENCES control_members(github_id, device)
) STRICT;
