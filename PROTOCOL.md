# Howl wire protocol proposal v1

This is the envelope proposed for review under PAS-2499. Peers authenticate transport independently of the sender and authorization carried by an envelope.

## Encoding

Encode unsigned integers as fixed-width big endian. Timestamps are Unix seconds in UTC. IDs, digests, and keys in the envelope are 32 raw bytes. Text prefixes below end with the byte 00. Lengths count bytes.

The encoded header has these fields in order.

| Field | Encoding and validation |
| --- | --- |
| Version | u8, value 1 |
| Intent | u8, 1 for chat or 2 for wake |
| Channel | Channel ID |
| Sender | Account ID, device ID, signing key ID |
| Membership epoch | u64, at least 1 |
| Sender sequence | u64, at least 1 |
| Created at, expires at | u64 each |
| Message ID | 32 fresh uniformly random bytes |
| Commitment | 32 bytes from the key derivation below |
| Recipient count | u16, 1 through 64 |
| Recipients | Count triples of account ID, device ID, encryption key ID |

Sort recipient triples by unsigned lexicographic byte order. Reject duplicate account and device pairs, unknown keys, and identities outside the authenticated roster. Use the identity roles in [IDENTITY.md](IDENTITY.md) for key IDs. The sender sequence increases per channel, account, device, and signing key across membership epochs. Reserve it durably before producing a new envelope. Allocate a new sequence for each new envelope and resend the stored bytes for a retry.

After the header, encode one wrap per recipient in header order. Each wrap consists of the 32-byte HPKE encapsulation followed by 48 bytes of wrapped key and tag. Then encode a u32 ciphertext length, the ciphertext and its 16-byte tag, and a 64-byte detached signature. The ciphertext length includes the tag and must be between 17 and 65,552 bytes. Reject unknown values, malformed lengths, excess bytes, and frames larger than 77,112 bytes. For chat, the plaintext is a nonempty UTF-8 string. For wake, it consists of a 32-byte target session ID followed by zero or more UTF-8 bytes. Text is carried as encoded, without normalization.

## Cryptography

Generate an independent 32-byte content secret for every new envelope, using system randomness. Set the salt to the message ID and extract once with HKDF-SHA-512. Derive a 32-byte data key with info `04 78` followed by ASCII `DERIVEKEY`. Derive the 32-byte commitment from the same extraction with ASCII info `COMMITKEY`. These are the key and commitment derivations from the AWS Encryption SDK suite 0x0478. [AWS Encryption SDK derivation rules](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/transitive-requirements.md)

Seal the plaintext with AES-256-GCM, a 12-byte all-zero nonce, and AAD consisting of ASCII `howl/payload/v1`, a zero byte, and the encoded header. This is one encryption under a newly derived key. Never re-encrypt on retry. Erase the transient content secret and data key after use.

For each recipient, run one fresh HPKE base-mode sender context with DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256, and AES-128-GCM (identifiers 0x0020, 0x0001, 0x0001). Use ASCII `howl/wrap/v1` followed by a zero byte as info. Seal the 32-byte content secret at HPKE sequence zero. Use as AAD the SHA-256 digest of the encoded header followed by that recipient's exact encoded triple. [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)

Sign ASCII `howl/envelope/v1`, one zero byte, and the entire encoded frame preceding the signature, using the roster-bound device signing key. Use pure Ed25519 with strict verification as in the identity specification. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)

Use the exact transport ALPN `howl/mesh/1` for this format. Reject an unsupported ALPN or a mismatched envelope version. A future version gets its own ALPN and cryptographic domains. Never fall back to an older profile following an authentication or parsing failure. Policy chooses which versions a peer may offer before connecting.

## Receive and dispatch

Check lengths and canonical encoding before resolving keys or allocating plaintext. Verify the signature, authenticated current roster, local recipient entry, and operation scope. Open the local HPKE wrap and compare the derived commitment in constant time before opening the payload. Validate the plaintext encoding before recording an accepted message. On failure, emit no plaintext, delivery acknowledgment, or action.

For v1 chat, require expiry zero. For wake, require `created_at < expires_at` and a lifetime of at most 300 seconds. Require the local time to be at or after `created_at - 30` (saturating at zero) and strictly before `expires_at`. Check at admission and again before dispatch. A node that detects a backward clock jump pauses wake admission and dispatch until it can establish a trustworthy current time.

Durably index both the signed message ID and the tuple (channel, sender account, sender device, signing key ID, sequence) with the signed-frame digest. Use a uniqueness constraint for each index. If a frame is an exact retry, repeat the prior durable delivery acknowledgment without requeueing. If an existing identifier maps to different authenticated bytes, reject the conflicting frame and retain evidence. Admit valid out-of-order frames as distinct arrivals. Commit inbox acceptance and eligible queue insertion together before acknowledging. Atomically claim each wake at most once, and check current membership, session, and required local grant before acting. Preserve deduplication records for at least the time a frame could still produce a wake.

## Threat model and fixtures

A relay can reorder, delay, drop, or duplicate frames. Authentication covers the routing context, recipient list, all wraps, and ciphertext. The channel and epoch prevent byte-for-byte replay into another context. If a malicious authorized sender signs two envelopes for the same sequence, any recipient that obtains both detects the conflict. A conflicting validly signed frame sent to an isolated recipient can be compared when peers exchange those signed bytes. A single signed envelope passes the commitment check for the same content secret across recipients.

Use [the wake frame fixture](spikes/protocol/wake-v1.json) for interoperability. The fixture uses deterministic test secrets and a fixed initial receiver state. Derive the HPKE keys from the listed IKM values with RFC 9180 `DeriveKeyPair`. All fixture byte strings are hex. At the specified receive time, expect the encoded plaintext, a durable acknowledgment after acceptance, and one queued wake.

| Mutation | Expected result |
| --- | --- |
| Change the channel, intent, expiry, recipient order, or ciphertext without resigning | Reject before opening the payload. |
| Present the unchanged envelope to a different channel or under a different epoch | Reject before opening the payload. |
| Receive `frame_with_wrong_wrapped_secret` | Reject the commitment before decryption. |
| Receive `frame_with_resigned_bad_payload_tag` | Fail payload authentication. |
| Receive the fixture exactly at expiry | Reject the wake even if the signature and commitment verify. |
| Deliver the frame twice at the fixture time, including across a receiver restart | Return the same durable delivery acknowledgment and retain one queued wake. |

Use the [HPKE Base mode vectors](https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1.1) and [Ed25519 vectors](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) to check library selection independently of the envelope.
