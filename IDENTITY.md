# Howl identity and authority

An account, device, agent, and human approval represent different authorities. A hosted account or relay routes requests to Howl identities. Each peer verifies the authority for a request against locally pinned account history and channel membership.

## Account and keys

An account begins with a genesis body containing the root and recovery Ed25519 public keys. The account ID is the SHA-256 digest of the canonical genesis body, including its record prefix. Root changes preserve that ID. Pin the account ID and current authority head through a trusted pairing exchange. Verify both genesis proofs when importing the chain.

| Key | Custody | Authority |
| --- | --- | --- |
| Account root | User-controlled signing store | Root succession, membership signer designation |
| Recovery | Separate offline user-controlled store | Account root recovery and recovery key replacement |
| Membership signer | User-controlled enrollment service or local keystore | Issue device certificates and sign channel rosters |
| Device signing | Daemon keystore outside agent contexts | Sign device messages and acknowledge durable receipt |
| iroh endpoint | Daemon transport keystore | Authenticate a transport endpoint |
| Device encryption | Daemon keystore outside agent contexts | Open X25519 HPKE wraps for messages |
| Human approval | Local approval broker protected by OS user authentication | Grant and revoke named capabilities in a session |
| Agent credential | Isolated agent process, issued by the daemon | Invoke a named subset of local mesh methods in one session |

Use independent key material across roles. Associate each issued key with one role and reject an attempt to bind the same public key bytes to multiple roles in an account. Retain public history for verification. The daemon stores private keys with restrictive access and excludes them from snapshots, logs, and artifacts. Retired decryption keys remain available for authorized historical reads only while local retention policy requires them.

## Record encoding

Use a binary body with the ASCII prefix `howl/identity/v1/` followed by the ASCII record name and one zero byte. Encode integers as unsigned, fixed-width big endian. Encode timestamps and counters as u64. All IDs, public keys, and digests are 32 raw bytes. Ed25519 signatures are 64 raw bytes, use pure Ed25519, and cover the full body including the prefix. Verify against a valid prime-order public key and require a canonical signature. A SHA-256 digest of the full body identifies a record. Signature trailers are fixed-width and follow the signer order below. Reject trailing bytes and noncanonical records.

| Record | Body fields in order | Signer order |
| --- | --- | --- |
| `genesis` | initial root, recovery | initial root, recovery |
| `rotate` | account ID, previous authority head, recovery generation, root sequence, new root | current root, new root |
| `recover` | account ID, previous authority head, recovery generation, root sequence, new root, next recovery | current recovery, new root, next recovery |
| `membership-signer` | account ID, authority head, designation sequence, signer key, floor count, floor entries | current root, signer key |
| `device` | account ID, designation digest, device ID, device sequence, signing key, endpoint key, encryption key | designated signer, device signing key |
| `device-revoke` | account ID, designation digest, device ID, greatest revoked device sequence | designated signer |
| `roster` | owner account ID, designation digest, channel ID, preceding roster digest, epoch, pause flag, member count, member entries | owner's designated signer |

Generate each device ID from 32 bytes of system randomness and keep it across key changes. Validate possession of the endpoint and encryption keys during enrollment over authenticated endpoint and HPKE challenges before issuing the device certificate. Key IDs for wire use are SHA-256 over ASCII `howl/key/v1/`, the ASCII role `device-signing` or `device-encryption`, one zero byte, and the raw public key. A roster entry pins the entire permitted device certificate digest, so a new certificate or an endpoint change takes effect through a new roster.

## Succession and roster authority

Genesis initializes recovery generation and root sequence to zero. A rotation increments root sequence by one, retains the recovery key and generation, and links to the exact current authority head. A recovery increments generation by one, resets the root sequence to zero, and links to the exact current authority head. When the recovery key is unchanged, its two proof slots contain the same signature. Reject overflow, repeated roots, and rollback to a prior head. Persist the accepted head before admitting work authorized by it.

A root designation starts at sequence one within an authority head and increments by one per replacement. Encode the designation floor count as u16 (zero through 4,096). Each floor entry contains a device ID and a positive u64 revoked-through sequence. Reject duplicate device IDs and require lexicographic order by device ID. Device sequences start at one and remain monotonic across authority heads. When the root or designation changes, suspend fresh channel work until a locally accepted current designation and channel roster confirm permitted device certificates. Channel creation pins the owner account and channel ID. Accept roster updates only from the current designation for that owner, with the next epoch and exact predecessor roster digest. At epoch one use a zero predecessor digest. Encode the pause flag as u8 (0 active, 1 paused) and the member count as u16 (0 through 64). Each entry contains a member account ID, device ID, permitted certificate digest, and nonzero u8 role mask. Bits 0, 1, and 2 grant receive, chat send, and wake request respectively. Reject other bits and repeated account and device pairs. Sort entries lexicographically by their account and device IDs. An epoch change replaces the accepted set atomically. A paused roster suspends channel actions until a later active epoch.

Accept a device revocation only for the current designation of the device account, with a positive device sequence. Each replacement designation carries the predecessor's final per-device revocation floors and signs them as part of the designation. Peers import these floors even if they missed individual revocations under the predecessor. A peer that already knows a greater floor keeps the greater value and suspends fresh actions for the affected device until the current authority includes that floor. Persist the maximum accepted revocation sequence for each account and device across subsequent designation and root changes. Reject certificates at or below that sequence even if a current roster pins them. Applying an authenticated revocation invalidates queued work that depends on revoked certificates. A later certificate with a higher sequence still needs a roster entry.

Persist digests before acknowledging accepted history. Accept a byte-identical replay as idempotent. Reject records with an unknown predecessor. Validate a competing successor against the retained state at its claimed predecessor before classifying it as stale. Two distinct valid authority records with the same previous head are evidence of a fork, including a recovery and a rotation with different counters. The same rule applies to distinct valid designations at one sequence and distinct valid rosters following one predecessor. Retain both proofs, stop authorizing fresh actions on the affected chain, and require an authenticated out-of-band choice of head before resuming. A device that loses trusted local state must import a fresh pin through pairing before admitting work.

## Human and agent authority

The local approval broker derives the principal from authenticated OS user presence. It issues grants scoped to the local account, device, session, principal, capability, and current session generation. A grant records an unpredictable broker challenge, an approval ID and a decision. Only the broker may consume the challenge and write the grant. Challenges are single-use and bound to the exact approval shown to the human. A grant lasts until revocation, session closure, or a generation change. Store the grant and its generation durably and consult them again before starting an authorized effect.

The observer session grants read access to a selected snapshot and scoped communication. A builder approval authorizes creation of a new isolated execution context. Applying a patch or performing an external effect uses its own scope and approval. Agent credentials identify one session and an allowed method set. Local IPC authenticates the connecting process and checks the credential, current session generation, method scope, and human grant required by the operation. A remote message may request attention. Only local policy and broker state can authorize an effect.

Use the [Ed25519 specification](https://www.rfc-editor.org/rfc/rfc8032) for signature generation. See [Security requirements](SECURITY.md) for denial and recovery cases.
