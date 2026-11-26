# Howl security requirements

A peer, relay, hosted mailbox, model provider, and isolated agent can each behave independently of the local human. Pairing pins account identity. Transport authenticates the endpoint, signed records authorize the device, and the local broker authorizes effects. The daemon checks each boundary at the point where it uses it.

## Required behavior

- Authenticate the local user before granting session capabilities. Neither a harness permission response nor an agent credential is an input that can satisfy user authentication.
- Start observation with an explicitly selected snapshot, writable disposable scratch, and scoped mesh communication. Enforce mount, credential, process, and egress policy outside the harness. Decline to launch when the isolation policy cannot be applied.
- Treat model providers and remote peers as recipients of any data deliberately sent to them. Enforce routing and egress grants before sending data. Keep keys, approval tokens, and confidential payloads out of traces.
- Recheck epoch, expiry, deduplication, and local authorization when dequeuing a wake or starting a privileged operation. On learning of a revocation or pause, persist it and invalidate affected pending work before admitting new work. Revalidate durable state on restart.
- During a network partition, apply the newest locally authenticated state. When synchronization resumes, verify the chain against the persisted head before accepting records or authorizing queued work.
- For root loss, require the recovery private key and proofs from the replacement authority. If both root and recovery private keys are lost, reject claimed successors for that account. Establish a new genesis and require each peer to pair again.

## Succession and approval test cases

| Given | Attempt | Expected result |
| --- | --- | --- |
| Genesis at generation 0, sequence 0 | Add a linked rotation carrying old and new root signatures | The account ID stays fixed. The head advances to generation 0, sequence 1. |
| A current rotated head | Replay genesis or submit a rotation signed by the retired root | Retain the current head and reject fresh authority. |
| Root key unavailable, recovery key available | Recover using the pinned head, installed recovery proof, and replacement proofs | Advance to generation 1, sequence 0. Accept designations from the new root only. |
| Root and recovery keys unavailable | Present a replacement root without the established recovery proof | Reject succession. Pair with the new genesis as a distinct account. |
| An accepted rotation | Encounter another correctly signed rotation for the same previous head and sequence | Persist evidence and suspend affected authorization until a trusted head is selected. |
| A valid device under a superseded designation | Attempt to wake an agent with the old certificate | Decline the wake. A current roster and certificate must authorize it. |
| Observer-only session | Agent invokes the grant method or replays the challenge from a different session | Reject the request with no grant. |
| A valid human grant | Restart the daemon, then reuse it in the same active session and generation | Apply the persisted grant if its scope still matches. |
| A valid human grant | Revoke the grant while an action is queued, then dequeue the action | Decline the action. |
| A real builder grant | Use it to apply an artifact or use an external capability | Require the separate authorization for the requested effect. |
