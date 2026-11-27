use sha2::{Digest, Sha256};

pub fn signing_bytes(
    audience: [u8; 32],
    subject: [u8; 32],
    operation: &str,
    nonce: [u8; 32],
    token_digest: [u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let mut bytes = b"howl/control-proof/v1\0".to_vec();
    bytes.extend(audience);
    bytes.extend(subject);
    bytes.extend(Sha256::digest(operation.as_bytes()));
    bytes.extend(nonce);
    bytes.extend(token_digest);
    bytes.extend(Sha256::digest(body));
    bytes
}
