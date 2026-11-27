use std::{io, path::Path};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use howl_envelope::Id;
use rmcp::{
    ErrorData,
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize};
use sha2_10::Sha256;
use zeroize::Zeroizing;

use crate::{
    identity::StateDirectory,
    interaction::{EventPage, Message},
    node::DELIVERY_KEY,
};

const KEY_DOMAIN: &[u8] = b"howl/mcp/event-cursor-key/v1\0";
const SCOPE_DOMAIN: &[u8] = b"howl/mcp/event-cursor-scope/v1\0";
const PREFIX: &str = "v1.";
const NONCE_LEN: usize = 12;
const POSITION_LEN: usize = 8;
const TAG_LEN: usize = 16;
const ENCODED_LEN: usize = 48;

#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
pub(crate) enum CursorInput {
    Token(String),
    Beginning(#[schemars(schema_with = "zero_schema")] u64),
}

fn zero_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "integer", "const": 0})
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RemoteEventPage {
    events: Vec<RemoteEvent>,
    cursor: String,
    gap: bool,
    more: bool,
}

#[derive(Serialize, JsonSchema)]
struct RemoteEvent {
    cursor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(flatten)]
    message: Message,
}

pub(crate) struct CursorKey(Zeroizing<Id>);

impl CursorKey {
    pub(crate) fn load(state: &Path) -> io::Result<Self> {
        let state = StateDirectory::open(state)?;
        let delivery_key = state.key(DELIVERY_KEY)?;
        let mut derive =
            <Hmac<Sha256> as Mac>::new_from_slice(&*delivery_key).expect("valid HMAC key");
        derive.update(KEY_DOMAIN);
        Ok(Self(Zeroizing::new(derive.finalize().into_bytes().into())))
    }

    pub(crate) fn scoped(&self, owner: &str, channel: Id, peer: Option<Id>) -> CursorScope {
        let mut scope = SCOPE_DOMAIN.to_vec();
        scope.extend_from_slice(&(owner.len() as u64).to_be_bytes());
        scope.extend_from_slice(owner.as_bytes());
        scope.extend_from_slice(&channel);
        scope.push(u8::from(peer.is_some()));
        if let Some(peer) = peer {
            scope.extend_from_slice(&peer);
        }
        CursorScope {
            cipher: Aes256Gcm::new((&*self.0).into()),
            scope,
        }
    }
}

pub(crate) struct CursorScope {
    cipher: Aes256Gcm,
    scope: Vec<u8>,
}

impl CursorScope {
    pub(crate) fn decode(&self, input: Option<&CursorInput>) -> Result<u64, ErrorData> {
        let token = match input {
            None | Some(CursorInput::Beginning(0)) => return Ok(0),
            Some(CursorInput::Beginning(_)) => return Err(invalid()),
            Some(CursorInput::Token(token)) => token,
        };
        let encoded = token
            .strip_prefix(PREFIX)
            .filter(|value| value.len() == ENCODED_LEN)
            .ok_or_else(invalid)?;
        let mut packet = [0; NONCE_LEN + POSITION_LEN + TAG_LEN];
        let written = URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut packet)
            .map_err(|_| invalid())?;
        if written != packet.len() {
            return Err(invalid());
        }
        let (nonce, content) = packet.split_at(NONCE_LEN);
        let (position, tag) = content.split_at(POSITION_LEN);
        let mut position: [u8; POSITION_LEN] = position.try_into().map_err(|_| invalid())?;
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                &self.scope,
                &mut position,
                Tag::from_slice(tag),
            )
            .map_err(|_| invalid())?;
        Ok(u64::from_be_bytes(position))
    }

    fn encode(&self, position: u64) -> Result<String, ErrorData> {
        let mut packet = [0; NONCE_LEN + POSITION_LEN + TAG_LEN];
        let (nonce, content) = packet.split_at_mut(NONCE_LEN);
        let (position_bytes, tag_bytes) = content.split_at_mut(POSITION_LEN);
        getrandom::fill(nonce).map_err(|_| unavailable())?;
        position_bytes.copy_from_slice(&position.to_be_bytes());
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), &self.scope, position_bytes)
            .map_err(|_| unavailable())?;
        tag_bytes.copy_from_slice(&tag);
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(packet)))
    }

    pub(crate) fn page(
        &self,
        page: EventPage,
        input: Option<&CursorInput>,
        after: u64,
    ) -> Result<RemoteEventPage, ErrorData> {
        let uses_last = page
            .events
            .last()
            .is_some_and(|event| event.cursor == page.cursor);
        let events = page
            .events
            .into_iter()
            .map(|event| {
                Ok::<_, ErrorData>(RemoteEvent {
                    cursor: self.encode(event.cursor)?,
                    recipient: event.recipient,
                    message: event.message,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cursor = if let Some(last) = events.last().filter(|_| uses_last) {
            last.cursor.clone()
        } else if page.cursor == after
            && let Some(CursorInput::Token(token)) = input
        {
            token.clone()
        } else {
            self.encode(page.cursor)?
        };
        Ok(RemoteEventPage {
            events,
            cursor,
            gap: page.gap,
            more: page.more,
        })
    }
}

fn invalid() -> ErrorData {
    ErrorData::invalid_params("invalid cursor for this event feed", None)
}

fn unavailable() -> ErrorData {
    ErrorData::internal_error("event cursor unavailable", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_authenticated_cursors_and_rejects_mismatched_scope() {
        let state = tempfile::tempdir().unwrap();
        let node = state.path().join("node");
        let key = CursorKey::load(&node).unwrap();
        let channel = [1; 32];
        let peer = [2; 32];
        let scope = key.scoped("owner", channel, Some(peer));
        assert_eq!(scope.decode(None).unwrap(), 0);
        assert_eq!(scope.decode(Some(&CursorInput::Beginning(0))).unwrap(), 0);
        assert!(scope.decode(Some(&CursorInput::Beginning(7))).is_err());
        let original = scope.encode(71).unwrap();
        assert_eq!(original.len(), PREFIX.len() + ENCODED_LEN);
        assert_ne!(original, scope.encode(71).unwrap());
        let token = CursorInput::Token(original.clone());
        let reopened = CursorKey::load(&node).unwrap();
        let different_device = CursorKey::load(&state.path().join("other-node")).unwrap();
        assert_eq!(
            reopened
                .scoped("owner", channel, Some(peer))
                .decode(Some(&token))
                .unwrap(),
            71
        );
        for different in [
            reopened.scoped("different", channel, Some(peer)),
            reopened.scoped("owner", [3; 32], Some(peer)),
            reopened.scoped("owner", channel, Some([3; 32])),
            reopened.scoped("owner", channel, None),
            different_device.scoped("owner", channel, Some(peer)),
        ] {
            assert_eq!(
                different.decode(Some(&token)).unwrap_err().message,
                invalid().message
            );
        }
        let mut tampered = original.into_bytes();
        tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
        let tampered = CursorInput::Token(String::from_utf8(tampered).unwrap());
        assert_eq!(
            scope.decode(Some(&tampered)).unwrap_err().message,
            invalid().message
        );
    }
}
