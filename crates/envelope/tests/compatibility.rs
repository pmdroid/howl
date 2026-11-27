use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use ed25519_dalek::Signer;
use howl_envelope::{
    AgentReply, AgentRole, AuthorizedSender, Body, DeviceAddress, Error, MAX_FRAME_SIZE,
    ReceivePolicy, Recipient, RecipientSecret, Routing, SigningKey,
    inspect_single_recipient_unverified, inspect_unverified, open, seal,
};
use hpke::{Kem, Serializable, kem::X25519HkdfSha256};
use serde_json::Value;

fn address(id: u8) -> DeviceAddress {
    DeviceAddress {
        account: [id; 32],
        device: [id + 1; 32],
    }
}

fn fixture_bytes(fixture: &Value, name: &str) -> Vec<u8> {
    hex::decode(fixture[name].as_str().unwrap()).unwrap()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../spikes/protocol/wake-v1.json")).unwrap()
}

fn fixture_recipient(fixture: &Value) -> RecipientSecret {
    let (private, public) =
        X25519HkdfSha256::derive_keypair(&fixture_bytes(fixture, "recipient_key_ikm"));
    assert_eq!(
        public.to_bytes().as_slice(),
        fixture_bytes(fixture, "recipient_encryption_public_key")
    );
    RecipientSecret::from_bytes(address(0x22), &private.to_bytes().into()).unwrap()
}

fn policy<'a>(
    routing: Routing,
    sender_key: [u8; 32],
    recipients: &'a [Recipient],
    now: u64,
) -> ReceivePolicy<'a> {
    ReceivePolicy {
        channel: routing.channel,
        epoch: routing.epoch,
        now,
        sender: AuthorizedSender {
            address: routing.sender,
            signing_key: sender_key,
            chat: true,
            wake: true,
        },
        authorized_recipients: recipients,
    }
}

#[test]
fn opens_independent_padded_wake_vector_and_rejects_signed_failures() {
    let vector = fixture();
    let frame = fixture_bytes(&vector, "frame");
    let metadata = inspect_unverified(&frame).unwrap();
    let recipient = fixture_recipient(&vector);
    let roster = [recipient.public_recipient()];
    let mut policy = policy(
        metadata.routing,
        fixture_bytes(&vector, "sender_signing_public_key")
            .try_into()
            .unwrap(),
        &roster,
        vector["receive_at"].as_u64().unwrap(),
    );
    let opened = open(&frame, &policy, &recipient).unwrap();
    assert_eq!(opened.metadata, metadata);
    assert_eq!(
        opened.body,
        Body::Wake {
            session: [0x88; 32],
            text: "ping".to_owned()
        }
    );
    assert_eq!(
        open(
            &fixture_bytes(&vector, "frame_with_wrong_wrapped_secret"),
            &policy,
            &recipient
        ),
        Err(Error::Commitment)
    );
    assert_eq!(
        open(
            &fixture_bytes(&vector, "frame_with_resigned_bad_payload_tag"),
            &policy,
            &recipient
        ),
        Err(Error::Ciphertext)
    );

    policy.now = metadata.routing.created_at - 31;
    assert_eq!(open(&frame, &policy, &recipient), Err(Error::Stale));
    policy.now += 1;
    assert!(open(&frame, &policy, &recipient).is_ok());
    policy.now = vector["expires_at"].as_u64().unwrap();
    assert_eq!(open(&frame, &policy, &recipient), Err(Error::Stale));
}

#[test]
fn separates_signed_agent_replies_from_human_chat() {
    let signer = SigningKey::from_bytes(&[12; 32]);
    let receiver = RecipientSecret::from_bytes(address(1), &[45; 32]).unwrap();
    let recipients = [receiver.public_recipient()];
    let routing = chat_routing();
    let role = AgentRole::Reviewer;
    let reply = AgentReply {
        agent: role.agent_id(&routing.sender.device),
        role,
        in_reply_to: [41; 32],
        context_digest: [42; 32],
        text: "proposal",
    };
    let bytes = seal(routing, Body::AgentReply(reply), &signer, &recipients).unwrap();
    let policy = policy(routing, signer.verifying_key().to_bytes(), &recipients, 1);
    assert_eq!(
        open(&bytes, &policy, &receiver).unwrap().body,
        Body::AgentReply(AgentReply {
            agent: reply.agent,
            role,
            in_reply_to: reply.in_reply_to,
            context_digest: reply.context_digest,
            text: reply.text.to_owned()
        })
    );
    assert_eq!(
        seal(
            routing,
            Body::AgentReply(AgentReply {
                role: AgentRole::Architect,
                ..reply
            }),
            &signer,
            &recipients,
        ),
        Err(Error::Unauthorized)
    );
    let chat = seal(
        routing,
        Body::Chat("agent reviewer proposal"),
        &signer,
        &recipients,
    )
    .unwrap();
    assert!(matches!(
        open(&chat, &policy, &receiver).unwrap().body,
        Body::Chat(_)
    ));
}

#[test]
fn authenticates_every_recipient_and_the_expected_channel_epoch() {
    let signer = SigningKey::from_bytes(&[12; 32]);
    let first = RecipientSecret::from_bytes(address(1), &[45; 32]).unwrap();
    let second = RecipientSecret::from_bytes(address(2), &[46; 32]).unwrap();
    let outsider = RecipientSecret::from_bytes(address(3), &[47; 32]).unwrap();
    let recipients = [second.public_recipient(), first.public_recipient()];
    let routing = chat_routing();
    let body = Body::Chat("hello");
    let frame = seal(routing, body, &signer, &recipients).unwrap();
    assert_eq!(inspect_single_recipient_unverified(&frame), Ok(None));
    let direct = seal(routing, Body::Chat("hello"), &signer, &recipients[..1]).unwrap();
    assert_eq!(
        inspect_single_recipient_unverified(&direct),
        Ok(Some(address(2)))
    );
    let mut policy = policy(routing, signer.verifying_key().to_bytes(), &recipients, 1);
    for recipient in [&first, &second] {
        let opened = open(&frame, &policy, recipient).unwrap();
        assert_eq!(opened.metadata.routing, routing);
        assert_eq!(opened.body, Body::Chat("hello".to_owned()));
    }
    assert_eq!(open(&frame, &policy, &outsider), Err(Error::Unauthorized));
    policy.authorized_recipients = &recipients[1..];
    assert_eq!(open(&frame, &policy, &first), Err(Error::Unauthorized));
    policy.authorized_recipients = &recipients;
    policy.sender.chat = false;
    assert_eq!(open(&frame, &policy, &first), Err(Error::Unauthorized));
    policy.sender.chat = true;
    policy.channel = [99; 32];
    assert_eq!(open(&frame, &policy, &first), Err(Error::Context));
    policy.channel = routing.channel;
    policy.epoch += 1;
    assert_eq!(open(&frame, &policy, &first), Err(Error::Context));
    policy.epoch = routing.epoch;

    for offset in [
        138,
        228 + 64,
        228 + 96 * 2,
        frame.len() - 65,
        frame.len() - 1,
    ] {
        let mut forged = frame.clone();
        forged[offset] ^= 1;
        assert_eq!(open(&forged, &policy, &first), Err(Error::Signature));
    }
    let mut unsorted = frame.clone();
    unsorted[228..420].rotate_left(96);
    assert_eq!(inspect_unverified(&unsorted), Err(Error::Encoding));
    let mut duplicate = frame.clone();
    duplicate.copy_within(228..292, 324);
    assert_eq!(inspect_unverified(&duplicate), Err(Error::Encoding));
    assert_eq!(
        seal(routing, Body::Chat("hello"), &signer, &[recipients[0]; 2]),
        Err(Error::Encoding)
    );
}

#[test]
fn enforces_frame_and_logical_bounds() {
    let vector = fixture();
    let frame = fixture_bytes(&vector, "frame");
    for len in 0..frame.len() {
        assert_eq!(inspect_unverified(&frame[..len]), Err(Error::Encoding));
    }
    let mut overlong = frame.clone();
    overlong.push(0);
    assert_eq!(inspect_unverified(&overlong), Err(Error::Encoding));

    let signer = SigningKey::from_bytes(&[12; 32]);
    let local = RecipientSecret::from_bytes(address(1), &[45; 32]).unwrap();
    let encryption_key = local.public_recipient().encryption_key;
    let mut recipients: Vec<_> = (1..=64)
        .map(|id| Recipient {
            address: address(id),
            encryption_key,
        })
        .collect();
    let routing = chat_routing();
    let text = "x".repeat(65_532);
    let max = seal(routing, Body::Chat(&text), &signer, &recipients).unwrap();
    assert_eq!(max.len(), MAX_FRAME_SIZE);
    let policy = policy(routing, signer.verifying_key().to_bytes(), &recipients, 0);
    assert_eq!(
        open(&max, &policy, &local).unwrap().body,
        Body::Chat(text.clone())
    );
    assert_eq!(
        seal(routing, Body::Chat(&(text + "x")), &signer, &recipients),
        Err(Error::Encoding)
    );
    assert_eq!(
        seal(routing, Body::Chat(""), &signer, &recipients),
        Err(Error::Encoding)
    );
    assert_eq!(
        seal(routing, Body::Chat("x"), &signer, &[]),
        Err(Error::Encoding)
    );
    recipients.push(Recipient {
        address: address(65),
        encryption_key,
    });
    assert_eq!(
        seal(routing, Body::Chat("x"), &signer, &recipients),
        Err(Error::Encoding)
    );
}

#[test]
fn rejects_authenticated_noncanonical_padding_and_invalid_text() {
    let vector = fixture();
    let frame = fixture_bytes(&vector, "frame");
    let metadata = inspect_unverified(&frame).unwrap();
    let recipient = fixture_recipient(&vector);
    let roster = [recipient.public_recipient()];
    let signer = SigningKey::from_bytes(
        &fixture_bytes(&vector, "sender_signing_seed")
            .try_into()
            .unwrap(),
    );
    let policy = policy(
        metadata.routing,
        signer.verifying_key().to_bytes(),
        &roster,
        vector["receive_at"].as_u64().unwrap(),
    );
    let key: [u8; 32] = fixture_bytes(&vector, "data_key").try_into().unwrap();
    let cipher = Aes256Gcm::new((&key).into());
    let mut padded = vec![0; 256];
    padded[0..4].copy_from_slice(&36u32.to_be_bytes());
    padded[4..40].copy_from_slice(&fixture_bytes(&vector, "plaintext"));
    let mut nonzero = padded.clone();
    nonzero[40] = 1;
    let mut extra_block = padded.clone();
    extra_block.resize(512, 0);
    let mut long_length = padded.clone();
    long_length[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut short_wake = padded.clone();
    short_wake[0..4].copy_from_slice(&31u32.to_be_bytes());
    short_wake[35..40].fill(0);
    padded[39] = 0xff;

    for mut invalid in [nonzero, extra_block, long_length, short_wake, padded] {
        let mut updated = frame[..404].to_vec();
        let aad = [b"howl/payload/v1\0".as_slice(), &frame[..324]].concat();
        let len = u32::try_from(invalid.len() + 16).unwrap();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&[0; 12]), &aad, &mut invalid)
            .unwrap();
        updated.extend_from_slice(&len.to_be_bytes());
        updated.extend_from_slice(&invalid);
        updated.extend_from_slice(&tag);
        let signature = signer.sign(&[b"howl/envelope/v1\0".as_slice(), &updated].concat());
        updated.extend_from_slice(&signature.to_bytes());
        assert_eq!(open(&updated, &policy, &recipient), Err(Error::Encoding));
    }
}

fn chat_routing() -> Routing {
    Routing {
        channel: [10; 32],
        sender: address(20),
        epoch: 1,
        sequence: 1,
        created_at: 1,
        expires_at: 0,
    }
}
