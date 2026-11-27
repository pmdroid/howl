use howl_envelope::{
    AgentReply, AgentRole, AuthorizedSender, Body, DeviceAddress, Error, Id, Intent, ReceivePolicy,
    RecipientSecret, Routing, SigningKey, inspect_unverified, open, open_history, seal,
    seal_integration,
};

const CHANNEL: Id = [1; 32];
const INTEGRATION: Id = [2; 32];
const SENDER: DeviceAddress = DeviceAddress {
    account: [3; 32],
    device: [4; 32],
};
const RECEIVER: DeviceAddress = DeviceAddress {
    account: [3; 32],
    device: [5; 32],
};
const CREATED: u64 = 1000;
const EXPIRY: u64 = 1100;

fn route(expires_at: u64) -> Routing {
    Routing {
        channel: CHANNEL,
        sender: SENDER,
        epoch: 1,
        sequence: 1,
        created_at: CREATED,
        expires_at,
    }
}

#[test]
fn integration_chat_authenticates_its_encrypted_origin_and_cannot_pass_as_human_chat() {
    let signer = SigningKey::from_bytes(&[6; 32]);
    let receiver = RecipientSecret::from_bytes(RECEIVER, &[7; 32]).unwrap();
    let recipients = [receiver.public_recipient()];
    let mut policy = ReceivePolicy {
        channel: CHANNEL,
        epoch: 1,
        now: CREATED,
        sender: AuthorizedSender {
            address: SENDER,
            signing_key: signer.verifying_key().to_bytes(),
            chat: true,
            wake: false,
        },
        authorized_recipients: &recipients,
    };
    let mut frame = seal_integration(
        route(0),
        Body::Chat("hello from the integration"),
        &signer,
        &recipients,
        INTEGRATION,
    )
    .unwrap();
    let metadata = inspect_unverified(&frame).unwrap();
    assert_eq!(metadata.intent, Intent::IntegrationChat);
    assert!(metadata.intent.is_integration());
    assert!(
        !frame
            .windows(INTEGRATION.len())
            .any(|chunk| chunk == INTEGRATION)
    );
    let opened = open(&frame, &policy, &receiver).unwrap();
    assert_eq!(opened.integration, Some(INTEGRATION));
    assert_eq!(
        opened.body,
        Body::Chat("hello from the integration".to_owned())
    );

    policy.sender.chat = false;
    assert_eq!(open(&frame, &policy, &receiver), Err(Error::Unauthorized));
    policy.sender.chat = true;
    frame[1] = Intent::Chat as u8;
    assert_eq!(open(&frame, &policy, &receiver), Err(Error::Signature));

    let legacy = seal(route(0), Body::Chat("human"), &signer, &recipients).unwrap();
    let opened = open(&legacy, &policy, &receiver).unwrap();
    assert_eq!(opened.metadata.intent, Intent::Chat);
    assert_eq!(opened.integration, None);
}

#[test]
fn integration_wake_requires_wake_permission_and_expires_at_its_signed_deadline() {
    let signer = SigningKey::from_bytes(&[6; 32]);
    let receiver = RecipientSecret::from_bytes(RECEIVER, &[7; 32]).unwrap();
    let recipients = [receiver.public_recipient()];
    let session = [8; 32];
    let frame = seal_integration(
        route(EXPIRY),
        Body::Wake {
            session,
            text: "review this",
        },
        &signer,
        &recipients,
        INTEGRATION,
    )
    .unwrap();
    let mut policy = ReceivePolicy {
        channel: CHANNEL,
        epoch: 1,
        now: CREATED,
        sender: AuthorizedSender {
            address: SENDER,
            signing_key: signer.verifying_key().to_bytes(),
            chat: true,
            wake: false,
        },
        authorized_recipients: &recipients,
    };
    assert_eq!(open(&frame, &policy, &receiver), Err(Error::Unauthorized));
    policy.sender.wake = true;
    policy.sender.chat = false;
    let opened = open(&frame, &policy, &receiver).unwrap();
    assert!(opened.metadata.intent.is_wake());
    assert_eq!(opened.metadata.intent, Intent::IntegrationWake);
    assert_eq!(opened.integration, Some(INTEGRATION));
    assert_eq!(
        opened.body,
        Body::Wake {
            session,
            text: "review this".to_owned(),
        }
    );
    policy.now = EXPIRY;
    assert_eq!(open(&frame, &policy, &receiver), Err(Error::Stale));
    assert_eq!(
        open_history(&frame, &policy, &receiver)
            .unwrap()
            .integration,
        Some(INTEGRATION)
    );

    let role = AgentRole::Reviewer;
    let reply = Body::AgentReply(AgentReply {
        agent: role.agent_id(&SENDER.device),
        role,
        in_reply_to: [9; 32],
        context_digest: [10; 32],
        text: "ready",
    });
    assert_eq!(
        seal_integration(route(0), reply, &signer, &recipients, INTEGRATION),
        Err(Error::Unauthorized)
    );
}
