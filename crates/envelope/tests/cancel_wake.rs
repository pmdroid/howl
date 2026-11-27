use howl_envelope::{
    AuthorizedSender, Body, DeviceAddress, Error, Intent, ReceivePolicy, RecipientSecret, Routing,
    SigningKey, inspect_unverified, open, seal, seal_integration,
};

#[test]
fn cancellation_is_an_encrypted_signed_wake_control_without_a_wake_deadline() {
    let sender = DeviceAddress {
        account: [1; 32],
        device: [2; 32],
    };
    let recipient = DeviceAddress {
        account: [1; 32],
        device: [3; 32],
    };
    let signer = SigningKey::from_bytes(&[4; 32]);
    let receiver = RecipientSecret::from_bytes(recipient, &[5; 32]).unwrap();
    let recipients = [receiver.public_recipient()];
    let routing = Routing {
        channel: [6; 32],
        sender,
        epoch: 1,
        sequence: 2,
        created_at: 1000,
        expires_at: 0,
    };
    let wake = [7; 32];
    let frame = seal(routing, Body::CancelWake { wake }, &signer, &recipients).unwrap();
    let intent = inspect_unverified(&frame).unwrap().intent;
    assert_eq!(intent, Intent::CancelWake);
    assert!(intent.requires_wake_permission());
    assert!(!intent.is_wake());
    assert!(!frame.windows(wake.len()).any(|chunk| chunk == wake));

    let mut policy = ReceivePolicy {
        channel: routing.channel,
        epoch: routing.epoch,
        now: 4000,
        sender: AuthorizedSender {
            address: sender,
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
    assert_eq!(opened.body, Body::CancelWake { wake });
    assert_eq!(opened.integration, None);

    assert_eq!(
        seal(
            Routing {
                expires_at: routing.created_at + 10,
                ..routing
            },
            Body::CancelWake { wake },
            &signer,
            &recipients,
        ),
        Err(Error::Encoding)
    );
    assert_eq!(
        seal_integration(
            routing,
            Body::CancelWake { wake },
            &signer,
            &recipients,
            [8; 32],
        ),
        Err(Error::Unauthorized)
    );
}
