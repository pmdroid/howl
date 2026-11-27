use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::{
    delivery::NewIntegrationRun,
    enrollment::{AuthorityRecord, AuthorityStore, Designation, Enroll, PairingTicket},
    identity::{LocalIdentity, StateDirectory},
    remote_mcp::IntegrationPermission,
};

use super::*;

const CHANNEL: Id = [0x12; 32];
const OTHER_CHANNEL: Id = [0x34; 32];

fn enrolled(state: &Path) {
    let identity = LocalIdentity::load_or_create(state).unwrap();
    let device = identity.certificate();
    let root = SigningKey::from_bytes(&[1; 32]);
    let recovery = SigningKey::from_bytes(&[2; 32]);
    let signer = SigningKey::from_bytes(&[3; 32]);
    let authority = AuthorityStore::open(state).unwrap();
    let genesis = AuthorityRecord::genesis(&root, &recovery);
    let account = genesis.digest();
    authority.initialize(&[genesis], account, account).unwrap();
    let designation =
        Designation::issue(authority.current().unwrap(), 1, &root, &signer, &[]).unwrap();
    let (ticket, offer) =
        PairingTicket::create(&designation, &signer, &device, device.fingerprint(), 1, 100)
            .unwrap();
    let response = offer
        .respond(&designation, &identity, ticket.invitation_secret(), 110)
        .unwrap();
    let enrollment = ticket
        .enroll(Enroll {
            state,
            designation: &designation,
            signer: &signer,
            peer: &device,
            offer: &offer,
            response: &response,
            now: 120,
        })
        .unwrap();
    let directory = StateDirectory::open(state).unwrap();
    directory
        .write("enrollment-designation", designation.as_bytes())
        .unwrap();
    directory
        .write("enrollment-certificate", enrollment.as_bytes())
        .unwrap();
    directory
        .write("enrollment-signer-key", &signer.to_bytes())
        .unwrap();
    let profile = crate::enrollment::profile::Profile::load(state, &device)
        .unwrap()
        .unwrap();
    for channel in [CHANNEL, OTHER_CHANNEL] {
        profile
            .issue(
                &crate::enrollment::RosterStore::open(state, channel).unwrap(),
                channel,
                false,
                vec![profile.member(*device.device_id(), 7).unwrap()],
            )
            .unwrap();
    }
}

fn integration(
    id: &str,
    channels: Vec<Id>,
    permission: IntegrationPermission,
) -> IntegrationPrincipal {
    IntegrationPrincipal {
        id: id.to_owned(),
        channels,
        permissions: vec![permission],
        revision: [0; 32],
        configuration: Arc::new("unused".into()),
    }
}

#[test]
fn resources_require_signed_channel_membership_and_own_run() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("node");
    enrolled(&state);
    let authorized = integration("reader", vec![CHANNEL], IntegrationPermission::Read);
    let writer = integration("writer", vec![CHANNEL], IntegrationPermission::Send);
    let both = integration(
        "reader",
        vec![CHANNEL, OTHER_CHANNEL],
        IntegrationPermission::Read,
    );
    let channel = hex::encode(CHANNEL);
    let other = hex::encode(OTHER_CHANNEL);
    let agents = format!("{CHANNEL_URI}{channel}/agents");
    assert_eq!(
        resource_value(&state, &authorized, &agents)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let no_access_for_writer = resource_value(&state, &writer, &agents).unwrap_err();
    let hidden_channel =
        resource_value(&state, &authorized, &format!("{CHANNEL_URI}{other}/agents")).unwrap_err();
    assert_eq!(no_access_for_writer.code, hidden_channel.code);
    assert_eq!(no_access_for_writer.message, hidden_channel.message);

    let run = node::prepare_integration_run(
        &state,
        NewIntegrationRun {
            owner: "reader",
            key: "resource-fixture",
            channel: CHANNEL,
            peer: [0x56; 32],
            target: [0x78; 32],
            lifetime: 60,
            text: "Review the proposed changes",
        },
    )
    .unwrap();
    let run = hex::encode(run.id);
    let result = format!("{CHANNEL_URI}{channel}/runs/{run}/result");
    assert_eq!(
        resource_value(&state, &authorized, &result).unwrap()["status"],
        "working"
    );
    let other_owner = integration("another-reader", vec![CHANNEL], IntegrationPermission::Read);
    let hidden_run = resource_value(&state, &other_owner, &result).unwrap_err();
    let wrong_channel = format!("{CHANNEL_URI}{other}/runs/{run}/result");
    let hidden_run_with_channel = resource_value(&state, &both, &wrong_channel).unwrap_err();
    assert_eq!(hidden_run.code, hidden_run_with_channel.code);
    assert_eq!(hidden_run.message, hidden_run_with_channel.message);
}

#[test]
fn prompt_and_template_discovery_are_bounded_and_stable() {
    let discovered = list_resource_templates(None).unwrap();
    assert_eq!(discovered.resource_templates.len(), 5);
    for template in discovered.resource_templates {
        let uri = template
            .uri_template
            .replace("{channel}", &hex::encode(CHANNEL))
            .replace("{run}", &hex::encode([0x56; 32]));
        assert_eq!(resource_path(&uri).unwrap().0, CHANNEL);
    }
    let prompts = list_prompts(None).unwrap();
    assert_eq!(
        prompts
            .prompts
            .iter()
            .map(|prompt| prompt.name.as_str())
            .collect::<Vec<_>>(),
        ["brainstorm", "debate", "review"],
    );
    let topic = "Store encrypted history on the node";
    let prompt = GetPromptRequestParams::new("review")
        .with_arguments(json!({"topic": topic}).as_object().unwrap().clone());
    let GetPromptResponse::Complete(response) = get_prompt(prompt).unwrap() else {
        panic!("expected completed prompt");
    };
    assert_eq!(response.messages[0].role, Role::User);
    assert!(
        response.messages[0]
            .content
            .as_text()
            .unwrap()
            .text
            .contains(topic)
    );
    assert!(get_prompt(GetPromptRequestParams::new("review")).is_err());

    let (first, next) = page(0..30, 0);
    assert_eq!(first, (0..PAGE_SIZE).collect::<Vec<_>>());
    let next = offset(Some(PaginatedRequestParams::default().with_cursor(next))).unwrap();
    let (last, next) = page(0..30, next);
    assert_eq!(last, (PAGE_SIZE..30).collect::<Vec<_>>());
    assert_eq!(next, None);
}
