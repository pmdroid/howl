pub mod cli;

mod authority;
mod store;

pub use authority::{Authority, AuthorityHead, AuthorityRecord, Id, Import};
pub use store::AuthorityStore;
mod membership;
mod pairing;
mod recovery;

pub use membership::{Designation, DeviceCertificate, Floor, revoke, verify_revocation};
pub use pairing::{Enroll, PairingOffer, PairingResponse, PairingTicket};
pub use recovery::RecoveryPackage;

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::SigningKey;

    use crate::identity::LocalIdentity;

    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn owner() -> (AuthorityHead, Designation) {
        let genesis = AuthorityRecord::genesis(&key(1), &key(2));
        let digest = genesis.digest();
        let head = Authority::import([genesis], digest, digest)
            .unwrap()
            .head()
            .unwrap();
        let designation = Designation::issue(head, 1, &key(1), &key(3), &[]).unwrap();
        (head, designation)
    }

    #[test]
    fn binds_enrollment_to_all_candidate_keys_and_rejects_durable_replay() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("operator");
        let (_, designation) = owner();
        let identity = LocalIdentity::load_or_create(&temp.path().join("candidate")).unwrap();
        let other = LocalIdentity::load_or_create(&temp.path().join("substitute")).unwrap();
        let peer = identity.certificate();
        let signer = key(3);
        assert!(
            PairingTicket::create(
                &designation,
                &signer,
                &peer,
                other.certificate().fingerprint(),
                1,
                100
            )
            .is_err()
        );
        let (ticket, offer) =
            PairingTicket::create(&designation, &signer, &peer, peer.fingerprint(), 1, 100)
                .unwrap();
        ticket.save(&state).unwrap();
        let request =
            |state: &Path, response: &PairingResponse, now| -> Result<DeviceCertificate, _> {
                PairingTicket::load(state, &offer).unwrap().enroll(Enroll {
                    state,
                    designation: &designation,
                    signer: &signer,
                    peer: &peer,
                    offer: &offer,
                    response,
                    now,
                })
            };
        assert!(
            offer
                .respond(&designation, &other, ticket.invitation_secret(), 120)
                .is_err()
        );
        assert!(
            offer
                .respond(&designation, &identity, ticket.invitation_secret(), 700)
                .is_err()
        );

        let foreign = offer
            .respond(&designation, &identity, &[21; 32], 120)
            .unwrap();
        assert!(request(&state, &foreign, 120).is_err());
        let mut tampered = offer.as_bytes().to_vec();
        let index = tampered.len() - 80;
        tampered[index] ^= 1;
        assert!(
            PairingOffer::from_bytes(&tampered)
                .unwrap()
                .respond(&designation, &identity, ticket.invitation_secret(), 120)
                .is_err()
        );

        let response = offer
            .respond(&designation, &identity, ticket.invitation_secret(), 120)
            .unwrap();
        assert!(request(&state, &response, 700).is_err());
        let certificate = request(&state, &response, 130).unwrap();
        assert!(certificate.matches(&peer));
        assert!(!certificate.matches(&other.certificate()));
        assert_eq!(
            DeviceCertificate::verify(certificate.as_bytes(), &designation).unwrap(),
            certificate
        );
        assert!(request(&state, &response, 130).is_err());
    }

    #[test]
    fn authenticates_offline_recovery_material_before_succession() {
        let (head, _) = owner();
        let (package, unlock) = RecoveryPackage::export(head, &key(2)).unwrap();
        assert!(package.unlock(head, &[0; 32]).is_err());
        let mut tampered = package.as_bytes().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            RecoveryPackage::from_bytes(&tampered)
                .unwrap()
                .unlock(head, &unlock)
                .is_err()
        );
        let recovery = RecoveryPackage::from_bytes(package.as_bytes())
            .unwrap()
            .unlock(head, &unlock)
            .unwrap();
        let replacement = AuthorityRecord::recover(head, &recovery, &key(4), &key(5)).unwrap();
        let genesis = AuthorityRecord::genesis(&key(1), &key(2));
        let digest = replacement.digest();
        let state = Authority::import([genesis, replacement], head.account, digest).unwrap();
        assert_eq!(
            state.head().unwrap().root,
            key(4).verifying_key().to_bytes()
        );
        assert!(package.unlock(state.head().unwrap(), &unlock).is_err());
    }

    #[test]
    fn current_designation_requires_signed_ordered_revocation_floors() {
        let (head, active) = owner();
        let floor = Floor {
            device: [7; 32],
            sequence: 4,
        };
        let revocation = revoke(&active, &key(3), floor).unwrap();
        assert_eq!(verify_revocation(&active, &revocation).unwrap(), floor);
        assert!(revoke(&active, &key(4), floor).is_err());
        let second = Designation::issue(head, 2, &key(1), &key(4), &[floor]).unwrap();
        assert_eq!(second.revoked_through(floor.device), 4);
        assert!(verify_revocation(&second, &revocation).is_err());
        assert!(Designation::issue(head, 3, &key(1), &key(4), &[floor, floor]).is_err());
    }
}
