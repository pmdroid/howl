use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    delivery::Id,
    identity::{LocalIdentity, PeerCertificate},
};

const DOMAIN: &[u8] = b"howl/peer-address/v1\0";
const LIFETIME: u64 = 86_400_000;
const FUTURE_SKEW: u64 = 120_000;
const BODY_LEN: usize = 1 + 32 + 32 + 8 + 8 + 1 + 16 + 2;
pub(crate) const HINT_LEN: usize = BODY_LEN + 64;

pub(crate) struct RouteHint([u8; HINT_LEN]);

impl RouteHint {
    pub(crate) fn issue(
        identity: &LocalIdentity,
        address: SocketAddr,
        now: u64,
    ) -> io::Result<Self> {
        let expires = now
            .checked_add(LIFETIME)
            .ok_or_else(|| invalid("invalid address hint clock"))?;
        validate_address(address)?;
        let mut bytes = [0; HINT_LEN];
        let certificate = identity.certificate();
        bytes[0] = 1;
        bytes[1..33].copy_from_slice(certificate.device_id());
        bytes[33..65].copy_from_slice(&certificate.fingerprint());
        bytes[65..73].copy_from_slice(&now.to_be_bytes());
        bytes[73..81].copy_from_slice(&expires.to_be_bytes());
        match address.ip() {
            IpAddr::V4(ip) => {
                bytes[81] = 4;
                bytes[82..86].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes[81] = 6;
                bytes[82..98].copy_from_slice(&ip.octets());
            }
        }
        bytes[98..100].copy_from_slice(&address.port().to_be_bytes());
        let signature = identity.sign(&[DOMAIN, &bytes[..BODY_LEN]].concat());
        bytes[BODY_LEN..].copy_from_slice(&signature);
        Ok(Self(bytes))
    }

    pub(crate) fn from_bytes(bytes: [u8; HINT_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; HINT_LEN] {
        &self.0
    }

    pub(crate) fn device(&self) -> &Id {
        self.field(1)
    }

    pub(crate) fn issued(&self) -> &[u8; 8] {
        self.field(65)
    }

    pub(crate) fn address(
        &self,
        peer: &PeerCertificate,
        now: u64,
    ) -> io::Result<Option<SocketAddr>> {
        if self.0[0] != 1
            || self.device() != peer.device_id()
            || self.field::<32>(33) != &peer.fingerprint()
        {
            return Err(invalid("address hint does not match the pinned device"));
        }
        let issued = u64::from_be_bytes(*self.issued());
        let expires = u64::from_be_bytes(*self.field(73));
        if !matches!(expires.checked_sub(issued), Some(1..=LIFETIME))
            || issued > now.saturating_add(FUTURE_SKEW)
        {
            return Err(invalid("invalid address hint time"));
        }
        peer.verify_signature(
            &[DOMAIN, &self.0[..BODY_LEN]].concat(),
            self.field(BODY_LEN),
        )?;
        let ip = match self.0[81] {
            4 if self.0[86..98] == [0; 12] => IpAddr::V4(Ipv4Addr::from(*self.field(82))),
            6 => IpAddr::V6(Ipv6Addr::from(*self.field(82))),
            _ => return Err(invalid("invalid address hint IP")),
        };
        let address = SocketAddr::new(ip, u16::from_be_bytes(*self.field(98)));
        validate_address(address)?;
        Ok((now < expires).then_some(address))
    }

    fn field<const N: usize>(&self, offset: usize) -> &[u8; N] {
        self.0[offset..].first_chunk().expect("fixed address hint")
    }
}

pub(crate) fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}

fn validate_address(address: SocketAddr) -> io::Result<()> {
    let invalid_address = match address {
        SocketAddr::V4(address) => address.ip().is_broadcast(),
        SocketAddr::V6(address) => {
            address.scope_id() != 0
                || address.flowinfo() != 0
                || address.ip().is_unicast_link_local()
                || address.ip().to_ipv4_mapped().is_some()
        }
    };
    let ip = address.ip();
    if address.port() == 0 || ip.is_unspecified() || ip.is_multicast() || invalid_address {
        return Err(invalid(
            "address hint requires a literal unicast socket address",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PeerTrust;

    #[test]
    fn hints_require_the_current_pinned_certificate_and_signature() {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("local");
        let peer = LocalIdentity::load_or_create(&root.path().join("peer")).unwrap();
        let unknown = LocalIdentity::load_or_create(&root.path().join("unknown")).unwrap();
        let trust = PeerTrust::open(&local).unwrap();
        let peer_cert = peer.certificate();
        trust.pin(&peer_cert, &peer_cert.fingerprint()).unwrap();
        let address = "[2001:db8::5]:3232".parse().unwrap();
        let issued = 10_000;
        let hint = RouteHint::issue(&peer, address, issued).unwrap();
        assert_eq!(
            hint.address(&trust.pinned(hint.device()).unwrap(), issued)
                .unwrap(),
            Some(address)
        );

        let mut changed = *hint.as_bytes();
        changed[99] ^= 1;
        assert!(
            RouteHint::from_bytes(changed)
                .address(&peer_cert, issued)
                .is_err()
        );
        let other_hint = RouteHint::issue(&unknown, address, issued).unwrap();
        assert!(trust.pinned(other_hint.device()).is_err());
        assert!(other_hint.address(&peer_cert, issued).is_err());
    }

    #[test]
    fn cached_hints_have_a_bounded_validity_window() {
        let root = tempfile::tempdir().unwrap();
        let local = LocalIdentity::load_or_create(&root.path().join("local")).unwrap();
        let certificate = local.certificate();
        let address = "192.0.2.4:3030".parse().unwrap();
        let issued = FUTURE_SKEW + 1;
        let hint = RouteHint::issue(&local, address, issued).unwrap();
        assert!(hint.address(&certificate, 0).is_err());
        assert_eq!(
            hint.address(&certificate, issued + LIFETIME - 1).unwrap(),
            Some(address)
        );
        assert_eq!(hint.address(&certificate, issued + LIFETIME).unwrap(), None);
        for invalid_address in [
            "0.0.0.0:3030",
            "192.0.2.1:0",
            "224.0.0.1:3030",
            "[fe80::1]:3030",
        ] {
            assert!(RouteHint::issue(&local, invalid_address.parse().unwrap(), issued).is_err());
        }
    }
}
