use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    delivery::Id,
    identity::{LocalIdentity, PeerCertificate},
    transport::RelayUrl,
};

const DOMAIN: &[u8] = b"howl/peer-address/v1\0";
const SET_DOMAIN: &[u8] = b"howl/peer-routes/v2\0";
const LIFETIME: u64 = 86_400_000;
const FUTURE_SKEW: u64 = 120_000;
const HEADER_LEN: usize = 1 + 32 + 32 + 8 + 8;
const ADDRESS_LEN: usize = 1 + 16 + 2;
const BODY_LEN: usize = HEADER_LEN + ADDRESS_LEN;
pub const HINT_LEN: usize = BODY_LEN + 64;
pub(crate) const MAX_ROUTES: usize = 8;
const MAX_RELAY_LEN: usize = 255;
pub(crate) const MAX_ROUTE_SET_LEN: usize =
    HEADER_LEN + 1 + MAX_ROUTES * ADDRESS_LEN + 2 + MAX_RELAY_LEN + 64;

pub struct RouteHint([u8; HINT_LEN]);

impl RouteHint {
    pub(crate) fn issue(
        identity: &LocalIdentity,
        address: SocketAddr,
        now: u64,
    ) -> io::Result<Self> {
        let mut bytes = [0; HINT_LEN];
        bytes[..HEADER_LEN].copy_from_slice(&header(identity, 1, now)?);
        bytes[HEADER_LEN..BODY_LEN].copy_from_slice(&encode_address(address)?);
        let signature = identity.sign(&[DOMAIN, &bytes[..BODY_LEN]].concat());
        bytes[BODY_LEN..].copy_from_slice(&signature);
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; HINT_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HINT_LEN] {
        &self.0
    }

    pub fn device(&self) -> &Id {
        self.field(1)
    }

    pub fn issued(&self) -> &[u8; 8] {
        self.field(65)
    }

    pub fn expires(&self) -> &[u8; 8] {
        self.field(73)
    }

    pub fn address(&self, peer: &PeerCertificate, now: u64) -> io::Result<Option<SocketAddr>> {
        let fresh = verify(&self.0, 1, DOMAIN, peer, now)?;
        let address = decode_address(&self.0[HEADER_LEN..BODY_LEN])?;
        Ok(fresh.then_some(address))
    }

    fn field<const N: usize>(&self, offset: usize) -> &[u8; N] {
        self.0[offset..].first_chunk().expect("fixed address hint")
    }
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) struct Routes {
    pub(crate) addresses: Vec<SocketAddr>,
    pub(crate) relay: Option<RelayUrl>,
}

pub(crate) fn sign_routes(
    identity: &LocalIdentity,
    routes: &Routes,
    now: u64,
) -> io::Result<Vec<u8>> {
    if routes.addresses.len() > MAX_ROUTES {
        return Err(invalid("too many advertised addresses"));
    }
    let mut body = header(identity, 2, now)?.to_vec();
    body.push(routes.addresses.len() as u8);
    for address in &routes.addresses {
        body.extend(encode_address(*address)?);
    }
    let relay = routes
        .relay
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    body.extend((relay.len() as u16).to_be_bytes());
    body.extend(relay.as_bytes());
    decode_routes(&body)?;
    body.extend(identity.sign(&[SET_DOMAIN, &body].concat()));
    Ok(body)
}

pub(crate) fn read_routes(
    bytes: &[u8],
    peer: &PeerCertificate,
    now: u64,
) -> io::Result<Option<Routes>> {
    if !(HEADER_LEN + 1 + 2 + 64..=MAX_ROUTE_SET_LEN).contains(&bytes.len()) {
        return Err(invalid("invalid signed route set length"));
    }
    let fresh = verify(bytes, 2, SET_DOMAIN, peer, now)?;
    let routes = decode_routes(&bytes[..bytes.len() - 64])?;
    Ok(fresh.then_some(routes))
}

fn decode_routes(body: &[u8]) -> io::Result<Routes> {
    let count = usize::from(body[HEADER_LEN]);
    let offset = HEADER_LEN + 1 + count * ADDRESS_LEN;
    if count > MAX_ROUTES || body.len() < offset + 2 {
        return Err(invalid("invalid signed route set address count"));
    }
    let addresses = body[HEADER_LEN + 1..offset]
        .as_chunks::<ADDRESS_LEN>()
        .0
        .iter()
        .map(|address| decode_address(address))
        .collect::<io::Result<Vec<_>>>()?;
    let length = usize::from(u16::from_be_bytes(field(body, offset)));
    let relay = &body[offset + 2..];
    if length != relay.len() || length > MAX_RELAY_LEN || (count == 0 && length == 0) {
        return Err(invalid("invalid route set relay length"));
    }
    let relay = if relay.is_empty() {
        None
    } else {
        let url = std::str::from_utf8(relay)
            .map_err(io::Error::other)?
            .parse::<RelayUrl>()
            .map_err(io::Error::other)?;
        if url.scheme() != "https" || url.as_str().as_bytes() != relay {
            return Err(invalid("invalid route set relay URL"));
        }
        Some(url)
    };
    Ok(Routes { addresses, relay })
}

fn header(identity: &LocalIdentity, version: u8, now: u64) -> io::Result<[u8; HEADER_LEN]> {
    let expires = now
        .checked_add(LIFETIME)
        .ok_or_else(|| invalid("invalid address hint clock"))?;
    let certificate = identity.certificate();
    let mut header = [0; HEADER_LEN];
    header[0] = version;
    header[1..33].copy_from_slice(certificate.device_id());
    header[33..65].copy_from_slice(&certificate.fingerprint());
    header[65..73].copy_from_slice(&now.to_be_bytes());
    header[73..81].copy_from_slice(&expires.to_be_bytes());
    Ok(header)
}

fn verify(
    bytes: &[u8],
    version: u8,
    domain: &[u8],
    peer: &PeerCertificate,
    now: u64,
) -> io::Result<bool> {
    if bytes[0] != version
        || &field::<32>(bytes, 1) != peer.device_id()
        || field::<32>(bytes, 33) != peer.fingerprint()
    {
        return Err(invalid("address hint does not match the pinned device"));
    }
    let issued = u64::from_be_bytes(field(bytes, 65));
    let expires = u64::from_be_bytes(field(bytes, 73));
    if !matches!(expires.checked_sub(issued), Some(1..=LIFETIME))
        || issued > now.saturating_add(FUTURE_SKEW)
    {
        return Err(invalid("invalid address hint time"));
    }
    let end = bytes.len() - 64;
    peer.verify_signature(&[domain, &bytes[..end]].concat(), &field(bytes, end))?;
    Ok(now < expires)
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    *bytes[offset..].first_chunk().expect("sized address field")
}

fn encode_address(address: SocketAddr) -> io::Result<[u8; ADDRESS_LEN]> {
    validate_address(address)?;
    let mut bytes = [0; ADDRESS_LEN];
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&ip.octets());
        }
    }
    bytes[17..].copy_from_slice(&address.port().to_be_bytes());
    Ok(bytes)
}

fn decode_address(bytes: &[u8]) -> io::Result<SocketAddr> {
    let ip = match bytes[0] {
        4 if bytes[5..17] == [0; 12] => IpAddr::V4(Ipv4Addr::from(field(bytes, 1))),
        6 => IpAddr::V6(Ipv6Addr::from(field(bytes, 1))),
        _ => return Err(invalid("invalid address hint IP")),
    };
    let address = SocketAddr::new(ip, u16::from_be_bytes(field(bytes, 17)));
    validate_address(address)?;
    Ok(address)
}

pub fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}

pub(crate) fn validate_address(address: SocketAddr) -> io::Result<()> {
    let invalid_address = match address {
        SocketAddr::V4(address) => address.ip().octets()[0] >= 224,
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
    fn route_sets_sign_the_lan_addresses_and_home_relay() {
        let root = tempfile::tempdir().unwrap();
        let local = LocalIdentity::load_or_create(&root.path().join("local")).unwrap();
        let other = LocalIdentity::load_or_create(&root.path().join("other")).unwrap();
        let cert = local.certificate();
        let routes = Routes {
            addresses: vec![
                "192.168.7.30:3030".parse().unwrap(),
                "[fd00::7]:3030".parse().unwrap(),
            ],
            relay: Some("https://relay.example.test/".parse().unwrap()),
        };
        let signed = sign_routes(&local, &routes, 50).unwrap();
        assert_eq!(read_routes(&signed, &cert, 55).unwrap(), Some(routes));
        assert_eq!(read_routes(&signed, &cert, 50 + LIFETIME).unwrap(), None);
        assert!(read_routes(&signed, &other.certificate(), 55).is_err());
        let mut tampered = signed;
        tampered[HEADER_LEN + 5] ^= 1;
        assert!(read_routes(&tampered, &cert, 55).is_err());

        let relay_only = Routes {
            addresses: vec![],
            relay: Some("https://relay.example.test/".parse().unwrap()),
        };
        let signed = sign_routes(&local, &relay_only, 50).unwrap();
        assert_eq!(read_routes(&signed, &cert, 55).unwrap(), Some(relay_only));
        assert!(
            sign_routes(
                &local,
                &Routes {
                    addresses: vec![],
                    relay: None
                },
                50
            )
            .is_err()
        );
    }

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
