use crate::{
    Body, DeviceAddress, Error, Id, Intent, MAX_FRAME_SIZE, MAX_RECIPIENTS, Metadata, Recipient,
    Routing, TAG_SIZE, WRAP_SIZE, key_id,
};
use zeroize::Zeroizing;

const WIRE_VERSION: u8 = 1;
const PADDING_BLOCK: usize = 256;
const MAX_PADDED_SIZE: usize = 65_536;
const FIXED_HEADER_SIZE: usize = 228;
const RECIPIENT_SIZE: usize = 96;
const SIGNATURE_SIZE: usize = 64;

pub fn validate_routing(routing: Routing, intent: Intent) -> Result<(), Error> {
    if routing.epoch == 0 || routing.sequence == 0 {
        return Err(Error::Encoding);
    }
    match intent {
        Intent::Chat if routing.expires_at == 0 => Ok(()),
        Intent::Wake
            if matches!(
                routing.expires_at.checked_sub(routing.created_at),
                Some(1..=300)
            ) =>
        {
            Ok(())
        }
        _ => Err(Error::Encoding),
    }
}

pub fn encode_header(metadata: Metadata, commitment: &Id, recipients: &[Recipient]) -> Vec<u8> {
    let mut header = Vec::with_capacity(FIXED_HEADER_SIZE + recipients.len() * RECIPIENT_SIZE);
    header.extend_from_slice(&[WIRE_VERSION, metadata.intent as u8]);
    let routing = metadata.routing;
    header.extend_from_slice(&routing.channel);
    header.extend_from_slice(&routing.sender.account);
    header.extend_from_slice(&routing.sender.device);
    header.extend_from_slice(&metadata.signing_key_id);
    header.extend_from_slice(&routing.epoch.to_be_bytes());
    header.extend_from_slice(&routing.sequence.to_be_bytes());
    header.extend_from_slice(&routing.created_at.to_be_bytes());
    header.extend_from_slice(&routing.expires_at.to_be_bytes());
    header.extend_from_slice(&metadata.message_id);
    header.extend_from_slice(commitment);
    header.extend_from_slice(&(recipients.len() as u16).to_be_bytes());
    for &recipient in recipients {
        header.extend_from_slice(&encode_recipient(recipient));
    }
    header
}

pub fn encode_recipient(recipient: Recipient) -> [u8; RECIPIENT_SIZE] {
    let mut triple = [0; RECIPIENT_SIZE];
    triple[..32].copy_from_slice(&recipient.address.account);
    triple[32..64].copy_from_slice(&recipient.address.device);
    triple[64..].copy_from_slice(&key_id(b"device-encryption", &recipient.encryption_key));
    triple
}

pub fn pad(body: Body<&str>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (session, text) = match body {
        Body::Chat(text) if !text.is_empty() => (None, text),
        Body::Wake { session, text } => (Some(session), text),
        Body::Chat(_) => return Err(Error::Encoding),
    };
    let logical_len = text
        .len()
        .checked_add(session.map_or(0, |id| id.len()))
        .ok_or(Error::Encoding)?;
    if logical_len > MAX_PADDED_SIZE - 4 {
        return Err(Error::Encoding);
    }
    let padded_len = (logical_len + 4).next_multiple_of(PADDING_BLOCK);
    let mut bytes = Zeroizing::new(Vec::with_capacity(padded_len));
    bytes.extend_from_slice(&(logical_len as u32).to_be_bytes());
    if let Some(session) = session {
        bytes.extend_from_slice(&session);
    }
    bytes.extend_from_slice(text.as_bytes());
    bytes.resize(padded_len, 0);
    Ok(bytes)
}

pub fn unpad(intent: Intent, plaintext: &[u8]) -> Result<Body<String>, Error> {
    let mut data = plaintext;
    let len = u32::from_be_bytes(take(&mut data)?) as usize;
    let (mut logical, padding) = data.split_at_checked(len).ok_or(Error::Encoding)?;
    if plaintext.len() != (len + 4).next_multiple_of(PADDING_BLOCK)
        || padding.iter().any(|byte| *byte != 0)
    {
        return Err(Error::Encoding);
    }
    let session = if intent == Intent::Wake {
        Some(take(&mut logical)?)
    } else if logical.is_empty() {
        return Err(Error::Encoding);
    } else {
        None
    };
    let text = std::str::from_utf8(logical)
        .map_err(|_| Error::Encoding)?
        .to_owned();
    Ok(match session {
        Some(session) => Body::Wake { session, text },
        None => Body::Chat(text),
    })
}

pub struct Decoded<'a> {
    pub metadata: Metadata,
    pub header: &'a [u8],
    pub signed: &'a [u8],
    pub signature: &'a [u8; SIGNATURE_SIZE],
    pub ciphertext: &'a [u8],
    pub commitment: &'a Id,
    pub wraps: &'a [u8],
    recipients: &'a [u8],
}

impl Decoded<'_> {
    pub fn recipients(&self) -> impl Iterator<Item = (&[u8], DeviceAddress, Id)> {
        self.recipients
            .as_chunks::<RECIPIENT_SIZE>()
            .0
            .iter()
            .map(|triple| {
                let [account, device, id] = triple.as_chunks::<32>().0 else {
                    unreachable!()
                };
                (
                    triple.as_slice(),
                    DeviceAddress {
                        account: *account,
                        device: *device,
                    },
                    *id,
                )
            })
    }
}

pub fn parse(frame: &[u8]) -> Result<Decoded<'_>, Error> {
    if frame.len() > MAX_FRAME_SIZE {
        return Err(Error::Encoding);
    }
    let mut bytes = frame;
    let (signed, signature) = bytes
        .split_last_chunk::<SIGNATURE_SIZE>()
        .ok_or(Error::Encoding)?;
    bytes = signed;
    let intent = match take(&mut bytes)? {
        [WIRE_VERSION, 1] => Intent::Chat,
        [WIRE_VERSION, 2] => Intent::Wake,
        _ => return Err(Error::Encoding),
    };
    let channel = take(&mut bytes)?;
    let sender = DeviceAddress {
        account: take(&mut bytes)?,
        device: take(&mut bytes)?,
    };
    let signing_key_id = take(&mut bytes)?;
    let routing = Routing {
        channel,
        sender,
        epoch: u64::from_be_bytes(take(&mut bytes)?),
        sequence: u64::from_be_bytes(take(&mut bytes)?),
        created_at: u64::from_be_bytes(take(&mut bytes)?),
        expires_at: u64::from_be_bytes(take(&mut bytes)?),
    };
    validate_routing(routing, intent)?;
    let message_id = take(&mut bytes)?;
    let (commitment, tail) = bytes.split_first_chunk().ok_or(Error::Encoding)?;
    bytes = tail;
    let count = usize::from(u16::from_be_bytes(take(&mut bytes)?));
    if count == 0 || count > MAX_RECIPIENTS {
        return Err(Error::Encoding);
    }
    let (recipients, tail) = bytes
        .split_at_checked(count * RECIPIENT_SIZE)
        .ok_or(Error::Encoding)?;
    let header = &frame[..FIXED_HEADER_SIZE + recipients.len()];
    let (wraps, mut tail) = tail
        .split_at_checked(count * WRAP_SIZE)
        .ok_or(Error::Encoding)?;
    let ciphertext_len = u32::from_be_bytes(take(&mut tail)?) as usize;
    if ciphertext_len != tail.len()
        || !(PADDING_BLOCK + TAG_SIZE..=MAX_PADDED_SIZE + TAG_SIZE).contains(&ciphertext_len)
        || !(ciphertext_len - TAG_SIZE).is_multiple_of(PADDING_BLOCK)
    {
        return Err(Error::Encoding);
    }

    let decoded = Decoded {
        metadata: Metadata {
            routing,
            intent,
            signing_key_id,
            message_id,
        },
        header,
        signed,
        signature,
        ciphertext: tail,
        commitment,
        wraps,
        recipients,
    };
    let mut previous = None;
    for (_, address, _) in decoded.recipients() {
        if previous.is_some_and(|previous| previous >= address) {
            return Err(Error::Encoding);
        }
        previous = Some(address);
    }
    Ok(decoded)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], Error> {
    let (first, tail) = bytes.split_first_chunk().ok_or(Error::Encoding)?;
    *bytes = tail;
    Ok(*first)
}
