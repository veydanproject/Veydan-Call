//! The STUN message (RFC 8489) and the ChannelData frame of TURN (RFC 8656):
//! reading them, writing them, and the integrity check.
//!
//! Only what the node and its probe use is here; the attributes are plain
//! `(type, bytes)` pairs with helpers for the few that have a shape
//! (addresses, errors, numbers). Nothing of the TURN logic: that is in
//! `turn`.
//!
//! ```text
//! 0                   1                   2                   3
//! |0 0|     STUN Message Type     |         Message Length        |
//! |                         Magic Cookie                          |
//! |                     Transaction ID (96 bits)                  |
//! |  Type  |  Length  |  Value (padded to 4)  | ...               |
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;
/// A message in a UDP packet: the MTU is the real limit, this is the sane one.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// The methods used here.
pub mod method {
    pub const BINDING: u16 = 0x001;
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;
}

/// The attributes used here. Below 0x8000 a receiver must understand them
/// or refuse the message (420); above, it may ignore them.
pub mod attr {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    pub const EVEN_PORT: u16 = 0x0018;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    pub const PASSWORD_ALGORITHM: u16 = 0x001D;
    pub const USERHASH: u16 = 0x001E;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    pub const ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
    pub const ADDRESS_ERROR_CODE: u16 = 0x8001;
    pub const PASSWORD_ALGORITHMS: u16 = 0x8002;
    pub const ALTERNATE_DOMAIN: u16 = 0x8003;
    pub const SOFTWARE: u16 = 0x8022;
    pub const ALTERNATE_SERVER: u16 = 0x8023;
    pub const FINGERPRINT: u16 = 0x8028;

    pub fn comprehension_required(kind: u16) -> bool {
        kind < 0x8000
    }
}

/// The transport number of UDP in REQUESTED-TRANSPORT.
pub const TRANSPORT_UDP: u8 = 17;
pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;

/// Channel numbers of ChannelData: RFC 8656 12.
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x4FFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attr {
    pub kind: u16,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub class: Class,
    pub method: u16,
    pub txid: [u8; 12],
    pub attrs: Vec<Attr>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("not a STUN message")]
    NotStun,
    #[error("truncated")]
    Truncated,
    #[error("bad attribute")]
    BadAttr,
    #[error("the fingerprint does not match")]
    Fingerprint,
}

/// A decoded message with what the integrity check needs: where the
/// MESSAGE-INTEGRITY attribute sat in the bytes.
pub struct Decoded<'a> {
    pub msg: Message,
    raw: &'a [u8],
    integrity_at: Option<usize>,
}

/// Is this the start of a STUN message? Its first two bits are zero and the
/// magic cookie follows the length.
pub fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[0] & 0xC0 == 0 && u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) == MAGIC_COOKIE
}

/// Is this the start of a ChannelData frame? Its first two bits are 01.
pub fn is_channel_data(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0] & 0xC0 == 0x40
}

/// What one frame on a stream is, from its first four bytes: the kind and
/// the whole length on the wire (ChannelData is padded to four on TCP).
pub enum Frame {
    Stun(usize),
    ChannelData(usize),
}

pub fn frame_of(head: &[u8]) -> Option<Frame> {
    if head.len() < 4 {
        return None;
    }
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    match head[0] & 0xC0 {
        0x00 => Some(Frame::Stun(HEADER_LEN + len)),
        0x40 => Some(Frame::ChannelData(4 + len.div_ceil(4) * 4)),
        _ => None,
    }
}

impl Message {
    pub fn new(class: Class, method: u16, txid: [u8; 12]) -> Self {
        Self { class, method, txid, attrs: Vec::new() }
    }

    /// A request with a fresh transaction id.
    pub fn request(method: u16) -> Self {
        Self::new(Class::Request, method, random_txid())
    }

    pub fn indication(method: u16) -> Self {
        Self::new(Class::Indication, method, random_txid())
    }

    /// The answer to `self`: same method, same transaction.
    pub fn success(&self) -> Self {
        Self::new(Class::Success, self.method, self.txid)
    }

    pub fn error(&self, code: u16, reason: &str) -> Self {
        let mut m = Self::new(Class::Error, self.method, self.txid);
        m.add_error(code, reason);
        m
    }

    pub fn get(&self, kind: u16) -> Option<&[u8]> {
        self.attrs.iter().find(|a| a.kind == kind).map(|a| a.value.as_slice())
    }

    pub fn has(&self, kind: u16) -> bool {
        self.get(kind).is_some()
    }

    pub fn add(&mut self, kind: u16, value: impl Into<Vec<u8>>) -> &mut Self {
        self.attrs.push(Attr { kind, value: value.into() });
        self
    }

    pub fn add_u32(&mut self, kind: u16, value: u32) -> &mut Self {
        self.add(kind, value.to_be_bytes().to_vec())
    }

    pub fn get_u32(&self, kind: u16) -> Option<u32> {
        let v = self.get(kind)?;
        (v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn add_str(&mut self, kind: u16, value: &str) -> &mut Self {
        self.add(kind, value.as_bytes().to_vec())
    }

    pub fn get_str(&self, kind: u16) -> Option<&str> {
        std::str::from_utf8(self.get(kind)?).ok()
    }

    /// An address XOR-ed with the cookie and the transaction id, so that
    /// nothing on the way rewrites it as it would a plain one.
    pub fn add_xor_addr(&mut self, kind: u16, addr: SocketAddr) -> &mut Self {
        self.add(kind, xor_addr(addr, &self.txid))
    }

    pub fn get_xor_addr(&self, kind: u16) -> Option<SocketAddr> {
        unxor_addr(self.get(kind)?, &self.txid)
    }

    /// Every XOR-PEER-ADDRESS, in order: CreatePermission may carry several.
    pub fn xor_peer_addrs(&self) -> Vec<Option<SocketAddr>> {
        self.attrs
            .iter()
            .filter(|a| a.kind == attr::XOR_PEER_ADDRESS)
            .map(|a| unxor_addr(&a.value, &self.txid))
            .collect()
    }

    pub fn add_error(&mut self, code: u16, reason: &str) -> &mut Self {
        let mut v = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
        v.extend_from_slice(reason.as_bytes());
        self.add(attr::ERROR_CODE, v)
    }

    pub fn get_error(&self) -> Option<(u16, String)> {
        let v = self.get(attr::ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        let code = (v[2] & 0x07) as u16 * 100 + (v[3] % 100) as u16;
        Some((code, String::from_utf8_lossy(&v[4..]).into_owned()))
    }

    /// ADDRESS-ERROR-CODE (RFC 8656 18.8): an error for one address family
    /// in a success response, as ERROR-CODE with the family in front.
    pub fn add_address_error(&mut self, family: u8, code: u16, reason: &str) -> &mut Self {
        let mut v = vec![family, 0, (code / 100) as u8, (code % 100) as u8];
        v.extend_from_slice(reason.as_bytes());
        self.add(attr::ADDRESS_ERROR_CODE, v)
    }

    pub fn get_address_error(&self) -> Option<(u8, u16, String)> {
        let v = self.get(attr::ADDRESS_ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        let code = (v[2] & 0x07) as u16 * 100 + (v[3] % 100) as u16;
        Some((v[0], code, String::from_utf8_lossy(&v[4..]).into_owned()))
    }

    pub fn get_channel(&self) -> Option<u16> {
        let v = self.get(attr::CHANNEL_NUMBER)?;
        (v.len() == 4).then(|| u16::from_be_bytes([v[0], v[1]]))
    }

    pub fn add_channel(&mut self, number: u16) -> &mut Self {
        self.add(attr::CHANNEL_NUMBER, vec![(number >> 8) as u8, number as u8, 0, 0])
    }

    /// Attributes below 0x8000 that are not in `known`: a receiver must
    /// answer 420 with them.
    pub fn unknown_required(&self, known: &[u16]) -> Vec<u16> {
        self.attrs
            .iter()
            .map(|a| a.kind)
            .filter(|k| attr::comprehension_required(*k) && !known.contains(k))
            .collect()
    }

    /// The bytes. With `key`, MESSAGE-INTEGRITY is added over everything
    /// before it; with `fingerprint`, FINGERPRINT closes the message.
    pub fn encode(&self, key: Option<&[u8]>, fingerprint: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(&message_type(self.class, self.method).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.txid);
        for a in &self.attrs {
            push_attr(&mut out, a.kind, &a.value);
        }
        if let Some(key) = key {
            // The length covers the attribute about to be added.
            let len = out.len() + 24 - HEADER_LEN;
            set_len(&mut out, len);
            let mac = hmac_sha1(key, &out);
            push_attr(&mut out, attr::MESSAGE_INTEGRITY, &mac);
        }
        if fingerprint {
            let len = out.len() + 8 - HEADER_LEN;
            set_len(&mut out, len);
            let crc = crc32(&out) ^ 0x5354_554E;
            push_attr(&mut out, attr::FINGERPRINT, &crc.to_be_bytes());
        }
        let len = out.len() - HEADER_LEN;
        set_len(&mut out, len);
        out
    }
}

impl<'a> Decoded<'a> {
    /// The message in `raw`, which must be exactly one message. A
    /// FINGERPRINT, when there is one, must be last and must match.
    pub fn parse(raw: &'a [u8]) -> Result<Self, DecodeError> {
        if !is_stun(raw) {
            return Err(DecodeError::NotStun);
        }
        let len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if !len.is_multiple_of(4) || raw.len() != HEADER_LEN + len {
            return Err(DecodeError::Truncated);
        }
        let kind = u16::from_be_bytes([raw[0], raw[1]]);
        let (class, method) = split_type(kind);
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&raw[8..20]);
        let mut msg = Message::new(class, method, txid);
        let mut at = HEADER_LEN;
        let mut integrity_at = None;
        let mut fingerprint_at = None;
        while at < raw.len() {
            if raw.len() - at < 4 {
                return Err(DecodeError::BadAttr);
            }
            let kind = u16::from_be_bytes([raw[at], raw[at + 1]]);
            let vlen = u16::from_be_bytes([raw[at + 2], raw[at + 3]]) as usize;
            let start = at + 4;
            let end = start + vlen;
            if end > raw.len() {
                return Err(DecodeError::BadAttr);
            }
            match kind {
                // Only a FINGERPRINT may follow MESSAGE-INTEGRITY; whatever
                // else does is not covered by it and is dropped (RFC 8489
                // 14.5).
                attr::MESSAGE_INTEGRITY if integrity_at.is_none() => {
                    if vlen != 20 {
                        return Err(DecodeError::BadAttr);
                    }
                    integrity_at = Some(at);
                    msg.attrs.push(Attr { kind, value: raw[start..end].to_vec() });
                }
                attr::FINGERPRINT => {
                    if vlen != 4 {
                        return Err(DecodeError::BadAttr);
                    }
                    fingerprint_at = Some(at);
                    msg.attrs.push(Attr { kind, value: raw[start..end].to_vec() });
                }
                _ if integrity_at.is_none() => msg.attrs.push(Attr { kind, value: raw[start..end].to_vec() }),
                _ => {}
            }
            at = start + vlen.div_ceil(4) * 4;
        }
        if let Some(fp) = fingerprint_at {
            let want = u32::from_be_bytes([raw[fp + 4], raw[fp + 5], raw[fp + 6], raw[fp + 7]]);
            if fp + 8 != raw.len() || crc32(&raw[..fp]) ^ 0x5354_554E != want {
                return Err(DecodeError::Fingerprint);
            }
        }
        Ok(Self { msg, raw, integrity_at })
    }

    pub fn has_integrity(&self) -> bool {
        self.integrity_at.is_some()
    }

    /// Does MESSAGE-INTEGRITY hold with `key`? False without one.
    pub fn verify_integrity(&self, key: &[u8]) -> bool {
        let Some(at) = self.integrity_at else {
            return false;
        };
        let mut head = self.raw[..at].to_vec();
        set_len(&mut head, at + 24 - HEADER_LEN);
        let mac = hmac_sha1(key, &head);
        crate::identity::same_secret(&mac, &self.raw[at + 4..at + 24])
    }
}

/// `ChannelData`: four bytes of header, then the bytes for the peer.
pub fn channel_data(number: u16, data: &[u8], pad_for_stream: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() + 3);
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    if pad_for_stream {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    out
}

/// `(channel number, data)` of a ChannelData frame; padding past the
/// length is ignored.
pub fn parse_channel_data(buf: &[u8]) -> Option<(u16, &[u8])> {
    if !is_channel_data(buf) {
        return None;
    }
    let number = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    (buf.len() >= 4 + len).then(|| (number, &buf[4..4 + len]))
}

/// The key of the long-term credential mechanism (RFC 8489 9.2.2):
/// MD5 of `username:realm:password`. The node knows the password from the
/// username alone (`turn::auth`), so the key is derived, never stored.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    h.finalize().into()
}

pub fn random_txid() -> [u8; 12] {
    use ring::rand::SecureRandom;
    let mut id = [0u8; 12];
    ring::rand::SystemRandom::new().fill(&mut id).expect("the system's randomness");
    id
}

fn message_type(class: Class, method: u16) -> u16 {
    let c = match class {
        Class::Request => 0b00,
        Class::Indication => 0b01,
        Class::Success => 0b10,
        Class::Error => 0b11,
    };
    ((method & 0x0F80) << 2) | ((method & 0x0070) << 1) | (method & 0x000F) | ((c & 2) << 7) | ((c & 1) << 4)
}

fn split_type(kind: u16) -> (Class, u16) {
    let method = ((kind & 0x3E00) >> 2) | ((kind & 0x00E0) >> 1) | (kind & 0x000F);
    let class = match ((kind & 0x0100) >> 7) | ((kind & 0x0010) >> 4) {
        0b00 => Class::Request,
        0b01 => Class::Indication,
        0b10 => Class::Success,
        _ => Class::Error,
    };
    (class, method)
}

fn set_len(buf: &mut [u8], len: usize) {
    buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
}

fn push_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn xor_addr(addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let mut v = vec![0, 0, (port >> 8) as u8, port as u8];
    match addr.ip() {
        IpAddr::V4(ip) => {
            v[1] = FAMILY_IPV4;
            let x = u32::from(ip) ^ MAGIC_COOKIE;
            v.extend_from_slice(&x.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            v[1] = FAMILY_IPV6;
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txid);
            let octets = ip.octets();
            v.extend((0..16).map(|i| octets[i] ^ mask[i]));
        }
    }
    v
}

fn unxor_addr(v: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match v[1] {
        FAMILY_IPV4 if v.len() == 8 => {
            let x = u32::from_be_bytes([v[4], v[5], v[6], v[7]]) ^ MAGIC_COOKIE;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(x)), port))
        }
        FAMILY_IPV6 if v.len() == 20 => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txid);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = v[4 + i] ^ mask[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    // SHA-1 is what RFC 8489 names for MESSAGE-INTEGRITY and what every
    // client sends; it keys a MAC here, where its weakness as a hash does
    // not reach.
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let tag = ring::hmac::sign(&key, data);
    let mut out = [0u8; 20];
    out.copy_from_slice(tag.as_ref());
    out
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

/// CRC-32 as FINGERPRINT wants it (the one of zip and Ethernet).
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_round_trip() {
        for method in [method::BINDING, method::ALLOCATE, method::REFRESH, method::SEND, method::DATA, method::CREATE_PERMISSION, method::CHANNEL_BIND] {
            for class in [Class::Request, Class::Indication, Class::Success, Class::Error] {
                assert_eq!(split_type(message_type(class, method)), (class, method));
            }
        }
        // The known encodings: Binding request 0x0001, Binding success 0x0101,
        // Allocate error 0x0113, Data indication 0x0017.
        assert_eq!(message_type(Class::Request, method::BINDING), 0x0001);
        assert_eq!(message_type(Class::Success, method::BINDING), 0x0101);
        assert_eq!(message_type(Class::Error, method::ALLOCATE), 0x0113);
        assert_eq!(message_type(Class::Indication, method::DATA), 0x0017);
    }

    #[test]
    fn crc32_is_the_standard_one() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn addresses_round_trip_through_xor() {
        let txid = random_txid();
        for text in ["203.0.113.7:3478", "[2001:db8::1]:65535", "0.0.0.0:0"] {
            let addr: SocketAddr = text.parse().unwrap();
            assert_eq!(unxor_addr(&xor_addr(addr, &txid), &txid), Some(addr));
        }
        assert_eq!(unxor_addr(&[0, 1, 0, 0], &txid), None);
    }

    #[test]
    fn integrity_and_fingerprint_are_checked() {
        let key = long_term_key("u", "veydan", "p");
        let mut m = Message::request(method::ALLOCATE);
        m.add_str(attr::USERNAME, "u").add_str(attr::REALM, "veydan").add_u32(attr::LIFETIME, 600);
        let raw = m.encode(Some(&key), true);
        let d = Decoded::parse(&raw).unwrap();
        assert!(d.has_integrity());
        assert!(d.verify_integrity(&key));
        assert!(!d.verify_integrity(b"other"));
        assert_eq!(d.msg.get_u32(attr::LIFETIME), Some(600));
        assert_eq!(d.msg.get_str(attr::USERNAME), Some("u"));

        // One bit of the body flipped: the fingerprint no longer matches.
        let mut bad = raw.clone();
        bad[HEADER_LEN + 4] ^= 1;
        assert!(matches!(Decoded::parse(&bad), Err(DecodeError::Fingerprint)));

        // Without a fingerprint the same flip is caught by the integrity check.
        let raw = m.encode(Some(&key), false);
        let mut bad = raw.clone();
        bad[HEADER_LEN + 4] ^= 1;
        assert!(!Decoded::parse(&bad).unwrap().verify_integrity(&key));
    }

    #[test]
    fn rfc_5769_binding_request_with_integrity_and_fingerprint() {
        // RFC 5769 2.1: a Binding request from a client with username
        // "evtj:h6vY", password "VOkJxbRl1RmTxUk/WvJxBt", short-term.
        let raw: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
            0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
            0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
            0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14,
            0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2,
            0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
        ];
        let d = Decoded::parse(&raw).unwrap();
        assert_eq!(d.msg.class, Class::Request);
        assert_eq!(d.msg.method, method::BINDING);
        assert_eq!(d.msg.get_str(attr::USERNAME), Some("evtj:h6vY"));
        assert!(d.verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt"));
    }

    #[test]
    fn rfc_5769_long_term_key_and_response_address() {
        // RFC 5769 2.4: a request under the long-term mechanism; the key
        // is MD5 of username, realm and the password after SASLprep
        // ("TheMatrIX"). The key and the MAC were checked against another
        // implementation: md5sum, and openssl dgst -sha1 -mac HMAC over
        // the message up to MESSAGE-INTEGRITY.
        let key = long_term_key("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}", "example.org", "TheMatrIX");
        assert_eq!(key, [0xe8, 0xca, 0x7a, 0xd5, 0x9d, 0x5e, 0xb0, 0x51, 0x8e, 0x31, 0x29, 0x11, 0xd2, 0xda, 0xb2, 0xa9]);
        let raw: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
            0x00, 0x06, 0x00, 0x12, 0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3,
            0x82, 0xb9, 0x00, 0x00, 0x00, 0x15, 0x00, 0x1c, 0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
            0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x14, 0x00, 0x0b,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x08, 0x00, 0x14, 0xf6, 0x70, 0x24, 0x65,
            0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66,
        ];
        let d = Decoded::parse(&raw).unwrap();
        assert_eq!(d.msg.get_str(attr::REALM), Some("example.org"));
        assert!(d.verify_integrity(&key));
        // RFC 5769 2.2: the XOR-MAPPED-ADDRESS of the IPv4 response.
        let raw: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
            0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08,
            0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
            0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
        ];
        let d = Decoded::parse(&raw).unwrap();
        assert_eq!(d.msg.class, Class::Success);
        assert_eq!(d.msg.get_xor_addr(attr::XOR_MAPPED_ADDRESS), Some("192.0.2.1:32853".parse().unwrap()));
        assert!(d.verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt"));
    }

    #[test]
    fn channel_data_frames() {
        let f = channel_data(0x4001, b"abcde", true);
        assert_eq!(f.len(), 12);
        assert_eq!(parse_channel_data(&f), Some((0x4001, &b"abcde"[..])));
        assert!(matches!(frame_of(&f), Some(Frame::ChannelData(12))));
        let f = channel_data(0x4001, b"abcde", false);
        assert_eq!(f.len(), 9);
        assert!(!is_stun(&f));
        let m = Message::request(method::BINDING).encode(None, false);
        assert!(matches!(frame_of(&m), Some(Frame::Stun(20))));
        assert!(is_stun(&m) && !is_channel_data(&m));
    }

    #[test]
    fn errors_and_unknown_attributes() {
        let req = Message::request(method::ALLOCATE);
        let mut e = req.error(437, "Allocation Mismatch");
        e.add(0x7777, vec![1]);
        let raw = e.encode(None, false);
        let d = Decoded::parse(&raw).unwrap();
        assert_eq!(d.msg.get_error(), Some((437, "Allocation Mismatch".to_string())));
        assert_eq!(d.msg.unknown_required(&[attr::ERROR_CODE]), vec![0x7777]);
        assert_eq!(d.msg.txid, req.txid);

        let mut s = req.success();
        s.add_address_error(FAMILY_IPV6, 440, "Address Family not Supported");
        let raw = s.encode(None, false);
        let d = Decoded::parse(&raw).unwrap();
        assert_eq!(d.msg.get_address_error(), Some((FAMILY_IPV6, 440, "Address Family not Supported".to_string())));
        assert_eq!(d.msg.get_error(), None);
        assert!(d.msg.unknown_required(&[]).is_empty(), "ADDRESS-ERROR-CODE may be ignored");
    }
}
