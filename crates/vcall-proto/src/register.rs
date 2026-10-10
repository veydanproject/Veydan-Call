//! What a node tells the registry, every few minutes: that it exists, where,
//! what it can do and how full it is. The registry (part of VHub) keeps
//! the nodes of the volunteers for the clients' lists.
//!
//! ```text
//! POST {registry}/v1/calls/register    Registration → Registered
//! ```
//!
//! The report is signed by the node's key, the Ed25519 key whose hash is
//! the node's id (`vlink-proto` identity v2): the registry believes an
//! address for an id from that key only, so nobody can report a node at an
//! address of their own and have it struck off as unreachable there. The
//! time of the report is under the signature too, so a report kept and
//! sent again later is refused. The same form as a bridge's registration,
//! under a context of its own: a signature for a bridge is never one for a
//! node, nor the other way round.
//!
//! Two forms: `v` 1, the first nodes' (5.1.7 and before: no `v` on the
//! wire), and `v` 2, which says besides how many rooms and cascade uplinks
//! the node holds, under a context of its own (`vcall-register/2`). A node
//! of today sends form 2; a registry that knows only form 1 refuses it,
//! and the node's log says so.

use std::net::{IpAddr, SocketAddr};

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

const CONTEXT_V1: &str = "vcall-register/1\n";
const CONTEXT_V2: &str = "vcall-register/2\n";

/// The newest form of [`Registration`]: what a node sends.
pub const REGISTRATION_VERSION: u32 = 2;

/// The DER of a SubjectPublicKeyInfo carrying an Ed25519 key, up to the
/// key itself. A node's id is SHA-256 of that structure, as the certificate
/// carrying the key has it (`vlink_proto::BridgeId::of_ed25519`).
const ED25519_SPKI_HEADER: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The most capabilities a report may name, and how long each may be.
pub const MAX_CAPS: usize = 16;
pub const MAX_CAP_LEN: usize = 32;
pub const MAX_REGION_LEN: usize = 16;
pub const MAX_VERSION_LEN: usize = 32;

/// How full the node is, as it says itself. The registry orders its lists
/// by it and believes it for nothing else. A `max_*` of 0: no limit said.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Load {
    /// TURN allocations now, and the node's cap on them.
    #[serde(default)]
    pub allocations: u32,
    #[serde(default)]
    pub max_allocations: u32,
    /// Participants of SFU rooms now, and the cap (rooms × seats).
    #[serde(default)]
    pub participants: u32,
    #[serde(default)]
    pub max_participants: u32,
    /// Bandwidth relayed now and the node's ceiling, Mbit/s.
    #[serde(default)]
    pub mbps: u32,
    #[serde(default)]
    pub max_mbps: u32,
    /// Rooms now (satellites of the cascade too), and the cap. Form 2.
    #[serde(default)]
    pub rooms: u32,
    #[serde(default)]
    pub max_rooms: u32,
    /// Cascade uplinks to other nodes' rooms now, and the cap. Form 2.
    #[serde(default)]
    pub uplinks: u32,
    #[serde(default)]
    pub max_uplinks: u32,
}

impl Load {
    /// The fullest of the parts, in percent (0–100). A part without a
    /// limit counts 0.
    pub fn percent(&self) -> u8 {
        let parts = [
            (self.allocations, self.max_allocations),
            (self.participants, self.max_participants),
            (self.mbps, self.max_mbps),
            (self.rooms, self.max_rooms),
            (self.uplinks, self.max_uplinks),
        ];
        parts.iter().map(|&(now, max)| if max == 0 { 0 } else { (u64::from(now) * 100 / u64::from(max)).min(100) }).max().unwrap_or(0) as u8
    }

    fn line(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.allocations, self.max_allocations, self.participants, self.max_participants, self.mbps, self.max_mbps
        )
    }

    fn line_v2(&self) -> String {
        format!("{},{},{},{}", self.rooms, self.max_rooms, self.uplinks, self.max_uplinks)
    }
}

fn first_form() -> u32 {
    1
}

fn is_first_form(v: &u32) -> bool {
    *v <= 1
}

/// The report. Every field but `sig` is under the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// The form: 1 (or none on the wire) or 2 ([`REGISTRATION_VERSION`]).
    #[serde(default = "first_form", skip_serializing_if = "is_first_form")]
    pub v: u32,
    /// The node's id, 64 hex characters.
    pub id: String,
    /// The node's public address, when it knows it (`VCALL_PUBLIC_IP`);
    /// otherwise the registry takes the one the request came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// TLS: control and TURN over TLS (`VCALL_LISTEN`, as the world reaches it).
    pub control_port: u16,
    /// STUN and TURN over UDP and TCP (`VCALL_TURN_LISTEN`).
    pub turn_port: u16,
    /// The SFU over UDP and TCP (`VCALL_SFU_LISTEN`); 0 when there is none.
    #[serde(default)]
    pub sfu_port: u16,
    /// A hint for clients: `eu`, `ru`. Lowercase letters, digits and `-`;
    /// empty when the operator said nothing.
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub version: String,
    /// As in WELCOME: `stun`, `turn`, `turn-tcp`, `turn-tls`, `sfu`.
    #[serde(default)]
    pub caps: Vec<String>,
    #[serde(default)]
    pub load: Load,
    /// When the node made the report, unix seconds.
    #[serde(default)]
    pub ts: u64,
    /// The node's key, 32 bytes as hex; `id` is its hash.
    #[serde(default)]
    pub key: String,
    /// The key's signature under [`Registration::message`], hex.
    #[serde(default)]
    pub sig: String,
}

/// Why a report is not believed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Unsigned {
    #[error("the report is not signed by the key of its id")]
    Key,
    #[error("the signature of the report does not hold")]
    Signature,
    #[error("the report's time is not now: check the clock of the node")]
    Clock,
}

/// Why a report is refused before its signature is looked at: a field
/// that cannot be put on one line of the signed text.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Malformed {
    #[error("the control port is 0")]
    ControlPort,
    #[error("the turn port is 0")]
    TurnPort,
    #[error("the region is not a short word")]
    Region,
    #[error("the version is too long or has a line break")]
    Version,
    #[error("a capability is not a short word, or there are too many")]
    Caps,
    #[error("the form {0} of a report is not known")]
    Form(u32),
}

fn word(text: &str, max: usize) -> bool {
    text.len() <= max && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Registration {
    /// The bytes the node's key signs: every field but the signature, one
    /// per line, the capabilities joined by commas. Form 2 has a context
    /// of its own and the rooms and uplinks on a line after the load.
    pub fn message(&self) -> Vec<u8> {
        let ip = self.ip.map(|ip| ip.to_string()).unwrap_or_default();
        let (context, more) = if is_first_form(&self.v) { (CONTEXT_V1, String::new()) } else { (CONTEXT_V2, format!("\n{}", self.load.line_v2())) };
        format!(
            "{context}{}\n{ip}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{more}\n{}\n{}",
            self.id,
            self.control_port,
            self.turn_port,
            self.sfu_port,
            self.region,
            self.version,
            self.caps.join(","),
            self.load.line(),
            self.ts,
            self.key
        )
        .into_bytes()
    }

    /// Is every field of a shape that signs without ambiguity?
    pub fn well_formed(&self) -> Result<(), Malformed> {
        if self.v > REGISTRATION_VERSION {
            return Err(Malformed::Form(self.v));
        }
        if self.control_port == 0 {
            return Err(Malformed::ControlPort);
        }
        if self.turn_port == 0 {
            return Err(Malformed::TurnPort);
        }
        if !word(&self.region, MAX_REGION_LEN) {
            return Err(Malformed::Region);
        }
        if self.version.len() > MAX_VERSION_LEN || self.version.contains(['\n', '\r']) {
            return Err(Malformed::Version);
        }
        if self.caps.len() > MAX_CAPS || self.caps.iter().any(|c| c.is_empty() || !word(c, MAX_CAP_LEN)) {
            return Err(Malformed::Caps);
        }
        Ok(())
    }

    /// As the node: the key and its signature put in, the other fields
    /// filled already.
    pub fn sign(&mut self, key: &Ed25519KeyPair) {
        self.key = hex(key.public_key().as_ref());
        self.sig = hex(key.sign(&self.message()).as_ref());
    }

    /// As the registry: is this the word of the node `id`, made within
    /// `skew` seconds of `now`? The key has to be the one the id is the
    /// hash of, and the signature its own over every field.
    pub fn verify(&self, now: u64, skew: u64) -> Result<(), Unsigned> {
        let key: [u8; 32] = unhex(&self.key).and_then(|k| k.try_into().ok()).ok_or(Unsigned::Key)?;
        if id_of_key(&key) != self.id {
            return Err(Unsigned::Key);
        }
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&self.message(), &unhex(&self.sig).ok_or(Unsigned::Signature)?)
            .map_err(|_| Unsigned::Signature)?;
        if self.ts.abs_diff(now) > skew {
            return Err(Unsigned::Clock);
        }
        Ok(())
    }

    /// Where the node's control channel is, as the registry takes it.
    pub fn control_addr(&self, seen_from: IpAddr) -> SocketAddr {
        SocketAddr::new(self.ip.unwrap_or(seen_from), self.control_port)
    }
}

/// The id of the node whose key this is: SHA-256 of the key's
/// SubjectPublicKeyInfo, as hex.
pub fn id_of_key(public: &[u8; 32]) -> String {
    let mut spki = ED25519_SPKI_HEADER.to_vec();
    spki.extend_from_slice(public);
    hex(ring::digest::digest(&ring::digest::SHA256, &spki).as_ref())
}

/// What the registry answers. The states are the bridges'.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    /// `new`, `verified`, `active`, `degraded`, `dead`, `banned`.
    pub state: String,
    /// The control address the registry has for the node.
    pub addr: SocketAddr,
}

impl Registered {
    /// Reported in, and nothing more yet: the node asks again soon.
    pub fn is_new(&self) -> bool {
        self.state == "new"
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes of a hex string; `None` for anything that is not one.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    bytes.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    pub fn registration(key: &Ed25519KeyPair) -> Registration {
        let mut public = [0u8; 32];
        public.copy_from_slice(key.public_key().as_ref());
        let mut r = Registration {
            v: 1,
            id: id_of_key(&public),
            ip: Some("203.0.113.7".parse().unwrap()),
            control_port: 8443,
            turn_port: 3478,
            sfu_port: 3479,
            region: "eu".into(),
            version: "0.1.0".into(),
            caps: vec!["stun".into(), "turn".into(), "sfu".into()],
            load: Load { allocations: 10, max_allocations: 1000, participants: 3, max_participants: 768, mbps: 30, max_mbps: 100, ..Load::default() },
            ts: 1000,
            key: String::new(),
            sig: String::new(),
        };
        r.sign(key);
        r
    }

    fn second_form(key: &Ed25519KeyPair) -> Registration {
        let mut r = registration(key);
        r.v = REGISTRATION_VERSION;
        r.caps.push("cascade".into());
        r.load.rooms = 3;
        r.load.max_rooms = 64;
        r.load.uplinks = 2;
        r.load.max_uplinks = 256;
        r.sign(key);
        r
    }

    #[test]
    fn a_report_is_taken_from_the_key_of_its_id_only() {
        let (node, stranger) = (key(), key());
        for r in [registration(&node), second_form(&node)] {
            assert_eq!(r.verify(1000, 300), Ok(()));
            assert_eq!(r.well_formed(), Ok(()));
            let back: Registration = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
            assert_eq!(back.verify(1200, 300), Ok(()));
            assert_eq!(r.verify(1301, 300), Err(Unsigned::Clock));
            assert_eq!(r.control_addr("9.9.9.9".parse().unwrap()), "203.0.113.7:8443".parse().unwrap());

            let mut forged = r.clone();
            forged.sign(&stranger);
            assert_eq!(forged.verify(1000, 300), Err(Unsigned::Key));
            let mut garbled = r.clone();
            garbled.sig = "zz".into();
            assert_eq!(garbled.verify(1000, 300), Err(Unsigned::Signature));
            // Every field is under the signature, the form too.
            let changes: [fn(&mut Registration); 9] = [
                |r| r.ip = None,
                |r| r.turn_port = 3480,
                |r| r.sfu_port = 0,
                |r| r.control_port = 443,
                |r| r.load.participants = 0,
                |r| r.caps.pop().map(drop).unwrap_or(()),
                |r| r.region = "ru".into(),
                |r| r.ts += 1,
                |r| r.v = 3 - r.v,
            ];
            for change in changes {
                let mut moved = r.clone();
                change(&mut moved);
                assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
            }
        }
        // Form 2 signs the rooms and the uplinks too; form 1 does not.
        let r = second_form(&node);
        for change in [|r: &mut Registration| r.load.rooms = 0, |r: &mut Registration| r.load.max_uplinks = 1] {
            let mut moved = r.clone();
            change(&mut moved);
            assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
        }
        let mut first = registration(&node);
        first.load.rooms = 60;
        assert_eq!(first.verify(1000, 300), Ok(()));
    }

    #[test]
    fn the_signed_lines_are_the_documented_ones() {
        let node = key();
        let r = registration(&node);
        let head = format!("{}\n203.0.113.7\n8443\n3478\n3479\neu\n0.1.0\n", r.id);
        let first = format!("vcall-register/1\n{head}stun,turn,sfu\n10,1000,3,768,30,100\n1000\n{}", r.key);
        assert_eq!(String::from_utf8(r.message()).unwrap(), first);
        // A node of 5.1.7 sends no `v`, and a form-1 report is written so.
        assert!(!serde_json::to_string(&r).unwrap().contains("\"v\""));
        let r = second_form(&node);
        let second = format!("vcall-register/2\n{head}stun,turn,sfu,cascade\n10,1000,3,768,30,100\n3,64,2,256\n1000\n{}", r.key);
        assert_eq!(String::from_utf8(r.message()).unwrap(), second);
        assert!(serde_json::to_string(&r).unwrap().starts_with("{\"v\":2,"));
        let mut r = second_form(&node);
        r.v = 3;
        assert_eq!(r.well_formed(), Err(Malformed::Form(3)));
    }

    #[test]
    fn what_cannot_be_signed_plainly_is_refused() {
        let node = key();
        let mut r = registration(&node);
        r.caps = vec!["stun,turn".into()];
        assert_eq!(r.well_formed(), Err(Malformed::Caps));
        r.caps = vec!["x".into(); MAX_CAPS + 1];
        assert_eq!(r.well_formed(), Err(Malformed::Caps));
        let mut r = registration(&node);
        r.region = "eu\nx".into();
        assert_eq!(r.well_formed(), Err(Malformed::Region));
        let mut r = registration(&node);
        r.version = "1\n2".into();
        assert_eq!(r.well_formed(), Err(Malformed::Version));
        let mut r = registration(&node);
        r.turn_port = 0;
        assert_eq!(r.well_formed(), Err(Malformed::TurnPort));
        r.turn_port = 3478;
        r.control_port = 0;
        assert_eq!(r.well_formed(), Err(Malformed::ControlPort));
    }

    #[test]
    fn load_is_the_fullest_part() {
        assert_eq!(Load::default().percent(), 0);
        let load = Load { allocations: 500, max_allocations: 1000, mbps: 90, max_mbps: 100, ..Load::default() };
        assert_eq!(load.percent(), 90);
        assert_eq!(Load { participants: 5000, max_participants: 1000, ..Load::default() }.percent(), 100);
        assert_eq!(Load { rooms: 48, max_rooms: 64, mbps: 10, max_mbps: 100, ..Load::default() }.percent(), 75);
        assert_eq!(Load { uplinks: 1, max_uplinks: 3, ..Load::default() }.percent(), 33);
        assert_eq!(Load { participants: 700, ..Load::default() }.percent(), 0);
        let answer: Registered = serde_json::from_str(r#"{"state":"new","addr":"203.0.113.7:8443"}"#).unwrap();
        assert!(answer.is_new());
    }
}
