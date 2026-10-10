//! The list of call nodes the registry gives out, and its check.
//!
//! ```text
//! GET {registry}/v1/calls        → SignedList    a few nodes for a client, the least loaded first
//! GET {registry}/v1/calls/all    → SignedList    every node, for a node: who is in the registry
//! ```
//!
//! The envelope and the delegation are the bridges' (`vlink_proto::list`):
//! the root key delegates a list key to the registry, the list key signs
//! the list. The context differs: a list of nodes is signed under
//! `vcall-list/1`, a list of bridges under `vlink-list/1`, so that one is
//! never taken for the other. The list itself is JSON (`CallList`), kept as
//! the very text that was signed.
//!
//! A node takes the complete list for the cascade: another node on it
//! holds seats here without the quota (`VCALL_CASCADE=on`), or at all
//! (`VCALL_CASCADE=registry`). The registry's word is believed as far as
//! the root's delegation reaches, as a client believes it for bridges.

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
pub use vlink_proto::list::{Delegation, Error, SignedList};
use vlink_proto::list::{hex, unhex};
pub use vlink_proto::wire::State;

const LIST_CONTEXT: &str = "vcall-list/1\n";

/// The versions of [`CallList`] taken: 1 (the first registries: active
/// nodes with their load in percent) and 2 (degraded nodes too, with the
/// state, the class and the load as a share). A node reads the ids and
/// the capabilities, which both have.
pub const LIST_VERSION_MIN: u32 = 1;
pub const LIST_VERSION: u32 = 2;
/// What a [`CallList`] lists; a list of bridges has no such field.
pub const KIND: &str = "call";
/// The class of every node of the registry: anybody may run one.
pub const CLASS_VOLUNTEER: &str = "volunteer";

/// One node of a list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallNode {
    /// `address:control_port#id`: what a client pins.
    #[serde(rename = "ref")]
    pub node: String,
    pub turn_port: u16,
    /// 0: no SFU.
    #[serde(default)]
    pub sfu_port: u16,
    /// The node's own hint (`VCALL_REGION`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// What the node reported, as far as the registry's dial-back agreed:
    /// `stun`, `turn`, `sfu`, `cascade`…
    #[serde(default)]
    pub caps: Vec<String>,
    /// [`CLASS_VOLUNTEER`] in a list of the registry.
    #[serde(default = "volunteer")]
    pub class: String,
    /// `active`, or `degraded` (the last check failed). Absent in version 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    /// How full the node said it was when the list was made: the fullest
    /// part of its load, 0 to 1 (version 1 wrote percent).
    #[serde(default)]
    pub load: f64,
}

fn volunteer() -> String {
    CLASS_VOLUNTEER.to_string()
}

impl CallNode {
    /// The id of the node, as its reference names it; `None` for a
    /// reference without one.
    pub fn id(&self) -> Option<&str> {
        self.node.split_once('#').map(|(_, id)| id).filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    pub fn has(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }
}

/// Call nodes and until when the list may be used. Times are unix seconds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallList {
    pub v: u32,
    pub kind: String,
    /// Every node the registry gives out (`/v1/calls/all`), rather than
    /// a few for a client.
    #[serde(default)]
    pub complete: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nodes: Vec<CallNode>,
}

/// The bytes the list key signs.
pub fn list_message(list: &str) -> Vec<u8> {
    format!("{LIST_CONTEXT}{list}").into_bytes()
}

/// As the registry (and the tests): signs `list` with the list key under
/// `delegation`.
pub fn sign_list(key: &Ed25519KeyPair, list: &CallList, delegation: &Delegation) -> SignedList {
    let text = serde_json::to_string(list).expect("a list is plain data");
    let sig = key.sign(&list_message(&text));
    SignedList { list: text, sig: hex(sig.as_ref()), delegation: delegation.clone() }
}

/// As a node or a client: the list, when the root delegated the key that
/// signed it, it is a list of call nodes of a version known, and nothing
/// ran out at `now`.
pub fn verify_list(signed: &SignedList, root_hex: &str, now: u64) -> Result<CallList, Error> {
    signed.delegation.verify(root_hex, now)?;
    let key = unhex(&signed.delegation.key)?;
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&list_message(&signed.list), &unhex(&signed.sig)?)
        .map_err(|_| Error::Signature)?;
    let list: CallList = serde_json::from_str(&signed.list).map_err(|e| Error::Malformed(e.to_string()))?;
    if !(LIST_VERSION_MIN..=LIST_VERSION).contains(&list.v) {
        return Err(Error::Version(list.v));
    }
    if list.kind != KIND {
        return Err(Error::Malformed(format!("a list of {}, not of call nodes", list.kind)));
    }
    if now >= list.expires_at {
        return Err(Error::Expired);
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    use vlink_proto::list::{BridgeList, VERSION};
    use vlink_proto::sign::Signer;

    fn pkcs8() -> Vec<u8> {
        Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap().as_ref().to_vec()
    }

    pub fn node(id: &str, caps: &[&str]) -> CallNode {
        CallNode {
            node: format!("203.0.113.7:8443#{id}"),
            turn_port: 3478,
            sfu_port: 3479,
            region: "eu".into(),
            caps: caps.iter().map(|c| c.to_string()).collect(),
            class: CLASS_VOLUNTEER.into(),
            state: Some(State::Active),
            load: 0.03,
        }
    }

    #[test]
    fn a_list_is_taken_under_the_root_and_never_for_a_bridge_list() {
        let root = Signer::from_pkcs8(&pkcs8()).unwrap();
        let list_der = pkcs8();
        let list_key = Ed25519KeyPair::from_pkcs8(&list_der).unwrap();
        let delegation = root.delegate(&hex(list_key.public_key().as_ref()), 10_000);
        let id = "ab".repeat(32);
        let list = CallList { v: LIST_VERSION, kind: KIND.into(), complete: true, issued_at: 100, expires_at: 5000, nodes: vec![node(&id, &["stun", "cascade"])] };
        let signed = sign_list(&list_key, &list, &delegation);
        let wire: SignedList = serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
        let got = verify_list(&wire, &root.public_hex(), 200).unwrap();
        assert_eq!(got, list);
        assert_eq!(got.nodes[0].id(), Some(id.as_str()));
        assert!(got.nodes[0].has("cascade") && !got.nodes[0].has("sfu"));
        // As the registry of today writes it.
        let expected = format!(
            "{{\"v\":2,\"kind\":\"call\",\"complete\":true,\"issued_at\":100,\"expires_at\":5000,\"nodes\":[{{\"ref\":\"203.0.113.7:8443#{id}\",\
             \"turn_port\":3478,\"sfu_port\":3479,\"region\":\"eu\",\"caps\":[\"stun\",\"cascade\"],\"class\":\"volunteer\",\
             \"state\":\"active\",\"load\":0.03}}]}}"
        );
        assert_eq!(wire.list, expected);
        assert_eq!(verify_list(&wire, &root.public_hex(), 5000), Err(Error::Expired));
        assert_eq!(verify_list(&wire, &"00".repeat(32), 200), Err(Error::Delegation));

        // A list of the first version, without the class and the state.
        let first = format!("{{\"v\":1,\"kind\":\"call\",\"issued_at\":100,\"expires_at\":5000,\"nodes\":[{{\"ref\":\"203.0.113.7:8443#{id}\",\"turn_port\":3478,\"caps\":[\"stun\"],\"load\":3}}]}}");
        let sig = hex(list_key.sign(&list_message(&first)).as_ref());
        let old = SignedList { list: first, sig, delegation: delegation.clone() };
        let got = verify_list(&old, &root.public_hex(), 200).unwrap();
        assert_eq!((got.v, got.complete, got.nodes[0].state, got.nodes[0].class.as_str()), (1, false, None, CLASS_VOLUNTEER));
        assert_eq!(got.nodes[0].load, 3.0);
        let mut newer = signed.clone();
        newer.list = newer.list.replace("\"v\":2", "\"v\":3");
        assert_eq!(verify_list(&newer, &root.public_hex(), 200), Err(Error::Signature));
        let newer = sign_list(&list_key, &CallList { v: 3, ..list.clone() }, &delegation);
        assert_eq!(verify_list(&newer, &root.public_hex(), 200), Err(Error::Version(3)));

        // Signed for bridges, the same key and delegation: no list of nodes.
        let signer = Signer::from_pkcs8(&list_der).unwrap();
        let bridges = BridgeList { v: VERSION, issued_at: 100, expires_at: 5000, bridges: vec![] };
        let as_bridges = signer.sign_list(&bridges, &delegation);
        assert_eq!(verify_list(&as_bridges, &root.public_hex(), 200), Err(Error::Signature));
        assert_eq!(signed.verify(&root.public_hex(), 200), Err(Error::Signature));
        let mut changed = signed.clone();
        changed.list = changed.list.replace("3478", "3477");
        assert_eq!(verify_list(&changed, &root.public_hex(), 200), Err(Error::Signature));
        // A reference without an id names no node.
        let mut bare = node(&id, &[]);
        bare.node = "203.0.113.7:8443".into();
        assert_eq!(bare.id(), None);
    }
}
