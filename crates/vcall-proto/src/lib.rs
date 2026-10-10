//! What a client and a call node say to each other.
//!
//! ```text
//! client ── TLS 1.3 to the node's address, its certificate pinned, ALPN vcall/1 ── h2
//!            POST /v1/hello    Hello        → Welcome           who are you, what can you do
//!            POST /v1/turn     TurnRequest  → TurnCredentials   short-lived TURN credentials
//!            POST /v1/rooms…                                    the SFU's rooms (`rooms`)
//!            POST /v1/invite   InviteRequest → DeviceCredentials an invitation to a private node exchanged
//! ```
//!
//! Every body is JSON. A refusal is a 4xx with a [`Refusal`] body. The
//! media itself (STUN, TURN, the SFU) does not pass through here: it goes
//! by the standard protocols, with what this channel handed out.
//!
//! The node never learns who calls: no npub, no name. It sees an address,
//! and, on a private node, an access key or the credentials of a device
//! it made itself (`invite`).
//!
//! `register` is the other direction: what a node tells the registry, and
//! `list` what the registry tells nodes and clients.

use serde::{Deserialize, Serialize};

pub mod invite;
pub mod list;
pub mod register;
pub mod rooms;

/// The protocol versions this crate speaks. A client sends its own range in
/// HELLO; the node answers with its range in WELCOME, and the two take the
/// highest version both have. Version 1: HELLO, TURN credentials, rooms.
pub const PROTOCOL_MIN: u16 = 1;
pub const PROTOCOL_MAX: u16 = 1;

/// The ALPN of the control channel. The node answers anything else on its
/// port as a web server with nothing to show would.
pub const ALPN: &[u8] = b"vcall/1";

pub const PATH_HELLO: &str = "/v1/hello";
pub const PATH_TURN: &str = "/v1/turn";
/// An invitation exchanged for the credentials of a device (`invite`).
pub const PATH_INVITE: &str = "/v1/invite";

/// A request or an answer is a few hundred bytes; more is not one.
pub const MAX_BODY: usize = 64 * 1024;

/// What a node may be able to do, as named in HELLO and WELCOME.
pub mod capability {
    pub const STUN: &str = "stun";
    /// TURN over UDP.
    pub const TURN: &str = "turn";
    pub const TURN_TCP: &str = "turn-tcp";
    pub const TURN_TLS: &str = "turn-tls";
    /// Rooms: RTP forwarded between participants, the data channel `ctl`.
    pub const SFU: &str = "sfu";
    /// Not there yet: named so that clients and nodes agree on the words.
    pub const SIMULCAST: &str = "simulcast";
    /// The cascade: the node takes a seat in another node's room for a
    /// participant of its own (`rooms::JoinRequest::home`), and gives
    /// seats to other nodes (`rooms::UplinkWord`).
    pub const CASCADE: &str = "cascade";
}

/// The highest version both sides have, if any.
pub fn common_version(a: (u16, u16), b: (u16, u16)) -> Option<u16> {
    let low = a.0.max(b.0);
    let high = a.1.min(b.1);
    (low <= high).then_some(high)
}

/// How a caller shows it may use a private node. All are absent on a
/// public node. A key or a device opens the node; either is enough.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    /// A key from the node's access-key file, given out by whoever runs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The credentials of a device the node made for an invitation
    /// (`invite`): what the app keeps after it took a link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceAccess>,
    /// A pass signed by an issuer the node trusts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<Pass>,
}

impl Access {
    pub fn key(key: impl Into<String>) -> Self {
        Self { key: Some(key.into()), ..Self::default() }
    }

    pub fn device(id: impl Into<String>, secret: impl Into<String>) -> Self {
        Self { device: Some(DeviceAccess { id: id.into(), secret: secret.into() }), ..Self::default() }
    }
}

/// The credentials of a device, as the node gave them for an invitation
/// ([`invite::DeviceCredentials`]) and as the device shows them since.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAccess {
    /// 32 hex characters.
    pub id: String,
    /// 64 hex characters; the node keeps only its hash.
    pub secret: String,
}

/// A short-lived pass from an issuer the node trusts (`VCALL_ISSUERS`),
/// carrying the limits its holder gets. The node checks it alone, without
/// asking the issuer. Meant for the Veydan Cloud subscription later; the
/// type is here so that the wire format does not move when it comes.
///
/// TODO: not accepted yet. A node refuses every pass with `pass_unsupported`
/// until the signing scheme is fixed (which bytes are signed, how the
/// issuer's key is named, how a pass is revoked).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pass {
    /// The issuer's public key, Ed25519, hex.
    pub issuer: String,
    /// Unix seconds.
    pub expires_at: u64,
    #[serde(default)]
    pub limits: PassLimits,
    /// Ed25519 over the pass, hex.
    pub signature: String,
}

/// What a pass may raise or lower. `None`: the node's own default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participants: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_quota_mb: Option<u32>,
}

/// The first thing a client says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_min: u16,
    pub protocol_max: u16,
    /// What the client can use, from [`capability`].
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Codecs the client has, lowercase: `opus`, `vp8`, `h264`.
    #[serde(default)]
    pub codecs: Vec<String>,
    #[serde(default)]
    pub access: Access,
    /// The client's name and version, for the log: `veydan-chat/5.1.0`.
    #[serde(default)]
    pub client: String,
}

/// What the node answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub protocol_min: u16,
    pub protocol_max: u16,
    /// The node's id, as the client pinned it: hex.
    pub node_id: String,
    /// The node's software version.
    pub version: String,
    pub capabilities: Vec<String>,
    /// Codecs the SFU forwards, lowercase: `opus`, `vp8`, `h264`.
    #[serde(default)]
    pub codecs: Vec<String>,
    /// A private node hands out nothing without access.
    pub private: bool,
    pub limits: Limits,
}

/// What the node allows. Clients show these and never carry limits of
/// their own.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// How long an allocation lives at most; a client refreshes before.
    pub turn_lifetime_secs: u32,
    /// Bandwidth one allocation gets, kbit/s.
    pub turn_kbps_per_allocation: u32,
    /// How long credentials are good for.
    pub credentials_ttl_secs: u32,
    /// Seats in a room of the SFU; 0 when the node has no SFU.
    #[serde(default)]
    pub room_max_participants: u32,
    /// What one participant of a room may send, kbit/s.
    #[serde(default)]
    pub room_kbps_per_participant: u32,
    /// How long a room lives at the longest, and how long it stands empty.
    #[serde(default)]
    pub room_lifetime_secs: u32,
    #[serde(default)]
    pub room_idle_secs: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnRequest {
    #[serde(default)]
    pub access: Access,
}

/// Short-lived TURN credentials, in the form every TURN client takes
/// (`username = expiry:random`, `password = HMAC(node secret, username)`),
/// and where to use them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub realm: String,
    pub ttl_secs: u64,
    /// Unix seconds.
    pub expires_at: u64,
    /// `stun:`, `turn:` and `turns:` URIs (RFC 7064, RFC 7065), as an ICE
    /// server list takes them.
    pub urls: Vec<String>,
}

/// Why a request was refused. `error` is one word a client acts on;
/// `message` is for a log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub error: String,
    #[serde(default)]
    pub message: String,
}

impl Refusal {
    pub fn new(error: &str, message: impl Into<String>) -> Self {
        Self { error: error.to_string(), message: message.into() }
    }
}

/// The words of `Refusal::error`.
pub mod refusal {
    /// No version in common.
    pub const VERSION: &str = "version";
    /// A private node, and no key or a wrong one (nor the credentials of
    /// a device the node made, or those of one it revoked).
    pub const ACCESS_KEY_REQUIRED: &str = "access_key_required";
    /// The invitation is not one the node made, was used as often as it
    /// may be, or ran out.
    pub const BAD_INVITE: &str = "bad_invite";
    /// The node could not keep what the exchange made (its data directory
    /// did not take the write): no device was made and the token was not
    /// spent; the same link, later.
    pub const NOT_KEPT: &str = "not_kept";
    /// A pass was shown; passes are not taken yet.
    pub const PASS_UNSUPPORTED: &str = "pass_unsupported";
    /// Too many credentials or rooms asked from one address.
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const BAD_REQUEST: &str = "bad_request";
    /// The node has no SFU.
    pub const NO_SFU: &str = "no_sfu";
    /// No room by that id: never was, or ended.
    pub const ROOM_NOT_FOUND: &str = "room_not_found";
    /// The join, admin or participant token is not the room's.
    pub const BAD_TOKEN: &str = "bad_token";
    /// Every seat of the room is taken.
    pub const ROOM_FULL: &str = "room_full";
    /// The node holds as many rooms as it may.
    pub const ROOMS_FULL: &str = "rooms_full";
    /// The SDP offer could not be taken.
    pub const BAD_SDP: &str = "bad_sdp";
    /// The home named in a join is not one the node may reach: not a
    /// node reference, the node itself, a private address, a room of this
    /// node, or a satellite of another home.
    pub const BAD_HOME: &str = "bad_home";
    /// The cascade is off, the quota of seats for the node is full, the
    /// home does not take uplinks, or the node has as many as it may.
    pub const CASCADE_REFUSED: &str = "cascade_refused";
    /// The node could not reach the home, or could not use its answer;
    /// the client goes to the home itself.
    pub const CASCADE_UNREACHABLE: &str = "cascade_unreachable";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_meet_at_the_highest_common_one() {
        assert_eq!(common_version((1, 1), (1, 1)), Some(1));
        assert_eq!(common_version((1, 3), (2, 5)), Some(3));
        assert_eq!(common_version((1, 1), (2, 2)), None);
    }

    #[test]
    fn the_wire_form_is_what_a_client_sends() {
        // Fields a client of version 1 does not know are left out and
        // absent fields take their defaults: a node and a client of
        // different ages still talk.
        let hello: Hello = serde_json::from_str(r#"{"protocol_min":1,"protocol_max":1}"#).unwrap();
        assert_eq!(hello.access, Access::default());
        assert!(hello.capabilities.is_empty());

        let welcome = Welcome {
            protocol_min: 1,
            protocol_max: 1,
            node_id: "ab".repeat(32),
            version: "0.1.0".into(),
            capabilities: vec![capability::STUN.into(), capability::TURN.into()],
            codecs: vec![],
            private: false,
            limits: Limits { turn_lifetime_secs: 600, turn_kbps_per_allocation: 2000, credentials_ttl_secs: 600, ..Limits::default() },
        };
        let text = serde_json::to_string(&welcome).unwrap();
        assert_eq!(serde_json::from_str::<Welcome>(&text).unwrap(), welcome);

        let creds: TurnCredentials = serde_json::from_str(
            r#"{"username":"1760000000:ab12","password":"x","realm":"veydan","ttl_secs":600,"expires_at":1760000000,"urls":["stun:203.0.113.7:3478","turn:203.0.113.7:3478?transport=udp"]}"#,
        )
        .unwrap();
        assert_eq!(creds.urls.len(), 2);

        let refusal: Refusal = serde_json::from_str(r#"{"error":"rate_limited"}"#).unwrap();
        assert_eq!(refusal.error, refusal::RATE_LIMITED);
        assert_eq!(refusal.message, "");
    }
}
