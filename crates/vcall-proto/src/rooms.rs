//! Rooms of the SFU: what a client says to make one, join one and leave
//! one, over the control channel.
//!
//! ```text
//! POST /v1/rooms                 RoomRequest   → RoomCreated     a room, its tokens
//! POST /v1/rooms/{id}/token      TokenRequest  → TokenChanged    a new join token (the admin)
//! POST /v1/rooms/{id}/join       JoinRequest   → Joined          an SDP answer, a seat
//! POST /v1/rooms/{id}/leave      LeaveRequest  → {}              the seat given up
//! POST /v1/rooms/{id}/delegate   DelegateRequest → Delegated     a one-time pass for a proxy seat (the cascade)
//! ```
//!
//! A room is an open label; who may enter is said by the join token, which
//! the creator hands to the group and may replace. Media goes to the SFU
//! port by ICE, not through here; once there, participants talk to each
//! other and hear of each other over the data channel `ctl` ([`ctl`]).
//!
//! The cascade: a participant may sit on a node of its own (B) that holds
//! a seat in the room of the home node (A) for it. The client takes a
//! one-time pass from the home (`delegate`), and joins B with the pass and
//! `home` in its [`JoinRequest`]; B joins the home with the pass and its
//! signed word ([`UplinkWord`]). For the home the seat is an ordinary one.

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::register::{hex, id_of_key, unhex, Unsigned};
use crate::Access;

pub const PATH_ROOMS: &str = "/v1/rooms";

/// The label of a data channel a participant opens for the room's
/// messages: the roster, the offers of the node, and bytes between
/// participants.
pub const CTL_CHANNEL: &str = "ctl";

/// `/v1/rooms/{id}/{action}` taken apart: the room and what is asked of it.
pub fn room_action(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix(PATH_ROOMS)?.strip_prefix('/')?;
    let (id, action) = rest.split_once('/')?;
    (!id.is_empty() && !action.is_empty() && !action.contains('/')).then_some((id, action))
}

pub mod action {
    pub const TOKEN: &str = "token";
    pub const JOIN: &str = "join";
    pub const LEAVE: &str = "leave";
    /// A pass for a proxy seat, by the join token: the cascade.
    pub const DELEGATE: &str = "delegate";
}

/// What the creator may ask of the room. A limit may only lower what the
/// node allows; more than that is cut to the node's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_participants: Option<u32>,
    /// What one participant may send, kbit/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kbps_per_participant: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomRequest {
    #[serde(default)]
    pub access: Access,
    #[serde(default)]
    pub media_limits: MediaLimits,
}

/// What the room is: the label, the two tokens and the limits as set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomCreated {
    /// An open label, 32 hex characters.
    pub room_id: String,
    /// Lets a participant in; given to the group, replaced by the admin.
    pub join_token: String,
    /// Replaces the join token and removes participants; the creator keeps it.
    pub admin_token: String,
    /// Unix seconds: the room ends then whatever is going on.
    pub expires_at: u64,
    /// Unix seconds without participants after which the room ends.
    pub idle_secs: u32,
    pub max_participants: u32,
    pub kbps_per_participant: u32,
    /// `address:port` of the SFU over UDP, and over TCP (RFC 4571 framing).
    pub sfu_udp: String,
    pub sfu_tcp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRequest {
    pub admin_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenChanged {
    pub join_token: String,
}

/// A member of the group asks the home for a one-time pass for a proxy
/// seat, by the join token; the pass goes to the member's own node, the
/// join token never does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateRequest {
    pub token: String,
}

/// The pass: good for one `join` with an [`UplinkWord`] in this room,
/// until `expires_at` (unix seconds).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegated {
    pub proxy_token: String,
    pub expires_at: u64,
}

/// The home of a room, as a client names it to its own node: the node's
/// reference, `address:port#id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeRef {
    pub node: String,
}

/// The client offers; what it offers is what it sends (`sendonly` audio
/// and video), and the data channel `ctl`. What the others send comes
/// later, in offers of the node over that channel.
///
/// With `home`, the request is to the client's own node for a seat in the
/// room of the home: `token` is then a pass from the home
/// ([`Delegated`]), and the node joins the home for the client with its
/// own word ([`UplinkWord`]) in `uplink`. A home takes `uplink` with a
/// pass only, never with the join token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub token: String,
    pub sdp_offer: String,
    /// What the client can take, from [`crate::capability`]: `simulcast`
    /// and the like.
    #[serde(default)]
    pub caps: Vec<String>,
    /// For a private node of one's own, when joining it with `home`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    /// The room's home, when this node is not it (the cascade).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<HomeRef>,
    /// The word of a node joining for one of its participants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink: Option<UplinkWord>,
}

impl JoinRequest {
    /// A plain join: the token, the offer, nothing of the cascade.
    pub fn new(token: impl Into<String>, sdp_offer: impl Into<String>, caps: Vec<String>) -> Self {
        Self { token: token.into(), sdp_offer: sdp_offer.into(), caps, access: None, home: None, uplink: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Joined {
    pub sdp_answer: String,
    /// The seat: what the others see this participant as, in the roster
    /// and in front of relayed bytes. In the cascade, the number the home
    /// gave: seats are one numbering over the whole room.
    pub participant_id: u32,
    /// Gives the seat up over the control channel; nobody else can.
    pub participant_token: String,
    /// Who is in the room already.
    pub participants: Vec<u32>,
    /// In the cascade: the token of the proxy seat at the home, with which
    /// the client may give that seat up itself when its own node is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_token: Option<String>,
}

/// The word of a node B that joins the room of a home A for one of its
/// participants: who B is, and that it holds the pass. The same form as a
/// report to the registry (`vcall-register/1`), under a context of its
/// own; the pass in the signature binds the word to one seat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UplinkWord {
    /// B's id, hex 64: the hash of `key`.
    pub node: String,
    /// B's key, Ed25519, hex 64.
    pub key: String,
    /// Unix seconds, when the word was made.
    pub ts: u64,
    /// Ed25519 over [`UplinkWord::message`], hex 128.
    pub sig: String,
}

impl UplinkWord {
    pub const CONTEXT: &'static str = "vcall-cascade/1\n";

    /// The bytes the key signs: the context, the home's id, the room, the
    /// pass and the time, a line each.
    pub fn message(home_id: &str, room_id: &str, proxy_token: &str, ts: u64) -> Vec<u8> {
        format!("{}{home_id}\n{room_id}\n{proxy_token}\n{ts}", Self::CONTEXT).into_bytes()
    }

    /// As the node B: its word for the pass `proxy_token` in `room_id` at
    /// the home `home_id`, made at `ts`.
    pub fn sign(key: &Ed25519KeyPair, home_id: &str, room_id: &str, proxy_token: &str, ts: u64) -> Self {
        let public: [u8; 32] = key.public_key().as_ref().try_into().expect("an Ed25519 public key");
        Self {
            node: id_of_key(&public),
            key: hex(&public),
            ts,
            sig: hex(key.sign(&Self::message(home_id, room_id, proxy_token, ts)).as_ref()),
        }
    }

    /// As the home: is this the word of the node `node`, for this pass in
    /// this room, made within `skew` seconds of `now`?
    pub fn verify(&self, home_id: &str, room_id: &str, proxy_token: &str, now: u64, skew: u64) -> Result<(), Unsigned> {
        let key: [u8; 32] = unhex(&self.key).and_then(|k| k.try_into().ok()).ok_or(Unsigned::Key)?;
        if id_of_key(&key) != self.node {
            return Err(Unsigned::Key);
        }
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&Self::message(home_id, room_id, proxy_token, self.ts), &unhex(&self.sig).ok_or(Unsigned::Signature)?)
            .map_err(|_| Unsigned::Signature)?;
        if self.ts.abs_diff(now) > skew {
            return Err(Unsigned::Clock);
        }
        Ok(())
    }
}

/// Leaving by request rather than by closing the connection. The token is
/// the participant's own, or the admin's: the admin removes anybody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveRequest {
    pub participant_id: u32,
    pub token: String,
}

/// What goes over the data channel `ctl`.
///
/// Text frames are JSON, one message each, with `t` saying which. The node
/// sends them; the client answers an `offer` with an `answer` and sends
/// nothing else as text. A binary frame from a participant is bytes for
/// the others: the node delivers it to everybody else in the room with
/// the sender's participant id in front (four bytes, big-endian) and
/// reads none of it. That is where the participants prove to each other
/// who they are; the node is not asked to understand.
pub mod ctl {
    use serde::{Deserialize, Serialize};

    /// Bytes of one binary frame a participant may send, and how many
    /// frames a second: enough for a signature and a key, not for a file.
    pub const MAX_FRAME: usize = 16 * 1024;
    pub const MAX_FRAMES_PER_SEC: u32 = 50;
    /// The sender's id in front of a relayed frame.
    pub const FROM_LEN: usize = 4;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "t", rename_all = "snake_case")]
    pub enum Message {
        /// The first message: the seat, and who is in the room.
        Hello { you: u32, participants: Vec<u32> },
        Joined { id: u32 },
        Left { id: u32 },
        /// An offer of the node: new m-lines, each sending one participant's
        /// stream, named in `tracks`. `seq` counts the node's offers to this
        /// participant from 1; an offer unanswered for a while is sent again
        /// with the same `seq` and the same SDP, never a different one in
        /// its place, so a late answer still fits. The client answers with
        /// `answer` carrying the same `seq`.
        Offer { seq: u32, sdp: String, tracks: Vec<Track> },
        /// The client's answer to the offer `seq`. An answer to any other
        /// offer than the one out is dropped by the node.
        Answer { seq: u32, sdp: String },
        /// From the client: the simulcast layer it wants of `participant`'s
        /// video, by rid (the `rids` of the track), for the size of the tile
        /// it shows; `None`, or a rid the origin does not send, is the top
        /// one. The node sends that layer, or a lower one when the client's
        /// bandwidth (TWCC) does not carry it.
        Layer { participant: u32, rid: Option<String> },
        /// From the node: who is talking, loudest first, at most the node's
        /// `VCALL_ROOM_AUDIO_N` of them. Sent when the list changes, not
        /// more often than twice a second. With more participants than that
        /// number and one, only their audio is forwarded.
        Speaking { participants: Vec<u32> },
        /// From a node of the cascade to its participants: the home of the
        /// room stopped answering. The connection is closed after it; the
        /// participants of the room will meet again elsewhere.
        HomeLost,
    }

    /// Which participant's media comes on an m-line, and of what kind.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Track {
        pub id: u32,
        /// `audio` or `video`.
        pub kind: String,
        pub mid: String,
        /// The simulcast layers the origin sends, lowest first (`q`, `h`,
        /// `f` as libwebrtc names them); empty for one stream. The node
        /// forwards one of them on the m-line: see [`Message::Layer`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub rids: Vec<String>,
    }

    /// A relayed frame: the sender's id in front of its bytes.
    pub fn relayed(from: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FROM_LEN + data.len());
        out.extend_from_slice(&from.to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// A relayed frame taken apart.
    pub fn from_relayed(frame: &[u8]) -> Option<(u32, &[u8])> {
        let head: [u8; 4] = frame.get(..FROM_LEN)?.try_into().ok()?;
        Some((u32::from_be_bytes(head), &frame[FROM_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_taken_apart() {
        assert_eq!(room_action("/v1/rooms/abc/join"), Some(("abc", "join")));
        assert_eq!(room_action("/v1/rooms/abc/token"), Some(("abc", "token")));
        assert_eq!(room_action("/v1/rooms"), None);
        assert_eq!(room_action("/v1/rooms/"), None);
        assert_eq!(room_action("/v1/rooms/abc"), None);
        assert_eq!(room_action("/v1/rooms/abc/join/x"), None);
        assert_eq!(room_action("/v1/rooms//join"), None);
    }

    #[test]
    fn ctl_messages_have_a_tag_and_frames_a_sender() {
        let m = ctl::Message::Offer { seq: 1, sdp: "v=0".into(), tracks: vec![ctl::Track { id: 2, kind: "audio".into(), mid: "3".into(), rids: vec![] }] };
        let text = serde_json::to_string(&m).unwrap();
        assert!(text.starts_with(r#"{"t":"offer","seq":1"#), "{text}");
        assert!(!text.contains("rids"), "no layers, no field: {text}");
        let video = ctl::Track { id: 2, kind: "video".into(), mid: "4".into(), rids: vec!["q".into(), "f".into()] };
        assert_eq!(serde_json::to_string(&video).unwrap(), r#"{"id":2,"kind":"video","mid":"4","rids":["q","f"]}"#);
        let layer: ctl::Message = serde_json::from_str(r#"{"t":"layer","participant":2,"rid":"q"}"#).unwrap();
        assert_eq!(layer, ctl::Message::Layer { participant: 2, rid: Some("q".into()) });
        let top: ctl::Message = serde_json::from_str(r#"{"t":"layer","participant":2,"rid":null}"#).unwrap();
        assert_eq!(top, ctl::Message::Layer { participant: 2, rid: None });
        let speaking = serde_json::to_string(&ctl::Message::Speaking { participants: vec![3, 1] }).unwrap();
        assert_eq!(speaking, r#"{"t":"speaking","participants":[3,1]}"#);
        let answer: ctl::Message = serde_json::from_str(r#"{"t":"answer","seq":1,"sdp":"v=0"}"#).unwrap();
        assert_eq!(answer, ctl::Message::Answer { seq: 1, sdp: "v=0".into() });
        assert_eq!(serde_json::from_str::<ctl::Message>(&text).unwrap(), m);
        let hello: ctl::Message = serde_json::from_str(r#"{"t":"hello","you":1,"participants":[]}"#).unwrap();
        assert_eq!(hello, ctl::Message::Hello { you: 1, participants: vec![] });
        let frame = ctl::relayed(7, b"bytes");
        assert_eq!(ctl::from_relayed(&frame), Some((7, &b"bytes"[..])));
        assert_eq!(ctl::from_relayed(b"abc"), None);
        assert_eq!(serde_json::to_string(&ctl::Message::HomeLost).unwrap(), r#"{"t":"home_lost"}"#);
    }

    #[test]
    fn a_plain_join_has_nothing_of_the_cascade_on_the_wire() {
        let plain = JoinRequest::new("t", "v=0", vec![]);
        assert_eq!(serde_json::to_string(&plain).unwrap(), r#"{"token":"t","sdp_offer":"v=0","caps":[]}"#);
        // What a client of version 1 sends is still read, and a joined
        // without a home token is one of a direct seat.
        let old: JoinRequest = serde_json::from_str(r#"{"token":"t","sdp_offer":"v=0"}"#).unwrap();
        assert_eq!(old, plain);
        let joined: Joined =
            serde_json::from_str(r#"{"sdp_answer":"v=0","participant_id":2,"participant_token":"x","participants":[1]}"#).unwrap();
        assert_eq!(joined.home_token, None);
        let via: JoinRequest = serde_json::from_str(
            r#"{"token":"pass","sdp_offer":"v=0","caps":["simulcast"],"home":{"node":"203.0.113.7:443#ab"},"access":{"key":"k"}}"#,
        )
        .unwrap();
        assert_eq!(via.home.as_ref().map(|h| h.node.as_str()), Some("203.0.113.7:443#ab"));
        assert_eq!(via.access.as_ref().and_then(|a| a.key.as_deref()), Some("k"));
        assert_eq!(room_action("/v1/rooms/abc/delegate"), Some(("abc", action::DELEGATE)));
    }

    #[test]
    fn the_word_of_a_node_is_for_one_pass_in_one_room_at_one_home() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let word = UplinkWord::sign(&key, "home", "room", "pass", 1000);
        assert_eq!(word.node.len(), 64);
        assert_eq!(word.verify("home", "room", "pass", 1100, 300), Ok(()));
        assert_eq!(word.verify("home", "room", "pass", 1400, 300), Err(Unsigned::Clock));
        assert_eq!(word.verify("other", "room", "pass", 1000, 300), Err(Unsigned::Signature));
        assert_eq!(word.verify("home", "other", "pass", 1000, 300), Err(Unsigned::Signature));
        assert_eq!(word.verify("home", "room", "other", 1000, 300), Err(Unsigned::Signature));
        let mut forged = word.clone();
        forged.node = "00".repeat(32);
        assert_eq!(forged.verify("home", "room", "pass", 1000, 300), Err(Unsigned::Key));
        let mut stale = word.clone();
        stale.ts += 1;
        assert_eq!(stale.verify("home", "room", "pass", 1000, 300), Err(Unsigned::Signature));
        let back: UplinkWord = serde_json::from_str(&serde_json::to_string(&word).unwrap()).unwrap();
        assert_eq!(back, word);
    }
}
