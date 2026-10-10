//! What the node counts since it started: no addresses, no names, numbers
//! only. `vcall ctl stats` shows them; the registry will get a summary.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

macro_rules! counters {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        /// The live counters.
        #[derive(Default)]
        pub struct Counters {
            $($(#[$doc])* pub $name: AtomicU64,)*
        }

        /// The counters at one moment.
        #[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
        pub struct Snapshot {
            $($(#[$doc])* pub $name: u64,)*
        }

        impl Counters {
            pub fn snapshot(&self) -> Snapshot {
                Snapshot { $($name: self.$name.load(Ordering::Relaxed),)* }
            }
        }
    };
}

counters! {
    /// STUN Binding requests answered.
    stun_bindings,
    /// TURN credentials handed out over the control channel.
    credentials_issued,
    /// Credentials refused: a private node and no key or a wrong one.
    credentials_refused_access,
    /// Credentials refused: too many asked from one address.
    credentials_refused_rate,
    /// Control requests refused for other reasons (a bad body, a pass).
    control_refused,
    /// Allocations made.
    allocations,
    /// Allocations that ended: expired, refreshed to zero, or their stream closed.
    allocations_ended,
    /// A request with credentials that do not hold: a username the node
    /// never gave out, or a wrong password. (A first request without
    /// credentials is the normal way in and is not counted.)
    refused_bad_credentials,
    /// A request with a stale nonce: answered 438, the client retries.
    stale_nonces,
    /// Allocate refused: credentials past their time.
    refused_expired_credentials,
    /// Allocate refused: the node is full.
    refused_quota_total,
    /// Allocate refused: the address has its share.
    refused_quota_ip,
    /// A peer address that is not allowed: private, loopback, the node itself.
    refused_forbidden_peer,
    /// Allocate refused: no relay port was free.
    refused_no_port,
    /// Packets dropped: no permission for the peer.
    dropped_no_permission,
    /// Packets dropped: past the bandwidth of the allocation, of TURN, or of the node.
    dropped_bandwidth,
    /// Packets dropped: the client's stream could not take them.
    dropped_stream_full,
    /// Bytes relayed from clients to peers.
    bytes_to_peers,
    /// Bytes relayed from peers to clients.
    bytes_to_clients,
    /// Connections over TCP and TLS that TURN took.
    stream_connections,
    /// Rooms of the SFU made, and ended (their time, or empty too long).
    rooms_created,
    rooms_ended,
    /// A room refused: the node holds as many as it may.
    rooms_refused_quota,
    /// Participants that joined a room, and that left (or were lost).
    participants_joined,
    participants_left,
    /// Of those that left: taken out for never connecting, a seat held
    /// over the control channel with no ICE and DTLS in time.
    participants_never_connected,
    /// A join refused: the token is not the room's, the room is full, the
    /// offer could not be taken (or carries too many m-lines).
    joins_refused_token,
    joins_refused_full,
    joins_refused_sdp,
    /// RTP packets and bytes a room took from participants, and gave out.
    sfu_packets_in,
    sfu_bytes_in,
    sfu_packets_out,
    sfu_bytes_out,
    /// Packets not forwarded: past a participant's or the node's
    /// bandwidth; no payload type of the receiver for the codec.
    sfu_dropped_bandwidth,
    sfu_dropped_no_codec,
    /// Packets on the SFU port from an address and a ufrag no room knows.
    sfu_dropped_unrouted,
    /// Packets a room could not take in time.
    sfu_dropped_queue,
    /// Packets to participants the SFU socket could not take: over UDP
    /// the send buffer was full (or the address is no good), over TCP the
    /// participant's stream queue was.
    sfu_dropped_socket,
    sfu_dropped_stream_full,
    /// Offers of the node sent again, unanswered too long; answers to
    /// another offer than the one out, dropped.
    sfu_offers_repeated,
    sfu_answers_stale,
    /// Audio packets that carried an audio level.
    sfu_audio_level_packets,
    /// Keyframe requests passed on to the origin of a stream.
    sfu_keyframe_requests,
    /// Simulcast: layers a receiver asked for over `ctl`, and switches of
    /// the layer forwarded to a receiver (asked for, or by its bandwidth).
    sfu_layer_requests,
    sfu_layer_switches,
    /// Changes of the list of speakers told over `ctl`.
    sfu_speaking_changes,
    /// Frames between participants relayed over `ctl`, and dropped: too
    /// big, too many, or nobody's channel could take them.
    sfu_ctl_messages,
    sfu_ctl_dropped,
    /// Connections the SFU took over TCP.
    sfu_tcp_connections,
    /// The cascade, as a home: passes for proxy seats handed out; seats
    /// of other nodes taken; refused for the node not being on the list
    /// (or the cascade being off), or for its quota; given up for silence.
    cascade_passes_issued,
    cascade_seats_joined,
    cascade_joins_refused_list,
    cascade_joins_refused_quota,
    cascade_seats_reaped,
    /// The cascade, as a node of participants: satellites made and ended;
    /// uplinks made; joins with a home refused here (off, a key wanted,
    /// too many attempts or uplinks, a home that takes none) and homes
    /// not reached; homes lost; bytes up to homes and down from them;
    /// packets of a home past the uplink's bandwidth.
    satellites_made,
    satellites_ended,
    cascade_uplinks_made,
    cascade_joins_refused,
    cascade_joins_unreachable,
    cascade_homes_lost,
    cascade_bytes_up,
    cascade_bytes_down,
    cascade_dropped_bandwidth,
    /// The registry's list of nodes (the trust of the cascade): taken,
    /// and not taken (not reached, not signed by the root's delegate).
    trust_list_refreshed,
    trust_list_failed,
    /// Invitations to a private node exchanged for a device's
    /// credentials, and refused (no such invitation, used up, run out,
    /// or too many attempts from one address).
    invites_exchanged,
    invites_refused,
}

/// `counters.allocations.bump()`: one more.
pub trait Bump {
    fn bump(&self);
    fn add(&self, n: u64);
}

impl Bump for AtomicU64 {
    fn bump(&self) {
        self.fetch_add(1, Ordering::Relaxed);
    }

    fn add(&self, n: u64) {
        self.fetch_add(n, Ordering::Relaxed);
    }
}
