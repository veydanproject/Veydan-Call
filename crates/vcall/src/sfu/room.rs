//! One room: its participants, and what goes between them.
//!
//! ```text
//!  A ──RTP──▶ room ──▶ B, C   each packet of A goes to everybody else, as it came
//!  A ──ctl──▶ room ──▶ B, C   bytes between participants, the node reads none
//!  room ──ctl──▶ A            who is here, who talks, and offers of the m-lines B and C send on
//! ```
//!
//! A room is one task owning one `Rtc` per participant: packets of its
//! participants come in on a channel from the sockets, nothing in here is
//! shared or locked. Every stream has an [`Origin`]: a participant of this
//! room today, a neighbouring node tomorrow (the cascade of stage 8); the
//! forwarding is written against the origin, not against a participant.
//!
//! What a participant sends is declared in its offer when it joins. What
//! it receives, the node declares: for every stream of every other
//! participant an m-line of its own, offered over the data channel `ctl`
//! and answered there. So a client offers only once, over the control
//! channel, and never while the node does.
//!
//! A video stream may come in simulcast layers (rids, lowest first); each
//! receiver gets one of them on its m-line, the one it asked for over
//! `ctl` or a lower one when its bandwidth (TWCC) does not carry it, and
//! the change of layer waits for a keyframe. Audio goes from the speakers
//! only, once the room is bigger than a conversation.
//!
//! The cascade, two ways. As a **home**, a room gives seats to other
//! nodes on a one-time pass and the node's word: such a seat is an
//! ordinary participant with `uplink` set, whose streams and bytes are
//! not sent back to other seats of the same node, and who is given up
//! after a few seconds of silence. As a **satellite** (`home` set), a
//! room holds seats of this node in a room elsewhere: for each seat one
//! [`Uplink`], a str0m participant of the home's room; what the seat
//! sends goes up on its uplink as it came, what the home sends down on
//! the uplink comes to the seat as streams of [`Origin::Node`]; the home's
//! roster, speakers and bytes are passed through, and between the seats
//! of one satellite everything goes as in a room of this node.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::bwe::{Bitrate, BweKind};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelData, ChannelId};
use str0m::format::{Codec, CodecConfig};
use str0m::media::{Direction, KeyframeRequest, KeyframeRequestKind, MediaKind, Mid, Pt, Rid, Rids};
use str0m::net::{Protocol, Receive, TcpType};
use str0m::rtp::{ExtensionValues, RtpPacket, RtpWrite, SeqNo, Ssrc};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tokio::sync::{mpsc, oneshot};
use vcall_proto::rooms::{ctl, Delegated, JoinRequest, Joined, LeaveRequest, TokenChanged};

use super::sdp;
use super::uplink::{DownTrack, Uplink};
use super::{Home, Reach, RoomError, Shared, DELEGATE_PER_SEAT, DELEGATE_TTL, HOME_LOST, SATELLITE_IDLE, UPLINK_CLOSE_GRACE, UPLINK_SEATLESS, UPLINK_SILENCE};
use crate::counters::Bump;
use crate::identity::same_secret;
use crate::turn::auth::{hex, random};
use crate::turn::limits::Bucket;
use crate::turn::unix_now;

/// The word of an uplink may be this far from the home's clock.
const WORD_SKEW: u64 = 300;

/// After an answer the node could not take, the next offer waits this
/// long, so that a client that answers wrongly does not get one every
/// millisecond.
const OFFER_BACKOFF: Duration = Duration::from_secs(2);
/// An offer the channel could not take (its queue full) is tried again
/// after this.
const OFFER_RETRY: Duration = Duration::from_secs(1);
/// New m-lines in one offer at the most. The rest wait for the next
/// offer, after the answer: an offer must fit the peer's SCTP message
/// (64 KiB by default) and the node's send queue, and a video m-line of
/// the node's offer is over a kilobyte.
pub const OFFER_TRACKS: usize = 8;
/// Audio and video m-lines a participant may declare in its offer: voice,
/// camera, a screen and one to spare. Each becomes an m-line of the
/// node's offers to every other participant.
pub const MAX_RX_TRACKS: usize = 4;
/// Addresses one participant's packets are routed by at the most. ICE
/// needs a few (the address behind the NAT, a relay or two); the oldest
/// makes room for a new one. A participant can make the node take STUN
/// from any source address it likes, and the maps must not grow with it.
pub const MAX_ADDRS: usize = 8;
/// Keyframe requests to one layer of one stream are passed on no more
/// often than this; and one receiver makes the node ask for a keyframe of
/// one stream no more often than this, whichever layer it asks for. A
/// receiver waiting for a keyframe of its layer asks again at this pace
/// until it comes: a request the layer's limit dropped, or the network
/// lost, is not the end of its picture.
const KEYFRAME_EVERY: Duration = Duration::from_secs(1);
/// SSRCs one participant's packets are mapped by at the most: its layers
/// (a few per m-line) and a change of SSRC or two. Past that the map is
/// pruned of SSRCs str0m has no stream for any more, and cleared when that
/// frees nothing: a participant can put a fresh SSRC on every packet, and
/// the map must not grow with it.
const MAX_SSRCS: usize = 32;
/// The desired bitrate (what the estimate probes up to) is told to str0m
/// again when it moved by more than this part of itself: every change
/// starts probes, and the measured rates it is made of move all the time.
const DESIRED_STEP: f64 = 0.1;
/// With no `Rtc` to wake for, the room looks at its clock this often.
const IDLE_TICK: Duration = Duration::from_secs(1);
/// Above this level (negative dB; 0 is the loudest) a packet counts as
/// somebody talking.
const TALKING_ABOVE: i8 = -50;
/// The room looks at who talks, and at what each receiver's bandwidth
/// carries, this often: the list of speakers changes at most twice a
/// second, as the protocol says.
pub const ROOM_TICK: Duration = Duration::from_millis(500);
/// A speaker that said nothing for this long gives its place up.
const TALK_HOLD: Duration = Duration::from_millis(1500);
/// Somebody not among the speakers takes the quietest speaker's place
/// when louder by this much (dB): a word in between does not reshuffle
/// everybody's audio.
const SWAP_MARGIN: f32 = 8.0;
/// A layer with no packet for this long is not sent: the origin stopped
/// it (libwebrtc drops its upper layers when its own uplink is short).
const LAYER_STALE: Duration = Duration::from_millis(1500);
/// A layer's rate is measured over windows this long, and smoothed.
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// A receiver's layers are chosen to use at most this part of its
/// estimate; stepping up needs the smaller part to fit, and this long
/// since the last switch, so that a wobbling estimate does not make the
/// picture wobble with it.
const BUDGET_DOWN: f64 = 0.9;
const BUDGET_UP: f64 = 0.75;
const UP_HOLD: Duration = Duration::from_secs(3);
/// What one audio m-line is reckoned to take of a receiver's bandwidth.
const AUDIO_BPS: u64 = 64_000;
/// The clock of the video codecs the node forwards.
const VIDEO_CLOCK: u64 = 90_000;

/// Where a stream comes from: a participant of this room, or the home of
/// a satellite, over the uplink of the seat it is for (the seat's number:
/// an uplink is one to a seat). The forwarding asks "who is this origin"
/// rather than "which participant".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    Client(u32),
    Node(u32),
}

/// One stream of the room: an m-line at its origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub origin: Origin,
    pub mid: Mid,
}

/// What the sockets and the control channel tell a room.
pub(crate) enum RoomInput {
    Packet { proto: Protocol, source: SocketAddr, at: Instant, data: Vec<u8> },
    Join { request: JoinRequest, reply: oneshot::Sender<Result<Joined, RoomError>> },
    Leave { request: LeaveRequest, reply: oneshot::Sender<Result<(), RoomError>> },
    Token { admin_token: String, reply: oneshot::Sender<Result<TokenChanged, RoomError>> },
    /// A pass for a proxy seat, by the join token (a home).
    Delegate { token: String, reply: oneshot::Sender<Result<Delegated, RoomError>> },
    /// A TCP connection closed: whoever came over it is gone from that address.
    Gone { proto: Protocol, source: SocketAddr },
    /// A satellite: an uplink to drive, answered by the home already;
    /// `ready` is told when its `ctl` opens, or when it fails.
    Uplink { uplink: Box<Uplink>, ready: oneshot::Sender<Result<(), String>> },
    /// A satellite: the uplink of `seat` is not wanted after all.
    DropUplink { seat: u32 },
    /// A satellite: the seat whose uplink is up takes its place; `others`
    /// is the home's roster as its join answered (the others at the seat).
    JoinSeat { seat: u32, request: JoinRequest, home_bandwidth: Vec<Option<u32>>, others: Vec<u32>, reply: oneshot::Sender<Result<Joined, RoomError>> },
    /// A satellite: a datagram from the home on the uplink of `seat`.
    UplinkPacket { seat: u32, source: SocketAddr, at: Instant, data: Vec<u8> },
    /// A satellite: another satellite of the same home lost it.
    HomeLost,
    /// The node is gone (a test): end without a word to anybody.
    Vanish,
}

pub(crate) type RoomSender = mpsc::Sender<RoomInput>;

/// Bits a second of one stream: the last full window, smoothed with the
/// ones before.
#[derive(Clone, Copy)]
struct RateMeter {
    window_start: Instant,
    bytes: u64,
    bps: u64,
    /// A full window was measured: before that the rate is unknown.
    measured: bool,
}

impl RateMeter {
    fn new(now: Instant) -> Self {
        Self { window_start: now, bytes: 0, bps: 0, measured: false }
    }

    fn add(&mut self, now: Instant, bytes: usize) {
        self.bytes += bytes as u64;
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed >= RATE_WINDOW {
            let measured = self.bytes * 8 * 1000 / (elapsed.as_millis() as u64).max(1);
            self.bps = if self.measured { (self.bps * 3 + measured) / 4 } else { measured };
            self.measured = true;
            self.bytes = 0;
            self.window_start = now;
        }
    }

    /// The rate, once a window was measured and the stream still comes.
    fn bps(&self, now: Instant) -> Option<u64> {
        (self.measured && now.saturating_duration_since(self.window_start) < 2 * RATE_WINDOW).then_some(self.bps)
    }
}

/// One layer of a stream a participant sends: a simulcast rid, or the
/// single stream (no rid).
struct Layer {
    rid: Option<Rid>,
    rate: RateMeter,
    last_packet: Option<Instant>,
    last_keyframe_request: Option<Instant>,
}

impl Layer {
    fn new(rid: Option<Rid>, now: Instant) -> Self {
        Self { rid, rate: RateMeter::new(now), last_packet: None, last_keyframe_request: None }
    }

    fn alive(&self, now: Instant) -> bool {
        self.last_packet.is_some_and(|t| now.saturating_duration_since(t) < LAYER_STALE)
    }
}

/// A stream a participant sends, as announced in its offer: its layers,
/// lowest first as the offer declared them.
struct RxTrack {
    mid: Mid,
    kind: MediaKind,
    layers: Vec<Layer>,
}

impl RxTrack {
    /// The rids of a stream in layers; none for one stream.
    fn rids(&self) -> Vec<String> {
        if self.layers.len() < 2 {
            return Vec::new();
        }
        self.layers.iter().filter_map(|l| l.rid.map(|r| r.to_string())).collect()
    }
}

/// A stream the node sends to a participant: somebody else's, on an
/// m-line of the node's offer.
struct TxTrack {
    source: StreamKey,
    kind: MediaKind,
    state: TxState,
    /// The main and the repair SSRC, once declared.
    ssrcs: Option<(Ssrc, Option<Ssrc>)>,
    /// The participant's payload type for each of the origin's, as matched.
    pts: HashMap<Pt, Option<Pt>>,
    /// The sequence numbers and timestamps the receiver sees.
    rewrite: Rewrite,
    /// The layer the receiver asked for; `None` is the top one.
    wanted: Option<Rid>,
    /// The layer of the origin being forwarded (an index into its layers),
    /// and the one to switch to at its next keyframe.
    current: Option<usize>,
    target: Option<usize>,
    switched_at: Instant,
    /// When the origin was last asked for a keyframe on this receiver's
    /// account (for a target, or a PLI of the receiver's own).
    asked_at: Option<Instant>,
    /// Audio of somebody who is not among the speakers: held back.
    held: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxState {
    ToOpen,
    Negotiating(Mid),
    Open(Mid),
    ToStop(Mid),
    NegotiatingStop(Mid),
}

impl TxTrack {
    fn new(source: StreamKey, kind: MediaKind, layers: usize, now: Instant) -> Self {
        Self {
            source,
            kind,
            state: TxState::ToOpen,
            ssrcs: None,
            pts: HashMap::new(),
            rewrite: Rewrite::new(),
            wanted: None,
            current: None,
            // A stream of one layer goes from its first packet (the receiver
            // asks for its keyframe itself). Layers wait for the plan and a
            // keyframe of the layer chosen.
            target: (kind.is_audio() || layers == 1).then_some(0),
            switched_at: now,
            asked_at: None,
            held: false,
        }
    }

    /// Whether a keyframe may be asked for on this receiver's account now.
    fn may_ask(&self, now: Instant) -> bool {
        self.asked_at.is_none_or(|t| now.saturating_duration_since(t) >= KEYFRAME_EVERY)
    }

    fn mid(&self) -> Option<Mid> {
        match self.state {
            TxState::ToOpen => None,
            TxState::Negotiating(m) | TxState::Open(m) | TxState::ToStop(m) | TxState::NegotiatingStop(m) => Some(m),
        }
    }

    /// The layer the track is at, or is going to.
    fn layer(&self) -> Option<usize> {
        self.target.or(self.current)
    }
}

/// The sequence numbers and timestamps a receiver sees: counted from a
/// low random one (SRTP counts rollovers from zero on a new stream),
/// step by step with the origin within a run, and contiguous across a
/// change of layer or a pause, where the origin's jump.
struct Rewrite {
    /// out = in + offset, in the extended domain.
    seq_offset: i64,
    /// Input below this is from before the run: dropped.
    run_start: u64,
    last_out_seq: u64,
    ts_offset: u32,
    last_out_ts: u32,
    last_arrival: Option<Instant>,
    /// The next packet starts a run: the first one, or one after a switch
    /// or a pause.
    rebase: bool,
}

impl Rewrite {
    fn new() -> Self {
        Self { seq_offset: 0, run_start: 0, last_out_seq: 0, ts_offset: 0, last_out_ts: 0, last_arrival: None, rebase: true }
    }

    /// The next packet starts a new run, contiguous with the last one.
    fn restart(&mut self) {
        self.rebase = true;
    }

    /// The numbers of a packet of the origin, or none for a packet from
    /// before the run. Video timestamps continue from the last packet by
    /// the time that passed: the layers of one source are clocked apart.
    fn map(&mut self, kind: MediaKind, seq_in: u64, ts_in: u32, arrival: Instant) -> Option<(SeqNo, u32)> {
        if self.rebase {
            self.rebase = false;
            match self.last_arrival {
                None => {
                    // Somewhere low in the first rollover, as a fresh sender starts.
                    let start = u64::from(u16::from_be_bytes([random(1)[0] & 0x3f, random(1)[0]])) + 1;
                    self.seq_offset = start as i64 - seq_in as i64;
                    self.ts_offset = 0;
                }
                Some(last) => {
                    self.seq_offset = (self.last_out_seq + 1) as i64 - seq_in as i64;
                    if kind.is_video() {
                        let elapsed = arrival.saturating_duration_since(last).clamp(Duration::from_millis(1), Duration::from_secs(5));
                        let ticks = (elapsed.as_secs_f64() * VIDEO_CLOCK as f64) as u32;
                        self.ts_offset = self.last_out_ts.wrapping_add(ticks.max(1)).wrapping_sub(ts_in);
                    }
                }
            }
            self.run_start = seq_in;
        }
        if seq_in < self.run_start {
            return None;
        }
        let out_seq = (seq_in as i64 + self.seq_offset) as u64;
        let out_ts = ts_in.wrapping_add(self.ts_offset);
        if out_seq >= self.last_out_seq {
            self.last_out_seq = out_seq;
            self.last_out_ts = out_ts;
        }
        self.last_arrival = Some(arrival);
        Some((SeqNo::from(out_seq), out_ts))
    }
}

/// What the audio-level extension said of a participant lately: a
/// smoothed loudness (0 silent, 127 the loudest), and when it last spoke.
#[derive(Default)]
struct AudioMeter {
    last_level: Option<i8>,
    packets: u64,
    talking: u64,
    loudness: f32,
    last_talk: Option<Instant>,
}

impl AudioMeter {
    fn hear(&mut self, level: i8, now: Instant) {
        self.packets += 1;
        self.last_level = Some(level);
        let lin = f32::from(127i16.saturating_add(i16::from(level)).clamp(0, 127));
        self.loudness = if self.packets == 1 { lin } else { self.loudness * 0.8 + lin * 0.2 };
        if level > TALKING_ABOVE {
            self.talking += 1;
            self.last_talk = Some(now);
        }
    }

    /// How loud, while talking; zero after a silence.
    fn score(&self, now: Instant) -> f32 {
        match self.last_talk {
            Some(t) if now.saturating_duration_since(t) < TALK_HOLD => self.loudness,
            _ => 0.0,
        }
    }
}

/// An offer of the node that is out: answered by `seq`, and sent again
/// as it is until it is.
struct Pending {
    offer: SdpPendingOffer,
    seq: u32,
    sdp: String,
    tracks: Vec<ctl::Track>,
    /// When it last went out; `None` when the channel did not take it.
    sent: Option<Instant>,
}

struct Participant {
    id: u32,
    token: String,
    rtc: Rtc,
    ufrag: String,
    /// The addresses the participant's packets came from, as routed,
    /// oldest first; at most [`MAX_ADDRS`].
    addrs: VecDeque<(Protocol, SocketAddr)>,
    joined_at: Instant,
    ctl: Option<ChannelId>,
    pending: Option<Pending>,
    /// Offers made to this participant so far: the next one's `seq` is
    /// one more.
    offers: u32,
    next_offer: Instant,
    rx_tracks: Vec<RxTrack>,
    tx_tracks: Vec<TxTrack>,
    /// Which m-line and layer each incoming SSRC belongs to, once seen.
    ssrc_layers: HashMap<Ssrc, (Mid, usize)>,
    ingress: Bucket,
    egress: Bucket,
    ctl_rate: Bucket,
    audio: AudioMeter,
    /// What the participant's TWCC feedback says the way to it carries,
    /// bit/s; none until it says.
    bwe: Option<u64>,
    /// What the estimate was last told to probe up to.
    desired: u64,
    connected: bool,
    /// A seat of another node (the cascade): that node's id. Nothing of
    /// this seat goes to other seats of the same node.
    uplink: Option<String>,
    /// When a packet last came, for a seat of another node: silence
    /// beyond [`UPLINK_SILENCE`] gives it up.
    last_packet: Instant,
}

pub(super) struct Room {
    id: String,
    shared: Arc<Shared>,
    tx: RoomSender,
    rx: mpsc::Receiver<RoomInput>,
    join_token: String,
    admin_token: String,
    max_participants: u32,
    kbps_per_participant: u32,
    expires: Instant,
    empty_since: Option<Instant>,
    participants: Vec<Participant>,
    next_id: u32,
    /// Who talks, loudest first, as last told (a satellite: as the home
    /// last said).
    speakers: Vec<u32>,
    next_tick: Instant,
    /// Passes for proxy seats, and when each is void (a home).
    proxy_tokens: Vec<(String, Instant)>,
    /// A satellite: the home, the uplinks (one a seat), and the roster
    /// of the home's room as last told.
    home: Option<Home>,
    uplinks: Vec<Uplink>,
    roster: Vec<u32>,
    /// A satellite ends with its last seat; one that never had a seat
    /// ends after a while.
    had_seat: bool,
    ending: bool,
    /// A satellite taken out of the table already (it settled).
    removed: bool,
    /// The node is gone (a test): nothing is sent any more.
    vanished: bool,
}

impl Room {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        id: String,
        shared: Arc<Shared>,
        tx: RoomSender,
        rx: mpsc::Receiver<RoomInput>,
        join_token: String,
        admin_token: String,
        max_participants: u32,
        kbps_per_participant: u32,
        lifetime: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            shared,
            tx,
            rx,
            join_token,
            admin_token,
            max_participants,
            kbps_per_participant,
            expires: now + lifetime,
            empty_since: Some(now),
            participants: Vec::new(),
            next_id: 1,
            speakers: Vec::new(),
            next_tick: now + ROOM_TICK,
            proxy_tokens: Vec::new(),
            home: None,
            uplinks: Vec::new(),
            roster: Vec::new(),
            had_seat: false,
            ending: false,
            removed: false,
            vanished: false,
        }
    }

    /// A satellite of `home`'s room `id`: no tokens of its own (the home
    /// judges who comes), no limit of seats (the home has one), the
    /// node's bandwidth per seat.
    pub(super) fn new_satellite(id: String, shared: Arc<Shared>, tx: RoomSender, rx: mpsc::Receiver<RoomInput>, home: Home) -> Self {
        let kbps = shared.config.kbps_per_participant;
        let lifetime = shared.config.lifetime;
        let mut room = Self::new(id, shared, tx, rx, hex(&random(24)), hex(&random(24)), u32::MAX, kbps, lifetime);
        room.home = Some(home);
        room
    }

    fn is_satellite(&self) -> bool {
        self.home.is_some()
    }

    /// The room for as long as it lasts: its lifetime, or its idle time
    /// without participants, whichever comes first; a satellite, until
    /// its last seat leaves or its home is lost, or, never seated, until
    /// it has been empty for its idle time.
    pub(super) async fn run(mut self) {
        loop {
            let now = Instant::now();
            if self.ending || now >= self.expires {
                break;
            }
            if self.is_satellite() {
                if self.idle_out(now) {
                    break;
                }
            } else if self.empty_since.is_some_and(|since| now.duration_since(since) >= self.shared.config.idle) {
                break;
            }
            if now >= self.next_tick {
                self.tick(now);
                self.next_tick = now + ROOM_TICK;
            }
            let earliest = self.poll_all();
            self.reap();
            if self.ending {
                break;
            }
            // A satellite is for its seats: the last one gone and no
            // uplink on its way to one, it ends, unless a join for it is
            // in the queue this moment.
            if self.is_satellite() && self.had_seat && self.participants.is_empty() && self.uplinks.is_empty() {
                if self.settle() {
                    break;
                }
                continue;
            }
            let idle = if self.is_satellite() { SATELLITE_IDLE } else { self.shared.config.idle };
            let deadline = earliest.unwrap_or(now + IDLE_TICK).min(self.expires);
            let deadline = match self.empty_since {
                Some(since) => deadline.min(since + idle),
                None => deadline.min(self.next_tick),
            };
            // A seat still waiting for its participant is looked at when
            // its time is up, whatever the `Rtc`s ask for; so is a seat of
            // another node that fell silent, and a home that did.
            let connect_timeout = self.shared.config.connect_timeout;
            let deadline = self
                .participants
                .iter()
                .filter_map(|p| {
                    let connect = (!p.connected).then_some(p.joined_at + connect_timeout);
                    let silence = (p.connected && p.uplink.is_some()).then_some(p.last_packet + UPLINK_SILENCE);
                    connect.into_iter().chain(silence).min()
                })
                .chain(self.uplinks.iter().filter(|u| u.connected).map(|u| u.last_packet + HOME_LOST))
                // An uplink closing is given its grace, one gone is reaped now.
                .chain(self.uplinks.iter().filter_map(|u| if u.rtc.is_alive() { u.closed_at.map(|at| at + UPLINK_CLOSE_GRACE) } else { Some(now) }))
                .fold(deadline, Instant::min);
            tokio::select! {
                input = self.rx.recv() => match input {
                    Some(input) => self.handle(input),
                    None => break,
                },
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    let now = Instant::now();
                    for p in &mut self.participants {
                        if let Err(e) = p.rtc.handle_input(Input::Timeout(now)) {
                            tracing::debug!(room = %self.id, participant = p.id, error = %e, "timeout");
                            p.rtc.disconnect();
                        }
                    }
                    for u in &mut self.uplinks {
                        if let Err(e) = u.rtc.handle_input(Input::Timeout(now)) {
                            tracing::debug!(room = %self.id, seat = u.seat, error = %e, "uplink timeout");
                            u.rtc.disconnect();
                        }
                    }
                }
            }
            // Whatever arrived behind the first input is handled before the
            // next poll: a burst of packets is one wake, not many.
            while let Ok(input) = self.rx.try_recv() {
                self.handle(input);
            }
        }
        self.end();
    }

    fn end(mut self) {
        tracing::debug!(room = %self.id, participants = self.participants.len(), satellite = self.is_satellite(), "room ends");
        // Everybody is told; what the close has to send goes out now, and
        // whoever did not get it finds out by ICE. A satellite closes its
        // uplinks too: the home gives the seats up at once.
        if !self.vanished {
            for p in &mut self.participants {
                let _ = p.rtc.close();
            }
            for u in &mut self.uplinks {
                let _ = u.rtc.close();
            }
            self.poll_all();
        }
        for p in &mut self.participants {
            p.rtc.disconnect();
        }
        for u in &mut self.uplinks {
            u.rtc.disconnect();
        }
        let ids: Vec<u32> = self.participants.iter().map(|p| p.id).collect();
        for id in ids {
            self.remove(id);
        }
        let seats: Vec<u32> = self.uplinks.iter().map(|u| u.seat).collect();
        for seat in seats {
            self.remove_uplink(seat);
        }
        match &self.home {
            Some(_) => {
                if !self.removed {
                    let shared = self.shared.clone();
                    let mut satellites = shared.satellites.lock().expect("satellites");
                    self.leave_table(&mut satellites);
                }
            }
            None => {
                self.shared.rooms.lock().expect("rooms").remove(&self.id);
                self.shared.rooms_now.fetch_sub(1, Ordering::Relaxed);
                self.shared.counters.rooms_ended.bump();
            }
        }
    }

    /// A satellite out of the table, counted as ended: with the table
    /// locked by the caller.
    fn leave_table(&mut self, satellites: &mut HashMap<(SocketAddr, String), RoomSender>) {
        let Some(home) = &self.home else { return };
        satellites.remove(&(home.addr(), self.id.clone()));
        self.removed = true;
        self.shared.satellites_now.fetch_sub(1, Ordering::Relaxed);
        self.shared.counters.satellites_ended.bump();
    }

    /// A satellite empty for its idle time (one that never came to a
    /// seat, as one that had seats ends with the last): whether it ends
    /// now. Not while an uplink is on its way to a seat (the join that
    /// made it is between the uplink and the seat; one that never comes
    /// to a seat is closed by [`Self::reap_uplinks`]), and decided as
    /// [`Self::settle`] decides it: a join queued this moment keeps it,
    /// not to be dropped with the queue and taken for the home failing.
    fn idle_out(&mut self, now: Instant) -> bool {
        self.empty_since.is_some_and(|since| now.duration_since(since) >= SATELLITE_IDLE) && self.uplinks.is_empty() && self.settle()
    }

    /// A satellite with nothing left: out of the table, unless a join
    /// for it is on its way. Decided with the table locked, as the joins
    /// send with it locked ([`super::Sfu::send_to_satellite`]): an uplink
    /// or a seat queued this moment is taken, and nothing is sent to a
    /// satellite that ended. Whether it ended.
    fn settle(&mut self) -> bool {
        let mut queued = Vec::new();
        let ended = {
            let shared = self.shared.clone();
            let mut satellites = shared.satellites.lock().expect("satellites");
            while let Ok(input) = self.rx.try_recv() {
                queued.push(input);
            }
            let wanted = queued.iter().any(|input| matches!(input, RoomInput::Uplink { .. } | RoomInput::JoinSeat { .. }));
            if !wanted {
                self.leave_table(&mut satellites);
            }
            !wanted
        };
        if ended {
            // Nothing queued matters to a satellite that ends, but a node
            // gone (a test) is not to send its closes.
            self.vanished |= queued.iter().any(|input| matches!(input, RoomInput::Vanish));
            self.ending = true;
            return true;
        }
        tracing::debug!(room = %self.id, "a join came as the satellite was ending: it goes on");
        for input in queued {
            self.handle(input);
        }
        false
    }

    fn handle(&mut self, input: RoomInput) {
        match input {
            RoomInput::Packet { proto, source, at, data } => self.packet(proto, source, at, &data),
            RoomInput::Join { request, reply } => {
                let _ = reply.send(self.join(request));
            }
            RoomInput::Leave { request, reply } => {
                let _ = reply.send(self.leave(request));
            }
            RoomInput::Token { admin_token, reply } => {
                let _ = reply.send(self.change_token(&admin_token));
            }
            RoomInput::Delegate { token, reply } => {
                let _ = reply.send(self.delegate(&token));
            }
            RoomInput::Gone { proto, source } => {
                for p in &mut self.participants {
                    p.addrs.retain(|a| *a != (proto, source));
                }
            }
            RoomInput::Uplink { uplink, ready } => self.add_uplink(*uplink, ready),
            RoomInput::DropUplink { seat } => {
                if let Some(u) = self.uplinks.iter().position(|u| u.seat == seat) {
                    self.close_uplink(u);
                }
            }
            RoomInput::JoinSeat { seat, request, home_bandwidth, others, reply } => {
                let _ = reply.send(self.join_seat(seat, request, &home_bandwidth, &others));
            }
            RoomInput::UplinkPacket { seat, source, at, data } => self.uplink_packet(seat, source, at, &data),
            RoomInput::HomeLost => self.home_lost(false),
            RoomInput::Vanish => {
                self.vanished = true;
                self.ending = true;
            }
        }
    }

    fn packet(&mut self, proto: Protocol, source: SocketAddr, at: Instant, data: &[u8]) {
        let destination = match proto {
            Protocol::Udp => self.shared.udp_addr,
            _ => self.shared.tcp_addr,
        };
        let Ok(recv) = Receive::new(proto, source, destination, data) else {
            return;
        };
        let input = Input::Receive(at, recv);
        let Some(i) = self.participants.iter().position(|p| p.rtc.accepts(&input)) else {
            tracing::trace!(room = %self.id, %source, "a packet nobody takes");
            return;
        };
        let p = &mut self.participants[i];
        if !p.addrs.contains(&(proto, source)) {
            let mut routes = self.shared.routes.lock().expect("routes");
            if p.addrs.len() >= MAX_ADDRS {
                if let Some(old) = p.addrs.pop_front() {
                    routes.remove(&old);
                }
            }
            p.addrs.push_back((proto, source));
            routes.insert((proto, source), self.tx.clone());
        }
        p.last_packet = at;
        if let Err(e) = p.rtc.handle_input(input) {
            tracing::debug!(room = %self.id, participant = p.id, error = %e, "input refused");
            p.rtc.disconnect();
        }
        // Polled before the next packet: in RTP mode str0m holds one received
        // packet for the next poll, and a second one in between would take
        // its place.
        self.poll_one(i);
    }

    // ---- joining and leaving --------------------------------------------

    /// A pass for a proxy seat, by the join token: one-time, good for a
    /// minute, so many alive at once (the oldest makes room).
    fn delegate(&mut self, token: &str) -> Result<Delegated, RoomError> {
        if self.is_satellite() {
            return Err(RoomError::NotFound);
        }
        if !same_secret(token.as_bytes(), self.join_token.as_bytes()) {
            self.shared.counters.joins_refused_token.bump();
            return Err(RoomError::BadToken);
        }
        let now = Instant::now();
        self.proxy_tokens.retain(|(_, until)| *until > now);
        let most = DELEGATE_PER_SEAT * self.max_participants as usize;
        while self.proxy_tokens.len() >= most {
            self.proxy_tokens.remove(0);
        }
        let proxy_token = hex(&random(24));
        self.proxy_tokens.push((proxy_token.clone(), now + DELEGATE_TTL));
        self.shared.counters.cascade_passes_issued.bump();
        Ok(Delegated { proxy_token, expires_at: unix_now() + DELEGATE_TTL.as_secs() })
    }

    /// The live pass `token`, if it is one: its place in the list.
    fn proxy_token_at(&mut self, token: &str) -> Option<usize> {
        let now = Instant::now();
        self.proxy_tokens.retain(|(_, until)| *until > now);
        // Every one is compared, so that the time says nothing of which
        // matched.
        let mut found = None;
        for (n, (t, _)) in self.proxy_tokens.iter().enumerate() {
            if same_secret(t.as_bytes(), token.as_bytes()) {
                found = Some(n);
            }
        }
        found
    }

    /// The word of a node that wants a seat: whose, if it holds and the
    /// node is admitted and under its quota.
    fn admit_uplink(&mut self, request: &JoinRequest, pass: &str) -> Result<String, RoomError> {
        let word = request.uplink.as_ref().expect("an uplink");
        if let Err(e) = word.verify(&self.shared.config.node_id, &self.id, pass, unix_now(), WORD_SKEW) {
            self.shared.counters.control_refused.bump();
            return Err(RoomError::BadWord(format!("the word of the node does not hold: {e}")));
        }
        let (admitted, listed) = self.shared.config.trust.admits(&word.node.to_ascii_lowercase());
        if !admitted {
            self.shared.counters.cascade_joins_refused_list.bump();
            return Err(RoomError::CascadeRefused("this node takes no seats of that node".into()));
        }
        let quota = self.shared.config.cascade_seats_per_node;
        if quota > 0 && !listed {
            let seats = self.shared.node_seats.lock().expect("node seats").get(&word.node).copied().unwrap_or(0);
            if seats >= quota {
                self.shared.counters.cascade_joins_refused_quota.bump();
                return Err(RoomError::CascadeRefused("the node holds as many seats here as it may".into()));
            }
        }
        Ok(word.node.clone())
    }

    fn join(&mut self, request: JoinRequest) -> Result<Joined, RoomError> {
        if self.is_satellite() {
            return Err(RoomError::NotFound);
        }
        // A seat of another node comes on a pass and the node's word; a
        // participant on the join token. Neither opens the other door.
        let pass = self.proxy_token_at(&request.token);
        let uplink = match (&request.uplink, pass) {
            (Some(_), Some(at)) => {
                let node = match self.admit_uplink(&request, &self.proxy_tokens[at].0.clone()) {
                    Ok(node) => node,
                    Err(e) => {
                        // The pass burns with a refusal of the node; it
                        // stays through a refusal of the request.
                        if matches!(e, RoomError::CascadeRefused(_)) {
                            self.proxy_tokens.remove(at);
                        }
                        return Err(e);
                    }
                };
                Some(node)
            }
            (Some(_), None) | (None, Some(_)) => {
                self.shared.counters.joins_refused_token.bump();
                return Err(RoomError::BadToken);
            }
            (None, None) => {
                if !same_secret(request.token.as_bytes(), self.join_token.as_bytes()) {
                    self.shared.counters.joins_refused_token.bump();
                    return Err(RoomError::BadToken);
                }
                None
            }
        };
        if self.participants.len() >= self.max_participants as usize {
            self.shared.counters.joins_refused_full.bump();
            return Err(RoomError::Full);
        }
        let (id, token, answer) = self.seat(None, &request)?;
        if let Some(pass) = pass {
            self.proxy_tokens.remove(pass);
        }
        if let Some(node) = &uplink {
            self.shared.proxy_seats_now.fetch_add(1, Ordering::Relaxed);
            self.shared.counters.cascade_seats_joined.bump();
            *self.shared.node_seats.lock().expect("node seats").entry(node.clone()).or_insert(0) += 1;
            if let Some(p) = self.participants.iter_mut().find(|p| p.id == id) {
                p.uplink = uplink.clone();
            }
            tracing::debug!(room = %self.id, participant = id, node = %node, "a seat of another node");
        }
        let others: Vec<u32> = self.participants.iter().filter(|p| p.id != id).map(|p| p.id).collect();
        // The answer says what the node will take on each m-line, so that
        // the participant's encoder stays under the bucket rather than
        // losing packets to it.
        let sdp_answer = if self.kbps_per_participant > 0 { sdp::with_bandwidth(&answer, self.kbps_per_participant) } else { answer };
        Ok(Joined { sdp_answer, participant_id: id, participant_token: token, participants: others, home_token: None })
    }

    /// A seat taken: the offer accepted, the participant in the room and
    /// announced; its number (`id`, or the next), its token, the answer.
    fn seat(&mut self, id: Option<u32>, request: &JoinRequest) -> Result<(u32, String, String), RoomError> {
        // Every m-line of the offer becomes one of the node's at every
        // other participant: so many and no more.
        let media_lines = sdp::media_lines(&request.sdp_offer);
        if media_lines > MAX_RX_TRACKS {
            self.shared.counters.joins_refused_sdp.bump();
            return Err(RoomError::BadSdp(format!("{media_lines} media lines, at most {MAX_RX_TRACKS}")));
        }
        let offer = SdpOffer::from_sdp_string(&request.sdp_offer).map_err(|e| {
            self.shared.counters.joins_refused_sdp.bump();
            RoomError::BadSdp(e.to_string())
        })?;
        let mut rtc = self.shared.new_rtc();
        for candidate in self.shared.candidates() {
            rtc.add_local_candidate(candidate);
        }
        let answer = rtc.sdp_api().accept_offer(offer).map_err(|e| {
            self.shared.counters.joins_refused_sdp.bump();
            RoomError::BadSdp(e.to_string())
        })?;
        let ufrag = rtc.direct_api().local_ice_credentials().ufrag;
        self.shared.ufrags.lock().expect("ufrags").insert(ufrag.clone(), self.tx.clone());

        let id = match id {
            Some(id) => {
                self.next_id = self.next_id.max(id + 1);
                id
            }
            None => {
                let id = self.next_id;
                self.next_id += 1;
                id
            }
        };
        let token = hex(&random(16));
        let kbps = u64::from(self.kbps_per_participant);
        let now = Instant::now();
        let mut participant = Participant {
            id,
            token: token.clone(),
            rtc,
            ufrag,
            addrs: VecDeque::new(),
            joined_at: now,
            ctl: None,
            pending: None,
            offers: 0,
            next_offer: now,
            rx_tracks: Vec::new(),
            tx_tracks: Vec::new(),
            ssrc_layers: HashMap::new(),
            ingress: Bucket::from_kbps(kbps),
            // What comes to one participant is what all the others send.
            egress: Bucket::from_kbps(kbps * u64::from(self.egress_seats())),
            ctl_rate: Bucket::new(u64::from(ctl::MAX_FRAMES_PER_SEC)),
            audio: AudioMeter::default(),
            bwe: None,
            desired: 0,
            connected: false,
            uplink: None,
            last_packet: now,
        };
        // Everything the others send already is for the newcomer too; a
        // seat of another node gets nothing of that node's other seats.
        let same_node = |other: &Participant| other.uplink.is_some() && other.uplink == request.uplink.as_ref().map(|w| w.node.clone());
        for other in &self.participants {
            if same_node(other) {
                continue;
            }
            for track in &other.rx_tracks {
                participant.tx_tracks.push(TxTrack::new(StreamKey { origin: Origin::Client(other.id), mid: track.mid }, track.kind, track.layers.len(), now));
            }
        }
        // A seat of a satellite: what the home sends on its uplink already.
        if let Some(u) = self.uplinks.iter().find(|u| u.seat == id) {
            for down in &u.rx {
                participant.tx_tracks.push(TxTrack::new(StreamKey { origin: Origin::Node(id), mid: down.mid }, down.kind, 1, now));
            }
        }
        self.participants.push(participant);
        self.empty_since = None;
        self.had_seat = true;
        self.shared.participants_now.fetch_add(1, Ordering::Relaxed);
        self.shared.counters.participants_joined.bump();
        if self.is_satellite() {
            self.roster_add(id, true);
        } else {
            // One more may make the room bigger than a conversation.
            self.apply_holds_all();
            self.broadcast(None, &ctl::Message::Joined { id });
        }
        tracing::debug!(room = %self.id, participant = id, "joined");
        Ok((id, token, answer.to_sdp_string()))
    }

    /// How many others a participant may hear at once: the seats of the
    /// room but one, or, in a satellite, the home's roster but one.
    fn egress_seats(&self) -> u32 {
        match self.home {
            Some(_) => (self.roster.len() as u32).saturating_sub(1).max(1),
            None => self.max_participants.saturating_sub(1).max(1),
        }
    }

    fn leave(&mut self, request: LeaveRequest) -> Result<(), RoomError> {
        let Some(p) = self.participants.iter_mut().find(|p| p.id == request.participant_id) else {
            return Err(RoomError::BadToken);
        };
        let own = same_secret(request.token.as_bytes(), p.token.as_bytes());
        let admin = same_secret(request.token.as_bytes(), self.admin_token.as_bytes());
        if !own && !admin {
            return Err(RoomError::BadToken);
        }
        // Told, not cut: the close goes out (DTLS close_notify) and the
        // participant is taken out once that is sent. One that never
        // connected has nothing to be told over, and is cut.
        if !p.connected || p.rtc.close().is_err() {
            p.rtc.disconnect();
        }
        Ok(())
    }

    /// A new join token; the passes handed out under the old one are void
    /// with it (a pass is the join token's credit, and the admin changes
    /// the token to shut the old one out).
    fn change_token(&mut self, admin_token: &str) -> Result<TokenChanged, RoomError> {
        if !same_secret(admin_token.as_bytes(), self.admin_token.as_bytes()) {
            return Err(RoomError::BadToken);
        }
        self.join_token = hex(&random(24));
        self.proxy_tokens.clear();
        Ok(TokenChanged { join_token: self.join_token.clone() })
    }

    /// Participants whose connection ended are taken out, and told of; so
    /// is one whose connection never came: a seat is held by a connection,
    /// not by a request on the control channel; and a seat of another
    /// node that fell silent. A satellite's uplinks that ended are taken
    /// out with their seats; a home that fell silent is lost.
    fn reap(&mut self) {
        let now = Instant::now();
        let connect_timeout = self.shared.config.connect_timeout;
        for p in &mut self.participants {
            if !p.connected && p.rtc.is_alive() && now.duration_since(p.joined_at) >= connect_timeout {
                tracing::debug!(room = %self.id, participant = p.id, "never connected");
                self.shared.counters.participants_never_connected.bump();
                p.rtc.disconnect();
            }
            if p.connected && p.uplink.is_some() && p.rtc.is_alive() && now.duration_since(p.last_packet) >= UPLINK_SILENCE {
                tracing::debug!(room = %self.id, participant = p.id, "a seat of another node fell silent");
                self.shared.counters.cascade_seats_reaped.bump();
                p.rtc.disconnect();
            }
        }
        let gone: Vec<u32> = self.participants.iter().filter(|p| !p.rtc.is_alive()).map(|p| p.id).collect();
        for id in gone {
            self.remove(id);
            if self.is_satellite() {
                self.roster_remove(id);
            } else {
                self.broadcast(None, &ctl::Message::Left { id });
            }
        }
        if self.is_satellite() {
            self.reap_uplinks(now);
        }
        if self.participants.is_empty() && self.empty_since.is_none() {
            self.empty_since = Some(Instant::now());
        }
    }

    fn remove(&mut self, id: u32) {
        let Some(at) = self.participants.iter().position(|p| p.id == id) else {
            return;
        };
        let p = self.participants.remove(at);
        {
            let mut routes = self.shared.routes.lock().expect("routes");
            for addr in &p.addrs {
                routes.remove(addr);
            }
        }
        self.shared.ufrags.lock().expect("ufrags").remove(&p.ufrag);
        self.shared.participants_now.fetch_sub(1, Ordering::Relaxed);
        self.shared.counters.participants_left.bump();
        if let Some(node) = &p.uplink {
            self.shared.proxy_seats_now.fetch_sub(1, Ordering::Relaxed);
            let mut seats = self.shared.node_seats.lock().expect("node seats");
            if let Some(n) = seats.get_mut(node) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    seats.remove(node);
                }
            }
        }
        // The streams it sent are stopped at everybody else's.
        let origin = Origin::Client(id);
        for other in &mut self.participants {
            other.tx_tracks.retain(|t| !(t.source.origin == origin && t.state == TxState::ToOpen));
            for track in &mut other.tx_tracks {
                if track.source.origin == origin {
                    if let TxState::Open(mid) = track.state {
                        track.state = TxState::ToStop(mid);
                    }
                }
            }
        }
        self.speakers.retain(|s| *s != id);
        // One less may make the room a conversation again: everybody's
        // audio goes, whoever talks.
        self.apply_holds_all();
        // A seat of a satellite takes its uplink with it: the home sees
        // the seat leave at once.
        if let Some(u) = self.uplinks.iter().position(|u| u.seat == id) {
            self.close_uplink(u);
        }
        tracing::debug!(room = %self.id, participant = id, "left");
    }

    /// The uplink `u` closed by this node: the close is said to the home
    /// now (not at the next wake), and the uplink is cut after its grace
    /// if it does not finish on its own. A node gone (a test) says nothing.
    fn close_uplink(&mut self, u: usize) {
        let now = Instant::now();
        let uplink = &mut self.uplinks[u];
        uplink.closing = true;
        uplink.closed_at = Some(now);
        if self.vanished || uplink.rtc.close().is_err() {
            uplink.rtc.disconnect();
            return;
        }
        self.poll_uplink(u);
    }

    fn index_of(&self, origin: Origin) -> Option<usize> {
        match origin {
            Origin::Client(id) => self.participants.iter().position(|p| p.id == id),
            // The home's streams have no participant here: the uplink is
            // asked instead, where it matters (keyframes, layers).
            Origin::Node(_) => None,
        }
    }

    // ---- the poll cycle -----------------------------------------------------

    /// Every participant and uplink polled until it asks for a timeout;
    /// the earliest of those, when there is any.
    fn poll_all(&mut self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut i = 0;
        while i < self.participants.len() {
            if let Some(t) = self.poll_one(i) {
                earliest = Some(earliest.map_or(t, |e| e.min(t)));
            }
            i += 1;
        }
        let mut u = 0;
        while u < self.uplinks.len() {
            if let Some(t) = self.poll_uplink(u) {
                earliest = Some(earliest.map_or(t, |e| e.min(t)));
            }
            u += 1;
        }
        earliest
    }

    /// Participant `i` polled until it asks for a timeout, its events
    /// handled; the timeout, when it is still alive.
    fn poll_one(&mut self, i: usize) -> Option<Instant> {
        {
            self.negotiate(i);
            let mut events = Vec::new();
            let timeout = loop {
                let p = &mut self.participants[i];
                if !p.rtc.is_alive() {
                    break None;
                }
                match p.rtc.poll_output() {
                    Ok(Output::Timeout(t)) => break Some(t),
                    Ok(Output::Transmit(t)) => self.shared.transmit(&t),
                    Ok(Output::Event(e)) => events.push(e),
                    Err(e) => {
                        tracing::debug!(room = %self.id, participant = p.id, error = %e, "poll failed");
                        p.rtc.disconnect();
                        break None;
                    }
                }
            };
            for event in events {
                self.event(i, event);
            }
            timeout
        }
    }

    fn event(&mut self, i: usize, event: Event) {
        match event {
            Event::Connected => {
                self.participants[i].connected = true;
                tracing::debug!(room = %self.id, participant = self.participants[i].id, "connected");
            }
            Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                self.participants[i].rtc.disconnect();
            }
            Event::MediaAdded(added) => {
                if added.direction.is_receiving() {
                    self.media_added(i, added.mid, added.kind);
                }
            }
            Event::RtpPacket(packet) => self.forward(i, packet),
            Event::KeyframeRequest(request) => self.keyframe_request(i, request),
            Event::EgressBitrateEstimate(BweKind::Twcc { estimate, can_probe }) => {
                // An estimate means something once feedback can come: without
                // the TWCC extension the number stays the starting one for good.
                if can_probe {
                    let p = &mut self.participants[i];
                    let before = p.bwe;
                    p.bwe = Some(estimate.as_u64());
                    if before != p.bwe {
                        self.plan_layers(i, Instant::now());
                    }
                }
            }
            Event::ChannelOpen(id, label) => {
                if label == vcall_proto::rooms::CTL_CHANNEL {
                    let p = &mut self.participants[i];
                    p.ctl = Some(id);
                    let you = p.id;
                    // A satellite tells the home's roster, as last heard.
                    let participants: Vec<u32> = match self.home {
                        Some(_) => self.roster.iter().copied().filter(|id| *id != you).collect(),
                        None => self.participants.iter().filter(|p| p.id != you).map(|p| p.id).collect(),
                    };
                    self.send_ctl(i, &ctl::Message::Hello { you, participants });
                    if !self.speakers.is_empty() {
                        let participants = self.speakers.clone();
                        self.send_ctl(i, &ctl::Message::Speaking { participants });
                    }
                }
            }
            Event::ChannelClose(id) => {
                let p = &mut self.participants[i];
                if p.ctl == Some(id) {
                    p.ctl = None;
                }
            }
            Event::ChannelData(data) => self.channel_data(i, data),
            _ => {}
        }
    }

    /// A participant announced a stream: every other participant gets an
    /// m-line for it, at the next offer. Its layers are the rids its
    /// offer declared for the m-line (simulcast), or the one stream.
    fn media_added(&mut self, i: usize, mid: Mid, kind: MediaKind) {
        let now = Instant::now();
        let p = &mut self.participants[i];
        if p.rx_tracks.iter().any(|t| t.mid == mid) {
            return;
        }
        let layers: Vec<Layer> = match p.rtc.media(mid).map(|m| m.rids_rx()) {
            Some(Rids::Specific(rids)) if kind.is_video() && !rids.is_empty() => rids.iter().map(|r| Layer::new(Some(*r), now)).collect(),
            _ => vec![Layer::new(None, now)],
        };
        let layers_n = layers.len();
        tracing::debug!(room = %self.id, participant = p.id, %mid, layers = layers_n, "stream announced");
        p.rx_tracks.push(RxTrack { mid, kind, layers });
        let key = StreamKey { origin: Origin::Client(p.id), mid };
        let node = p.uplink.clone();
        for (j, other) in self.participants.iter_mut().enumerate() {
            // Nothing of a seat of another node goes back to that node.
            let same_node = node.is_some() && other.uplink == node;
            if j != i && !same_node && !other.tx_tracks.iter().any(|t| t.source == key) {
                other.tx_tracks.push(TxTrack::new(key, kind, layers_n, now));
            }
        }
    }

    // ---- negotiation over ctl ------------------------------------------

    /// An offer to participant `i` for the streams it does not have an
    /// m-line for yet (so many at a time), and to close those whose
    /// origin left; when its channel is open and no offer is out. An offer
    /// that is out and unanswered too long is sent again as it is, never
    /// replaced: the client may well have applied it, and an offer with
    /// other mids in the same places would not fit its description any
    /// more, now or ever.
    fn negotiate(&mut self, i: usize) {
        let now = Instant::now();
        let (ctl_open, again) = {
            let p = &self.participants[i];
            let again = p.pending.as_ref().map(|pending| match pending.sent {
                Some(sent) => now.duration_since(sent) >= self.shared.config.offer_timeout,
                None => now >= p.next_offer,
            });
            (p.ctl.is_some(), again)
        };
        if !ctl_open {
            return;
        }
        match again {
            Some(true) => {
                tracing::debug!(room = %self.id, participant = self.participants[i].id, "offer unanswered, sent again");
                self.shared.counters.sfu_offers_repeated.bump();
                self.send_offer(i);
                return;
            }
            Some(false) => return,
            None => {}
        }
        if now < self.participants[i].next_offer {
            return;
        }
        // A stream whose origin left before it was ever offered is forgotten.
        let present: Vec<StreamKey> = self
            .participants
            .iter()
            .flat_map(|p| p.rx_tracks.iter().map(move |t| StreamKey { origin: Origin::Client(p.id), mid: t.mid }))
            .chain(self.uplinks.iter().flat_map(|u| u.rx.iter().map(move |d| StreamKey { origin: Origin::Node(u.seat), mid: d.mid })))
            .collect();
        // Whose each stream is and its layers, to name them in the offer: a
        // participant's, or, down an uplink, a participant of the home's.
        let named: HashMap<StreamKey, (u32, Vec<String>)> = self
            .participants
            .iter()
            .flat_map(|p| p.rx_tracks.iter().map(move |t| (StreamKey { origin: Origin::Client(p.id), mid: t.mid }, (p.id, t.rids()))))
            .chain(self.uplinks.iter().flat_map(|u| u.rx.iter().map(move |d| (StreamKey { origin: Origin::Node(u.seat), mid: d.mid }, (d.id, d.rids.clone())))))
            .collect();
        let p = &mut self.participants[i];
        p.tx_tracks.retain(|t| !(t.state == TxState::ToOpen && !present.contains(&t.source)));
        if !p.tx_tracks.iter().any(|t| matches!(t.state, TxState::ToOpen | TxState::ToStop(_))) {
            return;
        }
        let mut change = p.rtc.sdp_api();
        let mut tracks = Vec::new();
        let mut opening = 0;
        for track in &mut p.tx_tracks {
            match track.state {
                TxState::ToOpen if opening < OFFER_TRACKS => {
                    opening += 1;
                    let Some((id, rids)) = named.get(&track.source).cloned() else { continue };
                    let mid = change.add_media(track.kind, Direction::SendOnly, Some(format!("p{id}")), None, None);
                    track.state = TxState::Negotiating(mid);
                    tracks.push(ctl::Track { id, kind: kind_name(track.kind).into(), mid: mid.to_string(), rids });
                }
                TxState::ToStop(mid) => {
                    change.stop_media(mid);
                    track.state = TxState::NegotiatingStop(mid);
                }
                _ => {}
            }
        }
        let Some((offer, pending)) = change.apply() else {
            return;
        };
        p.offers += 1;
        p.pending = Some(Pending { offer: pending, seq: p.offers, sdp: offer.to_sdp_string(), tracks, sent: None });
        self.send_offer(i);
    }

    /// The offer that is out to participant `i`, over its channel. When
    /// the channel cannot take it, it is tried again a little later.
    fn send_offer(&mut self, i: usize) {
        let message = {
            let Some(pending) = &self.participants[i].pending else {
                return;
            };
            ctl::Message::Offer { seq: pending.seq, sdp: pending.sdp.clone(), tracks: pending.tracks.clone() }
        };
        let now = Instant::now();
        let written = self.send_ctl(i, &message);
        let p = &mut self.participants[i];
        if let Some(pending) = &mut p.pending {
            pending.sent = written.then_some(now);
        }
        if !written {
            p.next_offer = now + OFFER_RETRY;
        }
    }

    fn channel_data(&mut self, i: usize, data: ChannelData) {
        let p = &mut self.participants[i];
        if p.ctl != Some(data.id) {
            return;
        }
        if data.binary {
            self.relay(i, &data.data);
            return;
        }
        match serde_json::from_slice::<ctl::Message>(&data.data) {
            Ok(ctl::Message::Answer { seq, sdp }) => self.answer(i, seq, &sdp),
            Ok(ctl::Message::Layer { participant, rid }) => self.layer_request(i, participant, rid, Instant::now()),
            Ok(_) | Err(_) => {
                tracing::debug!(room = %self.id, participant = p.id, "a text frame that is no answer");
            }
        }
    }

    /// The answer to the offer `seq`; to any other, or when none is out,
    /// it is dropped: the client answered an offer that was replaced by
    /// its answer to the same one, or made one up.
    fn answer(&mut self, i: usize, seq: u32, sdp: &str) {
        let p = &mut self.participants[i];
        let Some(Pending { offer: pending, sdp: offer_sdp, .. }) = p.pending.take_if(|pending| pending.seq == seq) else {
            tracing::debug!(room = %self.id, participant = p.id, seq, "an answer to no offer that is out");
            self.shared.counters.sfu_answers_stale.bump();
            return;
        };
        let taken = SdpAnswer::from_sdp_string(sdp)
            .map_err(|e| e.to_string())
            .and_then(|answer| p.rtc.sdp_api().accept_answer(pending, answer).map_err(|e| e.to_string()));
        if let Err(e) = taken {
            tracing::debug!(room = %self.id, participant = p.id, error = %e, "answer refused");
            p.next_offer = Instant::now() + OFFER_BACKOFF;
            for track in &mut p.tx_tracks {
                match track.state {
                    TxState::Negotiating(_) => track.state = TxState::ToOpen,
                    TxState::NegotiatingStop(m) => track.state = TxState::ToStop(m),
                    _ => {}
                }
            }
            return;
        }
        let mut opened_video = false;
        let mut to_remove = Vec::new();
        for (t, track) in p.tx_tracks.iter_mut().enumerate() {
            match track.state {
                TxState::Negotiating(mid) => {
                    track.state = TxState::Open(mid);
                    match sdp::ssrcs_of(&offer_sdp, &mid) {
                        Some((main, rtx)) => {
                            let (main, rtx) = (Ssrc::from(main), rtx.map(Ssrc::from));
                            p.rtc.direct_api().declare_stream_tx(main, rtx, mid, None);
                            track.ssrcs = Some((main, rtx));
                            if track.kind.is_video() {
                                opened_video = true;
                            }
                        }
                        None => tracing::warn!(room = %self.id, participant = p.id, %mid, "no ssrc in the offer for the m-line"),
                    }
                }
                TxState::NegotiatingStop(_) => {
                    if let Some((main, _)) = track.ssrcs {
                        p.rtc.direct_api().remove_stream_tx(main);
                    }
                    to_remove.push(t);
                }
                _ => {}
            }
        }
        for t in to_remove.into_iter().rev() {
            p.tx_tracks.remove(t);
        }
        // A stream whose origin left while the offer was out is closed
        // with the next one.
        let present: Vec<StreamKey> = self
            .participants
            .iter()
            .flat_map(|p| p.rx_tracks.iter().map(move |t| StreamKey { origin: Origin::Client(p.id), mid: t.mid }))
            .chain(self.uplinks.iter().flat_map(|u| u.rx.iter().map(move |d| StreamKey { origin: Origin::Node(u.seat), mid: d.mid })))
            .collect();
        for track in &mut self.participants[i].tx_tracks {
            if let TxState::Open(mid) = track.state {
                if !present.contains(&track.source) {
                    track.state = TxState::ToStop(mid);
                }
            }
        }
        self.apply_holds(i);
        // A new viewer needs a picture to start from: the layers it gets
        // are chosen, and their origins asked for a keyframe.
        if opened_video {
            self.plan_layers(i, Instant::now());
        }
    }

    /// `message` to participant `i` over its channel; whether the channel
    /// took it.
    fn send_ctl(&mut self, i: usize, message: &ctl::Message) -> bool {
        let p = &mut self.participants[i];
        let Some(cid) = p.ctl else {
            return false;
        };
        let Ok(json) = serde_json::to_vec(message) else {
            return false;
        };
        let written = p.rtc.channel(cid).map(|mut c| c.write(false, &json));
        match written {
            Some(Ok(true)) => true,
            Some(Ok(false)) | None => {
                self.shared.counters.sfu_ctl_dropped.bump();
                false
            }
            Some(Err(e)) => {
                tracing::debug!(room = %self.id, participant = p.id, error = %e, "ctl write failed");
                self.shared.counters.sfu_ctl_dropped.bump();
                false
            }
        }
    }

    /// To every participant whose channel is open, but `except`.
    fn broadcast(&mut self, except: Option<usize>, message: &ctl::Message) {
        for i in 0..self.participants.len() {
            if except != Some(i) {
                self.send_ctl(i, message);
            }
        }
    }

    /// Bytes of participant `i` to everybody else, the sender's id in
    /// front; in a satellite, up its uplink too, as they are (the home
    /// puts the id in front for the others there).
    fn relay(&mut self, i: usize, data: &[u8]) {
        let p = &mut self.participants[i];
        if data.len() > ctl::MAX_FRAME || !p.ctl_rate.take(1) {
            self.shared.counters.sfu_ctl_dropped.bump();
            return;
        }
        let frame = ctl::relayed(p.id, data);
        let from = p.id;
        let node = p.uplink.clone();
        self.shared.counters.sfu_ctl_messages.bump();
        for j in 0..self.participants.len() {
            if j == i {
                continue;
            }
            let q = &mut self.participants[j];
            // Nothing of a seat of another node goes back to that node.
            if node.is_some() && q.uplink == node {
                continue;
            }
            let Some(cid) = q.ctl else {
                continue;
            };
            let ok = matches!(q.rtc.channel(cid).map(|mut c| c.write(true, &frame)), Some(Ok(true)));
            if !ok {
                self.shared.counters.sfu_ctl_dropped.bump();
            }
        }
        if let Some(u) = self.uplinks.iter_mut().find(|u| u.seat == from) {
            if !u.send_bytes(data) {
                self.shared.counters.sfu_ctl_dropped.bump();
            }
        }
    }

    // ---- media ----------------------------------------------------------------

    /// A packet of participant `i` to everybody who has an open m-line for
    /// its stream, as it came: payload, timestamp, marker and the audio
    /// level untouched, the sequence numbers counted from the first one
    /// forwarded, the payload type translated to the receiver's. Of a
    /// stream in layers each receiver gets its one layer, and moves to
    /// another at a keyframe of it; audio goes from the speakers. In a
    /// satellite, every layer goes up the participant's uplink as it came.
    fn forward(&mut self, i: usize, packet: RtpPacket) {
        let counters = self.shared.counters.clone();
        counters.sfu_packets_in.bump();
        let size = packet.payload.len() + packet.header.header_len;
        counters.sfu_bytes_in.add(size as u64);
        let now = packet.timestamp;
        let p = &mut self.participants[i];
        let ssrc = packet.header.ssrc;
        let (mid, layer) = match p.ssrc_layers.get(&ssrc) {
            Some(found) => *found,
            None => {
                let Some((mid, rid)) = p.rtc.direct_api().stream_rx(&ssrc).map(|s| (s.mid(), s.rid())) else {
                    return;
                };
                let Some(layer) = p.rx_tracks.iter().find(|t| t.mid == mid).and_then(|t| t.layers.iter().position(|l| l.rid == rid)) else {
                    tracing::trace!(room = %self.id, participant = p.id, %mid, ?rid, "a packet on a layer the offer did not declare");
                    return;
                };
                // A new SSRC on a layer takes the old one's stream in str0m
                // (one stream per mid and rid), so the old one is let go of.
                let mut api = p.rtc.direct_api();
                remember_ssrc(&mut p.ssrc_layers, ssrc, (mid, layer), |s| api.stream_rx(s).is_some());
                (mid, layer)
            }
        };
        let Some(track) = p.rx_tracks.iter_mut().find(|t| t.mid == mid) else {
            return;
        };
        let kind = track.kind;
        let single = track.layers.len() == 1;
        let rx_layer = &mut track.layers[layer];
        rx_layer.last_packet = Some(now);
        rx_layer.rate.add(now, size);
        if kind.is_audio() {
            if let Some(level) = packet.header.ext_vals.audio_level {
                p.audio.hear(level, now);
                counters.sfu_audio_level_packets.bump();
            }
        }
        if !p.ingress.take(size) {
            counters.sfu_dropped_bandwidth.bump();
            return;
        }
        let Some(params) = p.rtc.codec_config().params().iter().find(|c| c.pt() == packet.header.payload_type).copied() else {
            counters.sfu_dropped_no_codec.bump();
            return;
        };
        let from = p.id;
        let node = p.uplink.clone();
        let key = StreamKey { origin: Origin::Client(from), mid };
        let keyframe = kind.is_video() && is_keyframe(params.spec().codec, &packet.payload);
        let ext_vals = ExtensionValues {
            audio_level: packet.header.ext_vals.audio_level,
            voice_activity: packet.header.ext_vals.voice_activity,
            video_orientation: packet.header.ext_vals.video_orientation,
            ..ExtensionValues::default()
        };
        let mut switched = Vec::new();
        for j in 0..self.participants.len() {
            if j == i {
                continue;
            }
            let q = &mut self.participants[j];
            // Nothing of a seat of another node goes back to that node.
            if node.is_some() && q.uplink == node {
                continue;
            }
            match deliver(q, key, kind, layer, single, keyframe, params, &packet, &ext_vals, &self.shared.node_bucket, &counters) {
                Delivered::Switched => switched.push(q.id),
                Delivered::Sent | Delivered::Not => {}
            }
        }
        if !switched.is_empty() {
            tracing::debug!(room = %self.id, origin = from, %mid, layer, receivers = ?switched, "layer switched");
        }
        // Up the uplink: the same layer, the same numbers, the home's
        // payload type.
        if let Some(u) = self.uplinks.iter_mut().find(|u| u.seat == from) {
            let Some(up) = u.up_track(mid) else { return };
            let Some((_, up_ssrc)) = up.layers.get(layer).copied() else { return };
            let Some(pt) = u.rtc.codec_config().match_params(params).map(|c| c.pt()) else {
                counters.sfu_dropped_no_codec.bump();
                return;
            };
            if !self.shared.node_bucket.take(size) {
                counters.sfu_dropped_bandwidth.bump();
                return;
            }
            let mut api = u.rtc.direct_api();
            let Some(stream) = api.stream_tx(&up_ssrc) else { return };
            let write = RtpWrite::new(pt, packet.seq_no, packet.header.timestamp, packet.timestamp, packet.payload.clone())
                .marker(packet.header.marker)
                .ext_vals(ext_vals)
                .nackable(kind.is_video());
            stream.write_rtp(write);
            counters.cascade_bytes_up.add(size as u64);
        }
    }

    /// A receiver asked for a keyframe of an m-line the node sends it:
    /// passed to the origin of that stream, for the layer the receiver
    /// gets, at the receiver's pace.
    fn keyframe_request(&mut self, i: usize, request: KeyframeRequest) {
        let now = Instant::now();
        let Some((t, source, layer)) =
            self.participants[i].tx_tracks.iter().enumerate().find(|(_, t)| t.mid() == Some(request.mid)).map(|(n, t)| (n, t.source, t.layer()))
        else {
            return;
        };
        if !self.participants[i].tx_tracks[t].may_ask(now) {
            return;
        }
        if self.ask_keyframe(source, layer.unwrap_or(0), request.kind, now) {
            self.participants[i].tx_tracks[t].asked_at = Some(now);
        }
    }

    /// The origin of `source` asked for a keyframe of `layer`, unless it
    /// was asked for one lately; whether it was asked now. A stream down
    /// an uplink: the home is asked, over that uplink.
    fn ask_keyframe(&mut self, source: StreamKey, layer: usize, kind: KeyframeRequestKind, now: Instant) -> bool {
        if let Origin::Node(seat) = source.origin {
            let Some(u) = self.uplinks.iter_mut().find(|u| u.seat == seat) else { return false };
            let Some(down) = u.down_track_mut(source.mid) else { return false };
            if down.last_keyframe_request.is_some_and(|t| now.saturating_duration_since(t) < KEYFRAME_EVERY) {
                return false;
            }
            down.last_keyframe_request = Some(now);
            if let Some(stream) = u.rtc.direct_api().stream_rx_by_mid(source.mid, None) {
                stream.request_keyframe(kind);
                self.shared.counters.sfu_keyframe_requests.bump();
            }
            return true;
        }
        let Some(at) = self.index_of(source.origin) else {
            return false;
        };
        let p = &mut self.participants[at];
        let Some(track) = p.rx_tracks.iter_mut().find(|t| t.mid == source.mid) else {
            return false;
        };
        let Some(layer) = track.layers.get_mut(layer) else {
            return false;
        };
        if layer.last_keyframe_request.is_some_and(|t| now.saturating_duration_since(t) < KEYFRAME_EVERY) {
            return false;
        }
        layer.last_keyframe_request = Some(now);
        if let Some(stream) = p.rtc.direct_api().stream_rx_by_mid(source.mid, layer.rid) {
            stream.request_keyframe(kind);
            self.shared.counters.sfu_keyframe_requests.bump();
        }
        true
    }

    // ---- layers ---------------------------------------------------------------

    /// Participant `i` asked for a layer of `participant`'s video: of a
    /// participant here, planned here; of one at the home, asked of the
    /// home over the uplink as it is; of nobody, dropped.
    fn layer_request(&mut self, i: usize, participant: u32, rid: Option<String>, now: Instant) {
        let wanted = rid.as_deref().map(Rid::from);
        let origin = Origin::Client(participant);
        let seat = self.participants[i].id;
        let p = &mut self.participants[i];
        let mut any = false;
        for track in p.tx_tracks.iter_mut().filter(|t| t.source.origin == origin && t.kind.is_video()) {
            track.wanted = wanted;
            any = true;
        }
        if any {
            self.shared.counters.sfu_layer_requests.bump();
            self.plan_layers(i, now);
            return;
        }
        if let Some(u) = self.uplinks.iter_mut().find(|u| u.seat == seat) {
            if u.rx.iter().any(|d| d.id == participant && d.kind.is_video()) {
                u.send_ctl(&ctl::Message::Layer { participant, rid });
            }
        }
    }

    /// The layer each video track of participant `i` should carry: the
    /// one asked for, as far as the origin sends it and the participant's
    /// bandwidth carries it, with the others' layers counted in. A change
    /// becomes a target, and the origin is asked for a keyframe of it;
    /// and again, once a second, while the target waits for one. Until
    /// the participant's TWCC says what the way to it carries, the
    /// starting estimate is taken for it: a stream starts low and climbs.
    fn plan_layers(&mut self, i: usize, now: Instant) {
        let starting = u64::from(self.shared.config.bwe_kbps) * 1000;
        let budget = self.participants[i].bwe.or((starting > 0).then_some(starting));
        // What each open video track has to choose from: read off the
        // origins first, the receiver is changed after.
        let mut inputs: Vec<(usize, LayerChoice)> = Vec::new();
        let mut audio_lines = 0u64;
        for (t, track) in self.participants[i].tx_tracks.iter().enumerate() {
            if !matches!(track.state, TxState::Open(_)) {
                continue;
            }
            if track.kind.is_audio() {
                audio_lines += 1;
                continue;
            }
            let Some(at) = self.index_of(track.source.origin) else { continue };
            let Some(rx) = self.participants[at].rx_tracks.iter().find(|r| r.mid == track.source.mid) else { continue };
            let alive: Vec<(usize, Option<u64>)> = rx.layers.iter().enumerate().filter(|(_, l)| l.alive(now)).map(|(n, l)| (n, l.rate.bps(now))).collect();
            let cap = track.wanted.and_then(|w| rx.layers.iter().position(|l| l.rid == Some(w))).unwrap_or(rx.layers.len().saturating_sub(1));
            inputs.push((t, LayerChoice { alive, cap, at: track.layer(), since_switch: now.saturating_duration_since(track.switched_at) }));
        }
        if inputs.is_empty() {
            return;
        }
        let video_budget = budget.map(|b| b.saturating_sub(audio_lines * AUDIO_BPS));
        let choices: Vec<LayerChoice> = inputs.iter().map(|(_, c)| c.clone()).collect();
        let plan = plan_layers(&choices, video_budget);
        // What the receiver would like at the most, the layer it asked for
        // of each, so that the estimate probes up to it and no further: a
        // change starts probes, so only one that matters is told.
        let desired = (audio_lines * AUDIO_BPS + choices.iter().map(wanted_rate).sum::<u64>()) * 5 / 4;
        let desired = desired.max(starting);
        let mut asks = Vec::new();
        {
            let p = &mut self.participants[i];
            if p.desired == 0 || desired.abs_diff(p.desired) as f64 > p.desired as f64 * DESIRED_STEP {
                p.desired = desired;
                p.rtc.bwe().set_desired_bitrate(Bitrate::from(desired));
            }
            for ((t, _), planned) in inputs.iter().zip(plan) {
                let track = &mut p.tx_tracks[*t];
                let Some(planned) = planned else { continue };
                if track.current == Some(planned) {
                    // Where it is: a move elsewhere that was waiting is off.
                    track.target = None;
                    continue;
                }
                track.target = Some(planned);
                if track.may_ask(now) {
                    asks.push((*t, track.source, planned));
                }
            }
        }
        for (t, source, layer) in asks {
            if self.ask_keyframe(source, layer, KeyframeRequestKind::Pli, now) {
                self.participants[i].tx_tracks[t].asked_at = Some(now);
            }
        }
    }

    // ---- speakers -------------------------------------------------------------

    /// Twice a second: who talks, and what each receiver's bandwidth
    /// carries. A satellite has no speakers of its own: the home's list
    /// is the truth there.
    fn tick(&mut self, now: Instant) {
        if !self.is_satellite() {
            self.choose_speakers(now);
        }
        for i in 0..self.participants.len() {
            self.plan_layers(i, now);
        }
    }

    /// The speakers: those of last time that still talk, the loudest of
    /// the others into the free places, one louder than the quietest by a
    /// margin into its place. Told to everybody when the list changes.
    fn choose_speakers(&mut self, now: Instant) {
        let n = self.shared.config.audio_n.max(1) as usize;
        let scores: HashMap<u32, f32> = self.participants.iter().map(|p| (p.id, p.audio.score(now))).collect();
        let score = |id: u32| scores.get(&id).copied().unwrap_or(0.0);
        let mut next: Vec<u32> = self.speakers.iter().copied().filter(|id| score(*id) > 0.0).collect();
        let mut others: Vec<(u32, f32)> = self.participants.iter().map(|p| (p.id, score(p.id))).filter(|(id, s)| *s > 0.0 && !next.contains(id)).collect();
        others.sort_by(|a, b| b.1.total_cmp(&a.1));
        for (id, s) in others {
            if next.len() < n {
                next.push(id);
                continue;
            }
            let Some(quietest) = (0..next.len()).min_by(|a, b| score(next[*a]).total_cmp(&score(next[*b]))) else { break };
            if s > score(next[quietest]) + SWAP_MARGIN {
                next[quietest] = id;
            }
        }
        next.sort_by(|a, b| score(*b).total_cmp(&score(*a)));
        if next == self.speakers {
            return;
        }
        self.speakers = next;
        self.shared.counters.sfu_speaking_changes.bump();
        let message = ctl::Message::Speaking { participants: self.speakers.clone() };
        self.broadcast(None, &message);
        for i in 0..self.participants.len() {
            self.apply_holds(i);
        }
    }

    /// Which audio m-lines of participant `i` carry nothing: those of the
    /// participants who are not speakers, in a room bigger than a
    /// conversation. One that starts again continues the numbers.
    fn apply_holds(&mut self, i: usize) {
        let n = self.shared.config.audio_n.max(1) as usize;
        // A satellite holds nothing: the home sends what should go, and
        // the few seats of one node are a conversation among themselves.
        let select = !self.is_satellite() && self.participants.len() > n + 1;
        let speakers = &self.speakers;
        for track in self.participants[i].tx_tracks.iter_mut().filter(|t| t.kind.is_audio()) {
            let held = select && !matches!(track.source.origin, Origin::Client(id) if speakers.contains(&id));
            if track.held && !held {
                track.rewrite.restart();
            }
            track.held = held;
        }
    }

    /// The holds of everybody: after the speakers change, and after the
    /// room grows past a conversation or shrinks back to one.
    fn apply_holds_all(&mut self) {
        for i in 0..self.participants.len() {
            self.apply_holds(i);
        }
    }
}

// ---- the satellite: uplinks to the home ---------------------------------------

impl Room {
    /// An uplink answered by the home, to drive from here: the socket is
    /// read into this room, and `ready` is told when the uplink's `ctl`
    /// opens, or when it is not coming.
    fn add_uplink(&mut self, mut uplink: Uplink, ready: oneshot::Sender<Result<(), String>>) {
        if !self.is_satellite() {
            let _ = ready.send(Err("not a satellite".into()));
            return;
        }
        if let Some(old) = self.uplinks.iter().position(|u| u.seat == uplink.seat) {
            // The seat was ours before and its uplink is still here: the
            // old one goes without a word (the home gave the seat anew).
            let mut old = self.uplinks.remove(old);
            old.closing = true;
            old.rtc.disconnect();
            self.shared.uplinks_now.fetch_sub(1, Ordering::Relaxed);
        }
        uplink.ready = Some(ready);
        uplink.ingress = Bucket::from_kbps(self.kbps_down());
        uplink.start_reading(self.tx.clone(), self.shared.counters.clone());
        self.shared.uplinks_now.fetch_add(1, Ordering::Relaxed);
        self.shared.counters.cascade_uplinks_made.bump();
        tracing::debug!(room = %self.id, seat = uplink.seat, "uplink added");
        self.uplinks.push(uplink);
    }

    fn remove_uplink(&mut self, seat: u32) {
        let Some(at) = self.uplinks.iter().position(|u| u.seat == seat) else { return };
        let mut u = self.uplinks.remove(at);
        u.tell_ready(Err("the uplink ended".into()));
        self.shared.uplinks_now.fetch_sub(1, Ordering::Relaxed);
        // What came down it is stopped at its seat.
        let origin = Origin::Node(seat);
        for p in &mut self.participants {
            p.tx_tracks.retain(|t| !(t.source.origin == origin && t.state == TxState::ToOpen));
            for track in &mut p.tx_tracks {
                if track.source.origin == origin {
                    if let TxState::Open(mid) = track.state {
                        track.state = TxState::ToStop(mid);
                    }
                }
            }
        }
        tracing::debug!(room = %self.id, seat, "uplink removed");
    }

    /// Uplinks that ended: lost (the home is gone for everybody here),
    /// or closed by the home (the seat is closed with it); a home silent
    /// too long on a connected uplink is lost; an uplink up but never
    /// come to its seat (its join went nowhere) is closed, so that the
    /// seat at the home is not held for nobody.
    fn reap_uplinks(&mut self, now: Instant) {
        let seated: Vec<u32> = self.participants.iter().map(|p| p.id).collect();
        for u in &mut self.uplinks {
            if u.connected && !u.closing && u.rtc.is_alive() && now.duration_since(u.last_packet) >= HOME_LOST {
                tracing::debug!(room = %self.id, seat = u.seat, "the home fell silent");
                u.lost = true;
                u.rtc.disconnect();
            }
            // Closed and not finished in its grace: cut.
            if u.rtc.is_alive() && u.closed_at.is_some_and(|at| now.duration_since(at) >= UPLINK_CLOSE_GRACE) {
                u.rtc.disconnect();
            }
        }
        let seatless: Vec<usize> = self
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, u)| !u.closing && u.ready.is_none() && !seated.contains(&u.seat) && now.duration_since(u.made_at) >= UPLINK_SEATLESS)
            .map(|(u, _)| u)
            .collect();
        for u in seatless {
            tracing::debug!(room = %self.id, seat = self.uplinks[u].seat, "an uplink without a seat for too long");
            self.close_uplink(u);
        }
        if self.uplinks.iter().any(|u| u.lost) {
            self.home_lost(true);
            return;
        }
        let gone: Vec<(u32, bool)> = self.uplinks.iter().filter(|u| !u.rtc.is_alive()).map(|u| (u.seat, u.closing)).collect();
        for (seat, closing) in gone {
            self.remove_uplink(seat);
            if !closing {
                // The home closed the seat (the room ended, the admin
                // took it out): its participant is told the same way.
                if let Some(p) = self.participants.iter_mut().find(|p| p.id == seat) {
                    if p.rtc.close().is_err() {
                        p.rtc.disconnect();
                    }
                }
            }
        }
    }

    /// Uplink `u` polled until it asks for a timeout, its events handled.
    fn poll_uplink(&mut self, u: usize) -> Option<Instant> {
        let mut events = Vec::new();
        let timeout = loop {
            let uplink = &mut self.uplinks[u];
            if !uplink.rtc.is_alive() {
                break None;
            }
            match uplink.rtc.poll_output() {
                Ok(Output::Timeout(t)) => break Some(t),
                Ok(Output::Transmit(t)) => {
                    if !self.vanished {
                        if let Err(e) = uplink.socket.try_send_to(&t.contents, t.destination) {
                            tracing::trace!(to = %t.destination, error = %e, "uplink send");
                            self.shared.counters.sfu_dropped_socket.bump();
                        }
                    }
                }
                Ok(Output::Event(e)) => events.push(e),
                Err(e) => {
                    tracing::debug!(room = %self.id, seat = uplink.seat, error = %e, "uplink poll failed");
                    uplink.rtc.disconnect();
                    break None;
                }
            }
        };
        for event in events {
            self.uplink_event(u, event);
        }
        // One closing finishes on a timeout alone (str0m ends the instance
        // in its timeout handling, and asks for no timeout once drained):
        // given one now, it is gone as soon as it has said its close.
        let uplink = &mut self.uplinks[u];
        if uplink.closing && uplink.rtc.is_alive() {
            let _ = uplink.rtc.handle_input(Input::Timeout(Instant::now()));
            if !uplink.rtc.is_alive() {
                return None;
            }
        }
        timeout
    }

    fn uplink_event(&mut self, u: usize, event: Event) {
        match event {
            Event::Connected => {
                let uplink = &mut self.uplinks[u];
                uplink.connected = true;
                uplink.last_packet = Instant::now();
                tracing::debug!(room = %self.id, seat = uplink.seat, "uplink connected");
            }
            Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                let uplink = &mut self.uplinks[u];
                if uplink.closing {
                    uplink.rtc.disconnect();
                } else if uplink.connected {
                    tracing::debug!(room = %self.id, seat = uplink.seat, "uplink disconnected: the home is lost");
                    uplink.lost = true;
                    uplink.rtc.disconnect();
                } else {
                    uplink.tell_ready(Err("ice to the home did not come up".into()));
                    uplink.closing = true;
                    uplink.rtc.disconnect();
                }
            }
            Event::ChannelOpen(id, label) => {
                if label == vcall_proto::rooms::CTL_CHANNEL {
                    let uplink = &mut self.uplinks[u];
                    uplink.ctl = Some(id);
                    uplink.connected = true;
                    uplink.tell_ready(Ok(()));
                    if let Some(home) = &self.home {
                        self.shared.reach.mark(home.addr(), Reach::Good);
                    }
                }
            }
            Event::ChannelClose(id) => {
                let uplink = &mut self.uplinks[u];
                if uplink.ctl == Some(id) {
                    uplink.ctl = None;
                }
            }
            Event::ChannelData(data) => {
                if self.uplinks[u].ctl != Some(data.id) {
                    return;
                }
                if data.binary {
                    // Bytes of a participant at the home, the sender in
                    // front already: to the seat, and to it alone.
                    let seat = self.uplinks[u].seat;
                    if let Some(p) = self.participants.iter_mut().find(|p| p.id == seat) {
                        if let Some(cid) = p.ctl {
                            let ok = matches!(p.rtc.channel(cid).map(|mut c| c.write(true, &data.data)), Some(Ok(true)));
                            if ok {
                                self.shared.counters.sfu_ctl_messages.bump();
                            } else {
                                self.shared.counters.sfu_ctl_dropped.bump();
                            }
                        }
                    }
                    return;
                }
                match serde_json::from_slice::<ctl::Message>(&data.data) {
                    Ok(message) => self.home_message(u, message),
                    Err(e) => tracing::debug!(room = %self.id, seat = self.uplinks[u].seat, error = %e, "a text frame of the home that is no message"),
                }
            }
            Event::RtpPacket(packet) => self.forward_down(u, packet),
            Event::KeyframeRequest(request) => {
                // The home wants a keyframe of a layer the seat sends: the
                // seat is asked, at the usual pace.
                let uplink = &self.uplinks[u];
                let seat = uplink.seat;
                let Some(up) = uplink.tx.iter().find(|t| t.mid == request.mid) else { return };
                let layer = up.layers.iter().position(|(rid, _)| *rid == request.rid).unwrap_or(0);
                let source = StreamKey { origin: Origin::Client(seat), mid: up.seat_mid };
                self.ask_keyframe(source, layer, request.kind, Instant::now());
            }
            _ => {}
        }
    }

    /// A datagram from the home on the uplink of `seat`.
    fn uplink_packet(&mut self, seat: u32, source: SocketAddr, at: Instant, data: &[u8]) {
        let Some(u) = self.uplinks.iter().position(|u| u.seat == seat) else { return };
        let uplink = &mut self.uplinks[u];
        let Ok(recv) = Receive::new(Protocol::Udp, source, uplink.local, data) else { return };
        uplink.last_packet = at;
        if let Err(e) = uplink.rtc.handle_input(Input::Receive(at, recv)) {
            tracing::debug!(room = %self.id, seat, error = %e, "uplink input refused");
            uplink.rtc.disconnect();
        }
        self.poll_uplink(u);
    }

    /// A word of the home on the uplink `u`: the roster and the speakers
    /// are the home's, passed on when they change; an offer is answered
    /// here, and its streams become streams of the seat's.
    fn home_message(&mut self, u: usize, message: ctl::Message) {
        match message {
            ctl::Message::Hello { you, participants } => {
                // The home's room as it is now: whoever was in the list
                // from a join's answer and left before this uplink's `ctl`
                // opened (the home tells `left` over open channels alone)
                // is out. Seats of this node are never taken out on it: an
                // older `hello` says nothing of a seat that came after.
                let mut all = participants;
                all.push(you);
                let gone: Vec<u32> = self
                    .roster
                    .iter()
                    .copied()
                    .filter(|id| !all.contains(id) && !self.participants.iter().any(|p| p.id == *id) && !self.uplinks.iter().any(|u| u.seat == *id))
                    .collect();
                for id in gone {
                    self.roster_remove(id);
                }
                for id in all {
                    self.roster_add(id, false);
                }
            }
            ctl::Message::Joined { id } => self.roster_add(id, false),
            ctl::Message::Left { id } => self.roster_remove(id),
            ctl::Message::Speaking { participants } => {
                if participants != self.speakers {
                    self.speakers = participants.clone();
                    self.shared.counters.sfu_speaking_changes.bump();
                    self.broadcast(None, &ctl::Message::Speaking { participants });
                }
            }
            ctl::Message::Offer { seq, sdp, tracks } => self.home_offer(u, seq, &sdp, tracks),
            ctl::Message::HomeLost => {
                // A home that is itself a satellite: not what the cascade
                // allows, and the word is taken as the home going.
                self.uplinks[u].lost = true;
                self.uplinks[u].rtc.disconnect();
            }
            ctl::Message::Answer { .. } | ctl::Message::Layer { .. } => {}
        }
    }

    /// The home's offer on the uplink `u`: its m-lines for the seat's
    /// streams of the others, answered at once; each becomes a stream the
    /// seat gets on an m-line of this node's. An m-line the home closes
    /// closes the seat's with the next offer.
    fn home_offer(&mut self, u: usize, seq: u32, sdp: &str, tracks: Vec<ctl::Track>) {
        let seat = self.uplinks[u].seat;
        let stopped: Vec<Mid> = sdp::stopped_mids(sdp).into_iter().map(|m| Mid::from(m.as_str())).collect();
        let answer = {
            let uplink = &mut self.uplinks[u];
            let offer = match SdpOffer::from_sdp_string(sdp) {
                Ok(offer) => offer,
                Err(e) => {
                    tracing::debug!(room = %self.id, seat, error = %e, "the home's offer could not be read");
                    return;
                }
            };
            match uplink.rtc.sdp_api().accept_offer(offer) {
                Ok(answer) => answer.to_sdp_string(),
                Err(e) => {
                    tracing::debug!(room = %self.id, seat, error = %e, "the home's offer could not be taken");
                    return;
                }
            }
        };
        {
            let uplink = &mut self.uplinks[u];
            uplink.send_ctl(&ctl::Message::Answer { seq, sdp: answer });
            uplink.rx.retain(|d| !stopped.contains(&d.mid));
            let now = Instant::now();
            for track in &tracks {
                let mid = Mid::from(track.mid.as_str());
                let kind = if track.kind == "video" { MediaKind::Video } else { MediaKind::Audio };
                if uplink.rx.iter().any(|d| d.mid == mid) {
                    continue;
                }
                uplink.rx.push(DownTrack { mid, id: track.id, kind, rids: track.rids.clone(), last_keyframe_request: None });
                if let Some(p) = self.participants.iter_mut().find(|p| p.id == seat) {
                    let key = StreamKey { origin: Origin::Node(seat), mid };
                    if !p.tx_tracks.iter().any(|t| t.source == key) {
                        p.tx_tracks.push(TxTrack::new(key, kind, 1, now));
                    }
                }
            }
        }
        if let Some(p) = self.participants.iter_mut().find(|p| p.id == seat) {
            for track in &mut p.tx_tracks {
                if let (Origin::Node(_), TxState::Open(mid)) = (track.source.origin, track.state) {
                    if stopped.contains(&track.source.mid) {
                        track.state = TxState::ToStop(mid);
                    }
                }
            }
            p.tx_tracks.retain(|t| !(matches!(t.source.origin, Origin::Node(_)) && t.state == TxState::ToOpen && stopped.contains(&t.source.mid)));
        }
    }

    /// A packet of the home on the uplink `u`: to its seat, on the m-line
    /// of this node that carries that stream, as it came.
    fn forward_down(&mut self, u: usize, packet: RtpPacket) {
        let counters = self.shared.counters.clone();
        let size = packet.payload.len() + packet.header.header_len;
        counters.cascade_bytes_down.add(size as u64);
        let seat = self.uplinks[u].seat;
        let uplink = &mut self.uplinks[u];
        let ssrc = packet.header.ssrc;
        let mid = match uplink.ssrc_mids.get(&ssrc) {
            Some(mid) => *mid,
            None => {
                let Some(mid) = uplink.rtc.direct_api().stream_rx(&ssrc).map(|s| s.mid()) else { return };
                if uplink.ssrc_mids.len() >= MAX_SSRCS {
                    uplink.ssrc_mids.clear();
                }
                uplink.ssrc_mids.insert(ssrc, mid);
                mid
            }
        };
        let Some(kind) = uplink.down_track(mid).map(|d| d.kind) else { return };
        if !uplink.ingress.take(size) {
            counters.cascade_dropped_bandwidth.bump();
            return;
        }
        let Some(params) = uplink.rtc.codec_config().params().iter().find(|c| c.pt() == packet.header.payload_type).copied() else {
            counters.sfu_dropped_no_codec.bump();
            return;
        };
        let Some(p) = self.participants.iter_mut().find(|p| p.id == seat) else { return };
        let key = StreamKey { origin: Origin::Node(seat), mid };
        let ext_vals = ExtensionValues {
            audio_level: packet.header.ext_vals.audio_level,
            voice_activity: packet.header.ext_vals.voice_activity,
            video_orientation: packet.header.ext_vals.video_orientation,
            ..ExtensionValues::default()
        };
        deliver(p, key, kind, 0, true, true, params, &packet, &ext_vals, &self.shared.node_bucket, &counters);
    }

    /// The home is gone: every seat is told `home_lost` and closed, the
    /// uplinks are dropped, and this satellite ends. `noticed`: this
    /// satellite saw it on an uplink of its own; it then remembers the
    /// home as unreachable, counts the home lost (once a home, not once
    /// a satellite) and tells the other satellites of the home.
    fn home_lost(&mut self, noticed: bool) {
        if self.ending {
            return;
        }
        let Some(home) = self.home.clone() else { return };
        tracing::info!(room = %self.id, home = %home.addr(), seats = self.participants.len(), noticed, "home lost");
        // Two satellites may notice within the same moment: the home is
        // counted lost by the first to mark it.
        if noticed && self.shared.reach.mark(home.addr(), Reach::Bad) != Some(Reach::Bad) {
            self.shared.counters.cascade_homes_lost.bump();
        }
        for i in 0..self.participants.len() {
            self.send_ctl(i, &ctl::Message::HomeLost);
        }
        // The word goes out before the close that follows it.
        self.poll_all();
        for u in &mut self.uplinks {
            u.closing = true;
            u.rtc.disconnect();
        }
        // The others of the same home, if they have not noticed.
        if noticed {
            let siblings: Vec<RoomSender> = self
                .shared
                .satellites
                .lock()
                .expect("satellites")
                .iter()
                .filter(|((addr, id), _)| *addr == home.addr() && *id != self.id)
                .map(|(_, tx)| tx.clone())
                .collect();
            for sibling in siblings {
                let _ = sibling.try_send(RoomInput::HomeLost);
            }
        }
        self.ending = true;
    }

    /// The seat `seat` of this satellite, whose uplink is up: its `Rtc`,
    /// the answer to its offer, with the home's bandwidth on each m-line
    /// counted in. `others` is the home's roster as its join answered:
    /// it goes into the list before the seat is told of it, since the
    /// home's `hello` on the uplink comes as a datagram of its own, after
    /// the one that opened `ctl` (which is what made the seat's turn),
    /// and the seat must not be told of nobody when the home said who.
    fn join_seat(&mut self, seat: u32, request: JoinRequest, home_bandwidth: &[Option<u32>], others: &[u32]) -> Result<Joined, RoomError> {
        if !self.is_satellite() {
            return Err(RoomError::NotFound);
        }
        let Some(u) = self.uplinks.iter().find(|u| u.seat == seat) else {
            return Err(RoomError::Unreachable("the uplink of the seat is gone".into()));
        };
        let home_token = u.home_token.clone();
        if let Some(old) = self.participants.iter().position(|p| p.id == seat) {
            // The seat is ours again (a rejoin on a fresh uplink): the old
            // participant goes without a word, and the fresh uplink is
            // kept out of its way.
            let at = self.uplinks.iter().position(|u| u.seat == seat).expect("the uplink of the seat");
            let fresh = self.uplinks.remove(at);
            self.participants[old].rtc.disconnect();
            self.remove(seat);
            self.uplinks.push(fresh);
        }
        for other in others {
            if *other != seat {
                self.roster_add(*other, false);
            }
        }
        let (id, token, answer) = self.seat(Some(seat), &request)?;
        let participants: Vec<u32> = self.roster.iter().copied().filter(|p| *p != id).collect();
        let sdp_answer = sdp::with_bandwidth_capped(&answer, self.kbps_per_participant, home_bandwidth);
        Ok(Joined { sdp_answer, participant_id: id, participant_token: token, participants, home_token: Some(home_token) })
    }

    /// `id` is in the home's room: the seats here are told when that is
    /// news. `own`: the seat is one of this node's, joining now.
    fn roster_add(&mut self, id: u32, own: bool) {
        if self.roster.contains(&id) {
            return;
        }
        self.roster.push(id);
        self.roster.sort_unstable();
        self.refresh_egress();
        let except = self.participants.iter().position(|p| p.id == id);
        self.broadcast(except, &ctl::Message::Joined { id });
        if own {
            tracing::trace!(room = %self.id, seat = id, "a seat of ours in the roster");
        }
    }

    fn roster_remove(&mut self, id: u32) {
        let Some(at) = self.roster.iter().position(|p| *p == id) else { return };
        self.roster.remove(at);
        self.speakers.retain(|s| *s != id);
        self.refresh_egress();
        self.broadcast(None, &ctl::Message::Left { id });
    }

    /// What each seat may be sent follows the home's roster: at the seat,
    /// and at the uplink that carries it down (the home sends a seat
    /// everything the others send, one layer each).
    fn refresh_egress(&mut self) {
        let kbps = self.kbps_down();
        for p in &mut self.participants {
            p.egress = Bucket::from_kbps(kbps);
        }
        for u in &mut self.uplinks {
            u.ingress = Bucket::from_kbps(kbps);
        }
    }

    /// What one seat may be sent, kbit/s: the allowance of one
    /// participant for each of the others.
    fn kbps_down(&self) -> u64 {
        u64::from(self.kbps_per_participant) * u64::from(self.egress_seats())
    }
}

/// What came of a packet offered to one receiver.
enum Delivered {
    Sent,
    /// Sent, and the receiver moved to this layer with it.
    Switched,
    Not,
}

/// One packet of the stream `key`, layer `layer` (of `single` or more),
/// to the receiver `q`, on its open m-line for that stream: the layer it
/// is on, or the one it waits for at its keyframe (`keyframe`, or any
/// packet of audio or of a stream of one layer); the payload type the
/// receiver's, the numbers rewritten, under the receiver's and the
/// node's bandwidth.
#[allow(clippy::too_many_arguments)]
fn deliver(
    q: &mut Participant,
    key: StreamKey,
    kind: MediaKind,
    layer: usize,
    single: bool,
    keyframe: bool,
    params: str0m::format::PayloadParams,
    packet: &RtpPacket,
    ext_vals: &ExtensionValues,
    node_bucket: &Bucket,
    counters: &crate::counters::Counters,
) -> Delivered {
    let size = packet.payload.len() + packet.header.header_len;
    let now = packet.timestamp;
    let Some(track) = q.tx_tracks.iter_mut().find(|t| t.source == key && matches!(t.state, TxState::Open(_))) else {
        return Delivered::Not;
    };
    let Some((ssrc, _)) = track.ssrcs else {
        return Delivered::Not;
    };
    if track.held {
        return Delivered::Not;
    }
    let mut switched = false;
    match (track.current, track.target) {
        (_, Some(target)) if target == layer && (keyframe || single || !kind.is_video()) => {
            if track.current.is_some() {
                counters.sfu_layer_switches.bump();
                switched = true;
            }
            track.current = Some(layer);
            track.target = None;
            track.switched_at = now;
            track.rewrite.restart();
        }
        (Some(current), _) if current == layer => {}
        _ => return Delivered::Not,
    }
    let pt = match track.pts.get(&params.pt()) {
        Some(pt) => *pt,
        None => {
            let pt = match_pt(q.rtc.codec_config(), params);
            track.pts.insert(params.pt(), pt);
            pt
        }
    };
    let Some(pt) = pt else {
        counters.sfu_dropped_no_codec.bump();
        return Delivered::Not;
    };
    let Some((seq_no, ts)) = track.rewrite.map(kind, *packet.seq_no, packet.header.timestamp, now) else {
        return Delivered::Not; // from before the run
    };
    if !q.egress.take(size) || !node_bucket.take(size) {
        counters.sfu_dropped_bandwidth.bump();
        return Delivered::Not;
    }
    let mut api = q.rtc.direct_api();
    let Some(stream) = api.stream_tx(&ssrc) else {
        return Delivered::Not;
    };
    let write = RtpWrite::new(pt, seq_no, ts, packet.timestamp, packet.payload.clone())
        .marker(packet.header.marker)
        .ext_vals(ext_vals.clone())
        .nackable(kind.is_video());
    stream.write_rtp(write);
    counters.sfu_packets_out.bump();
    counters.sfu_bytes_out.add(size as u64);
    if switched {
        Delivered::Switched
    } else {
        Delivered::Sent
    }
}

/// The receiver's payload type for the origin's codec parameters.
fn match_pt(config: &CodecConfig, params: str0m::format::PayloadParams) -> Option<Pt> {
    config.match_params(params).map(|c| c.pt())
}

/// The rate of the layer a receiver asked for: the highest alive one up
/// to its cap whose rate is measured, or the lowest alive, as the plan
/// would pick for it; nothing while nothing is measured.
fn wanted_rate(c: &LayerChoice) -> u64 {
    let under_cap = c.alive.iter().filter(|(n, _)| *n <= c.cap).filter_map(|(_, r)| *r).next_back();
    under_cap.or_else(|| c.alive.first().and_then(|(_, r)| *r)).unwrap_or(0)
}

/// `ssrc` is of `layer`, remembered within [`MAX_SSRCS`]: past that, the
/// SSRCs that are not `known` any more make room, and failing that all.
fn remember_ssrc(map: &mut HashMap<Ssrc, (Mid, usize)>, ssrc: Ssrc, layer: (Mid, usize), mut known: impl FnMut(&Ssrc) -> bool) {
    if map.len() >= MAX_SSRCS {
        map.retain(|s, _| known(s));
        if map.len() >= MAX_SSRCS {
            map.clear();
        }
    }
    map.insert(ssrc, layer);
}

/// What a receiver's video track has to choose from.
#[derive(Clone, Debug)]
struct LayerChoice {
    /// The layers the origin sends right now, lowest first: the index into
    /// its layers, and the rate once measured.
    alive: Vec<(usize, Option<u64>)>,
    /// The highest the receiver wants (an index).
    cap: usize,
    /// Where the track is, or is going.
    at: Option<usize>,
    since_switch: Duration,
}

/// The layer for each track, under `budget` (bit/s) when there is one:
/// each at the highest alive layer up to its cap; then, over the budget,
/// the most expensive comes down a layer until it fits; then a step up
/// waits for room under the smaller part of the budget and for the hold
/// since the last switch. A layer whose rate is not measured yet counts
/// as not fitting, except the lowest alive, which always does: a stream
/// starts low and climbs. `None` for a track whose origin sends nothing.
fn plan_layers(tracks: &[LayerChoice], budget: Option<u64>) -> Vec<Option<usize>> {
    let rate = |t: &LayerChoice, pick: usize| -> u64 {
        let lowest = t.alive.first().map(|(n, _)| *n);
        match t.alive.iter().find(|(n, _)| *n == pick) {
            Some((_, Some(bps))) => *bps,
            Some((n, None)) if Some(*n) == lowest => 0,
            _ => u64::MAX / 4,
        }
    };
    let mut picks: Vec<Option<usize>> = tracks
        .iter()
        .map(|t| t.alive.iter().filter(|(n, _)| *n <= t.cap).map(|(n, _)| *n).max().or_else(|| t.alive.first().map(|(n, _)| *n)))
        .collect();
    let Some(budget) = budget else {
        return picks;
    };
    let total = |picks: &[Option<usize>]| -> u64 { tracks.iter().zip(picks).filter_map(|(t, p)| p.map(|p| rate(t, p))).fold(0u64, u64::saturating_add) };
    let lower = |t: &LayerChoice, pick: usize| t.alive.iter().filter(|(n, _)| *n < pick).map(|(n, _)| *n).max();
    // Down, from the most expensive, until it fits.
    while total(&picks) as f64 > budget as f64 * BUDGET_DOWN {
        let Some((k, _)) = tracks
            .iter()
            .zip(&picks)
            .enumerate()
            .filter_map(|(k, (t, p))| p.and_then(|p| lower(t, p).map(|_| (k, rate(t, p)))))
            .max_by_key(|(_, r)| *r)
        else {
            break;
        };
        picks[k] = lower(&tracks[k], picks[k].expect("a pick"));
    }
    // Up only with room and after the hold; down and sideways as planned.
    for (k, t) in tracks.iter().enumerate() {
        let (Some(planned), Some(at)) = (picks[k], t.at) else { continue };
        if planned > at && t.alive.iter().any(|(n, _)| *n == at) && (t.since_switch < UP_HOLD || total(&picks) as f64 > budget as f64 * BUDGET_UP) {
            picks[k] = Some(at);
        }
    }
    picks
}

/// Whether a video packet starts a keyframe, by its codec. A codec the
/// node cannot read is taken at its word: any packet does.
///
/// H.264: the parameter sets come first — an SPS of its own, or a
/// STAP-A that starts with one — and a decoder that missed them cannot
/// use the IDR behind them; so the switch is made at that packet, and
/// at an IDR only when it comes without them (str0m's detector).
fn is_keyframe(codec: Codec, payload: &[u8]) -> bool {
    match codec {
        Codec::Vp8 => str0m::format::detect_vp8_keyframe(payload),
        Codec::H264 => {
            const SPS: u8 = 7;
            const STAP_A: u8 = 24;
            match payload.first().map(|b| b & 0x1f) {
                Some(SPS) => true,
                Some(STAP_A) => payload.get(3).is_some_and(|b| b & 0x1f == SPS) || str0m::format::detect_h264_keyframe(payload),
                _ => str0m::format::detect_h264_keyframe(payload),
            }
        }
        _ => true,
    }
}

fn kind_name(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Audio => "audio",
        MediaKind::Video => "video",
    }
}

/// The node's candidates: its SFU address over UDP, and over TCP where
/// it waits for the connection.
pub(super) fn candidates(udp: SocketAddr, tcp: SocketAddr) -> Vec<Candidate> {
    let mut out = Vec::new();
    if let Ok(c) = Candidate::host(udp, Protocol::Udp) {
        out.push(c);
    }
    if let Ok(c) = Candidate::builder().tcp().host(tcp).tcptype(TcpType::Passive).build() {
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_numbers_start_low_and_keep_their_distance() {
        let now = Instant::now();
        let mut r = Rewrite::new();
        let (first, ts) = r.map(MediaKind::Audio, 70_000, 1000, now).unwrap();
        assert!(*first >= 1 && *first <= 0x3fff + 1, "{first:?}");
        assert_eq!(ts, 1000, "audio keeps the origin's clock");
        assert_eq!(*r.map(MediaKind::Audio, 70_010, 1960, now).unwrap().0, *first + 10);
        assert_eq!(r.map(MediaKind::Audio, 69_999, 900, now), None, "from before the run");
        // After a pause the numbers continue where they stopped, the
        // timestamps stay the origin's.
        r.restart();
        let (again, ts) = r.map(MediaKind::Audio, 90_000, 500_000, now + Duration::from_secs(10)).unwrap();
        assert_eq!(*again, *first + 11);
        assert_eq!(ts, 500_000);
        assert_eq!(r.map(MediaKind::Audio, 89_999, 1, now), None, "the old run is over");
    }

    #[test]
    fn a_switch_of_layer_keeps_video_contiguous() {
        let now = Instant::now();
        let mut r = Rewrite::new();
        let (s1, t1) = r.map(MediaKind::Video, 5000, 90_000, now).unwrap();
        let (s2, t2) = r.map(MediaKind::Video, 5001, 90_000, now + Duration::from_millis(1)).unwrap();
        assert_eq!((*s2, t2), (*s1 + 1, t1));
        // The other layer is clocked apart (another random offset) and
        // numbered apart: the receiver sees the next number, and a
        // timestamp a frame later.
        r.restart();
        let (s3, t3) = r.map(MediaKind::Video, 777_000, 3_000_000_000, now + Duration::from_millis(34)).unwrap();
        assert_eq!(*s3, *s1 + 2);
        let step = t3.wrapping_sub(t1);
        assert!((2900..=3100).contains(&step), "about 33 ms at 90 kHz, got {step}");
        let (s4, t4) = r.map(MediaKind::Video, 777_001, 3_000_000_000, now + Duration::from_millis(35)).unwrap();
        assert_eq!((*s4, t4), (*s3 + 1, t3));
        // A reordered packet of the old layer is not of this run.
        assert_eq!(r.map(MediaKind::Video, 5002, 90_000, now + Duration::from_millis(36)), None);
    }

    fn choice(alive: &[(usize, Option<u64>)], cap: usize, at: Option<usize>, since: u64) -> LayerChoice {
        LayerChoice { alive: alive.to_vec(), cap, at, since_switch: Duration::from_secs(since) }
    }

    #[test]
    fn layers_are_chosen_by_request_and_by_budget() {
        let three = [(0, Some(100_000)), (1, Some(300_000)), (2, Some(900_000))];
        // No budget: what is asked for, as far as it is sent.
        assert_eq!(plan_layers(&[choice(&three, 2, None, 0)], None), vec![Some(2)]);
        assert_eq!(plan_layers(&[choice(&three, 1, None, 0)], None), vec![Some(1)]);
        assert_eq!(plan_layers(&[choice(&three[..2], 2, None, 0)], None), vec![Some(1)], "the top one is not sent");
        assert_eq!(plan_layers(&[choice(&[], 2, None, 0)], None), vec![None], "nothing is sent");
        assert_eq!(plan_layers(&[choice(&three[1..], 0, None, 0)], None), vec![Some(1)], "below what is sent: the lowest");
        // A budget: the most expensive comes down until it fits nine tenths.
        assert_eq!(plan_layers(&[choice(&three, 2, None, 0)], Some(1_000_000)), vec![Some(2)]);
        assert_eq!(plan_layers(&[choice(&three, 2, None, 0)], Some(500_000)), vec![Some(1)]);
        assert_eq!(plan_layers(&[choice(&three, 2, None, 0)], Some(50_000)), vec![Some(0)], "the lowest, even over the budget");
        let two = [choice(&three, 2, None, 0), choice(&three, 2, None, 0)];
        let mut one_down = plan_layers(&two, Some(1_400_000));
        one_down.sort();
        assert_eq!(one_down, vec![Some(1), Some(2)], "one comes down");
        assert_eq!(plan_layers(&two, Some(700_000)), vec![Some(1), Some(1)]);
        // Not measured yet: only the lowest is trusted to fit.
        let fresh = [(0, None), (1, None), (2, None)];
        assert_eq!(plan_layers(&[choice(&fresh, 2, None, 0)], Some(5_000_000)), vec![Some(0)]);
        assert_eq!(plan_layers(&[choice(&fresh, 2, None, 0)], None), vec![Some(2)], "without a budget the ask counts");
        // Up needs the hold and room under three quarters; down is at once.
        assert_eq!(plan_layers(&[choice(&three, 2, Some(1), 1)], Some(2_000_000)), vec![Some(1)], "too soon");
        assert_eq!(plan_layers(&[choice(&three, 2, Some(1), 5)], Some(2_000_000)), vec![Some(2)]);
        assert_eq!(plan_layers(&[choice(&three, 2, Some(1), 5)], Some(1_100_000)), vec![Some(1)], "fits nine tenths, not three quarters");
        assert_eq!(plan_layers(&[choice(&three, 2, Some(2), 0)], Some(500_000)), vec![Some(1)], "down at once");
        assert_eq!(plan_layers(&[choice(&three[..1], 2, Some(2), 0)], Some(2_000_000)), vec![Some(0)], "the layer it was at is gone: to what is sent");
    }

    #[test]
    fn the_meter_measures_a_window_and_forgets_a_silence() {
        let now = Instant::now();
        let mut m = RateMeter::new(now);
        m.add(now, 1000);
        assert_eq!(m.bps(now), None, "nothing measured yet");
        m.add(now + Duration::from_millis(1000), 1000);
        assert_eq!(m.bps(now + Duration::from_millis(1000)), Some(16_000));
        assert_eq!(m.bps(now + Duration::from_millis(3500)), None, "stale");
    }

    #[test]
    fn the_audio_meter_scores_talking_and_not_silence() {
        let now = Instant::now();
        let mut m = AudioMeter::default();
        m.hear(-20, now);
        assert_eq!(m.score(now), 107.0);
        m.hear(-60, now);
        assert!(m.score(now) < 107.0 && m.score(now) > 90.0, "{}", m.score(now));
        assert_eq!(m.score(now + TALK_HOLD), 0.0, "silent for the hold");
        let mut quiet = AudioMeter::default();
        quiet.hear(-60, now);
        assert_eq!(quiet.score(now), 0.0, "below the talking level");
        assert_eq!((m.packets, m.talking), (2, 1));
    }

    #[test]
    fn keyframes_are_told_apart_by_codec() {
        // VP8: the first packet of a frame (S=1, PID=0) whose frame header has P=0.
        assert!(is_keyframe(Codec::Vp8, &[0x10, 0x00, 1, 2]));
        assert!(!is_keyframe(Codec::Vp8, &[0x10, 0x01, 1, 2]), "an interframe");
        assert!(!is_keyframe(Codec::Vp8, &[0x00, 0x00, 1, 2]), "not the first packet");
        // H.264: an IDR, an SPS, a STAP-A starting with an SPS or holding an IDR.
        assert!(is_keyframe(Codec::H264, &[0x65, 0x88]));
        assert!(is_keyframe(Codec::H264, &[0x67, 0x42]));
        assert!(is_keyframe(Codec::H264, &[0x78, 0x00, 0x02, 0x67, 0x42, 0x00, 0x02, 0x68, 0xce]), "STAP-A of SPS and PPS");
        assert!(is_keyframe(Codec::H264, &[0x78, 0x00, 0x02, 0x68, 0xce, 0x00, 0x02, 0x65, 0x88]), "STAP-A with an IDR");
        assert!(!is_keyframe(Codec::H264, &[0x78, 0x00, 0x02, 0x68, 0xce, 0x00, 0x02, 0x41, 0x9a]), "STAP-A of a PPS and a slice");
        assert!(!is_keyframe(Codec::H264, &[0x41, 0x9a]));
        assert!(is_keyframe(Codec::H264, &[0x7c, 0x85, 0x88]), "FU-A start of an IDR");
        assert!(!is_keyframe(Codec::H264, &[0x7c, 0x05, 0x88]), "FU-A middle");
        assert!(is_keyframe(Codec::Opus, &[0]), "unknown to the node: any packet");
    }

    #[test]
    fn the_ssrc_map_is_bounded() {
        let mid = Mid::from("0");
        let mut map = HashMap::new();
        for n in 0..MAX_SSRCS as u32 {
            remember_ssrc(&mut map, Ssrc::from(n), (mid, 0), |_| true);
        }
        assert_eq!(map.len(), MAX_SSRCS);
        // Full: the SSRCs str0m let go of make room (all but the last four).
        remember_ssrc(&mut map, Ssrc::from(1000), (mid, 1), |s| **s >= MAX_SSRCS as u32 - 4);
        assert_eq!(map.len(), 5, "{map:?}");
        assert_eq!(map.get(&Ssrc::from(1000)), Some(&(mid, 1)));
        assert!(map.contains_key(&Ssrc::from(MAX_SSRCS as u32 - 1)));
        // Full of SSRCs str0m still knows: all go, rather than one more.
        for n in 2000..2000 + (MAX_SSRCS - 5) as u32 {
            remember_ssrc(&mut map, Ssrc::from(n), (mid, 2), |_| true);
        }
        assert_eq!(map.len(), MAX_SSRCS);
        remember_ssrc(&mut map, Ssrc::from(3000), (mid, 2), |_| true);
        assert_eq!(map.len(), 1, "{map:?}");
        assert!(map.contains_key(&Ssrc::from(3000)));
    }

    // ---- a room on the bench: participants without a network ----------------

    pub(super) async fn bench(audio_n: u32, bwe_kbps: u32) -> Room {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let config = super::super::Config {
            listen: addr,
            public_ip: addr.ip(),
            max_rooms: 1,
            max_participants: 8,
            kbps_per_participant: 0,
            lifetime: Duration::from_secs(60),
            idle: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(60),
            offer_timeout: Duration::from_secs(60),
            audio_n,
            bwe_kbps,
            node_id: "ab".repeat(32),
            trust: Arc::new(crate::trust::Trust::new(super::super::CascadeMode::On)),
            cascade_seats_per_node: super::super::DEFAULT_CASCADE_SEATS_PER_NODE,
            cascade_uplinks: super::super::DEFAULT_CASCADE_UPLINKS,
        };
        let shared = Arc::new(Shared {
            config,
            udp: Arc::new(udp),
            udp_addr: addr,
            tcp_addr: addr,
            rooms: std::sync::Mutex::new(HashMap::new()),
            satellites: std::sync::Mutex::new(HashMap::new()),
            routes: std::sync::Mutex::new(HashMap::new()),
            ufrags: std::sync::Mutex::new(HashMap::new()),
            tcp_writers: std::sync::Mutex::new(HashMap::new()),
            counters: Arc::new(crate::counters::Counters::default()),
            node_bucket: Arc::new(Bucket::new(0)),
            rooms_now: std::sync::atomic::AtomicUsize::new(0),
            participants_now: std::sync::atomic::AtomicUsize::new(0),
            satellites_now: std::sync::atomic::AtomicUsize::new(0),
            uplinks_now: std::sync::atomic::AtomicUsize::new(0),
            proxy_seats_now: std::sync::atomic::AtomicUsize::new(0),
            node_seats: std::sync::Mutex::new(HashMap::new()),
            reach: super::super::ReachCache::default(),
        });
        let (tx, rx) = mpsc::channel(16);
        Room::new("bench".into(), shared, tx, rx, "join".into(), "admin".into(), 8, 0, Duration::from_secs(60))
    }

    /// A participant in its seat, connected, with nothing declared.
    fn seat(room: &mut Room, id: u32, now: Instant) {
        let shared = room.shared.clone();
        room.participants.push(Participant {
            id,
            token: String::new(),
            rtc: shared.new_rtc(),
            ufrag: format!("u{id}"),
            addrs: VecDeque::new(),
            joined_at: now,
            ctl: None,
            pending: None,
            offers: 0,
            next_offer: now,
            rx_tracks: Vec::new(),
            tx_tracks: Vec::new(),
            ssrc_layers: HashMap::new(),
            ingress: Bucket::new(0),
            egress: Bucket::new(0),
            ctl_rate: Bucket::new(0),
            audio: AudioMeter::default(),
            bwe: None,
            desired: 0,
            connected: true,
            uplink: None,
            last_packet: now,
        });
        room.next_id = room.next_id.max(id + 1);
    }

    fn at(room: &Room, id: u32) -> usize {
        room.participants.iter().position(|p| p.id == id).expect("in the room")
    }

    /// `origin` sends a stream on mid 0, open at everybody else on mid 1.
    fn declares(room: &mut Room, origin: u32, kind: MediaKind, layers: Vec<Layer>, now: Instant) {
        let n = layers.len();
        let i = at(room, origin);
        room.participants[i].rx_tracks.push(RxTrack { mid: Mid::from("0"), kind, layers });
        for other in room.participants.iter_mut().filter(|p| p.id != origin) {
            let mut track = TxTrack::new(StreamKey { origin: Origin::Client(origin), mid: Mid::from("0") }, kind, n, now);
            track.state = TxState::Open(Mid::from("1"));
            other.tx_tracks.push(track);
        }
    }

    /// Three layers q, h, f that keep coming (alive at any time of a test), at the rates measured now (`None`: not yet).
    fn layered(rates: [Option<u64>; 3], now: Instant) -> Vec<Layer> {
        LAYERS
            .iter()
            .zip(rates)
            .map(|(rid, bps)| {
                let mut layer = Layer::new(Some(Rid::from(*rid)), now);
                layer.last_packet = Some(now + Duration::from_secs(3600));
                if let Some(bps) = bps {
                    layer.rate = RateMeter { window_start: now, bytes: 0, bps, measured: true };
                }
                layer
            })
            .collect()
    }

    const LAYERS: [&str; 3] = ["q", "h", "f"];
    const MEASURED: [Option<u64>; 3] = [Some(100_000), Some(300_000), Some(900_000)];

    fn tx(room: &Room, id: u32, origin: u32) -> &TxTrack {
        room.participants[at(room, id)].tx_tracks.iter().find(|t| t.source.origin == Origin::Client(origin)).expect("a track")
    }

    fn tx_mut(room: &mut Room, id: u32, origin: u32) -> &mut TxTrack {
        let i = at(room, id);
        room.participants[i].tx_tracks.iter_mut().find(|t| t.source.origin == Origin::Client(origin)).expect("a track")
    }

    /// When `origin`'s layer was last asked for a keyframe.
    fn asked(room: &Room, origin: u32, layer: usize) -> Option<Instant> {
        room.participants[at(room, origin)].rx_tracks[0].layers[layer].last_keyframe_request
    }

    /// An offer as a client makes one: audio and the `ctl` channel.
    pub(super) fn an_offer() -> String {
        super::super::init_crypto();
        let mut rtc = Rtc::builder().set_rtp_mode(true).clear_codecs().enable_opus(true, false).build(Instant::now());
        let mut change = rtc.sdp_api();
        change.add_media(MediaKind::Audio, Direction::SendOnly, Some("me".into()), None, None);
        change.add_channel(vcall_proto::rooms::CTL_CHANNEL.to_string());
        change.apply().unwrap().0.to_sdp_string()
    }

    #[tokio::test]
    async fn the_holds_follow_the_size_of_the_room() {
        let now = Instant::now();
        let mut room = bench(1, 2500).await;
        for id in 1..=3 {
            seat(&mut room, id, now);
        }
        for id in 1..=3 {
            declares(&mut room, id, MediaKind::Audio, vec![Layer::new(None, now)], now);
        }
        // Three with one speaker: more than a conversation (N + 1 = 2), the
        // others' audio is held.
        room.speakers = vec![1];
        room.apply_holds_all();
        assert!(!tx(&room, 2, 1).held);
        assert!(tx(&room, 2, 3).held);
        assert!(tx(&room, 1, 3).held);
        // One leaves without the list of speakers changing: a conversation
        // again, everything goes.
        room.remove(3);
        assert_eq!(room.participants.len(), 2);
        assert!(!tx(&room, 2, 1).held);
        assert!(!tx(&room, 1, 2).held, "a non-speaker's audio goes in a room of two");
        // One joins: past a conversation again, the non-speaker is held
        // at the newcomer, and at the old ones.
        let joined = room.join(JoinRequest::new("join", an_offer(), vec![])).unwrap();
        assert_eq!(room.participants.len(), 3);
        assert!(!tx(&room, joined.participant_id, 1).held);
        assert!(tx(&room, joined.participant_id, 2).held);
        assert!(tx(&room, 1, 2).held);
    }

    #[tokio::test]
    async fn a_new_viewer_starts_low_before_any_estimate() {
        let now = Instant::now();
        let mut room = bench(3, 500).await;
        seat(&mut room, 1, now);
        seat(&mut room, 2, now);
        // Nothing measured, no estimate: the lowest layer, and a keyframe
        // of it asked for; not the top one.
        declares(&mut room, 1, MediaKind::Video, layered([None; 3], now), now);
        room.plan_layers(at(&room, 2), now);
        assert_eq!((tx(&room, 2, 1).current, tx(&room, 2, 1).target), (None, Some(0)));
        assert_eq!(tx(&room, 2, 1).asked_at, Some(now));
        assert_eq!(asked(&room, 1, 0), Some(now));
        assert_eq!(asked(&room, 1, 2), None, "the top layer is not asked for");
        // Measured, no estimate yet: the starting estimate (500 kbit/s)
        // is the budget, so h (300 kbit/s) fits and f does not.
        let mut room = bench(3, 500).await;
        seat(&mut room, 1, now);
        seat(&mut room, 2, now);
        declares(&mut room, 1, MediaKind::Video, layered(MEASURED, now), now);
        room.plan_layers(at(&room, 2), now);
        assert_eq!(tx(&room, 2, 1).target, Some(1));
        assert_eq!(asked(&room, 1, 1), Some(now));
    }

    #[tokio::test]
    async fn a_target_waiting_for_its_keyframe_is_asked_for_again() {
        let t0 = Instant::now();
        let mut room = bench(3, 2500).await;
        for id in 1..=3 {
            seat(&mut room, id, t0);
        }
        declares(&mut room, 1, MediaKind::Video, layered([None; 3], t0), t0);
        let (b, c) = (at(&room, 2), at(&room, 3));
        // B's answer: q asked for. C's, 300 ms later: the layer's limit
        // drops the ask, the target stays.
        room.plan_layers(b, t0);
        assert_eq!(asked(&room, 1, 0), Some(t0));
        room.plan_layers(c, t0 + Duration::from_millis(300));
        assert_eq!(tx(&room, 3, 1).target, Some(0));
        assert_eq!(tx(&room, 3, 1).asked_at, None, "dropped, so not counted as asked");
        assert_eq!(asked(&room, 1, 0), Some(t0));
        // The tick: still too soon; the next one, asked.
        room.plan_layers(c, t0 + Duration::from_millis(500));
        assert_eq!(asked(&room, 1, 0), Some(t0));
        room.plan_layers(c, t0 + Duration::from_millis(1000));
        assert_eq!(asked(&room, 1, 0), Some(t0 + Duration::from_millis(1000)));
        assert_eq!(tx(&room, 3, 1).asked_at, Some(t0 + Duration::from_millis(1000)));
        // B's own ask went out but its keyframe never came (lost): asked
        // again a second after.
        assert_eq!(tx(&room, 2, 1).asked_at, Some(t0));
        room.plan_layers(b, t0 + Duration::from_millis(1500));
        assert_eq!(asked(&room, 1, 0), Some(t0 + Duration::from_millis(1000)), "the layer's second is not up");
        room.plan_layers(b, t0 + Duration::from_millis(2000));
        assert_eq!(asked(&room, 1, 0), Some(t0 + Duration::from_millis(2000)));
        assert_eq!(tx(&room, 2, 1).asked_at, Some(t0 + Duration::from_millis(2000)));
        // Once the layer is forwarded, nothing is asked any more.
        tx_mut(&mut room, 2, 1).current = Some(0);
        tx_mut(&mut room, 2, 1).target = None;
        room.plan_layers(b, t0 + Duration::from_millis(4000));
        assert_eq!(asked(&room, 1, 0), Some(t0 + Duration::from_millis(2000)));
    }

    #[tokio::test]
    async fn one_receiver_asks_for_one_keyframe_a_second_whatever_the_layer() {
        // A minute on, so that a switch ten seconds back is on the clock.
        let t0 = Instant::now() + Duration::from_secs(60);
        let mut room = bench(3, 2500).await;
        seat(&mut room, 1, t0);
        seat(&mut room, 2, t0);
        declares(&mut room, 1, MediaKind::Video, layered(MEASURED, t0), t0);
        let b = at(&room, 2);
        room.participants[b].bwe = Some(10_000_000);
        tx_mut(&mut room, 2, 1).current = Some(1);
        tx_mut(&mut room, 2, 1).switched_at = t0 - Duration::from_secs(10);
        // q, f, q, f ... ten times a second: one ask goes out, to q; f is
        // never asked, and the receiver's own PLI in between is dropped too.
        room.layer_request(b, 1, Some("q".into()), t0);
        assert_eq!(asked(&room, 1, 0), Some(t0));
        for n in 1..10 {
            let now = t0 + Duration::from_millis(100 * n);
            let rid = if n % 2 == 1 { "f" } else { "q" };
            room.layer_request(b, 1, Some(rid.into()), now);
            if n == 3 {
                room.keyframe_request(b, KeyframeRequest { mid: Mid::from("1"), rid: None, kind: KeyframeRequestKind::Pli });
            }
        }
        assert_eq!(asked(&room, 1, 0), Some(t0));
        assert_eq!(asked(&room, 1, 2), None);
        assert_eq!(asked(&room, 1, 1), None);
        assert_eq!(tx(&room, 2, 1).target, Some(2), "the last ask is what waits");
        // A second on, the pending target is asked for: one more keyframe.
        room.plan_layers(b, t0 + Duration::from_millis(1000));
        assert_eq!(asked(&room, 1, 2), Some(t0 + Duration::from_millis(1000)));
    }

    #[tokio::test]
    async fn a_plan_back_to_the_current_layer_calls_the_move_off() {
        let t0 = Instant::now() + Duration::from_secs(60);
        let mut room = bench(3, 2500).await;
        seat(&mut room, 1, t0);
        seat(&mut room, 2, t0);
        declares(&mut room, 1, MediaKind::Video, layered(MEASURED, t0), t0);
        let b = at(&room, 2);
        room.participants[b].bwe = Some(10_000_000);
        // At h, going up to f; then the receiver wants h after all: the
        // move is off, and h is not asked for a keyframe it does not need.
        {
            let track = tx_mut(&mut room, 2, 1);
            track.current = Some(1);
            track.target = Some(2);
            track.switched_at = t0 - Duration::from_secs(10);
        }
        room.layer_request(b, 1, Some("h".into()), t0);
        assert_eq!((tx(&room, 2, 1).current, tx(&room, 2, 1).target), (Some(1), None));
        assert_eq!(asked(&room, 1, 1), None);
        assert_eq!(tx(&room, 2, 1).asked_at, None);
    }

    #[tokio::test]
    async fn the_desired_rate_is_what_was_asked_for_and_moves_by_a_tenth() {
        let t0 = Instant::now();
        let mut room = bench(3, 100).await;
        seat(&mut room, 1, t0);
        seat(&mut room, 2, t0);
        declares(&mut room, 1, MediaKind::Video, layered(MEASURED, t0), t0);
        let (a, b) = (at(&room, 1), at(&room, 2));
        // Nothing asked for: the top layer, and a quarter over.
        room.plan_layers(b, t0);
        assert_eq!(room.participants[b].desired, 1_125_000);
        // q asked for: q's rate, not f's.
        room.layer_request(b, 1, Some("q".into()), t0);
        assert_eq!(room.participants[b].desired, 125_000);
        // q's rate moves by a twentieth: not told; by a fifth: told.
        room.participants[a].rx_tracks[0].layers[0].rate.bps = 104_000;
        room.plan_layers(b, t0);
        assert_eq!(room.participants[b].desired, 125_000);
        room.participants[a].rx_tracks[0].layers[0].rate.bps = 120_000;
        room.plan_layers(b, t0);
        assert_eq!(room.participants[b].desired, 150_000);
        // Never under the starting estimate.
        room.participants[a].rx_tracks[0].layers[0].rate.bps = 10_000;
        room.plan_layers(b, t0);
        assert_eq!(room.participants[b].desired, 100_000);
    }

    #[test]
    fn the_node_offers_udp_and_passive_tcp() {
        let c = candidates("203.0.113.7:3479".parse().unwrap(), "203.0.113.7:3479".parse().unwrap());
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].proto(), Protocol::Udp);
        assert_eq!(c[1].proto(), Protocol::Tcp);
        assert!(c[1].to_sdp_string().contains("tcptype passive"), "{}", c[1]);
    }
}

#[cfg(test)]
mod satellite_tests {
    use super::tests::bench;
    use super::*;
    use crate::sfu::uplink::uplink_on_loopback;

    /// The bench room as a satellite of a home at 127.0.0.1:3479, in the
    /// table (as a made one is), with `kbps` a participant.
    async fn satellite(kbps: u32) -> Room {
        let mut room = bench(3, 2500).await;
        let node: crate::identity::NodeRef = format!("127.0.0.1:3479#{}", "ab".repeat(32)).parse().unwrap();
        room.home = Some(Home { node });
        room.kbps_per_participant = kbps;
        room.had_seat = true;
        room.shared.satellites.lock().unwrap().insert(("127.0.0.1:3479".parse().unwrap(), room.id.clone()), room.tx.clone());
        room.shared.satellites_now.store(1, Ordering::Relaxed);
        room
    }

    fn in_table(room: &Room) -> bool {
        room.shared.satellites.lock().unwrap().contains_key(&("127.0.0.1:3479".parse().unwrap(), room.id.clone()))
    }

    /// An uplink that reached `ctl` open but whose seat is not taken yet
    /// holds the satellite: the join is between the two; one that never
    /// comes to its seat is closed after a while.
    #[tokio::test]
    async fn an_uplink_without_its_seat_holds_the_satellite_for_a_while() {
        let mut room = satellite(0).await;
        let mut uplink = uplink_on_loopback(2, 0).await;
        uplink.connected = true;
        room.uplinks.push(uplink);
        let now = Instant::now();
        room.reap();
        assert!(!room.ending && !room.uplinks[0].closing, "held for the seat on its way");
        assert!(in_table(&room));
        // Too long without a seat: closed, so that the home's seat is
        // freed (one never connected is gone at once).
        room.uplinks[0].made_at = now - UPLINK_SEATLESS;
        room.reap_uplinks(now);
        assert!(room.uplinks.is_empty() || room.uplinks[0].closing, "closed as seatless");
        assert!(!room.ending, "the home is not lost for it");
    }

    /// The end of a satellite is decided with the table locked: a join
    /// queued at that moment keeps it, with nothing queued it is out of
    /// the table at once.
    #[tokio::test]
    async fn a_satellite_ending_takes_a_join_queued_that_moment_or_leaves_the_table() {
        let mut room = satellite(0).await;
        let (ready, mut told) = oneshot::channel();
        room.tx.try_send(RoomInput::Uplink { uplink: Box::new(uplink_on_loopback(2, 0).await), ready }).unwrap();
        assert!(!room.settle(), "the uplink queued keeps the satellite");
        assert_eq!(room.uplinks.len(), 1);
        assert!(in_table(&room) && !room.removed && !room.ending);
        assert!(told.try_recv().is_err(), "the uplink is not told off");
        room.uplinks.clear();
        assert!(room.settle(), "nothing queued: ended");
        assert!(!in_table(&room) && room.removed && room.ending);
        assert_eq!(room.shared.satellites_now.load(Ordering::Relaxed), 0);
        assert_eq!(room.shared.counters.satellites_ended.load(Ordering::Relaxed), 1);
    }

    /// A satellite that never came to a seat ends after its idle time
    /// the way one ends after its last seat: not while an uplink is on
    /// its way to a seat, and with the table locked, so that an uplink
    /// queued that moment is taken and not dropped (which would tell the
    /// join the home failed, and mark the home bad).
    #[tokio::test]
    async fn an_idle_satellite_never_seated_ends_as_one_whose_seats_left() {
        let mut room = satellite(0).await;
        room.had_seat = false;
        let now = Instant::now();
        assert!(!room.idle_out(now), "not idle yet");
        room.empty_since = Some(now - SATELLITE_IDLE);
        room.uplinks.push(uplink_on_loopback(2, 0).await);
        assert!(!room.idle_out(now), "an uplink on its way to a seat holds it");
        assert!(in_table(&room) && !room.ending);
        room.uplinks.clear();
        let (ready, mut told) = oneshot::channel();
        room.tx.try_send(RoomInput::Uplink { uplink: Box::new(uplink_on_loopback(3, 0).await), ready }).unwrap();
        assert!(!room.idle_out(now), "the uplink queued that moment keeps it");
        assert_eq!(room.uplinks.len(), 1);
        assert!(in_table(&room) && !room.ending);
        assert!(told.try_recv().is_err(), "the uplink is not told off");
        room.uplinks.clear();
        assert!(room.idle_out(now), "nothing in it, nothing queued: ended");
        assert!(!in_table(&room) && room.removed && room.ending);
        assert_eq!(room.shared.counters.satellites_ended.load(Ordering::Relaxed), 1);
    }

    /// What the home may send down an uplink is what its seat may be
    /// sent: one participant's allowance for each of the others in the
    /// home's roster, as the roster goes; a new uplink gets the same.
    #[tokio::test]
    async fn the_bucket_of_an_uplink_follows_the_homes_roster() {
        let mut room = satellite(64).await;
        let (ready, _told) = oneshot::channel();
        room.add_uplink(uplink_on_loopback(2, 64).await, ready);
        assert_eq!(room.uplinks[0].ingress.bytes_per_sec(), 8000, "one share until the roster is known");
        for id in [1, 2, 3, 4] {
            room.roster_add(id, false);
        }
        assert_eq!(room.uplinks[0].ingress.bytes_per_sec(), 3 * 8000, "three others");
        let (ready, _told2) = oneshot::channel();
        room.add_uplink(uplink_on_loopback(3, 64).await, ready);
        assert_eq!(room.uplinks[1].ingress.bytes_per_sec(), 3 * 8000, "sized by the roster at once");
        room.roster_remove(4);
        assert!(room.uplinks.iter().all(|u| u.ingress.bytes_per_sec() == 2 * 8000));
        // Without a limit there is none.
        room.kbps_per_participant = 0;
        room.refresh_egress();
        assert_eq!(room.uplinks[0].ingress.bytes_per_sec(), 0);
    }

    /// A seat is told of the others as the home's join answered, before
    /// the home's `hello` on the uplink is in (it comes in a datagram of
    /// its own, after the one that opened `ctl` and gave the seat its
    /// turn; over a long way the seat's turn came first on a live node and
    /// the seat was told of nobody). The `hello` then says who is in now:
    /// one who left in between is taken out, a seat of this node never.
    #[tokio::test]
    async fn a_seat_is_told_of_the_others_as_the_home_answered_before_its_hello() {
        let mut room = satellite(64).await;
        let (ready, _told) = oneshot::channel();
        room.add_uplink(uplink_on_loopback(3, 64).await, ready);
        room.uplinks[0].connected = true;
        let request = JoinRequest { token: "pass".into(), sdp_offer: super::tests::an_offer(), caps: vec![], access: None, home: None, uplink: None };
        let joined = room.join_seat(3, request.clone(), &[], &[1, 2]).expect("the seat");
        assert_eq!(joined.participant_id, 3);
        assert_eq!(joined.participants, vec![1, 2], "as the home answered, with no hello yet");
        assert_eq!(room.roster, vec![1, 2, 3]);
        assert_eq!(room.participants[0].egress.bytes_per_sec(), 2 * 8000, "sized by the home's roster from the start");
        // The home's hello, as of its ctl opening: 2 left in between.
        room.home_message(0, ctl::Message::Hello { you: 3, participants: vec![1] });
        assert_eq!(room.roster, vec![1, 3]);
        // A second seat of this node, answered by the home with the roster
        // of then; an older hello of the first uplink arriving after it
        // says nothing of the second seat.
        let (ready, _told2) = oneshot::channel();
        room.add_uplink(uplink_on_loopback(4, 64).await, ready);
        room.uplinks[1].connected = true;
        let joined = room.join_seat(4, request, &[], &[1, 3]).expect("the second seat");
        assert_eq!(joined.participants, vec![1, 3]);
        room.home_message(0, ctl::Message::Hello { you: 3, participants: vec![1] });
        assert_eq!(room.roster, vec![1, 3, 4], "a seat of ours stays");
        // The seat the home gave is never listed twice, and the hello of
        // its own uplink, naming it as `you`, changes nothing.
        room.home_message(1, ctl::Message::Hello { you: 4, participants: vec![1, 3] });
        assert_eq!(room.roster, vec![1, 3, 4]);
    }
}
