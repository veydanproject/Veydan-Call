//! The SFU: rooms where a group's streams meet, on a port of their own.
//!
//! ```text
//!  UDP VCALL_SFU_LISTEN (3479)   ICE, DTLS, SRTP, SCTP of every participant of every room
//!  TCP VCALL_SFU_LISTEN (3479)   the same, framed as RFC 4571, for networks that drop UDP
//! ```
//!
//! One socket for everybody: a packet is routed to its room by the address
//! it came from, and the first ones, STUN with the node's ufrag in the
//! username, by that ufrag. Each room is a task of its own (`room`); the
//! node keeps the rooms, the routes and the limits here, and the control
//! channel asks it to make, change, join and leave rooms.
//!
//! What a room forwards it cannot read: DTLS-SRTP ends at the node, but
//! the frames inside are encrypted between the participants (the client's
//! FrameCryptor), and the bytes on `ctl` are theirs.
//!
//! The cascade (`uplink`, `room`): a room of another node (the home) may
//! have a satellite here, a room of its own kind in a table of its own,
//! whose seats are participants of this node and whose link to the home
//! is one uplink per seat: this node as a participant of the home's room.
//! And the rooms here take such seats from other nodes, on a one-time
//! pass and the node's signed word.

pub mod room;
pub mod sdp;
pub mod uplink;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use str0m::net::{Protocol, Transmit};
use str0m::{Candidate, Rtc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use vcall_proto::rooms::{Delegated, JoinRequest, Joined, LeaveRequest, MediaLimits, RoomCreated, TokenChanged};

use crate::counters::{Bump, Counters};
use crate::identity::NodeRef;
use crate::stun::{self, attr, Decoded};
use crate::turn::auth::{hex, random};
use crate::turn::limits::Bucket;
use crate::Slots;
use room::{Room, RoomInput, RoomSender};
use uplink::Uplink;

/// A room lives this long at the longest, and this long without anybody.
pub const ROOM_LIFETIME: Duration = Duration::from_secs(12 * 3600);
pub const ROOM_IDLE: Duration = Duration::from_secs(5 * 60);
/// A seat taken over the control channel is given up when ICE and DTLS
/// have not come up in this time: a participant that never connects
/// would otherwise hold it, and keep the room, until the room's end.
pub const ROOM_CONNECT: Duration = Duration::from_secs(30);
/// An offer of the node unanswered for this long is sent again, the same
/// one: a client slow to answer (a stalled network, an app in the
/// background) gets another chance, and its late answer still fits.
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(10);
/// What the SFU socket is asked to hold each way. A room sends a burst of
/// datagrams back to back (one input to every other participant), and the
/// kernel's default of a couple of hundred KiB drops the end of a big one.
/// Linux cuts the ask to `net.core.wmem_max` / `rmem_max`; what the socket
/// did not take is counted in `sfu_dropped_socket`.
const SOCKET_BUFFER: usize = 4 * 1024 * 1024;
/// Packets a room may have waiting from the sockets before the socket
/// drops them: a room that cannot keep up loses packets, as a link would.
const ROOM_QUEUE: usize = 1024;
/// A datagram over the SFU port is at most this.
const MAX_DATAGRAM: usize = 2000;
/// Frames a TCP writer may hold for a client that does not read.
const TCP_QUEUE: usize = 256;
/// A TCP connection with nothing coming in for this long is closed; ICE
/// keeps a live one busy every few seconds.
const TCP_IDLE: Duration = Duration::from_secs(60);

/// A pass for a proxy seat ([`Sfu::delegate`]) is good this long, and a
/// room holds this many times its seats of them at the most.
pub const DELEGATE_TTL: Duration = Duration::from_secs(60);
pub const DELEGATE_PER_SEAT: usize = 2;
/// A seat of another node (an uplink) that sent nothing for this long is
/// given up, and the others told: an uplink is a server that checks its
/// pair every second, so silence is a dead node, and the room need not
/// wait for ICE to give it up (some twenty seconds at str0m's defaults).
pub const UPLINK_SILENCE: Duration = Duration::from_secs(5);
/// A satellite whose home sent nothing on an uplink for this long has
/// lost its home ([`room::Room`] tells its seats `home_lost`).
pub const HOME_LOST: Duration = Duration::from_secs(5);
/// A satellite made for a join that never came to a seat ends after this.
pub const SATELLITE_IDLE: Duration = Duration::from_secs(15);
/// An uplink up for this long without its seat (the join it was for went
/// nowhere) is closed: the seat at the home is held for nobody.
pub const UPLINK_SEATLESS: Duration = Duration::from_secs(15);
/// An uplink closed by this node has this long to finish closing (the
/// close said, what it had to say sent) before it is cut.
pub const UPLINK_CLOSE_GRACE: Duration = Duration::from_secs(1);
/// The cascade by default: the seats of other nodes one node may hold at
/// the most, over all rooms (0: no limit), and the uplinks a node makes.
pub const DEFAULT_CASCADE_SEATS_PER_NODE: u32 = 256;
pub const DEFAULT_CASCADE_UPLINKS: usize = 256;
/// A home is remembered as reachable this long after an uplink to it came
/// up, and as unreachable this long after any failure of the way.
pub const REACH_GOOD: Duration = Duration::from_secs(300);
pub const REACH_BAD: Duration = Duration::from_secs(60);

/// Codecs the SFU forwards, as named in WELCOME. Opus for voice; VP8 and
/// H.264 for video, the two every libwebrtc has.
pub const CODECS: &[&str] = &["opus", "vp8", "h264"];

/// Whether the node takes seats from other nodes, and joins other nodes
/// for its participants (`VCALL_CASCADE`). Who is admitted under each is
/// [`crate::trust::Trust`]'s to say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CascadeMode {
    /// Any node, within the quota of seats per node; a node on the
    /// registry's list without it.
    On,
    Off,
    /// Nodes on the registry's list only, without the quota.
    Registry,
    /// These nodes only, by id, without the quota.
    List(HashSet<String>),
}

impl CascadeMode {
    pub fn is_on(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// `on`, `off`, `registry`, or a file with ids: as `VCALL_CASCADE`
    /// names it, the file already read into its ids.
    pub fn name(&self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Registry => "registry",
            Self::List(_) => "list",
        }
    }
}

pub struct Config {
    /// Where the sockets are bound.
    pub listen: SocketAddr,
    /// The address participants reach the SFU at.
    pub public_ip: IpAddr,
    /// This node's id: what the word of an uplink names as the home.
    pub node_id: String,
    pub max_rooms: usize,
    pub max_participants: u32,
    /// What one participant may send, kbit/s; 0 for no limit.
    pub kbps_per_participant: u32,
    pub lifetime: Duration,
    pub idle: Duration,
    /// How long a seat waits for its participant to connect
    /// ([`ROOM_CONNECT`]), and an offer for its answer ([`OFFER_TIMEOUT`]).
    pub connect_timeout: Duration,
    pub offer_timeout: Duration,
    /// Speakers whose audio is forwarded when the room has more
    /// participants than this and one ([`DEFAULT_AUDIO_N`]).
    pub audio_n: u32,
    /// What a participant is assumed to be able to take, kbit/s, before
    /// its TWCC feedback says otherwise ([`DEFAULT_BWE_KBPS`]): the first
    /// simulcast layers are chosen against it, and str0m paces at it.
    pub bwe_kbps: u32,
    /// The cascade: whether, and from which nodes ([`crate::trust::Trust`]:
    /// the mode, and the registry's list as it comes); the seats one node
    /// may hold here ([`DEFAULT_CASCADE_SEATS_PER_NODE`]; 0 for no limit);
    /// the uplinks this node makes at the most ([`DEFAULT_CASCADE_UPLINKS`]).
    pub trust: Arc<crate::trust::Trust>,
    pub cascade_seats_per_node: u32,
    pub cascade_uplinks: usize,
}

/// A home of a satellite: where it is, as the client named it.
#[derive(Clone, Debug)]
pub struct Home {
    pub node: NodeRef,
}

impl Home {
    pub fn addr(&self) -> SocketAddr {
        self.node.addr
    }
}

/// Whether a home was reachable lately, by its control address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Good,
    Bad,
}

/// What the node remembers of the way to each home: good for a while
/// after an uplink came up, bad for a while after any failure.
#[derive(Default)]
pub struct ReachCache {
    seen: Mutex<HashMap<SocketAddr, (Reach, Instant)>>,
}

impl ReachCache {
    const MAX: usize = 4096;

    pub fn state(&self, home: SocketAddr) -> Option<Reach> {
        let seen = self.seen.lock().expect("reach");
        let (state, at) = *seen.get(&home)?;
        let hold = match state {
            Reach::Good => REACH_GOOD,
            Reach::Bad => REACH_BAD,
        };
        (at.elapsed() < hold).then_some(state)
    }

    /// `home` is `state` from now; what it was until now, if anything.
    pub fn mark(&self, home: SocketAddr, state: Reach) -> Option<Reach> {
        let was = self.state(home);
        let mut seen = self.seen.lock().expect("reach");
        if seen.len() >= Self::MAX && !seen.contains_key(&home) {
            seen.retain(|_, (s, at)| at.elapsed() < if *s == Reach::Good { REACH_GOOD } else { REACH_BAD });
            if seen.len() >= Self::MAX {
                seen.clear();
            }
        }
        seen.insert(home, (state, Instant::now()));
        was
    }
}

/// Speakers forwarded by default (`VCALL_ROOM_AUDIO_N`): three voices at
/// once are a conversation; more is noise, and every stream costs the
/// receiver bandwidth and decoding.
pub const DEFAULT_AUDIO_N: u32 = 3;
/// The starting bandwidth estimate towards a participant
/// (`VCALL_ROOM_BWE_KBPS`): what one participant may send at the most by
/// default, so one camera at full size fits from the first second and
/// TWCC takes it from there.
pub const DEFAULT_BWE_KBPS: u32 = 2500;

/// What a participant of a new room may send: the creator's ask, cut to
/// the node's limit. "No limit" (0) is the node's to say, not the
/// creator's: asked for, it means the node's value.
pub fn room_kbps(asked: Option<u32>, node: u32) -> u32 {
    match (asked.filter(|k| *k > 0), node) {
        (Some(asked), 0) => asked,
        (Some(asked), node) => asked.min(node),
        (None, node) => node,
    }
}

/// Why a room request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomError {
    NotFound,
    BadToken,
    Full,
    RoomsFull,
    BadSdp(String),
    /// The word of an uplink does not hold (400 `bad_request`).
    BadWord(String),
    /// The home named in a join is not one to reach (400 `bad_home`).
    BadHome(String),
    /// The cascade refuses: off, a node not on the list, a quota (403 at
    /// the home, 503 at the node of the participant).
    CascadeRefused(String),
    /// The home could not be reached or used (503 `cascade_unreachable`).
    Unreachable(String),
}

/// What the rooms and the sockets share.
pub struct Shared {
    pub config: Config,
    udp: Arc<UdpSocket>,
    /// The SFU as participants reach it: the candidates, and the
    /// destination of every received packet as str0m is told it.
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    rooms: Mutex<HashMap<String, RoomSender>>,
    /// The satellites: rooms of other nodes with seats here, by the
    /// home's control address and the room's id. Not among `rooms`: a
    /// satellite is reached with its home named, and is nobody's home.
    satellites: Mutex<HashMap<(SocketAddr, String), RoomSender>>,
    /// Where a packet from an address goes, once a room took one from it.
    routes: Mutex<HashMap<(Protocol, SocketAddr), RoomSender>>,
    /// Where a first packet goes: the node's ufrag in a STUN request names
    /// the participant it was answered to.
    ufrags: Mutex<HashMap<String, RoomSender>>,
    tcp_writers: Mutex<HashMap<SocketAddr, mpsc::Sender<Bytes>>>,
    counters: Arc<Counters>,
    node_bucket: Arc<Bucket>,
    rooms_now: AtomicUsize,
    participants_now: AtomicUsize,
    satellites_now: AtomicUsize,
    /// Uplinks this node holds to homes, and seats other nodes hold here.
    uplinks_now: AtomicUsize,
    /// Uplinks that were let in (`take_uplink`) and are not yet counted in
    /// `uplinks_now`: on their way to the task of a room.
    uplinks_pending: AtomicUsize,
    proxy_seats_now: AtomicUsize,
    /// Seats each other node holds here, by its id: the quota.
    node_seats: Mutex<HashMap<String, u32>>,
    pub reach: ReachCache,
}

pub struct Sfu {
    shared: Arc<Shared>,
    tcp: Mutex<Option<TcpListener>>,
}

impl Shared {
    /// A place for one more uplink, taken now: counted with those that are
    /// held, so that several asking at once do not all find the last place
    /// free. The place is given back when the reservation is dropped, which
    /// is when the room's task has taken the uplink or the message is lost.
    fn reserve_uplink(self: &Arc<Self>) -> Option<room::UplinkReservation> {
        let ahead = self.uplinks_pending.fetch_add(1, Ordering::SeqCst);
        let reservation = room::UplinkReservation(self.clone());
        (self.uplinks_now.load(Ordering::SeqCst) + ahead < self.config.cascade_uplinks).then_some(reservation)
    }

    /// A seat of `node` here, counted at once if the node is under its
    /// quota (`listed`: the node of the trust list has none), and not
    /// otherwise. The check and the count are one step: rooms are tasks of
    /// their own, and two of them taking the last seat of a node would
    /// otherwise both find it free.
    fn reserve_node_seat(&self, node: &str, listed: bool) -> bool {
        let quota = self.config.cascade_seats_per_node;
        let mut seats = self.node_seats.lock().expect("node seats");
        if quota > 0 && !listed && seats.get(node).copied().unwrap_or(0) >= quota {
            return false;
        }
        *seats.entry(node.to_string()).or_insert(0) += 1;
        true
    }

    /// The seat of `node` is not held any more.
    fn release_node_seat(&self, node: &str) {
        let mut seats = self.node_seats.lock().expect("node seats");
        if let Some(n) = seats.get_mut(node) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                seats.remove(node);
            }
        }
    }
    /// An `Rtc` for one participant: ICE-lite (the node has a public
    /// address, the client does the checking), RTP mode (packets as they
    /// are), the codecs of [`CODECS`], and an estimate of the bandwidth
    /// towards the participant from its TWCC feedback, which picks the
    /// simulcast layers it gets.
    fn new_rtc(&self) -> Rtc {
        init_crypto();
        Rtc::builder()
            .set_ice_lite(true)
            .set_rtp_mode(true)
            .clear_codecs()
            .enable_opus(true, false)
            .enable_vp8(true)
            .enable_h264(true)
            .enable_bwe(Some(str0m::bwe::Bitrate::kbps(u64::from(self.config.bwe_kbps.max(1)))))
            .build(Instant::now())
    }

    fn candidates(&self) -> Vec<Candidate> {
        room::candidates(self.udp_addr, self.tcp_addr)
    }

    /// A packet to a participant, by the way it came. What the socket
    /// cannot take right now is lost, as on a full link, and counted:
    /// the operator sees where the loss is.
    fn transmit(&self, t: &Transmit) {
        match t.proto {
            Protocol::Udp => {
                if let Err(e) = self.udp.try_send_to(&t.contents, t.destination) {
                    tracing::trace!(to = %t.destination, error = %e, "udp send");
                    self.counters.sfu_dropped_socket.bump();
                }
            }
            _ => {
                let writer = self.tcp_writers.lock().expect("tcp writers").get(&t.destination).cloned();
                let Some(writer) = writer else {
                    self.counters.sfu_dropped_socket.bump();
                    return;
                };
                let mut frame = Vec::with_capacity(2 + t.contents.len());
                frame.extend_from_slice(&(t.contents.len() as u16).to_be_bytes());
                frame.extend_from_slice(&t.contents);
                if writer.try_send(Bytes::from(frame)).is_err() {
                    self.counters.sfu_dropped_stream_full.bump();
                }
            }
        }
    }

    /// The room a packet from `source` belongs to.
    fn route(&self, proto: Protocol, source: SocketAddr, data: &[u8]) -> Option<RoomSender> {
        if let Some(room) = self.routes.lock().expect("routes").get(&(proto, source)) {
            return Some(room.clone());
        }
        // A first packet: a STUN request whose USERNAME is `ours:theirs`.
        if !stun::is_stun(data) {
            return None;
        }
        let decoded = Decoded::parse(data).ok()?;
        let username = decoded.msg.get_str(attr::USERNAME)?;
        let ours = username.split(':').next()?;
        self.ufrags.lock().expect("ufrags").get(ours).cloned()
    }

    fn dispatch(&self, proto: Protocol, source: SocketAddr, data: &[u8]) {
        let Some(room) = self.route(proto, source, data) else {
            self.counters.sfu_dropped_unrouted.bump();
            return;
        };
        let input = RoomInput::Packet { proto, source, at: Instant::now(), data: data.to_vec() };
        if room.try_send(input).is_err() {
            self.counters.sfu_dropped_queue.bump();
        }
    }
}

impl Sfu {
    /// Binds the UDP socket and the TCP listener; nothing is served until
    /// [`Sfu::run`]. With port 0 asked for (the tests), the port UDP got
    /// is the one TCP takes, with a few tries.
    pub async fn bind(config: Config, counters: Arc<Counters>, node_bucket: Arc<Bucket>) -> anyhow::Result<Self> {
        let mut pair = None;
        for _ in 0..8 {
            let udp = UdpSocket::bind(config.listen).await.with_context(|| format!("cannot listen on {}/udp", config.listen))?;
            let got = udp.local_addr()?;
            match TcpListener::bind(got).await {
                Ok(tcp) => {
                    pair = Some((udp, tcp));
                    break;
                }
                Err(e) if config.listen.port() == 0 => tracing::debug!(error = %e, "port {} is taken over tcp, another", got.port()),
                Err(e) => return Err(e).with_context(|| format!("cannot listen on {got}/tcp")),
            }
        }
        let (udp, tcp) = pair.context("no port is free for the SFU over both UDP and TCP")?;
        set_buffers(&udp);
        let port = udp.local_addr()?.port();
        let public = SocketAddr::new(config.public_ip, port);
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                udp: Arc::new(udp),
                udp_addr: public,
                tcp_addr: public,
                rooms: Mutex::new(HashMap::new()),
                satellites: Mutex::new(HashMap::new()),
                routes: Mutex::new(HashMap::new()),
                ufrags: Mutex::new(HashMap::new()),
                tcp_writers: Mutex::new(HashMap::new()),
                counters,
                node_bucket,
                rooms_now: AtomicUsize::new(0),
                participants_now: AtomicUsize::new(0),
                satellites_now: AtomicUsize::new(0),
                uplinks_now: AtomicUsize::new(0),
                uplinks_pending: AtomicUsize::new(0),
                proxy_seats_now: AtomicUsize::new(0),
                node_seats: Mutex::new(HashMap::new()),
                reach: ReachCache::default(),
            }),
            tcp: Mutex::new(Some(tcp)),
        })
    }

    /// The SFU address as bound (the port, when 0 was asked for).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.shared.udp.local_addr()
    }

    /// The SFU address as participants reach it.
    pub fn public_addr(&self) -> SocketAddr {
        self.shared.udp_addr
    }

    pub fn config(&self) -> &Config {
        &self.shared.config
    }

    pub fn rooms_now(&self) -> usize {
        self.shared.rooms_now.load(Ordering::Relaxed)
    }

    /// Seats taken, in rooms and in satellites alike; the seats of other
    /// nodes among them.
    pub fn participants_now(&self) -> usize {
        self.shared.participants_now.load(Ordering::Relaxed)
    }

    pub fn satellites_now(&self) -> usize {
        self.shared.satellites_now.load(Ordering::Relaxed)
    }

    /// Uplinks to homes this node holds now.
    pub fn uplinks_now(&self) -> usize {
        self.shared.uplinks_now.load(Ordering::Relaxed)
    }

    /// Seats other nodes hold in the rooms here now.
    pub fn proxy_seats_now(&self) -> usize {
        self.shared.proxy_seats_now.load(Ordering::Relaxed)
    }

    /// What the node remembers of the way to each home.
    pub fn reach(&self) -> &ReachCache {
        &self.shared.reach
    }

    /// Addresses the rooms route packets by, over all participants.
    pub fn routes_now(&self) -> usize {
        self.shared.routes.lock().expect("routes").len()
    }

    /// The SFU address the uplinks are bound at (the interface; the
    /// public address is what they declare).
    pub fn bind_ip(&self) -> IpAddr {
        self.shared.config.listen.ip()
    }

    pub fn public_ip(&self) -> IpAddr {
        self.shared.config.public_ip
    }

    /// Whether satellites of `home` are alive here.
    pub fn has_satellites_of(&self, home: SocketAddr) -> bool {
        self.shared.satellites.lock().expect("satellites").keys().any(|(addr, _)| *addr == home)
    }

    /// As if the process died: every room and satellite ends at once,
    /// without a word to anybody, and nothing is sent any more. For the
    /// tests of what the other side does when a node is gone.
    pub fn vanish(&self) {
        let rooms: Vec<RoomSender> = self.shared.rooms.lock().expect("rooms").values().cloned().collect();
        let satellites: Vec<RoomSender> = self.shared.satellites.lock().expect("satellites").values().cloned().collect();
        for room in rooms.into_iter().chain(satellites) {
            let _ = room.try_send(RoomInput::Vanish);
        }
    }

    /// Serves the sockets until one fails. `slots` are the node's
    /// connection places, shared with TURN and control.
    pub async fn run(self: Arc<Self>, slots: Arc<Slots>) -> anyhow::Result<()> {
        let tcp = self.tcp.lock().expect("tcp").take().context("the SFU runs once")?;
        let udp = tokio::spawn(self.shared.clone().serve_udp());
        let tcp = tokio::spawn(self.shared.clone().serve_tcp(tcp, slots));
        tokio::select! {
            _ = udp => anyhow::bail!("the sfu udp loop ended"),
            _ = tcp => anyhow::bail!("the sfu tcp loop ended"),
        }
    }

    /// A new room, with fresh tokens.
    pub fn create_room(&self, limits: &MediaLimits) -> Result<RoomCreated, RoomError> {
        let shared = &self.shared;
        let config = &shared.config;
        let (tx, rx) = RoomSender::channel(ROOM_QUEUE);
        let id = hex(&random(16));
        {
            let mut rooms = shared.rooms.lock().expect("rooms");
            if rooms.len() >= config.max_rooms {
                shared.counters.rooms_refused_quota.bump();
                return Err(RoomError::RoomsFull);
            }
            rooms.insert(id.clone(), tx.clone());
        }
        shared.rooms_now.fetch_add(1, Ordering::Relaxed);
        shared.counters.rooms_created.bump();
        // A creator may ask for less than the node gives, never for more.
        let max_participants = limits.max_participants.filter(|n| *n >= 2).unwrap_or(config.max_participants).min(config.max_participants);
        let kbps = room_kbps(limits.kbps_per_participant, config.kbps_per_participant);
        let join_token = hex(&random(24));
        let admin_token = hex(&random(24));
        let room = Room::new(
            id.clone(),
            shared.clone(),
            tx,
            rx,
            join_token.clone(),
            admin_token.clone(),
            max_participants,
            kbps,
            config.lifetime,
        );
        tokio::spawn(room.run());
        tracing::debug!(room = %id, max_participants, kbps, "room made");
        Ok(RoomCreated {
            room_id: id,
            join_token,
            admin_token,
            expires_at: crate::turn::unix_now() + config.lifetime.as_secs(),
            idle_secs: config.idle.as_secs() as u32,
            max_participants,
            kbps_per_participant: kbps,
            sfu_udp: shared.udp_addr.to_string(),
            sfu_tcp: shared.tcp_addr.to_string(),
        })
    }

    fn room(&self, id: &str) -> Result<RoomSender, RoomError> {
        self.shared.rooms.lock().expect("rooms").get(id).cloned().ok_or(RoomError::NotFound)
    }

    /// A room, or the satellite of that id (one at the most: a satellite
    /// of another home with the same id is refused at its making).
    fn room_or_satellite(&self, id: &str) -> Result<RoomSender, RoomError> {
        if let Ok(room) = self.room(id) {
            return Ok(room);
        }
        let satellites = self.shared.satellites.lock().expect("satellites");
        satellites.iter().find(|((_, room), _)| room == id).map(|(_, tx)| tx.clone()).ok_or(RoomError::NotFound)
    }

    async fn ask_room<T>(room: RoomSender, make: impl FnOnce(oneshot::Sender<Result<T, RoomError>>) -> RoomInput) -> Result<T, RoomError> {
        room.ask(make).await
    }

    async fn ask<T>(&self, id: &str, make: impl FnOnce(oneshot::Sender<Result<T, RoomError>>) -> RoomInput) -> Result<T, RoomError> {
        Self::ask_room(self.room(id)?, make).await
    }

    pub async fn join(&self, id: &str, request: JoinRequest) -> Result<Joined, RoomError> {
        self.ask(id, |reply| RoomInput::Join { request, reply }).await
    }

    /// Leaving a room, or a seat of a satellite (the node closes its
    /// uplink for it).
    pub async fn leave(&self, id: &str, request: LeaveRequest) -> Result<(), RoomError> {
        Self::ask_room(self.room_or_satellite(id)?, |reply| RoomInput::Leave { request, reply }).await
    }

    pub async fn change_token(&self, id: &str, admin_token: String) -> Result<TokenChanged, RoomError> {
        self.ask(id, |reply| RoomInput::Token { admin_token, reply }).await
    }

    /// A one-time pass for a proxy seat in room `id`, by its join token:
    /// the cascade.
    pub async fn delegate(&self, id: &str, token: String) -> Result<Delegated, RoomError> {
        self.ask(id, |reply| RoomInput::Delegate { token, reply }).await
    }

    // ---- the cascade: satellites -------------------------------------------

    /// Whether a satellite of `home` for `room_id` may be here: not when
    /// `room_id` is a room of this node, nor a satellite of another home
    /// (a satellite is nobody's home: the cascade is one deep).
    pub fn check_home(&self, home: SocketAddr, room_id: &str) -> Result<(), RoomError> {
        if self.shared.rooms.lock().expect("rooms").contains_key(room_id) {
            return Err(RoomError::BadHome("the room is this node's own".into()));
        }
        let satellites = self.shared.satellites.lock().expect("satellites");
        if satellites.keys().any(|(addr, id)| id == room_id && *addr != home) {
            return Err(RoomError::BadHome("the room is a satellite of another home".into()));
        }
        Ok(())
    }

    /// `input` to the satellite of `home` for `room_id`, made when there
    /// is none (satellites count among the node's rooms). Sent with the
    /// table locked: a satellite ending at this moment decides so with
    /// the table locked too ([`Room::settle`]), and either takes what is
    /// queued or is out of the table before anything more is queued.
    pub(crate) fn send_to_satellite(&self, home: &Home, room_id: &str, input: RoomInput) -> Result<(), RoomError> {
        let shared = &self.shared;
        self.check_home(home.addr(), room_id)?;
        let key = (home.addr(), room_id.to_string());
        let mut satellites = shared.satellites.lock().expect("satellites");
        let tx = match satellites.get(&key) {
            Some(tx) => tx.clone(),
            None => {
                if shared.rooms_now.load(Ordering::Relaxed) + satellites.len() >= shared.config.max_rooms {
                    shared.counters.rooms_refused_quota.bump();
                    return Err(RoomError::CascadeRefused("the node holds as many rooms as it may".into()));
                }
                let (tx, rx) = RoomSender::channel(ROOM_QUEUE);
                satellites.insert(key, tx.clone());
                shared.satellites_now.fetch_add(1, Ordering::Relaxed);
                shared.counters.satellites_made.bump();
                let room = Room::new_satellite(room_id.to_string(), shared.clone(), tx.clone(), rx, home.clone());
                tokio::spawn(room.run());
                tracing::debug!(room = room_id, home = %home.addr(), "satellite made");
                tx
            }
        };
        tx.try_send(input).map_err(|_| RoomError::Unreachable("the satellite is busy".into()))
    }

    /// An uplink to the home, made and answered already, given to the
    /// satellite to drive. The satellite says when the uplink is up (its
    /// `ctl` open) or gone, over `ready`.
    pub fn take_uplink(&self, home: &Home, room_id: &str, uplink: Uplink, ready: oneshot::Sender<Result<(), String>>) -> Result<(), RoomError> {
        let Some(reservation) = self.shared.reserve_uplink() else {
            self.shared.counters.cascade_joins_refused.bump();
            return Err(RoomError::CascadeRefused("the node holds as many uplinks as it may".into()));
        };
        self.send_to_satellite(home, room_id, RoomInput::Uplink { uplink: Box::new(uplink), ready, reservation: Some(reservation) })
    }

    /// The seat `seat` of the satellite of `home` for `room_id`, for the
    /// participant whose uplink is up: its `Rtc`, the answer to its offer.
    /// `others`: the home's roster as its join answered.
    pub async fn join_satellite(&self, home: &Home, room_id: &str, seat: u32, request: JoinRequest, home_bandwidth: Vec<Option<u32>>, others: Vec<u32>) -> Result<Joined, RoomError> {
        let (reply, answer) = oneshot::channel();
        self.send_to_satellite(home, room_id, RoomInput::JoinSeat { seat, request, home_bandwidth, others, reply })?;
        // The satellite gone with the seat queued (its home lost, its
        // time up): not the room's absence, which would end the call.
        answer.await.map_err(|_| RoomError::Unreachable("the satellite ended before the seat was taken".into()))?
    }

    /// The uplink of `seat` closed and forgotten: the join it was for did
    /// not come to a seat.
    pub fn drop_uplink(&self, home: &Home, room_id: &str, seat: u32) {
        let key = (home.addr(), room_id.to_string());
        if let Some(tx) = self.shared.satellites.lock().expect("satellites").get(&key) {
            let _ = tx.try_send(RoomInput::DropUplink { seat });
        }
    }
}

impl Shared {
    async fn serve_udp(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, source) = match self.udp.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::trace!(error = %e, "sfu udp recv");
                    continue;
                }
            };
            self.dispatch(Protocol::Udp, source, &buf[..n]);
        }
    }

    /// ICE over TCP: each connection carries frames of two bytes of length
    /// and the datagram (RFC 4571), both ways.
    async fn serve_tcp(self: Arc<Self>, listener: TcpListener, slots: Arc<Slots>) {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed (sfu tcp)");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Some(slot) = slots.take(peer.ip()) else {
                continue;
            };
            let shared = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let _ = tcp.set_nodelay(true);
                shared.counters.sfu_tcp_connections.bump();
                let (mut reader, mut writer) = tcp.into_split();
                let (tx, mut source) = mpsc::channel::<Bytes>(TCP_QUEUE);
                shared.tcp_writers.lock().expect("tcp writers").insert(peer, tx);
                let write = tokio::spawn(async move {
                    while let Some(frame) = source.recv().await {
                        if writer.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                });
                let mut frame = vec![0u8; MAX_DATAGRAM];
                loop {
                    let mut head = [0u8; 2];
                    let Ok(Ok(_)) = tokio::time::timeout(TCP_IDLE, reader.read_exact(&mut head)).await else {
                        break;
                    };
                    let len = u16::from_be_bytes(head) as usize;
                    if len == 0 || len > MAX_DATAGRAM {
                        break;
                    }
                    let Ok(Ok(_)) = tokio::time::timeout(TCP_IDLE, reader.read_exact(&mut frame[..len])).await else {
                        break;
                    };
                    shared.dispatch(Protocol::Tcp, peer, &frame[..len]);
                }
                write.abort();
                shared.tcp_writers.lock().expect("tcp writers").remove(&peer);
                let room = shared.routes.lock().expect("routes").remove(&(Protocol::Tcp, peer));
                if let Some(room) = room {
                    let _ = room.try_send(RoomInput::Gone { proto: Protocol::Tcp, source: peer });
                }
            });
        }
    }
}

/// The crypto backend of str0m, installed once for the process.
pub fn init_crypto() {
    static CRYPTO: Once = Once::new();
    CRYPTO.call_once(|| str0m::crypto::from_feature_flags().install_process_default());
}

/// The socket's buffers raised to [`SOCKET_BUFFER`], as far as the kernel
/// lets an unprivileged process (Linux: `net.core.wmem_max`, `rmem_max`).
fn set_buffers(udp: &UdpSocket) {
    let sock = socket2::SockRef::from(udp);
    if let Err(e) = sock.set_send_buffer_size(SOCKET_BUFFER) {
        tracing::debug!(error = %e, "sfu socket: send buffer not raised");
    }
    if let Err(e) = sock.set_recv_buffer_size(SOCKET_BUFFER) {
        tracing::debug!(error = %e, "sfu socket: receive buffer not raised");
    }
    tracing::debug!(send = ?sock.send_buffer_size(), recv = ?sock.recv_buffer_size(), "sfu socket buffers");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_creator_lowers_the_kbps_and_never_lifts_the_limit() {
        assert_eq!(room_kbps(None, 2500), 2500);
        assert_eq!(room_kbps(Some(500), 2500), 500);
        assert_eq!(room_kbps(Some(9000), 2500), 2500);
        // 0 from the creator is not "no limit": it is the node's value.
        assert_eq!(room_kbps(Some(0), 2500), 2500);
        // A node without a limit lets the creator set one, or none.
        assert_eq!(room_kbps(Some(700), 0), 700);
        assert_eq!(room_kbps(None, 0), 0);
        assert_eq!(room_kbps(Some(0), 0), 0);
    }

    async fn bound() -> Sfu {
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_ip: "127.0.0.1".parse().unwrap(),
            node_id: "ab".repeat(32),
            max_rooms: 1,
            max_participants: 2,
            kbps_per_participant: 0,
            lifetime: Duration::from_secs(60),
            idle: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(60),
            offer_timeout: Duration::from_secs(60),
            audio_n: DEFAULT_AUDIO_N,
            bwe_kbps: DEFAULT_BWE_KBPS,
            trust: Arc::new(crate::trust::Trust::new(CascadeMode::On)),
            cascade_seats_per_node: DEFAULT_CASCADE_SEATS_PER_NODE,
            cascade_uplinks: DEFAULT_CASCADE_UPLINKS,
        };
        Sfu::bind(config, Arc::new(Counters::default()), Arc::new(Bucket::new(0))).await.unwrap()
    }

    #[test]
    fn the_reach_of_a_home_is_remembered_for_a_while() {
        let cache = ReachCache::default();
        let home: SocketAddr = "203.0.113.7:443".parse().unwrap();
        assert_eq!(cache.state(home), None);
        cache.mark(home, Reach::Bad);
        assert_eq!(cache.state(home), Some(Reach::Bad));
        cache.mark(home, Reach::Good);
        assert_eq!(cache.state(home), Some(Reach::Good));
        // Stale: forgotten.
        cache.seen.lock().unwrap().insert(home, (Reach::Good, Instant::now() - REACH_GOOD));
        assert_eq!(cache.state(home), None);
        cache.seen.lock().unwrap().insert(home, (Reach::Bad, Instant::now() - REACH_BAD));
        assert_eq!(cache.state(home), None);
        let list = CascadeMode::List(["x".to_string()].into_iter().collect());
        assert!(list.is_on() && CascadeMode::Registry.is_on() && !CascadeMode::Off.is_on());
        assert_eq!((list.name(), CascadeMode::Registry.name(), CascadeMode::On.name()), ("list", "registry", "on"));
    }

    #[tokio::test]
    async fn the_sfu_socket_holds_more_than_the_default() {
        let plain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let default = socket2::SockRef::from(&plain).send_buffer_size().unwrap();
        let sfu = bound().await;
        let raised = socket2::SockRef::from(&*sfu.shared.udp).send_buffer_size().unwrap();
        assert!(raised > default, "{raised} vs the default {default}");
    }

    #[tokio::test]
    async fn packets_the_sockets_cannot_take_are_counted() {
        let sfu = bound().await;
        let shared = &sfu.shared;
        let source = shared.udp_addr;
        // Nowhere to send over UDP: the port 0.
        let nowhere: SocketAddr = "127.0.0.1:0".parse().unwrap();
        shared.transmit(&Transmit { proto: Protocol::Udp, source, destination: nowhere, contents: vec![1, 2, 3].into() });
        assert_eq!(shared.counters.sfu_dropped_socket.load(Ordering::Relaxed), 1);
        // Over TCP: a stream whose queue is full, and one that is gone.
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        tx.try_send(Bytes::from_static(b"full")).unwrap();
        shared.tcp_writers.lock().unwrap().insert(peer, tx);
        shared.transmit(&Transmit { proto: Protocol::Tcp, source, destination: peer, contents: vec![4].into() });
        assert_eq!(shared.counters.sfu_dropped_stream_full.load(Ordering::Relaxed), 1);
        shared.tcp_writers.lock().unwrap().remove(&peer);
        shared.transmit(&Transmit { proto: Protocol::Tcp, source, destination: peer, contents: vec![5].into() });
        assert_eq!(shared.counters.sfu_dropped_socket.load(Ordering::Relaxed), 2);
        assert_eq!(shared.counters.dropped_stream_full.load(Ordering::Relaxed), 0, "TURN's counter is not touched");
    }
}
