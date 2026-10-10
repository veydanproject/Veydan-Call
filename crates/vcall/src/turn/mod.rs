//! TURN (RFC 8656) and STUN Binding (RFC 8489): the relay of the node.
//!
//! ```text
//! client ── Allocate (credentials) ──▶ node: a UDP socket at a relay port
//! client ── CreatePermission peer ──▶ node: the peer may be reached, public addresses only
//! client ── Send / ChannelData ─────▶ node ──▶ peer           (peer ──▶ node ──▶ client the same way back)
//! ```
//!
//! One `Server` serves every transport: the UDP socket, and each TCP or
//! TLS connection the listener hands it. A client is its transport and
//! address; an allocation belongs to that pair and ends with its lifetime,
//! with a Refresh to zero, or with its stream.
//!
//! What the relay refuses, and why, is in `policy` (where packets may go),
//! `auth` (who may allocate) and `limits` (how much).

pub mod allocation;
pub mod auth;
pub mod limits;
pub mod policy;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::counters::{Bump, Counters};
use crate::stun::{self, attr, method, Class, Decoded, Message};
use allocation::{Allocation, ClientKey, Shared, Sink, StreamSink, Transport};
use auth::Auth;
use limits::{Bucket, PerIp};
use policy::{PeerPolicy, Port};

/// A stream that says nothing for this long is closed; an allocation on
/// it lasts at most an hour, and a client refreshes well before.
const STREAM_IDLE: Duration = Duration::from_secs(15 * 60);
/// How often expired allocations, permissions and channels are dropped.
const SWEEP_EVERY: Duration = Duration::from_secs(5);
/// Tries at binding a relay port before giving up with 508.
const PORT_TRIES: usize = 32;
/// One read off a stream.
const STREAM_CHUNK: usize = 16 * 1024;
/// Allocations one address may hold at once (`VCALL_TURN_MAX_PER_IP`).
/// libwebrtc makes one allocation per network interface per TURN URL,
/// and the node hands out three URLs (UDP, TCP, TLS): a client with two
/// or three interfaces (Wi-Fi, a VPN, a virtual adapter) takes six to
/// nine, and two callers behind one NAT — a household, an office — ask
/// for up to eighteen at once. With a cap of eight the second caller got
/// 486 for most of its allocations and the two never met through the
/// relay. Thirty-two leaves room for a group behind one address, and a
/// thousand allocations in all still bounds the node.
pub const DEFAULT_MAX_PER_IP: u32 = 32;

pub struct Config {
    /// The address relayed packets come from, as the world sees it.
    pub public_ip: IpAddr,
    pub relay_ports: RangeInclusive<u16>,
    pub realm: String,
    pub max_allocations: usize,
    pub max_per_ip: u32,
    /// What an allocation gets when it asks for nothing, and the most it may ask for.
    pub default_lifetime: Duration,
    pub max_lifetime: Duration,
    /// What one allocation may carry each way.
    pub kbps_per_allocation: u64,
    /// The ceiling of all TURN traffic together, before the node's own.
    pub turn_mbps: u64,
    pub policy: PeerPolicy,
}

pub struct Server {
    config: Config,
    auth: Arc<Auth>,
    allocations: Mutex<HashMap<ClientKey, Arc<Allocation>>>,
    /// The relay ports allocations hold right now: the only ports of the
    /// node's own address a packet may go to.
    live_ports: Mutex<HashSet<u16>>,
    per_ip: PerIp,
    shared: Arc<Shared>,
}

/// The attributes each request may carry; others below 0x8000 earn a 420.
const KNOWN_COMMON: &[u16] = &[attr::USERNAME, attr::REALM, attr::NONCE, attr::MESSAGE_INTEGRITY, attr::FINGERPRINT];
const KNOWN_ALLOCATE: &[u16] = &[
    attr::REQUESTED_TRANSPORT,
    attr::LIFETIME,
    attr::DONT_FRAGMENT,
    attr::EVEN_PORT,
    attr::RESERVATION_TOKEN,
    attr::REQUESTED_ADDRESS_FAMILY,
    attr::ADDITIONAL_ADDRESS_FAMILY,
];
const KNOWN_REFRESH: &[u16] = &[attr::LIFETIME, attr::REQUESTED_ADDRESS_FAMILY];
const KNOWN_PERMISSION: &[u16] = &[attr::XOR_PEER_ADDRESS];
const KNOWN_CHANNEL_BIND: &[u16] = &[attr::CHANNEL_NUMBER, attr::XOR_PEER_ADDRESS];

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Server {
    pub fn new(config: Config, auth: Arc<Auth>, node_bucket: Arc<Bucket>, counters: Arc<Counters>) -> Arc<Self> {
        let turn_bucket = Bucket::from_mbps(config.turn_mbps);
        Arc::new(Self {
            config,
            auth,
            allocations: Mutex::new(HashMap::new()),
            live_ports: Mutex::new(HashSet::new()),
            per_ip: PerIp::default(),
            shared: Arc::new(Shared { turn_bucket, node_bucket, counters }),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Allocations alive right now.
    pub fn active(&self) -> usize {
        self.allocations.lock().expect("allocations").len()
    }

    /// Serves the UDP socket: STUN and TURN from everybody, for good.
    pub async fn serve_udp(self: Arc<Self>, socket: Arc<UdpSocket>) {
        let mut buf = vec![0u8; stun::MAX_MESSAGE];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                // ICMP errors of earlier sends surface here on some
                // systems; the socket is fine.
                Err(e) => {
                    tracing::trace!(error = %e, "udp recv");
                    continue;
                }
            };
            let key = ClientKey { transport: Transport::Udp, addr: peer };
            let sink = Sink::Udp { socket: socket.clone(), addr: peer };
            self.handle(key, &sink, &buf[..n]).await;
        }
    }

    /// Serves one TCP or TLS connection until it closes, then ends what it
    /// allocated. `prefix` is what the listener read to tell it apart.
    pub async fn serve_stream<S>(self: Arc<Self>, stream: S, peer: SocketAddr, transport: Transport, prefix: Vec<u8>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.shared.counters.stream_connections.bump();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx, mut source) = StreamSink::new();
        let write = tokio::spawn(async move {
            while let Some(frame) = source.next().await {
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        let sink = Sink::Stream(tx);
        let key = ClientKey { transport, addr: peer };
        tracing::debug!(client = %peer, transport = transport.name(), "turn stream open");

        // Frames are taken from `buf` at `at`; what is left moves to the
        // front once per read, not once per frame, so that a read full of
        // tiny frames costs what it holds and not its square.
        let mut buf = prefix;
        let mut at = 0;
        let mut chunk = vec![0u8; STREAM_CHUNK];
        'conn: loop {
            let need = loop {
                let have = buf.len() - at;
                if have >= 4 {
                    let need = match stun::frame_of(&buf[at..]) {
                        Some(stun::Frame::Stun(n)) | Some(stun::Frame::ChannelData(n)) if n <= stun::MAX_MESSAGE => n,
                        _ => break 'conn,
                    };
                    if have >= need {
                        break need;
                    }
                }
                if at > 0 {
                    buf.drain(..at);
                    at = 0;
                }
                match tokio::time::timeout(STREAM_IDLE, reader.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => break 'conn,
                }
            };
            self.handle(key, &sink, &buf[at..at + need]).await;
            at += need;
        }
        tracing::debug!(client = %peer, transport = transport.name(), "turn stream closed");
        self.end_client(key);
        drop(sink);
        write.abort();
    }

    /// Drops everything the client holds: its stream closed.
    pub fn end_client(&self, key: ClientKey) {
        self.remove(key);
    }

    /// Drops what has run out. Runs for good.
    pub async fn sweep(self: Arc<Self>) {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        loop {
            tick.tick().await;
            let now = std::time::Instant::now();
            let (expired, alive): (Vec<_>, Vec<_>) = {
                let allocations = self.allocations.lock().expect("allocations");
                allocations.iter().map(|(k, a)| (*k, a.clone())).partition(|(_, a)| a.expired(now))
            };
            for (key, _) in expired {
                tracing::debug!(client = %key.addr, "allocation expired");
                self.remove(key);
            }
            for (_, a) in alive {
                a.sweep(now);
            }
        }
    }

    fn get(&self, key: ClientKey) -> Option<Arc<Allocation>> {
        self.allocations.lock().expect("allocations").get(&key).cloned()
    }

    fn remove(&self, key: ClientKey) {
        let removed = self.allocations.lock().expect("allocations").remove(&key);
        if let Some(a) = removed {
            a.stop();
            self.live_ports.lock().expect("live ports").remove(&a.relayed.port());
            self.per_ip.release(key.addr.ip());
            self.shared.counters.allocations_ended.bump();
        }
    }

    /// One frame from a client, answered through `sink` when there is an answer.
    pub async fn handle(&self, key: ClientKey, sink: &Sink, data: &[u8]) {
        if stun::is_channel_data(data) {
            self.channel_data(key, data).await;
            return;
        }
        let d = match Decoded::parse(data) {
            Ok(d) => d,
            Err(e) => {
                tracing::trace!(client = %key.addr, error = %e, "not a message");
                return;
            }
        };
        let reply = match (d.msg.class, d.msg.method) {
            (Class::Request, method::BINDING) => Some(self.binding(key, &d.msg)),
            (Class::Request, method::ALLOCATE) => Some(self.allocate(key, sink, &d).await),
            (Class::Request, method::REFRESH) => Some(self.refresh(key, &d)),
            (Class::Request, method::CREATE_PERMISSION) => Some(self.create_permission(key, &d)),
            (Class::Request, method::CHANNEL_BIND) => Some(self.channel_bind(key, &d)),
            (Class::Indication, method::SEND) => {
                self.send_indication(key, &d.msg).await;
                None
            }
            (Class::Request, _) => Some(d.msg.error(400, "Bad Request").encode(None, true)),
            // Other indications and any response: nothing to say.
            _ => None,
        };
        if let Some(reply) = reply {
            sink.reply(Bytes::from(reply)).await;
        }
    }

    fn binding(&self, key: ClientKey, m: &Message) -> Vec<u8> {
        self.shared.counters.stun_bindings.bump();
        let mut r = m.success();
        r.add_xor_addr(attr::XOR_MAPPED_ADDRESS, key.addr);
        r.encode(None, true)
    }

    /// A 401 or 438: the realm and a fresh nonce for this client to try
    /// again with.
    fn challenge(&self, key: ClientKey, m: &Message, code: u16, reason: &str) -> Vec<u8> {
        let mut r = m.error(code, reason);
        r.add_str(attr::REALM, self.auth.realm()).add_str(attr::NONCE, &self.auth.nonce(unix_now(), key));
        r.encode(None, true)
    }

    /// The long-term credential check (RFC 8489 9.2.4) with our
    /// short-lived usernames. Err carries the answer to send.
    ///
    /// With `existing`, the allocation the request is about: a request
    /// under the username that made it is checked with the key that made
    /// it, past the credentials' expiry too. The expiry limits making an
    /// allocation, not keeping one: a call that outlives it would otherwise
    /// lose its relay at the next Refresh, with no way for the client to
    /// bring new credentials to a live allocation. The allocation's own
    /// lifetime and the node's limits bound it.
    fn authenticate(&self, key: ClientKey, d: &Decoded<'_>, known: &[u16], existing: Option<&Allocation>) -> Result<([u8; 16], String), Vec<u8>> {
        let m = &d.msg;
        let now = unix_now();
        if !d.has_integrity() {
            return Err(self.challenge(key, m, 401, "Unauthorized"));
        }
        let (Some(username), Some(realm), Some(nonce)) = (m.get_str(attr::USERNAME), m.get_str(attr::REALM), m.get_str(attr::NONCE)) else {
            return Err(m.error(400, "Bad Request").encode(None, true));
        };
        if realm != self.auth.realm() {
            return Err(self.challenge(key, m, 401, "Unauthorized"));
        }
        if !self.auth.nonce_ok(nonce, now, key) {
            self.shared.counters.stale_nonces.bump();
            return Err(self.challenge(key, m, 438, "Stale Nonce"));
        }
        let ikey = match existing.filter(|a| a.username == username) {
            Some(a) => a.key,
            None => match self.auth.key_of(username, now) {
                Ok(key) => key,
                Err(auth::Refusal::Expired) => {
                    self.shared.counters.refused_expired_credentials.bump();
                    return Err(self.challenge(key, m, 401, "Unauthorized"));
                }
                Err(auth::Refusal::Unknown) => {
                    self.shared.counters.refused_bad_credentials.bump();
                    return Err(self.challenge(key, m, 401, "Unauthorized"));
                }
            },
        };
        if !d.verify_integrity(&ikey) {
            self.shared.counters.refused_bad_credentials.bump();
            return Err(self.challenge(key, m, 401, "Unauthorized"));
        }
        let unknown = m.unknown_required(&[KNOWN_COMMON, known].concat());
        if !unknown.is_empty() {
            let mut r = m.error(420, "Unknown Attribute");
            let mut list = Vec::with_capacity(unknown.len() * 2);
            for kind in unknown {
                list.extend_from_slice(&kind.to_be_bytes());
            }
            r.add(attr::UNKNOWN_ATTRIBUTES, list);
            return Err(r.encode(Some(&ikey), true));
        }
        Ok((ikey, username.to_string()))
    }

    fn lifetime_of(&self, m: &Message) -> Duration {
        let asked = m.get_u32(attr::LIFETIME).map(|s| Duration::from_secs(s as u64)).unwrap_or(self.config.default_lifetime);
        asked.clamp(self.config.default_lifetime, self.config.max_lifetime)
    }

    fn allocate_success(&self, a: &Allocation, m: &Message, lifetime: Duration) -> Vec<u8> {
        let mut r = m.success();
        r.add_xor_addr(attr::XOR_RELAYED_ADDRESS, a.relayed)
            .add_u32(attr::LIFETIME, lifetime.as_secs() as u32)
            .add_xor_addr(attr::XOR_MAPPED_ADDRESS, a.client.addr);
        // An IPv6 relay was asked for besides (RFC 8656 7.2): there is
        // none, the IPv4 one is given, and the answer says so.
        if m.has(attr::ADDITIONAL_ADDRESS_FAMILY) {
            r.add_address_error(stun::FAMILY_IPV6, 440, "Address Family not Supported");
        }
        r.encode(Some(&a.key), true)
    }

    async fn allocate(&self, key: ClientKey, sink: &Sink, d: &Decoded<'_>) -> Vec<u8> {
        let m = &d.msg;
        if let Some(a) = self.get(key) {
            // The same request again (a lost answer): the same answer. Any
            // other request on a 5-tuple that has an allocation: 437.
            if a.txid == m.txid {
                let lifetime = self.lifetime_of(m);
                return self.allocate_success(&a, m, lifetime);
            }
            return m.error(437, "Allocation Mismatch").encode(Some(&a.key), true);
        }
        let (ikey, username) = match self.authenticate(key, d, KNOWN_ALLOCATE, None) {
            Ok(x) => x,
            Err(reply) => return reply,
        };
        let refuse = |code: u16, reason: &str| m.error(code, reason).encode(Some(&ikey), true);

        match m.get(attr::REQUESTED_TRANSPORT) {
            Some(v) if v.len() == 4 && v[0] == stun::TRANSPORT_UDP => {}
            Some(_) => return refuse(442, "Unsupported Transport Protocol"),
            None => return refuse(400, "Bad Request"),
        }
        if m.has(attr::RESERVATION_TOKEN) {
            // No token is ever handed out, so none is ever valid.
            return refuse(508, "Insufficient Capacity");
        }
        let even_port = match m.get(attr::EVEN_PORT) {
            Some(v) if v.first().is_some_and(|b| b & 0x80 != 0) => return refuse(508, "Insufficient Capacity"),
            Some(_) => true,
            None => false,
        };
        // Relays are IPv4 for now: the public address of the node is one.
        // REQUESTED-ADDRESS-FAMILY IPv6 is refused; ADDITIONAL-ADDRESS-FAMILY
        // (RFC 8656 7.2: IPv6 besides IPv4, and nothing else) gets the IPv4
        // relay with an ADDRESS-ERROR-CODE for IPv6 in the success.
        if m.has(attr::ADDITIONAL_ADDRESS_FAMILY)
            && (m.has(attr::REQUESTED_ADDRESS_FAMILY) || m.get(attr::ADDITIONAL_ADDRESS_FAMILY).is_some_and(|v| v.first() != Some(&stun::FAMILY_IPV6)))
        {
            return refuse(400, "Bad Request");
        }
        if m.get(attr::REQUESTED_ADDRESS_FAMILY).is_some_and(|v| v.first() != Some(&stun::FAMILY_IPV4)) {
            return refuse(440, "Address Family not Supported");
        }

        if self.active() >= self.config.max_allocations {
            self.shared.counters.refused_quota_total.bump();
            return refuse(486, "Allocation Quota Reached");
        }
        if !self.per_ip.acquire(key.addr.ip(), self.config.max_per_ip) {
            self.shared.counters.refused_quota_ip.bump();
            return refuse(486, "Allocation Quota Reached");
        }
        let Some(relay) = self.bind_relay(even_port).await else {
            self.per_ip.release(key.addr.ip());
            self.shared.counters.refused_no_port.bump();
            return refuse(508, "Insufficient Capacity");
        };
        let port = relay.local_addr().map(|a| a.port()).unwrap_or(0);
        let relayed = SocketAddr::new(self.config.public_ip, port);
        let lifetime = self.lifetime_of(m);
        let a = Allocation::new(
            key,
            sink.clone(),
            Arc::new(relay),
            relayed,
            username,
            ikey,
            m.txid,
            lifetime,
            self.config.kbps_per_allocation * 1000 / 8,
        );
        a.start_reader(self.shared.clone());
        self.live_ports.lock().expect("live ports").insert(port);
        self.allocations.lock().expect("allocations").insert(key, a.clone());
        self.shared.counters.allocations.bump();
        tracing::debug!(client = %key.addr, transport = key.transport.name(), relay = %relayed, lifetime = lifetime.as_secs(), "allocated");
        self.allocate_success(&a, m, lifetime)
    }

    /// A UDP socket at a free relay port, bound to the public address when
    /// that is an address of this machine, to any otherwise (a container,
    /// a machine behind a NAT).
    async fn bind_relay(&self, even: bool) -> Option<UdpSocket> {
        let range = &self.config.relay_ports;
        let span = u32::from(*range.end()) - u32::from(*range.start()) + 1;
        for _ in 0..PORT_TRIES {
            let random = u32::from_be_bytes(auth::random(4).try_into().expect("4 bytes"));
            let mut port = *range.start() + (random % span) as u16;
            if even && port % 2 == 1 {
                port = if port == *range.end() { port - 1 } else { port + 1 };
            }
            for ip in [self.config.public_ip, IpAddr::from([0, 0, 0, 0])] {
                match UdpSocket::bind(SocketAddr::new(ip, port)).await {
                    Ok(socket) => return Some(socket),
                    Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => continue,
                    Err(_) => break,
                }
            }
        }
        None
    }

    /// The allocation of `key` under the credentials of `d`, or the answer
    /// to send instead.
    fn allocation_of(&self, key: ClientKey, d: &Decoded<'_>, known: &[u16]) -> Result<(Arc<Allocation>, [u8; 16]), Vec<u8>> {
        let existing = self.get(key);
        let (ikey, username) = self.authenticate(key, d, known, existing.as_deref())?;
        let Some(a) = existing else {
            return Err(d.msg.error(437, "Allocation Mismatch").encode(Some(&ikey), true));
        };
        if a.username != username {
            return Err(d.msg.error(441, "Wrong Credentials").encode(Some(&ikey), true));
        }
        Ok((a, ikey))
    }

    fn refresh(&self, key: ClientKey, d: &Decoded<'_>) -> Vec<u8> {
        let m = &d.msg;
        let (a, ikey) = match self.allocation_of(key, d, KNOWN_REFRESH) {
            Ok(x) => x,
            Err(reply) => return reply,
        };
        if m.get(attr::REQUESTED_ADDRESS_FAMILY).is_some_and(|v| v.first() != Some(&stun::FAMILY_IPV4)) {
            return m.error(443, "Peer Address Family Mismatch").encode(Some(&ikey), true);
        }
        let lifetime = if m.get_u32(attr::LIFETIME) == Some(0) {
            tracing::debug!(client = %key.addr, "allocation released");
            self.remove(key);
            Duration::ZERO
        } else {
            let lifetime = self.lifetime_of(m);
            a.refresh(lifetime);
            lifetime
        };
        let mut r = m.success();
        r.add_u32(attr::LIFETIME, lifetime.as_secs() as u32);
        r.encode(Some(&ikey), true)
    }

    /// Where may the client send? The policy's word, counted when it is
    /// no. `port_used` says whether a packet goes to the port named: it
    /// does in Send and ChannelBind, not in CreatePermission.
    fn peer_allowed(&self, key: ClientKey, peer: SocketAddr, port_used: bool) -> Result<(), u16> {
        let verdict = if port_used {
            let live = self.live_ports.lock().expect("live ports");
            self.config.policy.check(peer, Port::Used { live_relay_ports: &live })
        } else {
            self.config.policy.check(peer, Port::Ignored)
        };
        if let Err(why) = verdict {
            self.shared.counters.refused_forbidden_peer.bump();
            tracing::debug!(client = %key.addr, %peer, %why, "peer refused");
            return Err(403);
        }
        if peer.is_ipv6() && !peer.ip().to_canonical().is_ipv4() {
            return Err(443);
        }
        Ok(())
    }

    fn create_permission(&self, key: ClientKey, d: &Decoded<'_>) -> Vec<u8> {
        let m = &d.msg;
        let (a, ikey) = match self.allocation_of(key, d, KNOWN_PERMISSION) {
            Ok(x) => x,
            Err(reply) => return reply,
        };
        let peers = m.xor_peer_addrs();
        if peers.is_empty() || peers.iter().any(Option::is_none) {
            return m.error(400, "Bad Request").encode(Some(&ikey), true);
        }
        let peers: Vec<SocketAddr> = peers.into_iter().flatten().collect();
        for peer in &peers {
            if let Err(code) = self.peer_allowed(key, *peer, false) {
                let reason = if code == 403 { "Forbidden" } else { "Peer Address Family Mismatch" };
                return m.error(code, reason).encode(Some(&ikey), true);
            }
        }
        let ips: Vec<IpAddr> = peers.iter().map(|p| p.ip().to_canonical()).collect();
        if let Err(refused) = a.add_permissions(&ips) {
            tracing::debug!(client = %key.addr, why = refused.why(), "permissions refused");
            let (code, reason) = refused.code();
            return m.error(code, reason).encode(Some(&ikey), true);
        }
        m.success().encode(Some(&ikey), true)
    }

    fn channel_bind(&self, key: ClientKey, d: &Decoded<'_>) -> Vec<u8> {
        let m = &d.msg;
        let (a, ikey) = match self.allocation_of(key, d, KNOWN_CHANNEL_BIND) {
            Ok(x) => x,
            Err(reply) => return reply,
        };
        let refuse = |code: u16, reason: &str| m.error(code, reason).encode(Some(&ikey), true);
        let (Some(number), Some(peer)) = (m.get_channel(), m.get_xor_addr(attr::XOR_PEER_ADDRESS)) else {
            return refuse(400, "Bad Request");
        };
        if !(stun::CHANNEL_MIN..=stun::CHANNEL_MAX).contains(&number) {
            return refuse(400, "Bad Request");
        }
        if let Err(code) = self.peer_allowed(key, peer, true) {
            return refuse(code, if code == 403 { "Forbidden" } else { "Peer Address Family Mismatch" });
        }
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        if let Err(refused) = a.bind_channel(number, peer) {
            tracing::debug!(client = %key.addr, number, %peer, why = refused.why(), "channel refused");
            let (code, reason) = refused.code();
            return refuse(code, reason);
        }
        m.success().encode(Some(&ikey), true)
    }

    /// Takes `n` bytes out of every bucket on the way to a peer.
    fn bandwidth(&self, a: &Allocation, n: usize) -> bool {
        if a.up.take(n) && self.shared.turn_bucket.take(n) && self.shared.node_bucket.take(n) {
            return true;
        }
        self.shared.counters.dropped_bandwidth.bump();
        false
    }

    async fn relay_to(&self, a: &Allocation, peer: SocketAddr, data: &[u8]) {
        if !self.bandwidth(a, data.len()) {
            return;
        }
        if a.relay.send_to(data, peer).await.is_ok() {
            self.shared.counters.bytes_to_peers.add(data.len() as u64);
        }
    }

    async fn send_indication(&self, key: ClientKey, m: &Message) {
        let Some(a) = self.get(key) else {
            return;
        };
        let (Some(peer), Some(data)) = (m.get_xor_addr(attr::XOR_PEER_ADDRESS), m.get(attr::DATA)) else {
            return;
        };
        if self.peer_allowed(key, peer, true).is_err() {
            return;
        }
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        if !a.permitted(peer.ip()) {
            self.shared.counters.dropped_no_permission.bump();
            return;
        }
        self.relay_to(&a, peer, data).await;
    }

    async fn channel_data(&self, key: ClientKey, data: &[u8]) {
        let Some((number, payload)) = stun::parse_channel_data(data) else {
            return;
        };
        let Some(a) = self.get(key) else {
            return;
        };
        let Some(peer) = a.channel_peer(number) else {
            self.shared.counters.dropped_no_permission.bump();
            return;
        };
        self.relay_to(&a, peer, payload).await;
    }
}
