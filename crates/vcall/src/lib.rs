//! The call node.
//!
//! ```text
//!   TLS port (443)     control (ALPN vcall/1, h2)       HELLO, TURN credentials
//!                      TURN over TLS                     a STUN message first, or ALPN stun.turn
//!                      anybody else                      the page of an idle web server
//!   UDP 3478           STUN Binding, TURN
//!   TCP 3478           TURN
//!   UDP relay ports    one socket per allocation, towards the peers
//!   UDP, TCP 3479      the SFU: the rooms of group calls
//! ```
//!
//! The node knows nobody: a client is an address with credentials that
//! the node itself handed out a few minutes before, or a seat in a room it
//! was let into by a token. What it carries is DTLS-SRTP between the
//! callers, which it cannot read; in a room, frames encrypted between the
//! participants under keys the node never sees.

pub mod cascade;
pub mod client;
pub mod control;
pub mod counters;
pub mod ctl;
pub mod decoy;
pub mod devices;
pub mod https;
pub mod identity;
pub mod load;
pub mod register;
pub mod room_client;
pub mod sfu;
pub mod stun;
pub mod trust;
pub mod turn;

use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use vcall_proto::{capability, Limits};
use vlink_proto::io as h2io;
use vlink_proto::pin::ALPN_H2;

use cascade::Cascade;
use control::Control;
use counters::Counters;
use ctl::{CtlSocket, CtlState};
use devices::{Devices, Gate};
use identity::{Identity, NodeId};
use sfu::{CascadeMode, Sfu};
use trust::Trust;
use turn::allocation::Transport;
use turn::auth::Auth;
use turn::limits::{Bucket, PerIp, RateWindow};
use turn::policy::PeerPolicy;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the node can do, as WELCOME and the registry say it; `cascade`
/// besides, unless it is off ([`capabilities`]).
pub const CAPABILITIES: &[&str] =
    &[capability::STUN, capability::TURN, capability::TURN_TCP, capability::TURN_TLS, capability::SFU, capability::SIMULCAST];

/// [`CAPABILITIES`], with the cascade when the node takes part in it.
pub fn capabilities(cascade: bool) -> Vec<String> {
    let mut caps: Vec<String> = CAPABILITIES.iter().map(|c| c.to_string()).collect();
    if cascade {
        caps.push(capability::CASCADE.to_string());
    }
    caps
}

/// TLS and the first bytes after it.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A browser that keeps its h2 connection without asking is let go after
/// this: a decoy answers requests, it does not hold connections.
const DECOY_IDLE: Duration = Duration::from_secs(10);
/// A control connection with no request for this long is closed.
pub const CONTROL_IDLE: Duration = Duration::from_secs(120);
/// How often credentials are counted per address, on a public node.
const CREDENTIALS_WINDOW: Duration = Duration::from_secs(600);
/// What an allocation gets when it asks for nothing (RFC 8656: 10 minutes).
const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

pub struct Config {
    pub identity: Identity,
    /// The node's key as a signer (the key of `identity`'s id): its word
    /// to other nodes in the cascade.
    pub signing_key: Arc<ring::signature::Ed25519KeyPair>,
    pub turn_secret: Vec<u8>,
    /// Control and TURN over TLS.
    pub listen: SocketAddr,
    /// STUN and TURN over UDP, TURN over TCP: the same port on both.
    pub turn_listen: SocketAddr,
    /// The SFU over UDP and TCP: the same port on both.
    pub sfu_listen: SocketAddr,
    /// The address the world reaches this machine at.
    pub public_ip: IpAddr,
    /// The port the world reaches the TLS port at, when it is not `listen`'s.
    pub public_port: Option<u16>,
    pub relay_ports: RangeInclusive<u16>,
    pub realm: String,
    pub private: bool,
    pub access_keys: Vec<String>,
    /// The file the devices let in by invitation are kept in
    /// (`devices::FILE` in `VCALL_DATA`); none for in memory only (the tests).
    pub devices: Option<PathBuf>,
    pub issuers: Vec<String>,
    /// TCP and TLS connections held at once, of all kinds; and how many of
    /// them one address may hold, so that one host cannot take them all.
    pub max_connections: usize,
    pub max_connections_per_ip: u32,
    /// A control connection with no request for this long is closed
    /// ([`CONTROL_IDLE`]; the tests set less).
    pub control_idle: Duration,
    /// All traffic of the node, and the part of it TURN may take.
    pub max_mbps: u64,
    pub turn_mbps: u64,
    pub kbps_per_allocation: u64,
    pub max_allocations: usize,
    pub max_per_ip: u32,
    pub max_lifetime: Duration,
    pub credentials_ttl: Duration,
    pub credentials_per_ip: u32,
    /// Rooms of the SFU at once, seats in each, what a seat may send
    /// (kbit/s, 0 for no limit), how long a room lives and stands empty.
    pub max_rooms: usize,
    pub room_max_participants: u32,
    pub room_kbps_per_participant: u32,
    pub room_lifetime: Duration,
    pub room_idle: Duration,
    /// How long a seat waits for its participant to connect, and an offer
    /// of the node for its answer before it is sent again.
    pub room_connect_timeout: Duration,
    pub room_offer_timeout: Duration,
    /// Speakers whose audio is forwarded in a room with more participants
    /// than that and one; and what a participant is assumed to take,
    /// kbit/s, before its TWCC feedback says.
    pub room_audio_n: u32,
    pub room_bwe_kbps: u32,
    /// The cascade: on, off, the registry's list, or a list of nodes
    /// (`trust`); seats one node may hold here; uplinks this node makes;
    /// joins with a home from one address in ten minutes on a public node.
    pub cascade: CascadeMode,
    pub cascade_seats_per_node: u32,
    pub cascade_uplinks: usize,
    pub cascade_joins_per_ip: u32,
    /// Relay to loopback and private addresses: tests on one machine only.
    pub allow_private_peers: bool,
    /// The control socket; none for no socket.
    pub ctl: Option<PathBuf>,
}

/// Where the node listens, as bound: the ports are known only then when
/// 0 was asked for (the tests).
#[derive(Clone, Copy, Debug)]
pub struct Addrs {
    pub control: SocketAddr,
    pub turn_udp: SocketAddr,
    pub turn_tcp: SocketAddr,
    /// The SFU, over UDP and TCP alike.
    pub sfu: SocketAddr,
}

/// A handle that outlives [`Node::run`].
#[derive(Clone)]
pub struct Handle {
    pub counters: Arc<Counters>,
    pub turn: Arc<turn::Server>,
    pub sfu: Arc<Sfu>,
    pub cascade: Arc<Cascade>,
    /// Whose seats the node takes (the registry's list goes in here), and
    /// the devices a private node let in.
    pub trust: Arc<Trust>,
    pub devices: Arc<Devices>,
    pub started: Instant,
}

pub struct Node {
    id: NodeId,
    listener: TcpListener,
    turn_udp: Arc<UdpSocket>,
    turn_tcp: TcpListener,
    acceptor: TlsAcceptor,
    control: Arc<Control>,
    turn: Arc<turn::Server>,
    sfu: Arc<Sfu>,
    counters: Arc<Counters>,
    slots: Arc<Slots>,
    ctl: Option<CtlSocket>,
    trust: Arc<Trust>,
    devices: Arc<Devices>,
    /// The control channel as the world reaches it: what a link names.
    control_addr: SocketAddr,
    started: Instant,
}

/// The connections the node holds: so many in all, so many per address.
/// Control, TURN over TLS and TCP and the SFU over TCP share them, so
/// without the share per address one host could take them all and, with
/// them, the credentials every client needs.
pub struct Slots {
    all: Arc<Semaphore>,
    per_ip: PerIp,
    max_per_ip: u32,
}

/// One connection's place; given back when the connection ends.
pub struct Slot {
    slots: Arc<Slots>,
    ip: IpAddr,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Slots {
    fn new(max: usize, max_per_ip: u32) -> Arc<Self> {
        Arc::new(Self { all: Arc::new(Semaphore::new(max)), per_ip: PerIp::default(), max_per_ip })
    }

    /// A place for a connection from `ip`, or none: the node is full, or
    /// the address has its share. The connection is dropped then.
    pub fn take(self: &Arc<Self>, ip: IpAddr) -> Option<Slot> {
        let permit = self.all.clone().try_acquire_owned().ok()?;
        if !self.per_ip.acquire(ip, self.max_per_ip) {
            return None;
        }
        Some(Slot { slots: self.clone(), ip, _permit: permit })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.slots.per_ip.release(self.ip);
    }
}

impl Node {
    /// Binds every socket; nothing is served until [`Node::run`].
    pub async fn bind(config: Config) -> anyhow::Result<Self> {
        let id = identity::node_id(&config.identity)?;
        let tls = identity::server_config(config.identity)?;
        let listener = TcpListener::bind(config.listen).await.with_context(|| format!("cannot listen on {}", config.listen))?;
        // UDP and TCP on one port, as the URIs say. With port 0 asked for
        // (the tests), the port UDP got is the one TCP takes, with a few
        // tries in case that port is held by somebody over TCP.
        let (turn_udp, turn_tcp) = {
            let mut pair = None;
            for _ in 0..8 {
                let udp = UdpSocket::bind(config.turn_listen).await.with_context(|| format!("cannot listen on {}/udp", config.turn_listen))?;
                let got = udp.local_addr()?;
                match TcpListener::bind(got).await {
                    Ok(tcp) => {
                        pair = Some((udp, tcp));
                        break;
                    }
                    Err(e) if config.turn_listen.port() == 0 => tracing::debug!(error = %e, "port {} is taken over tcp, another", got.port()),
                    Err(e) => return Err(e).with_context(|| format!("cannot listen on {got}/tcp")),
                }
            }
            pair.context("no port is free for TURN over both UDP and TCP")?
        };
        let ctl = match &config.ctl {
            Some(path) => Some(CtlSocket::bind(path).await.with_context(|| format!("control socket {}", path.display()))?),
            None => None,
        };
        anyhow::ensure!(!config.relay_ports.is_empty(), "the relay port range is empty");
        // A private node is opened by a key, or by a device that took an
        // invitation; with neither and no socket to make an invitation
        // through, nobody could ever use it.
        let devices = Devices::open(config.devices.clone())?;
        anyhow::ensure!(
            !config.private || !config.access_keys.is_empty() || devices.has_any() || ctl.is_some(),
            "a private node needs access keys (VCALL_ACCESS_KEYS) or invitations (vcall ctl invite), or nobody can use it"
        );
        if config.private && config.access_keys.is_empty() && !devices.has_any() {
            tracing::warn!("a private node without keys or devices: make an invitation with `vcall ctl invite`");
        }
        let gate = Arc::new(Gate { private: config.private, keys: config.access_keys, devices: devices.clone() });
        let trust = Arc::new(Trust::new(config.cascade.clone()));

        let counters = Arc::new(Counters::default());
        let auth = Arc::new(Auth::new(&config.turn_secret, &config.realm));
        let node_bucket = Arc::new(Bucket::from_mbps(config.max_mbps));
        let sfu = Arc::new(
            Sfu::bind(
                sfu::Config {
                    listen: config.sfu_listen,
                    public_ip: config.public_ip,
                    node_id: id.to_string(),
                    max_rooms: config.max_rooms,
                    max_participants: config.room_max_participants.max(2),
                    kbps_per_participant: config.room_kbps_per_participant,
                    lifetime: config.room_lifetime,
                    idle: config.room_idle,
                    connect_timeout: config.room_connect_timeout,
                    offer_timeout: config.room_offer_timeout,
                    audio_n: config.room_audio_n.max(1),
                    bwe_kbps: config.room_bwe_kbps,
                    trust: trust.clone(),
                    cascade_seats_per_node: config.cascade_seats_per_node,
                    cascade_uplinks: config.cascade_uplinks,
                },
                counters.clone(),
                node_bucket.clone(),
            )
            .await?,
        );

        // Everything the node answers at is its own: a peer there, outside
        // the relay ports, would be the node's services.
        let mut own = vec![config.public_ip];
        for ip in [config.listen.ip(), config.turn_listen.ip()] {
            if !ip.is_unspecified() && !own.contains(&ip) {
                own.push(ip);
            }
        }
        if let Some(ip) = detect_public_ip() {
            if !own.contains(&ip) {
                own.push(ip);
            }
        }
        let turn = turn::Server::new(
            turn::Config {
                public_ip: config.public_ip,
                relay_ports: config.relay_ports.clone(),
                realm: config.realm.clone(),
                max_allocations: config.max_allocations,
                max_per_ip: config.max_per_ip,
                default_lifetime: DEFAULT_LIFETIME.min(config.max_lifetime),
                max_lifetime: config.max_lifetime,
                kbps_per_allocation: config.kbps_per_allocation,
                turn_mbps: config.turn_mbps,
                policy: PeerPolicy::new(own.clone(), config.allow_private_peers),
            },
            auth.clone(),
            node_bucket,
            counters.clone(),
        );
        // The same policy for the homes a client names: a node must not
        // open connections into the network behind it on a client's word.
        let cascade = Arc::new(Cascade::new(
            id,
            VERSION.to_string(),
            config.signing_key,
            sfu.clone(),
            Arc::new(PeerPolicy::new(own, config.allow_private_peers)),
            config.cascade.is_on(),
            gate.clone(),
            config.cascade_joins_per_ip,
            counters.clone(),
        ));

        let turn_port = turn_udp.local_addr()?.port();
        let tls_port = config.public_port.unwrap_or(listener.local_addr()?.port());
        let control_addr = SocketAddr::new(config.public_ip, tls_port);
        let control = Arc::new(Control {
            node_id: id,
            version: VERSION.to_string(),
            capabilities: capabilities(config.cascade.is_on()),
            codecs: sfu::CODECS.iter().map(|c| c.to_string()).collect(),
            private: config.private,
            gate,
            node_ref: format!("{control_addr}#{id}"),
            invites: RateWindow::new(control::INVITE_WINDOW, control::INVITE_ATTEMPTS_PER_IP),
            issuers: config.issuers,
            auth,
            credentials_ttl: config.credentials_ttl,
            idle: config.control_idle,
            urls: client::urls(config.public_ip, turn_port, tls_port),
            limits: Limits {
                turn_lifetime_secs: config.max_lifetime.as_secs() as u32,
                turn_kbps_per_allocation: config.kbps_per_allocation as u32,
                credentials_ttl_secs: config.credentials_ttl.as_secs() as u32,
                room_max_participants: sfu.config().max_participants,
                room_kbps_per_participant: sfu.config().kbps_per_participant,
                room_lifetime_secs: sfu.config().lifetime.as_secs() as u32,
                room_idle_secs: sfu.config().idle.as_secs() as u32,
            },
            rate: RateWindow::new(CREDENTIALS_WINDOW, config.credentials_per_ip),
            bad_tokens: RateWindow::new(control::BAD_TOKENS_WINDOW, control::BAD_TOKENS_PER_IP),
            counters: counters.clone(),
            sfu: sfu.clone(),
            cascade,
        });

        Ok(Self {
            id,
            listener,
            turn_udp: Arc::new(turn_udp),
            turn_tcp,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            control,
            turn,
            sfu,
            counters,
            slots: Slots::new(config.max_connections, config.max_connections_per_ip),
            ctl,
            trust,
            devices,
            control_addr,
            started: Instant::now(),
        })
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn addrs(&self) -> std::io::Result<Addrs> {
        Ok(Addrs {
            control: self.listener.local_addr()?,
            turn_udp: self.turn_udp.local_addr()?,
            turn_tcp: self.turn_tcp.local_addr()?,
            sfu: self.sfu.local_addr()?,
        })
    }

    pub fn handle(&self) -> Handle {
        Handle {
            counters: self.counters.clone(),
            turn: self.turn.clone(),
            sfu: self.sfu.clone(),
            cascade: self.control.cascade.clone(),
            trust: self.trust.clone(),
            devices: self.devices.clone(),
            started: self.started,
        }
    }

    /// The control channel as the world reaches it: `address:port`.
    pub fn control_addr(&self) -> SocketAddr {
        self.control_addr
    }

    /// Serves until a listener fails. Dropped (a test aborts it), the
    /// sockets stop with it: the node is gone for everybody.
    pub async fn run(self) -> anyhow::Result<()> {
        let udp = Stopped(tokio::spawn(self.turn.clone().serve_udp(self.turn_udp.clone())));
        let sweep = Stopped(tokio::spawn(self.turn.clone().sweep()));
        let tcp = Stopped(tokio::spawn(turn_tcp_loop(self.turn_tcp, self.turn.clone(), self.slots.clone())));
        let sfu = Stopped(tokio::spawn(self.sfu.clone().run(self.slots.clone())));
        if let Some(ctl) = self.ctl {
            let state = CtlState {
                version: VERSION.to_string(),
                started: self.started,
                counters: self.counters.clone(),
                turn: self.turn.clone(),
                sfu: self.sfu.clone(),
                trust: self.trust.clone(),
                devices: self.devices.clone(),
                node_id: self.id.to_string(),
                control_addr: self.control_addr.to_string(),
            };
            tokio::spawn(ctl.run(state));
        }
        let tls = tls_loop(self.listener, self.acceptor, self.control, self.turn, self.slots);
        let (mut udp, mut sweep, mut tcp, mut sfu) = (udp, sweep, tcp, sfu);
        tokio::select! {
            r = tls => r,
            _ = &mut udp.0 => anyhow::bail!("the udp loop ended"),
            _ = &mut tcp.0 => anyhow::bail!("the tcp loop ended"),
            _ = &mut sweep.0 => anyhow::bail!("the sweeper ended"),
            r = &mut sfu.0 => r?,
        }
    }
}

/// A task that is stopped when its handle is dropped, so that the loops
/// of a node end with the node.
struct Stopped<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for Stopped<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// TURN over TCP: each connection to the TURN server, for as long as it lasts.
async fn turn_tcp_loop(listener: TcpListener, turn: Arc<turn::Server>, slots: Arc<Slots>) -> anyhow::Result<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed (turn tcp)");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Some(slot) = slots.take(peer.ip()) else {
            continue; // full, or the address has its share: the connection is dropped
        };
        let turn = turn.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tcp.set_nodelay(true);
            turn.serve_stream(tcp, peer, Transport::Tcp, Vec::new()).await;
        });
    }
}

/// The TLS port: who came is told after the handshake.
async fn tls_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    control: Arc<Control>,
    turn: Arc<turn::Server>,
    slots: Arc<Slots>,
) -> anyhow::Result<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed (tls)");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Some(slot) = slots.take(peer.ip()) else {
            continue;
        };
        let acceptor = acceptor.clone();
        let control = control.clone();
        let turn = turn.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tcp.set_nodelay(true);
            let Ok(Ok(stream)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await else {
                return;
            };
            let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            match alpn.as_deref() {
                Some(vcall_proto::ALPN) => control::serve(stream, peer, control).await,
                Some(identity::ALPN_STUN_TURN) => turn.serve_stream(stream, peer, Transport::Tls, Vec::new()).await,
                Some(ALPN_H2) => decoy_h2(stream).await,
                Some(_) => decoy::http1(stream, Vec::new()).await,
                // No ALPN: a TURN client (libwebrtc sends none) starts with
                // a STUN message, whose first two bits are zero; a browser
                // starts with a letter.
                None => first_byte(stream, peer, turn).await,
            }
        });
    }
}

async fn first_byte(mut stream: TlsStream<TcpStream>, peer: SocketAddr, turn: Arc<turn::Server>) {
    let mut first = [0u8; 1];
    let Ok(Ok(1)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut first)).await else {
        return;
    };
    if first[0] & 0xC0 == 0 {
        turn.serve_stream(stream, peer, Transport::Tls, first.to_vec()).await
    } else {
        decoy::http1(stream, first.to_vec()).await
    }
}

/// A browser over h2 gets the same page for every request, and is let go
/// once it asks nothing for a while.
async fn decoy_h2(stream: TlsStream<TcpStream>) {
    let Ok(Ok(mut connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, h2io::server_builder().handshake::<_, Bytes>(stream)).await else {
        return;
    };
    while let Ok(Some(Ok((_request, mut respond)))) = tokio::time::timeout(DECOY_IDLE, connection.accept()).await {
        decoy::h2(&mut respond);
    }
}

/// The address this machine leaves by: a socket "connected" to a public
/// address (no packet is sent) is bound to it. On a server that is the
/// public address; behind a NAT it is private, and `VCALL_PUBLIC_IP` has
/// to say.
pub fn detect_public_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// `49152-65535` as a range.
pub fn parse_port_range(text: &str) -> anyhow::Result<RangeInclusive<u16>> {
    let (a, b) = text.trim().split_once('-').context("a range is `first-last`")?;
    let first: u16 = a.trim().parse().with_context(|| format!("not a port: {a}"))?;
    let last: u16 = b.trim().parse().with_context(|| format!("not a port: {b}"))?;
    anyhow::ensure!(first >= 1024 && first <= last, "the range must be within 1024-65535, first not past last");
    Ok(first..=last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges() {
        assert_eq!(parse_port_range("49152-65535").unwrap(), 49152..=65535);
        assert_eq!(parse_port_range(" 50000 - 50010 ").unwrap(), 50000..=50010);
        assert!(parse_port_range("65535-49152").is_err());
        assert!(parse_port_range("80-100").is_err());
        assert!(parse_port_range("abc").is_err());
    }
}
