//! One allocation (RFC 8656 5): a relay socket, the peers the client
//! allowed, the channels it bound, and the task that carries what peers
//! send back to the client.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::limits::Bucket;
use crate::counters::{Bump, Counters};
use crate::stun::{self, attr, method, Message};

/// RFC 8656 9: a permission lasts 5 minutes, a channel 10.
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
pub const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
/// Peers one allocation may hold permissions for at once. A call has a
/// handful of candidates on the other side; without a ceiling one
/// CreatePermission names thousands of addresses, and the map grows by
/// megabytes a second under the lock every packet takes.
pub const MAX_PERMISSIONS: usize = 64;

/// What a stream's writer may hold for a client that does not read: in
/// frames, and in bytes, since a frame from a peer is up to 64 KiB. A
/// second of an allocation's bandwidth is more than enough; a queue is
/// not a buffer for a slow link, UDP is allowed to lose.
pub const STREAM_QUEUE_FRAMES: usize = 256;
pub const STREAM_QUEUE_BYTES: usize = 256 * 1024;
/// Answers to the client's own requests wait in a lane of their own: a
/// Refresh that went unanswered because peers filled the queue would end
/// the allocation (over TCP the client does not retry, RFC 8489 6.2.2).
const REPLY_QUEUE: usize = 32;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
}

impl Transport {
    /// ChannelData on a stream is padded to four bytes; on UDP it is not.
    pub fn is_stream(self) -> bool {
        !matches!(self, Self::Udp)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }
}

/// The client's side of the 5-tuple: how it came and from where. The
/// node's side is one socket per transport, so these two name the client.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ClientKey {
    pub transport: Transport,
    pub addr: SocketAddr,
}

/// The way back to a client over a stream: two queues to one writer task,
/// replies first, and the bytes the data queue holds.
#[derive(Clone)]
pub struct StreamSink {
    replies: mpsc::Sender<Bytes>,
    data: mpsc::Sender<Bytes>,
    queued: Arc<AtomicUsize>,
}

/// What the writer task of a stream takes frames from.
pub struct StreamSource {
    replies: mpsc::Receiver<Bytes>,
    data: mpsc::Receiver<Bytes>,
    queued: Arc<AtomicUsize>,
}

impl StreamSink {
    pub fn new() -> (Self, StreamSource) {
        let (replies, replies_rx) = mpsc::channel(REPLY_QUEUE);
        let (data, data_rx) = mpsc::channel(STREAM_QUEUE_FRAMES);
        let queued = Arc::new(AtomicUsize::new(0));
        (Self { replies, data, queued: queued.clone() }, StreamSource { replies: replies_rx, data: data_rx, queued })
    }

    /// Bytes of relayed data waiting for the writer.
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }
}

impl StreamSource {
    /// The next frame: a reply when there is one, relayed data otherwise;
    /// `None` once the sink is gone.
    pub async fn next(&mut self) -> Option<Bytes> {
        tokio::select! {
            biased;
            reply = self.replies.recv() => reply,
            data = self.data.recv() => {
                let data = data?;
                self.queued.fetch_sub(data.len(), Ordering::Relaxed);
                Some(data)
            }
        }
    }
}

/// The way back to a client.
#[derive(Clone)]
pub enum Sink {
    Udp { socket: Arc<UdpSocket>, addr: SocketAddr },
    Stream(StreamSink),
}

impl Sink {
    /// An answer to the client's request. On a stream it waits for room in
    /// the reply lane rather than being dropped: the lane is short, and a
    /// client that does not read is answered when it does.
    pub async fn reply(&self, bytes: Bytes) -> bool {
        match self {
            Self::Udp { socket, addr } => socket.send_to(&bytes, addr).await.is_ok(),
            Self::Stream(s) => s.replies.send(bytes).await.is_ok(),
        }
    }

    /// A frame from a peer. On a stream it is dropped when the queue is
    /// full, in frames or in bytes, as a full link would drop it.
    pub async fn relay(&self, bytes: Bytes) -> bool {
        match self {
            Self::Udp { socket, addr } => socket.send_to(&bytes, addr).await.is_ok(),
            Self::Stream(s) => {
                let n = bytes.len();
                // Reserve first, so that two readers cannot both see room.
                if s.queued.fetch_add(n, Ordering::Relaxed) + n > STREAM_QUEUE_BYTES {
                    s.queued.fetch_sub(n, Ordering::Relaxed);
                    return false;
                }
                if s.data.try_send(bytes).is_ok() {
                    true
                } else {
                    s.queued.fetch_sub(n, Ordering::Relaxed);
                    false
                }
            }
        }
    }
}

/// What the relay reader needs of the node: the limits every allocation
/// shares, and the counters.
pub struct Shared {
    pub turn_bucket: Bucket,
    pub node_bucket: Arc<Bucket>,
    pub counters: Arc<Counters>,
}

struct Inner {
    expires: Instant,
    permissions: HashMap<IpAddr, Instant>,
    channels: HashMap<u16, (SocketAddr, Instant)>,
    peers: HashMap<SocketAddr, u16>,
}

/// Why a permission or a channel was not made, and the answer it earns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// 400: the channel number or the peer is bound otherwise.
    Bound(&'static str),
    /// 508: the allocation holds all the permissions it may.
    TooManyPermissions,
}

impl Refused {
    pub fn code(self) -> (u16, &'static str) {
        match self {
            Self::Bound(_) => (400, "Bad Request"),
            Self::TooManyPermissions => (508, "Insufficient Capacity"),
        }
    }

    pub fn why(self) -> &'static str {
        match self {
            Self::Bound(why) => why,
            Self::TooManyPermissions => "too many permissions",
        }
    }
}

pub struct Allocation {
    pub client: ClientKey,
    pub sink: Sink,
    pub relay: Arc<UdpSocket>,
    /// The relay socket as the world sees it: the public address, the port.
    pub relayed: SocketAddr,
    pub username: String,
    pub key: [u8; 16],
    /// The transaction that made the allocation: a retransmission of it
    /// gets the same answer, not 437.
    pub txid: [u8; 12],
    /// The bandwidth of the allocation, each way its own: a call sends and
    /// receives at once, and the limit is what one direction may carry.
    pub up: Bucket,
    pub down: Bucket,
    inner: Mutex<Inner>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl Allocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: ClientKey,
        sink: Sink,
        relay: Arc<UdpSocket>,
        relayed: SocketAddr,
        username: String,
        key: [u8; 16],
        txid: [u8; 12],
        lifetime: Duration,
        bytes_per_sec: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            client,
            sink,
            relay,
            relayed,
            username,
            key,
            txid,
            up: Bucket::new(bytes_per_sec),
            down: Bucket::new(bytes_per_sec),
            inner: Mutex::new(Inner {
                expires: Instant::now() + lifetime,
                permissions: HashMap::new(),
                channels: HashMap::new(),
                peers: HashMap::new(),
            }),
            reader: Mutex::new(None),
        })
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("allocation")
    }

    pub fn expired(&self, now: Instant) -> bool {
        self.inner().expires <= now
    }

    pub fn refresh(&self, lifetime: Duration) {
        self.inner().expires = Instant::now() + lifetime;
    }

    /// Permissions for `ips`, all or none: refreshed where there is one,
    /// made otherwise, as long as the allocation stays under
    /// [`MAX_PERMISSIONS`]. Expired ones count until the sweep.
    pub fn add_permissions(&self, ips: &[IpAddr]) -> Result<(), Refused> {
        let mut inner = self.inner();
        let now = Instant::now();
        let mut new = 0;
        for (i, ip) in ips.iter().enumerate() {
            if !inner.permissions.contains_key(ip) && !ips[..i].contains(ip) {
                new += 1;
            }
        }
        if inner.permissions.len() + new > MAX_PERMISSIONS {
            return Err(Refused::TooManyPermissions);
        }
        for ip in ips {
            inner.permissions.insert(*ip, now + PERMISSION_LIFETIME);
        }
        Ok(())
    }

    pub fn permissions(&self) -> usize {
        self.inner().permissions.len()
    }

    /// May packets go to and come from `ip`? A permission, or a channel to
    /// an address there (a channel implies one, RFC 8656 12.2).
    pub fn permitted(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let inner = self.inner();
        inner.permissions.get(&ip).is_some_and(|until| *until > now)
            || inner.peers.keys().any(|peer| peer.ip() == ip && inner.channels.get(&inner.peers[peer]).is_some_and(|(_, until)| *until > now))
    }

    /// Binds `number` to `peer` (RFC 8656 12.2): a number to one peer, a
    /// peer to one number, either may be refreshed with the same pair. A
    /// channel implies a permission, which counts like any other.
    pub fn bind_channel(&self, number: u16, peer: SocketAddr) -> Result<(), Refused> {
        let mut inner = self.inner();
        let now = Instant::now();
        match inner.channels.get(&number) {
            Some((bound, until)) if *bound != peer && *until > now => return Err(Refused::Bound("the channel is bound to another peer")),
            _ => {}
        }
        match inner.peers.get(&peer) {
            Some(bound) if *bound != number && inner.channels.get(bound).is_some_and(|(_, until)| *until > now) => {
                return Err(Refused::Bound("the peer has another channel"))
            }
            _ => {}
        }
        if !inner.permissions.contains_key(&peer.ip()) && inner.permissions.len() >= MAX_PERMISSIONS {
            return Err(Refused::TooManyPermissions);
        }
        // A number or a peer whose old binding has expired is free again.
        if let Some((old_peer, _)) = inner.channels.remove(&number) {
            inner.peers.remove(&old_peer);
        }
        if let Some(old_number) = inner.peers.remove(&peer) {
            inner.channels.remove(&old_number);
        }
        inner.channels.insert(number, (peer, now + CHANNEL_LIFETIME));
        inner.peers.insert(peer, number);
        inner.permissions.insert(peer.ip(), now + PERMISSION_LIFETIME);
        Ok(())
    }

    pub fn channel_peer(&self, number: u16) -> Option<SocketAddr> {
        let inner = self.inner();
        inner.channels.get(&number).filter(|(_, until)| *until > Instant::now()).map(|(peer, _)| *peer)
    }

    pub fn peer_channel(&self, peer: SocketAddr) -> Option<u16> {
        let inner = self.inner();
        let number = *inner.peers.get(&peer)?;
        inner.channels.get(&number).filter(|(_, until)| *until > Instant::now()).map(|_| number)
    }

    /// Forgets what has run out.
    pub fn sweep(&self, now: Instant) {
        let mut inner = self.inner();
        inner.permissions.retain(|_, until| *until > now);
        let gone: Vec<u16> = inner.channels.iter().filter(|(_, (_, until))| *until <= now).map(|(n, _)| *n).collect();
        for number in gone {
            if let Some((peer, _)) = inner.channels.remove(&number) {
                inner.peers.remove(&peer);
            }
        }
    }

    /// Starts carrying what peers send to the relay socket back to the
    /// client: as ChannelData where a channel is bound, as a Data
    /// indication otherwise, and not at all without a permission.
    pub fn start_reader(self: &Arc<Self>, shared: Arc<Shared>) {
        let alloc = self.clone();
        let handle = tokio::spawn(async move {
            let pad = alloc.client.transport.is_stream();
            let mut buf = vec![0u8; stun::MAX_MESSAGE];
            loop {
                let (n, peer) = match alloc.relay.recv_from(&mut buf).await {
                    Ok(x) => x,
                    // An ICMP error of an earlier send comes back as an
                    // error here on some systems; the socket is still good.
                    Err(_) => continue,
                };
                if !alloc.permitted(peer.ip()) {
                    shared.counters.dropped_no_permission.bump();
                    continue;
                }
                if !(alloc.down.take(n) && shared.turn_bucket.take(n) && shared.node_bucket.take(n)) {
                    shared.counters.dropped_bandwidth.bump();
                    continue;
                }
                let frame = match alloc.peer_channel(peer) {
                    Some(number) => stun::channel_data(number, &buf[..n], pad),
                    None => {
                        let mut m = Message::indication(method::DATA);
                        m.add_xor_addr(attr::XOR_PEER_ADDRESS, peer).add(attr::DATA, &buf[..n]);
                        m.encode(None, false)
                    }
                };
                if alloc.sink.relay(Bytes::from(frame)).await {
                    shared.counters.bytes_to_clients.add(n as u64);
                } else {
                    shared.counters.dropped_stream_full.bump();
                }
            }
        });
        *self.reader.lock().expect("reader") = Some(handle);
    }

    pub fn stop(&self) {
        if let Some(handle) = self.reader.lock().expect("reader").take() {
            handle.abort();
        }
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn allocation() -> Arc<Allocation> {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relayed = relay.local_addr().unwrap();
        let client = ClientKey { transport: Transport::Udp, addr: "127.0.0.1:1".parse().unwrap() };
        let (sink, _source) = StreamSink::new();
        Allocation::new(client, Sink::Stream(sink), relay, relayed, "u".into(), [0; 16], [0; 12], Duration::from_secs(60), 0)
    }

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(0x0B00_0000 + n))
    }

    #[tokio::test]
    async fn permissions_and_channels_follow_the_rules() {
        let a = allocation().await;
        let p1: SocketAddr = "93.184.216.1:5000".parse().unwrap();
        let p2: SocketAddr = "93.184.216.2:5000".parse().unwrap();
        let p1_other_port: SocketAddr = "93.184.216.1:6000".parse().unwrap();
        assert!(!a.permitted(p1.ip()));
        a.add_permissions(&[p1.ip()]).unwrap();
        assert!(a.permitted(p1.ip()));
        assert!(!a.permitted(p2.ip()));

        assert_eq!(a.bind_channel(0x4000, p2), Ok(()));
        assert!(a.permitted(p2.ip()), "a channel implies a permission");
        assert_eq!(a.channel_peer(0x4000), Some(p2));
        assert_eq!(a.peer_channel(p2), Some(0x4000));
        assert_eq!(a.bind_channel(0x4000, p2), Ok(()), "the same pair again");
        assert!(a.bind_channel(0x4000, p1).is_err(), "the number is taken");
        assert!(a.bind_channel(0x4001, p2).is_err(), "the peer has a channel");
        assert_eq!(a.bind_channel(0x4001, p1_other_port), Ok(()), "another port is another peer");
        assert_eq!(a.channel_peer(0x4002), None);

        a.sweep(Instant::now() + CHANNEL_LIFETIME + Duration::from_secs(1));
        assert_eq!(a.channel_peer(0x4000), None);
        assert!(!a.permitted(p1.ip()));
        assert_eq!(a.bind_channel(0x4000, p1), Ok(()), "free after the sweep");
    }

    #[tokio::test]
    async fn so_many_permissions_and_no_more() {
        let a = allocation().await;
        let first: Vec<IpAddr> = (0..MAX_PERMISSIONS as u32).map(ip).collect();
        a.add_permissions(&first).unwrap();
        assert_eq!(a.permissions(), MAX_PERMISSIONS);
        assert_eq!(a.add_permissions(&[ip(1000)]), Err(Refused::TooManyPermissions));
        assert_eq!(a.add_permissions(&[ip(0), ip(1000)]), Err(Refused::TooManyPermissions), "all or none");
        assert_eq!(a.permissions(), MAX_PERMISSIONS, "none were added");
        assert_eq!(a.add_permissions(&first[..10]), Ok(()), "refreshing what is there");
        assert_eq!(a.add_permissions(&[ip(0), ip(0)]), Ok(()), "the same address twice is one");
        // A channel to a new address is one more permission too.
        assert_eq!(a.bind_channel(0x4000, SocketAddr::new(ip(1000), 5000)), Err(Refused::TooManyPermissions));
        assert_eq!(a.bind_channel(0x4000, SocketAddr::new(ip(0), 5000)), Ok(()));
        assert_eq!(Refused::TooManyPermissions.code(), (508, "Insufficient Capacity"));
        // One request may not name more than the ceiling either.
        let a = allocation().await;
        let many: Vec<IpAddr> = (0..MAX_PERMISSIONS as u32 + 1).map(ip).collect();
        assert_eq!(a.add_permissions(&many), Err(Refused::TooManyPermissions));
        assert_eq!(a.permissions(), 0);
        // After the sweep there is room again.
        a.add_permissions(&first).unwrap();
        a.sweep(Instant::now() + PERMISSION_LIFETIME + Duration::from_secs(1));
        assert_eq!(a.add_permissions(&[ip(1000)]), Ok(()));
    }

    #[tokio::test]
    async fn the_lifetime_is_refreshed() {
        let a = allocation().await;
        assert!(!a.expired(Instant::now()));
        assert!(a.expired(Instant::now() + Duration::from_secs(61)));
        a.refresh(Duration::from_secs(600));
        assert!(!a.expired(Instant::now() + Duration::from_secs(61)));
    }

    #[tokio::test]
    async fn a_stream_queue_holds_so_many_bytes_and_answers_always() {
        let (sink, mut source) = StreamSink::new();
        let sink = Sink::Stream(sink);
        let frame = Bytes::from(vec![0u8; 64 * 1024]);
        // Four frames of 64 KiB fill the byte budget; the fifth is dropped
        // though the frame queue has room for 256.
        for _ in 0..STREAM_QUEUE_BYTES / frame.len() {
            assert!(sink.relay(frame.clone()).await);
        }
        assert!(!sink.relay(frame.clone()).await, "the budget is spent");
        assert!(!sink.relay(Bytes::from_static(b"x")).await);
        // A reply still goes through, and comes out first.
        assert!(sink.reply(Bytes::from_static(b"reply")).await);
        assert_eq!(source.next().await.unwrap(), Bytes::from_static(b"reply"));
        // Taking a frame out makes room for another.
        assert_eq!(source.next().await.unwrap().len(), frame.len());
        assert!(sink.relay(Bytes::from_static(b"x")).await);
        // Small frames are capped by their number.
        let (sink, _source) = StreamSink::new();
        let sink = Sink::Stream(sink);
        for _ in 0..STREAM_QUEUE_FRAMES {
            assert!(sink.relay(Bytes::from_static(b"x")).await);
        }
        assert!(!sink.relay(Bytes::from_static(b"x")).await);
        if let Sink::Stream(s) = &sink {
            assert_eq!(s.queued(), STREAM_QUEUE_FRAMES, "the dropped frame is not counted");
        }
        // Gone with the source.
        let (sink, source) = StreamSink::new();
        drop(source);
        assert!(!Sink::Stream(sink).reply(Bytes::from_static(b"x")).await);
    }
}
