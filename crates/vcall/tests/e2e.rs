//! The node end to end, on loopback: a node in this process, a TURN
//! client against it over UDP, TCP and TLS, the control channel, the
//! refusals, the limits, the rooms of the SFU with participants on str0m,
//! the report to a registry, and the control socket. No server, no network.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use vcall::client::{self, ControlClient, Incoming, TurnClient};
use vcall::identity::{self, Identity, NodeId, NodeRef};
use vcall::room_client::{JoinOptions, RoomClient, RoomEvent, SfuTransport};
use vcall::turn::allocation::Transport;
use vcall::{Addrs, Config, Handle, Node};
use vcall_proto::rooms::{self, JoinRequest, LeaveRequest, MediaLimits, RoomCreated, RoomRequest, TokenChanged, TokenRequest};
use vcall_proto::{refusal, Access, Refusal, TurnCredentials};

const WAIT: Duration = Duration::from_secs(3);

struct Started {
    id: NodeId,
    addrs: Addrs,
    handle: Handle,
    _task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Started {
    fn control(&self) -> NodeRef {
        NodeRef { addr: self.addrs.control, id: self.id, sni: None }
    }

    fn turn_addr(&self, transport: Transport) -> SocketAddr {
        match transport {
            Transport::Udp => self.addrs.turn_udp,
            Transport::Tcp => self.addrs.turn_tcp,
            Transport::Tls => self.addrs.control,
        }
    }

    async fn credentials(&self, access: Access) -> Result<TurnCredentials, (u16, vcall_proto::Refusal)> {
        let mut control = ControlClient::connect(&self.control()).await.unwrap();
        control.turn(access).await.unwrap()
    }

    /// A TURN client with fresh credentials.
    async fn client(&self, transport: Transport) -> TurnClient {
        let creds = self.credentials(Access::default()).await.unwrap();
        let mut c = TurnClient::connect(self.turn_addr(transport), transport, Some(self.id)).await.unwrap();
        c.set_credentials(&creds.username, &creds.password);
        c
    }

    fn counter(&self, pick: impl Fn(&vcall::counters::Counters) -> &std::sync::atomic::AtomicU64) -> u64 {
        pick(&self.handle.counters).load(Ordering::Relaxed)
    }
}

/// The config of a node on loopback, with nothing on it that this process
/// cannot use. The relay ports are high and few: a test needs one or two.
fn config(allow_private_peers: bool) -> Config {
    let (cert, key, signer) = identity::generate_with_key().unwrap();
    Config {
        identity: Identity::from_pem(&cert, &key).unwrap(),
        signing_key: std::sync::Arc::new(signer),
        turn_secret: vcall::turn::auth::random(32),
        listen: "127.0.0.1:0".parse().unwrap(),
        turn_listen: "127.0.0.1:0".parse().unwrap(),
        sfu_listen: "127.0.0.1:0".parse().unwrap(),
        public_ip: "127.0.0.1".parse().unwrap(),
        public_port: None,
        relay_ports: 50000..=50999,
        realm: "veydan-test".into(),
        private: false,
        access_keys: Vec::new(),
        devices: None,
        issuers: Vec::new(),
        max_connections: 64,
        max_connections_per_ip: 64,
        control_idle: Duration::from_secs(60),
        max_mbps: 0,
        turn_mbps: 0,
        kbps_per_allocation: 0,
        max_allocations: 100,
        max_per_ip: 10,
        max_lifetime: Duration::from_secs(600),
        credentials_ttl: Duration::from_secs(120),
        credentials_per_ip: 100,
        max_rooms: 4,
        room_max_participants: 3,
        room_kbps_per_participant: 0,
        room_lifetime: Duration::from_secs(600),
        room_idle: Duration::from_secs(600),
        room_connect_timeout: Duration::from_secs(600),
        room_offer_timeout: Duration::from_secs(600),
        room_audio_n: vcall::sfu::DEFAULT_AUDIO_N,
        room_bwe_kbps: vcall::sfu::DEFAULT_BWE_KBPS,
        cascade: vcall::sfu::CascadeMode::On,
        cascade_seats_per_node: vcall::sfu::DEFAULT_CASCADE_SEATS_PER_NODE,
        cascade_uplinks: vcall::sfu::DEFAULT_CASCADE_UPLINKS,
        cascade_joins_per_ip: vcall::cascade::DEFAULT_CASCADE_JOINS_PER_IP,
        allow_private_peers,
        ctl: None,
    }
}

async fn start(config: Config) -> Started {
    let node = Node::bind(config).await.unwrap();
    let id = node.id();
    let addrs = node.addrs().unwrap();
    let handle = node.handle();
    let task = tokio::spawn(node.run());
    Started { id, addrs, handle, _task: task }
}

async fn relay_both_ways(node: &Started, transport: Transport) {
    let mut a = node.client(transport).await;
    let mapped = a.binding().await.unwrap();
    assert_eq!(mapped.ip(), a.local_addr().ip());

    let alloc = a.allocate(None).await.unwrap();
    assert!((50000..=50999).contains(&alloc.relayed.port()), "{}", alloc.relayed);
    assert_eq!(alloc.relayed.ip().to_string(), "127.0.0.1");
    assert_eq!(alloc.lifetime, 600);
    assert_eq!(node.handle.turn.active(), 1);

    // The peer: a plain socket.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = client::binding_from(&peer, node.addrs.turn_udp).await.unwrap();
    assert_eq!(peer_addr, peer.local_addr().unwrap());
    let mut buf = [0u8; 1500];

    // Before a permission, nothing reaches the peer, and nothing comes
    // back from it.
    a.send(peer_addr, b"too early").await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await.is_err());
    peer.send_to(b"uninvited", alloc.relayed).await.unwrap();
    assert!(a.recv(Duration::from_millis(300)).await.is_err());

    a.create_permission(&[peer_addr]).await.unwrap();
    a.send(peer_addr, b"hello peer").await.unwrap();
    let (n, from) = tokio::time::timeout(WAIT, peer.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!((&buf[..n], from), (&b"hello peer"[..], alloc.relayed));
    peer.send_to(b"hello client", alloc.relayed).await.unwrap();
    assert_eq!(a.recv(WAIT).await.unwrap(), Incoming::Data { peer: peer_addr, data: b"hello client".to_vec() });

    // A channel: four bytes of header instead of a STUN message.
    a.channel_bind(0x4000, peer_addr).await.unwrap();
    a.send_channel(0x4000, b"over the channel").await.unwrap();
    let (n, from) = tokio::time::timeout(WAIT, peer.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!((&buf[..n], from), (&b"over the channel"[..], alloc.relayed));
    peer.send_to(b"and back", alloc.relayed).await.unwrap();
    assert_eq!(a.recv(WAIT).await.unwrap(), Incoming::Channel { number: 0x4000, data: b"and back".to_vec() });
    // A channel to another peer under the same number, or the same peer
    // under another number: refused.
    assert_eq!(a.channel_bind(0x4000, "127.0.0.1:1".parse().unwrap()).await.unwrap_err().code(), Some(400));
    assert_eq!(a.channel_bind(0x4001, peer_addr).await.unwrap_err().code(), Some(400));
    assert_eq!(a.channel_bind(0x3FFF, "127.0.0.1:2".parse().unwrap()).await.unwrap_err().code(), Some(400));

    assert_eq!(a.refresh(300).await.unwrap(), 600, "never below the default");
    assert_eq!(a.refresh(0).await.unwrap(), 0);
    assert_eq!(node.handle.turn.active(), 0);
    // Gone: the next request on the same 5-tuple finds no allocation.
    assert_eq!(a.create_permission(&[peer_addr]).await.unwrap_err().code(), Some(437));
}

#[tokio::test]
async fn relays_over_udp() {
    let node = start(config(true)).await;
    relay_both_ways(&node, Transport::Udp).await;
    assert_eq!(node.counter(|c| &c.allocations), 1);
    assert_eq!(node.counter(|c| &c.allocations_ended), 1);
    assert_eq!(node.counter(|c| &c.bytes_to_peers), 10 + 16);
    assert_eq!(node.counter(|c| &c.bytes_to_clients), 12 + 8);
    assert_eq!(node.counter(|c| &c.dropped_no_permission), 2);
    assert!(node.counter(|c| &c.stun_bindings) >= 2);
}

#[tokio::test]
async fn relays_over_tcp() {
    let node = start(config(true)).await;
    relay_both_ways(&node, Transport::Tcp).await;
    assert_eq!(node.counter(|c| &c.stream_connections), 1);
}

#[tokio::test]
async fn relays_over_tls_on_the_control_port() {
    let node = start(config(true)).await;
    relay_both_ways(&node, Transport::Tls).await;
    assert_eq!(node.counter(|c| &c.stream_connections), 1);
}

/// Two clients of one node, each the other's peer at the node's own
/// address: a relay-only call between two devices on one node, as the
/// policy allows it at a live relay port. And the allocations two
/// libwebrtc clients behind one NAT make (three transports, up to three
/// interfaces each) all fit under the default quota of an address.
#[tokio::test]
async fn two_clients_of_one_node_reach_each_other_through_its_relay() {
    let mut c = config(true);
    c.max_per_ip = vcall::turn::DEFAULT_MAX_PER_IP;
    let node = start(c).await;
    let mut a = node.client(Transport::Udp).await;
    let mut b = node.client(Transport::Tcp).await;
    let alloc_a = a.allocate(None).await.unwrap();
    let alloc_b = b.allocate(None).await.unwrap();
    assert_eq!(alloc_a.relayed.ip(), alloc_b.relayed.ip(), "both relays are the node's address");
    a.create_permission(&[alloc_b.relayed]).await.unwrap();
    b.create_permission(&[alloc_a.relayed]).await.unwrap();

    // Send/Data both ways: what leaves a's relay port arrives at b's, and
    // b sees it come from a's relayed address.
    a.send(alloc_b.relayed, b"a to b").await.unwrap();
    assert_eq!(b.recv(WAIT).await.unwrap(), Incoming::Data { peer: alloc_a.relayed, data: b"a to b".to_vec() });
    b.send(alloc_a.relayed, b"b to a").await.unwrap();
    assert_eq!(a.recv(WAIT).await.unwrap(), Incoming::Data { peer: alloc_b.relayed, data: b"b to a".to_vec() });
    // ChannelData both ways.
    a.channel_bind(0x4000, alloc_b.relayed).await.unwrap();
    b.channel_bind(0x4001, alloc_a.relayed).await.unwrap();
    a.send_channel(0x4000, b"a to b, channel").await.unwrap();
    assert_eq!(b.recv(WAIT).await.unwrap(), Incoming::Channel { number: 0x4001, data: b"a to b, channel".to_vec() });
    b.send_channel(0x4001, b"b to a, channel").await.unwrap();
    assert_eq!(a.recv(WAIT).await.unwrap(), Incoming::Channel { number: 0x4000, data: b"b to a, channel".to_vec() });
    assert_eq!(node.counter(|c| &c.bytes_to_peers), 6 + 6 + 15 + 15);
    assert_eq!(node.counter(|c| &c.bytes_to_clients), 6 + 6 + 15 + 15);
    assert_eq!(node.counter(|c| &c.refused_forbidden_peer), 0);
    assert_eq!(node.counter(|c| &c.dropped_no_permission), 0);

    // Sixteen more from the same address: eighteen in all, none refused.
    let mut more = Vec::new();
    for n in 0..16 {
        let mut c = node.client(if n % 2 == 0 { Transport::Udp } else { Transport::Tls }).await;
        c.allocate(None).await.unwrap();
        more.push(c);
    }
    assert_eq!(node.handle.turn.active(), 18);
    assert_eq!(node.counter(|c| &c.refused_quota_ip), 0);
    assert_eq!(node.counter(|c| &c.allocations), 18);
}

#[tokio::test]
async fn a_closed_stream_ends_its_allocation() {
    let node = start(config(true)).await;
    let mut a = node.client(Transport::Tcp).await;
    a.allocate(None).await.unwrap();
    assert_eq!(node.handle.turn.active(), 1);
    drop(a);
    for _ in 0..50 {
        if node.handle.turn.active() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(node.handle.turn.active(), 0);
    assert_eq!(node.counter(|c| &c.allocations_ended), 1);
}

#[tokio::test]
async fn hello_says_what_the_node_is() {
    let node = start(config(false)).await;
    let mut control = ControlClient::connect(&node.control()).await.unwrap();
    let welcome = control.hello(&client::hello(Access::default(), "e2e")).await.unwrap().unwrap();
    assert_eq!(welcome.node_id, node.id.to_string());
    assert_eq!(welcome.version, vcall::VERSION);
    assert_eq!((welcome.protocol_min, welcome.protocol_max), (1, 1));
    assert!(welcome.capabilities.iter().any(|c| c == "turn-tls"));
    assert!(!welcome.private);
    assert_eq!(welcome.limits.turn_lifetime_secs, 600);
    assert_eq!(welcome.limits.credentials_ttl_secs, 120);

    let mut old = client::hello(Access::default(), "e2e");
    old.protocol_min = 5;
    old.protocol_max = 6;
    let (status, r) = control.hello(&old).await.unwrap().unwrap_err();
    assert_eq!((status, r.error.as_str()), (426, refusal::VERSION));

    let creds = control.turn(Access::default()).await.unwrap().unwrap();
    assert_eq!(creds.realm, "veydan-test");
    assert_eq!(creds.ttl_secs, 120);
    let endpoints = client::Endpoints::of(&creds.urls);
    assert_eq!(endpoints.turn_udp, Some(node.addrs.turn_udp));
    assert_eq!(endpoints.turn_tcp, Some(node.addrs.turn_tcp));
    assert_eq!(endpoints.turns, Some(node.addrs.control));

    // Something else over the control ALPN gets the page of a web server.
    let r: Result<serde_json::Value, _> = control.post("/admin", &serde_json::json!({})).await.unwrap();
    assert_eq!(r.unwrap_err().0, 404);
}

#[tokio::test]
async fn without_credentials_there_is_no_allocation() {
    let node = start(config(true)).await;
    let turn = node.turn_addr(Transport::Udp);

    let mut none = TurnClient::connect(turn, Transport::Udp, None).await.unwrap();
    assert_eq!(none.allocate(None).await.unwrap_err().code(), Some(401));
    assert_eq!(none.binding().await.unwrap().ip(), none.local_addr().ip(), "STUN needs none");

    let creds = node.credentials(Access::default()).await.unwrap();
    let mut wrong = TurnClient::connect(turn, Transport::Udp, None).await.unwrap();
    wrong.set_credentials(&creds.username, "not the password");
    assert_eq!(wrong.allocate(None).await.unwrap_err().code(), Some(401));

    let mut made_up = TurnClient::connect(turn, Transport::Udp, None).await.unwrap();
    made_up.set_credentials("alice", "secret");
    assert_eq!(made_up.allocate(None).await.unwrap_err().code(), Some(401));

    let mut expired = TurnClient::connect(turn, Transport::Udp, None).await.unwrap();
    expired.set_credentials("1000000:abcd", "whatever");
    assert_eq!(expired.allocate(None).await.unwrap_err().code(), Some(401));

    assert_eq!(node.handle.turn.active(), 0);
    assert_eq!(node.counter(|c| &c.refused_bad_credentials), 2);
    assert_eq!(node.counter(|c| &c.refused_expired_credentials), 1);

    // The right ones work, over the same socket that was refused before.
    wrong.set_credentials(&creds.username, &creds.password);
    assert!(wrong.allocate(None).await.is_ok());
}

#[tokio::test]
async fn the_inside_of_the_network_is_not_reached() {
    let node = start(config(false)).await;
    let mut a = node.client(Transport::Udp).await;
    let alloc = a.allocate(None).await.unwrap();

    let loopback: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let private: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let own: SocketAddr = SocketAddr::new(node.addrs.turn_udp.ip(), node.addrs.turn_udp.port());
    let public: SocketAddr = "9.9.9.9:5000".parse().unwrap();
    assert_eq!(a.create_permission(&[loopback]).await.unwrap_err().code(), Some(403));
    assert_eq!(a.create_permission(&[private]).await.unwrap_err().code(), Some(403));
    assert_eq!(a.create_permission(&[public, private]).await.unwrap_err().code(), Some(403), "all or none");
    assert_eq!(a.channel_bind(0x4000, "192.168.1.1:5000".parse().unwrap()).await.unwrap_err().code(), Some(403));
    assert_eq!(a.channel_bind(0x4000, own).await.unwrap_err().code(), Some(403));
    a.create_permission(&[public]).await.unwrap();
    a.channel_bind(0x4000, public).await.unwrap();
    // A Send to the inside is dropped without a word.
    a.send(loopback, b"knock").await.unwrap();
    a.send(private, b"knock").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(node.counter(|c| &c.refused_forbidden_peer), 7);
    assert_eq!(node.counter(|c| &c.bytes_to_peers), 0);
    // Nothing from the inside reaches the client either: the peer socket
    // here is on loopback.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(b"from inside", alloc.relayed).await.unwrap();
    assert!(a.recv(Duration::from_millis(300)).await.is_err());
}

#[tokio::test]
async fn so_many_allocations_per_address_and_in_all() {
    let mut c = config(true);
    c.max_per_ip = 2;
    c.max_allocations = 3;
    let node = start(c).await;
    let mut first = node.client(Transport::Udp).await;
    let mut second = node.client(Transport::Tcp).await;
    let mut third = node.client(Transport::Udp).await;
    first.allocate(None).await.unwrap();
    second.allocate(None).await.unwrap();
    assert_eq!(third.allocate(None).await.unwrap_err().code(), Some(486), "the address has its share");
    assert_eq!(node.counter(|c| &c.refused_quota_ip), 1);
    first.refresh(0).await.unwrap();
    third.allocate(None).await.unwrap();
    assert_eq!(node.handle.turn.active(), 2);
    // Allocate again on a 5-tuple that has one: 437.
    assert_eq!(third.allocate(None).await.unwrap_err().code(), Some(437));
}

#[tokio::test]
async fn bandwidth_past_the_allocation_is_dropped() {
    let mut c = config(true);
    c.kbps_per_allocation = 8; // 1000 bytes a second, 1000 of burst
    let node = start(c).await;
    let mut a = node.client(Transport::Udp).await;
    let alloc = a.allocate(None).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    a.create_permission(&[peer_addr]).await.unwrap();
    let packet = [7u8; 400];
    for _ in 0..5 {
        a.send(peer_addr, &packet).await.unwrap();
    }
    let mut got = 0;
    let mut buf = [0u8; 1500];
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await {
        got += 1;
    }
    assert_eq!(got, 2, "two of 400 fit in a burst of 1000");
    assert_eq!(node.counter(|c| &c.dropped_bandwidth), 3);
    // The other way has a burst of its own: a call sends and receives at
    // once, and the limit is per direction, not the sum of both.
    let relayed = alloc.relayed;
    for _ in 0..5 {
        peer.send_to(&packet, relayed).await.unwrap();
    }
    let mut back = 0;
    while a.recv(Duration::from_millis(300)).await.is_ok() {
        back += 1;
    }
    assert_eq!(back, 2, "two of 400 fit in the burst towards the client too");
    assert_eq!(node.counter(|c| &c.dropped_bandwidth), 6);
}

#[tokio::test]
async fn credentials_outlive_their_ttl_on_a_live_allocation() {
    let mut c = config(true);
    c.credentials_ttl = Duration::from_secs(1);
    let node = start(c).await;
    let creds = node.credentials(Access::default()).await.unwrap();
    let mut a = TurnClient::connect(node.addrs.turn_udp, Transport::Udp, None).await.unwrap();
    a.set_credentials(&creds.username, &creds.password);
    a.allocate(None).await.unwrap();
    let peer: SocketAddr = "9.9.9.9:5000".parse().unwrap();
    a.create_permission(&[peer]).await.unwrap();
    // Past the expiry of the credentials.
    for _ in 0..30 {
        if vcall::turn::unix_now() > creds.expires_at {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(vcall::turn::unix_now() > creds.expires_at);
    // The allocation goes on: its permissions are refreshed, its lifetime
    // too, a channel is bound. A call does not end with the credentials.
    a.create_permission(&[peer]).await.unwrap();
    assert_eq!(a.refresh(600).await.unwrap(), 600);
    a.channel_bind(0x4000, peer).await.unwrap();
    assert_eq!(node.counter(|c| &c.refused_expired_credentials), 0);
    // A new allocation under them: no.
    let mut b = TurnClient::connect(node.addrs.turn_udp, Transport::Udp, None).await.unwrap();
    b.set_credentials(&creds.username, &creds.password);
    assert_eq!(b.allocate(None).await.unwrap_err().code(), Some(401));
    assert_eq!(node.counter(|c| &c.refused_expired_credentials), 1);
    assert_eq!(node.handle.turn.active(), 1);
}

#[tokio::test]
async fn one_address_holds_so_many_connections() {
    let mut c = config(true);
    c.max_connections_per_ip = 2;
    let node = start(c).await;
    let turn = node.turn_addr(Transport::Tcp);
    let mut first = TurnClient::connect(turn, Transport::Tcp, None).await.unwrap();
    let mut second = TurnClient::connect(turn, Transport::Tcp, None).await.unwrap();
    first.binding().await.unwrap();
    second.binding().await.unwrap();
    // The third from the same address is closed without a word.
    let mut third = TurnClient::connect(turn, Transport::Tcp, None).await.unwrap();
    assert!(third.binding().await.is_err());
    assert_eq!(node.counter(|c| &c.stream_connections), 2);
    // Control connections share the allowance: the handshake finds the
    // connection closed.
    assert!(ControlClient::connect(&node.control()).await.is_err());
    // One gone, one more may come.
    drop(first);
    let mut again = None;
    for _ in 0..40 {
        let mut c = TurnClient::connect(turn, Transport::Tcp, None).await.unwrap();
        if c.binding().await.is_ok() {
            again = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(again.is_some(), "the place of the closed connection is free again");
}

#[tokio::test]
async fn an_idle_control_connection_is_closed() {
    let mut c = config(true);
    c.control_idle = Duration::from_millis(300);
    let node = start(c).await;
    let mut control = ControlClient::connect(&node.control()).await.unwrap();
    control.hello(&client::hello(Access::default(), "e2e")).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    control.hello(&client::hello(Access::default(), "e2e")).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(control.hello(&client::hello(Access::default(), "e2e")).await.is_err(), "closed by the node");
}

#[tokio::test]
async fn a_permission_is_for_an_address_and_port_zero_is_fine() {
    let node = start(config(false)).await;
    let mut a = node.client(Transport::Udp).await;
    a.allocate(None).await.unwrap();
    let no_port: SocketAddr = "9.9.9.9:0".parse().unwrap();
    // CreatePermission does not look at the port (RFC 8656 9.1).
    a.create_permission(&[no_port]).await.unwrap();
    // Where a packet goes, port 0 is nowhere.
    assert_eq!(a.channel_bind(0x4000, no_port).await.unwrap_err().code(), Some(403));
    a.send(no_port, b"nowhere").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(node.counter(|c| &c.refused_forbidden_peer), 2);
    assert_eq!(node.counter(|c| &c.bytes_to_peers), 0);
}

#[tokio::test]
async fn so_many_permissions_per_allocation() {
    use vcall::turn::allocation::MAX_PERMISSIONS;
    let node = start(config(false)).await;
    let mut a = node.client(Transport::Udp).await;
    a.allocate(None).await.unwrap();
    let peer = |n: u32| SocketAddr::new(std::net::Ipv4Addr::from(0x0B00_0100 + n).into(), 5000);
    let too_many: Vec<SocketAddr> = (0..MAX_PERMISSIONS as u32 + 1).map(peer).collect();
    assert_eq!(a.create_permission(&too_many).await.unwrap_err().code(), Some(508));
    let just: Vec<SocketAddr> = (0..MAX_PERMISSIONS as u32).map(peer).collect();
    a.create_permission(&just).await.unwrap();
    assert_eq!(a.create_permission(&[peer(1000)]).await.unwrap_err().code(), Some(508));
    assert_eq!(a.channel_bind(0x4000, peer(1000)).await.unwrap_err().code(), Some(508));
    a.create_permission(&just[..3]).await.unwrap();
    a.channel_bind(0x4000, peer(0)).await.unwrap();
}

#[tokio::test]
async fn an_ipv6_relay_asked_besides_gets_ipv4_and_a_word() {
    use vcall::stun::{self, attr, method, Message};
    let node = start(config(true)).await;
    let allocate = |extra: Vec<(u16, Vec<u8>)>| {
        let mut m = Message::request(method::ALLOCATE);
        m.add(attr::REQUESTED_TRANSPORT, vec![stun::TRANSPORT_UDP, 0, 0, 0]);
        for (kind, value) in extra {
            m.add(kind, value);
        }
        m
    };
    // ADDITIONAL-ADDRESS-FAMILY IPv6: the IPv4 relay, and ADDRESS-ERROR-CODE
    // 440 for the IPv6 one that is not there (RFC 8656 7.2).
    let mut a = node.client(Transport::Udp).await;
    let r = a.request(allocate(vec![(attr::ADDITIONAL_ADDRESS_FAMILY, vec![stun::FAMILY_IPV6, 0, 0, 0])])).await.unwrap();
    assert!(r.get_xor_addr(attr::XOR_RELAYED_ADDRESS).is_some_and(|a| a.is_ipv4()));
    let (family, code, _) = r.get_address_error().unwrap();
    assert_eq!((family, code), (stun::FAMILY_IPV6, 440));
    assert_eq!(node.handle.turn.active(), 1);
    // Asked for the wrong way: 400 (IPv4 besides IPv4, or both attributes).
    let mut b = node.client(Transport::Udp).await;
    let e = b.request(allocate(vec![(attr::ADDITIONAL_ADDRESS_FAMILY, vec![stun::FAMILY_IPV4, 0, 0, 0])])).await.unwrap_err();
    assert_eq!(e.code(), Some(400));
    let e = b
        .request(allocate(vec![
            (attr::REQUESTED_ADDRESS_FAMILY, vec![stun::FAMILY_IPV4, 0, 0, 0]),
            (attr::ADDITIONAL_ADDRESS_FAMILY, vec![stun::FAMILY_IPV6, 0, 0, 0]),
        ]))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some(400));
    // An IPv6 relay alone is still 440.
    let e = b.request(allocate(vec![(attr::REQUESTED_ADDRESS_FAMILY, vec![stun::FAMILY_IPV6, 0, 0, 0])])).await.unwrap_err();
    assert_eq!(e.code(), Some(440));
    // The plain one still gets its ordinary answer.
    let r = b.request(allocate(vec![])).await.unwrap();
    assert_eq!(r.get_address_error(), None);
}

#[tokio::test]
async fn many_frames_in_one_read_are_each_handled() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vcall::stun::{self, attr, method, Class, Decoded, Message};
    let node = start(config(true)).await;
    let mut tcp = tokio::net::TcpStream::connect(node.addrs.turn_tcp).await.unwrap();
    // Thousands of the smallest ChannelData frames in one write, from a
    // client with no allocation, then a Binding request split in two.
    let mut flood = Vec::with_capacity(4096 * 4 + 64);
    for _ in 0..4096 {
        flood.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]);
    }
    let binding = Message::request(method::BINDING);
    let raw = binding.encode(None, true);
    flood.extend_from_slice(&raw[..7]);
    tcp.write_all(&flood).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    tcp.write_all(&raw[7..]).await.unwrap();
    let mut answer = vec![0u8; 256];
    let n = tokio::time::timeout(WAIT, tcp.read(&mut answer)).await.unwrap().unwrap();
    let d = Decoded::parse(&answer[..n]).unwrap();
    assert_eq!((d.msg.class, d.msg.method, d.msg.txid), (Class::Success, method::BINDING, binding.txid));
    assert_eq!(d.msg.get_xor_addr(attr::XOR_MAPPED_ADDRESS), Some(tcp.local_addr().unwrap()));
    assert_eq!(node.counter(|c| &c.stun_bindings), 1);
    // Still the same connection: another request is answered too.
    let again = Message::request(method::BINDING).encode(None, true);
    tcp.write_all(&again).await.unwrap();
    let n = tokio::time::timeout(WAIT, tcp.read(&mut answer)).await.unwrap().unwrap();
    assert!(stun::is_stun(&answer[..n]));
    assert_eq!(node.counter(|c| &c.stun_bindings), 2);
}

#[tokio::test]
async fn credentials_are_counted_per_address() {
    let mut c = config(false);
    c.credentials_per_ip = 2;
    let node = start(c).await;
    node.credentials(Access::default()).await.unwrap();
    node.credentials(Access::default()).await.unwrap();
    let (status, r) = node.credentials(Access::default()).await.unwrap_err();
    assert_eq!((status, r.error.as_str()), (429, refusal::RATE_LIMITED));
    assert_eq!(node.counter(|c| &c.credentials_issued), 2);
    assert_eq!(node.counter(|c| &c.credentials_refused_rate), 1);
}

#[tokio::test]
async fn a_private_node_gives_credentials_to_key_holders_only() {
    let mut c = config(true);
    c.private = true;
    c.access_keys = vec!["first-key".into(), "second-key".into()];
    let node = start(c).await;
    let (status, r) = node.credentials(Access::default()).await.unwrap_err();
    assert_eq!((status, r.error.as_str()), (401, refusal::ACCESS_KEY_REQUIRED));
    let wrong = Access::key("third-key");
    assert_eq!(node.credentials(wrong).await.unwrap_err().1.error, refusal::ACCESS_KEY_REQUIRED);
    let right = Access::key("second-key");
    let creds = node.credentials(right).await.unwrap();
    let mut a = TurnClient::connect(node.addrs.turn_udp, Transport::Udp, None).await.unwrap();
    a.set_credentials(&creds.username, &creds.password);
    a.allocate(None).await.unwrap();

    let mut control = ControlClient::connect(&node.control()).await.unwrap();
    let welcome = control.hello(&client::hello(Access::default(), "e2e")).await.unwrap().unwrap();
    assert!(welcome.private);
    assert_eq!(node.counter(|c| &c.credentials_refused_access), 2);
}

#[tokio::test]
async fn a_private_node_without_keys_does_not_start() {
    let mut c = config(true);
    c.private = true;
    assert!(Node::bind(c).await.is_err());
}

#[tokio::test]
async fn strangers_see_a_web_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let node = start(config(false)).await;
    for alpn in [Some(&b"http/1.1"[..]), None] {
        let mut config = identity::client_config(node.id, alpn.unwrap_or(b"")).unwrap();
        if alpn.is_none() {
            config.alpn_protocols.clear();
        }
        let tcp = tokio::net::TcpStream::connect(node.addrs.control).await.unwrap();
        let name = rustls::pki_types::ServerName::IpAddress(node.addrs.control.ip().into());
        let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect(name, tcp).await.unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(WAIT, tls.read_to_end(&mut answer)).await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&answer);
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\nServer: nginx"), "{text}");
        assert!(text.contains("<center>nginx</center>"));
    }
    // The wrong certificate (another node's id) is not accepted at all.
    let other = identity::client_config(vlink_proto::BridgeId([9u8; 32]), vcall_proto::ALPN).unwrap();
    let tcp = tokio::net::TcpStream::connect(node.addrs.control).await.unwrap();
    let name = rustls::pki_types::ServerName::IpAddress(node.addrs.control.ip().into());
    assert!(tokio_rustls::TlsConnector::from(std::sync::Arc::new(other)).connect(name, tcp).await.is_err());
}

#[tokio::test]
async fn ctl_stats_show_the_counters() {
    let dir = std::env::temp_dir().join(format!("vcall-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("ctl.sock");
    let mut c = config(true);
    c.ctl = Some(socket.clone());
    let node = start(c).await;
    let mut a = node.client(Transport::Udp).await;
    a.allocate(None).await.unwrap();

    let health = vcall::ctl::call(&socket, &vcall::ctl::Request::Health).await.unwrap();
    assert!(health.ok);
    let stats = vcall::ctl::call(&socket, &vcall::ctl::Request::Stats).await.unwrap();
    assert!(stats.ok, "{:?}", stats.error);
    let stats: vcall::ctl::Stats = serde_json::from_value(stats.data.unwrap()).unwrap();
    assert_eq!(stats.allocations_now, 1);
    assert_eq!(stats.since_start.allocations, 1);
    assert_eq!(stats.since_start.credentials_issued, 1);
    assert_eq!(stats.version, vcall::VERSION);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---- rooms --------------------------------------------------------------------

const ROOM_WAIT: Duration = Duration::from_secs(10);

impl Started {
    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(&self, path: &str, body: &T) -> Result<R, (u16, Refusal)> {
        let mut control = ControlClient::connect(&self.control()).await.unwrap();
        control.post(path, body).await.unwrap()
    }

    async fn room(&self, limits: MediaLimits) -> Result<RoomCreated, (u16, Refusal)> {
        self.post(rooms::PATH_ROOMS, &RoomRequest { access: Access::default(), media_limits: limits }).await
    }

    async fn join(&self, room: &RoomCreated, token: &str, video: bool, transport: SfuTransport) -> anyhow::Result<RoomClient> {
        RoomClient::join(&self.control(), &room.room_id, token, video, transport).await
    }

    /// A join that is refused: the words of the refusal.
    async fn refused(&self, room: &RoomCreated, token: &str) -> String {
        match self.join(room, token, false, SfuTransport::Udp).await {
            Ok(_) => panic!("let in"),
            Err(e) => e.to_string(),
        }
    }

    /// A participant in, connected, its `ctl` open.
    async fn participant(&self, room: &RoomCreated, video: bool, transport: SfuTransport) -> RoomClient {
        let mut c = self.join(room, &room.join_token, video, transport).await.unwrap();
        c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.expect("connected");
        c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.expect("ctl open");
        c
    }
}

/// The m-lines `of` sends on at `at`, once the node offered them: by kind.
async fn tracks_of(at: &mut RoomClient, of: u32) -> (String, Option<String>) {
    let tracks = at
        .wait_for(ROOM_WAIT, |e| match e {
            RoomEvent::Tracks(tracks) if tracks.iter().any(|t| t.id == of && t.kind == "audio") => Some(tracks.clone()),
            _ => None,
        })
        .await
        .unwrap_or_else(|| panic!("no tracks of {of}"));
    let audio = tracks.iter().find(|t| t.id == of && t.kind == "audio").map(|t| t.mid.clone()).unwrap();
    let video = tracks.iter().find(|t| t.id == of && t.kind == "video").map(|t| t.mid.clone());
    (audio, video)
}

/// Packets on one m-line: (seq, level, payload).
type Packets = Vec<(u64, Option<i8>, Vec<u8>)>;

/// RTP packets at `c` by m-line, until each of `want` has its count or
/// the time is up.
async fn rtp_on(c: &mut RoomClient, want: &[(&str, usize)]) -> std::collections::HashMap<String, Packets> {
    let mut got: std::collections::HashMap<String, Packets> = std::collections::HashMap::new();
    let until = std::time::Instant::now() + ROOM_WAIT;
    while want.iter().any(|(mid, n)| got.get(*mid).map_or(0, Vec::len) < *n) {
        let left = until.saturating_duration_since(std::time::Instant::now());
        let Some(event) = c.next(left).await else { break };
        if let RoomEvent::Rtp { mid, seq, audio_level, payload, .. } = event {
            got.entry(mid).or_default().push((seq, audio_level, payload));
        }
    }
    got
}

#[tokio::test]
async fn two_participants_exchange_rtp_through_a_room_and_a_third_over_tcp_hears_them() {
    let node = start(config(false)).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    assert_eq!(room.room_id.len(), 32);
    assert_eq!(room.max_participants, 3);
    assert_eq!(room.sfu_udp, node.addrs.sfu.to_string());
    assert_eq!(node.handle.sfu.rooms_now(), 1);

    let mut a = node.participant(&room, true, SfuTransport::Udp).await;
    let mut b = node.participant(&room, false, SfuTransport::Udp).await;
    assert_eq!(a.participants, Vec::<u32>::new());
    assert_eq!(b.participants, vec![a.participant_id]);
    assert_eq!(node.handle.sfu.participants_now(), 2);

    // The node names the m-lines: a's audio and video at b, b's audio at a.
    let (a_audio_at_b, a_video_at_b) = tracks_of(&mut b, a.participant_id).await;
    let a_video_at_b = a_video_at_b.expect("a's video at b");
    let (b_audio_at_a, b_video_at_a) = tracks_of(&mut a, b.participant_id).await;
    assert_eq!(b_video_at_a, None, "b sends no video");
    // The answers reach the node a moment after the clients sent them.
    tokio::time::sleep(Duration::from_millis(200)).await;

    for i in 0..20u8 {
        a.send_audio(&[0xA0, i], Some(-20)).await;
        b.send_audio(&[0xB0, i], Some(-40)).await;
        a.send_video(&[0x90, i], i % 4 == 3).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut at_b_all = rtp_on(&mut b, &[(&a_audio_at_b, 20), (&a_video_at_b, 20)]).await;
    let at_b = at_b_all.remove(&a_audio_at_b).unwrap_or_default();
    assert_eq!(at_b.len(), 20, "a's audio at b");
    assert!(at_b.iter().enumerate().all(|(i, (_, level, payload))| *level == Some(-20) && payload == &[0xA0, i as u8]), "{at_b:?}");
    assert!(at_b.windows(2).all(|w| w[1].0 == w[0].0 + 1), "in order, one by one");
    assert!(at_b[0].0 < 0x4000, "sequence numbers start low: {}", at_b[0].0);
    let at_a = rtp_on(&mut a, &[(&b_audio_at_a, 20)]).await.remove(&b_audio_at_a).unwrap_or_default();
    assert_eq!(at_a.len(), 20, "b's audio at a");
    assert!(at_a.iter().all(|(_, level, payload)| *level == Some(-40) && payload[0] == 0xB0));
    let video_at_b = at_b_all.remove(&a_video_at_b).unwrap_or_default();
    assert_eq!(video_at_b.len(), 20, "a's video at b");
    assert!(video_at_b.iter().enumerate().all(|(i, (_, _, p))| p == &[0x90, i as u8]), "{video_at_b:?}");

    // Bytes over ctl: to everybody else, the sender named by the node.
    a.send_bytes(b"i am a, signed").await;
    let from = b.wait_for(ROOM_WAIT, |e| match e {
        RoomEvent::Bytes { from, data } if data == b"i am a, signed" => Some(*from),
        _ => None,
    });
    assert_eq!(from.await, Some(a.participant_id));

    // A third, over TCP: told who is here, offered both streams, hears both.
    let mut c = node.participant(&room, false, SfuTransport::Tcp(node.addrs.sfu)).await;
    assert_eq!(c.participants, vec![a.participant_id, b.participant_id]);
    let hello = c.wait_for(ROOM_WAIT, |e| match e {
        RoomEvent::Hello { you, participants } => Some((*you, participants.clone())),
        _ => None,
    });
    assert_eq!(hello.await, Some((c.participant_id, vec![a.participant_id, b.participant_id])));
    let joined = b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Joined(id) if *id == c.participant_id).then_some(()));
    assert!(joined.await.is_some(), "b hears that c joined");
    // One offer names both streams at once.
    let at_c = c.wait_for(ROOM_WAIT, |e| match e {
        RoomEvent::Tracks(tracks) if !tracks.is_empty() => Some(tracks.clone()),
        _ => None,
    });
    let at_c = at_c.await.expect("c is offered the others' streams");
    let mid_at_c = |id: u32, kind: &str| at_c.iter().find(|t| t.id == id && t.kind == kind).map(|t| t.mid.clone()).unwrap_or_else(|| panic!("no {kind} of {id} at c: {at_c:?}"));
    let a_audio_at_c = mid_at_c(a.participant_id, "audio");
    let b_audio_at_c = mid_at_c(b.participant_id, "audio");
    assert!(at_c.iter().any(|t| t.id == a.participant_id && t.kind == "video"), "a's video at c");
    let (c_audio_at_a, _) = tracks_of(&mut a, c.participant_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    for i in 0..10u8 {
        a.send_audio(&[0xA1, i], None).await;
        b.send_audio(&[0xB1, i], None).await;
        c.send_audio(&[0xC1, i], None).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut at_c = rtp_on(&mut c, &[(&a_audio_at_c, 10), (&b_audio_at_c, 10)]).await;
    let from_a = at_c.remove(&a_audio_at_c).unwrap_or_default();
    assert_eq!(from_a.len(), 10, "a's audio at c, over tcp");
    assert!(from_a.iter().all(|(_, _, p)| p[0] == 0xA1));
    assert_eq!(at_c.remove(&b_audio_at_c).unwrap_or_default().len(), 10, "b's audio at c");
    let from_c = rtp_on(&mut a, &[(&c_audio_at_a, 10)]).await.remove(&c_audio_at_a).unwrap_or_default();
    assert_eq!(from_c.len(), 10, "c's audio at a");
    assert!(from_c.iter().all(|(_, _, p)| p[0] == 0xC1));

    let counters = node.handle.counters.snapshot();
    assert_eq!(counters.rooms_created, 1);
    assert_eq!(counters.participants_joined, 3);
    assert!(counters.sfu_packets_in >= 90, "{}", counters.sfu_packets_in);
    assert!(counters.sfu_packets_out >= 120, "{}", counters.sfu_packets_out);
    assert!(counters.sfu_audio_level_packets >= 40);
    assert_eq!(counters.sfu_ctl_messages, 1);
    assert_eq!(counters.sfu_tcp_connections, 1);
    assert_eq!(counters.sfu_dropped_no_codec, 0);
    assert_eq!(counters.sfu_dropped_bandwidth, 0);
}

#[tokio::test]
async fn a_room_is_entered_with_its_token_and_the_admin_changes_it() {
    let node = start(config(false)).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let join_path = format!("{}/{}/{}", rooms::PATH_ROOMS, room.room_id, rooms::action::JOIN);
    let token_path = format!("{}/{}/{}", rooms::PATH_ROOMS, room.room_id, rooms::action::TOKEN);

    let a = node.participant(&room, false, SfuTransport::Udp).await;
    // Without the token, or with another: 403. With a token but no offer: 400.
    let e = node.refused(&room, "not-the-token").await;
    assert!(e.contains("403") && e.contains(refusal::BAD_TOKEN), "{e}");
    let bad: Result<serde_json::Value, _> =
        node.post(&join_path, &JoinRequest::new(room.join_token.clone(), "v=0", vec![])).await;
    assert_eq!(bad.unwrap_err().1.error, refusal::BAD_SDP);
    // Another room: 404.
    let nowhere: Result<serde_json::Value, _> = node
        .post(&format!("{}/{}/{}", rooms::PATH_ROOMS, "0".repeat(32), rooms::action::JOIN), &JoinRequest::new("x", "v=0", vec![]))
        .await;
    assert_eq!(nowhere.unwrap_err().1.error, refusal::ROOM_NOT_FOUND);

    // Only the admin changes the token.
    let not_admin: Result<TokenChanged, _> = node.post(&token_path, &TokenRequest { admin_token: room.join_token.clone() }).await;
    assert_eq!(not_admin.unwrap_err(), (403, Refusal::new(refusal::BAD_TOKEN, "the token is not the room's")));
    let changed: TokenChanged = node.post(&token_path, &TokenRequest { admin_token: room.admin_token.clone() }).await.unwrap();
    assert_ne!(changed.join_token, room.join_token);
    // The old token lets nobody in any more; the new one does; a stays.
    let e = node.refused(&room, &room.join_token).await;
    assert!(e.contains(refusal::BAD_TOKEN), "{e}");
    let mut b = node.join(&room, &changed.join_token, false, SfuTransport::Udp).await.unwrap();
    assert_eq!(b.participants, vec![a.participant_id]);
    assert!(b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.is_some());
    assert_eq!(node.handle.sfu.participants_now(), 2);
    assert_eq!(node.counter(|c| &c.joins_refused_token), 2);
}

#[tokio::test]
async fn a_room_has_so_many_seats_and_the_node_so_many_rooms() {
    let node = start(config(false)).await;
    // The creator may ask for fewer seats than the node gives, not more.
    let room = node.room(MediaLimits { max_participants: Some(2), kbps_per_participant: Some(500) }).await.unwrap();
    assert_eq!((room.max_participants, room.kbps_per_participant), (2, 500));
    let big = node.room(MediaLimits { max_participants: Some(100), kbps_per_participant: None }).await.unwrap();
    assert_eq!((big.max_participants, big.kbps_per_participant), (3, 0));
    let _a = node.participant(&room, false, SfuTransport::Udp).await;
    let _b = node.participant(&room, false, SfuTransport::Udp).await;
    let e = node.refused(&room, &room.join_token).await;
    assert!(e.contains("409") && e.contains(refusal::ROOM_FULL), "{e}");
    assert_eq!(node.counter(|c| &c.joins_refused_full), 1);
    // Four rooms in all on this node.
    node.room(MediaLimits::default()).await.unwrap();
    node.room(MediaLimits::default()).await.unwrap();
    let (status, r) = node.room(MediaLimits::default()).await.unwrap_err();
    assert_eq!((status, r.error.as_str()), (429, refusal::ROOMS_FULL));
    assert_eq!(node.handle.sfu.rooms_now(), 4);
    assert_eq!(node.counter(|c| &c.rooms_refused_quota), 1);
}

#[tokio::test]
async fn a_participant_leaves_by_request_or_by_closing_and_the_others_are_told() {
    let node = start(config(false)).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let leave_path = format!("{}/{}/{}", rooms::PATH_ROOMS, room.room_id, rooms::action::LEAVE);
    let a = node.participant(&room, false, SfuTransport::Udp).await;
    let mut b = node.participant(&room, false, SfuTransport::Udp).await;
    let mut c = node.participant(&room, false, SfuTransport::Udp).await;
    let (a_at_b, _) = tracks_of(&mut b, a.participant_id).await;

    // Nobody removes a participant with another's token; the admin may.
    let wrong: Result<serde_json::Value, _> =
        node.post(&leave_path, &LeaveRequest { participant_id: a.participant_id, token: b.participant_token.clone() }).await;
    assert_eq!(wrong.unwrap_err().1.error, refusal::BAD_TOKEN);
    let _: serde_json::Value =
        node.post(&leave_path, &LeaveRequest { participant_id: c.participant_id, token: room.admin_token.clone() }).await.unwrap();
    let left_c = b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Left(id) if *id == c.participant_id).then_some(()));
    assert!(left_c.await.is_some(), "b hears that c was removed");
    assert!(c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Closed).then_some(())).await.is_some(), "c's connection ends");

    // By its own request; by closing the connection.
    a.leave(&node.control(), &room.room_id).await.unwrap();
    let left_a = b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Left(id) if *id == a.participant_id).then_some(()));
    assert!(left_a.await.is_some(), "b hears that a left");
    // The m-line a's audio came on is closed at b with the next offer.
    let stopped = b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Tracks(t) if t.is_empty()).then_some(()));
    assert!(stopped.await.is_some(), "an offer that only closes a's m-line");
    assert!(!a_at_b.is_empty());
    let mut d = node.participant(&room, false, SfuTransport::Udp).await;
    assert_eq!(d.participants, vec![b.participant_id]);
    b.close().await;
    let left_b = d.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Left(id) if *id == b.participant_id).then_some(()));
    assert!(left_b.await.is_some(), "d hears that b closed");
    assert_eq!(node.handle.sfu.participants_now(), 1);
    assert_eq!(node.counter(|c| &c.participants_left), 3);
    assert_eq!(node.handle.sfu.rooms_now(), 1);
}

#[tokio::test]
async fn an_empty_room_ends_after_its_idle_time() {
    let mut c = config(false);
    c.room_idle = Duration::from_millis(500);
    let node = start(c).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    assert_eq!(room.idle_secs, 0);
    let a = node.participant(&room, false, SfuTransport::Udp).await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(node.handle.sfu.rooms_now(), 1, "not empty: it stays");
    a.leave(&node.control(), &room.room_id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(node.handle.sfu.rooms_now(), 0);
    assert_eq!(node.counter(|c| &c.rooms_ended), 1);
    let e = node.refused(&room, &room.join_token).await;
    assert!(e.contains("404") && e.contains(refusal::ROOM_NOT_FOUND), "{e}");
}

#[tokio::test]
async fn hello_names_the_sfu_and_its_limits() {
    let node = start(config(false)).await;
    let mut control = ControlClient::connect(&node.control()).await.unwrap();
    let welcome = control.hello(&client::hello(Access::default(), "e2e")).await.unwrap().unwrap();
    assert!(welcome.capabilities.iter().any(|c| c == vcall_proto::capability::SFU));
    assert!(welcome.capabilities.iter().any(|c| c == vcall_proto::capability::SIMULCAST));
    assert_eq!(welcome.codecs, vec!["opus", "vp8", "h264"]);
    assert_eq!(welcome.limits.room_max_participants, 3);
    assert_eq!(welcome.limits.room_kbps_per_participant, 0);
    assert_eq!(welcome.limits.room_lifetime_secs, 600);
    assert_eq!(welcome.limits.room_idle_secs, 600);
}

/// An offer as a client makes one, audio and so many video m-lines, with
/// no candidate in it: a participant that takes a seat and never comes.
fn bare_offer(video_lines: usize) -> String {
    use str0m::media::{Direction, MediaKind};
    vcall::sfu::init_crypto();
    let mut rtc = str0m::Rtc::builder().set_rtp_mode(true).clear_codecs().enable_opus(true, false).enable_vp8(true).build(std::time::Instant::now());
    let mut change = rtc.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendOnly, Some("me".into()), None, None);
    for _ in 0..video_lines {
        change.add_media(MediaKind::Video, Direction::SendOnly, Some("me".into()), None, None);
    }
    change.add_channel(rooms::CTL_CHANNEL.to_string());
    let (offer, _pending) = change.apply().unwrap();
    offer.to_sdp_string()
}

fn room_path(room: &RoomCreated, action: &str) -> String {
    format!("{}/{}/{action}", rooms::PATH_ROOMS, room.room_id)
}

#[tokio::test]
async fn a_seat_is_given_up_when_its_participant_never_connects() {
    let mut c = config(false);
    c.room_connect_timeout = Duration::from_millis(1500);
    let node = start(c).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let join = |offer: String| JoinRequest::new(room.join_token.clone(), offer, vec![]);
    // One that connects stays past the time.
    let a = node.participant(&room, false, SfuTransport::Udp).await;
    // Two seats taken over the control channel only, never connected to.
    let phantom: rooms::Joined = node.post(&room_path(&room, rooms::action::JOIN), &join(bare_offer(0))).await.unwrap();
    let cut: rooms::Joined = node.post(&room_path(&room, rooms::action::JOIN), &join(bare_offer(0))).await.unwrap();
    assert_eq!(node.handle.sfu.participants_now(), 3);
    // The admin takes one out at once, though it has no connection to be told over.
    let _: serde_json::Value =
        node.post(&room_path(&room, rooms::action::LEAVE), &LeaveRequest { participant_id: cut.participant_id, token: room.admin_token.clone() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(node.handle.sfu.participants_now(), 2);
    tokio::time::sleep(Duration::from_millis(1700)).await;
    assert_eq!(node.handle.sfu.participants_now(), 1, "the phantom is gone, a stays");
    assert_eq!(node.counter(|c| &c.participants_never_connected), 1);
    assert_eq!(node.counter(|c| &c.participants_left), 2);
    assert_eq!(node.handle.sfu.rooms_now(), 1);
    // The seats are free again: the room holds three.
    let _b = node.participant(&room, false, SfuTransport::Udp).await;
    let _c = node.participant(&room, false, SfuTransport::Udp).await;
    assert_eq!(node.handle.sfu.participants_now(), 3);
    assert_ne!(phantom.participant_id, a.participant_id);
}

#[tokio::test]
async fn an_offer_with_too_many_media_lines_is_refused() {
    use vcall::sfu::room::MAX_RX_TRACKS;
    let node = start(config(false)).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let join = |offer: String| JoinRequest::new(room.join_token.clone(), offer, vec![]);
    // Audio and MAX_RX_TRACKS video m-lines: one too many.
    let too_many: Result<rooms::Joined, _> = node.post(&room_path(&room, rooms::action::JOIN), &join(bare_offer(MAX_RX_TRACKS))).await;
    let (status, r) = too_many.unwrap_err();
    assert_eq!((status, r.error.as_str()), (400, refusal::BAD_SDP));
    assert!(r.message.contains(&format!("{} media lines", MAX_RX_TRACKS + 1)), "{}", r.message);
    assert_eq!(node.counter(|c| &c.joins_refused_sdp), 1);
    assert_eq!(node.handle.sfu.participants_now(), 0);
    // At the limit: in.
    let ok: rooms::Joined = node.post(&room_path(&room, rooms::action::JOIN), &join(bare_offer(MAX_RX_TRACKS - 1))).await.unwrap();
    assert_eq!(ok.participant_id, 1);
}

#[tokio::test]
async fn the_addresses_one_participant_is_routed_by_are_so_many() {
    use vcall::stun::{attr, method, Message};
    let node = start(config(false)).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let a = node.participant(&room, false, SfuTransport::Udp).await;
    assert_eq!(node.handle.sfu.routes_now(), 1);
    // STUN requests the node takes as a's, from twenty addresses: a can
    // make them (they carry its credentials), and nobody else can.
    for _ in 0..20 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut m = Message::request(method::BINDING);
        m.add_str(attr::USERNAME, &format!("{}:{}", a.node_ufrag, a.ufrag));
        m.add_u32(0x0024, 1); // PRIORITY
        m.add(0x802A, vcall::turn::auth::random(8)); // ICE-CONTROLLING
        socket.send_to(&m.encode(Some(a.node_pwd.as_bytes()), true), node.addrs.sfu).await.unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf)).await.expect("the node answers the request").unwrap();
        assert!(vcall::stun::is_stun(&buf[..n]));
    }
    assert_eq!(node.handle.sfu.routes_now(), vcall::sfu::room::MAX_ADDRS);
    assert_eq!(node.handle.sfu.participants_now(), 1, "a is still here");
}

#[tokio::test]
async fn an_unanswered_offer_is_sent_again_as_it_is_and_a_late_answer_fits() {
    let mut c = config(false);
    c.room_offer_timeout = Duration::from_millis(800);
    let node = start(c).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let a = node.participant(&room, false, SfuTransport::Udp).await;
    let mut b = node.join(&room, &room.join_token, false, SfuTransport::Udp).await.unwrap();
    b.hold_offers(true).await;
    b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.unwrap();
    let offer = |e: &RoomEvent| match e {
        RoomEvent::Offer(seq) => Some(*seq),
        _ => None,
    };
    // The first offer, and the same one again while it is not answered.
    assert_eq!(b.wait_for(ROOM_WAIT, offer).await, Some(1));
    assert_eq!(b.wait_for(ROOM_WAIT, offer).await, Some(1), "the same offer again, not another");
    assert!(node.counter(|c| &c.sfu_offers_repeated) >= 1);
    // Answered late, and twice: the first answer is taken, the second is
    // to no offer that is out.
    b.hold_offers(false).await;
    let (a_at_b, _) = tracks_of(&mut b, a.participant_id).await;
    // The next participant comes with the next offer.
    let c = node.participant(&room, false, SfuTransport::Udp).await;
    assert_eq!(b.wait_for(ROOM_WAIT, offer).await, Some(2));
    let (c_at_b, _) = tracks_of(&mut b, c.participant_id).await;
    assert_ne!(a_at_b, c_at_b);
    for _ in 0..10 {
        a.send_audio(b"from a", Some(-20)).await;
        c.send_audio(b"from c", Some(-20)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = rtp_on(&mut b, &[(&a_at_b, 3), (&c_at_b, 3)]).await;
    assert!(got.get(&a_at_b).is_some_and(|p| p.len() >= 3), "{got:?}");
    assert!(got.get(&c_at_b).is_some_and(|p| p.len() >= 3), "{got:?}");
    assert!(node.counter(|c| &c.sfu_answers_stale) >= 1);
}

#[tokio::test]
async fn many_streams_come_in_several_offers() {
    use vcall::sfu::room::OFFER_TRACKS;
    let mut c = config(false);
    c.room_max_participants = 6;
    // Six is a conversation with five speakers: the audio below goes
    // without waiting for the speakers' tick (the test is about offers).
    c.room_audio_n = 5;
    let node = start(c).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let mut first = node.participant(&room, true, SfuTransport::Udp).await;
    let mut others = Vec::new();
    for _ in 0..4 {
        others.push(node.participant(&room, true, SfuTransport::Udp).await);
    }
    let mut last = node.participant(&room, true, SfuTransport::Udp).await;
    // Ten streams of five participants for the last one: more than one
    // offer carries, so they come in more than one.
    let mut offers = 0;
    let mut streams: Vec<rooms::ctl::Track> = Vec::new();
    let until = std::time::Instant::now() + ROOM_WAIT;
    while streams.len() < 10 {
        let left = until.saturating_duration_since(std::time::Instant::now());
        let Some(event) = last.next(left).await else { break };
        if let RoomEvent::Tracks(tracks) = event {
            assert!(tracks.len() <= OFFER_TRACKS, "{tracks:?}");
            offers += 1;
            streams.extend(tracks);
        }
    }
    let distinct: std::collections::HashSet<(u32, &str)> = streams.iter().map(|t| (t.id, t.kind.as_str())).collect();
    assert_eq!(distinct.len(), 10, "{streams:?}");
    assert!(offers >= 2, "{offers} offers for 10 streams, {OFFER_TRACKS} to an offer");
    // And the first hears the last.
    let (last_at_first, _) = tracks_of(&mut first, last.participant_id).await;
    let first_at_last = streams.iter().find(|t| t.id == first.participant_id && t.kind == "audio").map(|t| t.mid.clone()).unwrap();
    for _ in 0..10 {
        last.send_audio(b"from the last", Some(-20)).await;
        first.send_audio(b"from the first", Some(-20)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = rtp_on(&mut first, &[(&last_at_first, 3)]).await;
    assert!(got.get(&last_at_first).is_some_and(|p| p.len() >= 3), "{got:?}");
    let got = rtp_on(&mut last, &[(&first_at_last, 3)]).await;
    assert!(got.get(&first_at_last).is_some_and(|p| p.len() >= 3), "{got:?}");
    assert_eq!(node.counter(|c| &c.sfu_ctl_dropped), 0);
}

#[tokio::test]
async fn a_creator_lowers_the_kbps_and_the_answer_says_it() {
    let mut c = config(false);
    c.room_kbps_per_participant = 300;
    let node = start(c).await;
    // 0 from the creator is not a way past the node's limit.
    let zero = node.room(MediaLimits { max_participants: None, kbps_per_participant: Some(0) }).await.unwrap();
    assert_eq!(zero.kbps_per_participant, 300);
    let room = node.room(MediaLimits { max_participants: None, kbps_per_participant: Some(100) }).await.unwrap();
    assert_eq!(room.kbps_per_participant, 100);
    // The answer tells the participant what the node will take on each m-line.
    let joined: rooms::Joined = node
        .post(&room_path(&room, rooms::action::JOIN), &JoinRequest::new(room.join_token.clone(), bare_offer(1), vec![]))
        .await
        .unwrap();
    let bandwidth: Vec<&str> = joined.sdp_answer.lines().filter(|l| l.starts_with("b=")).collect();
    assert_eq!(bandwidth, vec!["b=AS:100", "b=AS:50"], "{}", joined.sdp_answer);
    // A participant on str0m takes such an answer and connects.
    let _a = node.participant(&room, true, SfuTransport::Udp).await;
    assert_eq!(node.handle.sfu.participants_now(), 2);
}

// ---- simulcast and speakers --------------------------------------------------

const LAYERS: [&str; 3] = ["q", "h", "f"];

/// A VP8 payload as the node reads it: the first packet of a keyframe
/// (`key`) or of an interframe, tagged with the layer and a number.
fn vp8(key: bool, layer: u8, n: u8) -> Vec<u8> {
    vec![0x10, if key { 0x00 } else { 0x01 }, layer, n]
}

/// A participant sending video in three layers, connected, its `ctl` open.
async fn layered_sender(node: &Started, room: &RoomCreated) -> RoomClient {
    let options = JoinOptions { video: true, layers: LAYERS.iter().map(|l| l.to_string()).collect(), ..JoinOptions::default() };
    let mut c = RoomClient::join_with(&node.control(), &room.room_id, &room.join_token, options).await.unwrap();
    c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.expect("connected");
    c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.expect("ctl open");
    c
}

/// What `at` received on `mid` while `from` sent `secs` seconds of video
/// in three layers at 50 packets a second each, a keyframe every tenth:
/// (seq, timestamp, layer, number), in order of arrival. `sizes` pads
/// each layer's payload to that many bytes.
async fn stream_layers(from: &RoomClient, at: &mut RoomClient, mid: &str, secs: f64, n: &mut u8, sizes: [usize; 3]) -> Vec<(u64, u32, u8, u8)> {
    let mut got = Vec::new();
    let packets = (secs * 50.0) as usize;
    for _ in 0..packets {
        for (layer, size) in sizes.iter().enumerate() {
            let mut payload = vp8(n.is_multiple_of(10), layer as u8, *n);
            payload.resize((*size).max(payload.len()), 0xEE);
            from.send_video_layer(layer, &payload, true).await;
        }
        *n = n.wrapping_add(1);
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Some(event) = at.next(Duration::ZERO).await {
            if let RoomEvent::Rtp { mid: m, seq, timestamp, payload, .. } = event {
                if m == mid {
                    got.push((seq, timestamp, payload[2], payload[3]));
                }
            }
        }
    }
    got
}

/// The layers of `got`, one entry per run: `[2, 0]` for f then q.
fn runs(got: &[(u64, u32, u8, u8)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for (_, _, layer, _) in got {
        if out.last() != Some(layer) {
            out.push(*layer);
        }
    }
    out
}

/// Sequence numbers one by one, timestamps never back, across everything.
fn assert_contiguous(got: &[(u64, u32, u8, u8)]) {
    for w in got.windows(2) {
        assert_eq!(w[1].0, w[0].0 + 1, "a gap in the sequence numbers at {:?} -> {:?}", w[0], w[1]);
        assert!(w[1].1.wrapping_sub(w[0].1) < 1 << 31, "the timestamp went back at {:?} -> {:?}", w[0], w[1]);
    }
}

#[tokio::test]
async fn a_receiver_gets_the_layer_it_asks_for_and_switches_at_a_keyframe() {
    let node = start(config(false)).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let a = layered_sender(&node, &room).await;
    let mut b = node.participant(&room, false, SfuTransport::Udp).await;
    // The offer names the layers of a's video.
    let video = b
        .wait_for(ROOM_WAIT, |e| match e {
            RoomEvent::Tracks(t) => t.iter().find(|t| t.id == a.participant_id && t.kind == "video").cloned(),
            _ => None,
        })
        .await
        .expect("a's video at b");
    assert_eq!(video.rids, LAYERS);
    let a_video_at_b = video.mid;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut n = 0u8;
    let sizes = [4, 4, 4];

    // Nothing asked for: the top layer, once the rates are measured and
    // the estimate has room (a stream starts low and climbs).
    let got = stream_layers(&a, &mut b, &a_video_at_b, 6.0, &mut n, sizes).await;
    assert!(!got.is_empty(), "nothing of a's video reached b");
    let seen = runs(&got);
    assert!(seen.windows(2).all(|w| w[1] > w[0]), "only upwards: {seen:?}");
    assert_eq!(seen.last(), Some(&2), "the top layer at the end: {seen:?}");
    assert_eq!(got[0].3 % 10, 0, "the first packet forwarded is a keyframe: {:?}", got[0]);
    assert_contiguous(&got);
    // Every packet of the layer came, once it was chosen: a's number counts up by one.
    let tail: Vec<u8> = got.iter().rev().take_while(|(_, _, l, _)| *l == 2).map(|(_, _, _, n)| *n).collect();
    assert!(tail.windows(2).all(|w| w[0] == w[1].wrapping_add(1)), "{tail:?}");

    // Asked for q: forwarded from its next keyframe on, the numbers
    // continuing; f never again.
    b.request_layer(a.participant_id, Some("q")).await;
    let got = stream_layers(&a, &mut b, &a_video_at_b, 1.5, &mut n, sizes).await;
    let seen = runs(&got);
    assert!(seen == [0] || seen == [2, 0], "f, then q from a keyframe: {seen:?}");
    let first_q = got.iter().find(|(_, _, l, _)| *l == 0).expect("q came");
    assert_eq!(first_q.3 % 10, 0, "the switch is at a keyframe: {first_q:?}");
    assert_contiguous(&got);

    // Asked for h: the middle one, after the hold.
    b.request_layer(a.participant_id, Some("h")).await;
    let got = stream_layers(&a, &mut b, &a_video_at_b, 4.5, &mut n, sizes).await;
    assert_eq!(runs(&got).last(), Some(&1), "{:?}", runs(&got));
    assert_contiguous(&got);
    // Nothing asked for (a rid the origin does not send is the same): the top one.
    b.request_layer(a.participant_id, Some("xl")).await;
    let got = stream_layers(&a, &mut b, &a_video_at_b, 4.5, &mut n, sizes).await;
    assert_eq!(runs(&got).last(), Some(&2), "{:?}", runs(&got));
    assert_contiguous(&got);

    let counters = node.handle.counters.snapshot();
    assert_eq!(counters.sfu_layer_requests, 3);
    assert!(counters.sfu_layer_switches >= 3, "{}", counters.sfu_layer_switches);
    assert!(counters.sfu_keyframe_requests >= 3, "{}", counters.sfu_keyframe_requests);
    assert_eq!(counters.sfu_dropped_no_codec, 0);
}

#[tokio::test]
async fn the_layer_follows_the_receivers_bandwidth() {
    // The node assumes little at first: the lowest layer fits it, the
    // others do not. The estimate climbs from there by probing, and the
    // layers with it.
    let mut c = config(false);
    c.room_bwe_kbps = 100;
    let node = start(c).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let a = layered_sender(&node, &room).await;
    let mut b = node.participant(&room, false, SfuTransport::Udp).await;
    let (_, a_video_at_b) = tracks_of(&mut b, a.participant_id).await;
    let a_video_at_b = a_video_at_b.expect("a's video at b");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut n = 0u8;
    // 50 packets a second of these: about 50, 200 and 400 kbit/s.
    let sizes = [125, 500, 1000];
    let got = stream_layers(&a, &mut b, &a_video_at_b, 3.0, &mut n, sizes).await;
    assert_eq!(runs(&got), vec![0], "the lowest layer alone under a small estimate: {:?}", runs(&got));
    assert_contiguous(&got);
    let got = stream_layers(&a, &mut b, &a_video_at_b, 12.0, &mut n, sizes).await;
    let seen = runs(&got);
    assert!(seen.last().is_some_and(|l| *l >= 1), "the estimate grew and a higher layer with it: {seen:?}");
    assert_contiguous(&got);
    assert_eq!(node.counter(|c| &c.sfu_layer_requests), 0, "nobody asked: the bandwidth chose");
}

/// Audio of `from` at `at`: how many packets came on each m-line, and
/// the last `speaking` list, while everybody in `senders` sent `secs`
/// seconds of audio at the given level (`None` sends nothing).
async fn stream_audio(senders: &[(&RoomClient, Option<i8>)], at: &mut RoomClient, secs: f64) -> (std::collections::HashMap<String, (usize, u64, u64)>, Option<Vec<u32>>) {
    let mut got: std::collections::HashMap<String, (usize, u64, u64)> = std::collections::HashMap::new();
    let mut speaking = None;
    let packets = (secs * 50.0) as usize;
    for i in 0..packets {
        for (sender, level) in senders {
            if let Some(level) = level {
                sender.send_audio(&[0xAA, i as u8], Some(*level)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Some(event) = at.next(Duration::ZERO).await {
            match event {
                RoomEvent::Rtp { mid, seq, .. } => {
                    let entry = got.entry(mid).or_insert((0, seq, seq));
                    entry.0 += 1;
                    entry.2 = seq;
                }
                RoomEvent::Speaking(list) => speaking = Some(list),
                _ => {}
            }
        }
    }
    (got, speaking)
}

#[tokio::test]
async fn the_loud_ones_are_forwarded_and_named() {
    let mut c = config(false);
    c.room_max_participants = 5;
    c.room_audio_n = 3;
    let node = start(c).await;
    let room = node.room(MediaLimits::default()).await.unwrap();
    let a = node.participant(&room, false, SfuTransport::Udp).await;
    let b = node.participant(&room, false, SfuTransport::Udp).await;
    let c = node.participant(&room, false, SfuTransport::Udp).await;
    let mut d = node.participant(&room, false, SfuTransport::Udp).await;
    let e = node.participant(&room, false, SfuTransport::Udp).await;
    // d's m-lines for the others' audio, as the offers name them.
    let mut mid_of: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let until = std::time::Instant::now() + ROOM_WAIT;
    while mid_of.len() < 4 {
        let left = until.saturating_duration_since(std::time::Instant::now());
        let Some(event) = d.next(left).await else { break };
        if let RoomEvent::Tracks(tracks) = event {
            for t in tracks.iter().filter(|t| t.kind == "audio") {
                mid_of.insert(t.id, t.mid.clone());
            }
        }
    }
    assert_eq!(mid_of.len(), 4, "{mid_of:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Three loud, one quiet (below the talking level), one silent: the
    // three loud are the speakers, loudest first, and only their audio
    // reaches d.
    let senders = [(&a, Some(-10)), (&b, Some(-20)), (&c, Some(-30)), (&e, Some(-60))];
    let (got, speaking) = stream_audio(&senders, &mut d, 3.0).await;
    assert_eq!(speaking, Some(vec![a.participant_id, b.participant_id, c.participant_id]));
    for who in [&a, &b, &c] {
        let (count, first, last) = got.get(&mid_of[&who.participant_id]).copied().unwrap_or_default();
        assert!(count >= 100, "{} packets of {}", count, who.participant_id);
        assert_eq!(last - first + 1, count as u64, "no gaps from {}", who.participant_id);
    }
    assert_eq!(got.get(&mid_of[&e.participant_id]), None, "nothing of the quiet one");

    // e speaks up, a falls silent: e takes a place; b and c keep theirs.
    let senders = [(&a, None), (&b, Some(-20)), (&c, Some(-30)), (&e, Some(-5))];
    let (got, speaking) = stream_audio(&senders, &mut d, 3.0).await;
    assert_eq!(speaking, Some(vec![e.participant_id, b.participant_id, c.participant_id]));
    let (count, first, last) = got.get(&mid_of[&e.participant_id]).copied().unwrap_or_default();
    assert!(count >= 80, "{count} packets of e");
    assert_eq!(last - first + 1, count as u64, "no gaps from e once it is forwarded");
    assert_eq!(got.get(&mid_of[&a.participant_id]), None, "a sent nothing");
    let counters = node.handle.counters.snapshot();
    assert!(counters.sfu_speaking_changes >= 2, "{}", counters.sfu_speaking_changes);
    assert!(counters.sfu_audio_level_packets >= 400);
}

// ---- the registry -----------------------------------------------------------

/// A registry of one request: what it got, and `answer` back.
async fn fake_registry(answer: &'static str) -> (String, tokio::sync::oneshot::Receiver<(String, Vec<u8>)>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/vlink", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            raw.extend_from_slice(&buf[..n]);
            let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
            let head = String::from_utf8_lossy(&raw[..at]).to_string();
            let length: usize = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
            if raw.len() >= at + 4 + length {
                let body = raw[at + 4..at + 4 + length].to_vec();
                let _ = tx.send((head, body));
                break;
            }
        }
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len());
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    (url, rx)
}

#[tokio::test]
async fn the_node_reports_to_the_registry_under_its_key() {
    use vcall_proto::register::Registration;
    let dir = std::env::temp_dir().join(format!("vcall-e2e-registry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let identity = identity::load_or_create(&dir).unwrap();
    let id = identity::node_id(&identity).unwrap();
    let key = identity::signing_key(&dir).unwrap();
    let mut c = config(false);
    c.identity = identity;
    let node = start(c).await;
    let mut a = node.client(Transport::Udp).await;
    a.allocate(None).await.unwrap();

    let (registry, got) = fake_registry(r#"{"state":"new","addr":"203.0.113.7:8443"}"#).await;
    let registrar = vcall::register::Registrar {
        registry,
        id: id.to_string(),
        key,
        public_ip: "203.0.113.7".parse().unwrap(),
        control_port: 8443,
        turn_port: 3478,
        sfu_port: 3479,
        region: "eu".into(),
        caps: vec!["stun".into(), "turn".into(), "sfu".into()],
        max_allocations: 1000,
        max_participants: 768,
        max_mbps: 100,
        max_rooms: 64,
        max_uplinks: 256,
        handle: node.handle.clone(),
    };
    let answer = registrar.report().await.unwrap();
    assert!(answer.is_new());
    assert_eq!(answer.addr.to_string(), "203.0.113.7:8443");

    let (head, body) = got.await.unwrap();
    assert!(head.starts_with("POST /vlink/v1/calls/register HTTP/1.1\r\n"), "{head}");
    assert!(body.starts_with(b"{\"v\":2,"), "the second form, with the rooms and uplinks under the signature");
    let report: Registration = serde_json::from_slice(&body).unwrap();
    assert_eq!(report.verify(vcall::turn::unix_now(), 300), Ok(()));
    assert_eq!(report.well_formed(), Ok(()));
    assert_eq!(report.v, vcall_proto::register::REGISTRATION_VERSION);
    assert_eq!(report.id, id.to_string());
    assert_eq!(report.ip, Some("203.0.113.7".parse().unwrap()));
    assert_eq!((report.control_port, report.turn_port, report.sfu_port), (8443, 3478, 3479));
    assert_eq!(report.version, vcall::VERSION);
    assert_eq!(report.caps, vec!["stun", "turn", "sfu"]);
    assert_eq!((report.load.allocations, report.load.max_allocations), (1, 1000));
    assert_eq!((report.load.participants, report.load.max_participants), (0, 768));
    assert_eq!(report.load.max_mbps, 100);
    assert_eq!((report.load.rooms, report.load.max_rooms, report.load.uplinks, report.load.max_uplinks), (0, 64, 0, 256));
    // The id is the one a client pins: what the hub computes from the key
    // is what the chain says.
    assert_eq!(vlink_proto::BridgeId::of_ed25519(&vcall_proto::register::unhex(&report.key).unwrap().try_into().unwrap()), id);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---- the cascade -------------------------------------------------------------

use vcall_proto::rooms::{Delegated, DelegateRequest, UplinkWord};

impl Started {
    /// As if the node's process died: nothing is said to anybody, nothing
    /// answers any more.
    fn stop(&self) {
        self.handle.sfu.vanish();
        self._task.abort();
    }

    /// A pass for a proxy seat in `room`, by its join token.
    async fn delegate(&self, room: &RoomCreated, token: &str) -> Result<Delegated, (u16, Refusal)> {
        self.post(&room_path(room, rooms::action::DELEGATE), &DelegateRequest { token: token.to_string() }).await
    }

    /// A join through this node into `room` at `home`, with a pass of
    /// the home: in, or the refusal.
    async fn join_via(&self, home: &Started, room: &RoomCreated, options: JoinOptions) -> Result<RoomClient, (u16, Refusal)> {
        let pass = home.delegate(room, &room.join_token).await.expect("a pass");
        let options = JoinOptions { home: Some(home.control()), ..options };
        RoomClient::try_join_with(&self.control(), &room.room_id, &pass.proxy_token, options).await.expect("the node answered")
    }

    /// Joined through this node, connected, `ctl` open.
    async fn via(&self, home: &Started, room: &RoomCreated, options: JoinOptions) -> RoomClient {
        let mut c = self.join_via(home, room, options).await.unwrap_or_else(|(status, r)| panic!("refused: {status} {} {}", r.error, r.message));
        c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.expect("connected");
        c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.expect("ctl open");
        c
    }
}

fn video_options() -> JoinOptions {
    JoinOptions { video: true, ..JoinOptions::default() }
}

/// A node whose signing key is not the key of its id: its word holds
/// nowhere.
fn config_with_a_wrong_key() -> Config {
    let mut c = config(true);
    let (_, _, stranger) = identity::generate_with_key().unwrap();
    c.signing_key = std::sync::Arc::new(stranger);
    c
}

#[tokio::test]
async fn a_pass_is_one_time_and_only_for_the_word_of_a_node() {
    let home = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let (_, _, key) = identity::generate_with_key().unwrap();
    let word = |pass: &str| UplinkWord::sign(&key, &home.id.to_string(), &room.room_id, pass, vcall::turn::unix_now());
    let with_word = |token: &str, word: UplinkWord| {
        let mut r = JoinRequest::new(token, bare_offer(0), vec![]);
        r.uplink = Some(word);
        r
    };
    let join_path = room_path(&room, rooms::action::JOIN);

    // A pass comes by the join token, for this room.
    assert_eq!(home.delegate(&room, "not-the-token").await.unwrap_err().1.error, refusal::BAD_TOKEN);
    let elsewhere = RoomCreated { room_id: "0".repeat(32), ..room.clone() };
    assert_eq!(home.delegate(&elsewhere, &room.join_token).await.unwrap_err().1.error, refusal::ROOM_NOT_FOUND);
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    assert_eq!(pass.proxy_token.len(), 48);
    let now = vcall::turn::unix_now();
    assert!((now + 55..=now + 65).contains(&pass.expires_at), "{}", pass.expires_at);
    assert_eq!(home.counter(|c| &c.cascade_passes_issued), 1);

    // The word with the join token instead of a pass: not a way in. A pass
    // without a word: not one either.
    let r: Result<rooms::Joined, _> = home.post(&join_path, &with_word(&room.join_token, word(&pass.proxy_token))).await;
    assert_eq!(r.unwrap_err(), (403, Refusal::new(refusal::BAD_TOKEN, "the token is not the room's")));
    let r: Result<rooms::Joined, _> = home.post(&join_path, &JoinRequest::new(pass.proxy_token.clone(), bare_offer(0), vec![])).await;
    assert_eq!(r.unwrap_err().1.error, refusal::BAD_TOKEN);
    // A word for another home, or another pass: 400, and the pass stays.
    let other = UplinkWord::sign(&key, &"ab".repeat(32), &room.room_id, &pass.proxy_token, vcall::turn::unix_now());
    let r: Result<rooms::Joined, _> = home.post(&join_path, &with_word(&pass.proxy_token, other)).await;
    assert_eq!(r.unwrap_err().0, 400);
    let r: Result<rooms::Joined, _> = home.post(&join_path, &with_word(&pass.proxy_token, word("another pass"))).await;
    assert_eq!(r.unwrap_err().1.error, refusal::BAD_REQUEST);
    let mut old = word(&pass.proxy_token);
    old.ts -= 1000;
    let r: Result<rooms::Joined, _> = home.post(&join_path, &with_word(&pass.proxy_token, old)).await;
    assert_eq!(r.unwrap_err().1.error, refusal::BAD_REQUEST);
    // The right word: a seat of the node; the pass is burnt with it.
    let joined: rooms::Joined = home.post(&join_path, &with_word(&pass.proxy_token, word(&pass.proxy_token))).await.unwrap();
    assert_eq!(joined.participant_id, 1);
    assert_eq!(joined.home_token, None, "a home token is the satellite's word, not the home's");
    assert_eq!(home.handle.sfu.proxy_seats_now(), 1);
    assert_eq!(home.handle.sfu.participants_now(), 1);
    assert_eq!(home.counter(|c| &c.cascade_seats_joined), 1);
    let r: Result<rooms::Joined, _> = home.post(&join_path, &with_word(&pass.proxy_token, word(&pass.proxy_token))).await;
    assert_eq!(r.unwrap_err().1.error, refusal::BAD_TOKEN, "a pass is one-time");
    assert_eq!(home.counter(|c| &c.joins_refused_token), 4);
    // So many passes alive at once: the oldest makes room.
    let mut passes = Vec::new();
    for _ in 0..(vcall::sfu::DELEGATE_PER_SEAT * room.max_participants as usize + 1) {
        passes.push(home.delegate(&room, &room.join_token).await.unwrap().proxy_token);
    }
    let r: Result<rooms::Joined, _> = home.post(&join_path, &with_word(&passes[0], word(&passes[0]))).await;
    assert_eq!(r.unwrap_err().1.error, refusal::BAD_TOKEN, "the oldest pass was pushed out");
    let last = passes.last().unwrap();
    let joined: rooms::Joined = home.post(&join_path, &with_word(last, word(last))).await.unwrap();
    assert_eq!(joined.participant_id, 2);

    // A home with the cascade off takes no word, and says so in WELCOME;
    // one with a quota of one seat a node refuses the second.
    let mut off = config(true);
    off.cascade = vcall::sfu::CascadeMode::Off;
    let off = start(off).await;
    let mut control = ControlClient::connect(&off.control()).await.unwrap();
    let welcome = control.hello(&client::hello(Access::default(), "e2e")).await.unwrap().unwrap();
    assert!(!welcome.capabilities.iter().any(|c| c == "cascade"), "{:?}", welcome.capabilities);
    let room_off = off.room(MediaLimits::default()).await.unwrap();
    let pass = off.delegate(&room_off, &room_off.join_token).await.unwrap();
    let word_off = UplinkWord::sign(&key, &off.id.to_string(), &room_off.room_id, &pass.proxy_token, vcall::turn::unix_now());
    let r: Result<rooms::Joined, _> = off.post(&room_path(&room_off, rooms::action::JOIN), &with_word(&pass.proxy_token, word_off)).await;
    assert_eq!(r.unwrap_err(), (403, Refusal::new(refusal::CASCADE_REFUSED, "this node takes no seats of that node")));
    assert_eq!(off.counter(|c| &c.cascade_joins_refused_list), 1);
    let mut one = config(true);
    one.cascade_seats_per_node = 1;
    let one = start(one).await;
    let room_one = one.room(MediaLimits::default()).await.unwrap();
    for n in 0..2 {
        let pass = one.delegate(&room_one, &room_one.join_token).await.unwrap();
        let w = UplinkWord::sign(&key, &one.id.to_string(), &room_one.room_id, &pass.proxy_token, vcall::turn::unix_now());
        let r: Result<rooms::Joined, _> = one.post(&room_path(&room_one, rooms::action::JOIN), &with_word(&pass.proxy_token, w)).await;
        match n {
            0 => assert_eq!(r.unwrap().participant_id, 1),
            _ => assert_eq!(r.unwrap_err().1.error, refusal::CASCADE_REFUSED),
        }
    }
    assert_eq!(one.counter(|c| &c.cascade_joins_refused_quota), 1);
}

#[tokio::test]
async fn participants_on_two_nodes_meet_through_the_cascade() {
    let home = start(config(true)).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let mut a = layered_sender(&home, &room).await;
    let mut b = own.via(&home, &room, JoinOptions::default()).await;
    let mut c = own.via(&home, &room, video_options()).await;
    // One numbering over the room, and the home token of the proxy seat.
    assert_eq!((a.participant_id, b.participant_id, c.participant_id), (1, 2, 3));
    assert_eq!(b.participants, vec![1]);
    assert_eq!(c.participants, vec![1, 2]);
    assert!(b.home_token.is_some());
    assert_eq!(home.handle.sfu.participants_now(), 3);
    assert_eq!(home.handle.sfu.proxy_seats_now(), 2);
    assert_eq!(own.handle.sfu.participants_now(), 2);
    assert_eq!(own.handle.sfu.satellites_now(), 1);
    assert_eq!(own.handle.sfu.uplinks_now(), 2);
    assert_eq!(own.handle.sfu.rooms_now(), 0);
    assert_eq!(own.counter(|c| &c.cascade_uplinks_made), 2);
    // The roster: c's hello, b hears of c.
    let hello = c.wait_for(ROOM_WAIT, |e| match e {
        RoomEvent::Hello { you, participants } => Some((*you, participants.clone())),
        _ => None,
    });
    assert_eq!(hello.await, Some((3, vec![1, 2])));
    // The room's id is a satellite's here: not a room of this node.
    let e = own.refused(&room, &room.join_token).await;
    assert!(e.contains("404") && e.contains(refusal::ROOM_NOT_FOUND), "{e}");

    // The streams: a's at b and c (down the uplinks, named as the home
    // names them, with a's layers), c's at b (within the node), b's and
    // c's at a (up the uplinks).
    let (a_audio_at_b, a_video_at_b) = tracks_of(&mut b, 1).await;
    let a_video_at_b = a_video_at_b.expect("a's video at b");
    assert!(b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Joined(3)).then_some(())).await.is_some(), "b hears that c joined");
    let (c_audio_at_b, c_video_at_b) = tracks_of(&mut b, 3).await;
    let c_video_at_b = c_video_at_b.expect("c's video at b");
    // One offer may name both: collected until both are in.
    let at_c = tracks_until(&mut c, &[1, 2]).await;
    let a_audio_at_c = at_c[&(1, "audio".to_string())].clone();
    let b_audio_at_c = at_c[&(2, "audio".to_string())].clone();
    let (b_audio_at_a, _) = tracks_of(&mut a, 2).await;
    assert!(a.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Joined(3)).then_some(())).await.is_some(), "a hears that c joined");
    let (c_audio_at_a, c_video_at_a) = tracks_of(&mut a, 3).await;
    assert!(c_video_at_a.is_some(), "c's video at a");
    tokio::time::sleep(Duration::from_millis(300)).await;
    for i in 0..20u8 {
        a.send_audio(&[0xA0, i], Some(-20)).await;
        b.send_audio(&[0xB0, i], Some(-30)).await;
        c.send_audio(&[0xC0, i], Some(-40)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let at_b = rtp_on(&mut b, &[(&a_audio_at_b, 20), (&c_audio_at_b, 20)]).await;
    let from_a = at_b.get(&a_audio_at_b).cloned().unwrap_or_default();
    assert_eq!(from_a.len(), 20, "a's audio at b, down the uplink: {}", from_a.len());
    assert!(from_a.iter().enumerate().all(|(i, (_, level, p))| *level == Some(-20) && p == &[0xA0, i as u8]), "{from_a:?}");
    assert!(from_a.windows(2).all(|w| w[1].0 == w[0].0 + 1), "in order");
    assert_eq!(at_b.get(&c_audio_at_b).map_or(0, Vec::len), 20, "c's audio at b, within the node");
    let at_c = rtp_on(&mut c, &[(&a_audio_at_c, 20), (&b_audio_at_c, 20)]).await;
    assert_eq!(at_c.get(&a_audio_at_c).map_or(0, Vec::len), 20, "a's audio at c");
    assert_eq!(at_c.get(&b_audio_at_c).map_or(0, Vec::len), 20, "b's audio at c");
    let at_a = rtp_on(&mut a, &[(&b_audio_at_a, 20), (&c_audio_at_a, 20)]).await;
    let from_b = at_a.get(&b_audio_at_a).cloned().unwrap_or_default();
    assert_eq!(from_b.len(), 20, "b's audio at a, up the uplink");
    assert!(from_b.iter().all(|(_, level, p)| *level == Some(-30) && p[0] == 0xB0), "{from_b:?}");
    assert_eq!(at_a.get(&c_audio_at_a).map_or(0, Vec::len), 20, "c's audio at a");
    // The speakers are the home's: a talks on alone, and b is told the
    // list as the home makes it.
    let mut speaking = None;
    'talk: for _ in 0..150 {
        a.send_audio(&[0xA1, 0], Some(-20)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Some(e) = b.next(Duration::ZERO).await {
            if let RoomEvent::Speaking(list) = e {
                if list == vec![1] {
                    speaking = Some(list);
                    break 'talk;
                }
            }
        }
    }
    assert_eq!(speaking, Some(vec![1]), "a alone is the speaker, as the home says");
    assert!(own.counter(|c| &c.sfu_speaking_changes) >= 1);

    // a's video in layers, down the uplink to b: the layer b asks for is
    // asked of the home; a layer of c, within the node, is planned here.
    let mut n = 0u8;
    let got = stream_layers(&a, &mut b, &a_video_at_b, 3.0, &mut n, [4, 4, 4]).await;
    assert!(!got.is_empty(), "a's video reached b");
    assert_contiguous(&got);
    b.request_layer(1, Some("q")).await;
    b.request_layer(3, Some("q")).await;
    let got = stream_layers(&a, &mut b, &a_video_at_b, 2.0, &mut n, [4, 4, 4]).await;
    assert_eq!(runs(&got).last(), Some(&0), "q as asked, from the home: {:?}", runs(&got));
    assert_contiguous(&got);
    assert_eq!(home.counter(|c| &c.sfu_layer_requests), 1, "the ask for a's layer went to the home");
    assert_eq!(own.counter(|c| &c.sfu_layer_requests), 1, "the ask for c's layer stayed here");
    assert!(own.counter(|c| &c.cascade_bytes_down) > 0 && own.counter(|c| &c.cascade_bytes_up) > 0);
    // c's video reaches b within the node, and a up the uplink.
    for i in 0..10u8 {
        c.send_video(&[0x90, i, 0, 0], i % 5 == 4).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(rtp_on(&mut b, &[(&c_video_at_b, 5)]).await.get(&c_video_at_b).is_some_and(|p| p.len() >= 5));
    let c_video_at_a = c_video_at_a.unwrap();
    assert!(rtp_on(&mut a, &[(&c_video_at_a, 5)]).await.get(&c_video_at_a).is_some_and(|p| p.len() >= 5));

    // Bytes: everybody gets a's once, b's once (c within the node, a up
    // the uplink), and the home never sees b's bytes twice.
    a.send_bytes(b"from a").await;
    b.send_bytes(b"from b").await;
    async fn bytes_at(c: &mut RoomClient) -> Vec<(u32, Vec<u8>)> {
        let mut got = Vec::new();
        while let Some(e) = c.next(Duration::from_millis(800)).await {
            if let RoomEvent::Bytes { from, data } = e {
                got.push((from, data));
            }
        }
        got.sort();
        got
    }
    assert_eq!(bytes_at(&mut c).await, vec![(1, b"from a".to_vec()), (2, b"from b".to_vec())]);
    assert_eq!(bytes_at(&mut a).await, vec![(2, b"from b".to_vec())]);
    assert_eq!(bytes_at(&mut b).await, vec![(1, b"from a".to_vec())]);
    assert_eq!(home.counter(|c| &c.sfu_ctl_messages), 2, "a's frame, and b's once up the uplink");

    // b gives its proxy seat up at the home itself, with the home token:
    // the home tells a, the satellite closes b.
    b.leave_home(&home.control(), &room.room_id).await.unwrap();
    assert!(a.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Left(2)).then_some(())).await.is_some(), "a hears that b left");
    assert!(b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Closed).then_some(())).await.is_some(), "b is closed by its node");
    assert!(c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Left(2)).then_some(())).await.is_some(), "c hears that b left");
    assert_eq!(home.handle.sfu.proxy_seats_now(), 1);
    assert_eq!(own.handle.sfu.uplinks_now(), 1);
    // The admin takes c out at the home: c's connection ends; the last
    // seat gone, the satellite ends.
    let _: serde_json::Value = home.post(&room_path(&room, rooms::action::LEAVE), &LeaveRequest { participant_id: 3, token: room.admin_token.clone() }).await.unwrap();
    assert!(c.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Closed).then_some(())).await.is_some(), "c is closed");
    assert!(a.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Left(3)).then_some(())).await.is_some());
    for _ in 0..40 {
        if own.handle.sfu.satellites_now() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(own.handle.sfu.satellites_now(), 0, "the satellite ended with its last seat");
    assert_eq!(own.handle.sfu.uplinks_now(), 0);
    assert_eq!(own.handle.sfu.participants_now(), 0);
    assert_eq!(home.handle.sfu.participants_now(), 1);
    assert_eq!(home.counter(|c| &c.cascade_seats_reaped), 0, "nobody fell silent");
    assert_eq!(own.counter(|c| &c.satellites_ended), 1);
}

#[tokio::test]
async fn a_home_that_dies_is_lost_to_its_satellites_within_six_seconds() {
    let home = start(config(true)).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let _a = home.participant(&room, false, SfuTransport::Udp).await;
    let mut b = own.via(&home, &room, JoinOptions::default()).await;
    let mut c = own.via(&home, &room, JoinOptions::default()).await;
    // A second room of the home with a seat here: a second satellite.
    let other = home.room(MediaLimits::default()).await.unwrap();
    let mut d = own.via(&home, &other, JoinOptions::default()).await;
    tracks_of(&mut b, 1).await;
    assert_eq!(own.handle.sfu.satellites_now(), 2);
    let t = std::time::Instant::now();
    home.stop();
    for (name, who) in [("b", &mut b), ("c", &mut c), ("d", &mut d)] {
        assert!(who.wait_for(Duration::from_secs(8), |e| matches!(e, RoomEvent::HomeLost).then_some(())).await.is_some(), "{name} told home_lost");
        assert!(who.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::Closed).then_some(())).await.is_some(), "{name} then closed");
    }
    let took = t.elapsed();
    assert!(took <= Duration::from_secs(6), "home_lost took {took:?}");
    assert_eq!(own.counter(|c| &c.cascade_homes_lost), 1, "one home lost, whatever the satellites");
    assert_eq!(own.handle.sfu.reach().state(home.addrs.control), Some(vcall::sfu::Reach::Bad));
    for _ in 0..40 {
        if own.handle.sfu.satellites_now() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!((own.handle.sfu.satellites_now(), own.handle.sfu.uplinks_now()), (0, 0));
    assert_eq!(own.counter(|c| &c.satellites_ended), 2);
    // The home is remembered as unreachable: the next join with it is
    // refused at once, without a word to it.
    let t = std::time::Instant::now();
    let pass = Delegated { proxy_token: "x".repeat(48), expires_at: 0 };
    let options = JoinOptions { home: Some(home.control()), ..JoinOptions::default() };
    let r = RoomClient::try_join_with(&own.control(), &room.room_id, &pass.proxy_token, options).await.unwrap();
    assert_eq!(r.err().map(|(s, r)| (s, r.error)), Some((503, refusal::CASCADE_UNREACHABLE.to_string())));
    assert!(t.elapsed() < Duration::from_secs(1), "refused from the cache");
    assert_eq!(own.counter(|c| &c.cascade_joins_unreachable), 1);
}

#[tokio::test]
async fn a_node_that_dies_loses_its_seats_at_the_home_within_six_seconds() {
    let home = start(config(true)).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let mut a = home.participant(&room, false, SfuTransport::Udp).await;
    let mut b = own.via(&home, &room, JoinOptions::default()).await;
    tracks_of(&mut a, 2).await;
    tracks_of(&mut b, 1).await;
    assert_eq!(home.handle.sfu.proxy_seats_now(), 1);
    let t = std::time::Instant::now();
    own.stop();
    assert!(a.wait_for(Duration::from_secs(8), |e| matches!(e, RoomEvent::Left(2)).then_some(())).await.is_some(), "a hears that the seat is gone");
    let took = t.elapsed();
    assert!(took <= Duration::from_secs(6), "the seat was given up after {took:?}");
    assert_eq!(home.counter(|c| &c.cascade_seats_reaped), 1);
    assert_eq!(home.handle.sfu.proxy_seats_now(), 0);
    assert_eq!(home.handle.sfu.participants_now(), 1);
}

#[tokio::test]
async fn the_refusals_of_a_join_with_a_home() {
    let home = start(config(true)).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let error = |r: Result<RoomClient, (u16, Refusal)>| r.err().map(|(s, r)| (s, r.error)).expect("refused");
    let via = |node: &Started, room_id: &str, home_ref: NodeRef, token: &str, key: Option<&str>| {
        let (node, room_id, token, key) = (node.control(), room_id.to_string(), token.to_string(), key.map(str::to_string));
        async move {
            let options = JoinOptions { home: Some(home_ref), access_key: key, ..JoinOptions::default() };
            RoomClient::try_join_with(&node, &room_id, &token, options).await.unwrap()
        }
    };

    // The home named is this node, or a room of this node: bad_home.
    let r = via(&own, &room.room_id, own.control(), "x", None).await;
    assert_eq!(error(r), (400, refusal::BAD_HOME.into()));
    let local = own.room(MediaLimits::default()).await.unwrap();
    let r = via(&own, &local.room_id, home.control(), "x", None).await;
    assert_eq!(error(r), (400, refusal::BAD_HOME.into()));
    // A home on a private address, without the unsafe flag: bad_home.
    let strict = start(config(false)).await;
    let r = via(&strict, &room.room_id, home.control(), "x", None).await;
    assert_eq!(error(r), (400, refusal::BAD_HOME.into()));
    // A pass that is not the home's: the home's 403, as it is; a room
    // the home does not have: its 404.
    let r = via(&own, &room.room_id, home.control(), &"f".repeat(48), None).await;
    assert_eq!(error(r), (403, refusal::BAD_TOKEN.into()));
    let r = via(&own, &"0".repeat(32), home.control(), "x", None).await;
    assert_eq!(error(r), (404, refusal::ROOM_NOT_FOUND.into()));
    assert_eq!(own.handle.sfu.satellites_now(), 0, "no satellite before the home gave a seat");
    // A full room: the home's 409.
    let mut small = config(true);
    small.room_max_participants = 2;
    let small = start(small).await;
    let tight = small.room(MediaLimits::default()).await.unwrap();
    let _x = small.participant(&tight, false, SfuTransport::Udp).await;
    let _y = small.participant(&tight, false, SfuTransport::Udp).await;
    let r = own.join_via(&small, &tight, JoinOptions::default()).await;
    assert_eq!(error(r), (409, refusal::ROOM_FULL.into()));

    // A private node of one's own wants its key; a public one counts
    // joins with a home per address.
    let mut private = config(true);
    private.private = true;
    private.access_keys = vec!["the-key".into()];
    let private = start(private).await;
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    let r = via(&private, &room.room_id, home.control(), &pass.proxy_token, None).await;
    assert_eq!(error(r), (401, refusal::ACCESS_KEY_REQUIRED.into()));
    let r = via(&private, &room.room_id, home.control(), &pass.proxy_token, Some("wrong")).await;
    assert_eq!(error(r), (401, refusal::ACCESS_KEY_REQUIRED.into()));
    let keyed = via(&private, &room.room_id, home.control(), &pass.proxy_token, Some("the-key")).await.unwrap_or_else(|(s, r)| panic!("{s} {}", r.error));
    assert_eq!(keyed.participant_id, 1);
    let mut counted = config(true);
    counted.cascade_joins_per_ip = 2;
    let counted = start(counted).await;
    for n in 0..3 {
        let r = via(&counted, &room.room_id, home.control(), "x", None).await;
        let (status, word) = error(r);
        match n {
            2 => assert_eq!((status, word), (429, refusal::RATE_LIMITED.into())),
            _ => assert_eq!((status, word), (403, refusal::BAD_TOKEN.into())),
        }
    }
    // The cascade off on one's own node: refused before anything.
    let mut off = config(true);
    off.cascade = vcall::sfu::CascadeMode::Off;
    let off = start(off).await;
    let r = via(&off, &room.room_id, home.control(), "x", None).await;
    assert_eq!(error(r), (503, refusal::CASCADE_REFUSED.into()));

    // A home that takes no uplinks: 503 cascade_refused, and the home
    // remembered as such.
    let mut deaf = config(true);
    deaf.cascade = vcall::sfu::CascadeMode::Off;
    let deaf = start(deaf).await;
    let deaf_room = deaf.room(MediaLimits::default()).await.unwrap();
    let r = own.join_via(&deaf, &deaf_room, JoinOptions::default()).await;
    assert_eq!(error(r), (503, refusal::CASCADE_REFUSED.into()));
    assert_eq!(own.handle.sfu.reach().state(deaf.addrs.control), Some(vcall::sfu::Reach::Bad));
    // A home that refuses this node (a quota of one seat): the same, after the home's 403.
    let mut one = config(true);
    one.cascade_seats_per_node = 1;
    let one = start(one).await;
    let one_room = one.room(MediaLimits::default()).await.unwrap();
    let _first = own.via(&one, &one_room, JoinOptions::default()).await;
    let r = own.join_via(&one, &one_room, JoinOptions::default()).await;
    assert_eq!(error(r), (503, refusal::CASCADE_REFUSED.into()));
    assert_eq!(one.counter(|c| &c.cascade_joins_refused_quota), 1);
    // A seat's offer with too many m-lines for a room: the client's
    // fault, judged here before a word to the home (the uplink's offer
    // mirrors it), 400 bad_sdp as the home would say it; the home is not
    // marked for it, and the next join with it goes through. A node whose
    // signing key is not its id's is no fault either: its word names the
    // key's id and holds (a word proves a key, not a node).
    let fresh = start(config(true)).await;
    let too_many = |pass: String| {
        let mut r = JoinRequest::new(pass, bare_offer(vcall::sfu::room::MAX_RX_TRACKS), vec![]);
        r.home = Some(rooms::HomeRef { node: home.control().to_string() });
        r
    };
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    let r: Result<rooms::Joined, _> = fresh.post(&room_path(&room, rooms::action::JOIN), &too_many(pass.proxy_token.clone())).await;
    assert_eq!(r.unwrap_err(), (400, Refusal::new(refusal::BAD_SDP, "the offer could not be taken: 5 media lines, at most 4")));
    assert_eq!(fresh.handle.sfu.reach().state(home.addrs.control), None, "the home is not marked for the client's offer");
    assert_eq!(fresh.counter(|c| &c.cascade_joins_unreachable), 0);
    assert_eq!(fresh.counter(|c| &c.joins_refused_sdp), 1);
    assert_eq!(fresh.counter(|c| &c.cascade_uplinks_made), 0);
    let fine = JoinOptions { home: Some(home.control()), ..JoinOptions::default() };
    let in_after_all = RoomClient::try_join_with(&fresh.control(), &room.room_id, &pass.proxy_token, fine).await.unwrap();
    let _in_after_all = in_after_all.unwrap_or_else(|(s, r)| panic!("the pass stayed, the home is reached: {s} {}", r.error));
    let liar = start(config_with_a_wrong_key()).await;
    let seat = liar.join_via(&home, &room, JoinOptions::default()).await.unwrap_or_else(|(s, r)| panic!("{s} {}", r.error));
    assert!(seat.home_token.is_some());
    drop(seat);
    // A home whose answer names an address that is not the home's: no
    // candidate to take, 503 cascade_unreachable. (The home listens on
    // 127.0.0.1 and declares 127.0.0.2.)
    let mut elsewhere = config(true);
    elsewhere.public_ip = "127.0.0.2".parse().unwrap();
    let elsewhere = start(elsewhere).await;
    let far_room = elsewhere.room(MediaLimits::default()).await.unwrap();
    let r = own.join_via(&elsewhere, &far_room, JoinOptions::default()).await;
    assert_eq!(error(r), (503, refusal::CASCADE_UNREACHABLE.into()));
    assert_eq!(own.handle.sfu.reach().state(elsewhere.addrs.control), Some(vcall::sfu::Reach::Bad));
    // A dead home: 503 cascade_unreachable, within the HELLO time.
    let gone = start(config(true)).await;
    let gone_ref = gone.control();
    gone.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t = std::time::Instant::now();
    let r = via(&own, &room.room_id, gone_ref, "x", None).await;
    assert_eq!(error(r), (503, refusal::CASCADE_UNREACHABLE.into()));
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert_eq!(home.handle.sfu.proxy_seats_now(), 2, "the keyed one, and the one after the bad offer");
}

/// A home is named by address and id, and the connection to it is pinned
/// to that id: a wrong id for a live address is the client's reference
/// at fault (400 bad_home), which marks nothing of the home for the
/// others, and which never rides a connection made for the right id (a
/// node's signed word must not reach whoever sits at an address). A join
/// that fails with no satellite of the home here leaves no connection
/// behind.
#[tokio::test]
async fn a_home_is_the_node_named_and_a_wrong_id_marks_nothing() {
    let home = start(config(true)).await;
    let own = start(config(true)).await;
    let stranger = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    // The home's address with another node's id.
    let misnamed = NodeRef { addr: home.addrs.control, id: stranger.id, sni: None };
    let via = |home_ref: NodeRef, token: String| {
        let node = own.control();
        let room_id = room.room_id.clone();
        async move {
            let options = JoinOptions { home: Some(home_ref), ..JoinOptions::default() };
            RoomClient::try_join_with(&node, &room_id, &token, options).await.unwrap().map_err(|(s, r)| (s, r.error))
        }
    };
    // Nothing known of the home yet: the wrong id fails at the pin, as
    // the client's fault, and the home is not remembered bad.
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    let r = via(misnamed.clone(), pass.proxy_token.clone()).await;
    assert_eq!(r.as_ref().err(), Some(&(400, refusal::BAD_HOME.to_string())), "{:?}", r.as_ref().err());
    assert_eq!(own.handle.sfu.reach().state(home.addrs.control), None);
    assert_eq!(own.counter(|c| &c.cascade_joins_unreachable), 0);
    assert_eq!(own.handle.cascade.links_now(), 0, "no connection left behind");
    // The right id: in at once (not refused from a cache the wrong id
    // poisoned), with the same pass (it was never shown to the home).
    let b = via(home.control(), pass.proxy_token.clone()).await.unwrap_or_else(|(s, e)| panic!("{s} {e}"));
    assert_eq!(b.participant_id, 1);
    assert_eq!(own.handle.sfu.reach().state(home.addrs.control), Some(vcall::sfu::Reach::Good));
    assert_eq!(own.handle.cascade.links_now(), 1);
    // The home known good, its connection kept: the wrong id gets no ride
    // on it; the home sees no join for the other id, and stays good.
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    let r = via(misnamed, pass.proxy_token).await;
    assert_eq!(r.as_ref().err(), Some(&(400, refusal::BAD_HOME.to_string())), "{:?}", r.as_ref().err());
    assert_eq!(own.handle.sfu.reach().state(home.addrs.control), Some(vcall::sfu::Reach::Good));
    assert_eq!(home.handle.sfu.proxy_seats_now(), 1, "no seat for a word of another id");
    assert_eq!(own.handle.cascade.links_now(), 1, "the satellite's connection stays, nothing else");
    // A join another home refuses, with no satellite of it here: the
    // connection made for it is dropped with the refusal.
    let other = stranger.room(MediaLimits::default()).await.unwrap();
    let options = JoinOptions { home: Some(stranger.control()), ..JoinOptions::default() };
    let r = RoomClient::try_join_with(&own.control(), &other.room_id, "not-a-pass", options).await.unwrap();
    assert_eq!(r.err().map(|(s, r)| (s, r.error)), Some((403, refusal::BAD_TOKEN.to_string())));
    assert_eq!(own.handle.cascade.links_now(), 1, "a failed join leaves no connection behind");
    drop(b);
}

/// The home closes a control connection idle for its time; the node
/// keeps one a home while satellites live and finds it closed at the
/// next join: that join goes on a fresh connection, and the home is not
/// taken for lost.
#[tokio::test]
async fn a_connection_the_home_closed_as_idle_is_made_anew_for_the_next_join() {
    let mut h = config(true);
    h.control_idle = Duration::from_millis(500);
    let home = start(h).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let _a = home.participant(&room, false, SfuTransport::Udp).await;
    let mut b = own.via(&home, &room, JoinOptions::default()).await;
    tracks_of(&mut b, 1).await;
    assert_eq!(own.handle.cascade.links_now(), 1);
    // Long past the home's idle time: the kept connection is closed at
    // the home (the node's own HELLO on it comes only after a minute).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let c = own.join_via(&home, &room, JoinOptions::default()).await.unwrap_or_else(|(s, r)| panic!("{s} {} {}", r.error, r.message));
    assert_eq!(c.participant_id, 3);
    assert_eq!(own.counter(|c| &c.cascade_joins_unreachable), 0);
    assert_eq!(own.handle.sfu.reach().state(home.addrs.control), Some(vcall::sfu::Reach::Good));
    assert_eq!(own.handle.cascade.links_now(), 1);
}

/// The admin's new join token shuts the old one out, passes taken under
/// it included: a member excluded with a pass in hand does not come back
/// through its node.
#[tokio::test]
async fn a_new_join_token_voids_the_passes_taken_under_the_old_one() {
    let home = start(config(true)).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let old = home.delegate(&room, &room.join_token).await.unwrap();
    let changed: TokenChanged = home.post(&room_path(&room, rooms::action::TOKEN), &TokenRequest { admin_token: room.admin_token.clone() }).await.unwrap();
    let options = || JoinOptions { home: Some(home.control()), ..JoinOptions::default() };
    let r = RoomClient::try_join_with(&own.control(), &room.room_id, &old.proxy_token, options()).await.unwrap();
    assert_eq!(r.err().map(|(s, r)| (s, r.error)), Some((403, refusal::BAD_TOKEN.to_string())), "the old pass is void");
    assert_eq!(home.counter(|c| &c.joins_refused_token), 1);
    assert_eq!(home.handle.sfu.proxy_seats_now(), 0);
    // A pass under the new token is a way in.
    let fresh = home.delegate(&room, &changed.join_token).await.unwrap();
    let b = RoomClient::try_join_with(&own.control(), &room.room_id, &fresh.proxy_token, options()).await.unwrap().unwrap_or_else(|(s, r)| panic!("{s} {}", r.error));
    assert_eq!(b.participant_id, 1);
    assert_eq!(home.handle.sfu.proxy_seats_now(), 1);
}

#[tokio::test]
async fn an_uplink_has_a_bucket_and_the_answer_carries_the_lower_bandwidth() {
    let mut h = config(true);
    h.room_kbps_per_participant = 400;
    let home = start(h).await;
    let mut o = config(true);
    o.room_kbps_per_participant = 64; // 8000 bytes a second down each uplink, times the others of the roster (here: one)
    let own = start(o).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let a = home.participant(&room, true, SfuTransport::Udp).await;
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    let options = JoinOptions { video: true, home: Some(home.control()), ..JoinOptions::default() };
    let mut b = RoomClient::try_join_with(&own.control(), &room.room_id, &pass.proxy_token, options).await.unwrap().unwrap_or_else(|(s, r)| panic!("{s} {}", r.error));
    b.wait_for(ROOM_WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.expect("ctl open");
    let (_, a_video_at_b) = tracks_of(&mut b, 1).await;
    let a_video_at_b = a_video_at_b.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // 1000 bytes a packet, fifty a second: 400 kbit/s, past the uplink's 64.
    let mut got = 0;
    for i in 0..100u8 {
        let mut payload = vec![0x10, 0x00, 0, i];
        payload.resize(1000, 0xEE);
        a.send_video(&payload, true).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Some(e) = b.next(Duration::ZERO).await {
            if matches!(e, RoomEvent::Rtp { ref mid, .. } if *mid == a_video_at_b) {
                got += 1;
            }
        }
    }
    assert!(got > 0 && got < 60, "{got} of 100 came through the uplink's bucket");
    assert!(own.counter(|c| &c.cascade_dropped_bandwidth) >= 40, "{}", own.counter(|c| &c.cascade_dropped_bandwidth));
    assert_eq!(home.counter(|c| &c.sfu_dropped_bandwidth), 0, "the home's bucket of 400 holds it");
}

#[tokio::test]
async fn the_answer_of_a_join_with_a_home_says_the_lower_bandwidth() {
    let mut h = config(true);
    h.room_kbps_per_participant = 300;
    let home = start(h).await;
    let own = start(config(true)).await;
    let room = home.room(MediaLimits::default()).await.unwrap();
    let pass = home.delegate(&room, &room.join_token).await.unwrap();
    let mut request = JoinRequest::new(pass.proxy_token.clone(), bare_offer(1), vec![]);
    request.home = Some(rooms::HomeRef { node: home.control().to_string() });
    let joined: rooms::Joined = own.post(&room_path(&room, rooms::action::JOIN), &request).await.unwrap();
    let bandwidth: Vec<&str> = joined.sdp_answer.lines().filter(|l| l.starts_with("b=")).collect();
    assert_eq!(bandwidth, vec!["b=AS:128", "b=AS:163"], "the home's limit, as this node has none: {}", joined.sdp_answer);
    assert!(joined.home_token.is_some());
    assert_eq!(joined.participant_id, 1);
    assert_eq!(own.handle.sfu.satellites_now(), 1);
    assert_eq!(own.handle.sfu.participants_now(), 1);
    assert_eq!(home.handle.sfu.proxy_seats_now(), 1);
}

/// The m-lines at `at` for the streams of `ids`, collected over as many
/// offers as it takes until every id has an audio m-line: by (id, kind).
async fn tracks_until(at: &mut RoomClient, ids: &[u32]) -> std::collections::HashMap<(u32, String), String> {
    let mut got = std::collections::HashMap::new();
    let until = std::time::Instant::now() + ROOM_WAIT;
    while ids.iter().any(|id| !got.contains_key(&(*id, "audio".to_string()))) {
        let left = until.saturating_duration_since(std::time::Instant::now());
        let Some(event) = at.next(left).await else { panic!("no tracks of {ids:?}: {got:?}") };
        if let RoomEvent::Tracks(tracks) = event {
            for t in tracks {
                got.insert((t.id, t.kind.clone()), t.mid.clone());
            }
        }
    }
    got
}

// ---- the trust of the cascade: the registry's list -----------------------------

use ring::signature::{Ed25519KeyPair, KeyPair};
use vcall::trust::{ListFetcher, Trust};
use vcall_proto::list::{self, CallList, CallNode};
use vlink_proto::sign::Signer;

fn pkcs8() -> Vec<u8> {
    Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap().as_ref().to_vec()
}

/// A registry that answers every GET of the complete list of nodes with
/// `answer`, and anything else with 404, for as long as the test runs.
async fn fake_list_registry(answer: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/vlink", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let answer = answer.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else { return };
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&raw).to_string();
                let response = if head.starts_with("GET /vlink/v1/calls/all HTTP/1.1\r\n") {
                    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len())
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    url
}

/// A complete list naming `ids`, signed by `list_key` under `root`'s
/// delegation, as the registry sends it.
fn signed_list(root: &Signer, list_key: &Ed25519KeyPair, ids: &[NodeId], now: u64) -> String {
    let delegation = root.delegate(&vcall_proto::register::hex(list_key.public_key().as_ref()), now + 86_400);
    let nodes = ids
        .iter()
        .map(|id| CallNode {
            node: format!("203.0.113.7:8443#{id}"),
            turn_port: 3478,
            sfu_port: 3479,
            region: "eu".into(),
            caps: vec!["stun".into(), "turn".into(), "sfu".into(), "cascade".into()],
            class: list::CLASS_VOLUNTEER.into(),
            state: Some(list::State::Active),
            load: 0.01,
        })
        .collect();
    let list = CallList { v: list::LIST_VERSION, kind: list::KIND.into(), complete: true, issued_at: now, expires_at: now + 3600, nodes };
    serde_json::to_string(&list::sign_list(list_key, &list, &delegation)).unwrap()
}

/// A node the registry lists holds seats at a home without the quota; one
/// it does not list is held to it. A list that is not the root's changes
/// nothing. The list kept in the file comes back after a restart. With
/// `VCALL_CASCADE=registry` an unlisted node gets no seat at all.
#[tokio::test]
async fn nodes_on_the_registrys_list_hold_seats_without_the_quota_and_registry_mode_takes_no_others() {
    let dir = std::env::temp_dir().join(format!("vcall-e2e-trust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut h = config(true);
    h.cascade_seats_per_node = 1;
    h.room_max_participants = 8;
    let home = start(h).await;
    let own = start(config(true)).await;
    let stranger = start(config(true)).await;
    let error = |r: Result<RoomClient, (u16, Refusal)>| r.err().map(|(s, r)| (s, r.error)).expect("refused");

    let root = Signer::from_pkcs8(&pkcs8()).unwrap();
    let list_key = Ed25519KeyPair::from_pkcs8(&pkcs8()).unwrap();
    let now = vcall::turn::unix_now();
    let registry = fake_list_registry(signed_list(&root, &list_key, &[own.id], now)).await;
    let cache = dir.join(vcall::trust::LIST_FILE);
    let fetcher = ListFetcher {
        registry: registry.clone(),
        root_hex: root.public_hex(),
        cache: Some(cache.clone()),
        trust: home.handle.trust.clone(),
        counters: home.handle.counters.clone(),
    };
    assert_eq!(home.handle.trust.listed_now(), 0);
    assert_eq!(fetcher.refresh().await.unwrap(), 1);
    assert!(home.handle.trust.is_listed(&own.id.to_string()));
    assert!(!home.handle.trust.is_listed(&stranger.id.to_string()));
    assert!(cache.exists(), "the list is kept");

    // The listed node: two seats under a quota of one. The other: one, then the quota.
    let room = home.room(MediaLimits::default()).await.unwrap();
    let _a = own.via(&home, &room, JoinOptions::default()).await;
    let _b = own.via(&home, &room, JoinOptions::default()).await;
    let _c = stranger.via(&home, &room, JoinOptions::default()).await;
    let r = stranger.join_via(&home, &room, JoinOptions::default()).await;
    assert_eq!(error(r), (503, refusal::CASCADE_REFUSED.into()));
    assert_eq!(home.counter(|c| &c.cascade_joins_refused_quota), 1);
    assert_eq!(home.counter(|c| &c.cascade_joins_refused_list), 0);
    assert_eq!(home.handle.sfu.proxy_seats_now(), 3);

    // A list under another root, naming the stranger: not taken.
    let other_root = Signer::from_pkcs8(&pkcs8()).unwrap();
    let forged = fake_list_registry(signed_list(&other_root, &list_key, &[stranger.id], now)).await;
    let bad = ListFetcher { registry: forged, root_hex: root.public_hex(), cache: None, trust: home.handle.trust.clone(), counters: home.handle.counters.clone() };
    let e = bad.refresh().await.unwrap_err().to_string();
    assert!(e.contains("delegation"), "{e}");
    assert!(home.handle.trust.is_listed(&own.id.to_string()));
    assert!(!home.handle.trust.is_listed(&stranger.id.to_string()));
    // A registry that is away: the error, and nothing changes.
    let away = ListFetcher { registry: "http://127.0.0.1:1/vlink".into(), root_hex: root.public_hex(), cache: None, trust: home.handle.trust.clone(), counters: home.handle.counters.clone() };
    assert!(away.refresh().await.is_err());
    assert_eq!(home.handle.trust.listed_now(), 1);

    // After a restart, the kept list is trusted until the registry answers.
    let fresh = ListFetcher {
        registry: "http://127.0.0.1:1/vlink".into(),
        root_hex: root.public_hex(),
        cache: Some(cache.clone()),
        trust: std::sync::Arc::new(Trust::new(vcall::sfu::CascadeMode::On)),
        counters: home.handle.counters.clone(),
    };
    assert_eq!(fresh.load_cache(), Some(1));
    assert!(fresh.trust.is_listed(&own.id.to_string()));
    // Kept under another root (a registry of one's own that moved): not taken.
    let moved = ListFetcher { root_hex: other_root.public_hex(), trust: std::sync::Arc::new(Trust::new(vcall::sfu::CascadeMode::On)), ..fresh };
    assert_eq!(moved.load_cache(), None);
    assert_eq!(moved.trust.listed_now(), 0);

    // VCALL_CASCADE=registry: the stranger gets no seat, the listed node does.
    let mut r = config(true);
    r.cascade = vcall::sfu::CascadeMode::Registry;
    let strict = start(r).await;
    let strict_room = strict.room(MediaLimits::default()).await.unwrap();
    let refused = stranger.join_via(&strict, &strict_room, JoinOptions::default()).await;
    assert_eq!(error(refused), (503, refusal::CASCADE_REFUSED.into()));
    assert_eq!(strict.counter(|c| &c.cascade_joins_refused_list), 1);
    assert_eq!(strict.handle.sfu.proxy_seats_now(), 0);
    let r = own.join_via(&strict, &strict_room, JoinOptions::default()).await;
    assert_eq!(error(r), (503, refusal::CASCADE_REFUSED.into()), "nobody is listed yet");
    strict.handle.trust.set_listed([own.id.to_string()].into_iter().collect());
    // The home was marked unreachable by the refusal; a fresh node of the
    // same key would not be, so clear the mark as a minute would.
    own.handle.sfu.reach().mark(strict.addrs.control, vcall::sfu::Reach::Good);
    let _d = own.via(&strict, &strict_room, JoinOptions::default()).await;
    assert_eq!(strict.handle.sfu.proxy_seats_now(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---- invitations to a private node ----------------------------------------------

use vcall_proto::invite::{DeviceCredentials, InviteRequest};

/// An invitation made over the control socket is a link; its token is
/// exchanged once for the credentials of a device, which open the node
/// (credentials, rooms, the cascade through it) until the device is
/// revoked; attempts at the exchange are counted per address.
#[tokio::test]
async fn an_invitation_is_exchanged_for_the_credentials_of_a_device_that_open_a_private_node() {
    let dir = std::env::temp_dir().join(format!("vcall-e2e-invite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("ctl.sock");
    let devices_file = dir.join("devices.json");
    let mut c = config(true);
    c.private = true;
    c.ctl = Some(socket.clone());
    c.devices = Some(devices_file.clone());
    let node = start(c).await;
    assert_eq!(node.credentials(Access::default()).await.unwrap_err().0, 401, "nothing opens it yet");

    // The invitation: a link naming the node, its control address and a token.
    let made = vcall::ctl::call(&socket, &vcall::ctl::Request::Invite { uses: 1, ttl_secs: 600, label: "Anna's phone".into() }).await.unwrap();
    assert!(made.ok, "{:?}", made.error);
    let invited: vcall::ctl::Invited = serde_json::from_value(made.data.unwrap()).unwrap();
    let prefix = format!("veydan://call-node/{}?a=127.0.0.1%3A{}&t=", node.id, node.addrs.control.port());
    assert!(invited.link.starts_with(&prefix), "{}", invited.link);
    let token = invited.link[prefix.len()..].to_string();
    assert_eq!((token.len(), invited.uses, invited.label.as_str()), (48, 1, "Anna's phone"));
    assert!(invited.expires_at >= vcall::turn::unix_now() + 590);
    let listing: vcall::devices::Listing = serde_json::from_value(vcall::ctl::call(&socket, &vcall::ctl::Request::Devices).await.unwrap().data.unwrap()).unwrap();
    assert_eq!((listing.invites.len(), listing.devices.len()), (1, 0));

    // The exchange: a wrong token, then the right one.
    let wrong: Result<DeviceCredentials, _> = node.post(vcall_proto::PATH_INVITE, &InviteRequest { token: "0".repeat(48), name: "x".into() }).await;
    assert_eq!(wrong.unwrap_err().1.error, refusal::BAD_INVITE);
    let creds: DeviceCredentials = node.post(vcall_proto::PATH_INVITE, &InviteRequest { token: token.clone(), name: "Chat 5.1.8".into() }).await.unwrap();
    assert_eq!(creds.node, format!("127.0.0.1:{}#{}", node.addrs.control.port(), node.id));
    assert_eq!(creds.label, "Anna's phone");
    assert_eq!((creds.device_id.len(), creds.secret.len()), (32, 64));
    let device = Access::device(creds.device_id.clone(), creds.secret.clone());

    // The credentials open the node: TURN, a room, and the cascade through it.
    let turn = node.credentials(device.clone()).await.unwrap();
    let mut a = TurnClient::connect(node.addrs.turn_udp, Transport::Udp, None).await.unwrap();
    a.set_credentials(&turn.username, &turn.password);
    a.allocate(None).await.unwrap();
    let room: RoomCreated = node.post(rooms::PATH_ROOMS, &RoomRequest { access: device.clone(), media_limits: MediaLimits::default() }).await.unwrap();
    let _p = node.participant(&room, false, SfuTransport::Udp).await;
    assert_eq!(node.credentials(Access::device(creds.device_id.clone(), "0".repeat(64))).await.unwrap_err().0, 401);
    assert_eq!(node.credentials(Access::device("0".repeat(32), creds.secret.clone())).await.unwrap_err().0, 401);
    let home = start(config(true)).await;
    let home_room = home.room(MediaLimits::default()).await.unwrap();
    let without = node.join_via(&home, &home_room, JoinOptions::default()).await;
    assert_eq!(without.err().map(|(s, r)| (s, r.error)), Some((401, refusal::ACCESS_KEY_REQUIRED.into())));
    let options = JoinOptions { device: Some((creds.device_id.clone(), creds.secret.clone())), ..JoinOptions::default() };
    let seat = node.via(&home, &home_room, options).await;
    assert!(seat.home_token.is_some());
    // The token was for one device: used up.
    let again: Result<DeviceCredentials, _> = node.post(vcall_proto::PATH_INVITE, &InviteRequest { token: token.clone(), name: String::new() }).await;
    assert_eq!(again.unwrap_err().1.error, refusal::BAD_INVITE);
    let listing: vcall::devices::Listing = serde_json::from_value(vcall::ctl::call(&socket, &vcall::ctl::Request::Devices).await.unwrap().data.unwrap()).unwrap();
    assert_eq!((listing.invites.len(), listing.devices.len()), (0, 1));
    assert_eq!((listing.devices[0].id.as_str(), listing.devices[0].label.as_str(), listing.devices[0].name.as_str()), (creds.device_id.as_str(), "Anna's phone", "Chat 5.1.8"));

    // Revoked: a stranger again, on the node and in the file.
    let revoked = vcall::ctl::call(&socket, &vcall::ctl::Request::Revoke { id: creds.device_id.clone() }).await.unwrap();
    assert!(revoked.ok);
    assert!(!vcall::ctl::call(&socket, &vcall::ctl::Request::Revoke { id: creds.device_id.clone() }).await.unwrap().ok);
    assert_eq!(node.credentials(device.clone()).await.unwrap_err().0, 401);
    let kept = vcall::devices::Devices::open(Some(devices_file)).unwrap();
    assert_eq!(kept.devices_now(), 0);
    assert!(!kept.check(&creds.device_id, &creds.secret, vcall::turn::unix_now()));

    // So many attempts from one address in the window, right or wrong.
    let tried = 3; // the wrong one, the right one, the used-up one
    for _ in tried..vcall::control::INVITE_ATTEMPTS_PER_IP {
        let r: Result<DeviceCredentials, _> = node.post(vcall_proto::PATH_INVITE, &InviteRequest { token: "1".repeat(48), name: String::new() }).await;
        assert_eq!(r.unwrap_err().1.error, refusal::BAD_INVITE);
    }
    let r: Result<DeviceCredentials, _> = node.post(vcall_proto::PATH_INVITE, &InviteRequest { token, name: String::new() }).await;
    assert_eq!(r.unwrap_err(), (429, Refusal::new(refusal::RATE_LIMITED, "too many invitations tried from this address")));
    assert_eq!(node.counter(|c| &c.invites_exchanged), 1);
    // The wrong one, the used-up one, the seven guesses, the one over the window.
    assert_eq!(node.counter(|c| &c.invites_refused), u64::from(vcall::control::INVITE_ATTEMPTS_PER_IP));
    // An invitation withdrawn by the hash the listing shows.
    let made = vcall::ctl::call(&socket, &vcall::ctl::Request::Invite { uses: 5, ttl_secs: 600, label: String::new() }).await.unwrap();
    assert!(made.ok);
    let listing: vcall::devices::Listing = serde_json::from_value(vcall::ctl::call(&socket, &vcall::ctl::Request::Devices).await.unwrap().data.unwrap()).unwrap();
    assert_eq!(listing.invites[0].uses_left, 5);
    assert!(vcall::ctl::call(&socket, &vcall::ctl::Request::Revoke { id: listing.invites[0].hash.clone() }).await.unwrap().ok);
    assert!(node.handle.devices.list(vcall::turn::unix_now()).invites.is_empty());
    let stats: vcall::ctl::Stats = serde_json::from_value(vcall::ctl::call(&socket, &vcall::ctl::Request::Stats).await.unwrap().data.unwrap()).unwrap();
    assert_eq!((stats.devices_now, stats.invites_now, stats.cascade.as_str()), (0, 0, "on"));
    drop(seat);
    std::fs::remove_dir_all(&dir).unwrap();
}
