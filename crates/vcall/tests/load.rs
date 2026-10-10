//! `vcall load` against a node in this process: participants in rooms
//! and a TURN stream, all on loopback; what the tool counts is what the
//! node forwarded.

use std::time::Duration;

use vcall::identity::{self, Identity, NodeRef};
use vcall::load::{self, Options, Shape, Video, Watch};
use vcall::turn::allocation::Transport;
use vcall::{Config, Node};

fn config() -> Config {
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
        relay_ports: 51000..=51099,
        realm: "veydan-test".into(),
        private: false,
        access_keys: Vec::new(),
        devices: None,
        issuers: Vec::new(),
        max_connections: 256,
        max_connections_per_ip: 256,
        control_idle: Duration::from_secs(60),
        max_mbps: 0,
        turn_mbps: 0,
        kbps_per_allocation: 0,
        max_allocations: 100,
        max_per_ip: 100,
        max_lifetime: Duration::from_secs(600),
        credentials_ttl: Duration::from_secs(120),
        credentials_per_ip: 1000,
        max_rooms: 4,
        room_max_participants: 12,
        room_kbps_per_participant: 0,
        room_lifetime: Duration::from_secs(600),
        room_idle: Duration::from_secs(600),
        room_connect_timeout: Duration::from_secs(600),
        room_offer_timeout: Duration::from_secs(600),
        room_audio_n: vcall::sfu::DEFAULT_AUDIO_N,
        // Enough for everybody's video from the first second: the node's
        // estimate is not what is tested here.
        room_bwe_kbps: 20_000,
        cascade: vcall::sfu::CascadeMode::On,
        cascade_seats_per_node: vcall::sfu::DEFAULT_CASCADE_SEATS_PER_NODE,
        cascade_uplinks: vcall::sfu::DEFAULT_CASCADE_UPLINKS,
        cascade_joins_per_ip: vcall::cascade::DEFAULT_CASCADE_JOINS_PER_IP,
        allow_private_peers: true,
        ctl: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn participants_in_two_rooms_and_a_turn_stream_count_what_the_node_forwards() {
    let node = Node::bind(config()).await.unwrap();
    let reference = NodeRef { addr: node.addrs().unwrap().control, id: node.id(), sni: None };
    let handle = node.handle();
    let _task = tokio::spawn(node.run());

    // 10 participants × 2 rooms with audio and a small video; 1 TURN stream.
    let options = Options {
        node: reference,
        access_key: None,
        rooms: 2,
        per_room: 10,
        shape: Shape { audio_kbps: 48, video: Some(Video { kbps: 120, fps: 10 }), mtu: load::DEFAULT_MTU },
        sfu_tcp: false,
        turn: 1,
        turn_shape: Shape { audio_kbps: 48, video: None, mtu: load::DEFAULT_MTU },
        turn_transport: Transport::Udp,
        turn_channel: true,
        duration: Duration::from_secs(4),
        ramp: None,
        max_loss_pct: 0.0,
        max_cpu_pct: 0.0,
        report_every: Duration::from_secs(2),
        watch: Watch::default(),
        quiet: true,
    };
    let summary = load::run(options).await.unwrap();

    assert_eq!(summary.participants, 20);
    assert_eq!(summary.connected, 20, "{summary:?}");
    assert_eq!(summary.join_failures, 0);
    assert_eq!(summary.turn_streams, 1);
    assert!(summary.stopped_by.is_none(), "{:?}", summary.stopped_by);
    // Video of everybody else: 9 streams a participant. Audio: a room of
    // ten is past a conversation, so the three speakers' alone, and a
    // speaker does not get its own: 3 × 2 + 7 × 3 a room.
    let t = &summary.totals;
    assert_eq!(t.video.streams, 20 * 9, "{t:?}");
    assert!(t.audio.streams >= 2 * (3 * 2 + 7 * 3) && t.audio.streams <= 20 * 9, "{t:?}");
    assert!(t.video.received > 20 * 9 * 10 * 3, "{t:?}");
    assert!(t.audio.received > 20 * 3 * 50 * 3, "{t:?}");
    assert!(t.video.loss_pct() < 1.0 && t.audio.loss_pct() < 1.0, "{t:?}");
    // The TURN stream, both ways: a hundred packets at least each way.
    assert!(t.data.received >= 200, "{t:?}");
    assert!(t.data.loss_pct() < 1.0, "{t:?}");
    assert!(summary.rx_mbps > 0.0 && summary.tx_mbps > 0.0);
    assert!(!summary.samples.is_empty());

    // The node saw it all, and counted as much as the tool got.
    let c = handle.counters.snapshot();
    assert!(c.sfu_packets_out >= t.audio.received + t.video.received, "{c:?}");
    assert_eq!(c.allocations, 2);
    assert!(c.bytes_to_peers > 0 && c.bytes_to_clients > 0);
    assert_eq!(c.sfu_dropped_socket + c.sfu_dropped_queue, 0, "{c:?}");

    // Everybody left when the run ended.
    for _ in 0..50 {
        if handle.sfu.participants_now() == 0 && handle.turn.active() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(handle.sfu.participants_now(), 0);
    assert_eq!(handle.turn.active(), 0);
}
