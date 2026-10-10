//! `vcall`: the node, and the tools to try one.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::net::UdpSocket;
use vcall::client::{self, ControlClient, Endpoints, Incoming, TurnClient};
use vcall::identity::{self, NodeRef};
use vcall::register::Registrar;
use vcall::room_client::{RoomClient, RoomEvent, SfuTransport};
use vcall::turn::allocation::Transport;
use vcall::{ctl, load, Config, Node};
use vcall_proto::rooms::{self, MediaLimits, RoomCreated, RoomRequest, TokenChanged, TokenRequest};
use vcall_proto::{capability, Access};

#[derive(Parser)]
#[command(name = "vcall", about = "Veydan call node: STUN, TURN, SFU", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    node: NodeArgs,
}

#[derive(Args, Clone)]
struct NodeArgs {
    /// Control and TURN over TLS.
    #[arg(long, env = "VCALL_LISTEN", default_value = "0.0.0.0:443")]
    listen: SocketAddr,
    /// STUN and TURN over UDP, TURN over TCP.
    #[arg(long, env = "VCALL_TURN_LISTEN", default_value = "0.0.0.0:3478")]
    turn_listen: SocketAddr,
    /// The SFU over UDP, and over TCP on the same port.
    #[arg(long, env = "VCALL_SFU_LISTEN", default_value = "0.0.0.0:3479")]
    sfu_listen: SocketAddr,
    /// Where the node keeps its key and its TURN secret.
    #[arg(long, env = "VCALL_DATA", default_value = "data")]
    data: PathBuf,
    /// The address the world reaches this machine at; found by itself on a
    /// server with its own address, needed behind a NAT or in a container.
    #[arg(long, env = "VCALL_PUBLIC_IP")]
    public_ip: Option<IpAddr>,
    /// The port the world reaches the TLS port at, when it is not the one
    /// it listens on.
    #[arg(long, env = "VCALL_PUBLIC_PORT")]
    public_port: Option<u16>,
    /// UDP ports allocations are given from: `first-last`. Open them in the firewall.
    #[arg(long, env = "VCALL_RELAY_PORTS", default_value = "49152-65535")]
    relay_ports: String,
    /// The realm of the TURN credentials.
    #[arg(long, env = "VCALL_REALM", default_value = "veydan")]
    realm: String,
    /// Give credentials only to callers with an access key.
    #[arg(long, env = "VCALL_PRIVATE")]
    private: bool,
    /// A file with the access keys of a private node, one per line.
    #[arg(long, env = "VCALL_ACCESS_KEYS")]
    access_keys: Option<PathBuf>,
    /// Public keys (hex) of pass issuers the node trusts; not used yet.
    #[arg(long, env = "VCALL_ISSUERS", value_delimiter = ',')]
    issuers: Vec<String>,
    /// The control socket for `vcall ctl`; <data>/ctl.sock by default.
    #[arg(long, env = "VCALL_CTL")]
    ctl: Option<PathBuf>,
    /// TCP and TLS connections held at once.
    #[arg(long, env = "VCALL_MAX_CONNECTIONS", default_value_t = 4096)]
    max_connections: usize,
    /// TCP and TLS connections one address may hold at once.
    #[arg(long, env = "VCALL_MAX_CONNECTIONS_PER_IP", default_value_t = 32)]
    max_connections_per_ip: u32,
    /// All the traffic the node relays, Mbit/s; 0 for no limit.
    #[arg(long, env = "VCALL_MAX_MBPS", default_value_t = 100)]
    max_mbps: u64,
    /// The part of it TURN may take, Mbit/s; 0 for no limit of its own.
    #[arg(long, env = "VCALL_TURN_MAX_MBPS", default_value_t = 50)]
    turn_max_mbps: u64,
    /// What one allocation may carry, kbit/s; 0 for no limit.
    #[arg(long, env = "VCALL_TURN_ALLOC_KBPS", default_value_t = 2000)]
    turn_alloc_kbps: u64,
    #[arg(long, env = "VCALL_TURN_MAX_ALLOCATIONS", default_value_t = 1000)]
    turn_max_allocations: usize,
    /// Allocations one address may hold: a caller makes several (one per
    /// interface and transport), and callers share a NAT.
    #[arg(long, env = "VCALL_TURN_MAX_PER_IP", default_value_t = vcall::turn::DEFAULT_MAX_PER_IP)]
    turn_max_per_ip: u32,
    /// The most an allocation may last without a refresh, seconds.
    #[arg(long, env = "VCALL_TURN_MAX_LIFETIME", default_value_t = 3600)]
    turn_max_lifetime: u64,
    /// How long credentials are good for, seconds.
    #[arg(long, env = "VCALL_CREDENTIALS_TTL", default_value_t = 600)]
    credentials_ttl: u64,
    /// Credentials and rooms one address may ask for in ten minutes, on a public node.
    #[arg(long, env = "VCALL_CREDENTIALS_PER_IP", default_value_t = 30)]
    credentials_per_ip: u32,
    /// Rooms of the SFU at once.
    #[arg(long, env = "VCALL_ROOMS_MAX", default_value_t = 64)]
    rooms_max: usize,
    /// Seats in a room.
    #[arg(long, env = "VCALL_ROOM_MAX", default_value_t = 12)]
    room_max: u32,
    /// What one participant of a room may send, kbit/s; 0 for no limit.
    #[arg(long, env = "VCALL_ROOM_KBPS", default_value_t = 2500)]
    room_kbps: u32,
    /// Speakers whose audio is forwarded in a room with more participants than that and one.
    #[arg(long, env = "VCALL_ROOM_AUDIO_N", default_value_t = vcall::sfu::DEFAULT_AUDIO_N)]
    room_audio_n: u32,
    /// What a participant of a room is assumed to take, kbit/s, before its TWCC feedback says.
    #[arg(long, env = "VCALL_ROOM_BWE_KBPS", default_value_t = vcall::sfu::DEFAULT_BWE_KBPS)]
    room_bwe_kbps: u32,
    /// The registry to report to and to take the list of nodes from,
    /// `https://host/vlink`. None: the node stays unlisted and has no list
    /// (with `--cascade on` every node is held to the quota; `registry`
    /// does not start; a file names the trusted nodes on its own).
    #[arg(long, env = "VCALL_REGISTRY")]
    registry: Option<String>,
    /// The root key (hex) the registry's list of nodes is checked against;
    /// the VLink root by default, as the app has it.
    #[arg(long, env = "VCALL_REGISTRY_ROOT", default_value = vcall::trust::ROOT_PUB)]
    registry_root: String,
    /// A hint for clients in the report: `eu`, `ru`.
    #[arg(long, env = "VCALL_REGION", default_value = "")]
    region: String,
    /// The cascade: `on` (seats of any node within the quota, of a node
    /// on the registry's list without it), `off`, `registry` (nodes on the
    /// registry's list only), or a file with the ids of the nodes whose
    /// seats this node takes, one per line (those only, without the quota).
    #[arg(long, env = "VCALL_CASCADE", default_value = "on")]
    cascade: String,
    /// Seats one other node may hold here, over all rooms; 0 for no limit.
    #[arg(long, env = "VCALL_CASCADE_SEATS_PER_NODE", default_value_t = vcall::sfu::DEFAULT_CASCADE_SEATS_PER_NODE)]
    cascade_seats_per_node: u32,
    /// Uplinks to other nodes this node holds at once.
    #[arg(long, env = "VCALL_CASCADE_UPLINKS", default_value_t = vcall::sfu::DEFAULT_CASCADE_UPLINKS)]
    cascade_uplinks: usize,
    /// Joins with a home one address may make in ten minutes, on a public node.
    #[arg(long, env = "VCALL_CASCADE_JOINS_PER_IP", default_value_t = vcall::cascade::DEFAULT_CASCADE_JOINS_PER_IP)]
    cascade_joins_per_ip: u32,
    /// Relay to loopback and private addresses. For tests on one machine;
    /// on the internet this opens the network behind the node.
    #[arg(long, env = "VCALL_UNSAFE_RELAY_TO_PRIVATE")]
    unsafe_relay_to_private: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TransportArg {
    Udp,
    Tcp,
    Tls,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node (what happens with no command at all).
    Node(Box<NodeArgs>),
    /// Print the node's id; with --addr, the full reference a client takes.
    Id {
        #[arg(long, env = "VCALL_DATA", default_value = "data")]
        data: PathBuf,
        /// The public address of the node's TLS port, `address:port`.
        #[arg(long)]
        addr: Option<SocketAddr>,
        /// A new TLS key and certificate over it; the id stays.
        #[arg(long)]
        renew_cert: bool,
    },
    /// Try a node from outside: credentials, STUN, an allocation, and a
    /// packet relayed through it both ways.
    Probe {
        /// The node: `address:port#id`, as `vcall id --addr` prints it.
        node: NodeRef,
        #[arg(long, value_enum, default_value_t = TransportArg::Udp)]
        transport: TransportArg,
        /// The access key of a private node.
        #[arg(long, env = "VCALL_ACCESS_KEY")]
        access_key: Option<String>,
    },
    /// Try a node's SFU from outside: a room, two participants of this
    /// process in it, RTP and bytes between them, the token changed, a
    /// third kept out.
    RoomTest {
        /// The node: `address:port#id`, as `vcall id --addr` prints it.
        node: NodeRef,
        /// The access key of a private node.
        #[arg(long, env = "VCALL_ACCESS_KEY")]
        access_key: Option<String>,
    },
    /// Try the cascade between two nodes from outside: a room on the
    /// home, one participant there, one on the other node through it;
    /// audio and bytes both ways, the proxy seat given up by its home
    /// token.
    CascadeTest {
        /// The home: `address:port#id`.
        home: NodeRef,
        /// The participant's own node: `address:port#id`.
        own: NodeRef,
        /// The access key of the own node, when it is private.
        #[arg(long, env = "VCALL_ACCESS_KEY")]
        access_key: Option<String>,
    },
    /// Load a node from outside: synthetic participants in rooms of its
    /// SFU and streams through its TURN, each counting what it gets; the
    /// node's CPU and memory alongside (`spec/load.md`).
    Load(Box<LoadArgs>),
    /// Ask the running node.
    Ctl {
        #[arg(long, env = "VCALL_CTL", default_value = "/run/vcall/ctl.sock")]
        socket: PathBuf,
        #[command(subcommand)]
        what: CtlCommand,
    },
}

#[derive(Args, Clone)]
struct LoadArgs {
    /// The node: `address:port#id`, as `vcall id --addr` prints it.
    node: NodeRef,
    /// The access key of a private node.
    #[arg(long, env = "VCALL_ACCESS_KEY")]
    access_key: Option<String>,
    /// Rooms of the SFU to fill.
    #[arg(long, default_value_t = 1)]
    rooms: usize,
    /// Participants in each room.
    #[arg(long, default_value_t = 4)]
    per_room: u32,
    /// Audio alone, no video.
    #[arg(long)]
    audio_only: bool,
    /// What each participant's audio takes, kbit/s, in 20 ms packets.
    #[arg(long, default_value_t = 48)]
    audio_kbps: u32,
    /// What each participant's video takes, kbit/s, in frames at --fps,
    /// packets of --mtu bytes at the most.
    #[arg(long, default_value_t = 600)]
    video_kbps: u32,
    #[arg(long, default_value_t = 30)]
    fps: u32,
    #[arg(long, default_value_t = load::DEFAULT_MTU)]
    mtu: usize,
    /// The SFU over TCP, as a client behind a network that drops UDP.
    #[arg(long)]
    sfu_tcp: bool,
    /// TURN streams: each is two allocations of the node sending to each
    /// other through it, as two callers on the relay.
    #[arg(long, default_value_t = 0)]
    turn: usize,
    /// What each TURN endpoint sends, kbit/s: audio at --audio-kbps, the
    /// rest as video at --fps; audio alone at or under --audio-kbps.
    #[arg(long, default_value_t = 648)]
    turn_kbps: u32,
    #[arg(long, value_enum, default_value_t = TransportArg::Udp)]
    turn_transport: TransportArg,
    /// ChannelData instead of Send indications.
    #[arg(long)]
    turn_channel: bool,
    /// How long to hold the load once everybody is in, seconds.
    #[arg(long, default_value_t = 30)]
    duration: u64,
    /// `n/t`: n more participants every t seconds, until the rooms are
    /// full or --max-loss or --max-cpu is passed; all at once without it.
    #[arg(long)]
    ramp: Option<load::Ramp>,
    /// Stop adding participants past this loss over one report, percent; 0 for never.
    #[arg(long, default_value_t = 2.0)]
    max_loss: f64,
    /// Stop adding participants past this CPU of the node's machine, percent; 0 for never.
    #[arg(long, default_value_t = 80.0)]
    max_cpu: f64,
    /// A line every so many seconds.
    #[arg(long, default_value_t = 5)]
    report: u64,
    /// The node runs on this machine as this process: its CPU and memory
    /// are read from /proc.
    #[arg(long)]
    node_pid: Option<u32>,
    /// The node runs where this ssh command reaches (`ssh -i key root@host`):
    /// its CPU, memory and `ctl stats` are read there every report.
    #[arg(long)]
    ssh: Option<String>,
    /// The `vcall` binary and the control socket where the node runs, for
    /// `ctl stats` there; this binary with --node-pid.
    #[arg(long, default_value = "/opt/vcall/bin/vcall")]
    node_bin: String,
    #[arg(long, default_value = "/run/vcall/ctl.sock")]
    node_ctl: String,
}

impl LoadArgs {
    fn options(self) -> anyhow::Result<load::Options> {
        let video = (!self.audio_only).then_some(load::Video { kbps: self.video_kbps, fps: self.fps.max(1) });
        let shape = load::Shape { audio_kbps: self.audio_kbps, video, mtu: self.mtu.max(1) };
        let turn_shape = if self.turn_kbps > self.audio_kbps {
            load::Shape { audio_kbps: self.audio_kbps, video: Some(load::Video { kbps: self.turn_kbps - self.audio_kbps, fps: self.fps.max(1) }), mtu: self.mtu.max(1) }
        } else {
            load::Shape { audio_kbps: self.turn_kbps.max(1), video: None, mtu: self.mtu.max(1) }
        };
        let turn_transport = match self.turn_transport {
            TransportArg::Udp => Transport::Udp,
            TransportArg::Tcp => Transport::Tcp,
            TransportArg::Tls => Transport::Tls,
        };
        let prefix: Vec<String> = self.ssh.as_deref().unwrap_or("").split_whitespace().map(str::to_string).collect();
        let watch = match (prefix.is_empty(), self.node_pid) {
            (true, None) => load::Watch::default(),
            (true, Some(pid)) => load::Watch {
                prefix,
                pid: Some(pid),
                vcall: Some(std::env::current_exe().map(|p| p.display().to_string()).unwrap_or(self.node_bin.clone())),
                ctl: Some(self.node_ctl.clone()),
            },
            (false, pid) => load::Watch { prefix, pid, vcall: Some(self.node_bin.clone()), ctl: Some(self.node_ctl.clone()) },
        };
        anyhow::ensure!(self.rooms > 0 || self.turn > 0, "nothing to load: --rooms or --turn");
        Ok(load::Options {
            node: self.node,
            access_key: self.access_key,
            rooms: self.rooms,
            per_room: self.per_room,
            shape,
            sfu_tcp: self.sfu_tcp,
            turn: self.turn,
            turn_shape,
            turn_transport,
            turn_channel: self.turn_channel,
            duration: Duration::from_secs(self.duration),
            ramp: self.ramp,
            max_loss_pct: self.max_loss,
            max_cpu_pct: self.max_cpu,
            report_every: Duration::from_secs(self.report.max(1)),
            watch,
            quiet: false,
        })
    }
}

#[derive(Subcommand)]
enum CtlCommand {
    /// Allocations, bytes, refusals by reason.
    Stats,
    Health,
    /// An invitation to this (private) node: a link to give the person
    /// invited, good for so many devices and so long.
    Invite {
        /// How many devices may take it.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// How long it is good for: `7d`, `12h`, `30m`, or seconds.
        #[arg(long, default_value = "7d")]
        ttl: String,
        /// A word for `vcall ctl devices`: whose invitation it is.
        #[arg(long, default_value = "")]
        label: String,
    },
    /// The devices let in by invitation, and the invitations still open.
    Devices,
    /// A device out, by its id (`devices` shows them); or an invitation
    /// withdrawn, by the hash `devices` shows.
    Revoke { id: String },
}

fn read_keys(path: &PathBuf) -> anyhow::Result<Vec<String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect())
}

async fn run_node(args: NodeArgs) -> anyhow::Result<()> {
    let identity = identity::load_or_create(&args.data)?;
    let id = identity::node_id(&identity)?;
    let turn_secret = vcall::turn::auth::load_or_create_secret(&args.data)?;
    let public_ip = match args.public_ip {
        Some(ip) => ip,
        None => {
            let ip = vcall::detect_public_ip().context("cannot tell the public address: set VCALL_PUBLIC_IP")?;
            let private = match ip {
                IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
            };
            if private {
                tracing::warn!(%ip, "the address this machine leaves by is private: set VCALL_PUBLIC_IP, or relayed addresses will be unreachable");
            }
            ip
        }
    };
    let access_keys = match &args.access_keys {
        Some(path) => read_keys(path)?,
        None => Vec::new(),
    };
    if args.unsafe_relay_to_private {
        tracing::warn!("relaying to private addresses: the network behind this node is open to its clients");
    }
    let signing_key = identity::signing_key(&args.data)?;
    let cascade = match args.cascade.trim() {
        "on" | "" => vcall::sfu::CascadeMode::On,
        "off" => vcall::sfu::CascadeMode::Off,
        "registry" => vcall::sfu::CascadeMode::Registry,
        path => vcall::sfu::CascadeMode::List(read_keys(&PathBuf::from(path))?.into_iter().map(|id| id.to_ascii_lowercase()).collect()),
    };
    if cascade == vcall::sfu::CascadeMode::Registry && args.registry.is_none() {
        anyhow::bail!("VCALL_CASCADE=registry needs the registry (VCALL_REGISTRY), or no node is trusted");
    }
    anyhow::ensure!(
        args.registry_root.len() == 64 && args.registry_root.bytes().all(|b| b.is_ascii_hexdigit()),
        "VCALL_REGISTRY_ROOT is not a key: 64 hex characters"
    );
    let node = Node::bind(Config {
        identity,
        signing_key: std::sync::Arc::new(identity::signing_key(&args.data)?),
        turn_secret,
        listen: args.listen,
        turn_listen: args.turn_listen,
        sfu_listen: args.sfu_listen,
        public_ip,
        public_port: args.public_port,
        relay_ports: vcall::parse_port_range(&args.relay_ports)?,
        realm: args.realm,
        private: args.private,
        access_keys,
        devices: Some(vcall::devices::file_in(&args.data)),
        issuers: args.issuers,
        max_connections: args.max_connections,
        max_connections_per_ip: args.max_connections_per_ip.max(1),
        control_idle: vcall::CONTROL_IDLE,
        max_mbps: args.max_mbps,
        turn_mbps: args.turn_max_mbps,
        kbps_per_allocation: args.turn_alloc_kbps,
        max_allocations: args.turn_max_allocations,
        max_per_ip: args.turn_max_per_ip,
        max_lifetime: Duration::from_secs(args.turn_max_lifetime.max(60)),
        credentials_ttl: Duration::from_secs(args.credentials_ttl.max(60)),
        credentials_per_ip: args.credentials_per_ip,
        max_rooms: args.rooms_max,
        room_max_participants: args.room_max,
        room_kbps_per_participant: args.room_kbps,
        room_lifetime: vcall::sfu::ROOM_LIFETIME,
        room_idle: vcall::sfu::ROOM_IDLE,
        room_connect_timeout: vcall::sfu::ROOM_CONNECT,
        room_offer_timeout: vcall::sfu::OFFER_TIMEOUT,
        room_audio_n: args.room_audio_n,
        room_bwe_kbps: args.room_bwe_kbps,
        cascade: cascade.clone(),
        cascade_seats_per_node: args.cascade_seats_per_node,
        cascade_uplinks: args.cascade_uplinks,
        cascade_joins_per_ip: args.cascade_joins_per_ip,
        allow_private_peers: args.unsafe_relay_to_private,
        ctl: Some(args.ctl.unwrap_or_else(|| args.data.join("ctl.sock"))),
    })
    .await?;
    let addrs = node.addrs()?;
    tracing::info!(
        control = %addrs.control,
        turn = %addrs.turn_udp,
        sfu = %addrs.sfu,
        %public_ip,
        relay_ports = %args.relay_ports,
        private = args.private,
        cascade = args.cascade.trim(),
        %id,
        "node is up"
    );

    // A public node tells the registry about itself; a private one is for
    // the people who hold its key, and stays unlisted.
    match (&args.registry, args.private) {
        (Some(registry), false) => {
            let registrar = Registrar {
                registry: registry.clone(),
                id: id.to_string(),
                key: signing_key,
                public_ip,
                control_port: args.public_port.unwrap_or(addrs.control.port()),
                turn_port: addrs.turn_udp.port(),
                sfu_port: addrs.sfu.port(),
                region: args.region.clone(),
                caps: vcall::capabilities(cascade.is_on()),
                max_allocations: args.turn_max_allocations as u32,
                max_participants: (args.rooms_max as u32).saturating_mul(args.room_max),
                max_mbps: args.max_mbps as u32,
                max_rooms: args.rooms_max as u32,
                max_uplinks: args.cascade_uplinks as u32,
                handle: node.handle(),
            };
            tokio::spawn(registrar.run());
        }
        (Some(_), true) => tracing::info!("a private node: the registry is not told"),
        (None, _) => {}
    }
    // Public or private, a node in the cascade takes the registry's list
    // of nodes: whom it gives seats without the quota, or at all.
    if let Some(registry) = &args.registry {
        let handle = node.handle();
        if handle.trust.wants_list() {
            let fetcher = vcall::trust::ListFetcher {
                registry: registry.clone(),
                root_hex: args.registry_root.to_ascii_lowercase(),
                cache: Some(args.data.join(vcall::trust::LIST_FILE)),
                trust: handle.trust.clone(),
                counters: handle.counters.clone(),
            };
            tokio::spawn(fetcher.run());
        }
    }

    let handle = node.handle();
    tokio::spawn(async move {
        // A line a minute: enough to see from the log that the node works.
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let c = handle.counters.snapshot();
            tracing::info!(
                allocations = handle.turn.active(),
                made = c.allocations,
                credentials = c.credentials_issued,
                to_peers = c.bytes_to_peers,
                to_clients = c.bytes_to_clients,
                forbidden = c.refused_forbidden_peer,
                bad_credentials = c.refused_bad_credentials,
                rooms = handle.sfu.rooms_now(),
                participants = handle.sfu.participants_now(),
                sfu_in = c.sfu_bytes_in,
                sfu_out = c.sfu_bytes_out,
                "status"
            );
        }
    });

    tokio::select! {
        r = node.run() => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
    }
    Ok(())
}

fn ms(since: Instant) -> String {
    format!("{:.1} ms", since.elapsed().as_secs_f64() * 1000.0)
}

/// Unix seconds as `YYYY-MM-DD HH:MM UTC` (Howard Hinnant's civil-from-days).
fn human_time(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", secs / 3600, secs % 3600 / 60)
}

/// What a client does, from outside: the whole way to a relayed packet.
async fn probe(node: NodeRef, transport: Transport, access_key: Option<String>) -> anyhow::Result<()> {
    let access = Access { key: access_key, ..Access::default() };
    let t = Instant::now();
    let mut control = ControlClient::connect(&node).await.context("the control channel")?;
    println!("control   {}  tls+h2 in {}", node.addr, ms(t));

    let welcome = control
        .hello(&client::hello(access.clone(), &format!("vcall-probe/{}", vcall::VERSION)))
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("hello refused: {status} {}: {}", r.error, r.message))?;
    anyhow::ensure!(welcome.node_id == node.id.to_string(), "the node says it is {}, not {}", welcome.node_id, node.id);
    println!(
        "node      v{}  protocol {}..{}  {}{}",
        welcome.version,
        welcome.protocol_min,
        welcome.protocol_max,
        welcome.capabilities.join(","),
        if welcome.private { "  private" } else { "" }
    );
    println!(
        "limits    lifetime {} s, {} kbit/s per allocation, credentials {} s",
        welcome.limits.turn_lifetime_secs, welcome.limits.turn_kbps_per_allocation, welcome.limits.credentials_ttl_secs
    );
    let creds = control.turn(access).await?.map_err(|(status, r)| anyhow::anyhow!("credentials refused: {status} {}: {}", r.error, r.message))?;
    println!("creds     {}  good for {} s", creds.username, creds.ttl_secs);
    for url in &creds.urls {
        println!("          {url}");
    }
    let endpoints = Endpoints::of(&creds.urls);
    let turn_addr = endpoints.for_transport(transport).with_context(|| format!("the node offers no TURN over {}", transport.name()))?;
    let stun_addr = endpoints.stun.context("the node offers no STUN")?;

    // STUN, then the allocation.
    let mut a = TurnClient::connect(turn_addr, transport, Some(node.id)).await.with_context(|| format!("TURN over {}", transport.name()))?;
    let t = Instant::now();
    let mapped = a.binding().await.context("STUN binding")?;
    println!("stun      {}  this side is {mapped}  in {}", transport.name(), ms(t));
    a.set_credentials(&creds.username, &creds.password);
    let t = Instant::now();
    let alloc = a.allocate(None).await.context("TURN allocate")?;
    println!("allocate  relayed {}  lifetime {} s  in {}", alloc.relayed, alloc.lifetime, ms(t));

    // The peer: a plain socket here, its address as the node sees it. The
    // permission is for the address (RFC 8656: the port is not looked at).
    let peer = UdpSocket::bind(if stun_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
    let peer_addr = client::binding_from(&peer, stun_addr).await.context("STUN for the peer socket")?;
    println!("peer      {peer_addr}  (by STUN)");
    if let Err(e) = a.create_permission(&[peer_addr]).await {
        if e.code() == Some(403) {
            anyhow::bail!(
                "permission refused (403): the peer address {peer_addr} is not public. Run the probe from another machine than the node, outside its network"
            );
        }
        return Err(e).context("CreatePermission");
    }

    // The peer speaks first, towards the relayed address: a NAT in front
    // of this machine lets the relay port answer only through a mapping
    // the peer opened, and what the node sees the packet come from (the
    // port may differ from the one STUN saw: a symmetric NAT) is where
    // the client then sends.
    let mut buf = vec![0u8; 2048];
    let t = Instant::now();
    peer.send_to(b"vcall probe: punch", alloc.relayed).await?;
    let seen = match a.recv(Duration::from_secs(5)).await {
        Ok(Incoming::Data { peer: seen, data }) if data == b"vcall probe: punch" => seen,
        Ok(other) => anyhow::bail!("something else came from the peer: {other:?}"),
        Err(_) => anyhow::bail!(
            "nothing from the peer socket reached the node's relay port {}: a symmetric NAT in front of this machine (run the probe from a host with a public address), or the relay ports are closed on the node",
            alloc.relayed
        ),
    };
    if seen != peer_addr {
        println!("peer      {seen}  as the relay port sees it (a NAT maps each destination anew; handled)");
    }
    a.send(seen, b"vcall probe: send").await?;
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .context("nothing reached the peer from the relay port, though the peer reached it: a firewall on this machine?")??;
    anyhow::ensure!(from == alloc.relayed && &buf[..n] == b"vcall probe: send", "the peer got something else: {} bytes from {from}", n);
    peer.send_to(b"vcall probe: back", alloc.relayed).await?;
    match a.recv(Duration::from_secs(5)).await.context("nothing came back from the peer")? {
        Incoming::Data { peer: p, data } if p == seen && data == b"vcall probe: back" => {}
        other => anyhow::bail!("something else came back: {other:?}"),
    }
    println!("relay     send/data both ways in {}", ms(t));
    let peer_addr = seen;

    let t = Instant::now();
    a.channel_bind(0x4000, peer_addr).await.context("ChannelBind")?;
    a.send_channel(0x4000, b"vcall probe: channel").await?;
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await.context("nothing reached the peer over the channel")??;
    anyhow::ensure!(from == alloc.relayed && &buf[..n] == b"vcall probe: channel", "the peer got something else over the channel");
    peer.send_to(b"vcall probe: channel back", alloc.relayed).await?;
    match a.recv(Duration::from_secs(5)).await.context("nothing came back over the channel")? {
        Incoming::Channel { number: 0x4000, data } if data == b"vcall probe: channel back" => {}
        other => anyhow::bail!("something else came back: {other:?}"),
    }
    println!("channel   both ways in {}", ms(t));

    let left = a.refresh(0).await.context("Refresh 0")?;
    anyhow::ensure!(left == 0, "the allocation did not end");
    println!("ok        the node relays");
    Ok(())
}

/// What a group does, from outside: a room, two participants through it.
async fn room_test(node: NodeRef, access_key: Option<String>) -> anyhow::Result<()> {
    const WAIT: Duration = Duration::from_secs(15);
    let access = Access { key: access_key, ..Access::default() };
    let t = Instant::now();
    let mut control = ControlClient::connect(&node).await.context("the control channel")?;
    let welcome = control
        .hello(&client::hello(access.clone(), &format!("vcall-room-test/{}", vcall::VERSION)))
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("hello refused: {status} {}: {}", r.error, r.message))?;
    anyhow::ensure!(welcome.capabilities.iter().any(|c| c == capability::SFU), "the node has no SFU: {}", welcome.capabilities.join(","));
    println!("node      v{}  {}  codecs {}  in {}", welcome.version, welcome.capabilities.join(","), welcome.codecs.join(","), ms(t));
    println!(
        "limits    {} seats, {} kbit/s a seat, a room lives {} s, stands empty {} s",
        welcome.limits.room_max_participants,
        welcome.limits.room_kbps_per_participant,
        welcome.limits.room_lifetime_secs,
        welcome.limits.room_idle_secs
    );

    let t = Instant::now();
    let room: RoomCreated = control
        .post(rooms::PATH_ROOMS, &RoomRequest { access, media_limits: MediaLimits::default() })
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("room refused: {status} {}: {}", r.error, r.message))?;
    println!("room      {}  sfu {} udp, {} tcp  in {}", room.room_id, room.sfu_udp, room.sfu_tcp, ms(t));

    let t = Instant::now();
    let mut a = RoomClient::join(&node, &room.room_id, &room.join_token, true, SfuTransport::Udp).await.context("a joins")?;
    let mut b = RoomClient::join(&node, &room.room_id, &room.join_token, false, SfuTransport::Udp).await.context("b joins")?;
    anyhow::ensure!(b.participants == vec![a.participant_id], "b was told of {:?}, not of a", b.participants);
    println!("joined    a = {}, b = {}  in {}", a.participant_id, b.participant_id, ms(t));
    let t = Instant::now();
    for (name, c) in [("a", &mut a), ("b", &mut b)] {
        c.wait_for(WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.with_context(|| format!("{name} did not connect to the SFU"))?;
        c.wait_for(WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.with_context(|| format!("ctl of {name} did not open"))?;
    }
    println!("connected both, ctl open  in {}", ms(t));

    // The node offers each the other's streams; the m-lines are named.
    let t = Instant::now();
    let (a_id, b_id) = (a.participant_id, b.participant_id);
    let a_mids = b.wait_for(WAIT, |e| match e {
        RoomEvent::Tracks(tracks) if tracks.iter().any(|t| t.id == a_id && t.kind == "audio") => Some(tracks.clone()),
        _ => None,
    });
    let b_mids = a.wait_for(WAIT, |e| match e {
        RoomEvent::Tracks(tracks) if tracks.iter().any(|t| t.id == b_id && t.kind == "audio") => Some(tracks.clone()),
        _ => None,
    });
    let (a_mids, b_mids) = tokio::join!(a_mids, b_mids);
    let a_at_b = a_mids.context("b was not offered a's streams")?;
    let b_at_a = b_mids.context("a was not offered b's streams")?;
    let a_audio_at_b = a_at_b.iter().find(|t| t.kind == "audio").map(|t| t.mid.clone()).context("no audio of a at b")?;
    let a_video_at_b = a_at_b.iter().find(|t| t.kind == "video").map(|t| t.mid.clone()).context("no video of a at b")?;
    let b_audio_at_a = b_at_a.iter().find(|t| t.kind == "audio").map(|t| t.mid.clone()).context("no audio of b at a")?;
    println!("tracks    a's audio at b on mid {a_audio_at_b}, a's video on {a_video_at_b}; b's audio at a on {b_audio_at_a}  in {}", ms(t));

    // RTP both ways: payloads as given, in order, the audio level with them.
    let t = Instant::now();
    let mut got_b = 0;
    let mut got_a = 0;
    let mut got_video = 0;
    for i in 0..50u8 {
        a.send_audio(&[0xA0, i], Some(-20)).await;
        b.send_audio(&[0xB0, i], Some(-30)).await;
        a.send_video(&[0x90, i, 0, 0], i % 5 == 4).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Counted until all are in, or a second passes with nothing more.
    let until = Instant::now() + WAIT;
    while (got_b < 50 || got_a < 50 || got_video < 50) && Instant::now() < until {
        tokio::select! {
            Some(e) = b.next(Duration::from_secs(1)) => if let RoomEvent::Rtp { mid, payload, audio_level, .. } = e {
                if mid == a_audio_at_b && payload.first() == Some(&0xA0) && audio_level == Some(-20) { got_b += 1 }
                if mid == a_video_at_b && payload.first() == Some(&0x90) { got_video += 1 }
            },
            Some(e) = a.next(Duration::from_secs(1)) => if let RoomEvent::Rtp { mid, payload, audio_level, .. } = e {
                if mid == b_audio_at_a && payload.first() == Some(&0xB0) && audio_level == Some(-30) { got_a += 1 }
            },
            else => break,
        }
    }
    anyhow::ensure!(got_b >= 40 && got_a >= 40 && got_video >= 40, "of 50 packets each: a→b audio {got_b}, b→a audio {got_a}, a→b video {got_video}");
    println!("rtp       a→b audio {got_b}/50, video {got_video}/50; b→a audio {got_a}/50  in {}", ms(t));

    // Bytes over ctl, the sender named by the node.
    let t = Instant::now();
    a.send_bytes(b"who i am, signed").await;
    let from = b.wait_for(WAIT, |e| match e {
        RoomEvent::Bytes { from, data } if data == b"who i am, signed" => Some(*from),
        _ => None,
    });
    anyhow::ensure!(from.await == Some(a.participant_id), "b did not get a's bytes");
    println!("ctl       a's bytes reached b  in {}", ms(t));

    // The admin changes the token: the old one lets nobody in, the new one does.
    let t = Instant::now();
    let changed: TokenChanged = control
        .post(&format!("{}/{}/{}", rooms::PATH_ROOMS, room.room_id, rooms::action::TOKEN), &TokenRequest { admin_token: room.admin_token.clone() })
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("token change refused: {status} {}: {}", r.error, r.message))?;
    let old = RoomClient::join(&node, &room.room_id, &room.join_token, false, SfuTransport::Udp).await;
    anyhow::ensure!(old.as_ref().err().is_some_and(|e| e.to_string().contains("403")), "the old token still lets in: {:?}", old.map(|_| ()));
    // The third comes over TCP, as a client behind a network that drops UDP would.
    let sfu_tcp: SocketAddr = room.sfu_tcp.parse().context("the room's sfu_tcp")?;
    let mut c = RoomClient::join(&node, &room.room_id, &changed.join_token, false, SfuTransport::Tcp(sfu_tcp)).await.context("c joins with the new token")?;
    c.wait_for(WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.context("c did not connect")?;
    let seen_c = b.wait_for(WAIT, |e| matches!(e, RoomEvent::Joined(id) if *id == c.participant_id).then_some(()));
    anyhow::ensure!(seen_c.await.is_some(), "b did not hear that c joined");
    println!("token     changed; the old one refused (403), c in with the new, over tcp  in {}", ms(t));

    // Leaving: by request and by closing.
    let t = Instant::now();
    c.leave(&node, &room.room_id).await.context("c leaves")?;
    let left_c = b.wait_for(WAIT, |e| matches!(e, RoomEvent::Left(id) if *id == c.participant_id).then_some(()));
    anyhow::ensure!(left_c.await.is_some(), "b did not hear that c left");
    a.close().await;
    let left_a = b.wait_for(Duration::from_secs(40), |e| matches!(e, RoomEvent::Left(id) if *id == a.participant_id).then_some(()));
    anyhow::ensure!(left_a.await.is_some(), "b did not hear that a left after a closed");
    println!("left      c by request, a by closing; b told of both  in {}", ms(t));
    b.close().await;
    println!("ok        the node's SFU forwards");
    Ok(())
}

/// What the cascade does, from outside: a seat of the home's room taken
/// through another node.
async fn cascade_test(home: NodeRef, own: NodeRef, access_key: Option<String>) -> anyhow::Result<()> {
    const WAIT: Duration = Duration::from_secs(15);
    let t = Instant::now();
    let mut control = ControlClient::connect(&home).await.context("the control channel of the home")?;
    let welcome = control
        .hello(&client::hello(Access::default(), &format!("vcall-cascade-test/{}", vcall::VERSION)))
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("hello refused: {status} {}: {}", r.error, r.message))?;
    anyhow::ensure!(welcome.capabilities.iter().any(|c| c == capability::CASCADE), "the home takes no uplinks: {}", welcome.capabilities.join(","));
    let mut own_control = ControlClient::connect(&own).await.context("the control channel of the own node")?;
    let own_welcome = own_control
        .hello(&client::hello(Access { key: access_key.clone(), ..Access::default() }, &format!("vcall-cascade-test/{}", vcall::VERSION)))
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("hello refused by the own node: {status} {}: {}", r.error, r.message))?;
    anyhow::ensure!(own_welcome.capabilities.iter().any(|c| c == capability::CASCADE), "the own node has no cascade: {}", own_welcome.capabilities.join(","));
    println!("home      v{}  {}  in {}", welcome.version, welcome.capabilities.join(","), ms(t));
    println!("own       v{}  {}", own_welcome.version, own_welcome.capabilities.join(","));

    let t = Instant::now();
    let room: RoomCreated = control
        .post(rooms::PATH_ROOMS, &RoomRequest { access: Access::default(), media_limits: MediaLimits::default() })
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("room refused: {status} {}: {}", r.error, r.message))?;
    println!("room      {}  on the home  in {}", room.room_id, ms(t));

    let t = Instant::now();
    let mut a = RoomClient::join(&home, &room.room_id, &room.join_token, false, SfuTransport::Udp).await.context("a joins the home")?;
    let pass = RoomClient::delegate(&home, &room.room_id, &room.join_token)
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("pass refused: {status} {}: {}", r.error, r.message))?;
    println!("pass      {}…  good for {} s  in {}", &pass.proxy_token[..8], pass.expires_at.saturating_sub(vcall::turn::unix_now()), ms(t));
    let t = Instant::now();
    let options = vcall::room_client::JoinOptions { home: Some(home.clone()), access_key, ..Default::default() };
    let mut b = RoomClient::join_with(&own, &room.room_id, &pass.proxy_token, options).await.context("b joins through the own node")?;
    anyhow::ensure!(b.participants == vec![a.participant_id], "b was told of {:?}, not of a", b.participants);
    anyhow::ensure!(b.home_token.is_some(), "no home token in b's answer");
    println!("joined    a = {} on the home, b = {} through the own node (home token given)  in {}", a.participant_id, b.participant_id, ms(t));
    let t = Instant::now();
    for (name, c) in [("a", &mut a), ("b", &mut b)] {
        c.wait_for(WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.with_context(|| format!("{name} did not connect"))?;
        c.wait_for(WAIT, |e| matches!(e, RoomEvent::CtlOpen).then_some(())).await.with_context(|| format!("ctl of {name} did not open"))?;
    }
    println!("connected both, ctl open  in {}", ms(t));

    let t = Instant::now();
    let (a_id, b_id) = (a.participant_id, b.participant_id);
    let a_at_b = b.wait_for(WAIT, |e| match e {
        RoomEvent::Tracks(tracks) => tracks.iter().find(|t| t.id == a_id && t.kind == "audio").map(|t| t.mid.clone()),
        _ => None,
    });
    let b_at_a = a.wait_for(WAIT, |e| match e {
        RoomEvent::Tracks(tracks) => tracks.iter().find(|t| t.id == b_id && t.kind == "audio").map(|t| t.mid.clone()),
        _ => None,
    });
    let (a_at_b, b_at_a) = tokio::join!(a_at_b, b_at_a);
    let a_at_b = a_at_b.context("b was not offered a's audio (down the uplink)")?;
    let b_at_a = b_at_a.context("a was not offered b's audio (up the uplink)")?;
    println!("tracks    a's audio at b on mid {a_at_b}, b's audio at a on mid {b_at_a}  in {}", ms(t));

    let t = Instant::now();
    let (mut got_b, mut got_a) = (0, 0);
    for i in 0..50u8 {
        a.send_audio(&[0xA0, i], Some(-20)).await;
        b.send_audio(&[0xB0, i], Some(-30)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let until = Instant::now() + WAIT;
    while (got_b < 50 || got_a < 50) && Instant::now() < until {
        tokio::select! {
            Some(e) = b.next(Duration::from_secs(1)) => if let RoomEvent::Rtp { mid, payload, audio_level, .. } = e {
                if mid == a_at_b && payload.first() == Some(&0xA0) && audio_level == Some(-20) { got_b += 1 }
            },
            Some(e) = a.next(Duration::from_secs(1)) => if let RoomEvent::Rtp { mid, payload, audio_level, .. } = e {
                if mid == b_at_a && payload.first() == Some(&0xB0) && audio_level == Some(-30) { got_a += 1 }
            },
            else => break,
        }
    }
    anyhow::ensure!(got_b >= 40 && got_a >= 40, "of 50 packets each: a→b {got_b}, b→a {got_a}");
    println!("rtp       a→b {got_b}/50 down the uplink, b→a {got_a}/50 up it  in {}", ms(t));

    let t = Instant::now();
    a.send_bytes(b"from a").await;
    b.send_bytes(b"from b").await;
    let at_b = b.wait_for(WAIT, |e| matches!(e, RoomEvent::Bytes { from, data } if *from == a_id && data == b"from a").then_some(()));
    let at_a = a.wait_for(WAIT, |e| matches!(e, RoomEvent::Bytes { from, data } if *from == b_id && data == b"from b").then_some(()));
    let (at_b, at_a) = tokio::join!(at_b, at_a);
    anyhow::ensure!(at_b.is_some() && at_a.is_some(), "bytes did not reach both ways");
    println!("ctl       bytes both ways  in {}", ms(t));

    let t = Instant::now();
    b.leave_home(&home, &room.room_id).await.context("b gives its seat up at the home")?;
    let left = a.wait_for(WAIT, |e| matches!(e, RoomEvent::Left(id) if *id == b_id).then_some(()));
    anyhow::ensure!(left.await.is_some(), "a did not hear that b left");
    let closed = b.wait_for(WAIT, |e| matches!(e, RoomEvent::Closed).then_some(()));
    anyhow::ensure!(closed.await.is_some(), "b's own node did not close b after the home gave the seat up");
    println!("left      b by its home token: a told, b closed by its node  in {}", ms(t));
    a.close().await;
    println!("ok        the cascade carries");
    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        None => run_node(cli.node).await,
        Some(Command::Node(args)) => run_node(*args).await,
        Some(Command::Id { data, addr, renew_cert }) => {
            let identity = if renew_cert { identity::renew(&data)? } else { identity::load_or_create(&data)? };
            let id = identity::node_id(&identity)?;
            match addr {
                Some(addr) => println!("{}", NodeRef { addr, id, sni: None }),
                None => println!("{id}"),
            }
            Ok(())
        }
        Some(Command::Probe { node, transport, access_key }) => {
            let transport = match transport {
                TransportArg::Udp => Transport::Udp,
                TransportArg::Tcp => Transport::Tcp,
                TransportArg::Tls => Transport::Tls,
            };
            probe(node, transport, access_key).await
        }
        Some(Command::RoomTest { node, access_key }) => room_test(node, access_key).await,
        Some(Command::CascadeTest { home, own, access_key }) => cascade_test(home, own, access_key).await,
        Some(Command::Load(args)) => load::run(args.options()?).await.map(|_| ()),
        Some(Command::Ctl { socket, what }) => {
            let invite = matches!(what, CtlCommand::Invite { .. });
            let request = match what {
                CtlCommand::Stats => ctl::Request::Stats,
                CtlCommand::Health => ctl::Request::Health,
                CtlCommand::Invite { uses, ttl, label } => ctl::Request::Invite { uses, ttl_secs: vcall::devices::parse_ttl(&ttl)?.as_secs(), label },
                CtlCommand::Devices => ctl::Request::Devices,
                CtlCommand::Revoke { id } => ctl::Request::Revoke { id },
            };
            let response = ctl::call(&socket, &request).await?;
            match (response.ok, response.data, response.error) {
                // An invitation: the link on a line of its own, to be copied.
                (true, Some(data), _) if invite => {
                    let invited: ctl::Invited = serde_json::from_value(data)?;
                    println!("{}", invited.link);
                    eprintln!(
                        "good for {} device{} until {} (unix {}){}",
                        invited.uses,
                        if invited.uses == 1 { "" } else { "s" },
                        human_time(invited.expires_at),
                        invited.expires_at,
                        if invited.label.is_empty() { String::new() } else { format!("; label: {}", invited.label) }
                    );
                }
                (true, Some(data), _) => println!("{}", serde_json::to_string_pretty(&data)?),
                (true, None, _) => println!("ok"),
                (false, _, error) => anyhow::bail!("{}", error.unwrap_or_else(|| "refused".into())),
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    // VCALL_LOG=debug shows every allocation and refusal; the default says
    // what is up and a status line a minute.
    let level = std::env::var("VCALL_LOG").ok().and_then(|l| l.parse().ok()).unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt().with_max_level(level).with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vcall: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vcall: {e:#}");
            ExitCode::FAILURE
        }
    }
}
