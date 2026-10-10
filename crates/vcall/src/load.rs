//! `vcall load`: synthetic participants and TURN streams against a node,
//! to find what a participant and a relayed stream cost it.
//!
//! ```text
//! rooms:  N participants in each of M rooms, every one on a str0m Rtc of
//!         its own (room_client): audio 20 ms packets, video frames at a
//!         rate, each takes the others' streams and counts what came
//! turn:   K streams, each two allocations of the node relaying to each
//!         other at a rate, both ways, as two callers on the relay would
//! node:   its CPU, memory and counters, read every few seconds from
//!         /proc and `vcall ctl stats`, here or over ssh
//! ```
//!
//! The streams carry no codec: the payloads are filler of the right size
//! and pace, and the node forwards them as it would Opus and VP8 (it does
//! not look inside). What is measured is the node's work per packet and
//! per byte, which is what a real call costs it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::sync::watch;

use crate::client::{self, ControlClient, Endpoints, Incoming, TurnClient};
use crate::identity::NodeRef;
use crate::room_client::{JoinOptions, RoomClient, RoomEvent, SfuTransport};
use crate::turn::allocation::Transport;
use vcall_proto::rooms::{self, MediaLimits, RoomCreated, RoomRequest};
use vcall_proto::Access;

/// Bytes an RTP header takes (no CSRCs; the extensions are not counted).
pub const RTP_HEADER: usize = 12;
/// A video packet's payload at the most: what fits a 1280-byte datagram
/// with the headers of SRTP and the network.
pub const DEFAULT_MTU: usize = 1200;
const AUDIO_FRAME: Duration = Duration::from_millis(20);
const AUDIO_CLOCK: f64 = 48_000.0;
const VIDEO_CLOCK: f64 = 90_000.0;
const CONNECT_WAIT: Duration = Duration::from_secs(20);
/// A stream with nothing for this long is not counted among the live ones.
const STREAM_LIVE: Duration = Duration::from_secs(2);
/// How often a TURN endpoint renews its allocation, permission and
/// channel: within the node's shortest lifetime (the permission's 300 s).
const TURN_RENEW: Duration = Duration::from_secs(240);
/// The audio of this many speakers is forwarded in a room past a
/// conversation (`sfu::DEFAULT_AUDIO_N`): what a receiver should get.
const AUDIO_N: usize = crate::sfu::DEFAULT_AUDIO_N as usize;

// ---- the shape of what a participant sends ----------------------------------

/// A video stream: `kbps` in frames at `fps`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Video {
    pub kbps: u32,
    pub fps: u32,
}

/// What one participant (or one TURN endpoint) sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub audio_kbps: u32,
    pub video: Option<Video>,
    pub mtu: usize,
}

impl Shape {
    /// The payload of one 20 ms audio packet: 48 kbit/s gives 120 bytes.
    pub fn audio_payload(&self) -> usize {
        (u64::from(self.audio_kbps) * 1000 / 8 * AUDIO_FRAME.as_millis() as u64 / 1000).max(1) as usize
    }

    /// The bytes of one video frame.
    pub fn frame_bytes(&self) -> usize {
        self.video.map(|v| (u64::from(v.kbps) * 1000 / 8 / u64::from(v.fps.max(1))).max(1) as usize).unwrap_or(0)
    }

    /// The payloads of one frame's packets.
    pub fn frame_packets(&self) -> Vec<usize> {
        if self.video.is_none() {
            return Vec::new();
        }
        split_frame(self.frame_bytes(), self.mtu)
    }

    pub fn frame_interval(&self) -> Option<Duration> {
        self.video.map(|v| Duration::from_secs_f64(1.0 / f64::from(v.fps.max(1))))
    }

    /// Bits a second of audio alone, and of video alone, on the wire.
    fn audio_bps(&self) -> f64 {
        (self.audio_payload() + RTP_HEADER) as f64 * 8.0 * (1000.0 / AUDIO_FRAME.as_millis() as f64)
    }

    fn video_bps(&self) -> f64 {
        self.video
            .map(|v| self.frame_packets().iter().map(|p| (p + RTP_HEADER) as f64 * 8.0).sum::<f64>() * f64::from(v.fps))
            .unwrap_or(0.0)
    }

    /// Packets a second, audio and video.
    pub fn pps(&self) -> f64 {
        let audio = 1000.0 / AUDIO_FRAME.as_millis() as f64;
        let video = self.video.map(|v| f64::from(v.fps) * self.frame_packets().len() as f64).unwrap_or(0.0);
        audio + video
    }

    /// Bits a second on the wire, RTP headers counted.
    pub fn bps(&self) -> f64 {
        self.audio_bps() + self.video_bps()
    }

    /// Bits a second of the payloads alone: what a TURN endpoint sends,
    /// which carries no RTP header.
    pub fn payload_bps(&self) -> f64 {
        let audio = self.audio_payload() as f64 * 8.0 * (1000.0 / AUDIO_FRAME.as_millis() as f64);
        let video = self.video.map(|v| self.frame_packets().iter().map(|p| *p as f64 * 8.0).sum::<f64>() * f64::from(v.fps)).unwrap_or(0.0);
        audio + video
    }
}

/// Which room the `n`th participant (from 0) goes to when the rooms are
/// filled one after another: the slope of a ramp is then the cost of a
/// seat in a full room, not in rooms of every size at once.
pub fn room_of(n: usize, per_room: u32, rooms: usize) -> usize {
    (n / (per_room as usize).max(1)).min(rooms.saturating_sub(1))
}

/// Bits a second everybody in rooms of these sizes should get from the
/// node when all send `shape`: everybody else's video, and the audio of
/// everybody else in a conversation (up to `AUDIO_N` + 1), else of the
/// speakers alone (`AUDIO_N`, one fewer for a speaker itself).
pub fn expected_rx_bps(shape: &Shape, rooms: &[usize]) -> f64 {
    rooms
        .iter()
        .map(|&n| {
            let video = (n * n.saturating_sub(1)) as f64 * shape.video_bps();
            let audio_streams = if n > AUDIO_N + 1 { AUDIO_N * n - AUDIO_N } else { n * n.saturating_sub(1) };
            video + audio_streams as f64 * shape.audio_bps()
        })
        .sum()
}

/// An interval of `period` whose first tick comes at a random moment
/// within it, as real senders' clocks are to each other: without this
/// every participant started together sends in the same millisecond.
fn paced(period: Duration) -> tokio::time::Interval {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    let fraction = (h.finish() % 10_000) as f64 / 10_000.0;
    let mut i = tokio::time::interval_at(tokio::time::Instant::now() + period.mul_f64(fraction), period);
    i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    i
}

/// A `rx of expected` share, percent; 0 with nothing expected.
pub fn delivery_pct(rx_mbps: f64, expected_bps: f64) -> f64 {
    if expected_bps <= 0.0 {
        0.0
    } else {
        rx_mbps * 1e6 * 100.0 / expected_bps
    }
}

/// A frame of `bytes` in packets of `mtu` at the most, the last one
/// what is left; one packet, maybe empty-ish, for a tiny frame.
pub fn split_frame(bytes: usize, mtu: usize) -> Vec<usize> {
    let mtu = mtu.max(1);
    let mut out = Vec::with_capacity(bytes / mtu + 1);
    let mut left = bytes.max(1);
    while left > 0 {
        let n = left.min(mtu);
        out.push(n);
        left -= n;
    }
    out
}

/// `n/t`: `n` more participants every `t` seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ramp {
    pub step: usize,
    pub every: Duration,
}

impl std::str::FromStr for Ramp {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (n, t) = s.split_once('/').context("a ramp is n/t: so many participants every so many seconds")?;
        let step: usize = n.trim().parse().context("the ramp's n")?;
        let secs: f64 = t.trim().trim_end_matches('s').parse().context("the ramp's t")?;
        anyhow::ensure!(step > 0 && secs > 0.0, "a ramp is n/t with both above zero");
        Ok(Self { step, every: Duration::from_secs_f64(secs) })
    }
}

// ---- what a receiver counts --------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Audio,
    Video,
    /// A TURN stream: no RTP clock, no jitter.
    Data,
}

impl Kind {
    fn clock(self) -> Option<f64> {
        match self {
            Kind::Audio => Some(AUDIO_CLOCK),
            Kind::Video => Some(VIDEO_CLOCK),
            Kind::Data => None,
        }
    }
}

/// One stream as it arrives: the numbers, the bytes, the jitter of RFC
/// 3550 (6.4.1) against the sender's clock.
#[derive(Clone, Debug)]
pub struct StreamAcc {
    pub kind: Kind,
    pub first_seq: u64,
    pub max_seq: u64,
    pub received: u64,
    pub bytes: u64,
    /// In clock units, as the RFC keeps it.
    jitter: f64,
    last: Option<(u32, f64)>,
    pub last_at: Option<Instant>,
}

impl StreamAcc {
    pub fn new(kind: Kind) -> Self {
        Self { kind, first_seq: 0, max_seq: 0, received: 0, bytes: 0, jitter: 0.0, last: None, last_at: None }
    }

    /// One packet: its number, its timestamp on the sender's clock, its
    /// size, and when it came (seconds on any one clock).
    pub fn packet(&mut self, seq: u64, timestamp: u32, bytes: usize, arrival_secs: f64) {
        if self.received == 0 {
            self.first_seq = seq;
            self.max_seq = seq;
        } else if seq > self.max_seq {
            self.max_seq = seq;
        } else if seq < self.first_seq {
            self.first_seq = seq;
        }
        self.received += 1;
        self.bytes += bytes as u64;
        if let Some(clock) = self.kind.clock() {
            let arrival = arrival_secs * clock;
            if let Some((last_ts, last_arrival)) = self.last {
                let transit = arrival - f64::from(timestamp);
                let last_transit = last_arrival - f64::from(last_ts);
                let d = (transit - last_transit).abs();
                self.jitter += (d - self.jitter) / 16.0;
            }
            self.last = Some((timestamp, arrival));
        }
    }

    pub fn expected(&self) -> u64 {
        if self.received == 0 {
            0
        } else {
            self.max_seq - self.first_seq + 1
        }
    }

    pub fn lost(&self) -> u64 {
        self.expected().saturating_sub(self.received)
    }

    pub fn jitter_ms(&self) -> f64 {
        self.kind.clock().map(|c| self.jitter / c * 1000.0).unwrap_or(0.0)
    }
}

/// The streams one receiver gets, by the m-line they come on.
#[derive(Default)]
pub struct RxAcc {
    pub streams: HashMap<String, StreamAcc>,
    kinds: HashMap<String, Kind>,
    /// The timestamp of the first packet, the origin of `arrival_secs`.
    epoch: Option<Instant>,
}

impl RxAcc {
    /// The node said what m-line `mid` carries.
    pub fn track(&mut self, mid: &str, kind: &str) {
        let kind = if kind == "video" { Kind::Video } else { Kind::Audio };
        self.kinds.insert(mid.to_string(), kind);
    }

    pub fn packet(&mut self, mid: &str, seq: u64, timestamp: u32, bytes: usize, now: Instant) {
        let epoch = *self.epoch.get_or_insert(now);
        let kind = self.kinds.get(mid).copied().unwrap_or(Kind::Audio);
        let stream = self.streams.entry(mid.to_string()).or_insert_with(|| StreamAcc::new(kind));
        stream.kind = kind;
        stream.packet(seq, timestamp, bytes, now.saturating_duration_since(epoch).as_secs_f64());
        stream.last_at = Some(now);
    }

    pub fn totals(&self, now: Instant) -> Totals {
        let mut t = Totals::default();
        for s in self.streams.values() {
            let k = match s.kind {
                Kind::Audio => &mut t.audio,
                Kind::Video => &mut t.video,
                Kind::Data => &mut t.data,
            };
            k.add(s, now);
        }
        t
    }
}

/// The totals of one kind of stream over many.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct KindTotals {
    pub streams: u64,
    pub live: u64,
    pub received: u64,
    pub expected: u64,
    pub lost: u64,
    pub bytes: u64,
    /// The jitter of the live streams summed, to average over `live`.
    pub jitter_ms_sum: f64,
}

impl KindTotals {
    fn add(&mut self, s: &StreamAcc, now: Instant) {
        self.streams += 1;
        self.received += s.received;
        self.expected += s.expected();
        self.lost += s.lost();
        self.bytes += s.bytes;
        if s.last_at.is_some_and(|at| now.saturating_duration_since(at) < STREAM_LIVE) {
            self.live += 1;
            self.jitter_ms_sum += s.jitter_ms();
        }
    }

    pub fn merge(&mut self, o: &KindTotals) {
        self.streams += o.streams;
        self.live += o.live;
        self.received += o.received;
        self.expected += o.expected;
        self.lost += o.lost;
        self.bytes += o.bytes;
        self.jitter_ms_sum += o.jitter_ms_sum;
    }

    pub fn loss_pct(&self) -> f64 {
        if self.expected == 0 {
            0.0
        } else {
            self.lost as f64 * 100.0 / self.expected as f64
        }
    }

    pub fn jitter_ms(&self) -> f64 {
        if self.live == 0 {
            0.0
        } else {
            self.jitter_ms_sum / self.live as f64
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Totals {
    pub audio: KindTotals,
    pub video: KindTotals,
    pub data: KindTotals,
}

impl Totals {
    pub fn merge(&mut self, o: &Totals) {
        self.audio.merge(&o.audio);
        self.video.merge(&o.video);
        self.data.merge(&o.data);
    }

    pub fn received(&self) -> u64 {
        self.audio.received + self.video.received + self.data.received
    }

    pub fn expected(&self) -> u64 {
        self.audio.expected + self.video.expected + self.data.expected
    }

    pub fn lost(&self) -> u64 {
        self.audio.lost + self.video.lost + self.data.lost
    }

    pub fn bytes(&self) -> u64 {
        self.audio.bytes + self.video.bytes + self.data.bytes
    }

    /// Loss over everything since `before`.
    pub fn loss_pct_since(&self, before: &Totals) -> f64 {
        let expected = self.expected().saturating_sub(before.expected());
        let lost = self.lost().saturating_sub(before.lost());
        if expected == 0 {
            0.0
        } else {
            lost as f64 * 100.0 / expected as f64
        }
    }
}

// ---- the node, watched -------------------------------------------------------

/// Where the node's CPU and memory are read: a shell here (the node is on
/// this machine, `pid` says which) or over ssh (`prefix` is the ssh
/// command, the node is the `vcall` service there, or `pid`).
#[derive(Clone, Debug, Default)]
pub struct Watch {
    /// `ssh -i key root@host`, split into words; empty for this machine.
    pub prefix: Vec<String>,
    pub pid: Option<u32>,
    /// The `vcall` binary and the control socket there, for `ctl stats`.
    pub vcall: Option<String>,
    pub ctl: Option<String>,
}

impl Watch {
    pub fn is_set(&self) -> bool {
        !self.prefix.is_empty() || self.pid.is_some()
    }

    /// The script that reads what one sample needs, as `sh -c` takes it.
    pub fn script(&self) -> String {
        let find = match self.pid {
            Some(pid) => format!("p={pid}"),
            None => "p=$(systemctl show -p MainPID --value vcall 2>/dev/null); case \"$p\" in ''|0) p=$(pgrep -o -x vcall);; esac".to_string(),
        };
        let stats = match (&self.vcall, &self.ctl) {
            (Some(vcall), Some(ctl)) => format!("echo \"stats $({vcall} ctl --socket {ctl} stats 2>/dev/null | tr -d '\\n')\""),
            _ => String::new(),
        };
        format!(
            "{find}; echo \"pid $p\"; echo \"stat $(cat /proc/$p/stat)\"; echo \"status $(grep VmRSS /proc/$p/status)\"; \
             echo \"cpu $(head -1 /proc/stat)\"; echo \"ncpu $(nproc)\"; echo \"mem $(grep MemAvailable /proc/meminfo)\"; {stats}"
        )
    }

    async fn sample(&self) -> anyhow::Result<Sample> {
        let script = self.script();
        let prefix = self.prefix.clone();
        let out = tokio::task::spawn_blocking(move || {
            let mut cmd = if prefix.is_empty() {
                let mut c = std::process::Command::new("sh");
                c.arg("-c").arg(&script);
                c
            } else {
                let mut c = std::process::Command::new(&prefix[0]);
                c.args(&prefix[1..]).arg("sh").arg("-c").arg(shell_quote(&script));
                c
            };
            cmd.stdin(std::process::Stdio::null()).output()
        })
        .await??;
        anyhow::ensure!(out.status.success(), "the sampling command failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        parse_sample(&String::from_utf8_lossy(&out.stdout))
    }
}

/// `text` in single quotes, for a remote shell.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// One reading of the node and its machine.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sample {
    pub pid: u32,
    /// user + system, clock ticks (100 a second on Linux).
    pub node_ticks: u64,
    pub threads: u32,
    pub rss_kb: u64,
    pub host_busy: u64,
    pub host_total: u64,
    pub ncpu: u32,
    pub mem_available_kb: u64,
    pub stats: Option<serde_json::Value>,
}

/// Clock ticks a second of `/proc/<pid>/stat`: Linux on x86_64 and
/// aarch64 alike.
pub const CLK_TCK: f64 = 100.0;

pub fn parse_sample(text: &str) -> anyhow::Result<Sample> {
    let mut s = Sample::default();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(' ') else { continue };
        match key {
            "pid" => s.pid = rest.trim().parse().context("the node's pid")?,
            "stat" => {
                // Fields after the command in parentheses (it may hold spaces):
                // state, ppid, ..., utime is the 14th field, stime the 15th,
                // the threads the 20th.
                let after = rest.rsplit_once(')').map(|(_, a)| a).context("/proc/pid/stat")?;
                let fields: Vec<&str> = after.split_whitespace().collect();
                anyhow::ensure!(fields.len() > 17, "/proc/pid/stat is short");
                let utime: u64 = fields[11].parse()?;
                let stime: u64 = fields[12].parse()?;
                s.node_ticks = utime + stime;
                s.threads = fields[17].parse()?;
            }
            "status" => {
                // VmRSS:	   41234 kB
                s.rss_kb = rest.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(0);
            }
            "cpu" => {
                // cpu user nice system idle iowait irq softirq steal ...
                let v: Vec<u64> = rest.split_whitespace().skip(1).filter_map(|n| n.parse().ok()).collect();
                anyhow::ensure!(v.len() >= 5, "/proc/stat is short");
                s.host_total = v.iter().take(8).sum();
                s.host_busy = s.host_total - v[3] - v[4];
            }
            "ncpu" => s.ncpu = rest.trim().parse().unwrap_or(1),
            "mem" => s.mem_available_kb = rest.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(0),
            "stats" => s.stats = serde_json::from_str(rest.trim()).ok(),
            _ => {}
        }
    }
    anyhow::ensure!(s.pid != 0 && s.host_total != 0, "no node in the sample: {}", text.trim());
    Ok(s)
}

/// What two samples say about the time between them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NodeRate {
    /// CPU time the node took per second of wall time, milliseconds: 1000
    /// is one core.
    pub cpu_ms_per_s: f64,
    pub threads: u32,
    pub rss_mb: f64,
    /// The machine's CPU busy, percent of all its cores.
    pub host_pct: f64,
    pub ncpu: u32,
    pub mem_available_mb: f64,
}

pub fn rate(a: &Sample, b: &Sample, elapsed: Duration) -> NodeRate {
    let secs = elapsed.as_secs_f64().max(0.001);
    let host = b.host_total.saturating_sub(a.host_total);
    NodeRate {
        cpu_ms_per_s: b.node_ticks.saturating_sub(a.node_ticks) as f64 / CLK_TCK * 1000.0 / secs,
        threads: b.threads,
        rss_mb: b.rss_kb as f64 / 1024.0,
        host_pct: if host == 0 { 0.0 } else { b.host_busy.saturating_sub(a.host_busy) as f64 * 100.0 / host as f64 },
        ncpu: b.ncpu,
        mem_available_mb: b.mem_available_kb as f64 / 1024.0,
    }
}

/// The node's own drop counters out of its stats, summed; what the
/// operator would look at under load.
pub fn node_drops(stats: &serde_json::Value) -> (u64, u64, u64) {
    let since = &stats["since_start"];
    let n = |k: &str| since[k].as_u64().unwrap_or(0);
    (n("sfu_dropped_socket") + n("sfu_dropped_stream_full"), n("sfu_dropped_queue"), n("sfu_dropped_bandwidth") + n("dropped_bandwidth"))
}

/// The bytes the node sent out of its stats: the SFU's, and the TURN
/// relay's both ways. Against what the tool gets, this tells whether a
/// shortfall is the node's or the path's.
pub fn node_bytes_out(stats: &serde_json::Value) -> u64 {
    let since = &stats["since_start"];
    let n = |k: &str| since[k].as_u64().unwrap_or(0);
    n("sfu_bytes_out") + n("bytes_to_clients") + n("bytes_to_peers")
}

/// Least squares `y = a + b x` over points; `b`, or none with fewer than
/// two distinct `x`.
pub fn slope(points: &[(f64, f64)]) -> Option<f64> {
    let n = points.len() as f64;
    if points.len() < 2 {
        return None;
    }
    let mx = points.iter().map(|p| p.0).sum::<f64>() / n;
    let my = points.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = points.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx == 0.0 {
        return None;
    }
    let sxy: f64 = points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    Some(sxy / sxx)
}

// ---- the run -----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Options {
    pub node: NodeRef,
    pub access_key: Option<String>,
    pub rooms: usize,
    pub per_room: u32,
    pub shape: Shape,
    /// The SFU over TCP (the room's `sfu_tcp`), as a client behind a
    /// network that drops UDP.
    pub sfu_tcp: bool,
    /// TURN streams (two allocations each), what each sends each way, and how.
    pub turn: usize,
    pub turn_shape: Shape,
    pub turn_transport: Transport,
    pub turn_channel: bool,
    /// How long to hold the full load (after the last join).
    pub duration: Duration,
    pub ramp: Option<Ramp>,
    /// Stop adding participants past this loss over a report interval,
    /// percent; and past this CPU of the node's machine, percent.
    pub max_loss_pct: f64,
    pub max_cpu_pct: f64,
    pub report_every: Duration,
    pub watch: Watch,
    /// Nothing printed: the tests.
    pub quiet: bool,
}

/// What a run came to.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub participants: usize,
    pub connected: usize,
    pub rooms: usize,
    pub turn_streams: usize,
    pub join_failures: usize,
    pub tx_mbps: f64,
    pub rx_mbps: f64,
    /// Of the last interval, as [`Point::delivery_pct`].
    pub delivery_pct: f64,
    pub totals: Totals,
    pub node: Option<NodeRate>,
    /// Of the steady samples: node CPU ms/s and RSS KiB per participant.
    pub cpu_ms_per_participant: Option<f64>,
    pub rss_kb_per_participant: Option<f64>,
    pub stopped_by: Option<String>,
    pub samples: Vec<Point>,
}

/// One report line's numbers, kept for the regression and the tables.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Point {
    pub at_secs: f64,
    pub participants: usize,
    pub turn_streams: usize,
    pub steady: bool,
    pub tx_mbps: f64,
    pub rx_mbps: f64,
    pub loss_pct: f64,
    /// What came against what the connected participants and TURN
    /// endpoints should get, percent: a stream the node withholds (its
    /// bandwidth estimate, a drop for bandwidth) shows here, not in `loss`.
    pub delivery_pct: f64,
    pub audio_jitter_ms: f64,
    pub video_jitter_ms: f64,
    pub node: Option<NodeRate>,
    /// What the node's own counters say it sent over the interval, when
    /// its stats are read.
    pub node_out_mbps: Option<f64>,
}

struct Participant {
    acc: Arc<Mutex<RxAcc>>,
    connected: Arc<AtomicBool>,
    room: usize,
}

struct TurnStream {
    acc: [Arc<Mutex<RxAcc>>; 2],
}

struct State {
    tx_bytes: AtomicU64,
    participants: Mutex<Vec<Participant>>,
    turn: Mutex<Vec<TurnStream>>,
    join_failures: AtomicUsize,
    last_error: Mutex<Option<String>>,
}

/// What the state adds up at one moment.
struct Counted {
    totals: Totals,
    /// Participants in all, and connected.
    count: usize,
    connected: usize,
    /// The connected participants of each room (rooms with none left out).
    room_sizes: Vec<usize>,
    turn_streams: usize,
}

impl State {
    fn totals(&self, now: Instant, rooms: usize) -> Counted {
        let mut t = Totals::default();
        let mut connected = 0;
        let mut room_sizes = vec![0usize; rooms];
        let participants = self.participants.lock().expect("participants");
        for p in participants.iter() {
            if p.connected.load(Ordering::Relaxed) {
                connected += 1;
                if let Some(n) = room_sizes.get_mut(p.room) {
                    *n += 1;
                }
            }
            t.merge(&p.acc.lock().expect("acc").totals(now));
        }
        let count = participants.len();
        drop(participants);
        let turn = self.turn.lock().expect("turn");
        for s in turn.iter() {
            for acc in &s.acc {
                t.merge(&acc.lock().expect("acc").totals(now));
            }
        }
        room_sizes.retain(|n| *n > 0);
        Counted { totals: t, count, connected, room_sizes, turn_streams: turn.len() }
    }
}

macro_rules! say {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            println!($($arg)*);
        }
    };
}

pub async fn run(options: Options) -> anyhow::Result<Summary> {
    let quiet = options.quiet;
    let access = Access { key: options.access_key.clone(), ..Access::default() };
    let mut control = ControlClient::connect(&options.node).await.context("the control channel")?;
    let welcome = control
        .hello(&client::hello(access.clone(), &format!("vcall-load/{}", crate::VERSION)))
        .await?
        .map_err(|(status, r)| anyhow::anyhow!("hello refused: {status} {}: {}", r.error, r.message))?;
    say!(quiet, "node      v{}  {}  seats {} a room, {} kbit/s a seat", welcome.version, welcome.capabilities.join(","), welcome.limits.room_max_participants, welcome.limits.room_kbps_per_participant);
    anyhow::ensure!(
        options.per_room <= welcome.limits.room_max_participants || options.rooms == 0,
        "{} a room asked, the node seats {}",
        options.per_room,
        welcome.limits.room_max_participants
    );
    let total = options.rooms * options.per_room as usize;
    say!(
        quiet,
        "plan      {} rooms × {} = {} participants, each {:.0} kbit/s in {:.0} packets/s{}; {} turn streams of {:.0} kbit/s each way over {}{}",
        options.rooms,
        options.per_room,
        total,
        options.shape.bps() / 1000.0,
        options.shape.pps(),
        if options.shape.video.is_none() { " (audio only)" } else { "" },
        options.turn,
        options.turn_shape.bps() / 1000.0,
        options.turn_transport.name(),
        match options.ramp {
            Some(r) => format!("; ramp {} every {:.0} s", r.step, r.every.as_secs_f64()),
            None => String::new(),
        }
    );

    // The rooms, all at once: a room is a request.
    let mut rooms_made: Vec<RoomCreated> = Vec::new();
    for _ in 0..options.rooms {
        let room: RoomCreated = control
            .post(rooms::PATH_ROOMS, &RoomRequest { access: access.clone(), media_limits: MediaLimits::default() })
            .await?
            .map_err(|(status, r)| anyhow::anyhow!("room refused: {status} {}: {}", r.error, r.message))?;
        rooms_made.push(room);
    }
    let state = Arc::new(State {
        tx_bytes: AtomicU64::new(0),
        participants: Mutex::new(Vec::new()),
        turn: Mutex::new(Vec::new()),
        join_failures: AtomicUsize::new(0),
        last_error: Mutex::new(None),
    });
    let (stop_tx, stop_rx) = watch::channel(false);

    // The TURN streams, all at once, on one set of credentials.
    if options.turn > 0 {
        let creds = control.turn(access.clone()).await?.map_err(|(status, r)| anyhow::anyhow!("credentials refused: {status} {}: {}", r.error, r.message))?;
        let endpoints = Endpoints::of(&creds.urls);
        let turn_addr = endpoints.for_transport(options.turn_transport).with_context(|| format!("the node offers no TURN over {}", options.turn_transport.name()))?;
        for n in 0..options.turn {
            let acc = [Arc::new(Mutex::new(RxAcc::default())), Arc::new(Mutex::new(RxAcc::default()))];
            state.turn.lock().expect("turn").push(TurnStream { acc: acc.clone() });
            let pair = turn_pair(turn_addr, options.turn_transport, options.node.id, (creds.username.clone(), creds.password.clone()), options.turn_shape, options.turn_channel, acc, state.clone(), stop_rx.clone());
            tokio::spawn(async move {
                if let Err(e) = pair.await {
                    tracing::warn!(stream = n, error = %e, "turn stream ended");
                }
            });
        }
        say!(quiet, "turn      {} streams allocating via {}", options.turn, turn_addr);
    }
    drop(control);

    // The joiner: fills the rooms up to `target`, one join at a time.
    let target = Arc::new(AtomicUsize::new(if options.ramp.is_some() { 0 } else { total }));
    let joiner = {
        let (state, target, options, rooms_made, stop_rx) = (state.clone(), target.clone(), options.clone(), rooms_made.clone(), stop_rx.clone());
        tokio::spawn(async move {
            let mut joined = 0usize;
            loop {
                if *stop_rx.borrow() {
                    return;
                }
                if joined >= target.load(Ordering::Relaxed).min(total) {
                    if joined >= total {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                // The rooms fill one after another: a ramp's steady points
                // are then whole rooms, and the slope the cost of a seat
                // in a full one.
                let room = room_of(joined, options.per_room, options.rooms);
                let acc = Arc::new(Mutex::new(RxAcc::default()));
                let connected = Arc::new(AtomicBool::new(false));
                joined += 1;
                match join(&options, &rooms_made[room]).await {
                    Ok(client) => {
                        // Counted once it is in: a refused one is not a
                        // participant, and would hold the count above the
                        // connected for the rest of the run.
                        state.participants.lock().expect("participants").push(Participant { acc: acc.clone(), connected: connected.clone(), room });
                        let (state, stop_rx) = (state.clone(), stop_rx.clone());
                        let shape = options.shape;
                        tokio::spawn(async move {
                            if let Err(e) = participant(client, shape, acc, connected, state.clone(), stop_rx).await {
                                tracing::debug!(error = %e, "participant ended");
                            }
                        });
                    }
                    Err(e) => {
                        state.join_failures.fetch_add(1, Ordering::Relaxed);
                        *state.last_error.lock().expect("error") = Some(format!("{e:#}"));
                        // Refused is refused: no more are tried.
                        target.store(joined.saturating_sub(1), Ordering::Relaxed);
                        return;
                    }
                }
            }
        })
    };

    // The reporter: every interval, what came, what the node does; the
    // ramp's next step, or the end.
    let started = Instant::now();
    let mut last_report = started;
    let mut last_totals = Totals::default();
    let mut last_tx = 0u64;
    let mut last_sample: Option<(Instant, Sample)> = None;
    let mut last_count = 0usize;
    let mut last_connected = 0usize;
    let mut next_step = started;
    let mut full_at: Option<Instant> = None;
    let mut stopped_by: Option<String> = None;
    let mut points: Vec<Point> = Vec::new();
    let mut node_rate: Option<NodeRate> = None;
    let mut node_out_mbps: Option<f64> = None;
    let mut drops_before: Option<(u64, u64, u64)> = None;
    if options.watch.is_set() {
        match options.watch.sample().await {
            Ok(s) => {
                drops_before = s.stats.as_ref().map(node_drops);
                last_sample = Some((Instant::now(), s));
            }
            Err(e) => say!(quiet, "watch     cannot read the node: {e:#}"),
        }
    }
    loop {
        // The ramp: a step when its time comes, unless stopped.
        if let Some(ramp) = options.ramp {
            if stopped_by.is_none() && Instant::now() >= next_step && target.load(Ordering::Relaxed) < total {
                let t = (target.load(Ordering::Relaxed) + ramp.step).min(total);
                target.store(t, Ordering::Relaxed);
                next_step = Instant::now() + ramp.every;
            }
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(last_report + options.report_every)).await;
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(last_report).as_secs_f64().max(0.001);
        let Counted { totals, count, connected, room_sizes, turn_streams } = state.totals(now, options.rooms);
        let tx = state.tx_bytes.load(Ordering::Relaxed);
        let tx_mbps = (tx - last_tx) as f64 * 8.0 / elapsed / 1e6;
        let rx_mbps = totals.bytes().saturating_sub(last_totals.bytes()) as f64 * 8.0 / elapsed / 1e6;
        let loss = totals.loss_pct_since(&last_totals);
        // What should come: the rooms' streams to their connected, and
        // both endpoints of every TURN stream.
        let expected_bps = expected_rx_bps(&options.shape, &room_sizes) + (2 * turn_streams) as f64 * options.turn_shape.payload_bps();
        let delivery = delivery_pct(rx_mbps, expected_bps);
        let mut drops_line = String::new();
        if options.watch.is_set() {
            match options.watch.sample().await {
                Ok(s) => {
                    if let Some((at, before)) = &last_sample {
                        node_rate = Some(rate(before, &s, now.saturating_duration_since(*at)));
                    }
                    if let (Some(stats), Some(before)) = (s.stats.as_ref(), drops_before) {
                        let (socket, queue, bw) = node_drops(stats);
                        drops_line = format!("  drops socket {} queue {} bw {}", socket - before.0, queue - before.1, bw - before.2);
                    }
                    if let (Some(stats), Some((at, before))) = (s.stats.as_ref(), &last_sample) {
                        if let Some(before) = before.stats.as_ref() {
                            let secs = now.saturating_duration_since(*at).as_secs_f64().max(0.001);
                            node_out_mbps = Some(node_bytes_out(stats).saturating_sub(node_bytes_out(before)) as f64 * 8.0 / secs / 1e6);
                        }
                    }
                    last_sample = Some((now, s));
                }
                Err(e) => say!(quiet, "watch     {e:#}"),
            }
        }
        let steady = count == last_count && connected == count && count > 0;
        let point = Point {
            at_secs: now.saturating_duration_since(started).as_secs_f64(),
            participants: connected,
            turn_streams,
            steady,
            tx_mbps,
            rx_mbps,
            loss_pct: loss,
            delivery_pct: delivery,
            audio_jitter_ms: totals.audio.jitter_ms(),
            video_jitter_ms: totals.video.jitter_ms(),
            node: node_rate,
            node_out_mbps,
        };
        points.push(point);
        let node_line = match node_rate {
            Some(r) => format!(
                "  node {:.0} ms/s cpu ({:.0}% of {} cpu, {} thr) rss {:.0} MB  host {:.0}%{}",
                r.cpu_ms_per_s,
                r.cpu_ms_per_s / 10.0 / f64::from(r.ncpu.max(1)),
                r.ncpu,
                r.threads,
                r.rss_mb,
                r.host_pct,
                node_out_mbps.map(|m| format!("  node out {m:.1} Mbit/s")).unwrap_or_default()
            ),
            None => String::new(),
        };
        say!(
            quiet,
            "t={:>4.0}s  parts {}/{} ({} rooms)  tx {:.1} rx {:.1} Mbit/s ({:.0}% of expected)  loss {:.2}%  live a {} v {}  jitter a {:.1} v {:.1} ms{}{}{}",
            point.at_secs,
            connected,
            count,
            room_sizes.len(),
            tx_mbps,
            rx_mbps,
            delivery,
            loss,
            totals.audio.live,
            totals.video.live,
            point.audio_jitter_ms,
            point.video_jitter_ms,
            if turn_streams > 0 {
                format!("  turn {} live {}/{} loss {:.2}%", turn_streams, totals.data.live, 2 * turn_streams, totals.data.loss_pct())
            } else {
                String::new()
            },
            node_line,
            drops_line
        );
        if full_at.is_some() && connected < last_connected {
            say!(quiet, "note      {} participants gone since the last report (closed by the node?)", last_connected - connected);
        }
        last_report = now;
        last_totals = totals;
        last_tx = tx;
        last_count = count;
        last_connected = connected;

        // The end: the thresholds stop the ramp; the hold runs out.
        if stopped_by.is_none() {
            if options.max_loss_pct > 0.0 && loss > options.max_loss_pct && count > 0 {
                stopped_by = Some(format!("loss {loss:.2}% over {:.0}%", options.max_loss_pct));
            } else if let Some(r) = node_rate {
                if options.max_cpu_pct > 0.0 && r.host_pct > options.max_cpu_pct {
                    stopped_by = Some(format!("host cpu {:.0}% over {:.0}%", r.host_pct, options.max_cpu_pct));
                }
            }
            if let Some(why) = &stopped_by {
                say!(quiet, "stop      {why}: no more participants; holding {:.0} s", options.duration.as_secs_f64());
                target.store(count, Ordering::Relaxed);
                full_at = Some(now);
            } else if state.join_failures.load(Ordering::Relaxed) > 0 {
                let why = state.last_error.lock().expect("error").clone().unwrap_or_default();
                stopped_by = Some(format!("join refused: {why}"));
                say!(quiet, "stop      {}: holding {:.0} s", stopped_by.as_deref().unwrap_or(""), options.duration.as_secs_f64());
                full_at = Some(now);
            }
        }
        if full_at.is_none() && joiner.is_finished() && count >= total {
            full_at = Some(now);
        }
        if full_at.is_some_and(|at| now.saturating_duration_since(at) >= options.duration) {
            break;
        }
    }
    // What came, before everybody is told to go.
    let Counted { totals, count, connected, turn_streams, .. } = state.totals(Instant::now(), options.rooms);
    let _ = stop_tx.send(true);
    joiner.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let steady: Vec<&Point> = points.iter().filter(|p| p.steady && p.node.is_some()).collect();
    let cpu_points: Vec<(f64, f64)> = steady.iter().map(|p| (p.participants as f64, p.node.map(|n| n.cpu_ms_per_s).unwrap_or(0.0))).collect();
    let rss_points: Vec<(f64, f64)> = steady.iter().map(|p| (p.participants as f64, p.node.map(|n| n.rss_mb * 1024.0).unwrap_or(0.0))).collect();
    let summary = Summary {
        participants: count,
        connected,
        rooms: options.rooms,
        turn_streams,
        join_failures: state.join_failures.load(Ordering::Relaxed),
        tx_mbps: points.last().map(|p| p.tx_mbps).unwrap_or(0.0),
        rx_mbps: points.last().map(|p| p.rx_mbps).unwrap_or(0.0),
        delivery_pct: points.last().map(|p| p.delivery_pct).unwrap_or(0.0),
        totals,
        node: node_rate,
        cpu_ms_per_participant: slope(&cpu_points),
        rss_kb_per_participant: slope(&rss_points),
        stopped_by,
        samples: points,
    };
    if !quiet {
        print_summary(&summary, &options);
    }
    Ok(summary)
}

fn print_summary(s: &Summary, options: &Options) {
    println!();
    println!(
        "result    {} participants ({} connected) in {} rooms, {} turn streams{}",
        s.participants,
        s.connected,
        s.rooms,
        s.turn_streams,
        s.stopped_by.as_ref().map(|w| format!("; stopped: {w}")).unwrap_or_default()
    );
    println!(
        "received  audio {} of {} ({:.2}% lost, jitter {:.1} ms), video {} of {} ({:.2}% lost, jitter {:.1} ms), turn {} of {} ({:.2}% lost)",
        s.totals.audio.received,
        s.totals.audio.expected,
        s.totals.audio.loss_pct(),
        s.totals.audio.jitter_ms(),
        s.totals.video.received,
        s.totals.video.expected,
        s.totals.video.loss_pct(),
        s.totals.video.jitter_ms(),
        s.totals.data.received,
        s.totals.data.expected,
        s.totals.data.loss_pct()
    );
    println!("traffic   last interval: tx {:.1} Mbit/s, rx {:.1} Mbit/s at the tool ({:.0}% of what the connected should get)", s.tx_mbps, s.rx_mbps, s.delivery_pct);
    if let Some(n) = s.node {
        println!("node      last interval: {:.0} ms/s cpu on {} cpu, {} threads, rss {:.0} MB; host {:.0}% busy, {:.0} MB free", n.cpu_ms_per_s, n.ncpu, n.threads, n.rss_mb, n.host_pct, n.mem_available_mb);
        if s.connected > 0 {
            println!("per seat  {:.1} ms/s cpu (all in, last interval); tx {:.0} kbit/s, rx {:.0} kbit/s", n.cpu_ms_per_s / s.connected as f64, s.tx_mbps * 1000.0 / s.connected as f64, s.rx_mbps * 1000.0 / s.connected as f64);
        }
        if let Some(c) = s.cpu_ms_per_participant {
            let steady = s.samples.iter().filter(|p| p.steady && p.node.is_some()).count();
            println!(
                "slope     {:.1} ms/s cpu and {:.0} KiB rss per participant (least squares over {} steady samples, rooms filled one after another); ~{} participants a core at 80%",
                c,
                s.rss_kb_per_participant.unwrap_or(0.0),
                steady,
                if c > 0.0 { (800.0 / c) as u64 } else { 0 }
            );
        }
    }
    if options.turn > 0 && s.participants == 0 {
        if let Some(n) = s.node {
            println!("per turn  {:.1} ms/s cpu an allocation (all in, last interval), {:.0} kbit/s each way", n.cpu_ms_per_s / (2 * s.turn_streams) as f64, options.turn_shape.bps() / 1000.0);
        }
    }
}

async fn join(options: &Options, room: &RoomCreated) -> anyhow::Result<RoomClient> {
    let transport = if options.sfu_tcp { SfuTransport::Tcp(room.sfu_tcp.parse().context("the room's sfu_tcp")?) } else { SfuTransport::Udp };
    let join_options = JoinOptions { video: options.shape.video.is_some(), transport, access_key: options.access_key.clone(), ..JoinOptions::default() };
    RoomClient::join_with(&options.node, &room.room_id, &room.join_token, join_options).await
}

/// One participant: connects, then sends on its clocks and counts what
/// comes, until told to stop or closed by the node.
async fn participant(mut client: RoomClient, shape: Shape, acc: Arc<Mutex<RxAcc>>, connected: Arc<AtomicBool>, state: Arc<State>, mut stop: watch::Receiver<bool>) -> anyhow::Result<()> {
    client.wait_for(CONNECT_WAIT, |e| matches!(e, RoomEvent::Connected).then_some(())).await.context("did not connect")?;
    connected.store(true, Ordering::Relaxed);
    let sender = client.sender();
    let audio = vec![0xA5u8; shape.audio_payload()];
    let frame: Vec<usize> = shape.frame_packets();
    let video_buf = vec![0x9Au8; frame.iter().copied().max().unwrap_or(0)];
    let mut audio_tick = paced(AUDIO_FRAME);
    let mut video_tick = paced(shape.frame_interval().unwrap_or(Duration::from_secs(3600)));
    let has_video = shape.video.is_some();
    loop {
        tokio::select! {
            _ = audio_tick.tick() => {
                sender.send_audio(&audio, Some(-30)).await;
                state.tx_bytes.fetch_add((audio.len() + RTP_HEADER) as u64, Ordering::Relaxed);
            }
            _ = video_tick.tick(), if has_video => {
                let last = frame.len() - 1;
                for (n, size) in frame.iter().enumerate() {
                    sender.send_video(&video_buf[..*size], n == last).await;
                    state.tx_bytes.fetch_add((size + RTP_HEADER) as u64, Ordering::Relaxed);
                }
            }
            event = client.next(Duration::from_secs(3600)) => match event {
                Some(RoomEvent::Rtp { mid, seq, timestamp, payload, .. }) => {
                    acc.lock().expect("acc").packet(&mid, seq, timestamp, payload.len() + RTP_HEADER, Instant::now());
                }
                Some(RoomEvent::Tracks(tracks)) => {
                    let mut acc = acc.lock().expect("acc");
                    for t in &tracks {
                        acc.track(&t.mid, &t.kind);
                    }
                }
                Some(RoomEvent::Closed) | None => {
                    connected.store(false, Ordering::Relaxed);
                    return Ok(());
                }
                Some(_) => {}
            },
            _ = stop.changed() => {
                sender.close().await;
                connected.store(false, Ordering::Relaxed);
                return Ok(());
            }
        }
    }
}

/// A TURN stream: two allocations, each with a permission (and a
/// channel) for the other's relayed address, sending to each other at
/// `shape`'s pace with a number in every packet, and counting.
#[allow(clippy::too_many_arguments)]
async fn turn_pair(
    turn_addr: SocketAddr,
    transport: Transport,
    pin: crate::identity::NodeId,
    creds: (String, String),
    shape: Shape,
    channel: bool,
    acc: [Arc<Mutex<RxAcc>>; 2],
    state: Arc<State>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut a = TurnClient::connect(turn_addr, transport, Some(pin)).await.context("TURN connect")?;
    let mut b = TurnClient::connect(turn_addr, transport, Some(pin)).await.context("TURN connect")?;
    a.set_credentials(&creds.0, &creds.1);
    b.set_credentials(&creds.0, &creds.1);
    let alloc_a = a.allocate(None).await.context("allocate a")?;
    let alloc_b = b.allocate(None).await.context("allocate b")?;
    a.create_permission(&[alloc_b.relayed]).await.context("permission a")?;
    b.create_permission(&[alloc_a.relayed]).await.context("permission b")?;
    if channel {
        a.channel_bind(0x4000, alloc_b.relayed).await.context("channel a")?;
        b.channel_bind(0x4000, alloc_a.relayed).await.context("channel b")?;
    }
    let [acc_a, acc_b] = acc;
    let ta = tokio::spawn(turn_endpoint(a, alloc_b.relayed, shape, channel, acc_a, state.clone(), stop.clone()));
    let tb = tokio::spawn(turn_endpoint(b, alloc_a.relayed, shape, channel, acc_b, state, stop));
    let (ra, rb) = tokio::join!(ta, tb);
    ra??;
    rb??;
    Ok(())
}

async fn turn_endpoint(mut client: TurnClient, peer: SocketAddr, shape: Shape, channel: bool, acc: Arc<Mutex<RxAcc>>, state: Arc<State>, mut stop: watch::Receiver<bool>) -> anyhow::Result<()> {
    let mut seq = 0u64;
    let mut audio = vec![0xA5u8; shape.audio_payload().max(8)];
    let frame: Vec<usize> = shape.frame_packets();
    let mut video_buf = vec![0x9Au8; frame.iter().copied().max().unwrap_or(0).max(8)];
    let mut audio_tick = paced(AUDIO_FRAME);
    let mut video_tick = paced(shape.frame_interval().unwrap_or(Duration::from_secs(3600)));
    let has_video = shape.video.is_some();
    // Renewed well within the lifetimes the node keeps: the allocation
    // (600 s asked), the permission (300 s) and the channel (600 s); a
    // lapsed permission or channel would silently end the stream, and
    // its loss would read as none (nothing expected).
    let mut refresh = tokio::time::interval(TURN_RENEW);
    refresh.tick().await;
    loop {
        tokio::select! {
            _ = audio_tick.tick() => {
                seq += 1;
                audio[..8].copy_from_slice(&seq.to_be_bytes());
                turn_send(&mut client, peer, channel, &audio).await?;
                state.tx_bytes.fetch_add(audio.len() as u64, Ordering::Relaxed);
            }
            _ = video_tick.tick(), if has_video => {
                for size in &frame {
                    seq += 1;
                    let size = (*size).max(8);
                    video_buf[..8].copy_from_slice(&seq.to_be_bytes());
                    turn_send(&mut client, peer, channel, &video_buf[..size]).await?;
                    state.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
                }
            }
            _ = refresh.tick() => {
                client.refresh(600).await.context("turn refresh")?;
                if channel {
                    client.channel_bind(0x4000, peer).await.context("turn channel renewal")?;
                } else {
                    client.create_permission(&[peer]).await.context("turn permission renewal")?;
                }
            }
            r = client.recv(Duration::from_secs(1)) => match r {
                Ok(Incoming::Data { data, .. }) | Ok(Incoming::Channel { data, .. }) => {
                    if data.len() >= 8 {
                        let n = u64::from_be_bytes(data[..8].try_into().expect("8 bytes"));
                        let mut acc = acc.lock().expect("acc");
                        acc.kinds.insert("turn".into(), Kind::Data);
                        acc.packet("turn", n, 0, data.len(), Instant::now());
                    }
                }
                Err(client::TurnError::Timeout) => {}
                Err(e) => return Err(e).context("turn recv"),
            },
            _ = stop.changed() => {
                let _ = client.refresh(0).await;
                return Ok(());
            }
        }
    }
}

async fn turn_send(client: &mut TurnClient, peer: SocketAddr, channel: bool, data: &[u8]) -> anyhow::Result<()> {
    if channel {
        client.send_channel(0x4000, data).await?;
    } else {
        client.send(peer, data).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> Shape {
        Shape { audio_kbps: 48, video: Some(Video { kbps: 600, fps: 30 }), mtu: DEFAULT_MTU }
    }

    #[test]
    fn audio_is_120_bytes_every_20_ms_at_48_kbps() {
        assert_eq!(shape().audio_payload(), 120);
        assert_eq!(Shape { audio_kbps: 24, video: None, mtu: 1200 }.audio_payload(), 60);
    }

    #[test]
    fn video_frames_split_at_the_mtu() {
        let s = shape();
        assert_eq!(s.frame_bytes(), 2500);
        assert_eq!(s.frame_packets(), vec![1200, 1200, 100]);
        assert_eq!(split_frame(1200, 1200), vec![1200]);
        assert_eq!(split_frame(0, 1200), vec![1]);
        assert_eq!(split_frame(2401, 1200), vec![1200, 1200, 1]);
    }

    #[test]
    fn rates_count_headers_and_packets() {
        let s = shape();
        // 50 audio + 90 video packets a second.
        assert_eq!(s.pps() as u64, 140);
        // 50 × 132 B + 30 × (2500 + 3 × 12) B, in bits.
        let bits = 50.0 * 132.0 * 8.0 + 30.0 * (2500.0 + 36.0) * 8.0;
        assert!((s.bps() - bits).abs() < 1.0, "{}", s.bps());
        let audio_only = Shape { audio_kbps: 48, video: None, mtu: 1200 };
        assert_eq!(audio_only.pps() as u64, 50);
        assert_eq!(audio_only.bps() as u64, 52_800);
        assert_eq!(audio_only.payload_bps() as u64, 48_000);
        assert_eq!(s.payload_bps() as u64, 48_000 + 600_000);
        assert!(audio_only.frame_packets().is_empty());
    }

    #[test]
    fn a_ramp_is_n_per_t() {
        let r: Ramp = "4/10".parse().unwrap();
        assert_eq!(r, Ramp { step: 4, every: Duration::from_secs(10) });
        let r: Ramp = "2/2.5s".parse().unwrap();
        assert_eq!(r.every, Duration::from_millis(2500));
        assert!("4".parse::<Ramp>().is_err());
        assert!("0/10".parse::<Ramp>().is_err());
    }

    #[test]
    fn a_stream_counts_what_came_and_what_did_not() {
        let mut s = StreamAcc::new(Kind::Audio);
        for (n, seq) in [10u64, 11, 12, 14, 15, 13, 18].iter().enumerate() {
            s.packet(*seq, (n as u32) * 960, 132, n as f64 * 0.02);
        }
        assert_eq!(s.received, 7);
        assert_eq!(s.expected(), 9);
        assert_eq!(s.lost(), 2);
        assert_eq!(s.bytes, 7 * 132);
    }

    #[test]
    fn jitter_is_zero_on_a_perfect_clock_and_grows_with_a_late_packet() {
        let mut s = StreamAcc::new(Kind::Audio);
        for n in 0..20u64 {
            s.packet(n, n as u32 * 960, 132, n as f64 * 0.02);
        }
        assert!(s.jitter_ms() < 0.001, "{}", s.jitter_ms());
        // A packet 16 ms late: the RFC's estimator moves a sixteenth of it.
        s.packet(20, 20 * 960, 132, 20.0 * 0.02 + 0.016);
        assert!((s.jitter_ms() - 1.0).abs() < 0.01, "{}", s.jitter_ms());
        let mut v = StreamAcc::new(Kind::Video);
        v.packet(1, 0, 1200, 0.0);
        v.packet(2, 3000, 1200, 1.0 / 30.0 + 0.009);
        assert!((v.jitter_ms() - 9.0 / 16.0).abs() < 0.01, "{}", v.jitter_ms());
        let d = StreamAcc::new(Kind::Data);
        assert_eq!(d.jitter_ms(), 0.0);
    }

    #[test]
    fn totals_tell_kinds_apart_and_live_streams() {
        let mut acc = RxAcc::default();
        acc.track("1", "audio");
        acc.track("2", "video");
        let t0 = Instant::now();
        acc.packet("1", 1, 0, 132, t0);
        acc.packet("1", 3, 1920, 132, t0);
        acc.packet("2", 1, 0, 1212, t0);
        let totals = acc.totals(t0);
        assert_eq!(totals.audio.received, 2);
        assert_eq!(totals.audio.lost, 1);
        assert_eq!(totals.video.received, 1);
        assert_eq!(totals.audio.live, 1);
        assert_eq!(totals.video.live, 1);
        assert_eq!(totals.bytes(), 132 * 2 + 1212);
        let later = acc.totals(t0 + Duration::from_secs(3));
        assert_eq!(later.audio.live, 0);
        assert_eq!(later.audio.streams, 1);
        let before = Totals::default();
        assert!((totals.loss_pct_since(&before) - 25.0).abs() < 0.01);
        let mut merged = totals;
        merged.merge(&totals);
        assert_eq!(merged.audio.received, 4);
        assert_eq!(merged.audio.loss_pct(), 100.0 / 3.0);
    }

    #[test]
    fn a_sample_is_read_off_proc() {
        let text = "pid 1234\n\
            stat 1234 (vcall node) S 1 1234 1234 0 -1 4194560 10 0 0 0 250 50 0 0 20 0 3 0 1000 54321 10000 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
            status VmRSS:\t   40960 kB\n\
            cpu  cpu  1000 10 500 8000 100 0 20 0 0 0\n\
            ncpu 2\n\
            mem MemAvailable:   1500000 kB\n\
            stats {\"participants_now\": 3, \"since_start\": {\"sfu_dropped_socket\": 5, \"sfu_dropped_queue\": 1, \"sfu_dropped_bandwidth\": 2, \"dropped_bandwidth\": 4, \"sfu_dropped_stream_full\": 0}}\n";
        let s = parse_sample(text).unwrap();
        assert_eq!(s.pid, 1234);
        assert_eq!(s.node_ticks, 300);
        assert_eq!(s.threads, 3);
        assert_eq!(s.rss_kb, 40960);
        assert_eq!(s.host_total, 9630);
        assert_eq!(s.host_busy, 9630 - 8000 - 100);
        assert_eq!(s.ncpu, 2);
        assert_eq!(s.mem_available_kb, 1_500_000);
        assert_eq!(node_drops(s.stats.as_ref().unwrap()), (5, 1, 6));
        assert_eq!(node_bytes_out(s.stats.as_ref().unwrap()), 0);
        let stats: serde_json::Value = serde_json::json!({"since_start": {"sfu_bytes_out": 1000, "bytes_to_clients": 10, "bytes_to_peers": 5}});
        assert_eq!(node_bytes_out(&stats), 1015);

        let mut later = s.clone();
        later.node_ticks += 50;
        later.host_total += 1000;
        later.host_busy += 400;
        let r = rate(&s, &later, Duration::from_secs(5));
        assert!((r.cpu_ms_per_s - 100.0).abs() < 0.01);
        assert!((r.host_pct - 40.0).abs() < 0.01);
        assert!((r.rss_mb - 40.0).abs() < 0.01);
        assert!(parse_sample("pid 0\n").is_err());
    }

    #[test]
    fn rooms_fill_one_after_another() {
        assert_eq!(room_of(0, 12, 8), 0);
        assert_eq!(room_of(11, 12, 8), 0);
        assert_eq!(room_of(12, 12, 8), 1);
        assert_eq!(room_of(95, 12, 8), 7);
        // Past the plan it stays in the last room; a plan of none is one room.
        assert_eq!(room_of(96, 12, 8), 7);
        assert_eq!(room_of(5, 0, 0), 0);
    }

    #[test]
    fn what_a_room_should_get_is_everybody_elses_video_and_the_speakers_audio() {
        let s = shape();
        let (a, v) = (s.audio_bps(), s.video_bps());
        assert!((a - 52_800.0).abs() < 1.0);
        assert!((v - 30.0 * (2500.0 + 36.0) * 8.0).abs() < 1.0);
        assert_eq!(expected_rx_bps(&s, &[]), 0.0);
        assert_eq!(expected_rx_bps(&s, &[1]), 0.0);
        // A conversation: everybody gets everybody else.
        assert!((expected_rx_bps(&s, &[4]) - 12.0 * (a + v)).abs() < 1.0);
        // Past it: three speakers get two others, the rest get three.
        let n = 12.0;
        assert!((expected_rx_bps(&s, &[12]) - (n * 11.0 * v + (3.0 * 2.0 + 9.0 * 3.0) * a)).abs() < 1.0);
        assert!((expected_rx_bps(&s, &[12, 4]) - expected_rx_bps(&s, &[12]) - expected_rx_bps(&s, &[4])).abs() < 1.0);
        let audio = Shape { audio_kbps: 48, video: None, mtu: 1200 };
        assert!((expected_rx_bps(&audio, &[12]) - 33.0 * a).abs() < 1.0);
        assert!((delivery_pct(1.0, 2e6) - 50.0).abs() < 1e-9);
        assert_eq!(delivery_pct(1.0, 0.0), 0.0);
    }

    #[test]
    fn the_slope_is_the_cost_of_one_more() {
        assert_eq!(slope(&[]), None);
        assert_eq!(slope(&[(1.0, 1.0)]), None);
        assert_eq!(slope(&[(2.0, 1.0), (2.0, 3.0)]), None);
        let b = slope(&[(0.0, 10.0), (10.0, 60.0), (20.0, 110.0)]).unwrap();
        assert!((b - 5.0).abs() < 1e-9);
    }

    #[test]
    fn the_watch_script_names_the_pid_or_finds_the_service() {
        let w = Watch { prefix: Vec::new(), pid: Some(42), vcall: Some("/opt/vcall/bin/vcall".into()), ctl: Some("/run/vcall/ctl.sock".into()) };
        let s = w.script();
        assert!(s.starts_with("p=42;"));
        assert!(s.contains("ctl --socket /run/vcall/ctl.sock stats"));
        let w = Watch::default();
        assert!(!w.is_set());
        assert!(w.script().contains("systemctl show -p MainPID"));
        assert!(!w.script().contains("stats"));
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
