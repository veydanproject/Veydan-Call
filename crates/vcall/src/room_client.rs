//! A participant of a room, as `vcall room-test` and the tests are: a
//! str0m `Rtc` on a UDP socket of its own, driven by a task, that sends
//! what it is told and reports what it gets. Not for apps: libwebrtc is
//! the engine there; this one has no codecs, no camera, no microphone, and
//! sends whatever bytes it is given as RTP payloads.
//!
//! ```text
//! join:  offer (sendonly audio [+ video, in layers], the channel ctl) ──control──▶ node ──▶ answer
//! then:  ICE and DTLS to the SFU port, over UDP or over TCP (RFC 4571 frames);
//!        `ctl` opens; the node's offers are answered here, layers asked for here
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context;
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::channel::ChannelId;
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid, Rid, Simulcast, SimulcastLayer};
use str0m::net::{Protocol, Receive, TcpType, Transmit};
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo, Ssrc};
use str0m::{Candidate, Event, Input, Output, Rtc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use vcall_proto::rooms::{self, ctl, JoinRequest, Joined, LeaveRequest};

use crate::client::ControlClient;
use crate::identity::NodeRef;
use crate::sfu::sdp;

/// What the room tells this participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomEvent {
    /// ICE and DTLS are up.
    Connected,
    /// The data channel is open; the node's `hello` follows.
    CtlOpen,
    Hello { you: u32, participants: Vec<u32> },
    Joined(u32),
    Left(u32),
    /// An offer of the node came, with this `seq`; answered at once, or
    /// kept while offers are held (`hold_offers`).
    Offer(u32),
    /// The node's offer was answered: these m-lines carry these streams.
    Tracks(Vec<ctl::Track>),
    /// An RTP packet on one of the node's m-lines.
    Rtp { mid: String, pt: u8, seq: u64, timestamp: u32, marker: bool, audio_level: Option<i8>, payload: Vec<u8> },
    /// Bytes of another participant, relayed by the node.
    Bytes { from: u32, data: Vec<u8> },
    /// Who talks, loudest first, as the node says.
    Speaking(Vec<u32>),
    /// From one's own node in the cascade: the home of the room is gone;
    /// `Closed` follows.
    HomeLost,
    /// The connection ended.
    Closed,
}

/// How a participant reaches the SFU port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SfuTransport {
    Udp,
    /// Over TCP to this address (the room's `sfu_tcp`), as a client
    /// behind a network that drops UDP would.
    Tcp(SocketAddr),
}

/// What a participant sends, and how it comes.
#[derive(Clone, Debug)]
pub struct JoinOptions {
    pub video: bool,
    /// Simulcast: the rids of the video layers, lowest first (`q`, `h`,
    /// `f`); empty for one stream. Needs `video`.
    pub layers: Vec<String>,
    pub transport: SfuTransport,
    /// The cascade: the room's home, when the node joined is one's own
    /// and not the home. The token is then a pass from the home
    /// ([`RoomClient::delegate`]).
    pub home: Option<NodeRef>,
    /// The access key of one's own private node, with `home`; or the
    /// credentials of a device the node made (id, secret).
    pub access_key: Option<String>,
    pub device: Option<(String, String)>,
}

impl Default for JoinOptions {
    fn default() -> Self {
        Self { video: false, layers: Vec::new(), transport: SfuTransport::Udp, home: None, access_key: None, device: None }
    }
}

impl JoinOptions {
    /// What the join shows of access: the key, the device, or nothing.
    fn access(&self) -> Option<vcall_proto::Access> {
        if self.access_key.is_none() && self.device.is_none() {
            return None;
        }
        Some(vcall_proto::Access {
            key: self.access_key.clone(),
            device: self.device.as_ref().map(|(id, secret)| vcall_proto::DeviceAccess { id: id.clone(), secret: secret.clone() }),
            pass: None,
        })
    }
}

enum Cmd {
    Audio { payload: Vec<u8>, level: Option<i8> },
    Video { layer: usize, payload: Vec<u8>, marker: bool },
    Bytes(Vec<u8>),
    /// A text frame over `ctl`: a layer request.
    Text(Vec<u8>),
    /// Keep the node's offers unanswered (true), or answer them, and the
    /// kept ones now (false): a client that is slow to answer.
    Hold(bool),
    Close,
}

pub struct RoomClient {
    pub participant_id: u32,
    pub participant_token: String,
    /// Who was in the room when this one joined.
    pub participants: Vec<u32>,
    /// In the cascade: the token of the seat at the home.
    pub home_token: Option<String>,
    /// The mids this participant sends on, in its own offer.
    pub audio_mid: String,
    pub video_mid: Option<String>,
    /// The ICE credentials, this side's ufrag and the node's ufrag and
    /// password, as the offer and the answer said them: what a STUN
    /// request to the node is made of.
    pub ufrag: String,
    pub node_ufrag: String,
    pub node_pwd: String,
    cmds: mpsc::Sender<Cmd>,
    events: mpsc::Receiver<RoomEvent>,
}

/// One stream this side sends video on: a layer, or the only one.
struct VideoTx {
    ssrc: Ssrc,
    seq: u64,
    ts: u32,
}

/// The sending half of a participant, apart from its events: what a
/// task that drives the sending on a clock holds while another reads
/// [`RoomClient::next`]. Cheap to clone.
#[derive(Clone)]
pub struct RoomSender {
    cmds: mpsc::Sender<Cmd>,
}

impl RoomSender {
    /// As [`RoomClient::send_audio`].
    pub async fn send_audio(&self, payload: &[u8], level: Option<i8>) {
        let _ = self.cmds.send(Cmd::Audio { payload: payload.to_vec(), level }).await;
    }

    /// As [`RoomClient::send_video`].
    pub async fn send_video(&self, payload: &[u8], marker: bool) {
        let _ = self.cmds.send(Cmd::Video { layer: 0, payload: payload.to_vec(), marker }).await;
    }

    /// As [`RoomClient::close`].
    pub async fn close(&self) {
        let _ = self.cmds.send(Cmd::Close).await;
    }
}

impl RoomClient {
    /// The sending half, to hold apart from the events.
    pub fn sender(&self) -> RoomSender {
        RoomSender { cmds: self.cmds.clone() }
    }

    /// Joins `room` on `node` with `token`: the offer over the control
    /// channel, then the connection to the SFU. Returns once the node
    /// answered; `Connected` comes as an event.
    pub async fn join(node: &NodeRef, room: &str, token: &str, video: bool, transport: SfuTransport) -> anyhow::Result<Self> {
        Self::join_with(node, room, token, JoinOptions { video, transport, ..JoinOptions::default() }).await
    }

    /// A pass for a proxy seat in `room` at its home, by the join token:
    /// what a client joins its own node with, naming the home.
    pub async fn delegate(home: &NodeRef, room: &str, join_token: &str) -> anyhow::Result<Result<rooms::Delegated, (u16, vcall_proto::Refusal)>> {
        let mut control = ControlClient::connect(home).await.context("the control channel of the home")?;
        control.post(&format!("{}/{room}/{}", rooms::PATH_ROOMS, rooms::action::DELEGATE), &rooms::DelegateRequest { token: join_token.to_string() }).await
    }

    /// [`RoomClient::join_with`], and the refusal as the node sent it:
    /// the status and the word.
    pub async fn try_join_with(node: &NodeRef, room: &str, token: &str, options: JoinOptions) -> anyhow::Result<Result<Self, (u16, vcall_proto::Refusal)>> {
        Self::join_inner(node, room, token, options).await
    }

    /// [`RoomClient::join`] with every option: video in simulcast layers,
    /// a home to join through the node.
    pub async fn join_with(node: &NodeRef, room: &str, token: &str, options: JoinOptions) -> anyhow::Result<Self> {
        Self::join_inner(node, room, token, options)
            .await?
            .map_err(|(status, r)| anyhow::anyhow!("join refused: {status} {}: {}", r.error, r.message))
    }

    async fn join_inner(node: &NodeRef, room: &str, token: &str, options: JoinOptions) -> anyhow::Result<Result<Self, (u16, vcall_proto::Refusal)>> {
        let (io, local, candidate) = match options.transport {
            SfuTransport::Udp => {
                let socket = UdpSocket::bind(if node.addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
                // The candidate names the interface the node is reached by: a
                // socket "connected" to the node (no packet sent) is bound to it.
                let local = SocketAddr::new(local_ip_towards(node.addr)?, socket.local_addr()?.port());
                (Io::Udp(socket), local, Candidate::host(local, Protocol::Udp)?)
            }
            SfuTransport::Tcp(sfu) => {
                let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(sfu)).await??;
                let _ = stream.set_nodelay(true);
                let local = stream.local_addr()?;
                let candidate = Candidate::builder().tcp().host(local).tcptype(TcpType::Active).build()?;
                (Io::Tcp { stream, buf: Vec::new(), remote: sfu }, local, candidate)
            }
        };

        crate::sfu::init_crypto();
        let mut rtc = Rtc::builder().set_rtp_mode(true).clear_codecs().enable_opus(true, false).enable_vp8(true).build(Instant::now());
        rtc.add_local_candidate(candidate);
        let mut change = rtc.sdp_api();
        let audio_mid = change.add_media(MediaKind::Audio, Direction::SendOnly, Some("me".into()), None, None);
        let video_mid = options.video.then(|| {
            let simulcast = (!options.layers.is_empty()).then(|| {
                let mut s = Simulcast::new();
                for rid in &options.layers {
                    s.add_send_layer(SimulcastLayer::new(rid));
                }
                s
            });
            change.add_media(MediaKind::Video, Direction::SendOnly, Some("me".into()), None, simulcast)
        });
        change.add_channel(rooms::CTL_CHANNEL.to_string());
        let (offer, pending) = change.apply().context("nothing to offer")?;
        let offer_sdp = offer.to_sdp_string();

        let mut control = ControlClient::connect(node).await.context("the control channel")?;
        let mut request = JoinRequest::new(token, offer_sdp.clone(), Vec::new());
        if !options.layers.is_empty() {
            request.caps.push(vcall_proto::capability::SIMULCAST.into());
        }
        if let Some(home) = &options.home {
            request.home = Some(rooms::HomeRef { node: home.to_string() });
            request.access = options.access();
        }
        // A join with a home takes longer: the node reaches the home first.
        let wait = if options.home.is_some() { Duration::from_secs(10) } else { Duration::from_secs(5) };
        let posted = tokio::time::timeout(wait, control.post::<_, Joined>(&format!("{}/{room}/{}", rooms::PATH_ROOMS, rooms::action::JOIN), &request))
            .await
            .map_err(|_| anyhow::anyhow!("the node did not answer the join in time"))??;
        let joined: Joined = match posted {
            Ok(joined) => joined,
            Err(refused) => return Ok(Err(refused)),
        };
        let answer = SdpAnswer::from_sdp_string(&joined.sdp_answer).context("the node's answer")?;
        rtc.sdp_api().accept_answer(pending, answer).context("the node's answer")?;
        let (ufrag, _) = sdp::ice_credentials(&offer_sdp).context("no ice credentials in the offer")?;
        let (node_ufrag, node_pwd) = sdp::ice_credentials(&joined.sdp_answer).context("no ice credentials in the node's answer")?;

        // In RTP mode what is sent is declared by hand, with the SSRCs the
        // offer announced: one pair a layer, in the order of the rids.
        let (audio_ssrc, _) = sdp::ssrcs_of(&offer_sdp, &audio_mid).context("no ssrc for the audio m-line")?;
        let audio_ssrc = Ssrc::from(audio_ssrc);
        rtc.direct_api().declare_stream_tx(audio_ssrc, None, audio_mid, None);
        let mut video = Vec::new();
        if let Some(mid) = video_mid {
            let groups = sdp::ssrc_groups_of(&offer_sdp, &mid);
            anyhow::ensure!(!groups.is_empty(), "no ssrc for the video m-line");
            anyhow::ensure!(options.layers.is_empty() || groups.len() == options.layers.len(), "{} ssrc pairs for {} layers", groups.len(), options.layers.len());
            for (n, (main, rtx)) in groups.into_iter().enumerate() {
                let (main, rtx) = (Ssrc::from(main), rtx.map(Ssrc::from));
                let rid = options.layers.get(n).map(|r| Rid::from(r.as_str()));
                rtc.direct_api().declare_stream_tx(main, rtx, mid, rid);
                video.push(VideoTx { ssrc: main, seq: 1, ts: 0 });
            }
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::channel(4096);
        let task = Task {
            rtc,
            io,
            local,
            cmds: cmd_rx,
            events: event_tx,
            ctl: None,
            audio_ssrc,
            video,
            audio_seq: 1,
            audio_ts: 0,
            mids: HashMap::new(),
            hold: false,
            held: Vec::new(),
            closing: false,
        };
        tokio::spawn(task.run());
        Ok(Ok(Self {
            participant_id: joined.participant_id,
            participant_token: joined.participant_token,
            participants: joined.participants,
            home_token: joined.home_token,
            audio_mid: audio_mid.to_string(),
            video_mid: video_mid.map(|m| m.to_string()),
            ufrag,
            node_ufrag,
            node_pwd,
            cmds: cmd_tx,
            events: event_rx,
        }))
    }

    /// Keeps the node's offers unanswered while `hold`; when it ends, the
    /// kept ones are answered in their order. A slow client, for the tests.
    pub async fn hold_offers(&self, hold: bool) {
        let _ = self.cmds.send(Cmd::Hold(hold)).await;
    }

    /// The next event, within `timeout`.
    pub async fn next(&mut self, timeout: Duration) -> Option<RoomEvent> {
        tokio::time::timeout(timeout, self.events.recv()).await.ok().flatten()
    }

    /// Events until `pick` takes one, within `timeout`; the others are dropped.
    pub async fn wait_for<T>(&mut self, timeout: Duration, mut pick: impl FnMut(&RoomEvent) -> Option<T>) -> Option<T> {
        let until = Instant::now() + timeout;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let event = self.next(left).await?;
            if let Some(t) = pick(&event) {
                return Some(t);
            }
        }
    }

    /// One audio packet: `payload` as it is, 20 ms on the clock.
    pub async fn send_audio(&self, payload: &[u8], level: Option<i8>) {
        let _ = self.cmds.send(Cmd::Audio { payload: payload.to_vec(), level }).await;
    }

    /// One video packet on the only stream, or the lowest layer; `marker`
    /// ends a frame, and the next one is a frame later on the clock.
    pub async fn send_video(&self, payload: &[u8], marker: bool) {
        self.send_video_layer(0, payload, marker).await;
    }

    /// One video packet on layer `layer` (an index into the rids of
    /// `JoinOptions::layers`).
    pub async fn send_video_layer(&self, layer: usize, payload: &[u8], marker: bool) {
        let _ = self.cmds.send(Cmd::Video { layer, payload: payload.to_vec(), marker }).await;
    }

    /// Asks the node for the layer `rid` of `participant`'s video; `None`
    /// for the top one.
    pub async fn request_layer(&self, participant: u32, rid: Option<&str>) {
        let message = ctl::Message::Layer { participant, rid: rid.map(str::to_string) };
        if let Ok(json) = serde_json::to_vec(&message) {
            let _ = self.cmds.send(Cmd::Text(json)).await;
        }
    }

    /// Bytes to everybody else in the room, over `ctl`.
    pub async fn send_bytes(&self, data: &[u8]) {
        let _ = self.cmds.send(Cmd::Bytes(data.to_vec())).await;
    }

    /// Ends the connection, telling the node (DTLS close_notify).
    pub async fn close(&self) {
        let _ = self.cmds.send(Cmd::Close).await;
    }

    /// Leaves over the control channel, with the participant's own token.
    pub async fn leave(&self, node: &NodeRef, room: &str) -> anyhow::Result<()> {
        let mut control = ControlClient::connect(node).await?;
        let request = LeaveRequest { participant_id: self.participant_id, token: self.participant_token.clone() };
        control
            .post::<_, serde_json::Value>(&format!("{}/{room}/{}", rooms::PATH_ROOMS, rooms::action::LEAVE), &request)
            .await?
            .map_err(|(status, r)| anyhow::anyhow!("leave refused: {status} {}: {}", r.error, r.message))?;
        self.close().await;
        Ok(())
    }

    /// In the cascade: the seat at the home given up with the home token,
    /// as a client does when its own node is gone.
    pub async fn leave_home(&self, home: &NodeRef, room: &str) -> anyhow::Result<()> {
        let token = self.home_token.clone().context("no home token: not a seat of the cascade")?;
        let mut control = ControlClient::connect(home).await?;
        let request = LeaveRequest { participant_id: self.participant_id, token };
        control
            .post::<_, serde_json::Value>(&format!("{}/{room}/{}", rooms::PATH_ROOMS, rooms::action::LEAVE), &request)
            .await?
            .map_err(|(status, r)| anyhow::anyhow!("leave refused: {status} {}: {}", r.error, r.message))?;
        Ok(())
    }
}

/// The socket to the SFU: a datagram each, or frames on a stream.
enum Io {
    Udp(UdpSocket),
    Tcp { stream: TcpStream, buf: Vec<u8>, remote: SocketAddr },
}

impl Io {
    /// One datagram into `out`, and where it came from.
    async fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<SocketAddr> {
        match self {
            Io::Udp(socket) => {
                out.resize(2000, 0);
                let (n, from) = socket.recv_from(out).await?;
                out.truncate(n);
                Ok(from)
            }
            Io::Tcp { stream, buf, remote } => loop {
                if buf.len() >= 2 {
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() >= 2 + len {
                        out.clear();
                        out.extend_from_slice(&buf[2..2 + len]);
                        buf.drain(..2 + len);
                        return Ok(*remote);
                    }
                }
                let mut chunk = [0u8; 4096];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                buf.extend_from_slice(&chunk[..n]);
            },
        }
    }

    async fn send(&mut self, t: &Transmit) -> io::Result<()> {
        match self {
            Io::Udp(socket) => socket.send_to(&t.contents, t.destination).await.map(|_| ()),
            Io::Tcp { stream, .. } => {
                let mut frame = Vec::with_capacity(2 + t.contents.len());
                frame.extend_from_slice(&(t.contents.len() as u16).to_be_bytes());
                frame.extend_from_slice(&t.contents);
                stream.write_all(&frame).await
            }
        }
    }

    fn proto(&self) -> Protocol {
        match self {
            Io::Udp(_) => Protocol::Udp,
            Io::Tcp { .. } => Protocol::Tcp,
        }
    }
}

struct Task {
    rtc: Rtc,
    io: Io,
    local: SocketAddr,
    cmds: mpsc::Receiver<Cmd>,
    events: mpsc::Sender<RoomEvent>,
    ctl: Option<ChannelId>,
    audio_ssrc: Ssrc,
    video: Vec<VideoTx>,
    audio_seq: u64,
    audio_ts: u32,
    mids: HashMap<Ssrc, Mid>,
    /// Offers are kept rather than answered; the kept ones.
    hold: bool,
    held: Vec<(u32, String, Vec<ctl::Track>)>,
    /// A close is under way, said by either side.
    closing: bool,
}

impl Task {
    async fn run(mut self) {
        let mut buf = vec![0u8; 2000];
        loop {
            let timeout = loop {
                if !self.rtc.is_alive() {
                    let _ = self.events.send(RoomEvent::Closed).await;
                    return;
                }
                // One closing finishes on a timeout alone (str0m ends the
                // instance in its timeout handling, and asks for no timeout
                // once drained): given one now, it is closed as soon as it
                // has said its close.
                if self.closing && self.rtc.handle_input(Input::Timeout(Instant::now())).is_ok() && !self.rtc.is_alive() {
                    continue;
                }
                match self.rtc.poll_output() {
                    // An instance whose close drained in this very poll
                    // ends with it, and asks for no timeout: seen now, not
                    // at the next wake, which may never come (a node that
                    // ended the room says nothing more).
                    Ok(Output::Timeout(_)) if !self.rtc.is_alive() => continue,
                    Ok(Output::Timeout(t)) => break t,
                    Ok(Output::Transmit(t)) => {
                        if let Err(e) = self.io.send(&t).await {
                            tracing::debug!(error = %e, "room client: send failed");
                            self.rtc.disconnect();
                        }
                    }
                    Ok(Output::Event(e)) => self.event(e).await,
                    Err(e) => {
                        tracing::debug!(error = %e, "room client: poll failed");
                        self.rtc.disconnect();
                    }
                }
            };
            let proto = self.io.proto();
            tokio::select! {
                r = self.io.recv(&mut buf) => match r {
                    Ok(source) => {
                        if let Ok(recv) = Receive::new(proto, source, self.local, &buf) {
                            if let Err(e) = self.rtc.handle_input(Input::Receive(Instant::now(), recv)) {
                                tracing::debug!(error = %e, "room client: input refused");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "room client: the connection ended");
                        self.rtc.disconnect();
                    }
                },
                cmd = self.cmds.recv() => match cmd {
                    // A close is said to the node (DTLS close_notify), and the
                    // instance drains what it has to say before it ends.
                    Some(Cmd::Close) | None => {
                        self.closing = true;
                        let _ = self.rtc.close();
                    }
                    Some(cmd) => self.command(cmd),
                },
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(timeout)) => {
                    let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));
                }
            }
        }
    }

    fn pt_of(&self, codec: Codec) -> Option<str0m::media::Pt> {
        self.rtc.codec_config().params().iter().find(|p| p.spec().codec == codec).map(|p| p.pt())
    }

    fn command(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Audio { payload, level } => {
                let Some(pt) = self.pt_of(Codec::Opus) else { return };
                let seq = SeqNo::from(self.audio_seq);
                self.audio_seq += 1;
                self.audio_ts = self.audio_ts.wrapping_add(960);
                let ts = self.audio_ts;
                if let Some(stream) = self.rtc.direct_api().stream_tx(&self.audio_ssrc) {
                    let ext = ExtensionValues { audio_level: level, voice_activity: level.map(|l| l > -50), ..ExtensionValues::default() };
                    stream.write_rtp(RtpWrite::new(pt, seq, ts, Instant::now(), payload).ext_vals(ext));
                }
            }
            Cmd::Video { layer, payload, marker } => {
                let Some(pt) = self.pt_of(Codec::Vp8) else { return };
                let Some(video) = self.video.get_mut(layer) else { return };
                let seq = SeqNo::from(video.seq);
                video.seq += 1;
                // Every packet of a frame carries the frame's timestamp;
                // the clock moves on after the one with the marker.
                let ts = video.ts;
                if marker {
                    video.ts = video.ts.wrapping_add(3000);
                }
                if let Some(stream) = self.rtc.direct_api().stream_tx(&video.ssrc) {
                    stream.write_rtp(RtpWrite::new(pt, seq, ts, Instant::now(), payload).marker(marker).nackable(true));
                }
            }
            Cmd::Bytes(data) => {
                if let Some(mut channel) = self.ctl.and_then(|id| self.rtc.channel(id)) {
                    let _ = channel.write(true, &data);
                }
            }
            Cmd::Text(json) => {
                if let Some(mut channel) = self.ctl.and_then(|id| self.rtc.channel(id)) {
                    let _ = channel.write(false, &json);
                }
            }
            Cmd::Hold(hold) => {
                self.hold = hold;
                if !hold {
                    for (seq, sdp, tracks) in std::mem::take(&mut self.held) {
                        if self.offer(seq, &sdp) {
                            let _ = self.events.try_send(RoomEvent::Tracks(tracks));
                        }
                    }
                }
            }
            Cmd::Close => {}
        }
    }

    async fn event(&mut self, event: Event) {
        let out = match event {
            Event::Connected => Some(RoomEvent::Connected),
            Event::Closed => {
                // The node said its close: this side drains and ends.
                self.closing = true;
                None
            }
            Event::IceConnectionStateChange(str0m::IceConnectionState::Disconnected) => {
                self.rtc.disconnect();
                None
            }
            Event::ChannelOpen(id, label) => {
                if label == rooms::CTL_CHANNEL {
                    self.ctl = Some(id);
                    Some(RoomEvent::CtlOpen)
                } else {
                    None
                }
            }
            Event::ChannelData(data) if Some(data.id) == self.ctl => {
                if data.binary {
                    ctl::from_relayed(&data.data).map(|(from, bytes)| RoomEvent::Bytes { from, data: bytes.to_vec() })
                } else {
                    match serde_json::from_slice::<ctl::Message>(&data.data) {
                        Ok(ctl::Message::Hello { you, participants }) => Some(RoomEvent::Hello { you, participants }),
                        Ok(ctl::Message::Joined { id }) => Some(RoomEvent::Joined(id)),
                        Ok(ctl::Message::Left { id }) => Some(RoomEvent::Left(id)),
                        Ok(ctl::Message::Speaking { participants }) => Some(RoomEvent::Speaking(participants)),
                        Ok(ctl::Message::Offer { seq, sdp, tracks }) => {
                            let _ = self.events.send(RoomEvent::Offer(seq)).await;
                            if self.hold {
                                self.held.push((seq, sdp, tracks));
                                None
                            } else {
                                self.offer(seq, &sdp).then_some(RoomEvent::Tracks(tracks))
                            }
                        }
                        Ok(ctl::Message::HomeLost) => Some(RoomEvent::HomeLost),
                        Ok(ctl::Message::Answer { .. }) | Ok(ctl::Message::Layer { .. }) | Err(_) => None,
                    }
                }
            }
            Event::RtpPacket(packet) => {
                let ssrc = packet.header.ssrc;
                let mid = match self.mids.get(&ssrc) {
                    Some(mid) => Some(*mid),
                    None => {
                        let mid = self.rtc.direct_api().stream_rx(&ssrc).map(|s| s.mid());
                        if let Some(mid) = mid {
                            self.mids.insert(ssrc, mid);
                        }
                        mid
                    }
                };
                mid.map(|mid| RoomEvent::Rtp {
                    mid: mid.to_string(),
                    pt: *packet.header.payload_type,
                    seq: *packet.seq_no,
                    timestamp: packet.header.timestamp,
                    marker: packet.header.marker,
                    audio_level: packet.header.ext_vals.audio_level,
                    payload: packet.payload.to_vec(),
                })
            }
            _ => None,
        };
        if let Some(out) = out {
            let _ = self.events.send(out).await;
        }
    }

    /// The node's offer `seq` taken, the answer sent back on `ctl`.
    fn offer(&mut self, seq: u32, sdp: &str) -> bool {
        let Ok(offer) = SdpOffer::from_sdp_string(sdp) else {
            return false;
        };
        let Ok(answer) = self.rtc.sdp_api().accept_offer(offer) else {
            return false;
        };
        let Ok(json) = serde_json::to_vec(&ctl::Message::Answer { seq, sdp: answer.to_sdp_string() }) else {
            return false;
        };
        match self.ctl.and_then(|id| self.rtc.channel(id)) {
            Some(mut channel) => matches!(channel.write(false, &json), Ok(true)),
            None => false,
        }
    }
}

/// The address a socket here reaches `node` from.
pub fn local_ip_towards(node: SocketAddr) -> io::Result<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(node)?;
    Ok(probe.local_addr()?.ip())
}
