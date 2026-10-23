//! An uplink: this node as a participant of another node's room, for one
//! participant of its own (the cascade).
//!
//! ```text
//!  seat p on this node ──▶ satellite ──▶ U_p ──UDP──▶ the home's SFU port
//!                                      ◀── U_p ◀────── what the home sends p
//! ```
//!
//! An uplink is a str0m `Rtc` as `room_client` has one, on a UDP socket
//! of its own, driven by the satellite room that owns it: a full ICE
//! agent (the home is ICE-lite) that checks its pair every second and
//! gives the home up after a few seconds of silence. Its offer mirrors
//! the participant's: the same audio and video m-lines, `sendonly`, the
//! same simulcast rids in the same order, and the channel `ctl`. What
//! the participant sends goes up on it as it came; what the home offers
//! on it comes down to the participant on m-lines of this node.
//!
//! Only the home's address is taken as a candidate, and only the home's
//! address is let through to str0m: a node must not open connections to
//! wherever a client's word points it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::media::{MediaKind, Mid, Rid, Simulcast, SimulcastLayer};
use str0m::net::Protocol;
use str0m::rtp::Ssrc;
use str0m::{Candidate, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use vcall_proto::rooms::ctl;

use super::sdp::{self, MediaSection};
use super::room::{NotQueued, RoomInput, RoomSender};
use crate::counters::{Bump, Counters};
use crate::turn::limits::Bucket;
use crate::turn::policy::{PeerPolicy, Port};

/// The ICE agent of an uplink checks its pair this often once connected,
/// and gives up after this many unanswered checks: the home is gone in
/// about five seconds (str0m's defaults are 3 s and 9, some twenty).
pub const STUN_RTO: Duration = Duration::from_secs(1);
pub const STUN_RETRANSMITS: usize = 5;
/// A datagram from the home is at most this.
const MAX_DATAGRAM: usize = 2000;

/// One m-line of the seat's offer mirrored on the uplink: the seat's
/// mid, the uplink's mid, and the SSRC the uplink sends each layer on
/// (one, or the rids in the seat's order).
pub struct UpTrack {
    pub seat_mid: Mid,
    pub mid: Mid,
    pub kind: MediaKind,
    pub layers: Vec<(Option<Rid>, Ssrc)>,
}

/// One stream the home sends on this uplink: on its m-line, of a
/// participant of the room, in these layers (the home sends one of them
/// at a time; the seat asks for the one it wants and this node passes
/// the ask on).
pub struct DownTrack {
    pub mid: Mid,
    pub id: u32,
    pub kind: MediaKind,
    pub rids: Vec<String>,
    pub last_keyframe_request: Option<Instant>,
}

/// An uplink in the making: the offer is out, the answer not in.
pub struct UplinkDraft {
    rtc: Rtc,
    pending: SdpPendingOffer,
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    sections: Vec<(MediaSection, Mid)>,
    pub offer_sdp: String,
}

pub struct Uplink {
    /// The seat this uplink is for: the number the home gave.
    pub seat: u32,
    pub rtc: Rtc,
    pub socket: Arc<UdpSocket>,
    /// The candidate this side declared: the destination str0m is told.
    pub local: SocketAddr,
    pub home_ip: IpAddr,
    /// The token of the seat at the home: the client may give the seat up
    /// with it when this node is gone.
    pub home_token: String,
    pub ctl: Option<ChannelId>,
    pub connected: bool,
    pub tx: Vec<UpTrack>,
    pub rx: Vec<DownTrack>,
    /// What the home sends on each SSRC, once seen.
    pub ssrc_mids: std::collections::HashMap<Ssrc, Mid>,
    /// What the home may send down, bytes a second: what the seat may be
    /// sent, this node's allowance for one participant times the others
    /// of the home's roster (the satellite sizes it as the roster goes;
    /// one share until the roster is known).
    pub ingress: Bucket,
    /// Frames of the home on `ctl` a second: the pace of a participant's.
    pub ctl_rate: Bucket,
    pub last_packet: Instant,
    pub made_at: Instant,
    /// Told once: the uplink is up (its `ctl` open), or it is not coming.
    pub ready: Option<oneshot::Sender<Result<(), String>>>,
    /// The home stopped answering (ICE disconnected, or silence).
    pub lost: bool,
    /// Closed by this node for its seat: its end is nobody's loss.
    pub closing: bool,
    /// When this node closed it: one that does not finish closing in a
    /// while is cut.
    pub closed_at: Option<Instant>,
    reader: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Uplink {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }
}

impl UplinkDraft {
    /// An uplink's offer for a seat whose offer is `seat_offer`: bound on
    /// `bind_ip`, declaring `public_ip` as its candidate.
    pub async fn make(seat_offer: &str, bind_ip: IpAddr, public_ip: IpAddr) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await.context("an uplink socket")?;
        let local = SocketAddr::new(public_ip, socket.local_addr()?.port());
        super::init_crypto();
        let mut config = Rtc::builder().set_rtp_mode(true).clear_codecs().enable_opus(true, false).enable_vp8(true).enable_h264(true);
        config.set_max_stun_rto(STUN_RTO);
        config.set_max_stun_retransmits(STUN_RETRANSMITS);
        let mut rtc = config.build(Instant::now());
        rtc.add_local_candidate(Candidate::host(local, Protocol::Udp)?);
        let mut change = rtc.sdp_api();
        let mut sections = Vec::new();
        for section in sdp::media_sections(seat_offer) {
            let simulcast = (section.kind.is_video() && !section.rids.is_empty()).then(|| {
                let mut s = Simulcast::new();
                for rid in &section.rids {
                    s.add_send_layer(SimulcastLayer::new(rid));
                }
                s
            });
            let mid = change.add_media(section.kind, str0m::media::Direction::SendOnly, Some("up".into()), None, simulcast);
            sections.push((section, mid));
        }
        change.add_channel(vcall_proto::rooms::CTL_CHANNEL.to_string());
        let (offer, pending) = change.apply().context("nothing to offer")?;
        let offer_sdp = offer.to_sdp_string();
        Ok(Self { rtc, pending, socket: Arc::new(socket), local, sections, offer_sdp })
    }

    /// The home's answer taken, with its candidates at the home's address
    /// alone (UDP, and allowed by `policy`): the uplink, its streams
    /// declared, ready to be driven. `Err` when no candidate is usable or
    /// the answer is not.
    pub fn accept(mut self, answer_sdp: &str, home_ip: IpAddr, policy: &PeerPolicy, seat: u32, home_token: String, kbps: u32) -> anyhow::Result<Uplink> {
        let live = std::collections::HashSet::new();
        let (answer_sdp, kept) = sdp::keep_candidates(answer_sdp, |transport, ip| {
            transport == "udp" && ip == home_ip && policy.check(SocketAddr::new(ip, 1), Port::Used { live_relay_ports: &live }).is_ok()
        });
        anyhow::ensure!(kept > 0, "no candidate of the home's answer is at the home's address");
        let answer = SdpAnswer::from_sdp_string(&answer_sdp).context("the home's answer")?;
        self.rtc.sdp_api().accept_answer(self.pending, answer).context("the home's answer")?;
        let mut tx = Vec::new();
        for (section, mid) in &self.sections {
            let groups = sdp::ssrc_groups_of(&self.offer_sdp, mid);
            anyhow::ensure!(!groups.is_empty(), "no ssrc for the m-line {mid} of the uplink's offer");
            let mut layers = Vec::new();
            for (n, (main, rtx)) in groups.into_iter().enumerate() {
                let (main, rtx) = (Ssrc::from(main), rtx.map(Ssrc::from));
                let rid = section.rids.get(n).map(|r| Rid::from(r.as_str()));
                self.rtc.direct_api().declare_stream_tx(main, rtx, *mid, rid);
                layers.push((rid, main));
            }
            tx.push(UpTrack { seat_mid: Mid::from(section.mid.as_str()), mid: *mid, kind: section.kind, layers });
        }
        let now = Instant::now();
        Ok(Uplink {
            seat,
            rtc: self.rtc,
            socket: self.socket,
            local: self.local,
            home_ip,
            home_token,
            ctl: None,
            connected: false,
            tx,
            rx: Vec::new(),
            ssrc_mids: std::collections::HashMap::new(),
            ingress: Bucket::from_kbps(u64::from(kbps)),
            ctl_rate: Bucket::new(u64::from(ctl::MAX_FRAMES_PER_SEC)),
            last_packet: now,
            made_at: now,
            ready: None,
            lost: false,
            closing: false,
            closed_at: None,
            reader: None,
        })
    }
}

impl Uplink {
    /// Reads the socket into `room` for as long as the uplink lives.
    /// Packets from anywhere but the home are dropped here, before str0m:
    /// an uplink is a server with one address, it has no peer-reflexive
    /// candidates to find. A room too busy to take a packet loses that
    /// packet (counted, as the SFU socket counts its own), not the
    /// reader: a full queue is a moment, a deaf uplink would be the home
    /// lost.
    pub(crate) fn start_reading(&mut self, room: RoomSender, counters: Arc<Counters>) {
        let socket = self.socket.clone();
        let seat = self.seat;
        let home_ip = self.home_ip;
        self.reader = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let (n, source) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::trace!(error = %e, "uplink recv");
                        continue;
                    }
                };
                if source.ip() != home_ip {
                    continue;
                }
                let input = RoomInput::UplinkPacket { seat, source, at: Instant::now(), data: buf[..n].to_vec() };
                match room.try_send(input) {
                    Ok(()) => {}
                    Err(NotQueued::Full) => counters.sfu_dropped_queue.bump(),
                    Err(NotQueued::Closed) => break,
                }
            }
        }));
    }

    /// The reader is still at the socket.
    #[cfg(test)]
    fn reading(&self) -> bool {
        self.reader.as_ref().is_some_and(|r| !r.is_finished())
    }

    /// The up-track the seat's m-line `seat_mid` goes on.
    pub fn up_track(&self, seat_mid: Mid) -> Option<&UpTrack> {
        self.tx.iter().find(|t| t.seat_mid == seat_mid)
    }

    pub fn down_track(&self, mid: Mid) -> Option<&DownTrack> {
        self.rx.iter().find(|t| t.mid == mid)
    }

    pub fn down_track_mut(&mut self, mid: Mid) -> Option<&mut DownTrack> {
        self.rx.iter_mut().find(|t| t.mid == mid)
    }

    /// `message` over the uplink's `ctl`; whether the channel took it.
    pub fn send_ctl(&mut self, message: &ctl::Message) -> bool {
        let Some(cid) = self.ctl else { return false };
        let Ok(json) = serde_json::to_vec(message) else { return false };
        matches!(self.rtc.channel(cid).map(|mut c| c.write(false, &json)), Some(Ok(true)))
    }

    /// Bytes of the seat over the uplink's `ctl`, as the seat sent them;
    /// the home puts the seat's number in front for the others.
    pub fn send_bytes(&mut self, data: &[u8]) -> bool {
        let Some(cid) = self.ctl else { return false };
        matches!(self.rtc.channel(cid).map(|mut c| c.write(true, data)), Some(Ok(true)))
    }

    /// Told once that it is up, or not.
    pub fn tell_ready(&mut self, result: Result<(), String>) {
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(result);
        }
    }
}

/// An uplink on loopback for the tests of this module and the room's: a
/// seat's offer of audio and three video layers, mirrored, answered by a
/// home at 127.0.0.1:3479 (ICE-lite), accepted as seat `seat`.
#[cfg(test)]
pub(crate) async fn uplink_on_loopback(seat: u32, kbps: u32) -> Uplink {
    let seat_offer = seat_offer_for_tests();
    let draft = UplinkDraft::make(&seat_offer, "127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap()).await.unwrap();
    let mut home = Rtc::builder().set_ice_lite(true).set_rtp_mode(true).clear_codecs().enable_opus(true, false).enable_vp8(true).build(Instant::now());
    home.add_local_candidate(Candidate::host("127.0.0.1:3479".parse().unwrap(), Protocol::Udp).unwrap());
    let answer = home.sdp_api().accept_offer(str0m::change::SdpOffer::from_sdp_string(&draft.offer_sdp).unwrap()).unwrap().to_sdp_string();
    let policy = PeerPolicy::new(vec![], true);
    draft.accept(&answer, "127.0.0.1".parse().unwrap(), &policy, seat, "tok".into(), kbps).unwrap()
}

#[cfg(test)]
fn seat_offer_for_tests() -> String {
    super::init_crypto();
    let mut rtc = Rtc::builder().set_rtp_mode(true).clear_codecs().enable_opus(true, false).enable_vp8(true).build(Instant::now());
    let mut change = rtc.sdp_api();
    change.add_media(MediaKind::Audio, str0m::media::Direction::SendOnly, Some("me".into()), None, None);
    let mut s = Simulcast::new();
    for rid in ["q", "h", "f"] {
        s.add_send_layer(SimulcastLayer::new(rid));
    }
    change.add_media(MediaKind::Video, str0m::media::Direction::SendOnly, Some("me".into()), None, Some(s));
    change.add_channel(vcall_proto::rooms::CTL_CHANNEL.to_string());
    change.apply().unwrap().0.to_sdp_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_uplink_mirrors_the_seat_and_takes_the_home_alone() {
        let seat_offer = seat_offer_for_tests();
        let draft = UplinkDraft::make(&seat_offer, "127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap()).await.unwrap();
        let mirrored = sdp::media_sections(&draft.offer_sdp);
        assert_eq!(mirrored.len(), 2);
        assert_eq!((mirrored[0].kind, mirrored[1].kind), (MediaKind::Audio, MediaKind::Video));
        assert_eq!(mirrored[1].rids, vec!["q", "h", "f"]);
        assert!(draft.offer_sdp.contains("a=sendonly"));
        assert!(draft.offer_sdp.contains("webrtc-datachannel"));
        assert_eq!(draft.sections.len(), 2);

        // A home (ICE-lite, as the node's rooms are) answers; a candidate
        // not at its address is dropped before str0m sees it.
        let mut home = Rtc::builder().set_ice_lite(true).set_rtp_mode(true).clear_codecs().enable_opus(true, false).enable_vp8(true).build(Instant::now());
        home.add_local_candidate(Candidate::host("127.0.0.1:3479".parse().unwrap(), Protocol::Udp).unwrap());
        home.add_local_candidate(Candidate::host("10.0.0.5:3479".parse().unwrap(), Protocol::Udp).unwrap());
        let answer = home.sdp_api().accept_offer(str0m::change::SdpOffer::from_sdp_string(&draft.offer_sdp).unwrap()).unwrap().to_sdp_string();
        assert_eq!(answer.matches("a=candidate:").count(), 2);
        let policy = PeerPolicy::new(vec![], true);
        let uplink = draft.accept(&answer, "127.0.0.1".parse().unwrap(), &policy, 3, "tok".into(), 0).unwrap();
        assert_eq!(uplink.seat, 3);
        assert_eq!(uplink.tx.len(), 2);
        assert_eq!(uplink.tx[1].layers.len(), 3, "one SSRC a layer");
        assert_eq!(uplink.tx[1].layers[0].0, Some(Rid::from("q")));
        assert_eq!(uplink.tx[0].seat_mid, Mid::from(sdp::media_sections(&seat_offer)[0].mid.as_str()));
        assert!(uplink.ssrc_mids.is_empty());

        // A home whose answer carries no candidate at its address: refused.
        let draft = UplinkDraft::make(&seat_offer, "127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap()).await.unwrap();
        let mut elsewhere = Rtc::builder().set_ice_lite(true).set_rtp_mode(true).clear_codecs().enable_opus(true, false).build(Instant::now());
        elsewhere.add_local_candidate(Candidate::host("127.0.0.2:3479".parse().unwrap(), Protocol::Udp).unwrap());
        let answer = elsewhere.sdp_api().accept_offer(str0m::change::SdpOffer::from_sdp_string(&draft.offer_sdp).unwrap()).unwrap().to_sdp_string();
        let e = draft.accept(&answer, "127.0.0.1".parse().unwrap(), &policy, 3, "tok".into(), 0).err().expect("refused");
        assert!(e.to_string().contains("no candidate"), "{e}");
    }

    /// The room's queue full for a moment: the datagram is lost and
    /// counted, the reader stays at the socket and the next datagram
    /// reaches the room; a room that is gone ends the reader.
    #[tokio::test]
    async fn a_full_room_queue_loses_a_datagram_and_not_the_reader() {
        let mut uplink = uplink_on_loopback(7, 0).await;
        let counters = Arc::new(Counters::default());
        let (tx, mut rx) = RoomSender::channel(1);
        tx.try_send(RoomInput::HomeLost).unwrap();
        uplink.start_reading(tx, counters.clone());
        let home = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = uplink.socket.local_addr().unwrap();
        home.send_to(b"one", to).await.unwrap();
        let dropped = async {
            while counters.sfu_dropped_queue.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(2), dropped).await.expect("the datagram was dropped for the full queue");
        assert!(uplink.reading(), "the reader goes on");
        assert!(matches!(rx.recv().await, Some(RoomInput::HomeLost)));
        home.send_to(b"two", to).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.expect("the next datagram").expect("a packet") {
            RoomInput::UplinkPacket { seat, data, .. } => assert_eq!((seat, data.as_slice()), (7, &b"two"[..])),
            _ => panic!("not a packet"),
        }
        assert_eq!(counters.sfu_dropped_queue.load(std::sync::atomic::Ordering::Relaxed), 1);
        // A packet from elsewhere is nothing; the room gone ends the reader.
        drop(rx);
        home.send_to(b"three", to).await.unwrap();
        let ended = async {
            while uplink.reading() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(2), ended).await.expect("the reader ended with the room");
    }
}
