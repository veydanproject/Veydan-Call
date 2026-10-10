//! The cascade, as the node of a participant: a seat in another node's
//! room (the home) for one of its own, over an uplink.
//!
//! ```text
//!  client ──join {home, pass}──▶ this node ──HELLO (2 s)──▶ home     reachable? takes uplinks?
//!                                          ──join {pass, word}──▶ home   a proxy seat
//!                                          ◀═══ ICE, DTLS, ctl (4 s) ═══  the uplink is up
//!  client ◀── Joined {seat of the home, home_token} ──
//! ```
//!
//! Every refusal has a class: the client's fault comes back as the home
//! said it (403, 404, 409, 400 `bad_sdp`), or as this node finds it (400
//! `bad_home`: the reference, or something other than the node named at
//! its address); this node's and the way's as 503, after which the
//! client goes to the home itself. A home that could not be reached or
//! used is remembered as such for a minute (`sfu::ReachCache`), so the
//! next join with it is refused at once; what the client got wrong does
//! not mark the home, so that nobody marks a live home bad for others.
//!
//! The limits a node sets on its own cascade, on top of the room's: an
//! access key on a private node; so many joins with a home from one
//! address in ten minutes on a public one (a join opens connections to
//! wherever the client points); so many attempts at once in all and to
//! one home (an attempt holds a seat at the home until it comes up).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::StatusCode;
use ring::signature::Ed25519KeyPair;
use tokio::sync::oneshot;
use vcall_proto::rooms::{self, JoinRequest, Joined, LeaveRequest, UplinkWord};
use vcall_proto::{capability, Access, Hello, Welcome};

use crate::client::{ConnectError, ControlClient};
use crate::counters::{Bump, Counters};
use crate::devices::Gate;
use crate::identity::{NodeId, NodeRef};
use crate::sfu::room::MAX_RX_TRACKS;
use crate::sfu::uplink::UplinkDraft;
use crate::sfu::{sdp, Home, Reach, RoomError, Sfu};
use crate::turn::limits::RateWindow;
use crate::turn::policy::{PeerPolicy, Port};

/// A HELLO to the home is answered within this, or the home is not there.
pub const CASCADE_HELLO: Duration = Duration::from_secs(2);
/// The home answers the join of the uplink within this.
pub const CASCADE_JOIN: Duration = Duration::from_secs(3);
/// ICE, DTLS and `ctl` of the uplink come up within this, by UDP.
pub const CASCADE_CONNECT: Duration = Duration::from_secs(4);
/// Attempts (HELLO to `ctl` open) at once in all, and towards one home.
pub const CASCADE_ATTEMPTS: u32 = 16;
pub const CASCADE_ATTEMPTS_PER_HOME: u32 = 4;
/// Joins with a home from one address, in the window, on a public node.
pub const DEFAULT_CASCADE_JOINS_PER_IP: u32 = 10;
pub const CASCADE_JOINS_WINDOW: Duration = Duration::from_secs(600);
/// The h2 connection to a home is kept alive with a HELLO this often
/// while satellites of the home live here (a home closes a connection
/// without a request for two minutes).
pub const CASCADE_H2_REFRESH: Duration = Duration::from_secs(60);

/// What a join with a home ends in, besides a seat.
pub struct Cascade {
    pub node_id: NodeId,
    pub version: String,
    /// The node's key: what signs its word to a home.
    pub signing_key: Arc<Ed25519KeyPair>,
    pub sfu: Arc<Sfu>,
    pub policy: Arc<PeerPolicy>,
    /// The node takes joins with a home at all.
    pub enabled: bool,
    /// The door of a private node: a key or a device is wanted in the join.
    pub gate: Arc<Gate>,
    /// Joins with a home per address and window, on a public node.
    pub joins: RateWindow,
    pub counters: Arc<Counters>,
    attempts: Mutex<Attempts>,
    /// One control connection a home, kept while its satellites live. By
    /// address and id: a connection is pinned to the id it was made with,
    /// and a join naming another id at the address gets its own.
    links: Mutex<HashMap<LinkKey, ControlClient>>,
    /// The homes whose connection a task keeps alive.
    keepers: Mutex<std::collections::HashSet<LinkKey>>,
}

/// A home as a connection is pinned to it: its address and its id.
type LinkKey = (SocketAddr, NodeId);

fn key_of(home: &NodeRef) -> LinkKey {
    (home.addr, home.id)
}

#[derive(Default)]
struct Attempts {
    all: u32,
    per_home: HashMap<SocketAddr, u32>,
}

/// An attempt under way; given back when it ends, however it ends.
struct Attempt<'a> {
    cascade: &'a Cascade,
    home: SocketAddr,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let mut a = self.cascade.attempts.lock().expect("attempts");
        a.all = a.all.saturating_sub(1);
        if let Some(n) = a.per_home.get_mut(&self.home) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                a.per_home.remove(&self.home);
            }
        }
    }
}

impl Cascade {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        version: String,
        signing_key: Arc<Ed25519KeyPair>,
        sfu: Arc<Sfu>,
        policy: Arc<PeerPolicy>,
        enabled: bool,
        gate: Arc<Gate>,
        joins_per_ip: u32,
        counters: Arc<Counters>,
    ) -> Self {
        Self {
            node_id,
            version,
            signing_key,
            sfu,
            policy,
            enabled,
            gate,
            joins: RateWindow::new(CASCADE_JOINS_WINDOW, joins_per_ip),
            counters,
            attempts: Mutex::new(Attempts::default()),
            links: Mutex::new(HashMap::new()),
            keepers: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// What this node says of itself to a home.
    fn hello(&self) -> Hello {
        Hello {
            protocol_min: vcall_proto::PROTOCOL_MIN,
            protocol_max: vcall_proto::PROTOCOL_MAX,
            capabilities: vec![capability::STUN.into(), capability::TURN.into(), capability::SFU.into(), capability::SIMULCAST.into(), capability::CASCADE.into()],
            codecs: crate::sfu::CODECS.iter().map(|c| c.to_string()).collect(),
            access: Access::default(),
            client: format!("vcall/{}", self.version),
        }
    }

    /// The home named in a join, when it is one this node may reach: a
    /// node reference, not this node, at an address the policy allows.
    fn home_of(&self, request: &JoinRequest) -> Result<Home, RoomError> {
        let text = request.home.as_ref().map(|h| h.node.as_str()).unwrap_or("");
        let node: NodeRef = text.parse().map_err(|_| RoomError::BadHome("the home is not a node reference".into()))?;
        if node.id == self.node_id {
            return Err(RoomError::BadHome("the home is this node".into()));
        }
        let live = std::collections::HashSet::new();
        if let Err(why) = self.policy.check(node.addr, Port::Used { live_relay_ports: &live }) {
            return Err(RoomError::BadHome(format!("the home's address is not one to reach: {why}")));
        }
        Ok(Home { node })
    }

    /// The control connection to `home`: the one kept (and that it was),
    /// or a new one.
    async fn link(&self, home: &NodeRef) -> anyhow::Result<(ControlClient, bool)> {
        if let Some(link) = self.links.lock().expect("links").get(&key_of(home)) {
            return Ok((link.clone(), true));
        }
        let link = ControlClient::connect(home).await?;
        self.links.lock().expect("links").insert(key_of(home), link.clone());
        Ok((link, false))
    }

    fn drop_link(&self, home: &NodeRef) {
        self.links.lock().expect("links").remove(&key_of(home));
    }

    /// Control connections to homes kept now.
    pub fn links_now(&self) -> usize {
        self.links.lock().expect("links").len()
    }

    /// One request to the home within `timeout`. A kept connection that
    /// fails is dropped and the request made once more on a fresh one
    /// (a home closes a connection idle for two minutes); a failure of
    /// the way drops the connection, so that the next request makes a
    /// new one.
    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(&self, home: &NodeRef, path: &str, body: &T, timeout: Duration) -> anyhow::Result<Result<R, (u16, vcall_proto::Refusal)>> {
        let work = async {
            let (mut link, kept) = self.link(home).await?;
            match link.post(path, body).await {
                Err(e) if kept => {
                    tracing::debug!(home = %home.addr, error = %e, "the kept connection to the home failed: a fresh one");
                    self.drop_link(home);
                    let (mut link, _) = self.link(home).await?;
                    link.post(path, body).await
                }
                answer => answer,
            }
        };
        match tokio::time::timeout(timeout, work).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(e)) => {
                self.drop_link(home);
                Err(e)
            }
            Err(_) => {
                self.drop_link(home);
                Err(anyhow::anyhow!("no answer from the home in time"))
            }
        }
    }

    /// Keeps the connection to `home` alive with a HELLO every so often,
    /// while satellites of the home live here.
    fn keep_link(self: &Arc<Self>, home: NodeRef) {
        if !self.keepers.lock().expect("keepers").insert(key_of(&home)) {
            return;
        }
        let cascade = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CASCADE_H2_REFRESH).await;
                if !cascade.sfu.has_satellites_of(home.addr) {
                    cascade.drop_link(&home);
                    break;
                }
                if cascade.post::<_, Welcome>(&home, vcall_proto::PATH_HELLO, &cascade.hello(), CASCADE_HELLO).await.is_err() {
                    // Made anew by the next request; the uplinks judge the home.
                    break;
                }
            }
            cascade.keepers.lock().expect("keepers").remove(&key_of(&home));
        });
    }

    /// A join with a home, step by step: the request judged, the home
    /// reached, the uplink made and brought up, the seat taken. A join
    /// that fails leaves no connection behind, unless satellites of the
    /// home keep it.
    pub async fn join_via_home(self: &Arc<Self>, room_id: &str, request: JoinRequest, peer: IpAddr) -> Result<Joined, RoomError> {
        let home = self.home_of(&request)?;
        let joined = self.join_with_home(&home, room_id, request, peer).await;
        if joined.is_err() && !self.sfu.has_satellites_of(home.addr()) {
            self.drop_link(&home.node);
        }
        joined
    }

    async fn join_with_home(self: &Arc<Self>, home: &Home, room_id: &str, request: JoinRequest, peer: IpAddr) -> Result<Joined, RoomError> {
        let home = home.clone();
        self.sfu.check_home(home.addr(), room_id)?;
        // The seat's offer is judged here as the home judges the uplink's,
        // which mirrors it: the client's fault stays the client's.
        let media_lines = sdp::media_lines(&request.sdp_offer);
        if media_lines > MAX_RX_TRACKS {
            self.counters.joins_refused_sdp.bump();
            return Err(RoomError::BadSdp(format!("{media_lines} media lines, at most {MAX_RX_TRACKS}")));
        }
        if !self.enabled {
            self.counters.cascade_joins_refused.bump();
            return Err(RoomError::CascadeRefused("the cascade is off on this node".into()));
        }
        // Access: a key or a device on a private node, a window per
        // address on a public one.
        if self.gate.private {
            if !self.gate.opens(request.access.as_ref(), crate::turn::unix_now()) {
                self.counters.credentials_refused_access.bump();
                return Err(RoomError::CascadeRefused("key".into()));
            }
        } else if !self.joins.allow(peer) {
            self.counters.credentials_refused_rate.bump();
            return Err(RoomError::CascadeRefused("rate".into()));
        }
        let _attempt = self.attempt(home.addr())?;
        // The way to the home, as remembered, or as HELLO finds it.
        match self.sfu.reach().state(home.addr()) {
            Some(Reach::Bad) => {
                self.counters.cascade_joins_unreachable.bump();
                return Err(RoomError::Unreachable("the home was not reachable lately".into()));
            }
            Some(Reach::Good) => {}
            None => self.hello_home(&home).await?,
        }
        // The uplink: an offer like the seat's, the word, the home's answer.
        let draft = match UplinkDraft::make(&request.sdp_offer, self.sfu.bind_ip(), self.sfu.public_ip()).await {
            Ok(draft) => draft,
            Err(e) => {
                self.counters.joins_refused_sdp.bump();
                return Err(RoomError::BadSdp(e.to_string()));
            }
        };
        let word = UplinkWord::sign(&self.signing_key, &home.node.id.to_string(), room_id, &request.token, crate::turn::unix_now());
        let up = JoinRequest {
            token: request.token.clone(),
            sdp_offer: draft.offer_sdp.clone(),
            caps: request.caps.iter().filter(|c| c.as_str() == capability::SIMULCAST).cloned().collect(),
            access: None,
            home: None,
            uplink: Some(word),
        };
        let path = format!("{}/{room_id}/{}", rooms::PATH_ROOMS, rooms::action::JOIN);
        let joined: Joined = match self.post(&home.node, &path, &up, CASCADE_JOIN).await {
            Ok(Ok(joined)) => joined,
            Ok(Err((status, refusal))) => return Err(self.home_refused(&home, status, refusal)),
            Err(e) => return Err(self.way_failed(&home, "the home did not answer the join", e)),
        };
        let seat = joined.participant_id;
        let home_bandwidth = crate::sfu::sdp::bandwidth_of(&joined.sdp_answer);
        let uplink = match draft.accept(&joined.sdp_answer, home.addr().ip(), &self.policy, seat, joined.participant_token.clone(), self.sfu.config().kbps_per_participant) {
            Ok(uplink) => uplink,
            Err(e) => {
                self.leave_home(&home, room_id, seat, &joined.participant_token).await;
                return Err(self.unreachable(&home, format!("the home's answer could not be used: {e:#}")));
            }
        };
        // Up: ICE, DTLS and `ctl`, within the time.
        let (ready, up) = oneshot::channel();
        if let Err(e) = self.sfu.take_uplink(&home, room_id, uplink, ready) {
            self.leave_home(&home, room_id, seat, &joined.participant_token).await;
            return Err(e);
        }
        match tokio::time::timeout(CASCADE_CONNECT, up).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(why))) => {
                self.sfu.drop_uplink(&home, room_id, seat);
                self.leave_home(&home, room_id, seat, &joined.participant_token).await;
                return Err(self.unreachable(&home, format!("the uplink did not come up: {why}")));
            }
            Ok(Err(_)) | Err(_) => {
                self.sfu.drop_uplink(&home, room_id, seat);
                self.leave_home(&home, room_id, seat, &joined.participant_token).await;
                return Err(self.unreachable(&home, "the uplink did not come up in time"));
            }
        }
        self.keep_link(home.node.clone());
        // The seat: as the home numbered it, told of the others as the
        // home answered (its `hello` on the uplink may be on its way yet).
        match self.sfu.join_satellite(&home, room_id, seat, request, home_bandwidth, joined.participants.clone()).await {
            Ok(joined) => Ok(joined),
            Err(e) => {
                self.sfu.drop_uplink(&home, room_id, seat);
                self.leave_home(&home, room_id, seat, &joined.participant_token).await;
                Err(e)
            }
        }
    }

    /// One more attempt, within the ceilings.
    fn attempt(&self, home: SocketAddr) -> Result<Attempt<'_>, RoomError> {
        let mut a = self.attempts.lock().expect("attempts");
        let to_home = a.per_home.get(&home).copied().unwrap_or(0);
        if a.all >= CASCADE_ATTEMPTS || to_home >= CASCADE_ATTEMPTS_PER_HOME {
            self.counters.cascade_joins_refused.bump();
            return Err(RoomError::CascadeRefused("too many joins with a home under way".into()));
        }
        a.all += 1;
        *a.per_home.entry(home).or_insert(0) += 1;
        Ok(Attempt { cascade: self, home })
    }

    /// HELLO to the home: it answers, and takes uplinks.
    async fn hello_home(&self, home: &Home) -> Result<(), RoomError> {
        match self.post::<_, Welcome>(&home.node, vcall_proto::PATH_HELLO, &self.hello(), CASCADE_HELLO).await {
            Ok(Ok(welcome)) => {
                if welcome.capabilities.iter().any(|c| c == capability::CASCADE) {
                    Ok(())
                } else {
                    self.sfu.reach().mark(home.addr(), Reach::Bad);
                    self.counters.cascade_joins_refused.bump();
                    Err(RoomError::CascadeRefused("the home takes no uplinks".into()))
                }
            }
            Ok(Err((status, refusal))) => Err(self.unreachable(home, format!("the home refused hello: {status} {}", refusal.error))),
            Err(e) => Err(self.way_failed(home, "the home did not answer hello", e)),
        }
    }

    /// A failure of the way, or of the home's answer: remembered, counted.
    fn unreachable(&self, home: &Home, why: impl Into<String>) -> RoomError {
        self.sfu.reach().mark(home.addr(), Reach::Bad);
        self.counters.cascade_joins_unreachable.bump();
        RoomError::Unreachable(why.into())
    }

    /// No answer from the home: the way failing, remembered as such; or
    /// something other than the node named at its address, which is the
    /// client's reference and not the way (a wrong id for a live address
    /// must not mark that address bad for everybody).
    fn way_failed(&self, home: &Home, what: &str, e: anyhow::Error) -> RoomError {
        if ConnectError::is_not_the_node(&e) {
            return RoomError::BadHome(format!("the node at the home's address is not the one named: {e:#}"));
        }
        self.unreachable(home, format!("{what}: {e:#}"))
    }

    /// The home refused the uplink's join: the client's fault as it is
    /// (its pass, the room, its offer), the home's refusal of this node
    /// as `cascade_refused`, anything else as the way failing.
    fn home_refused(&self, home: &Home, status: u16, refusal: vcall_proto::Refusal) -> RoomError {
        match (status, refusal.error.as_str()) {
            (403, vcall_proto::refusal::BAD_TOKEN) => RoomError::BadToken,
            (404, _) => RoomError::NotFound,
            (409, _) => RoomError::Full,
            (400, vcall_proto::refusal::BAD_SDP) => {
                // The uplink's offer mirrors the seat's: what the home
                // could not take of it, the client sent.
                let why = refusal.message.strip_prefix("the offer could not be taken: ").unwrap_or(&refusal.message);
                RoomError::BadSdp(format!("as the home says: {why}"))
            }
            (403, vcall_proto::refusal::CASCADE_REFUSED) => {
                self.sfu.reach().mark(home.addr(), Reach::Bad);
                self.counters.cascade_joins_refused.bump();
                RoomError::CascadeRefused(format!("the home refused this node: {}", refusal.message))
            }
            _ => self.unreachable(home, format!("the home answered {status} {}: {}", refusal.error, refusal.message)),
        }
    }

    /// The seat at the home given up over the control channel, after an
    /// uplink that did not come to a seat; nothing comes of a failure
    /// (the home gives a silent seat up in a few seconds).
    async fn leave_home(&self, home: &Home, room_id: &str, seat: u32, token: &str) {
        let path = format!("{}/{room_id}/{}", rooms::PATH_ROOMS, rooms::action::LEAVE);
        let request = LeaveRequest { participant_id: seat, token: token.to_string() };
        let _ = self.post::<_, serde_json::Value>(&home.node, &path, &request, CASCADE_JOIN).await;
    }
}

/// How a refusal of the cascade reads on the wire: the home's words for
/// the client's fault, 503 for this node's and the way's, and the two
/// of access.
pub fn refused(e: RoomError) -> (StatusCode, vcall_proto::Refusal) {
    use vcall_proto::{refusal, Refusal};
    match e {
        RoomError::CascadeRefused(why) if why == "key" => (StatusCode::UNAUTHORIZED, Refusal::new(refusal::ACCESS_KEY_REQUIRED, "this node needs an access key or the credentials of a device")),
        RoomError::CascadeRefused(why) if why == "rate" => (StatusCode::TOO_MANY_REQUESTS, Refusal::new(refusal::RATE_LIMITED, "too many joins with a home from this address")),
        RoomError::CascadeRefused(why) => (StatusCode::SERVICE_UNAVAILABLE, Refusal::new(refusal::CASCADE_REFUSED, why)),
        RoomError::Unreachable(why) => (StatusCode::SERVICE_UNAVAILABLE, Refusal::new(refusal::CASCADE_UNREACHABLE, why)),
        RoomError::BadHome(why) => (StatusCode::BAD_REQUEST, Refusal::new(refusal::BAD_HOME, why)),
        other => crate::control::Refused::from(other),
    }
}
