//! The control channel: h2 over the node's TLS port, ALPN `vcall/1`.
//!
//! The requests (`vcall-proto`): HELLO, which says what the node is and
//! can do; TURN, which hands out credentials; the rooms of the SFU, made,
//! joined and left; and an invitation exchanged for the credentials of a
//! device. A public node gives credentials and rooms to anybody, so many
//! per address; a private node only to a caller with an access key or
//! the credentials of a device it made (`devices::Gate`). A signed pass
//! is refused until passes are done. Nothing here knows who the caller is.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{Method, Request, Response, StatusCode};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use vcall_proto::invite::{DeviceCredentials, InviteRequest};
use vcall_proto::rooms::{self, action, DelegateRequest, JoinRequest, LeaveRequest, RoomRequest, TokenRequest};
use vcall_proto::{refusal, Access, Hello, Limits, Refusal, TurnCredentials, TurnRequest, Welcome};
use vlink_proto::io;

use crate::cascade::Cascade;
use crate::counters::{Bump, Counters};
use crate::devices::{ExchangeError, Gate};
use crate::sfu::{RoomError, Sfu};
use crate::turn::auth::Auth;
use crate::turn::limits::RateWindow;
use crate::turn::unix_now;
use crate::{decoy, identity::NodeId};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// Requests one control connection may hold open at once.
const MAX_STREAMS: u32 = 16;
/// Exchanges of an invitation one address may try in the window, right
/// or wrong: a token has 192 bits, and a guesser gets ten tries an hour.
pub const INVITE_ATTEMPTS_PER_IP: u32 = 10;
pub const INVITE_WINDOW: Duration = Duration::from_secs(3600);

/// Tokens of rooms (join, admin) that may be wrong, from one address in a
/// window. The id of a room is no secret to whoever was in it, and every
/// try costs the room's task a turn; past this the address is told to wait.
pub const BAD_TOKENS_PER_IP: u32 = 20;
pub const BAD_TOKENS_WINDOW: Duration = Duration::from_secs(60);

pub struct Control {
    pub node_id: NodeId,
    pub version: String,
    pub capabilities: Vec<String>,
    /// What the SFU forwards.
    pub codecs: Vec<String>,
    pub private: bool,
    /// The door of a private node: the keys, and the devices it made.
    pub gate: Arc<Gate>,
    /// The node as a device is told it: `address:port#id`.
    pub node_ref: String,
    /// Exchanges of invitations per address and window.
    pub invites: RateWindow,
    /// Issuers of passes the node would trust: kept, not used yet.
    pub issuers: Vec<String>,
    pub auth: Arc<Auth>,
    pub credentials_ttl: Duration,
    /// A connection with no request for this long is closed: a client
    /// comes for HELLO and credentials and goes, and a thousand that
    /// come and stay would be all the node's connections.
    pub idle: Duration,
    /// Where the credentials are good: the node's STUN and TURN URIs.
    pub urls: Vec<String>,
    pub limits: Limits,
    /// Credentials and rooms per address and window, on a public node.
    pub rate: RateWindow,
    /// Wrong tokens of rooms per address and window.
    pub bad_tokens: RateWindow,
    pub counters: Arc<Counters>,
    pub sfu: Arc<Sfu>,
    /// Joins with a home: this node as the participant's own.
    pub cascade: Arc<Cascade>,
}

pub type Refused = (StatusCode, Refusal);

impl From<RoomError> for Refused {
    fn from(e: RoomError) -> Self {
        match e {
            RoomError::NotFound => (StatusCode::NOT_FOUND, Refusal::new(refusal::ROOM_NOT_FOUND, "no such room")),
            RoomError::BadToken => (StatusCode::FORBIDDEN, Refusal::new(refusal::BAD_TOKEN, "the token is not the room's")),
            RoomError::Full => (StatusCode::CONFLICT, Refusal::new(refusal::ROOM_FULL, "every seat of the room is taken")),
            RoomError::RoomsFull => (StatusCode::TOO_MANY_REQUESTS, Refusal::new(refusal::ROOMS_FULL, "the node holds as many rooms as it may")),
            RoomError::BadSdp(why) => (StatusCode::BAD_REQUEST, Refusal::new(refusal::BAD_SDP, format!("the offer could not be taken: {why}"))),
            RoomError::BadWord(why) => (StatusCode::BAD_REQUEST, Refusal::new(refusal::BAD_REQUEST, why)),
            RoomError::BadHome(why) => (StatusCode::BAD_REQUEST, Refusal::new(refusal::BAD_HOME, why)),
            // As a home: this node refuses the other node's seat.
            RoomError::CascadeRefused(why) => (StatusCode::FORBIDDEN, Refusal::new(refusal::CASCADE_REFUSED, why)),
            RoomError::Unreachable(why) => (StatusCode::SERVICE_UNAVAILABLE, Refusal::new(refusal::CASCADE_UNREACHABLE, why)),
        }
    }
}

impl Control {
    /// Checks what the caller shows. On a public node, a pass is still
    /// refused (so that nobody relies on it being ignored), a key is
    /// ignored, and the rate of the address is counted.
    fn access(&self, access: &Access, peer: IpAddr) -> Result<(), Refused> {
        if access.pass.is_some() {
            // TODO: verify the pass against `issuers` once the scheme is fixed.
            self.counters.control_refused.bump();
            return Err((StatusCode::FORBIDDEN, Refusal::new(refusal::PASS_UNSUPPORTED, "signed passes are not accepted yet")));
        }
        if self.private {
            if !self.gate.opens(Some(access), unix_now()) {
                self.counters.credentials_refused_access.bump();
                return Err((StatusCode::UNAUTHORIZED, Refusal::new(refusal::ACCESS_KEY_REQUIRED, "this node needs an access key or the credentials of a device")));
            }
            return Ok(());
        }
        if !self.rate.allow(peer) {
            self.counters.credentials_refused_rate.bump();
            return Err((StatusCode::TOO_MANY_REQUESTS, Refusal::new(refusal::RATE_LIMITED, "too many requests from this address")));
        }
        Ok(())
    }

    pub fn hello(&self, hello: &Hello) -> Result<Welcome, Refused> {
        let welcome = Welcome {
            protocol_min: vcall_proto::PROTOCOL_MIN,
            protocol_max: vcall_proto::PROTOCOL_MAX,
            node_id: self.node_id.to_string(),
            version: self.version.clone(),
            capabilities: self.capabilities.clone(),
            codecs: self.codecs.clone(),
            private: self.private,
            limits: self.limits.clone(),
        };
        if vcall_proto::common_version((hello.protocol_min, hello.protocol_max), (welcome.protocol_min, welcome.protocol_max)).is_none() {
            self.counters.control_refused.bump();
            return Err((
                StatusCode::UPGRADE_REQUIRED,
                Refusal::new(refusal::VERSION, format!("the node speaks {}..{}", welcome.protocol_min, welcome.protocol_max)),
            ));
        }
        Ok(welcome)
    }

    pub fn turn(&self, request: &TurnRequest, peer: IpAddr) -> Result<TurnCredentials, Refused> {
        self.access(&request.access, peer)?;
        let now = unix_now();
        let c = self.auth.issue(now, self.credentials_ttl);
        self.counters.credentials_issued.bump();
        Ok(TurnCredentials {
            username: c.username,
            password: c.password,
            realm: self.auth.realm().to_string(),
            ttl_secs: self.credentials_ttl.as_secs(),
            expires_at: c.expires_at,
            urls: self.urls.clone(),
        })
    }

    /// A room: the same access as credentials, and the same allowance per
    /// address on a public node.
    pub fn create_room(&self, request: &RoomRequest, peer: IpAddr) -> Result<rooms::RoomCreated, Refused> {
        self.access(&request.access, peer)?;
        Ok(self.sfu.create_room(&request.media_limits)?)
    }

    /// A pass for a proxy seat: counted per address as rooms are, on a
    /// public node (a member asks once per join).
    pub async fn delegate(&self, id: &str, request: &DelegateRequest, peer: IpAddr) -> Result<rooms::Delegated, Refused> {
        if !self.private && !self.rate.allow(peer) {
            self.counters.credentials_refused_rate.bump();
            return Err((StatusCode::TOO_MANY_REQUESTS, Refusal::new(refusal::RATE_LIMITED, "too many requests from this address")));
        }
        Ok(self.sfu.delegate(id, request.token.clone()).await?)
    }

    /// A join: of a room here, or, with a home named, of a room elsewhere
    /// through this node.
    pub async fn join(&self, id: &str, request: JoinRequest, peer: IpAddr) -> Result<rooms::Joined, Refused> {
        self.not_guessing(peer)?;
        let joined = if request.home.is_some() {
            self.cascade.join_via_home(id, request, peer).await.map_err(crate::cascade::refused)
        } else {
            self.sfu.join(id, request).await.map_err(Refused::from)
        };
        self.noted(peer, joined)
    }

    /// Leaving a room: the participant's token is the proof.
    pub async fn leave(&self, id: &str, request: LeaveRequest, peer: IpAddr) -> Result<serde_json::Value, Refused> {
        self.not_guessing(peer)?;
        let left = self.sfu.leave(id, request).await.map(|()| serde_json::json!({})).map_err(Refused::from);
        self.noted(peer, left)
    }

    /// A new join token, by the admin token.
    pub async fn change_token(&self, id: &str, request: TokenRequest, peer: IpAddr) -> Result<rooms::TokenChanged, Refused> {
        self.not_guessing(peer)?;
        let changed = self.sfu.change_token(id, request.admin_token).await.map_err(Refused::from);
        self.noted(peer, changed)
    }

    /// An address that was wrong about tokens too often is not answered
    /// until its window is over, whatever it brings.
    fn not_guessing(&self, peer: IpAddr) -> Result<(), Refused> {
        if self.bad_tokens.exhausted(peer) {
            self.counters.credentials_refused_rate.bump();
            return Err((StatusCode::TOO_MANY_REQUESTS, Refusal::new(refusal::RATE_LIMITED, "too many wrong tokens from this address")));
        }
        Ok(())
    }

    /// Counts a wrong token against the address it came from.
    fn noted<T>(&self, peer: IpAddr, result: Result<T, Refused>) -> Result<T, Refused> {
        if matches!(&result, Err((_, refusal)) if refusal.error == refusal::BAD_TOKEN) {
            self.bad_tokens.allow(peer);
        }
        result
    }

    /// An invitation exchanged for the credentials of a device. Every
    /// attempt counts against the address, so that a token cannot be
    /// guessed; a token the node does not know, used up or run out is
    /// one refusal, whichever it was.
    pub fn invite(&self, request: &InviteRequest, peer: IpAddr) -> Result<DeviceCredentials, Refused> {
        if !self.invites.allow(peer) {
            self.counters.invites_refused.bump();
            return Err((StatusCode::TOO_MANY_REQUESTS, Refusal::new(refusal::RATE_LIMITED, "too many invitations tried from this address")));
        }
        match self.gate.devices.exchange(&request.token, &request.name, unix_now()) {
            Ok((device_id, secret, label)) => {
                self.counters.invites_exchanged.bump();
                Ok(DeviceCredentials { device_id, secret, node: self.node_ref.clone(), label })
            }
            Err(ExchangeError::Refused) => {
                self.counters.invites_refused.bump();
                Err((StatusCode::FORBIDDEN, Refusal::new(refusal::BAD_INVITE, "no such invitation, or it was used up or ran out")))
            }
            // The node could not keep the device: none was made, the token
            // is not spent, and the same link works once the node is right.
            Err(ExchangeError::NotWritten(_)) => {
                self.counters.invites_refused.bump();
                Err((StatusCode::SERVICE_UNAVAILABLE, Refusal::new(refusal::NOT_KEPT, "the node could not keep the device; open the link again later")))
            }
        }
    }
}

/// A client called with ALPN vcall/1: its requests, one by one, until it
/// goes, stops answering pings, or asks nothing for `Control::idle`.
pub async fn serve(stream: TlsStream<TcpStream>, peer: SocketAddr, control: Arc<Control>) {
    let mut builder = io::server_builder();
    builder.max_concurrent_streams(MAX_STREAMS);
    let Ok(Ok(mut connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, builder.handshake::<_, Bytes>(stream)).await else {
        return;
    };
    tracing::debug!(client = %peer, "control connected");
    // A connection that froze without closing (a throttled path, a host
    // that vanished) is found by the ping, as on a bridge.
    let pings = connection.ping_pong().map(io::keepalive);
    let mut pings = Box::pin(async move {
        match pings {
            Some(p) => p.await,
            None => std::future::pending().await,
        }
    });
    loop {
        let accepted = tokio::select! {
            r = tokio::time::timeout(control.idle, connection.accept()) => r,
            _ = &mut pings => {
                tracing::debug!(client = %peer, "control: no answer to ping");
                return;
            }
        };
        let (request, respond) = match accepted {
            Ok(Some(Ok(pair))) => pair,
            Ok(_) => return,
            Err(_) => {
                tracing::debug!(client = %peer, "control: idle, closed");
                return;
            }
        };
        let control = control.clone();
        tokio::spawn(async move {
            if let Err(e) = answer(request, respond, peer, &control).await {
                tracing::debug!(client = %peer, error = %e, "control request ended");
            }
        });
    }
}

/// What a request is about, by its path.
enum Route<'a> {
    Hello,
    Turn,
    Invite,
    Rooms,
    Room(&'a str, &'a str),
}

fn route(path: &str) -> Option<Route<'_>> {
    match path {
        vcall_proto::PATH_HELLO => Some(Route::Hello),
        vcall_proto::PATH_TURN => Some(Route::Turn),
        vcall_proto::PATH_INVITE => Some(Route::Invite),
        rooms::PATH_ROOMS => Some(Route::Rooms),
        _ => rooms::room_action(path).map(|(id, action)| Route::Room(id, action)),
    }
}

async fn answer(request: Request<RecvStream>, mut respond: SendResponse<Bytes>, peer: SocketAddr, control: &Control) -> anyhow::Result<()> {
    let path = request.uri().path().to_string();
    let Some(route) = route(&path).filter(|_| request.method() == Method::POST) else {
        decoy::h2(&mut respond);
        return Ok(());
    };
    let body = match tokio::time::timeout(BODY_TIMEOUT, read_body(request.into_body())).await {
        Ok(Ok(body)) => body,
        _ => {
            send(&mut respond, StatusCode::BAD_REQUEST, &Refusal::new(refusal::BAD_REQUEST, "the body did not arrive"))?;
            return Ok(());
        }
    };
    let (status, json) = match route {
        Route::Hello => match serde_json::from_slice::<Hello>(&body) {
            Ok(hello) => {
                tracing::debug!(client = %peer, who = %hello.client, "hello");
                reply(control.hello(&hello))
            }
            Err(e) => bad_request(control, e),
        },
        Route::Turn => match serde_json::from_slice::<TurnRequest>(&body) {
            Ok(request) => {
                let r = control.turn(&request, peer.ip());
                match &r {
                    Ok(_) => tracing::debug!(client = %peer, "credentials issued"),
                    Err((_, refusal)) => tracing::debug!(client = %peer, why = %refusal.error, "credentials refused"),
                }
                reply(r)
            }
            Err(e) => bad_request(control, e),
        },
        Route::Invite => match serde_json::from_slice::<InviteRequest>(&body) {
            Ok(request) => {
                let r = control.invite(&request, peer.ip());
                match &r {
                    Ok(creds) => tracing::info!(client = %peer, device = %creds.device_id, label = %creds.label, "a device let in by an invitation"),
                    Err((_, refusal)) => tracing::debug!(client = %peer, why = %refusal.error, "invitation refused"),
                }
                reply(r)
            }
            Err(e) => bad_request(control, e),
        },
        Route::Rooms => match serde_json::from_slice::<RoomRequest>(&body) {
            Ok(request) => {
                let r = control.create_room(&request, peer.ip());
                match &r {
                    Ok(room) => tracing::debug!(client = %peer, room = %room.room_id, "room made"),
                    Err((_, refusal)) => tracing::debug!(client = %peer, why = %refusal.error, "room refused"),
                }
                reply(r)
            }
            Err(e) => bad_request(control, e),
        },
        Route::Room(id, action::JOIN) => match serde_json::from_slice::<JoinRequest>(&body) {
            Ok(request) => {
                let via_home = request.home.is_some();
                let r = control.join(id, request, peer.ip()).await;
                match &r {
                    Ok(joined) => tracing::debug!(client = %peer, room = id, participant = joined.participant_id, via_home, "joined"),
                    Err((status, refusal)) => tracing::debug!(client = %peer, room = id, %status, why = %refusal.error, via_home, "join refused"),
                }
                reply(r)
            }
            Err(e) => bad_request(control, e),
        },
        Route::Room(id, action::DELEGATE) => match serde_json::from_slice::<DelegateRequest>(&body) {
            Ok(request) => reply(control.delegate(id, &request, peer.ip()).await),
            Err(e) => bad_request(control, e),
        },
        Route::Room(id, action::LEAVE) => match serde_json::from_slice::<LeaveRequest>(&body) {
            Ok(request) => reply(control.leave(id, request, peer.ip()).await),
            Err(e) => bad_request(control, e),
        },
        Route::Room(id, action::TOKEN) => match serde_json::from_slice::<TokenRequest>(&body) {
            Ok(request) => reply(control.change_token(id, request, peer.ip()).await),
            Err(e) => bad_request(control, e),
        },
        Route::Room(..) => {
            decoy::h2(&mut respond);
            return Ok(());
        }
    };
    send_bytes(&mut respond, status, json)
}

fn reply<T: serde::Serialize>(r: Result<T, Refused>) -> (StatusCode, Vec<u8>) {
    match r {
        Ok(body) => (StatusCode::OK, serde_json::to_vec(&body).unwrap_or_default()),
        Err((status, refusal)) => (status, serde_json::to_vec(&refusal).unwrap_or_default()),
    }
}

fn bad_request(control: &Control, e: serde_json::Error) -> (StatusCode, Vec<u8>) {
    control.counters.control_refused.bump();
    let refusal = Refusal::new(refusal::BAD_REQUEST, format!("not a request: {e}"));
    (StatusCode::BAD_REQUEST, serde_json::to_vec(&refusal).unwrap_or_default())
}

fn send(respond: &mut SendResponse<Bytes>, status: StatusCode, body: &Refusal) -> anyhow::Result<()> {
    send_bytes(respond, status, serde_json::to_vec(body)?)
}

fn send_bytes(respond: &mut SendResponse<Bytes>, status: StatusCode, json: Vec<u8>) -> anyhow::Result<()> {
    let response = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("content-length", json.len())
        .body(())
        .expect("response");
    let mut body = respond.send_response(response, false)?;
    body.send_data(Bytes::from(json), true)?;
    Ok(())
}

/// The whole body, up to the limit; past it, an error.
pub async fn read_body(mut body: RecvStream) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        anyhow::ensure!(out.len() <= vcall_proto::MAX_BODY, "the body is too long");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn control(private: bool) -> Control {
        let counters = Arc::new(Counters::default());
        let node_id = vlink_proto::BridgeId([7u8; 32]);
        let sfu = Sfu::bind(
            crate::sfu::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                public_ip: "127.0.0.1".parse().unwrap(),
                node_id: node_id.to_string(),
                max_rooms: 2,
                max_participants: 4,
                kbps_per_participant: 0,
                lifetime: Duration::from_secs(60),
                idle: Duration::from_secs(60),
                connect_timeout: Duration::from_secs(60),
                offer_timeout: Duration::from_secs(60),
                audio_n: crate::sfu::DEFAULT_AUDIO_N,
                bwe_kbps: crate::sfu::DEFAULT_BWE_KBPS,
                trust: Arc::new(crate::trust::Trust::new(crate::sfu::CascadeMode::On)),
                cascade_seats_per_node: crate::sfu::DEFAULT_CASCADE_SEATS_PER_NODE,
                cascade_uplinks: crate::sfu::DEFAULT_CASCADE_UPLINKS,
            },
            counters.clone(),
            Arc::new(crate::turn::limits::Bucket::new(0)),
        )
        .await
        .unwrap();
        let sfu = Arc::new(sfu);
        let (_, _, key) = crate::identity::generate_with_key().unwrap();
        let gate = Arc::new(Gate { private, keys: vec!["k1".into(), "k2".into()], devices: crate::devices::Devices::open(None).unwrap() });
        let cascade = Arc::new(Cascade::new(
            node_id,
            "0.1.0".into(),
            Arc::new(key),
            sfu.clone(),
            Arc::new(crate::turn::policy::PeerPolicy::new(vec![], true)),
            true,
            gate.clone(),
            crate::cascade::DEFAULT_CASCADE_JOINS_PER_IP,
            counters.clone(),
        ));
        Control {
            node_id,
            version: "0.1.0".into(),
            capabilities: vec!["stun".into(), "turn".into()],
            codecs: vec!["opus".into()],
            private,
            gate,
            node_ref: format!("203.0.113.7:443#{node_id}"),
            invites: RateWindow::new(Duration::from_secs(60), 3),
            issuers: vec![],
            auth: Arc::new(Auth::new(b"secret", "veydan")),
            credentials_ttl: Duration::from_secs(600),
            idle: Duration::from_secs(60),
            urls: vec!["stun:203.0.113.7:3478".into()],
            limits: Limits::default(),
            rate: RateWindow::new(Duration::from_secs(60), 2),
            bad_tokens: RateWindow::new(BAD_TOKENS_WINDOW, BAD_TOKENS_PER_IP),
            counters,
            sfu,
            cascade,
        }
    }

    fn hello(min: u16, max: u16) -> Hello {
        Hello { protocol_min: min, protocol_max: max, capabilities: vec![], codecs: vec![], access: Access::default(), client: "test".into() }
    }

    #[tokio::test]
    async fn hello_meets_on_a_version_or_not() {
        let c = control(false).await;
        let w = c.hello(&hello(1, 1)).unwrap();
        assert_eq!(w.node_id, c.node_id.to_string());
        assert!(!w.private);
        let (status, r) = c.hello(&hello(7, 9)).unwrap_err();
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        assert_eq!(r.error, refusal::VERSION);
    }

    #[tokio::test]
    async fn a_public_node_gives_credentials_so_many_per_address() {
        let c = control(false).await;
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let first = c.turn(&TurnRequest::default(), ip).unwrap();
        assert_eq!(first.ttl_secs, 600);
        assert_eq!(first.realm, "veydan");
        assert_eq!(first.urls, c.urls);
        assert!(c.auth.key_of(&first.username, unix_now()).is_ok());
        c.turn(&TurnRequest::default(), ip).unwrap();
        let (status, r) = c.turn(&TurnRequest::default(), ip).unwrap_err();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.error, refusal::RATE_LIMITED);
        assert_eq!(c.counters.credentials_issued.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(c.counters.credentials_refused_rate.load(std::sync::atomic::Ordering::Relaxed), 1);
        // Another address is another allowance.
        c.turn(&TurnRequest::default(), "198.51.100.2".parse().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn a_private_node_wants_a_key() {
        let c = control(true).await;
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let (status, r) = c.turn(&TurnRequest::default(), ip).unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(r.error, refusal::ACCESS_KEY_REQUIRED);
        let wrong = TurnRequest { access: Access::key("k3") };
        assert_eq!(c.turn(&wrong, ip).unwrap_err().1.error, refusal::ACCESS_KEY_REQUIRED);
        let right = TurnRequest { access: Access::key("k2") };
        // No rate limit for key holders: the key is the limit.
        for _ in 0..5 {
            c.turn(&right, ip).unwrap();
        }
        assert_eq!(c.counters.credentials_refused_access.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn an_invitation_opens_a_private_node_to_a_device_and_attempts_are_counted() {
        let c = control(true).await;
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let made = c.gate.devices.invite(1, Duration::from_secs(600), "phone", unix_now()).unwrap();
        let (status, r) = c.invite(&InviteRequest { token: "0".repeat(48), name: String::new() }, ip).unwrap_err();
        assert_eq!((status, r.error.as_str()), (StatusCode::FORBIDDEN, refusal::BAD_INVITE));
        let creds = c.invite(&InviteRequest { token: made.token.clone(), name: "Chat".into() }, ip).unwrap();
        assert_eq!((creds.node.as_str(), creds.label.as_str()), (c.node_ref.as_str(), "phone"));
        // The credentials open the node; the token is used up.
        let device = TurnRequest { access: Access::device(creds.device_id.clone(), creds.secret.clone()) };
        c.turn(&device, ip).unwrap();
        let (status, _) = c.invite(&InviteRequest { token: made.token.clone(), name: String::new() }, ip).unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
        // The third attempt in the window was the last one allowed.
        let (status, r) = c.invite(&InviteRequest { token: made.token, name: String::new() }, ip).unwrap_err();
        assert_eq!((status, r.error.as_str()), (StatusCode::TOO_MANY_REQUESTS, refusal::RATE_LIMITED));
        assert_eq!(c.counters.invites_exchanged.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(c.counters.invites_refused.load(std::sync::atomic::Ordering::Relaxed), 3);
        // Revoked: a stranger.
        assert_eq!(c.gate.devices.revoke(&creds.device_id), Ok(true));
        assert_eq!(c.turn(&device, ip).unwrap_err().1.error, refusal::ACCESS_KEY_REQUIRED);
    }

    #[tokio::test]
    async fn an_address_that_guesses_tokens_is_told_to_wait_and_one_that_is_right_is_not() {
        let c = control(false).await;
        let room = c.sfu.create_room(&Default::default()).unwrap();
        let guesser: IpAddr = "198.51.100.1".parse().unwrap();
        let wrong = || JoinRequest::new("not-the-token", "", vec![]);
        for _ in 0..BAD_TOKENS_PER_IP {
            let (status, r) = c.join(&room.room_id, wrong(), guesser).await.unwrap_err();
            assert_eq!((status, r.error.as_str()), (StatusCode::FORBIDDEN, refusal::BAD_TOKEN));
        }
        // Past the allowance nothing reaches the room, whatever it is.
        let asked_before = c.counters.joins_refused_token.load(std::sync::atomic::Ordering::Relaxed);
        let (status, r) = c.join(&room.room_id, wrong(), guesser).await.unwrap_err();
        assert_eq!((status, r.error.as_str()), (StatusCode::TOO_MANY_REQUESTS, refusal::RATE_LIMITED));
        let leave = LeaveRequest { participant_id: 1, token: "x".into() };
        assert_eq!(c.leave(&room.room_id, leave, guesser).await.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);
        let token = TokenRequest { admin_token: "x".into() };
        assert_eq!(c.change_token(&room.room_id, token, guesser).await.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(c.counters.joins_refused_token.load(std::sync::atomic::Ordering::Relaxed), asked_before);

        // Another address is not touched, and the admin's own token works.
        let friend: IpAddr = "198.51.100.2".parse().unwrap();
        let changed = c.change_token(&room.room_id, TokenRequest { admin_token: room.admin_token.clone() }, friend).await.unwrap();
        assert!(!changed.join_token.is_empty());
        let (_, r) = c.change_token(&room.room_id, TokenRequest { admin_token: "x".into() }, friend).await.unwrap_err();
        assert_eq!(r.error, refusal::BAD_TOKEN);
    }

    #[tokio::test]
    async fn passes_are_refused_for_now() {
        let pass = vcall_proto::Pass { issuer: "ab".into(), expires_at: 1, limits: Default::default(), signature: "cd".into() };
        for private in [false, true] {
            let c = control(private).await;
            let r = TurnRequest { access: Access { pass: Some(pass.clone()), ..Access::key("k1") } };
            let (status, refusal) = c.turn(&r, "198.51.100.1".parse().unwrap()).unwrap_err();
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(refusal.error, refusal::PASS_UNSUPPORTED);
        }
    }
}
