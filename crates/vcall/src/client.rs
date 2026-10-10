//! A client of a node, as `vcall probe` and the tests are: the control
//! channel for credentials, and enough of a TURN client (RFC 8656) for
//! one allocation over UDP, TCP or TLS. Not for apps: libwebrtc has its
//! own TURN client, and takes what the control channel hands out.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use vcall_proto::{Access, Hello, Refusal, TurnCredentials, TurnRequest, Welcome};
use vlink_proto::io as h2io;

use crate::identity::{self, NodeId, NodeRef};
use crate::stun::{self, attr, method, Class, Decoded, Message};
use crate::turn::allocation::Transport;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A request over UDP is sent again at these moments, then given up.
const UDP_RETRIES: [Duration; 4] =
    [Duration::from_millis(500), Duration::from_millis(1000), Duration::from_millis(2000), Duration::from_millis(3000)];
const STREAM_WAIT: Duration = Duration::from_secs(6);

#[derive(Debug, thiserror::Error)]
pub enum TurnError {
    /// An error response: the code and its reason.
    #[error("{0} {1}")]
    Refused(u16, String),
    #[error("no answer from the node")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Other(String),
}

impl TurnError {
    pub fn code(&self) -> Option<u16> {
        match self {
            Self::Refused(code, _) => Some(*code),
            _ => None,
        }
    }
}

/// What a peer sent, as it reached the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Data { peer: SocketAddr, data: Vec<u8> },
    Channel { number: u16, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocated {
    pub relayed: SocketAddr,
    pub mapped: SocketAddr,
    pub lifetime: u32,
}

enum Io {
    Udp(UdpSocket),
    Stream { io: Box<dyn Stream>, buf: Vec<u8> },
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub struct TurnClient {
    io: Io,
    local: SocketAddr,
    transport: Transport,
    credentials: Option<(String, String)>,
    realm: Option<String>,
    nonce: Option<String>,
    key: Option<[u8; 16]>,
    pending: VecDeque<Incoming>,
}

impl TurnClient {
    /// A client of the node at `server`. TLS pins the node's id.
    pub async fn connect(server: SocketAddr, transport: Transport, pin: Option<NodeId>) -> anyhow::Result<Self> {
        let any = if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let (io, local) = match transport {
            Transport::Udp => {
                let socket = UdpSocket::bind(any).await?;
                socket.connect(server).await?;
                let local = socket.local_addr()?;
                (Io::Udp(socket), local)
            }
            Transport::Tcp => {
                let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server)).await??;
                let _ = tcp.set_nodelay(true);
                let local = tcp.local_addr()?;
                (Io::Stream { io: Box::new(tcp), buf: Vec::new() }, local)
            }
            Transport::Tls => {
                let id = pin.ok_or_else(|| anyhow::anyhow!("TLS needs the node's id to pin"))?;
                let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server)).await??;
                let _ = tcp.set_nodelay(true);
                let local = tcp.local_addr()?;
                let config = identity::client_config(id, identity::ALPN_STUN_TURN)?;
                let name = rustls::pki_types::ServerName::IpAddress(server.ip().into());
                let tls = tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(Arc::new(config)).connect(name, tcp)).await??;
                (Io::Stream { io: Box::new(tls), buf: Vec::new() }, local)
            }
        };
        Ok(Self { io, local, transport, credentials: None, realm: None, nonce: None, key: None, pending: VecDeque::new() })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn set_credentials(&mut self, username: &str, password: &str) {
        self.credentials = Some((username.to_string(), password.to_string()));
        self.key = None;
    }

    async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &mut self.io {
            Io::Udp(socket) => socket.send(bytes).await.map(|_| ()),
            Io::Stream { io, .. } => io.write_all(bytes).await,
        }
    }

    /// One frame: a datagram, or a STUN message or ChannelData off the stream.
    async fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        match &mut self.io {
            Io::Udp(socket) => {
                let mut buf = vec![0u8; stun::MAX_MESSAGE];
                let n = socket.recv(&mut buf).await?;
                buf.truncate(n);
                Ok(buf)
            }
            Io::Stream { io, buf } => {
                let mut chunk = vec![0u8; 16 * 1024];
                loop {
                    if buf.len() >= 4 {
                        let need = match stun::frame_of(buf) {
                            Some(stun::Frame::Stun(n)) | Some(stun::Frame::ChannelData(n)) => n,
                            None => return Err(io::Error::other("not a frame")),
                        };
                        if buf.len() >= need {
                            return Ok(buf.drain(..need).collect());
                        }
                    }
                    let n = io.read(&mut chunk).await?;
                    if n == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }

    /// Reads until the response to `txid`, keeping what peers sent meanwhile.
    async fn wait_response(&mut self, txid: [u8; 12], until: Instant) -> Result<Option<Message>, TurnError> {
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let frame = match tokio::time::timeout(left, self.read_frame()).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(None),
            };
            if let Some(incoming) = self.incoming(&frame) {
                self.pending.push_back(incoming);
                continue;
            }
            if let Ok(d) = Decoded::parse(&frame) {
                if matches!(d.msg.class, Class::Success | Class::Error) && d.msg.txid == txid {
                    return Ok(Some(d.msg));
                }
            }
        }
    }

    fn incoming(&self, frame: &[u8]) -> Option<Incoming> {
        if let Some((number, data)) = stun::parse_channel_data(frame) {
            return Some(Incoming::Channel { number, data: data.to_vec() });
        }
        let d = Decoded::parse(frame).ok()?;
        if d.msg.class == Class::Indication && d.msg.method == method::DATA {
            let peer = d.msg.get_xor_addr(attr::XOR_PEER_ADDRESS)?;
            let data = d.msg.get(attr::DATA)?.to_vec();
            return Some(Incoming::Data { peer, data });
        }
        None
    }

    /// Sends `m` and waits for its answer; with credentials, under the
    /// long-term mechanism, taking the realm and nonce of a 401 or 438
    /// once and trying again.
    async fn transact(&mut self, mut m: Message) -> Result<Message, TurnError> {
        let mut retried = false;
        loop {
            let key = match (&self.credentials, &self.realm, &self.nonce) {
                (Some((username, password)), Some(realm), Some(nonce)) => {
                    m.attrs.retain(|a| !matches!(a.kind, attr::USERNAME | attr::REALM | attr::NONCE));
                    m.add_str(attr::USERNAME, username).add_str(attr::REALM, realm).add_str(attr::NONCE, nonce);
                    let key = *self.key.get_or_insert_with(|| stun::long_term_key(username, realm, password));
                    Some(key)
                }
                _ => None,
            };
            let raw = m.encode(key.as_ref().map(|k| &k[..]), true);
            let response = self.send_and_wait(&raw, m.txid).await?.ok_or(TurnError::Timeout)?;
            if response.class == Class::Success {
                return Ok(response);
            }
            let (code, reason) = response.get_error().unwrap_or((0, "no error code".into()));
            let challenge = matches!(code, 401 | 438) && self.credentials.is_some() && !retried;
            if challenge {
                if let (Some(realm), Some(nonce)) = (response.get_str(attr::REALM), response.get_str(attr::NONCE)) {
                    self.realm = Some(realm.to_string());
                    self.nonce = Some(nonce.to_string());
                    self.key = None;
                    retried = true;
                    continue;
                }
            }
            return Err(TurnError::Refused(code, reason));
        }
    }

    async fn send_and_wait(&mut self, raw: &[u8], txid: [u8; 12]) -> Result<Option<Message>, TurnError> {
        match self.transport {
            Transport::Udp => {
                let start = Instant::now();
                self.write(raw).await?;
                for retry in UDP_RETRIES {
                    if let Some(r) = self.wait_response(txid, start + retry).await? {
                        return Ok(Some(r));
                    }
                    self.write(raw).await?;
                }
                self.wait_response(txid, Instant::now() + UDP_RETRIES[0]).await
            }
            _ => {
                self.write(raw).await?;
                self.wait_response(txid, Instant::now() + STREAM_WAIT).await
            }
        }
    }

    /// Any request, as the tests shape one; the success response.
    pub async fn request(&mut self, m: Message) -> Result<Message, TurnError> {
        self.transact(m).await
    }

    /// The client's address as the node sees it.
    pub async fn binding(&mut self) -> Result<SocketAddr, TurnError> {
        let r = self.transact(Message::request(method::BINDING)).await?;
        r.get_xor_addr(attr::XOR_MAPPED_ADDRESS).ok_or_else(|| TurnError::Other("no mapped address".into()))
    }

    pub async fn allocate(&mut self, lifetime: Option<u32>) -> Result<Allocated, TurnError> {
        let mut m = Message::request(method::ALLOCATE);
        m.add(attr::REQUESTED_TRANSPORT, vec![stun::TRANSPORT_UDP, 0, 0, 0]);
        if let Some(l) = lifetime {
            m.add_u32(attr::LIFETIME, l);
        }
        let r = self.transact(m).await?;
        Ok(Allocated {
            relayed: r.get_xor_addr(attr::XOR_RELAYED_ADDRESS).ok_or_else(|| TurnError::Other("no relayed address".into()))?,
            mapped: r.get_xor_addr(attr::XOR_MAPPED_ADDRESS).ok_or_else(|| TurnError::Other("no mapped address".into()))?,
            lifetime: r.get_u32(attr::LIFETIME).unwrap_or(0),
        })
    }

    /// Asks for `lifetime` more seconds; 0 ends the allocation.
    pub async fn refresh(&mut self, lifetime: u32) -> Result<u32, TurnError> {
        let mut m = Message::request(method::REFRESH);
        m.add_u32(attr::LIFETIME, lifetime);
        let r = self.transact(m).await?;
        Ok(r.get_u32(attr::LIFETIME).unwrap_or(0))
    }

    pub async fn create_permission(&mut self, peers: &[SocketAddr]) -> Result<(), TurnError> {
        let mut m = Message::request(method::CREATE_PERMISSION);
        for peer in peers {
            m.add_xor_addr(attr::XOR_PEER_ADDRESS, *peer);
        }
        self.transact(m).await.map(|_| ())
    }

    pub async fn channel_bind(&mut self, number: u16, peer: SocketAddr) -> Result<(), TurnError> {
        let mut m = Message::request(method::CHANNEL_BIND);
        m.add_channel(number).add_xor_addr(attr::XOR_PEER_ADDRESS, peer);
        self.transact(m).await.map(|_| ())
    }

    /// `data` to `peer` as a Send indication.
    pub async fn send(&mut self, peer: SocketAddr, data: &[u8]) -> io::Result<()> {
        let mut m = Message::indication(method::SEND);
        m.add_xor_addr(attr::XOR_PEER_ADDRESS, peer).add(attr::DATA, data);
        let raw = m.encode(None, false);
        self.write(&raw).await
    }

    pub async fn send_channel(&mut self, number: u16, data: &[u8]) -> io::Result<()> {
        let raw = stun::channel_data(number, data, self.transport.is_stream());
        self.write(&raw).await
    }

    /// The next thing a peer sent, within `timeout`.
    pub async fn recv(&mut self, timeout: Duration) -> Result<Incoming, TurnError> {
        if let Some(incoming) = self.pending.pop_front() {
            return Ok(incoming);
        }
        let until = Instant::now() + timeout;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TurnError::Timeout);
            }
            let frame = match tokio::time::timeout(left, self.read_frame()).await {
                Ok(frame) => frame?,
                Err(_) => return Err(TurnError::Timeout),
            };
            if let Some(incoming) = self.incoming(&frame) {
                return Ok(incoming);
            }
        }
    }
}

/// A STUN Binding from a plain socket: the address `socket` has as the
/// node at `server` sees it. For a peer that is no TURN client.
pub async fn binding_from(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr, TurnError> {
    let request = Message::request(method::BINDING);
    let raw = request.encode(None, true);
    let mut buf = vec![0u8; stun::MAX_MESSAGE];
    let start = Instant::now();
    socket.send_to(&raw, server).await?;
    for retry in UDP_RETRIES {
        loop {
            let left = (start + retry).saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) = tokio::time::timeout(left, socket.recv_from(&mut buf)).await else { break };
            if from != server {
                continue;
            }
            if let Ok(d) = Decoded::parse(&buf[..n]) {
                if d.msg.txid == request.txid && d.msg.class == Class::Success {
                    return d.msg.get_xor_addr(attr::XOR_MAPPED_ADDRESS).ok_or_else(|| TurnError::Other("no mapped address".into()));
                }
            }
        }
        socket.send_to(&raw, server).await?;
    }
    Err(TurnError::Timeout)
}

/// Why no control connection came of a node reference: nothing took it
/// at the address in time (the way), or what took it is not the node
/// named (TLS and its pin, the ALPN, h2). The two are told apart for the
/// cascade: a client naming a wrong id for a live address is not a home
/// out of reach.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("no connection to the address: {0:#}")]
    NoWay(anyhow::Error),
    #[error("not the node named: {0:#}")]
    NotTheNode(anyhow::Error),
}

impl ConnectError {
    /// Whether `e` (from [`ControlClient::connect`], as it came or wrapped)
    /// says that something else sits at the address.
    pub fn is_not_the_node(e: &anyhow::Error) -> bool {
        matches!(e.downcast_ref::<ConnectError>(), Some(ConnectError::NotTheNode(_)))
    }
}

/// The control channel of one node: h2 over pinned TLS. A clone shares
/// the connection: requests go side by side on it.
#[derive(Clone)]
pub struct ControlClient {
    send: h2::client::SendRequest<Bytes>,
}

impl ControlClient {
    /// The error is a [`ConnectError`]: whether the way or the node named
    /// is what failed.
    pub async fn connect(node: &NodeRef) -> anyhow::Result<Self> {
        Ok(Self::connect_classified(node).await?)
    }

    async fn connect_classified(node: &NodeRef) -> Result<Self, ConnectError> {
        use ConnectError::{NoWay, NotTheNode};
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(node.addr)).await.map_err(|e| NoWay(e.into()))?.map_err(|e| NoWay(e.into()))?;
        let _ = tcp.set_nodelay(true);
        let config = identity::client_config(node.id, vcall_proto::ALPN).map_err(NotTheNode)?;
        let name = identity::server_name(node).map_err(NotTheNode)?;
        let tls = tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(Arc::new(config)).connect(name, tcp)).await.map_err(|e| NoWay(e.into()))?.map_err(|e| NotTheNode(e.into()))?;
        if tls.get_ref().1.alpn_protocol() != Some(vcall_proto::ALPN) {
            return Err(NotTheNode(anyhow::anyhow!("the node did not take the control ALPN")));
        }
        let (send, connection) = tokio::time::timeout(CONNECT_TIMEOUT, h2io::client_builder().handshake::<_, Bytes>(tls)).await.map_err(|e| NoWay(e.into()))?.map_err(|e| NotTheNode(e.into()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { send })
    }

    /// One request; `Err` inside is the node's refusal with its status.
    pub async fn post<T: Serialize, R: DeserializeOwned>(&mut self, path: &str, body: &T) -> anyhow::Result<Result<R, (u16, Refusal)>> {
        let send = self.send.clone().ready().await?;
        let mut send = send;
        let request = Request::builder().method(Method::POST).uri(path).header("content-type", "application/json").body(())?;
        let (response, mut stream) = send.send_request(request, false)?;
        stream.send_data(Bytes::from(serde_json::to_vec(body)?), true)?;
        let response = tokio::time::timeout(CONNECT_TIMEOUT, response).await??;
        let status = response.status().as_u16();
        let body = tokio::time::timeout(CONNECT_TIMEOUT, crate::control::read_body(response.into_body())).await??;
        if status == 200 {
            Ok(Ok(serde_json::from_slice(&body)?))
        } else {
            let refusal = serde_json::from_slice(&body).unwrap_or_else(|_| Refusal::new("http", format!("status {status}")));
            Ok(Err((status, refusal)))
        }
    }

    pub async fn hello(&mut self, hello: &Hello) -> anyhow::Result<Result<Welcome, (u16, Refusal)>> {
        self.post(vcall_proto::PATH_HELLO, hello).await
    }

    pub async fn turn(&mut self, access: Access) -> anyhow::Result<Result<TurnCredentials, (u16, Refusal)>> {
        self.post(vcall_proto::PATH_TURN, &TurnRequest { access }).await
    }
}

/// What this client says of itself.
pub fn hello(access: Access, client: &str) -> Hello {
    use vcall_proto::capability as cap;
    Hello {
        protocol_min: vcall_proto::PROTOCOL_MIN,
        protocol_max: vcall_proto::PROTOCOL_MAX,
        capabilities: vec![cap::STUN.into(), cap::TURN.into(), cap::TURN_TCP.into(), cap::TURN_TLS.into()],
        codecs: Vec::new(),
        access,
        client: client.to_string(),
    }
}

/// The addresses in a credentials' URI list, by transport.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub stun: Option<SocketAddr>,
    pub turn_udp: Option<SocketAddr>,
    pub turn_tcp: Option<SocketAddr>,
    pub turns: Option<SocketAddr>,
}

impl Endpoints {
    pub fn of(urls: &[String]) -> Self {
        let mut e = Self::default();
        for url in urls {
            let Some((scheme, rest)) = url.split_once(':') else { continue };
            let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
            let Ok(addr) = addr.parse::<SocketAddr>() else { continue };
            let transport = query.strip_prefix("transport=").unwrap_or("udp");
            match (scheme, transport) {
                ("stun", _) => e.stun = Some(addr),
                ("turn", "udp") => e.turn_udp = Some(addr),
                ("turn", "tcp") => e.turn_tcp = Some(addr),
                ("turns", "tcp") => e.turns = Some(addr),
                _ => {}
            }
        }
        e
    }

    pub fn for_transport(&self, transport: Transport) -> Option<SocketAddr> {
        match transport {
            Transport::Udp => self.turn_udp,
            Transport::Tcp => self.turn_tcp,
            Transport::Tls => self.turns,
        }
    }
}

/// `stun:`, `turn:` and `turns:` URIs of a node, as they go into the credentials.
pub fn urls(public_ip: IpAddr, turn_port: u16, tls_port: u16) -> Vec<String> {
    let host = match public_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    vec![
        format!("stun:{host}:{turn_port}"),
        format!("turn:{host}:{turn_port}?transport=udp"),
        format!("turn:{host}:{turn_port}?transport=tcp"),
        format!("turns:{host}:{tls_port}?transport=tcp"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_round_trip_through_endpoints() {
        let list = urls("203.0.113.7".parse().unwrap(), 3478, 443);
        assert_eq!(list[0], "stun:203.0.113.7:3478");
        assert_eq!(list[3], "turns:203.0.113.7:443?transport=tcp");
        let e = Endpoints::of(&list);
        assert_eq!(e.stun, Some("203.0.113.7:3478".parse().unwrap()));
        assert_eq!(e.turn_udp, Some("203.0.113.7:3478".parse().unwrap()));
        assert_eq!(e.turn_tcp, Some("203.0.113.7:3478".parse().unwrap()));
        assert_eq!(e.turns, Some("203.0.113.7:443".parse().unwrap()));
        assert_eq!(e.for_transport(Transport::Tls), e.turns);

        let v6 = urls("2001:db8::7".parse().unwrap(), 3478, 8443);
        assert_eq!(v6[1], "turn:[2001:db8::7]:3478?transport=udp");
        assert_eq!(Endpoints::of(&v6).turns, Some("[2001:db8::7]:8443".parse().unwrap()));
        assert_eq!(Endpoints::of(&["junk".into(), "turn:nohost".into()]), Endpoints::default());
    }
}
