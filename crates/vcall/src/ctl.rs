//! The control socket: how `vcall ctl` talks to the running node.
//!
//! A unix socket, not a port: whoever may open the file may ask, and
//! nobody else can reach it. One JSON line in, one JSON line out, as
//! `vpush ctl` does it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::counters::{Counters, Snapshot};
use crate::sfu::Sfu;
use crate::turn;

/// One connection may send this much in all; `vcall ctl` sends a line.
const MAX_LINE: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Health,
    /// What the node holds now, and what it has counted since it started.
    Stats,
    /// An invitation to this node: a link with a token good for so many
    /// exchanges and so long (`devices`).
    Invite {
        #[serde(default = "one")]
        uses: u32,
        #[serde(default = "week")]
        ttl_secs: u64,
        #[serde(default)]
        label: String,
    },
    /// The devices let in, and the invitations still open.
    Devices,
    /// A device out, by its id; or an invitation withdrawn, by the hash
    /// `devices` shows.
    Revoke { id: String },
}

fn one() -> u32 {
    1
}

fn week() -> u64 {
    crate::devices::DEFAULT_TTL.as_secs()
}

/// What `vcall ctl invite` prints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invited {
    /// `veydan://call-node/<id>?a=<address>&t=<token>`: what the person
    /// invited opens in the app.
    pub link: String,
    pub uses: u32,
    pub expires_at: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn ok(data: impl Serialize) -> Self {
        match serde_json::to_value(data) {
            Ok(v) => Self { ok: true, data: Some(v), error: None },
            Err(e) => Self::err(e.to_string()),
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self { ok: false, data: None, error: Some(message.into()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub version: String,
    pub uptime_secs: u64,
}

/// What `vcall ctl stats` shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub version: String,
    pub uptime_secs: u64,
    pub allocations_now: usize,
    /// Rooms of the SFU with their task running, and seats taken in them.
    #[serde(default)]
    pub rooms_now: usize,
    #[serde(default)]
    pub participants_now: usize,
    /// The cascade: satellites of other nodes' rooms here, uplinks to
    /// their homes, and seats other nodes hold in the rooms here.
    #[serde(default)]
    pub satellites_now: usize,
    #[serde(default)]
    pub cascade_uplinks_now: usize,
    #[serde(default)]
    pub cascade_seats_now: usize,
    /// The cascade's trust: `on`, `off`, `registry` or `list`, and how
    /// many nodes the registry's list names now.
    #[serde(default)]
    pub cascade: String,
    #[serde(default)]
    pub trusted_nodes_now: usize,
    /// A private node: the devices let in, and the invitations open.
    #[serde(default)]
    pub devices_now: usize,
    #[serde(default)]
    pub invites_now: usize,
    pub since_start: Snapshot,
}

#[derive(Clone)]
pub struct CtlState {
    pub version: String,
    pub started: Instant,
    pub counters: Arc<Counters>,
    pub turn: Arc<turn::Server>,
    pub sfu: Arc<Sfu>,
    pub trust: Arc<crate::trust::Trust>,
    pub devices: Arc<crate::devices::Devices>,
    /// The node as a link names it: its id, and `address:port` of the
    /// control channel as the world reaches it.
    pub node_id: String,
    pub control_addr: String,
}

impl CtlState {
    pub fn stats(&self) -> Stats {
        Stats {
            version: self.version.clone(),
            uptime_secs: self.started.elapsed().as_secs(),
            allocations_now: self.turn.active(),
            rooms_now: self.sfu.rooms_now(),
            participants_now: self.sfu.participants_now(),
            satellites_now: self.sfu.satellites_now(),
            cascade_uplinks_now: self.sfu.uplinks_now(),
            cascade_seats_now: self.sfu.proxy_seats_now(),
            cascade: self.trust.mode().name().to_string(),
            trusted_nodes_now: self.trust.listed_now(),
            devices_now: self.devices.devices_now(),
            invites_now: self.devices.invites_now(),
            since_start: self.counters.snapshot(),
        }
    }

    fn invite(&self, uses: u32, ttl_secs: u64, label: &str) -> Response {
        match self.devices.invite(uses, Duration::from_secs(ttl_secs), label, turn::unix_now()) {
            Ok(made) => Response::ok(Invited {
                link: vcall_proto::invite::link(&self.node_id, &self.control_addr, &made.token),
                uses: made.uses,
                expires_at: made.expires_at,
                label: made.label,
            }),
            Err(e) => Response::err(e.to_string()),
        }
    }

    /// `ok` only once the file has it: a device the file still holds would
    /// be in again after a restart.
    fn revoke(&self, id: &str) -> Response {
        let id = id.trim();
        match self.devices.revoke(id) {
            Ok(true) => return Response::ok(serde_json::json!({"revoked": "device", "id": id})),
            Err(e) => return Response::err(format!("device {id} is still in: {e}; revoke it again once the disk is right")),
            Ok(false) => {}
        }
        match self.devices.revoke_invite(id) {
            Ok(true) => Response::ok(serde_json::json!({"revoked": "invite", "hash": id})),
            Err(e) => Response::err(format!("invitation {id} is still open: {e}; revoke it again once the disk is right")),
            Ok(false) => Response::err(format!("no device and no invitation {id}")),
        }
    }
}

/// The socket file; removed when dropped.
pub struct CtlSocket {
    listener: UnixListener,
    path: PathBuf,
}

impl Drop for CtlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl CtlSocket {
    /// Takes the socket path. A file left by a dead node is replaced; a
    /// socket somebody answers on means a second node, and that is an error.
    pub async fn bind(path: &Path) -> io::Result<Self> {
        if path.exists() {
            if UnixStream::connect(path).await.is_ok() {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("another vcall answers on {}", path.display())));
            }
            std::fs::remove_file(path)?;
        }
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let listener = UnixListener::bind(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        }
        Ok(Self { listener, path: path.to_path_buf() })
    }

    pub async fn run(self, state: CtlState) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_connection(stream, state).await {
                            tracing::debug!(error = %e, "ctl connection ended with an error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ctl socket: accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }
}

async fn serve_connection(stream: UnixStream, state: CtlState) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read.take(MAX_LINE as u64)).lines();
    while let Some(line) = tokio::time::timeout(IO_TIMEOUT, lines.next_line())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no request in time"))??
    {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(Request::Health) => Response::ok(Health { version: state.version.clone(), uptime_secs: state.started.elapsed().as_secs() }),
            Ok(Request::Stats) => Response::ok(state.stats()),
            Ok(Request::Invite { uses, ttl_secs, label }) => state.invite(uses, ttl_secs, &label),
            Ok(Request::Devices) => Response::ok(state.devices.list(turn::unix_now())),
            Ok(Request::Revoke { id }) => state.revoke(&id),
            Err(e) => Response::err(format!("not a request: {e}")),
        };
        let mut out = serde_json::to_vec(&response)?;
        out.push(b'\n');
        write.write_all(&out).await?;
    }
    Ok(())
}

/// `vcall ctl`: one request to the node at `path`, its answer back.
pub async fn call(path: &Path, request: &Request) -> anyhow::Result<Response> {
    let mut stream = UnixStream::connect(path).await.map_err(|e| anyhow::anyhow!("cannot reach the node at {}: {e}", path.display()))?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    let (read, _) = stream.split();
    let mut lines = BufReader::new(read.take(MAX_LINE as u64)).lines();
    let answer = tokio::time::timeout(IO_TIMEOUT, lines.next_line()).await??.ok_or_else(|| anyhow::anyhow!("the node closed without an answer"))?;
    Ok(serde_json::from_str(&answer)?)
}
