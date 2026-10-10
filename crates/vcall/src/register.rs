//! The node tells the registry that it exists, and keeps telling.
//!
//! The first report makes the node known; the registry then reaches its
//! control channel and its STUN port on its own. Later reports say it is
//! still there and how full it is. A node that stops reporting is dropped
//! from the lists. Every report is signed by the node's key with the time
//! it was made (`vcall_proto::register`).
//!
//! A private node (`VCALL_PRIVATE`) never reports: it is for the people
//! who hold its key. Until there is a registry to report to, a failed
//! report is a line in the log and nothing more.

use std::net::IpAddr;
use std::time::Duration;

use ring::signature::Ed25519KeyPair;
use vcall_proto::register::{Registered, Registration};

use crate::Handle;

/// Between reports, once the registry knows the node.
const EVERY: Duration = Duration::from_secs(300);
/// Between attempts while it does not.
const RETRY: Duration = Duration::from_secs(30);

pub struct Registrar {
    /// The registry, `https://host/vlink`.
    pub registry: String,
    pub id: String,
    /// The node's key, which signs every report.
    pub key: Ed25519KeyPair,
    pub public_ip: IpAddr,
    pub control_port: u16,
    pub turn_port: u16,
    pub sfu_port: u16,
    pub region: String,
    pub caps: Vec<String>,
    /// What the node holds now and may hold at most.
    pub max_allocations: u32,
    pub max_participants: u32,
    pub max_mbps: u32,
    pub max_rooms: u32,
    pub max_uplinks: u32,
    pub handle: Handle,
}

impl Registrar {
    /// Reports for as long as the node runs.
    pub async fn run(self) {
        let mut known: Option<String> = None;
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            let settled = match self.report().await {
                Ok(reply) => {
                    if known.as_deref() != Some(reply.state.as_str()) {
                        tracing::info!(registry = %self.registry, state = %reply.state, addr = %reply.addr, "registry knows this node");
                        known = Some(reply.state.clone());
                    }
                    !reply.is_new()
                }
                Err(e) => {
                    tracing::warn!(registry = %self.registry, error = %format!("{e:#}"), "registry was not told");
                    false
                }
            };
            // Until the registry has checked the node, it is of no use to
            // anybody: ask again soon. After that the reports are a heartbeat.
            tokio::time::sleep(if settled { EVERY } else { RETRY }).await;
        }
    }

    /// The report as of now, signed.
    pub fn registration(&self) -> Registration {
        let c = self.handle.counters.snapshot();
        // Bytes relayed since the start, over the uptime: not the rate of
        // the last minute, but a number that says how busy the node is.
        let bytes = c.bytes_to_peers + c.bytes_to_clients + c.sfu_bytes_out;
        let mbps = (bytes * 8 / self.handle.started.elapsed().as_secs().max(1) / 1_000_000) as u32;
        let mut r = Registration {
            v: vcall_proto::register::REGISTRATION_VERSION,
            id: self.id.clone(),
            ip: Some(self.public_ip),
            control_port: self.control_port,
            turn_port: self.turn_port,
            sfu_port: self.sfu_port,
            region: self.region.clone(),
            version: crate::VERSION.to_string(),
            caps: self.caps.clone(),
            load: vcall_proto::register::Load {
                allocations: self.handle.turn.active() as u32,
                max_allocations: self.max_allocations,
                participants: self.handle.sfu.participants_now() as u32,
                max_participants: self.max_participants,
                mbps,
                max_mbps: self.max_mbps,
                rooms: (self.handle.sfu.rooms_now() + self.handle.sfu.satellites_now()) as u32,
                max_rooms: self.max_rooms,
                uplinks: self.handle.sfu.uplinks_now() as u32,
                max_uplinks: self.max_uplinks,
            },
            ts: crate::turn::unix_now(),
            key: String::new(),
            sig: String::new(),
        };
        r.sign(&self.key);
        r
    }

    pub async fn report(&self) -> anyhow::Result<Registered> {
        let request = self.registration();
        request.well_formed()?;
        let body = serde_json::to_vec(&request)?;
        let url = format!("{}/v1/calls/register", self.registry.trim_end_matches('/'));
        let answer = crate::https::post_json(&url, &body).await?;
        anyhow::ensure!(answer.status == 200, "{} {}", answer.status, answer.text());
        Ok(serde_json::from_slice(&answer.body)?)
    }
}
