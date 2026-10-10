//! The devices a private node let in, and the invitations that let them.
//!
//! ```text
//!  vcall ctl invite   → a token, in a link            kept as its hash, so many uses, until a day
//!  POST /v1/invite    token → device id and secret    the secret kept as its hash
//!  access.device      id and secret in every request  checked here, in the time a compare takes
//!  vcall ctl devices  what is in                      vcall ctl revoke <id>: out
//! ```
//!
//! All of it lives in one file in `VCALL_DATA` (`devices.json`), written
//! whole after every change, for the node alone. A change the file does
//! not take (a full disk, a directory gone read-only) is not made: the
//! node holds what the file holds, the caller is told, and a revocation
//! or an invitation is asked for again once the disk is right. The file
//! holds hashes: whoever reads it can revoke nobody and let nobody in.
//! What a device is called is the label the operator gave the invitation
//! and the name the app sent, nothing of the person.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vcall_proto::invite::{self, DEVICE_ID_BYTES, SECRET_BYTES, TOKEN_BYTES};
use vcall_proto::Access;

use crate::identity::same_secret;
use crate::turn::auth::{hex, random};

pub const FILE: &str = "devices.json";
/// Live invitations and devices a node holds at the most: a file that
/// cannot grow without end.
pub const MAX_INVITES: usize = 256;
pub const MAX_DEVICES: usize = 4096;
/// What an invitation may be: so many uses, so long.
pub const MAX_USES: u32 = 1000;
pub const MAX_TTL: Duration = Duration::from_secs(365 * 86_400);
pub const DEFAULT_TTL: Duration = Duration::from_secs(7 * 86_400);
/// `last_seen` of a device is written when it moved by this much: a
/// device that calls every minute is not a write every minute.
const SEEN_STEP: u64 = 3600;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    invites: Vec<Invite>,
    #[serde(default)]
    devices: Vec<Device>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Invite {
    /// SHA-256 of the token, hex.
    token_hash: String,
    #[serde(default)]
    label: String,
    uses_left: u32,
    expires_at: u64,
    made_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Device {
    id: String,
    /// SHA-256 of the secret, hex.
    secret_hash: String,
    /// The label of the invitation, and the name the app sent.
    #[serde(default)]
    label: String,
    #[serde(default)]
    name: String,
    made_at: u64,
    #[serde(default)]
    last_seen: u64,
}

/// What `vcall ctl invite` gets: the token, once.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteMade {
    pub token: String,
    pub uses: u32,
    pub expires_at: u64,
    pub label: String,
}

/// What `vcall ctl devices` shows.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Listing {
    pub invites: Vec<InviteView>,
    pub devices: Vec<DeviceView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteView {
    /// The first characters of the token's hash: enough to tell one from
    /// another in a list, of no use to anybody.
    pub hash: String,
    pub label: String,
    pub uses_left: u32,
    pub expires_at: u64,
    pub made_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceView {
    pub id: String,
    pub label: String,
    pub name: String,
    pub made_at: u64,
    pub last_seen: u64,
}

/// Why an invitation was not made.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    #[error("uses must be 1 to {MAX_USES}")]
    Uses,
    #[error("the time to live must be a minute to a year")]
    Ttl,
    #[error("the node holds as many invitations as it may ({MAX_INVITES}); revoke some")]
    TooMany,
    /// The file did not take it, so it was not made.
    #[error("{0}")]
    NotWritten(String),
}

/// Why a token was not exchanged.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExchangeError {
    /// Not a token the node made, used up, run out, or no room for one
    /// more device: one word for all of them, so that tokens cannot be
    /// told apart by the answer.
    #[error("no such invitation, or it was used up or ran out")]
    Refused,
    /// The file did not take the device, so none was made and the token
    /// was not spent.
    #[error("{0}")]
    NotWritten(String),
}

/// The file did not take a change.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct NotWritten(pub String);

pub struct Devices {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

fn sha256_hex(text: &str) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref())
}

impl Devices {
    /// The devices kept in `path` (made on the first change), or in memory
    /// alone with no path (the tests).
    pub fn open(path: Option<PathBuf>) -> anyhow::Result<Arc<Self>> {
        let state = match &path {
            Some(path) if path.exists() => {
                let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{}: not the devices of a node: {e}", path.display()))?
            }
            _ => State::default(),
        };
        Ok(Arc::new(Self { path, state: Mutex::new(state) }))
    }

    /// Keys, devices or invitations: anybody could get in.
    pub fn has_any(&self) -> bool {
        let s = self.state.lock().expect("devices");
        !s.devices.is_empty() || !s.invites.is_empty()
    }

    pub fn devices_now(&self) -> usize {
        self.state.lock().expect("devices").devices.len()
    }

    pub fn invites_now(&self) -> usize {
        self.state.lock().expect("devices").invites.len()
    }

    /// `state` written to the file, whole or not at all.
    fn save(&self, state: &State) -> Result<(), NotWritten> {
        let Some(path) = &self.path else { return Ok(()) };
        let text = serde_json::to_string_pretty(state).expect("plain data");
        crate::trust::write_private(path, &text).map_err(|e| {
            tracing::error!(file = %path.display(), error = %e, "the devices could not be written; the change is not made");
            NotWritten(format!("{} could not be written: {e}", path.display()))
        })
    }

    /// `change` made to the state and written. When the file does not
    /// take it, the state is as it was: the node holds what the file
    /// holds, and a restart changes nothing.
    fn commit<T>(&self, s: &mut State, change: impl FnOnce(&mut State) -> T) -> Result<T, NotWritten> {
        let before = s.clone();
        let made = change(s);
        match self.save(s) {
            Ok(()) => Ok(made),
            Err(e) => {
                *s = before;
                Err(e)
            }
        }
    }

    fn sweep(state: &mut State, now: u64) {
        state.invites.retain(|i| i.uses_left > 0 && i.expires_at > now);
    }

    /// A new invitation: the token goes into the link and is not kept.
    pub fn invite(&self, uses: u32, ttl: Duration, label: &str, now: u64) -> Result<InviteMade, InviteError> {
        if !(1..=MAX_USES).contains(&uses) {
            return Err(InviteError::Uses);
        }
        if ttl < Duration::from_secs(60) || ttl > MAX_TTL {
            return Err(InviteError::Ttl);
        }
        let mut s = self.state.lock().expect("devices");
        Self::sweep(&mut s, now);
        if s.invites.len() >= MAX_INVITES {
            return Err(InviteError::TooMany);
        }
        let token = hex(&random(TOKEN_BYTES));
        let label = invite::label(label);
        let expires_at = now + ttl.as_secs();
        let token_hash = sha256_hex(&token);
        self.commit(&mut s, |s| s.invites.push(Invite { token_hash, label: label.clone(), uses_left: uses, expires_at, made_at: now }))
            .map_err(|NotWritten(e)| InviteError::NotWritten(e))?;
        Ok(InviteMade { token, uses, expires_at, label })
    }

    /// The token of an invitation exchanged for a device: its id and
    /// secret, once, and the label of the invitation.
    pub fn exchange(&self, token: &str, name: &str, now: u64) -> Result<(String, String, String), ExchangeError> {
        let hash = sha256_hex(token);
        let mut s = self.state.lock().expect("devices");
        Self::sweep(&mut s, now);
        let at = s.invites.iter().position(|i| same_secret(i.token_hash.as_bytes(), hash.as_bytes())).ok_or(ExchangeError::Refused)?;
        if s.devices.len() >= MAX_DEVICES {
            tracing::warn!("the node holds as many devices as it may ({MAX_DEVICES}); revoke some");
            return Err(ExchangeError::Refused);
        }
        let id = hex(&random(DEVICE_ID_BYTES));
        let secret = hex(&random(SECRET_BYTES));
        let secret_hash = sha256_hex(&secret);
        let name = invite::label(name);
        let label = self
            .commit(&mut s, |s| {
                s.invites[at].uses_left -= 1;
                let label = s.invites[at].label.clone();
                if s.invites[at].uses_left == 0 {
                    s.invites.remove(at);
                }
                s.devices.push(Device { id: id.clone(), secret_hash, label: label.clone(), name, made_at: now, last_seen: now });
                label
            })
            .map_err(|NotWritten(e)| ExchangeError::NotWritten(e))?;
        Ok((id, secret, label))
    }

    /// Are these the credentials of a device the node made and has not
    /// revoked? Compared to the end whatever they are.
    pub fn check(&self, id: &str, secret: &str, now: u64) -> bool {
        let hash = sha256_hex(secret);
        let mut s = self.state.lock().expect("devices");
        let Some(device) = s.devices.iter_mut().find(|d| d.id == id) else {
            // The time of a compare all the same, for an id that is not there.
            let _ = same_secret(hash.as_bytes(), hash.as_bytes());
            return false;
        };
        if !same_secret(device.secret_hash.as_bytes(), hash.as_bytes()) {
            return false;
        }
        if now.saturating_sub(device.last_seen) >= SEEN_STEP {
            device.last_seen = now;
            // When it is seen is a convenience for the listing: the file
            // not taking it changes nothing about who is in.
            let _ = self.save(&s);
        }
        true
    }

    /// The device is a stranger from now on; was it known? An error when
    /// it was, but the file did not take it: the device stays in, and the
    /// revocation is to be asked for again.
    pub fn revoke(&self, id: &str) -> Result<bool, NotWritten> {
        let mut s = self.state.lock().expect("devices");
        if !s.devices.iter().any(|d| d.id == id) {
            return Ok(false);
        }
        self.commit(&mut s, |s| s.devices.retain(|d| d.id != id))?;
        Ok(true)
    }

    /// An invitation withdrawn by the hash `vcall ctl devices` shows; was
    /// there one? An error as [`Devices::revoke`] gives it.
    pub fn revoke_invite(&self, hash_prefix: &str) -> Result<bool, NotWritten> {
        let mut s = self.state.lock().expect("devices");
        if hash_prefix.len() < 6 || !s.invites.iter().any(|i| i.token_hash.starts_with(hash_prefix)) {
            return Ok(false);
        }
        self.commit(&mut s, |s| s.invites.retain(|i| !i.token_hash.starts_with(hash_prefix)))?;
        Ok(true)
    }

    pub fn list(&self, now: u64) -> Listing {
        let mut s = self.state.lock().expect("devices");
        Self::sweep(&mut s, now);
        Listing {
            invites: s
                .invites
                .iter()
                .map(|i| InviteView { hash: i.token_hash[..12].to_string(), label: i.label.clone(), uses_left: i.uses_left, expires_at: i.expires_at, made_at: i.made_at })
                .collect(),
            devices: s
                .devices
                .iter()
                .map(|d| DeviceView { id: d.id.clone(), label: d.label.clone(), name: d.name.clone(), made_at: d.made_at, last_seen: d.last_seen })
                .collect(),
        }
    }
}

/// The door of a private node: a key from the file, or a device the node
/// made. On a public node it stands open.
pub struct Gate {
    pub private: bool,
    pub keys: Vec<String>,
    pub devices: Arc<Devices>,
}

impl Gate {
    /// Does what the caller shows open the node? Always on a public one.
    pub fn opens(&self, access: Option<&Access>, now: u64) -> bool {
        if !self.private {
            return true;
        }
        let Some(access) = access else { return false };
        if let Some(key) = access.key.as_deref() {
            if self.keys.iter().any(|k| same_secret(k.as_bytes(), key.as_bytes())) {
                return true;
            }
        }
        if let Some(device) = &access.device {
            if self.devices.check(&device.id, &device.secret, now) {
                return true;
            }
        }
        false
    }
}

/// `7d`, `12h`, `30m`, `3600` (seconds): how long an invitation lives.
pub fn parse_ttl(text: &str) -> anyhow::Result<Duration> {
    let text = text.trim();
    let (digits, scale) = match text.chars().last() {
        Some('d') => (&text[..text.len() - 1], 86_400),
        Some('h') => (&text[..text.len() - 1], 3600),
        Some('m') => (&text[..text.len() - 1], 60),
        Some('s') => (&text[..text.len() - 1], 1),
        _ => (text, 1),
    };
    let n: u64 = digits.trim().parse().map_err(|_| anyhow::anyhow!("not a time: {text} (7d, 12h, 30m or seconds)"))?;
    Ok(Duration::from_secs(n.saturating_mul(scale)))
}

/// A path for the file: in `dir`.
pub fn file_in(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vcall-devices-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_invitation_is_exchanged_so_many_times_and_the_device_lasts_until_revoked() {
        let dir = temp("exchange");
        let path = file_in(&dir);
        let d = Devices::open(Some(path.clone())).unwrap();
        assert!(!d.has_any());
        let made = d.invite(2, Duration::from_secs(600), " Anna's\tphone ", 1000).unwrap();
        assert_eq!(made.token.len(), TOKEN_BYTES * 2);
        assert_eq!((made.uses, made.expires_at, made.label.as_str()), (2, 1600, "Anna'sphone"));
        assert!(d.has_any());
        // The file holds the hash, not the token.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&made.token) && text.contains(&sha256_hex(&made.token)));

        assert_eq!(d.exchange("not-a-token", "x", 1001), Err(ExchangeError::Refused));
        let (id, secret, label) = d.exchange(&made.token, "Chat 5.1.8", 1001).unwrap();
        assert_eq!((id.len(), secret.len(), label.as_str()), (DEVICE_ID_BYTES * 2, SECRET_BYTES * 2, "Anna'sphone"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&secret) && text.contains(&id));
        assert!(d.check(&id, &secret, 1002));
        assert!(!d.check(&id, &"0".repeat(64), 1002));
        assert!(!d.check(&"0".repeat(32), &secret, 1002));
        // The second use, then none.
        let (id2, secret2, _) = d.exchange(&made.token, "", 1003).unwrap();
        assert_eq!(d.exchange(&made.token, "", 1004), Err(ExchangeError::Refused));
        assert_eq!(d.list(1004).invites.len(), 0);
        assert_eq!(d.list(1004).devices.len(), 2);
        // An invitation runs out.
        let late = d.invite(1, Duration::from_secs(60), "", 2000).unwrap();
        assert_eq!(d.exchange(&late.token, "", 2060), Err(ExchangeError::Refused));
        // Revoked: a stranger. What was kept comes back after a restart.
        assert_eq!(d.revoke(&id), Ok(true));
        assert_eq!(d.revoke(&id), Ok(false));
        assert!(!d.check(&id, &secret, 1005));
        let again = Devices::open(Some(path)).unwrap();
        assert!(again.check(&id2, &secret2, 1006));
        assert!(!again.check(&id, &secret, 1006));
        assert_eq!(again.devices_now(), 1);
        // An invitation withdrawn by its hash.
        let withdrawn = d.invite(1, Duration::from_secs(600), "", 3000).unwrap();
        let hash = d.list(3000).invites[0].hash.clone();
        assert_eq!(d.revoke_invite(&hash), Ok(true));
        assert_eq!(d.revoke_invite(&hash), Ok(false));
        assert_eq!(d.exchange(&withdrawn.token, "", 3001), Err(ExchangeError::Refused));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A change the file does not take is not made: the node says so and
    /// holds what the file holds, so a restart brings nothing back that
    /// the operator was told was gone.
    #[test]
    fn a_change_the_file_does_not_take_is_not_made() {
        let dir = temp("unwritten");
        let path = file_in(&dir);
        let d = Devices::open(Some(path.clone())).unwrap();
        let made = d.invite(2, Duration::from_secs(600), "phone", 1000).unwrap();
        let (id, secret, _) = d.exchange(&made.token, "", 1001).unwrap();
        let kept = std::fs::read_to_string(&path).unwrap();
        // The disk goes wrong: a file where the directory was, so nothing
        // under it can be written, whoever runs the test.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "").unwrap();
        let unwritten = |e: &str| e.contains("could not be written");
        // A revocation that did not reach the file is not one.
        let e = d.revoke(&id).unwrap_err();
        assert!(unwritten(&e.0), "{e}");
        assert!(d.check(&id, &secret, 1002), "the device is in, as the file has it");
        assert_eq!(d.devices_now(), 1);
        // Nor an invitation withdrawn, made or exchanged.
        let hash = d.list(1002).invites[0].hash.clone();
        assert!(matches!(d.revoke_invite(&hash), Err(NotWritten(e)) if unwritten(&e)));
        assert_eq!(d.list(1002).invites[0].uses_left, 1);
        assert!(matches!(d.invite(1, Duration::from_secs(600), "", 1003), Err(InviteError::NotWritten(e)) if unwritten(&e)));
        assert_eq!(d.invites_now(), 1);
        assert!(matches!(d.exchange(&made.token, "", 1004), Err(ExchangeError::NotWritten(e)) if unwritten(&e)));
        assert_eq!((d.devices_now(), d.list(1004).invites[0].uses_left), (1, 1), "the token is not spent");
        // Seeing a device again is not a change: it is let in all the same.
        assert!(d.check(&id, &secret, 1001 + SEEN_STEP));
        // The disk is right again: the same asks go through, and the file
        // takes them.
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &kept).unwrap();
        assert_eq!(d.revoke(&id), Ok(true));
        assert!(!d.check(&id, &secret, 1005));
        let (id2, secret2, _) = d.exchange(&made.token, "", 1006).unwrap();
        let again = Devices::open(Some(path)).unwrap();
        assert!(!again.check(&id, &secret, 1007));
        assert!(again.check(&id2, &secret2, 1007));
        assert_eq!(again.invites_now(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_limits_of_an_invitation_hold() {
        let d = Devices::open(None).unwrap();
        assert_eq!(d.invite(0, Duration::from_secs(600), "", 1).unwrap_err(), InviteError::Uses);
        assert_eq!(d.invite(MAX_USES + 1, Duration::from_secs(600), "", 1).unwrap_err(), InviteError::Uses);
        assert_eq!(d.invite(1, Duration::from_secs(1), "", 1).unwrap_err(), InviteError::Ttl);
        assert_eq!(d.invite(1, MAX_TTL + Duration::from_secs(1), "", 1).unwrap_err(), InviteError::Ttl);
        for _ in 0..MAX_INVITES {
            d.invite(1, Duration::from_secs(600), "", 1).unwrap();
        }
        assert_eq!(d.invite(1, Duration::from_secs(600), "", 1).unwrap_err(), InviteError::TooMany);
        // Run out, they make room.
        assert!(d.invite(1, Duration::from_secs(600), "", 1000).is_ok());
        assert_eq!(parse_ttl("7d").unwrap(), Duration::from_secs(7 * 86_400));
        assert_eq!(parse_ttl("12h").unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("90").unwrap(), Duration::from_secs(90));
        assert!(parse_ttl("soon").is_err());
    }

    #[test]
    fn the_gate_takes_a_key_or_a_device_and_stands_open_on_a_public_node() {
        let devices = Devices::open(None).unwrap();
        let made = devices.invite(1, Duration::from_secs(600), "", 1).unwrap();
        let (id, secret, _) = devices.exchange(&made.token, "", 1).unwrap();
        let gate = Gate { private: true, keys: vec!["k1".into()], devices: devices.clone() };
        assert!(!gate.opens(None, 2));
        assert!(!gate.opens(Some(&Access::default()), 2));
        assert!(gate.opens(Some(&Access::key("k1")), 2));
        assert!(!gate.opens(Some(&Access::key("k2")), 2));
        assert!(gate.opens(Some(&Access::device(id.clone(), secret.clone())), 2));
        assert!(!gate.opens(Some(&Access::device(id.clone(), "x")), 2));
        // A wrong key with a right device: the device opens.
        let both = Access { key: Some("k2".into()), device: Some(vcall_proto::DeviceAccess { id: id.clone(), secret: secret.clone() }), pass: None };
        assert!(gate.opens(Some(&both), 2));
        devices.revoke(&id).unwrap();
        assert!(!gate.opens(Some(&Access::device(id, secret)), 2));
        let public = Gate { private: false, keys: vec![], devices };
        assert!(public.opens(None, 2));
    }
}
