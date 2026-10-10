//! Short-lived TURN credentials, and the nonce of the long-term mechanism.
//!
//! The node keeps one secret. Credentials are derived from it and never
//! stored: `username = <unix expiry>:<random>`, `password = hex(HMAC-SHA256
//! (secret, username))`. Whoever holds a username can be checked by
//! recomputing the password; after the expiry the username is refused. This
//! is the form every TURN server and client already take (coturn's
//! `use-auth-secret`, the "REST API" draft), so libwebrtc needs nothing new.
//!
//! The nonce is stateless too: a time, a random part and a MAC of both
//! together with the client's transport and address, so that a nonce the
//! node did not make, made too long ago, or made for another client is
//! refused without the node remembering any. The address in the MAC is
//! what keeps a nonce from being used with a forged source address: an
//! attacker who got one from his own address cannot drive the node over
//! UDP as somebody else, and a sniffed request does not replay from
//! elsewhere. A client whose address changed gets 438 and a fresh nonce,
//! as it would after an hour.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use ring::hmac;
use ring::rand::SecureRandom;

use super::allocation::{ClientKey, Transport};
use crate::stun;

const SECRET_FILE: &str = "turn.secret";
/// How long a nonce is taken; a client gets a fresh one with 438 after.
const NONCE_LIFETIME: u64 = 3600;
/// A username is `expiry:random`; anything far longer is not one of ours.
const MAX_USERNAME: usize = 64;

/// What the client is given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not in our form: nobody we gave credentials to.
    Unknown,
    Expired,
}

pub struct Auth {
    key: hmac::Key,
    realm: String,
}

impl Auth {
    pub fn new(secret: &[u8], realm: &str) -> Self {
        Self { key: hmac::Key::new(hmac::HMAC_SHA256, secret), realm: realm.to_string() }
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Credentials good until `now + ttl`.
    pub fn issue(&self, now: u64, ttl: Duration) -> Credentials {
        let expires_at = now + ttl.as_secs();
        let username = format!("{expires_at}:{}", hex(&random(8)));
        let password = self.password_of(&username);
        Credentials { username, password, expires_at }
    }

    pub fn password_of(&self, username: &str) -> String {
        hex(hmac::sign(&self.key, username.as_bytes()).as_ref())
    }

    /// The long-term key of `username`, if the username is one of ours and
    /// still good. The expiry limits making an allocation; one that exists
    /// keeps its key (`turn::Server::authenticate`).
    pub fn key_of(&self, username: &str, now: u64) -> Result<[u8; 16], Refusal> {
        if username.len() > MAX_USERNAME {
            return Err(Refusal::Unknown);
        }
        let (expiry, random) = username.split_once(':').ok_or(Refusal::Unknown)?;
        let expiry: u64 = expiry.parse().map_err(|_| Refusal::Unknown)?;
        if random.is_empty() || !random.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Refusal::Unknown);
        }
        if expiry <= now {
            return Err(Refusal::Expired);
        }
        Ok(stun::long_term_key(username, &self.realm, &self.password_of(username)))
    }

    /// A nonce for a 401 or 438 to `client`: `hex(time ‖ random ‖ mac)`,
    /// the MAC over the time, the random part, and the client.
    pub fn nonce(&self, now: u64, client: ClientKey) -> String {
        let mut raw = Vec::with_capacity(24);
        raw.extend_from_slice(&now.to_be_bytes());
        raw.extend_from_slice(&random(8));
        let mac = self.nonce_mac(&raw, client);
        raw.extend_from_slice(&mac);
        hex(&raw)
    }

    /// Did we make this nonce for `client`, less than an hour ago?
    pub fn nonce_ok(&self, nonce: &str, now: u64, client: ClientKey) -> bool {
        let Some(raw) = unhex(nonce) else {
            return false;
        };
        if raw.len() != 24 {
            return false;
        }
        if !crate::identity::same_secret(&self.nonce_mac(&raw[..16], client), &raw[16..]) {
            return false;
        }
        let mut t = [0u8; 8];
        t.copy_from_slice(&raw[..8]);
        let made = u64::from_be_bytes(t);
        made <= now && now - made < NONCE_LIFETIME
    }

    /// Eight bytes of MAC over `time ‖ random ‖ transport ‖ address ‖ port`.
    fn nonce_mac(&self, time_and_random: &[u8], client: ClientKey) -> [u8; 8] {
        let mut data = Vec::with_capacity(16 + 1 + 16 + 2);
        data.extend_from_slice(time_and_random);
        data.push(match client.transport {
            Transport::Udp => 0,
            Transport::Tcp => 1,
            Transport::Tls => 2,
        });
        match client.addr.ip() {
            IpAddr::V4(ip) => data.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => data.extend_from_slice(&ip.octets()),
        }
        data.extend_from_slice(&client.addr.port().to_be_bytes());
        let mac = hmac::sign(&self.key, &data);
        let mut out = [0u8; 8];
        out.copy_from_slice(&mac.as_ref()[..8]);
        out
    }
}

/// The node's secret from `dir`, made there on the first call.
pub fn load_or_create_secret(dir: &Path) -> anyhow::Result<Vec<u8>> {
    let path = dir.join(SECRET_FILE);
    if !path.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        crate::identity::write_private(&path, &hex(&random(32)))?;
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let secret = unhex(text.trim()).filter(|s| s.len() >= 16).with_context(|| format!("{} is not a secret", path.display()))?;
    Ok(secret)
}

pub fn random(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    ring::rand::SystemRandom::new().fill(&mut out).expect("the system's randomness");
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes of a hex string; `None` for anything that is not one. The
/// text comes from the network (a NONCE), so it is walked as bytes: a
/// slice of a `str` at a byte inside a multi-byte character would panic,
/// and with `panic = "abort"` take the node with it.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    bytes.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(transport: Transport, addr: &str) -> ClientKey {
        ClientKey { transport, addr: addr.parse().unwrap() }
    }

    #[test]
    fn credentials_hold_until_their_time_and_not_after() {
        let auth = Auth::new(b"secret", "veydan");
        let c = auth.issue(1_000_000, Duration::from_secs(600));
        assert_eq!(c.expires_at, 1_000_600);
        assert!(c.username.starts_with("1000600:"));
        assert_eq!(c.password.len(), 64);
        let key = auth.key_of(&c.username, 1_000_599).unwrap();
        assert_eq!(key, stun::long_term_key(&c.username, "veydan", &c.password));
        assert_eq!(auth.key_of(&c.username, 1_000_600), Err(Refusal::Expired));
        assert_eq!(auth.key_of(&c.username, 2_000_000), Err(Refusal::Expired));
    }

    #[test]
    fn usernames_of_other_shapes_are_nobody() {
        let auth = Auth::new(b"secret", "veydan");
        for name in ["", "alice", "1000600", ":abc", "1000600:", "1000600:zz", "x:abcd", &"1".repeat(100)] {
            assert_eq!(auth.key_of(name, 1), Err(Refusal::Unknown), "{name:?}");
        }
    }

    #[test]
    fn another_secret_makes_other_passwords() {
        let a = Auth::new(b"one", "veydan");
        let b = Auth::new(b"two", "veydan");
        let c = a.issue(1_000_000, Duration::from_secs(60));
        assert_ne!(a.password_of(&c.username), b.password_of(&c.username));
        assert_ne!(a.key_of(&c.username, 1_000_000).unwrap(), b.key_of(&c.username, 1_000_000).unwrap());
    }

    #[test]
    fn nonces_are_ours_for_an_hour() {
        let auth = Auth::new(b"secret", "veydan");
        let c = client(Transport::Udp, "198.51.100.1:40000");
        let n = auth.nonce(5000, c);
        assert_eq!(n.len(), 48);
        assert!(auth.nonce_ok(&n, 5000, c));
        assert!(auth.nonce_ok(&n, 5000 + NONCE_LIFETIME - 1, c));
        assert!(!auth.nonce_ok(&n, 5000 + NONCE_LIFETIME, c));
        assert!(!auth.nonce_ok(&n, 4999, c), "from the future");
        assert!(!Auth::new(b"other", "veydan").nonce_ok(&n, 5000, c));
        let mut forged = n.clone();
        forged.replace_range(46..48, "00");
        assert!(!auth.nonce_ok(&forged, 5000, c) || n.ends_with("00"));
        assert!(!auth.nonce_ok("abc", 5000, c));
        assert!(!auth.nonce_ok("", 5000, c));
    }

    #[test]
    fn a_nonce_is_for_one_client_only() {
        let auth = Auth::new(b"secret", "veydan");
        let c = client(Transport::Udp, "198.51.100.1:40000");
        let n = auth.nonce(5000, c);
        assert!(auth.nonce_ok(&n, 5000, c));
        // Another port, another address, another transport: another client.
        assert!(!auth.nonce_ok(&n, 5000, client(Transport::Udp, "198.51.100.1:40001")));
        assert!(!auth.nonce_ok(&n, 5000, client(Transport::Udp, "198.51.100.2:40000")));
        assert!(!auth.nonce_ok(&n, 5000, client(Transport::Tcp, "198.51.100.1:40000")));
        assert!(!auth.nonce_ok(&n, 5000, client(Transport::Tls, "198.51.100.1:40000")));
        let v6 = client(Transport::Udp, "[2001:db8::1]:40000");
        assert!(auth.nonce_ok(&auth.nonce(5000, v6), 5000, v6));
        assert!(!auth.nonce_ok(&auth.nonce(5000, v6), 5000, c));
    }

    #[test]
    fn a_nonce_that_is_not_hex_is_refused_without_a_panic() {
        // "aéb" is four bytes, an even number, and byte 2 is inside 'é':
        // slicing the str there would panic, and the node would abort.
        let auth = Auth::new(b"secret", "veydan");
        let c = client(Transport::Udp, "198.51.100.1:40000");
        for text in ["aéb", "é", "éé", "zz", "0g", "é0", "ééééééééééééééééééééééééééé"] {
            assert!(!auth.nonce_ok(text, 5000, c), "{text:?}");
            assert_eq!(unhex(text), None, "{text:?}");
        }
        assert_eq!(unhex("00ff"), Some(vec![0, 255]));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex(""), Some(Vec::new()));
    }

    #[test]
    fn the_secret_is_made_once() {
        let dir = std::env::temp_dir().join(format!("vcall-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = load_or_create_secret(&dir).unwrap();
        let b = load_or_create_secret(&dir).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
