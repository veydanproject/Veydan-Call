//! Who the node is, and how a caller makes sure of it.
//!
//! The scheme is VLink's identity v2 (`vlink_proto::id`, `vlink_proto::pin`),
//! and nothing of the checking is written here: a caller accepts what the
//! pin accepts. Two keys, as a bridge has:
//!
//! - **The node's key** (`node.key`, Ed25519) is made once and kept: its
//!   hash is the node's id. It signs the TLS certificate and nothing else.
//!   A node that loses it is a new node to everybody who knew the old one.
//! - **The TLS key** (`tls.key`, ECDSA P-256) is what the handshake is
//!   signed with: the kind every browser takes, so a passer-by gets the
//!   page of a bare web server rather than an alert. It may be replaced at
//!   any time with the certificate over it (`vcall id --renew-cert`); the
//!   id does not change with it.
//!
//! `node.crt` holds the certificate over the TLS key, signed by the node's
//! key, and behind it the certificate carrying the node's key: the chain
//! the node shows, as the pin checks it. Everything the node needs of its
//! identity is named through this module, so a change of scheme stays here.

use std::path::Path;

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData, SerialNumber, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use vlink_proto::pin;

pub use vlink_proto::tls::Identity;
/// The node's id: what a client pins. Printed as 64 hex characters.
pub type NodeId = vlink_proto::BridgeId;
/// `address:port#id`: all a client needs to reach a node.
pub type NodeRef = vlink_proto::BridgeRef;

const CERT_FILE: &str = "node.crt";
const KEY_FILE: &str = "node.key";
const TLS_KEY_FILE: &str = "tls.key";

/// A TURN client over TLS, RFC 7443. libwebrtc sends no ALPN; the node
/// then tells TURN from a browser by the first byte.
pub const ALPN_STUN_TURN: &[u8] = b"stun.turn";
pub const ALPN_HTTP1: &[u8] = b"http/1.1";

/// The id of the node with this identity.
pub fn node_id(identity: &Identity) -> anyhow::Result<NodeId> {
    Ok(identity.bridge_id()?)
}

/// Are two secrets the same? Compared to the end whatever they are, so
/// that the time taken says nothing of where they differ.
pub fn same_secret(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// The identity kept in `dir`: the node's key is made there on the first
/// call, and a TLS key and a chain over it whenever either is missing.
/// What is there is held to the rule: a node's key of another kind, or a
/// chain not over these keys, stops the node with a word on what to do,
/// rather than quietly making it another node.
pub fn load_or_create(dir: &Path) -> anyhow::Result<Identity> {
    let key_path = dir.join(KEY_FILE);
    let tls_key_path = dir.join(TLS_KEY_FILE);
    let cert_path = dir.join(CERT_FILE);
    if !key_path.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        write_private(&key_path, &generate_key()?)?;
        // A TLS key and a certificate without the node's key, left over
        // from something, are of no use: new ones take their place.
        let _ = std::fs::remove_file(&tls_key_path);
        let _ = std::fs::remove_file(&cert_path);
    }
    let key = std::fs::read_to_string(&key_path).with_context(|| format!("cannot read {}", key_path.display()))?;
    key_of(&key).with_context(|| {
        format!(
            "{}: not the key of a node; remove it, {} and {} and start again: the node comes back as a new node",
            key_path.display(),
            tls_key_path.display(),
            cert_path.display()
        )
    })?;
    if !tls_key_path.exists() {
        write_private(&tls_key_path, &generate_tls_key()?)?;
        let _ = std::fs::remove_file(&cert_path);
    }
    let tls_key =
        std::fs::read_to_string(&tls_key_path).with_context(|| format!("cannot read {}", tls_key_path.display()))?;
    tls_key_of(&tls_key)
        .with_context(|| format!("{}: not the TLS key of a node; remove it and start again", tls_key_path.display()))?;
    if !cert_path.exists() {
        std::fs::write(&cert_path, certificate(&key, &tls_key)?)
            .with_context(|| format!("cannot write {}", cert_path.display()))?;
    }
    let chain = std::fs::read_to_string(&cert_path).with_context(|| format!("cannot read {}", cert_path.display()))?;
    identity_of(&key, &chain, &tls_key).with_context(|| format!("{}", cert_path.display()))
}

/// A new TLS key and a new chain over it in place of those kept in `dir`.
/// The node's key, and so the id, stay.
pub fn renew(dir: &Path) -> anyhow::Result<Identity> {
    let key_path = dir.join(KEY_FILE);
    if !key_path.exists() {
        return load_or_create(dir);
    }
    let key = std::fs::read_to_string(&key_path).with_context(|| format!("cannot read {}", key_path.display()))?;
    key_of(&key).with_context(|| format!("{}: not the key of a node", key_path.display()))?;
    let tls_key = generate_tls_key()?;
    let chain = certificate(&key, &tls_key)?;
    write_private(&dir.join(TLS_KEY_FILE), &tls_key)?;
    let cert_path = dir.join(CERT_FILE);
    std::fs::write(&cert_path, &chain).with_context(|| format!("cannot write {}", cert_path.display()))?;
    identity_of(&key, &chain, &tls_key)
}

/// The node's key as a signer, from `dir`: what signs the reports to the
/// registry. The id it makes is the one of [`load_or_create`].
pub fn signing_key(dir: &Path) -> anyhow::Result<ring::signature::Ed25519KeyPair> {
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    let key_path = dir.join(KEY_FILE);
    let pem = std::fs::read_to_string(&key_path).with_context(|| format!("cannot read {}", key_path.display()))?;
    key_of(&pem).with_context(|| format!("{}: not the key of a node", key_path.display()))?;
    let der = match PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))? {
        PrivateKeyDer::Pkcs8(der) => der,
        _ => anyhow::bail!("{}: not a PKCS#8 key", key_path.display()),
    };
    ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der())
        .map_err(|e| anyhow::anyhow!("{}: not an Ed25519 key: {e}", key_path.display()))
}

/// The TLS identity these files make, held to the rule: the chain has to
/// be what a client takes for the node of this key.
fn identity_of(key_pem: &str, chain: &str, tls_key: &str) -> anyhow::Result<Identity> {
    let id = vlink_proto::BridgeId::of_key(&key_of(key_pem)?.subject_public_key_info());
    let tls = Identity::from_pem(chain, tls_key)?;
    anyhow::ensure!(
        tls.bridge_id()? == id,
        "the certificate is not signed by the node's key: run `vcall id --renew-cert` to issue one that is"
    );
    Ok(tls)
}

/// A fresh node, as PEM: the chain and the TLS key, ready for
/// `Identity::from_pem`. The node's key behind it is not kept: this is for
/// a node that lives as long as the process, as in a test.
pub fn generate() -> anyhow::Result<(String, String)> {
    let (chain, tls_key, _) = generate_with_key()?;
    Ok((chain, tls_key))
}

/// [`generate`], with the node's key as a signer too: what signs its
/// reports and its word in the cascade. The id of the chain is the id of
/// that key.
pub fn generate_with_key() -> anyhow::Result<(String, String, ring::signature::Ed25519KeyPair)> {
    let key = generate_key()?;
    let tls_key = generate_tls_key()?;
    let signer = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&key_of(&key)?.serialize_der())
        .map_err(|e| anyhow::anyhow!("not an Ed25519 key: {e}"))?;
    Ok((certificate(&key, &tls_key)?, tls_key, signer))
}

/// A fresh node's key, as PEM.
fn generate_key() -> anyhow::Result<String> {
    Ok(KeyPair::generate_for(&PKCS_ED25519)?.serialize_pem())
}

/// A fresh TLS key, as PEM.
fn generate_tls_key() -> anyhow::Result<String> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?.serialize_pem())
}

/// The chain over `tls_key_pem`, signed by `key_pem`, as PEM: the TLS
/// certificate first, the certificate carrying the node's key behind it.
/// Nothing in either is checked by those who know the node but the
/// signature and the dates. The fields are what a server set up in a
/// hurry would have, and each chain issued is new: its own serials, the
/// dates of its day.
fn certificate(key_pem: &str, tls_key_pem: &str) -> anyhow::Result<String> {
    let key = key_of(key_pem)?;
    let tls_key = tls_key_of(tls_key_pem)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = localhost();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    params.serial_number = Some(serial()?);
    dates(&mut params);
    let own = params.self_signed(&key)?;
    let issuer = Issuer::new(params, key);
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params.distinguished_name = localhost();
    params.serial_number = Some(serial()?);
    dates(&mut params);
    let tls = params.signed_by(&tls_key, &issuer)?;
    Ok(format!("{}{}", tls.pem(), own.pem()))
}

fn localhost() -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "localhost");
    name
}

fn serial() -> anyhow::Result<SerialNumber> {
    use ring::rand::SecureRandom;
    let mut serial = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut serial).map_err(|_| anyhow::anyhow!("no random bytes"))?;
    Ok(SerialNumber::from(serial.to_vec()))
}

/// The dates of the day: a day back, as the clocks of two machines never
/// quite agree, to twenty years on.
fn dates(params: &mut CertificateParams) {
    let now = std::time::SystemTime::now();
    params.not_before = (now - std::time::Duration::from_secs(86_400)).into();
    params.not_after = (now + std::time::Duration::from_secs(20 * 365 * 86_400)).into();
}

/// The node's key, when it is the kind a node has.
fn key_of(key_pem: &str) -> anyhow::Result<KeyPair> {
    let key = KeyPair::from_pem(key_pem).context("not a key")?;
    anyhow::ensure!(key.algorithm() == &PKCS_ED25519, "not an Ed25519 key");
    Ok(key)
}

/// The TLS key: the kind every browser takes.
fn tls_key_of(tls_key_pem: &str) -> anyhow::Result<KeyPair> {
    let key = KeyPair::from_pem(tls_key_pem).context("not a key")?;
    anyhow::ensure!(key.algorithm() == &PKCS_ECDSA_P256_SHA256, "not a P-256 key");
    Ok(key)
}

/// How the node answers on its port: TLS 1.3, its own certificate, nothing
/// asked of the caller. The ALPNs it offers, in order of preference.
pub fn server_config(identity: Identity) -> anyhow::Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(pin::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(identity.chain, identity.key)?;
    config.alpn_protocols =
        vec![vcall_proto::ALPN.to_vec(), ALPN_STUN_TURN.to_vec(), pin::ALPN_H2.to_vec(), ALPN_HTTP1.to_vec()];
    Ok(config)
}

/// How a caller reaches the node `id`: the one certificate accepted, and
/// the ALPN of what it is there for.
pub fn client_config(id: NodeId, alpn: &[u8]) -> anyhow::Result<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(pin::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(pin::verifier(id))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// The name the TLS hello is addressed to: none for a bare address.
pub fn server_name(node: &NodeRef) -> anyhow::Result<ServerName<'static>> {
    Ok(pin::server_name(node)?)
}

/// For the owner alone, where the system knows what that means.
pub(crate) fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot write {}", path.display()))?;
        file.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vcall-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_identity_is_made_once_and_the_tls_key_may_be_renewed() {
        let dir = temp_dir("files");
        let a = node_id(&load_or_create(&dir).unwrap()).unwrap();
        assert_eq!(node_id(&load_or_create(&dir).unwrap()).unwrap(), a);
        assert_eq!(a.to_string().len(), 64);
        let reference: NodeRef = format!("203.0.113.7:443#{a}").parse().unwrap();
        assert_eq!(reference.id, a);
        // The signing key is the key of the id: what it signs, the
        // registry takes for this node and no other.
        let signer = signing_key(&dir).unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(ring::signature::KeyPair::public_key(&signer).as_ref());
        assert_eq!(vcall_proto::register::id_of_key(&public), a.to_string());
        assert_eq!(vlink_proto::BridgeId::of_ed25519(&public), a);
        // Renewed: another TLS key and chain, the same id.
        let cert_before = std::fs::read_to_string(dir.join(CERT_FILE)).unwrap();
        assert_eq!(node_id(&renew(&dir).unwrap()).unwrap(), a);
        assert_ne!(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap(), cert_before);
        assert_eq!(node_id(&load_or_create(&dir).unwrap()).unwrap(), a);
        // Another node's chain over this node's files stops the node.
        let (chain, tls_key) = generate().unwrap();
        std::fs::write(dir.join(CERT_FILE), chain).unwrap();
        std::fs::write(dir.join(TLS_KEY_FILE), tls_key).unwrap();
        let err = format!("{:#}", load_or_create(&dir).err().expect("refused"));
        assert!(err.contains("--renew-cert"), "{err}");
        assert_eq!(node_id(&renew(&dir).unwrap()).unwrap(), a);
        // A key of another kind is not a node's key.
        std::fs::write(dir.join(KEY_FILE), KeyPair::generate().unwrap().serialize_pem()).unwrap();
        assert!(format!("{:#}", load_or_create(&dir).err().expect("refused")).contains("Ed25519"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_generated_identity_is_a_chain_over_a_browser_kind_of_key() {
        let (chain, tls_key) = generate().unwrap();
        let identity = Identity::from_pem(&chain, &tls_key).unwrap();
        assert_eq!(identity.chain.len(), 2);
        assert_eq!(tls_key_of(&tls_key).unwrap().algorithm(), &PKCS_ECDSA_P256_SHA256);
        assert_eq!(node_id(&identity).unwrap(), vlink_proto::BridgeId::of_cert(identity.chain[1].as_ref()).unwrap());
        // With the signer: its id is the chain's.
        let (chain, tls_key, signer) = generate_with_key().unwrap();
        let identity = Identity::from_pem(&chain, &tls_key).unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(ring::signature::KeyPair::public_key(&signer).as_ref());
        assert_eq!(vlink_proto::BridgeId::of_ed25519(&public), node_id(&identity).unwrap());
        assert!(same_secret(b"abc", b"abc"));
        assert!(!same_secret(b"abc", b"abd"));
        assert!(!same_secret(b"abc", b"abcd"));
        assert!(!same_secret(b"", b"a"));
    }
}
