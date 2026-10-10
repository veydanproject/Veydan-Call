//! A small HTTP client: one request, one answer, the connection closed.
//!
//! The node says a few short things to the registry, as the bridge does.
//! Over `https://` the certificate is checked against the bundled roots,
//! so that nothing of the system is needed; `http://` is for a registry
//! on the same machine and the tests.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// The registry answers in a few kilobytes; more is not an answer.
const MAX_ANSWER: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).trim().to_string()
    }
}

/// `http[s]://host[:port]/path` taken apart.
struct Address {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> anyhow::Result<Address> {
    let (tls, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        _ => anyhow::bail!("not an http(s) address: {url}"),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':').filter(|(h, _)| !h.contains(']') || h.ends_with(']')) {
        Some((host, port)) => (host, port.parse().with_context(|| format!("bad port in {url}"))?),
        None => (authority, if tls { 443 } else { 80 }),
    };
    anyhow::ensure!(!host.is_empty(), "no host in {url}");
    Ok(Address { tls, host: host.trim_matches(['[', ']']).to_ascii_lowercase(), port, path: path.to_string() })
}

fn tls_config() -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// One request with a JSON body, the answer whatever its status.
pub async fn post_json(url: &str, body: &[u8]) -> anyhow::Result<Answer> {
    request(url, Some(body)).await
}

/// One GET, the answer whatever its status.
pub async fn get(url: &str) -> anyhow::Result<Answer> {
    request(url, None).await
}

async fn request(url: &str, body: Option<&[u8]>) -> anyhow::Result<Answer> {
    let address = parse(url)?;
    let work = async {
        let stream = TcpStream::connect((address.host.as_str(), address.port)).await?;
        if address.tls {
            let name = ServerName::try_from(address.host.clone())?;
            let tls = TlsConnector::from(Arc::new(tls_config()?)).connect(name, stream).await?;
            exchange(tls, &address, body).await
        } else {
            exchange(stream, &address, body).await
        }
    };
    tokio::time::timeout(TIMEOUT, work).await.map_err(|_| anyhow::anyhow!("timed out"))?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, address: &Address, body: Option<&[u8]>) -> anyhow::Result<Answer> {
    let head = match body {
        Some(body) => format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: vcall/{}\r\nAccept: application/json\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            address.path,
            address.host,
            crate::VERSION,
            body.len()
        ),
        None => format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: vcall/{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            address.path,
            address.host,
            crate::VERSION
        ),
    };
    stream.write_all(head.as_bytes()).await?;
    if let Some(body) = body {
        stream.write_all(body).await?;
    }
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        anyhow::ensure!(raw.len() <= MAX_ANSWER, "the answer is too long");
    }
    let (head, body) = split(&raw).context("no http answer")?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("no status in the answer")?;
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { unchunk(body) } else { body.to_vec() };
    Ok(Answer { status, body })
}

fn split(raw: &[u8]) -> Option<(String, &[u8])> {
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((String::from_utf8_lossy(&raw[..at]).into_owned(), &raw[at + 4..]))
}

/// A chunked body put together; what cannot be read as chunks is left out.
fn unchunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(at) = body.windows(2).position(|w| w == b"\r\n") {
        let Ok(size) = usize::from_str_radix(String::from_utf8_lossy(&body[..at]).trim().split(';').next().unwrap_or(""), 16) else {
            break;
        };
        body = &body[at + 2..];
        if size == 0 || body.len() < size {
            break;
        }
        out.extend_from_slice(&body[..size]);
        body = body.get(size + 2..).unwrap_or(&[]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_taken_apart() {
        let a = parse("https://hub.example/vlink/v1/calls/register").unwrap();
        assert!(a.tls);
        assert_eq!((a.host.as_str(), a.port, a.path.as_str()), ("hub.example", 443, "/vlink/v1/calls/register"));
        let b = parse("http://127.0.0.1:8080").unwrap();
        assert!(!b.tls);
        assert_eq!((b.host.as_str(), b.port, b.path.as_str()), ("127.0.0.1", 8080, "/"));
        assert!(parse("ftp://x").is_err());
        assert!(parse("http://").is_err());
    }

    #[test]
    fn chunks_are_joined() {
        assert_eq!(unchunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"), b"abcde");
        let (head, body) = split(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\n{}").unwrap();
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(body, b"{}");
    }
}
