//! What anybody who is not a client gets on the node's port: the page a
//! bare web server would give. The same words as the VLink bridge, so that
//! the node looks like one more idle server.

use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use http::{Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BODY: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
const READ_TIMEOUT: Duration = Duration::from_secs(10);

pub fn h2(respond: &mut SendResponse<Bytes>) {
    let response = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("server", "nginx")
        .header("content-type", "text/html")
        .header("content-length", BODY.len())
        .body(())
        .expect("response");
    if let Ok(mut body) = respond.send_response(response, false) {
        let _ = body.send_data(Bytes::from_static(BODY.as_bytes()), true);
    }
}

/// Reads the request up to the end of its head (`already` is what was
/// read before), does not look at it, and answers 404.
pub async fn http1<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, already: Vec<u8>) {
    let mut head = already;
    let mut buf = [0u8; 1024];
    let read = async {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8 * 1024 {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        true
    };
    if !matches!(tokio::time::timeout(READ_TIMEOUT, read).await, Ok(true)) {
        return;
    }
    let answer = format!(
        "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        BODY.len(),
        BODY
    );
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}
