use crate::connection::{Connection as TuicConnection, ERROR_CODE};
use std::net::SocketAddr;
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tuic::Address as TuicAddress;

/// Handle an HTTP CONNECT tunnel request (used for HTTPS).
///
/// The client sends `CONNECT host:port HTTP/1.1`, we open a relay connection
/// to the target, reply `200 Connection Established`, then copy bidirectionally.
pub async fn handle_connect(mut stream: TcpStream, peer_addr: SocketAddr, target: &str) {
    let (host, port) = match parse_host_port(target) {
        Some(hp) => hp,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    };

    let tuic_addr = TuicAddress::DomainAddress(host.to_string(), port);

    let relay = match TuicConnection::get().await {
        Ok(conn) => conn.connect(tuic_addr.clone()).await,
        Err(err) => Err(err),
    };

    match relay {
        Ok(relay) => {
            let mut relay = relay.compat();

            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                let _ = relay.shutdown().await;
                return;
            }

            match io::copy_bidirectional(&mut stream, &mut relay).await {
                Ok(_) => {}
                Err(err) => {
                    let _ = stream.shutdown().await;
                    let _ = relay.get_mut().reset(ERROR_CODE);
                    log::warn!(
                        "[http] [{peer_addr}] [connect] [{tuic_addr}] TCP stream relaying error: {err}"
                    );
                }
            }
        }
        Err(err) => {
            log::warn!("[http] [{peer_addr}] [connect] [{tuic_addr}] unable to relay: {err}");
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    }
}

/// Handle a plain HTTP proxy request (GET, POST, etc.).
///
/// Extracts the target host from the absolute URL, opens a relay connection,
/// forwards the (sanitised) request, then copies bidirectionally so that the
/// response and any keep-alive follow-up requests are streamed correctly.
pub async fn handle_request(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    method: &str,
    url: &str,
    version: &str,
    headers: &[(&str, &str)],
) {
    let (host, port, path) = match parse_http_url(url) {
        Some(hp) => hp,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    };

    let tuic_addr = TuicAddress::DomainAddress(host, port);

    let relay = match TuicConnection::get().await {
        Ok(conn) => conn.connect(tuic_addr.clone()).await,
        Err(err) => Err(err),
    };

    match relay {
        Ok(relay) => {
            let mut relay = relay.compat();

            // Forward the request with origin-form URL (RFC 7230 §5.3.1).
            // Subsequent keep-alive requests from the client pass through
            // copy_bidirectional in absolute-form, which servers must accept
            // per RFC 7230 §5.3.2.
            let mut request_buf = format!("{method} {path} {version}\r\n");
            for (key, val) in headers {
                request_buf.push_str(key);
                request_buf.push_str(": ");
                request_buf.push_str(val);
                request_buf.push_str("\r\n");
            }
            request_buf.push_str("\r\n");

            if relay.write_all(request_buf.as_bytes()).await.is_err() {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            }

            match io::copy_bidirectional(&mut stream, &mut relay).await {
                Ok(_) => {}
                Err(err) => {
                    let _ = stream.shutdown().await;
                    let _ = relay.get_mut().reset(ERROR_CODE);
                    log::warn!(
                        "[http] [{peer_addr}] [request] [{tuic_addr}] TCP stream relaying error: {err}"
                    );
                }
            }
        }
        Err(err) => {
            log::warn!("[http] [{peer_addr}] [request] [{tuic_addr}] unable to relay: {err}");
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    }
}

/// Parse `host:port` from a CONNECT target string.
fn parse_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port_str) = target.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

/// Parse an absolute HTTP URL into `(host, port, path)`.
///
/// ```text
/// http://example.com/path       -> ("example.com", 80,  "/path")
/// https://example.com:8443/path -> ("example.com", 8443, "/path")
/// http://example.com            -> ("example.com", 80,  "/")
/// ```
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let is_https = url.starts_with("https://");
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    let default_port: u16 = if is_https { 443 } else { 80 };

    let (authority, path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], without_scheme[idx..].to_string()),
        None => (without_scheme, "/".to_string()),
    };

    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p.parse().ok()?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default_port)
    };

    Some((host, port, path))
}
