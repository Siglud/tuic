use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod handle_task;

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    username: Option<&'static [u8]>,
    password: Option<&'static [u8]>,
) {
    if let Err(err) = inner_handle(stream, peer_addr, username, password).await {
        log::warn!("[http] [{peer_addr}] connection error: {err}");
    }
}

async fn inner_handle(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    username: Option<&[u8]>,
    password: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read HTTP request headers byte-by-byte until we reach the blank line
    let mut header_buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        header_buf.push(byte[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 16384 {
            return Err("HTTP request header too large".into());
        }
    }

    let header_str = std::str::from_utf8(&header_buf)?;
    let mut lines = header_str.split("\r\n");

    // Parse the request line
    let request_line = lines.next().ok_or("empty HTTP request")?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().ok_or("missing HTTP method")?;
    let url = parts.next().ok_or("missing HTTP URL")?;
    let version = parts.next().ok_or("missing HTTP version")?;

    // Parse headers, collecting proxy-specific ones separately
    let mut proxy_authorization: Option<&str> = None;
    let mut forwarded_headers: Vec<(&str, &str)> = Vec::new();

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim();
            let val = line[colon_pos + 1..].trim();
            if key.eq_ignore_ascii_case("proxy-authorization") {
                proxy_authorization = Some(val);
            } else if key.eq_ignore_ascii_case("proxy-connection") {
                // Convert Proxy-Connection to Connection
                forwarded_headers.push(("Connection", val));
            } else {
                forwarded_headers.push((key, val));
            }
        }
    }

    // Verify proxy authentication when credentials are configured
    if let (Some(required_user), Some(required_pass)) = (username, password) {
        let auth_ok = proxy_authorization
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|b64| decode_base64(b64.trim()))
            .map(|decoded| {
                decoded
                    .iter()
                    .position(|&b| b == b':')
                    .map(|colon| {
                        &decoded[..colon] == required_user
                            && &decoded[colon + 1..] == required_pass
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if !auth_ok {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"tuic-client\"\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        log::info!("[http] [{peer_addr}] [connect] {url}");
        handle_task::handle_connect(stream, peer_addr, url).await;
    } else {
        log::info!("[http] [{peer_addr}] [request] {method} {url}");
        handle_task::handle_request(stream, peer_addr, method, url, version, &forwarded_headers)
            .await;
    }

    Ok(())
}

/// Decode a base64-encoded string into bytes.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for &byte in input.as_bytes() {
        let val = TABLE.iter().position(|&x| x == byte)? as u32;
        bits = (bits << 6) | val;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Some(result)
}
