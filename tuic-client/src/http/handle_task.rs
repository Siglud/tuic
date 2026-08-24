use crate::connection::{Connection as TuicConnection, ERROR_CODE};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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

    let tuic_addr = to_tuic_address(host, port);

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

    let tuic_addr = to_tuic_address(host, port);

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
            let request_buf = format_request(method, &path, version, headers);

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
    parse_authority(target, None)
}

/// Parse an absolute HTTP URL into `(host, port, path)`.
///
/// ```text
/// http://example.com/path       -> ("example.com", 80,  "/path")
/// https://example.com:8443/path -> ("example.com", 8443, "/path")
/// http://example.com            -> ("example.com", 80,  "/")
/// ```
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        80
    } else if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        return None;
    };
    let remainder = &url[scheme_end + 3..];
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let (host, port) = parse_authority(authority, Some(default_port))?;

    let path_and_query = remainder[authority_end..]
        .split_once('#')
        .map_or(&remainder[authority_end..], |(before, _)| before);
    let path = if path_and_query.is_empty() {
        "/".to_string()
    } else if path_and_query.starts_with('?') {
        format!("/{path_and_query}")
    } else if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        "/".to_string()
    };

    Some((host, port, path))
}

fn parse_authority(authority: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    if authority.is_empty() || authority.contains('@') || authority.trim() != authority {
        return None;
    }

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed.find(']')?;
        let host = &bracketed[..closing];
        host.parse::<Ipv6Addr>().ok()?;
        let remainder = &bracketed[closing + 1..];
        let port = if remainder.is_empty() {
            default_port?
        } else {
            parse_explicit_port(remainder.strip_prefix(':')?)?
        };
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host, parse_explicit_port(port)?)
    } else {
        (authority, default_port?)
    };

    if host.is_empty() {
        return None;
    }

    Some((host.to_string(), port))
}

fn parse_explicit_port(value: &str) -> Option<u16> {
    value.parse::<u16>().ok().filter(|port| *port != 0)
}

fn to_tuic_address(host: String, port: u16) -> TuicAddress {
    match host.parse::<IpAddr>() {
        Ok(ip) => TuicAddress::SocketAddress(SocketAddr::new(ip, port)),
        Err(_) => TuicAddress::DomainAddress(host, port),
    }
}

fn format_request(method: &str, path: &str, version: &str, headers: &[(&str, &str)]) -> String {
    let mut request = format!("{method} {path} {version}\r\n");
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let key = if key.eq_ignore_ascii_case("proxy-connection") {
            "Connection"
        } else {
            key
        };
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_authority_requires_valid_explicit_port() {
        assert_eq!(
            parse_host_port("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_host_port("[::1]:8443"),
            Some(("::1".to_string(), 8443))
        );

        for invalid in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            ":443",
            "::1:443",
            "[::1]",
            "[::1]:bad",
        ] {
            assert_eq!(parse_host_port(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn http_url_supports_defaults_paths_queries_and_ipv6() {
        let cases = [
            (
                "http://example.com",
                ("example.com".to_string(), 80, "/".to_string()),
            ),
            (
                "https://example.com:8443/path?q=1",
                ("example.com".to_string(), 8443, "/path?q=1".to_string()),
            ),
            (
                "HTTP://example.com?query=yes",
                ("example.com".to_string(), 80, "/?query=yes".to_string()),
            ),
            (
                "hTtPs://[::1]/resource",
                ("::1".to_string(), 443, "/resource".to_string()),
            ),
            (
                "http://[2001:db8::1]:8080/path#ignored",
                ("2001:db8::1".to_string(), 8080, "/path".to_string()),
            ),
        ];

        for (url, expected) in cases {
            assert_eq!(parse_http_url(url), Some(expected), "failed {url}");
        }
    }

    #[test]
    fn http_url_rejects_bad_scheme_authority_and_ports() {
        for invalid in [
            "example.com/path",
            "ftp://example.com/path",
            "http://",
            "http:///path",
            "http://:80/path",
            "http://example.com:0/path",
            "http://example.com:bad/path",
            "http://example.com:65536/path",
            "http://::1/path",
            "http://[::1/path",
            "http://[example.com]/path",
            "http://user@example.com/path",
        ] {
            assert_eq!(parse_http_url(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn address_conversion_distinguishes_ips_and_domains() {
        assert!(matches!(
            to_tuic_address("example.com".to_string(), 80),
            TuicAddress::DomainAddress(domain, 80) if domain == "example.com"
        ));
        assert!(matches!(
            to_tuic_address("2001:db8::1".to_string(), 443),
            TuicAddress::SocketAddress(addr)
                if addr == "[2001:db8::1]:443".parse().unwrap()
        ));
    }

    #[test]
    fn request_formatting_uses_origin_form_and_sanitizes_proxy_headers() {
        let request = format_request(
            "GET",
            "/path?q=1",
            "HTTP/1.1",
            &[
                ("Host", "example.com"),
                ("Proxy-Authorization", "Basic secret"),
                ("pRoXy-CoNnEcTiOn", "keep-alive"),
                ("X-Test", "value"),
            ],
        );

        assert_eq!(
            request,
            "GET /path?q=1 HTTP/1.1\r\n\
             Host: example.com\r\n\
             Connection: keep-alive\r\n\
             X-Test: value\r\n\r\n"
        );
        assert!(!request.to_ascii_lowercase().contains("proxy-"));
    }
}
