use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::net::SocketAddr;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

mod handle_task;

const MAX_REQUEST_HEAD_SIZE: usize = 16 * 1024;

async fn write_http_response<W>(stream: &mut W, response: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(response).await?;
    stream.flush().await
}

struct RequestHead<'a> {
    method: &'a str,
    url: &'a str,
    version: &'a str,
    proxy_authorization: Option<&'a str>,
    forwarded_headers: Vec<(&'a str, &'a str)>,
}

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    username: Option<&[u8]>,
    password: Option<&[u8]>,
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
    let header_buf = read_request_head(&mut stream).await?;
    let request = parse_request_head(&header_buf)?;

    if let (Some(required_user), Some(required_pass)) = (username, password) {
        if !valid_basic_auth(request.proxy_authorization, required_user, required_pass) {
            let _ = write_http_response(
                &mut stream,
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"tuic-client\"\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n",
            )
            .await;
            return Ok(());
        }
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        log::info!("[http] [{peer_addr}] [connect] {}", request.url);
        handle_task::handle_connect(stream, peer_addr, request.url).await;
    } else {
        log::info!(
            "[http] [{peer_addr}] [request] {} {}",
            request.method,
            request.url
        );
        handle_task::handle_request(
            stream,
            peer_addr,
            request.method,
            request.url,
            request.version,
            &request.forwarded_headers,
        )
        .await;
    }

    Ok(())
}

async fn read_request_head<R>(stream: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header_buf = Vec::with_capacity(4096);
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        header_buf.push(byte[0]);
        if header_buf.len() > MAX_REQUEST_HEAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request header too large",
            ));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            return Ok(header_buf);
        }
    }
}

fn parse_request_head(header_buf: &[u8]) -> Result<RequestHead<'_>, &'static str> {
    if header_buf.len() > MAX_REQUEST_HEAD_SIZE {
        return Err("HTTP request header too large");
    }

    let header_str = std::str::from_utf8(header_buf).map_err(|_| "invalid HTTP header encoding")?;
    let header_str = header_str
        .strip_suffix("\r\n\r\n")
        .ok_or("incomplete HTTP request header")?;
    let mut lines = header_str.split("\r\n");

    let request_line = lines.next().ok_or("empty HTTP request")?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().ok_or("missing HTTP method")?;
    let url = parts.next().ok_or("missing HTTP URL")?;
    let version = parts.next().ok_or("missing HTTP version")?;
    if parts.next().is_some() {
        return Err("malformed HTTP request line");
    }

    let mut proxy_authorization: Option<&str> = None;
    let mut forwarded_headers: Vec<(&str, &str)> = Vec::new();

    for line in lines {
        let (key, val) = line.split_once(':').ok_or("malformed HTTP header line")?;
        let key = key.trim();
        if key.is_empty() {
            return Err("empty HTTP header name");
        }
        let val = val.trim();
        if key.eq_ignore_ascii_case("proxy-authorization") {
            proxy_authorization = Some(val);
        } else if key.eq_ignore_ascii_case("proxy-connection") {
            forwarded_headers.push(("Connection", val));
        } else {
            forwarded_headers.push((key, val));
        }
    }

    Ok(RequestHead {
        method,
        url,
        version,
        proxy_authorization,
        forwarded_headers,
    })
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    STANDARD.decode(input).ok()
}

fn valid_basic_auth(header: Option<&str>, required_user: &[u8], required_pass: &[u8]) -> bool {
    let mut parts = match header {
        Some(header) => header.split_ascii_whitespace(),
        None => return false,
    };
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(encoded) = parts.next() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Basic") || parts.next().is_some() {
        return false;
    }

    decode_base64(encoded)
        .and_then(|decoded| {
            decoded
                .iter()
                .position(|&byte| byte == b':')
                .map(|colon| (decoded, colon))
        })
        .map(|(decoded, colon)| {
            decoded[..colon] == *required_user && decoded[colon + 1..] == *required_pass
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };
    use tokio::io::{duplex, AsyncWriteExt};

    #[derive(Default)]
    struct FlushState {
        buffered: Vec<u8>,
        flushed: Vec<u8>,
        flush_pending: bool,
        allow_flush: bool,
        dropped: bool,
        dropped_with_buffered_data: bool,
        flush_waker: Option<Waker>,
    }

    struct PendingFlushWriter {
        state: Arc<Mutex<FlushState>>,
    }

    impl AsyncWrite for PendingFlushWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.state.lock().unwrap().buffered.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            if !state.allow_flush {
                state.flush_pending = true;
                state.flush_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }

            let buffered = std::mem::take(&mut state.buffered);
            state.flushed.extend_from_slice(&buffered);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    impl Drop for PendingFlushWriter {
        fn drop(&mut self) {
            let mut state = self.state.lock().unwrap();
            state.dropped = true;
            state.dropped_with_buffered_data = !state.buffered.is_empty();
        }
    }

    #[tokio::test]
    async fn http_response_is_flushed_before_writer_can_close() {
        const RESPONSE: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

        let state = Arc::new(Mutex::new(FlushState::default()));
        let writer = PendingFlushWriter {
            state: Arc::clone(&state),
        };
        let write_task = tokio::spawn(async move {
            let mut writer = writer;
            write_http_response(&mut writer, RESPONSE).await
        });

        loop {
            if state.lock().unwrap().flush_pending {
                break;
            }
            assert!(
                !write_task.is_finished(),
                "response write completed without polling flush"
            );
            tokio::task::yield_now().await;
        }

        {
            let state = state.lock().unwrap();
            assert_eq!(state.buffered, RESPONSE);
            assert!(state.flushed.is_empty());
            assert!(!state.dropped);
        }

        let flush_waker = {
            let mut state = state.lock().unwrap();
            state.allow_flush = true;
            state.flush_waker.take().unwrap()
        };
        flush_waker.wake();

        write_task.await.unwrap().unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.flushed, RESPONSE);
        assert!(state.buffered.is_empty());
        assert!(state.dropped);
        assert!(!state.dropped_with_buffered_data);
    }

    #[tokio::test]
    async fn reads_fragmented_request_head() {
        let (mut reader, mut writer) = duplex(128);
        let write = async move {
            for fragment in [
                b"GET http://example.com/ HTTP/1.1\r\n".as_slice(),
                b"Host: example.com\r\nProxy-Connection: keep-alive\r\n",
                b"\r\nbody",
            ] {
                writer.write_all(fragment).await.unwrap();
            }
        };
        let read = read_request_head(&mut reader);
        let (_, header) = tokio::join!(write, read);

        assert_eq!(
            header.unwrap(),
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
    }

    #[test]
    fn parses_request_line_and_sanitizes_proxy_headers() {
        let request = parse_request_head(
            b"POST http://example.com/upload HTTP/1.1\r\n\
              Host : example.com \r\n\
              pRoXy-AuThOrIzAtIoN : Basic dXNlcjpwYXNz\r\n\
              PROXY-CONNECTION:  keep-alive  \r\n\
              X-Test: one:two\r\n\r\n",
        )
        .unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "http://example.com/upload");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(request.proxy_authorization, Some("Basic dXNlcjpwYXNz"));
        assert_eq!(
            request.forwarded_headers,
            [
                ("Host", "example.com"),
                ("Connection", "keep-alive"),
                ("X-Test", "one:two"),
            ]
        );
    }

    #[test]
    fn request_head_enforces_16_kib_limit() {
        let prefix = b"GET / HTTP/1.1\r\nX-Fill: ";
        let suffix = b"\r\n\r\n";
        let mut exact = Vec::from(prefix.as_slice());
        exact.resize(MAX_REQUEST_HEAD_SIZE - suffix.len(), b'a');
        exact.extend_from_slice(suffix);
        assert_eq!(exact.len(), MAX_REQUEST_HEAD_SIZE);
        assert!(parse_request_head(&exact).is_ok());

        exact.insert(exact.len() - suffix.len(), b'a');
        assert!(matches!(
            parse_request_head(&exact),
            Err("HTTP request header too large")
        ));
    }

    #[test]
    fn request_head_rejects_invalid_encoding_and_malformed_lines() {
        let cases = [
            b"GET / HTTP/1.1 extra\r\n\r\n".as_slice(),
            b"GET /\r\n\r\n",
            b"GET / HTTP/1.1\r\nMissing-Colon\r\n\r\n",
            b"GET / HTTP/1.1\r\n: value\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n",
            b"GET / HTTP/1.1\r\nX-Test: \xff\r\n\r\n",
        ];

        for case in cases {
            assert!(parse_request_head(case).is_err());
        }
    }

    #[test]
    fn strict_base64_rejects_padding_and_quartet_errors() {
        assert_eq!(decode_base64("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(decode_base64("Zg=="), Some(b"f".to_vec()));

        for invalid in ["Zg", "Zg=", "Zg===", "Zh==", "dXNlcjpwYXNz=", "AA=A"] {
            assert_eq!(decode_base64(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn basic_auth_checks_scheme_credentials_and_first_colon() {
        assert!(valid_basic_auth(
            Some("bAsIc dXNlcjpwOmE6c3M="),
            b"user",
            b"p:a:ss"
        ));
        assert!(valid_basic_auth(Some("Basic Og=="), b"", b""));
        assert!(!valid_basic_auth(
            Some("Basic dXM6ZXI6cGFzcw=="),
            b"us:er",
            b"pass"
        ));

        for header in [
            None,
            Some("Bearer dXNlcjpwYXNz"),
            Some("Basic"),
            Some("Basic !!!="),
            Some("Basic dXNlcnBhc3M="),
            Some("Basic dXNlcjpwYXNz extra"),
        ] {
            assert!(!valid_basic_auth(header, b"user", b"pass"));
        }
    }
}
