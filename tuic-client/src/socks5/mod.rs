use crate::{config::Local, error::Error};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::{
    handshake::{
        password::{Request as PasswordRequest, Response as PasswordResponse},
        Method, Request as HandshakeRequest, Response as HandshakeResponse,
    },
    Command, Request,
};
use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::atomic::{AtomicU16, Ordering},
};
use tokio::net::{TcpListener, TcpStream};

mod handle_task;
mod udp_session;

pub use self::udp_session::UDP_SESSIONS;

static SERVER: OnceCell<Server> = OnceCell::new();

pub struct Server {
    listener: TcpListener,
    dual_stack: Option<bool>,
    max_pkt_size: usize,
    next_assoc_id: AtomicU16,
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
    enable_http: bool,
}

impl Server {
    pub fn set_config(cfg: Local) -> Result<(), Error> {
        SERVER
            .set(Self::new(
                cfg.server,
                cfg.dual_stack,
                cfg.max_packet_size,
                cfg.username,
                cfg.password,
                cfg.enable_http,
            )?)
            .map_err(|_| "failed initializing proxy server")
            .unwrap();

        UDP_SESSIONS
            .set(Mutex::new(HashMap::new()))
            .map_err(|_| "failed initializing socks5 UDP session pool")
            .unwrap();

        Ok(())
    }

    fn new(
        addr: SocketAddr,
        dual_stack: Option<bool>,
        max_pkt_size: usize,
        username: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
        enable_http: bool,
    ) -> Result<Self, Error> {
        let socket = {
            let domain = match addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|err| Error::Socket("failed to create proxy server socket", err))?;

            if let Some(dual_stack) = dual_stack {
                socket.set_only_v6(!dual_stack).map_err(|err| {
                    Error::Socket("proxy server dual-stack socket setting error", err)
                })?;
            }

            socket.set_reuse_address(true).map_err(|err| {
                Error::Socket("failed to set proxy server socket to reuse_address", err)
            })?;

            socket.set_nonblocking(true).map_err(|err| {
                Error::Socket("failed setting proxy server socket as non-blocking", err)
            })?;

            socket
                .bind(&SockAddr::from(addr))
                .map_err(|err| Error::Socket("failed to bind proxy server socket", err))?;

            socket
                .listen(i32::MAX)
                .map_err(|err| Error::Socket("failed to listen on proxy server socket", err))?;

            TcpListener::from_std(StdTcpListener::from(socket))
                .map_err(|err| Error::Socket("failed to create proxy server socket", err))?
        };

        match (&username, &password) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => return Err(Error::InvalidSocks5Auth),
        }

        Ok(Self {
            listener: socket,
            dual_stack,
            max_pkt_size,
            next_assoc_id: AtomicU16::new(0),
            username,
            password,
            enable_http,
        })
    }

    pub async fn start() {
        let server = SERVER.get().unwrap();

        if server.enable_http {
            log::warn!(
                "[proxy] server started (SOCKS5+HTTP), listening on {}",
                server.listener.local_addr().unwrap()
            );
        } else {
            log::warn!(
                "[socks5] server started, listening on {}",
                server.listener.local_addr().unwrap()
            );
        }

        loop {
            match server.listener.accept().await {
                Ok((stream, addr)) => {
                    log::debug!("[proxy] [{addr}] connection established");

                    tokio::spawn(async move {
                        server.dispatch_connection(stream, addr).await;
                    });
                }
                Err(err) => log::warn!("[proxy] failed to accept connection: {err}"),
            }
        }
    }

    async fn dispatch_connection(&self, stream: TcpStream, addr: SocketAddr) {
        if self.enable_http {
            let mut first_byte = [0u8; 1];
            match stream.peek(&mut first_byte).await {
                Ok(1) => {
                    if first_byte[0] == 0x05 {
                        self.handle_socks5(stream, addr).await;
                    } else {
                        crate::http::handle_connection(
                            stream,
                            addr,
                            self.username.as_deref(),
                            self.password.as_deref(),
                        )
                        .await;
                    }
                }
                Ok(_) => {
                    log::warn!("[proxy] [{addr}] failed to peek connection: no data");
                }
                Err(err) => {
                    log::warn!("[proxy] [{addr}] failed to peek connection: {err}");
                }
            }
        } else {
            self.handle_socks5(stream, addr).await;
        }
    }

    async fn handle_socks5(&self, mut stream: TcpStream, addr: SocketAddr) {
        log::debug!("[socks5] [{addr}] connection established");

        // Read the SOCKS5 handshake request (method negotiation)
        let req = match HandshakeRequest::read_from(&mut stream).await {
            Ok(req) => req,
            Err(err) => {
                log::warn!("[socks5] [{addr}] handshake error: {err}");
                return;
            }
        };

        // Negotiate authentication method
        let auth_ok = match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                let method = Method::PASSWORD;
                if !req.methods.contains(&method) {
                    let resp = HandshakeResponse::new(Method::UNACCEPTABLE);
                    let _ = resp.write_to(&mut stream).await;
                    log::warn!("[socks5] [{addr}] no acceptable authentication method");
                    return;
                }

                let resp = HandshakeResponse::new(method);
                if resp.write_to(&mut stream).await.is_err() {
                    return;
                }

                let auth_req = match PasswordRequest::read_from(&mut stream).await {
                    Ok(r) => r,
                    Err(err) => {
                        log::warn!("[socks5] [{addr}] auth request error: {err}");
                        return;
                    }
                };

                let ok = auth_req.username.as_slice() == username.as_slice()
                    && auth_req.password.as_slice() == password.as_slice();

                let auth_resp = PasswordResponse::new(ok);
                if auth_resp.write_to(&mut stream).await.is_err() {
                    return;
                }

                ok
            }
            (None, None) => {
                let method = Method::NONE;
                if !req.methods.contains(&method) {
                    let resp = HandshakeResponse::new(Method::UNACCEPTABLE);
                    let _ = resp.write_to(&mut stream).await;
                    return;
                }

                let resp = HandshakeResponse::new(method);
                if resp.write_to(&mut stream).await.is_err() {
                    return;
                }

                true
            }
            _ => unreachable!(), // validated in `new()`
        };

        if !auth_ok {
            log::warn!("[socks5] [{addr}] authentication failed");
            return;
        }

        // Read the command request
        let req = match Request::read_from(&mut stream).await {
            Ok(req) => req,
            Err(err) => {
                log::warn!("[socks5] [{addr}] command error: {err}");
                return;
            }
        };

        match req.command {
            Command::Associate => {
                let assoc_id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
                log::info!("[socks5] [{addr}] [associate] [{assoc_id:#06x}]");
                Self::handle_associate(stream, addr, assoc_id, self.dual_stack, self.max_pkt_size)
                    .await;
            }
            Command::Bind => {
                log::info!("[socks5] [{addr}] [bind]");
                Self::handle_bind(stream, addr).await;
            }
            Command::Connect => {
                log::info!("[socks5] [{addr}] [connect] {}", req.address);
                Self::handle_connect(stream, addr, req.address).await;
            }
        }

        log::debug!("[socks5] [{addr}] connection closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socks5_proto::handshake::{
        password::Response as PasswordResponse, Response as HandshakeResponse,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    fn test_server(
        username: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
        enable_http: bool,
    ) -> Result<Server, Error> {
        Server::new(
            "127.0.0.1:0".parse().unwrap(),
            None,
            1500,
            username,
            password,
            enable_http,
        )
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        (accepted.unwrap().0, connected.unwrap())
    }

    #[tokio::test]
    async fn new_binds_ephemeral_ipv4_and_validates_auth_pairs() {
        let server = test_server(None, None, false).unwrap();
        let addr = server.listener.local_addr().unwrap();
        assert!(addr.is_ipv4());
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);

        assert!(test_server(Some(b"user".to_vec()), Some(b"pass".to_vec()), false).is_ok());
        assert!(matches!(
            test_server(Some(b"user".to_vec()), None, false),
            Err(Error::InvalidSocks5Auth)
        ));
        assert!(matches!(
            test_server(None, Some(b"pass".to_vec()), false),
            Err(Error::InvalidSocks5Auth)
        ));
    }

    #[tokio::test]
    async fn negotiates_no_auth_over_loopback() {
        let server = test_server(None, None, false).unwrap();
        let (server_stream, mut client_stream) = tcp_pair().await;
        let peer_addr = server_stream.peer_addr().unwrap();

        timeout(Duration::from_secs(2), async {
            let server_side = server.handle_socks5(server_stream, peer_addr);
            let client_side = async {
                client_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let response = HandshakeResponse::read_from(&mut client_stream)
                    .await
                    .unwrap();
                assert_eq!(response.method, Method::NONE);
                client_stream.shutdown().await.unwrap();
            };
            tokio::join!(server_side, client_side);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn password_negotiation_accepts_and_rejects_credentials() {
        for (password, expected) in [(b"pass".as_slice(), true), (b"wrong".as_slice(), false)] {
            let server =
                test_server(Some(b"user".to_vec()), Some(b"pass".to_vec()), false).unwrap();
            let (server_stream, mut client_stream) = tcp_pair().await;
            let peer_addr = server_stream.peer_addr().unwrap();

            timeout(Duration::from_secs(2), async {
                let server_side = server.handle_socks5(server_stream, peer_addr);
                let client_side = async {
                    client_stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                    let response = HandshakeResponse::read_from(&mut client_stream)
                        .await
                        .unwrap();
                    assert_eq!(response.method, Method::PASSWORD);

                    let mut request = vec![0x01, 0x04];
                    request.extend_from_slice(b"user");
                    request.push(password.len() as u8);
                    request.extend_from_slice(password);
                    client_stream.write_all(&request).await.unwrap();
                    let response = PasswordResponse::read_from(&mut client_stream)
                        .await
                        .unwrap();
                    assert_eq!(response.status, expected);
                    client_stream.shutdown().await.unwrap();
                };
                tokio::join!(server_side, client_side);
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn dispatches_socks_and_http_by_first_byte() {
        let server = test_server(None, None, true).unwrap();

        let (server_stream, mut client_stream) = tcp_pair().await;
        let peer_addr = server_stream.peer_addr().unwrap();
        timeout(Duration::from_secs(2), async {
            let server_side = server.dispatch_connection(server_stream, peer_addr);
            let client_side = async {
                client_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let response = HandshakeResponse::read_from(&mut client_stream)
                    .await
                    .unwrap();
                assert_eq!(response.method, Method::NONE);
                client_stream.shutdown().await.unwrap();
            };
            tokio::join!(server_side, client_side);
        })
        .await
        .unwrap();

        let (server_stream, mut client_stream) = tcp_pair().await;
        let peer_addr = server_stream.peer_addr().unwrap();
        timeout(Duration::from_secs(2), async {
            let server_side = server.dispatch_connection(server_stream, peer_addr);
            let client_side = async {
                client_stream
                    .write_all(b"GET relative HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    .await
                    .unwrap();
                let mut response = Vec::new();
                client_stream.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
            };
            tokio::join!(server_side, client_side);
        })
        .await
        .unwrap();
    }
}
