use crate::{config::Local, error::Error};
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::handshake::{
    password::{Request as PasswordRequest, Response as PasswordResponse},
    Method,
};
use socks5_server::{auth::Auth, Command, Server as Socks5Server};
use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};
use tokio::net::{TcpListener, TcpStream};

mod handle_task;
mod udp_session;

pub use self::udp_session::UDP_SESSIONS;

static SERVER: OnceCell<Server> = OnceCell::new();

struct NoAuthAdapter;

#[async_trait]
impl Auth for NoAuthAdapter {
    type Output = bool;

    fn as_handshake_method(&self) -> Method {
        Method::NONE
    }

    async fn execute(&self, _stream: &mut TcpStream) -> bool {
        true
    }
}

struct PasswordAdapter {
    username: Vec<u8>,
    password: Vec<u8>,
}

#[async_trait]
impl Auth for PasswordAdapter {
    type Output = bool;

    fn as_handshake_method(&self) -> Method {
        Method::PASSWORD
    }

    async fn execute(&self, stream: &mut TcpStream) -> bool {
        let req = match PasswordRequest::read_from(stream).await {
            Ok(req) => req,
            Err(_) => return false,
        };
        let ok = req.username == self.username && req.password == self.password;
        let resp = PasswordResponse::new(ok);
        let _ = resp.write_to(stream).await;
        ok
    }
}

pub struct Server {
    inner: Socks5Server<bool>,
    dual_stack: Option<bool>,
    max_pkt_size: usize,
    next_assoc_id: AtomicU16,
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
            )?)
            .map_err(|_| "failed initializing socks5 server")
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
    ) -> Result<Self, Error> {
        let socket = {
            let domain = match addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|err| Error::Socket("failed to create socks5 server socket", err))?;

            if let Some(dual_stack) = dual_stack {
                socket.set_only_v6(!dual_stack).map_err(|err| {
                    Error::Socket("socks5 server dual-stack socket setting error", err)
                })?;
            }

            socket.set_reuse_address(true).map_err(|err| {
                Error::Socket("failed to set socks5 server socket to reuse_address", err)
            })?;

            socket.set_nonblocking(true).map_err(|err| {
                Error::Socket("failed setting socks5 server socket as non-blocking", err)
            })?;

            socket
                .bind(&SockAddr::from(addr))
                .map_err(|err| Error::Socket("failed to bind socks5 server socket", err))?;

            socket
                .listen(i32::MAX)
                .map_err(|err| Error::Socket("failed to listen on socks5 server socket", err))?;

            TcpListener::from_std(StdTcpListener::from(socket))
                .map_err(|err| Error::Socket("failed to create socks5 server socket", err))?
        };

        let auth: Arc<dyn Auth<Output = bool> + Send + Sync> = match (username, password) {
            (Some(username), Some(password)) => Arc::new(PasswordAdapter { username, password }),
            (None, None) => Arc::new(NoAuthAdapter),
            _ => return Err(Error::InvalidSocks5Auth),
        };

        Ok(Self {
            inner: Socks5Server::new(socket, auth),
            dual_stack,
            max_pkt_size,
            next_assoc_id: AtomicU16::new(0),
        })
    }

    pub async fn start() {
        let server = SERVER.get().unwrap();

        log::warn!(
            "[socks5] server started, listening on {}",
            server.inner.local_addr().unwrap()
        );

        loop {
            match server.inner.accept().await {
                Ok((conn, addr)) => {
                    log::debug!("[socks5] [{addr}] connection established");

                    tokio::spawn(async move {
                        let (conn, auth_ok) = match conn.authenticate().await {
                            Ok(result) => result,
                            Err((err, _)) => {
                                log::warn!("[socks5] [{addr}] handshake error: {err}");
                                return;
                            }
                        };

                        if !auth_ok {
                            log::warn!("[socks5] [{addr}] authentication failed");
                            return;
                        }

                        match conn.wait().await {
                            Ok(Command::Associate(associate, _)) => {
                                let assoc_id =
                                    server.next_assoc_id.fetch_add(1, Ordering::Relaxed);
                                log::info!("[socks5] [{addr}] [associate] [{assoc_id:#06x}]");
                                Self::handle_associate(
                                    associate,
                                    assoc_id,
                                    server.dual_stack,
                                    server.max_pkt_size,
                                )
                                .await;
                            }
                            Ok(Command::Bind(bind, _)) => {
                                log::info!("[socks5] [{addr}] [bind]");
                                Self::handle_bind(bind).await;
                            }
                            Ok(Command::Connect(connect, target_addr)) => {
                                log::info!("[socks5] [{addr}] [connect] {target_addr}");
                                Self::handle_connect(connect, target_addr).await;
                            }
                            Err((err, _)) => {
                                log::warn!("[socks5] [{addr}] command error: {err}")
                            }
                        }

                        log::debug!("[socks5] [{addr}] connection closed");
                    });
                }
                Err(err) => log::warn!("[socks5] failed to establish connection: {err}"),
            }
        }
    }
}
