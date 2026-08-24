use super::{udp_session::UdpSession, Server, UDP_SESSIONS};
use crate::connection::{Connection as TuicConnection, ERROR_CODE};
use socks5_proto::{Address, Reply, Response};
use std::net::SocketAddr;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tuic::Address as TuicAddress;

impl Server {
    pub async fn handle_associate(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        assoc_id: u16,
        dual_stack: Option<bool>,
        max_pkt_size: usize,
    ) {
        let local_ip = stream.local_addr().unwrap().ip();

        match UdpSession::new(assoc_id, peer_addr, local_ip, dual_stack, max_pkt_size) {
            Ok(session) => {
                let local_addr = session.local_addr().unwrap();
                log::debug!(
                    "[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] bound to {local_addr}"
                );

                let resp =
                    Response::new(Reply::Succeeded, Address::SocketAddress(local_addr));
                if resp.write_to(&mut stream).await.is_err() {
                    return;
                }

                UDP_SESSIONS
                    .get()
                    .unwrap()
                    .lock()
                    .insert(assoc_id, session.clone());

                let handle_local_incoming_pkt = async move {
                    loop {
                        let (pkt, target_addr) = match session.recv().await {
                            Ok(res) => res,
                            Err(err) => {
                                log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed to receive UDP packet: {err}");
                                continue;
                            }
                        };

                        let forward = async move {
                            let target_addr = match target_addr {
                                Address::DomainAddress(domain, port) => {
                                    TuicAddress::DomainAddress(
                                        String::from_utf8_lossy(&domain).into_owned(),
                                        port,
                                    )
                                }
                                Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
                            };

                            match TuicConnection::get().await {
                                Ok(conn) => conn.packet(pkt, target_addr, assoc_id).await,
                                Err(err) => Err(err),
                            }
                        };

                        tokio::spawn(async move {
                            match forward.await {
                                Ok(()) => {}
                                Err(err) => {
                                    log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed relaying UDP packet: {err}");
                                }
                            }
                        });
                    }
                };

                // Wait for the TCP control connection to close
                let wait_close = async {
                    loop {
                        match stream.read(&mut [0]).await {
                            Ok(0) => break Ok(()),
                            Ok(_) => {}
                            Err(err) => break Err(err),
                        }
                    }
                };

                match tokio::select! {
                    res = wait_close => res,
                    _ = handle_local_incoming_pkt => unreachable!(),
                } {
                    Ok(()) => {}
                    Err(err) => {
                        log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] associate connection error: {err}")
                    }
                }

                log::debug!(
                    "[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] stopped associating"
                );

                UDP_SESSIONS
                    .get()
                    .unwrap()
                    .lock()
                    .remove(&assoc_id)
                    .unwrap();

                let res = match TuicConnection::get().await {
                    Ok(conn) => conn.dissociate(assoc_id).await,
                    Err(err) => Err(err),
                };

                match res {
                    Ok(()) => {}
                    Err(err) => log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed stopping UDP relaying session: {err}"),
                }
            }
            Err(err) => {
                log::warn!("[socks5] [{peer_addr}] [associate] [{assoc_id:#06x}] failed setting up UDP associate session: {err}");

                let resp = Response::new(Reply::GeneralFailure, Address::unspecified());
                let _ = resp.write_to(&mut stream).await;
            }
        }
    }

    pub async fn handle_bind(mut stream: TcpStream, peer_addr: SocketAddr) {
        log::warn!("[socks5] [{peer_addr}] [bind] command not supported");

        let resp = Response::new(Reply::CommandNotSupported, Address::unspecified());
        let _ = resp.write_to(&mut stream).await;
    }

    pub async fn handle_connect(mut stream: TcpStream, peer_addr: SocketAddr, addr: Address) {
        let target_addr = match addr {
            Address::DomainAddress(domain, port) => TuicAddress::DomainAddress(
                String::from_utf8_lossy(&domain).into_owned(),
                port,
            ),
            Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
        };

        let relay = match TuicConnection::get().await {
            Ok(conn) => conn.connect(target_addr.clone()).await,
            Err(err) => Err(err),
        };

        match relay {
            Ok(relay) => {
                let mut relay = relay.compat();

                let resp = Response::new(Reply::Succeeded, Address::unspecified());
                match resp.write_to(&mut stream).await {
                    Ok(()) => match io::copy_bidirectional(&mut stream, &mut relay).await {
                        Ok(_) => {}
                        Err(err) => {
                            let _ = stream.shutdown().await;
                            let _ = relay.get_mut().reset(ERROR_CODE);
                            log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] TCP stream relaying error: {err}");
                        }
                    },
                    Err(err) => {
                        let _ = relay.shutdown().await;
                        log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] command reply error: {err}");
                    }
                }
            }
            Err(err) => {
                log::warn!("[socks5] [{peer_addr}] [connect] [{target_addr}] unable to relay TCP stream: {err}");

                let resp = Response::new(Reply::GeneralFailure, Address::unspecified());
                let _ = resp.write_to(&mut stream).await;
            }
        }
    }
}
