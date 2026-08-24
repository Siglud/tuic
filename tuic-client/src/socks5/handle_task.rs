use super::{udp_session::UdpSession, Server, UDP_SESSIONS};
use crate::connection::{Connection as TuicConnection, ERROR_CODE};
use socks5_proto::{Address, Reply, Response};
use std::net::SocketAddr;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWriteExt},
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

                let resp = Response::new(Reply::Succeeded, Address::SocketAddress(local_addr));
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
                            let target_addr = to_tuic_address(target_addr);

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
                let wait_close = wait_for_eof(&mut stream);

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
        let target_addr = to_tuic_address(addr);

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

fn to_tuic_address(addr: Address) -> TuicAddress {
    match addr {
        Address::DomainAddress(domain, port) => {
            TuicAddress::DomainAddress(String::from_utf8_lossy(&domain).into_owned(), port)
        }
        Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
    }
}

async fn wait_for_eof<R>(stream: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await? {
            0 => return Ok(()),
            _ => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socks5_proto::Reply;
    use tokio::io::{duplex, AsyncWriteExt};

    #[test]
    fn converts_socks_addresses_to_tuic_addresses() {
        assert!(matches!(
            to_tuic_address(Address::DomainAddress(b"example.com".to_vec(), 443)),
            TuicAddress::DomainAddress(domain, 443) if domain == "example.com"
        ));

        let socket_addr = "127.0.0.1:8080".parse().unwrap();
        assert!(matches!(
            to_tuic_address(Address::SocketAddress(socket_addr)),
            TuicAddress::SocketAddress(addr) if addr == socket_addr
        ));
    }

    #[tokio::test]
    async fn bind_replies_command_not_supported() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        let (server_stream, peer_addr) = accepted.unwrap();
        let mut client_stream = connected.unwrap();

        let server_side = Server::handle_bind(server_stream, peer_addr);
        let client_side = async {
            let response = Response::read_from(&mut client_stream).await.unwrap();
            assert_eq!(response.reply, Reply::CommandNotSupported);
            assert_eq!(response.address, Address::unspecified());
        };
        tokio::join!(server_side, client_side);
    }

    #[tokio::test]
    async fn eof_waiter_stays_alive_until_peer_closes() {
        let (mut reader, mut writer) = duplex(8);
        let wait = wait_for_eof(&mut reader);
        tokio::pin!(wait);

        tokio::select! {
            biased;
            result = &mut wait => panic!("waiter completed before input: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        writer.write_all(b"x").await.unwrap();
        tokio::select! {
            biased;
            result = &mut wait => panic!("waiter treated data as EOF: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        writer.shutdown().await.unwrap();
        wait.await.unwrap();
    }
}
