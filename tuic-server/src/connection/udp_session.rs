use super::Connection;
use crate::error::Error;
use bytes::Bytes;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io::Error as IoError,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
};
use tokio::{
    net::UdpSocket,
    sync::oneshot::{self, Sender},
};
use tuic::Address;

#[derive(Clone)]
pub struct UdpSession(Arc<UdpSessionInner>);

struct UdpSessionInner {
    assoc_id: u16,
    conn: Connection,
    sockets: UdpSockets,
    close: Mutex<Option<Sender<()>>>,
}

struct UdpSockets {
    socket_v4: UdpSocket,
    socket_v6: Option<UdpSocket>,
    max_pkt_size: usize,
}

impl UdpSockets {
    fn new(udp_relay_ipv6: bool, max_pkt_size: usize) -> Result<Self, Error> {
        let socket_v4 = {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|err| Error::Socket("failed to create UDP associate IPv4 socket", err))?;

            socket.set_nonblocking(true).map_err(|err| {
                Error::Socket(
                    "failed setting UDP associate IPv4 socket as non-blocking",
                    err,
                )
            })?;

            socket
                .bind(&SockAddr::from(SocketAddr::from((
                    Ipv4Addr::UNSPECIFIED,
                    0,
                ))))
                .map_err(|err| Error::Socket("failed to bind UDP associate IPv4 socket", err))?;

            UdpSocket::from_std(StdUdpSocket::from(socket))?
        };

        let socket_v6 = if udp_relay_ipv6 {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|err| Error::Socket("failed to create UDP associate IPv6 socket", err))?;

            socket.set_nonblocking(true).map_err(|err| {
                Error::Socket(
                    "failed setting UDP associate IPv6 socket as non-blocking",
                    err,
                )
            })?;

            socket.set_only_v6(true).map_err(|err| {
                Error::Socket("failed setting UDP associate IPv6 socket as IPv6-only", err)
            })?;

            socket
                .bind(&SockAddr::from(SocketAddr::from((
                    Ipv6Addr::UNSPECIFIED,
                    0,
                ))))
                .map_err(|err| Error::Socket("failed to bind UDP associate IPv6 socket", err))?;

            Some(UdpSocket::from_std(StdUdpSocket::from(socket))?)
        } else {
            None
        };

        Ok(Self {
            socket_v4,
            socket_v6,
            max_pkt_size,
        })
    }

    async fn send(&self, pkt: Bytes, addr: SocketAddr) -> Result<(), Error> {
        let socket = match addr {
            SocketAddr::V4(_) => &self.socket_v4,
            SocketAddr::V6(_) => self
                .socket_v6
                .as_ref()
                .ok_or_else(|| Error::UdpRelayIpv6Disabled(addr))?,
        };

        socket.send_to(&pkt, addr).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<(Bytes, SocketAddr), IoError> {
        async fn recv(
            socket: &UdpSocket,
            max_pkt_size: usize,
        ) -> Result<(Bytes, SocketAddr), IoError> {
            #[cfg(windows)]
            let receive_size = max_pkt_size.max(u16::MAX as usize);
            #[cfg(not(windows))]
            let receive_size = max_pkt_size;

            let mut buf = vec![0u8; receive_size];
            let (n, addr) = socket.recv_from(&mut buf).await?;
            buf.truncate(n.min(max_pkt_size));
            Ok((Bytes::from(buf), addr))
        }

        if let Some(socket_v6) = &self.socket_v6 {
            tokio::select! {
                res = recv(&self.socket_v4, self.max_pkt_size) => res,
                res = recv(socket_v6, self.max_pkt_size) => res,
            }
        } else {
            recv(&self.socket_v4, self.max_pkt_size).await
        }
    }
}

impl UdpSession {
    pub fn new(
        conn: Connection,
        assoc_id: u16,
        udp_relay_ipv6: bool,
        max_pkt_size: usize,
    ) -> Result<Self, Error> {
        let sockets = UdpSockets::new(udp_relay_ipv6, max_pkt_size)?;
        let (tx, rx) = oneshot::channel();

        let session = Self(Arc::new(UdpSessionInner {
            conn,
            assoc_id,
            sockets,
            close: Mutex::new(Some(tx)),
        }));

        let session_listening = session.clone();
        let listen = async move {
            loop {
                let (pkt, addr) = match session_listening.recv().await {
                    Ok(res) => res,
                    Err(err) => {
                        log::warn!(
                            "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] outbound listening error: {err}",
                            id = session_listening.0.conn.id(),
                            addr = session_listening.0.conn.inner.remote_address(),
                            user = session_listening.0.conn.auth,
                        );
                        continue;
                    }
                };

                tokio::spawn(session_listening.0.conn.clone().relay_packet(
                    pkt,
                    Address::SocketAddress(addr),
                    session_listening.0.assoc_id,
                ));
            }
        };

        tokio::spawn(async move {
            tokio::select! {
                _ = listen => unreachable!(),
                _ = rx => {},
            }
        });

        Ok(session)
    }

    pub async fn send(&self, pkt: Bytes, addr: SocketAddr) -> Result<(), Error> {
        self.0.sockets.send(pkt, addr).await
    }

    async fn recv(&self) -> Result<(Bytes, SocketAddr), IoError> {
        self.0.sockets.recv().await
    }

    pub fn close(&self) {
        signal_close(&self.0.close);
    }

    #[cfg(test)]
    pub(super) fn is_closed(&self) -> bool {
        self.0.close.lock().is_none()
    }
}

fn signal_close(close: &Mutex<Option<Sender<()>>>) {
    if let Some(sender) = close.lock().take() {
        let _ = sender.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::time::{timeout, Duration};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    async fn bounded<F: std::future::Future>(future: F) -> F::Output {
        timeout(TEST_TIMEOUT, future)
            .await
            .expect("loopback UDP operation timed out")
    }

    #[tokio::test]
    async fn sends_ipv4_datagram_to_loopback_socket() {
        let sockets = UdpSockets::new(false, 1500).unwrap();
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        bounded(sockets.send(Bytes::from_static(b"outbound packet"), receiver_addr))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let (length, source) = bounded(receiver.recv_from(&mut buffer)).await.unwrap();

        assert_eq!(&buffer[..length], b"outbound packet");
        assert_eq!(
            source.port(),
            sockets.socket_v4.local_addr().unwrap().port()
        );
    }

    #[tokio::test]
    async fn receives_and_truncates_ipv4_datagram_to_configured_size() {
        let sockets = UdpSockets::new(false, 4).unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            sockets.socket_v4.local_addr().unwrap().port(),
        ));

        bounded(sender.send_to(b"abcdefgh", target)).await.unwrap();
        let (packet, source) = bounded(sockets.recv()).await.unwrap();

        assert_eq!(packet.as_ref(), b"abcd");
        assert_eq!(source, sender.local_addr().unwrap());
    }

    #[tokio::test]
    async fn disabled_ipv6_relay_rejects_ipv6_destination() {
        let sockets = UdpSockets::new(false, 1500).unwrap();
        let address = SocketAddr::from((Ipv6Addr::LOCALHOST, 43123));

        assert!(matches!(
            sockets.send(Bytes::from_static(b"packet"), address).await,
            Err(Error::UdpRelayIpv6Disabled(rejected)) if rejected == address
        ));
    }

    #[tokio::test]
    async fn close_signal_is_idempotent_and_cancels_waiter() {
        let (sender, receiver) = oneshot::channel();
        let close = Mutex::new(Some(sender));

        signal_close(&close);
        signal_close(&close);

        bounded(receiver).await.unwrap();
        assert!(close.lock().is_none());
    }
}
