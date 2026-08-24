use crate::error::Error;
use bytes::Bytes;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::{Address, UdpHeader};
use socks5_server::AssociatedUdpSocket;
use std::{
    collections::HashMap,
    io::Error as IoError,
    net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
};
use tokio::net::UdpSocket;

pub static UDP_SESSIONS: OnceCell<Mutex<HashMap<u16, UdpSession>>> = OnceCell::new();

#[derive(Clone)]
pub struct UdpSession {
    socket: Arc<AssociatedUdpSocket>,
    assoc_id: u16,
    ctrl_addr: SocketAddr,
}

impl UdpSession {
    pub fn new(
        assoc_id: u16,
        ctrl_addr: SocketAddr,
        local_ip: IpAddr,
        dual_stack: Option<bool>,
        max_pkt_size: usize,
    ) -> Result<Self, Error> {
        let domain = match local_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
            Error::Socket("failed to create socks5 server UDP associate socket", err)
        })?;

        if let Some(dual_stack) = dual_stack {
            socket.set_only_v6(!dual_stack).map_err(|err| {
                Error::Socket(
                    "socks5 server UDP associate dual-stack socket setting error",
                    err,
                )
            })?;
        }

        socket.set_nonblocking(true).map_err(|err| {
            Error::Socket(
                "failed setting socks5 server UDP associate socket as non-blocking",
                err,
            )
        })?;

        socket
            .bind(&SockAddr::from(SocketAddr::from((local_ip, 0))))
            .map_err(|err| {
                Error::Socket("failed to bind socks5 server UDP associate socket", err)
            })?;

        let socket = UdpSocket::from_std(StdUdpSocket::from(socket)).map_err(|err| {
            Error::Socket("failed to create socks5 server UDP associate socket", err)
        })?;

        Ok(Self {
            socket: Arc::new(AssociatedUdpSocket::new(socket, max_pkt_size)),
            assoc_id,
            ctrl_addr,
        })
    }

    pub async fn send(&self, pkt: Bytes, src_addr: Address) -> Result<(), Error> {
        let src_addr_display = src_addr.to_string();
        let dst_addr = self.socket.get_ref().peer_addr().unwrap_or(self.ctrl_addr);

        log::debug!(
            "[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr}",
            ctrl_addr = self.ctrl_addr,
            assoc_id = self.assoc_id,
        );

        let header = UdpHeader::new(0, src_addr);
        if let Err(err) = self.socket.send_to(pkt, &header, dst_addr).await {
            log::warn!(
                "[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr} error: {err}",
                ctrl_addr = self.ctrl_addr,
                assoc_id = self.assoc_id,
            );

            return Err(Error::Io(err));
        }

        Ok(())
    }

    pub async fn recv(&self) -> Result<(Bytes, Address), Error> {
        let (pkt, header, src_addr) = self
            .socket
            .recv_from()
            .await
            .map_err(|(e, _)| Error::Io(IoError::other(e.to_string())))?;

        if let Ok(connected_addr) = self.socket.get_ref().peer_addr() {
            let connected_addr = normalize_connected_addr(connected_addr, src_addr);
            if src_addr != connected_addr {
                return Err(Error::Io(IoError::other(format!(
                    "invalid source address: {src_addr}"
                ))));
            }
        } else {
            self.socket.get_ref().connect(src_addr).await?;
        }

        if header.frag != 0 {
            return Err(Error::Io(IoError::other(
                "fragmented packet is not supported",
            )));
        }

        log::debug!(
            "[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] receive packet from {src_addr} to {dst_addr}",
            ctrl_addr = self.ctrl_addr,
            assoc_id = self.assoc_id,
            dst_addr = header.address,
        );

        Ok((pkt, header.address))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
        self.socket.get_ref().local_addr()
    }
}

fn normalize_connected_addr(connected_addr: SocketAddr, source_addr: SocketAddr) -> SocketAddr {
    match connected_addr {
        SocketAddr::V4(addr) if source_addr.is_ipv6() => {
            SocketAddr::new(addr.ip().to_ipv6_mapped().into(), addr.port())
        }
        SocketAddr::V6(addr) if source_addr.is_ipv4() => {
            addr.ip().to_ipv4_mapped().map_or(connected_addr, |ip| {
                SocketAddr::new(IpAddr::V4(ip), addr.port())
            })
        }
        _ => connected_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::io::Cursor;
    use tokio::time::{timeout, Duration};

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    fn frame(frag: u8, address: Address, payload: &[u8]) -> Vec<u8> {
        let header = UdpHeader::new(frag, address);
        let mut frame = BytesMut::with_capacity(header.serialized_len() + payload.len());
        header.write_to_buf(&mut frame);
        frame.put_slice(payload);
        frame.to_vec()
    }

    async fn socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    fn session(ctrl_addr: SocketAddr, max_pkt_size: usize) -> UdpSession {
        UdpSession::new(
            7,
            ctrl_addr,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            None,
            max_pkt_size,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn receives_pins_and_sends_framed_packets_on_loopback() {
        let client = socket().await;
        let client_addr = client.local_addr().unwrap();
        let session = session(client_addr, 1500);
        let session_addr = session.local_addr().unwrap();
        assert!(session_addr.ip().is_loopback());
        assert_ne!(session_addr.port(), 0);

        let target = Address::DomainAddress(b"target.example".to_vec(), 53);
        client
            .send_to(&frame(0, target.clone(), b"request"), session_addr)
            .await
            .unwrap();
        let (payload, received_target) = timeout(TEST_TIMEOUT, session.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"request".as_slice());
        assert_eq!(received_target, target);
        assert_eq!(session.socket.get_ref().peer_addr().unwrap(), client_addr);

        let source = Address::SocketAddress("192.0.2.10:5353".parse().unwrap());
        session
            .send(Bytes::from_static(b"response"), source.clone())
            .await
            .unwrap();
        let mut raw = [0u8; 1500];
        let (len, from) = timeout(TEST_TIMEOUT, client.recv_from(&mut raw))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, session_addr);
        let mut cursor = Cursor::new(&raw[..len]);
        let header = UdpHeader::read_from(&mut cursor).await.unwrap();
        assert_eq!(header.address, source);
        assert_eq!(&raw[header.serialized_len()..len], b"response");
    }

    #[tokio::test]
    async fn rejects_fragmented_and_malformed_frames() {
        let client = socket().await;
        let target = Address::SocketAddress("127.0.0.1:53".parse().unwrap());

        let fragmented = session(client.local_addr().unwrap(), 1500);
        client
            .send_to(
                &frame(1, target, b"fragment"),
                fragmented.local_addr().unwrap(),
            )
            .await
            .unwrap();
        let error = timeout(TEST_TIMEOUT, fragmented.recv())
            .await
            .unwrap()
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("fragmented packet is not supported"));

        for malformed in [b"".as_slice(), &[0, 0, 0], &[0, 0, 0, 1, 127]] {
            let malformed_session = session(client.local_addr().unwrap(), 1500);
            client
                .send_to(malformed, malformed_session.local_addr().unwrap())
                .await
                .unwrap();
            assert!(timeout(TEST_TIMEOUT, malformed_session.recv())
                .await
                .unwrap()
                .is_err());
        }
    }

    #[tokio::test]
    async fn never_accepts_packets_from_foreign_source_after_pinning() {
        let pinned_client = socket().await;
        let foreign_client = socket().await;
        let session = session(pinned_client.local_addr().unwrap(), 1500);
        let session_addr = session.local_addr().unwrap();
        let target = Address::DomainAddress(b"target.example".to_vec(), 53);

        pinned_client
            .send_to(&frame(0, target.clone(), b"pin"), session_addr)
            .await
            .unwrap();
        timeout(TEST_TIMEOUT, session.recv())
            .await
            .unwrap()
            .unwrap();

        foreign_client
            .send_to(&frame(0, target.clone(), b"foreign"), session_addr)
            .await
            .unwrap();
        pinned_client
            .send_to(&frame(0, target.clone(), b"valid"), session_addr)
            .await
            .unwrap();

        match timeout(TEST_TIMEOUT, session.recv()).await.unwrap() {
            Ok((payload, address)) => {
                assert_eq!(payload, b"valid".as_slice());
                assert_eq!(address, target);
            }
            Err(error) => {
                assert!(error.to_string().contains("invalid source address"));
                let (payload, address) = timeout(TEST_TIMEOUT, session.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, b"valid".as_slice());
                assert_eq!(address, target);
            }
        }
    }

    #[tokio::test]
    async fn receive_buffer_enforces_max_packet_size() {
        let client = socket().await;
        let target = Address::SocketAddress("127.0.0.1:53".parse().unwrap());
        let header_len = UdpHeader::new(0, target.clone()).serialized_len();
        let session = session(client.local_addr().unwrap(), header_len + 3);

        client
            .send_to(
                &frame(0, target.clone(), b"abcdefgh"),
                session.local_addr().unwrap(),
            )
            .await
            .unwrap();
        let result = timeout(TEST_TIMEOUT, session.recv()).await.unwrap();

        #[cfg(windows)]
        assert!(result.is_err());

        #[cfg(not(windows))]
        {
            let (payload, address) = result.unwrap();
            assert_eq!(address, target);
            assert_eq!(payload, b"abc".as_slice());
        }
    }

    #[test]
    fn normalizes_ipv4_mapped_addresses_for_source_checks() {
        let ipv4 = SocketAddr::from(([127, 0, 0, 1], 9000));
        let mapped = SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), 9000);
        assert_eq!(normalize_connected_addr(ipv4, mapped), mapped);
        assert_eq!(normalize_connected_addr(mapped, ipv4), ipv4);
    }
}
