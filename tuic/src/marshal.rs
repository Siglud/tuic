use crate::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet, VERSION};
use bytes::{BufMut, BytesMut};
#[cfg(feature = "async_marshal")]
use futures_util::{AsyncWrite, AsyncWriteExt};
#[cfg(feature = "marshal")]
use std::io::Write;
use std::{io::Error as IoError, net::SocketAddr};

impl Header {
    /// Marshals the header into an `AsyncWrite` stream
    #[cfg(feature = "async_marshal")]
    pub async fn async_marshal(&self, s: &mut (impl AsyncWrite + Unpin)) -> Result<(), IoError> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write(&mut buf);
        s.write_all(&buf).await
    }

    /// Marshals the header into a `Write` stream
    #[cfg(feature = "marshal")]
    pub fn marshal(&self, s: &mut impl Write) -> Result<(), IoError> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write(&mut buf);
        s.write_all(&buf)
    }

    /// Writes the header into a `BufMut`
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(VERSION);
        buf.put_u8(self.type_code());

        match self {
            Self::Authenticate(auth) => auth.write(buf),
            Self::Connect(conn) => conn.write(buf),
            Self::Packet(packet) => packet.write(buf),
            Self::Dissociate(dissociate) => dissociate.write(buf),
            Self::Heartbeat(heartbeat) => heartbeat.write(buf),
        }
    }
}

impl Address {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.type_code());

        match self {
            Self::None => {}
            Self::DomainAddress(domain, port) => {
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                for seg in addr.ip().segments() {
                    buf.put_u16(seg);
                }
                buf.put_u16(addr.port());
            }
        }
    }
}

impl Authenticate {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.uuid().as_ref());
        buf.put_slice(&self.token());
    }
}

impl Connect {
    fn write(&self, buf: &mut impl BufMut) {
        self.addr().write(buf);
    }
}

impl Packet {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.assoc_id());
        buf.put_u16(self.pkt_id());
        buf.put_u8(self.frag_total());
        buf.put_u8(self.frag_id());
        buf.put_u16(self.size());
        self.addr().write(buf);
    }
}

impl Dissociate {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.assoc_id());
    }
}

impl Heartbeat {
    fn write(&self, _buf: &mut impl BufMut) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use uuid::Uuid;

    const AUTHENTICATE_BYTES: [u8; 50] = [
        0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
        0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    ];
    const CONNECT_DOMAIN_BYTES: [u8; 17] = [
        0x05, 0x01, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        0x01, 0xbb,
    ];
    const CONNECT_IPV4_BYTES: [u8; 9] = [0x05, 0x01, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x01, 0xbb];
    const CONNECT_IPV6_BYTES: [u8; 21] = [
        0x05, 0x01, 0x02, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x01, 0xbb,
    ];
    const PACKET_FIRST_BYTES: [u8; 25] = [
        0x05, 0x02, 0x12, 0x34, 0x56, 0x78, 0x02, 0x00, 0x00, 0x03, 0x00, 0x0b, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb,
    ];
    const PACKET_CONTINUATION_BYTES: [u8; 11] = [
        0x05, 0x02, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0xff,
    ];
    const DISSOCIATE_BYTES: [u8; 4] = [0x05, 0x03, 0x12, 0x34];
    const HEARTBEAT_BYTES: [u8; 2] = [0x05, 0x04];

    fn fixtures() -> Vec<(Header, &'static [u8])> {
        vec![
            (
                Header::Authenticate(Authenticate::new(
                    Uuid::from_bytes([
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ]),
                    [
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                    ],
                )),
                &AUTHENTICATE_BYTES,
            ),
            (
                Header::Connect(Connect::new(Address::DomainAddress(
                    "example.com".into(),
                    443,
                ))),
                &CONNECT_DOMAIN_BYTES,
            ),
            (
                Header::Connect(Connect::new(Address::SocketAddress(
                    (Ipv4Addr::new(192, 0, 2, 1), 443).into(),
                ))),
                &CONNECT_IPV4_BYTES,
            ),
            (
                Header::Connect(Connect::new(Address::SocketAddress(
                    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443).into(),
                ))),
                &CONNECT_IPV6_BYTES,
            ),
            (
                Header::Packet(Packet::new(
                    0x1234,
                    0x5678,
                    2,
                    0,
                    3,
                    Address::DomainAddress("example.com".into(), 443),
                )),
                &PACKET_FIRST_BYTES,
            ),
            (
                Header::Packet(Packet::new(0x1234, 0x5678, 2, 1, 2, Address::None)),
                &PACKET_CONTINUATION_BYTES,
            ),
            (
                Header::Dissociate(Dissociate::new(0x1234)),
                &DISSOCIATE_BYTES,
            ),
            (Header::Heartbeat(Heartbeat::new()), &HEARTBEAT_BYTES),
        ]
    }

    #[test]
    fn write_matches_spec_fixtures() {
        for (header, expected) in fixtures() {
            let mut bytes = BytesMut::new();
            header.write(&mut bytes);
            assert_eq!(bytes.as_ref(), expected);
            assert_eq!(header.len(), expected.len());
        }
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_marshal_matches_spec_fixtures() {
        for (header, expected) in fixtures() {
            let mut bytes = Vec::new();
            header.marshal(&mut bytes).unwrap();
            assert_eq!(bytes, expected);
        }
    }

    #[cfg(feature = "async_marshal")]
    #[test]
    fn async_marshal_matches_spec_fixtures() {
        futures_executor::block_on(async {
            for (header, expected) in fixtures() {
                let mut bytes = futures_util::io::Cursor::new(Vec::new());
                header.async_marshal(&mut bytes).await.unwrap();
                assert_eq!(bytes.into_inner(), expected);
            }
        });
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_marshal_propagates_writer_errors() {
        use std::io::{Error, ErrorKind, Write};

        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> Result<usize, Error> {
                Err(Error::new(ErrorKind::BrokenPipe, "write failed"))
            }

            fn flush(&mut self) -> Result<(), Error> {
                Ok(())
            }
        }

        let error = Header::Heartbeat(Heartbeat::new())
            .marshal(&mut FailingWriter)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }
}
