use crate::{Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet, VERSION};
#[cfg(feature = "async_marshal")]
use futures_util::{AsyncRead, AsyncReadExt};
#[cfg(feature = "marshal")]
use std::io::Read;
use std::{io::Error as IoError, net::SocketAddr, string::FromUtf8Error};
use thiserror::Error;
use uuid::{Error as UuidError, Uuid};

impl Header {
    /// Unmarshals a header from an `AsyncRead` stream
    #[cfg(feature = "async_marshal")]
    pub async fn async_unmarshal(s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 1];
        s.read_exact(&mut buf).await?;
        let ver = buf[0];

        if ver != VERSION {
            return Err(UnmarshalError::InvalidVersion(ver));
        }

        let mut buf = [0; 1];
        s.read_exact(&mut buf).await?;
        let cmd = buf[0];

        match cmd {
            Header::TYPE_CODE_AUTHENTICATE => {
                Authenticate::async_read(s).await.map(Self::Authenticate)
            }
            Header::TYPE_CODE_CONNECT => Connect::async_read(s).await.map(Self::Connect),
            Header::TYPE_CODE_PACKET => Packet::async_read(s).await.map(Self::Packet),
            Header::TYPE_CODE_DISSOCIATE => Dissociate::async_read(s).await.map(Self::Dissociate),
            Header::TYPE_CODE_HEARTBEAT => Heartbeat::async_read(s).await.map(Self::Heartbeat),
            _ => Err(UnmarshalError::InvalidCommand(cmd)),
        }
    }

    /// Unmarshals a header from a `Read` stream
    #[cfg(feature = "marshal")]
    pub fn unmarshal(s: &mut impl Read) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 1];
        s.read_exact(&mut buf)?;
        let ver = buf[0];

        if ver != VERSION {
            return Err(UnmarshalError::InvalidVersion(ver));
        }

        let mut buf = [0; 1];
        s.read_exact(&mut buf)?;
        let cmd = buf[0];

        match cmd {
            Header::TYPE_CODE_AUTHENTICATE => Authenticate::read(s).map(Self::Authenticate),
            Header::TYPE_CODE_CONNECT => Connect::read(s).map(Self::Connect),
            Header::TYPE_CODE_PACKET => Packet::read(s).map(Self::Packet),
            Header::TYPE_CODE_DISSOCIATE => Dissociate::read(s).map(Self::Dissociate),
            Header::TYPE_CODE_HEARTBEAT => Heartbeat::read(s).map(Self::Heartbeat),
            _ => Err(UnmarshalError::InvalidCommand(cmd)),
        }
    }
}

impl Address {
    #[cfg(feature = "async_marshal")]
    async fn async_read(s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 1];
        s.read_exact(&mut buf).await?;
        let type_code = buf[0];

        match type_code {
            Address::TYPE_CODE_NONE => Ok(Self::None),
            Address::TYPE_CODE_DOMAIN => {
                let mut buf = [0; 1];
                s.read_exact(&mut buf).await?;
                let len = buf[0] as usize;

                let mut buf = vec![0; len + 2];
                s.read_exact(&mut buf).await?;
                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                buf.truncate(len);
                let domain = String::from_utf8(buf)?;

                Ok(Self::DomainAddress(domain, port))
            }
            Address::TYPE_CODE_IPV4 => {
                let mut buf = [0; 6];
                s.read_exact(&mut buf).await?;
                let ip = [buf[0], buf[1], buf[2], buf[3]];
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Self::SocketAddress(SocketAddr::from((ip, port))))
            }
            Address::TYPE_CODE_IPV6 => {
                let mut buf = [0; 18];
                s.read_exact(&mut buf).await?;
                let ip = [
                    u16::from_be_bytes([buf[0], buf[1]]),
                    u16::from_be_bytes([buf[2], buf[3]]),
                    u16::from_be_bytes([buf[4], buf[5]]),
                    u16::from_be_bytes([buf[6], buf[7]]),
                    u16::from_be_bytes([buf[8], buf[9]]),
                    u16::from_be_bytes([buf[10], buf[11]]),
                    u16::from_be_bytes([buf[12], buf[13]]),
                    u16::from_be_bytes([buf[14], buf[15]]),
                ];
                let port = u16::from_be_bytes([buf[16], buf[17]]);

                Ok(Self::SocketAddress(SocketAddr::from((ip, port))))
            }
            _ => Err(UnmarshalError::InvalidAddressType(type_code)),
        }
    }

    #[cfg(feature = "marshal")]
    fn read(s: &mut impl Read) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 1];
        s.read_exact(&mut buf)?;
        let type_code = buf[0];

        match type_code {
            Address::TYPE_CODE_NONE => Ok(Self::None),
            Address::TYPE_CODE_DOMAIN => {
                let mut buf = [0; 1];
                s.read_exact(&mut buf)?;
                let len = buf[0] as usize;

                let mut buf = vec![0; len + 2];
                s.read_exact(&mut buf)?;
                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                buf.truncate(len);
                let domain = String::from_utf8(buf)?;

                Ok(Self::DomainAddress(domain, port))
            }
            Address::TYPE_CODE_IPV4 => {
                let mut buf = [0; 6];
                s.read_exact(&mut buf)?;
                let ip = [buf[0], buf[1], buf[2], buf[3]];
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Self::SocketAddress(SocketAddr::from((ip, port))))
            }
            Address::TYPE_CODE_IPV6 => {
                let mut buf = [0; 18];
                s.read_exact(&mut buf)?;
                let ip = [
                    u16::from_be_bytes([buf[0], buf[1]]),
                    u16::from_be_bytes([buf[2], buf[3]]),
                    u16::from_be_bytes([buf[4], buf[5]]),
                    u16::from_be_bytes([buf[6], buf[7]]),
                    u16::from_be_bytes([buf[8], buf[9]]),
                    u16::from_be_bytes([buf[10], buf[11]]),
                    u16::from_be_bytes([buf[12], buf[13]]),
                    u16::from_be_bytes([buf[14], buf[15]]),
                ];
                let port = u16::from_be_bytes([buf[16], buf[17]]);

                Ok(Self::SocketAddress(SocketAddr::from((ip, port))))
            }
            _ => Err(UnmarshalError::InvalidAddressType(type_code)),
        }
    }
}

impl Authenticate {
    #[cfg(feature = "async_marshal")]
    async fn async_read(s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 48];
        s.read_exact(&mut buf).await?;
        let uuid = Uuid::from_slice(&buf[..16])?;
        let token = TryFrom::try_from(&buf[16..]).unwrap();
        Ok(Self::new(uuid, token))
    }

    #[cfg(feature = "marshal")]
    fn read(s: &mut impl Read) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 48];
        s.read_exact(&mut buf)?;
        let uuid = Uuid::from_slice(&buf[..16])?;
        let token = TryFrom::try_from(&buf[16..]).unwrap();
        Ok(Self::new(uuid, token))
    }
}

impl Connect {
    #[cfg(feature = "async_marshal")]
    async fn async_read(s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        Ok(Self::new(Address::async_read(s).await?))
    }

    #[cfg(feature = "marshal")]
    fn read(s: &mut impl Read) -> Result<Self, UnmarshalError> {
        Ok(Self::new(Address::read(s)?))
    }
}

impl Packet {
    #[cfg(feature = "async_marshal")]
    async fn async_read(s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 8];
        s.read_exact(&mut buf).await?;

        let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
        let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
        let frag_total = buf[4];
        let frag_id = buf[5];
        let size = u16::from_be_bytes([buf[6], buf[7]]);
        let addr = Address::async_read(s).await?;

        Ok(Self::new(assoc_id, pkt_id, frag_total, frag_id, size, addr))
    }

    #[cfg(feature = "marshal")]
    fn read(s: &mut impl Read) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 8];
        s.read_exact(&mut buf)?;

        let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
        let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
        let frag_total = buf[4];
        let frag_id = buf[5];
        let size = u16::from_be_bytes([buf[6], buf[7]]);
        let addr = Address::read(s)?;

        Ok(Self::new(assoc_id, pkt_id, frag_total, frag_id, size, addr))
    }
}

impl Dissociate {
    #[cfg(feature = "async_marshal")]
    async fn async_read(s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 2];
        s.read_exact(&mut buf).await?;
        let assoc_id = u16::from_be_bytes(buf);
        Ok(Self::new(assoc_id))
    }

    #[cfg(feature = "marshal")]
    fn read(s: &mut impl Read) -> Result<Self, UnmarshalError> {
        let mut buf = [0; 2];
        s.read_exact(&mut buf)?;
        let assoc_id = u16::from_be_bytes(buf);
        Ok(Self::new(assoc_id))
    }
}

impl Heartbeat {
    #[cfg(feature = "async_marshal")]
    async fn async_read(_s: &mut (impl AsyncRead + Unpin)) -> Result<Self, UnmarshalError> {
        Ok(Self::new())
    }

    #[cfg(feature = "marshal")]
    fn read(_s: &mut impl Read) -> Result<Self, UnmarshalError> {
        Ok(Self::new())
    }
}

/// Errors that can occur when unmarshalling a packet
#[derive(Debug, Error)]
pub enum UnmarshalError {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error("invalid version: {0}")]
    InvalidVersion(u8),
    #[error("invalid command: {0}")]
    InvalidCommand(u8),
    #[error("invalid UUID: {0}")]
    InvalidUuid(#[from] UuidError),
    #[error("invalid address type: {0}")]
    InvalidAddressType(u8),
    #[error("address parsing error: {0}")]
    AddressParse(#[from] FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    const TOKEN: [u8; 32] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f,
    ];
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

    fn fixtures() -> [&'static [u8]; 8] {
        [
            &AUTHENTICATE_BYTES,
            &CONNECT_DOMAIN_BYTES,
            &CONNECT_IPV4_BYTES,
            &CONNECT_IPV6_BYTES,
            &PACKET_FIRST_BYTES,
            &PACKET_CONTINUATION_BYTES,
            &DISSOCIATE_BYTES,
            &HEARTBEAT_BYTES,
        ]
    }

    fn assert_fixture(index: usize, header: Header) {
        match (index, header) {
            (0, Header::Authenticate(authenticate)) => {
                assert_eq!(
                    authenticate.uuid(),
                    Uuid::from_bytes([
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ])
                );
                assert_eq!(authenticate.token(), TOKEN);
            }
            (1, Header::Connect(connect)) => {
                assert_eq!(
                    connect.addr(),
                    &Address::DomainAddress("example.com".into(), 443)
                );
            }
            (2, Header::Connect(connect)) => {
                assert_eq!(
                    connect.addr(),
                    &Address::SocketAddress(([192, 0, 2, 1], 443).into())
                );
            }
            (3, Header::Connect(connect)) => {
                assert_eq!(
                    connect.addr(),
                    &Address::SocketAddress(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 443).into())
                );
            }
            (4, Header::Packet(packet)) => {
                assert_eq!(packet.assoc_id(), 0x1234);
                assert_eq!(packet.pkt_id(), 0x5678);
                assert_eq!(packet.frag_total(), 2);
                assert_eq!(packet.frag_id(), 0);
                assert_eq!(packet.size(), 3);
                assert_eq!(
                    packet.addr(),
                    &Address::DomainAddress("example.com".into(), 443)
                );
            }
            (5, Header::Packet(packet)) => {
                assert_eq!(packet.assoc_id(), 0x1234);
                assert_eq!(packet.pkt_id(), 0x5678);
                assert_eq!(packet.frag_total(), 2);
                assert_eq!(packet.frag_id(), 1);
                assert_eq!(packet.size(), 2);
                assert!(packet.addr().is_none());
            }
            (6, Header::Dissociate(dissociate)) => {
                assert_eq!(dissociate.assoc_id(), 0x1234);
            }
            (7, Header::Heartbeat(_)) => {}
            (_, header) => panic!("unexpected fixture {index}: {header:?}"),
        }
    }

    #[cfg(feature = "marshal")]
    fn sync_error(bytes: &[u8]) -> UnmarshalError {
        Header::unmarshal(&mut std::io::Cursor::new(bytes)).unwrap_err()
    }

    #[cfg(feature = "async_marshal")]
    async fn async_error(bytes: &[u8]) -> UnmarshalError {
        Header::async_unmarshal(&mut futures_util::io::Cursor::new(bytes))
            .await
            .unwrap_err()
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_unmarshal_matches_spec_fixtures() {
        for (index, bytes) in fixtures().into_iter().enumerate() {
            let mut input = std::io::Cursor::new(bytes);
            let header = Header::unmarshal(&mut input).unwrap();
            assert_eq!(input.position() as usize, bytes.len());
            assert_fixture(index, header);
        }
    }

    #[cfg(feature = "async_marshal")]
    #[test]
    fn async_unmarshal_matches_spec_fixtures() {
        futures_executor::block_on(async {
            for (index, bytes) in fixtures().into_iter().enumerate() {
                let mut input = futures_util::io::Cursor::new(bytes);
                let header = Header::async_unmarshal(&mut input).await.unwrap();
                assert_eq!(input.position() as usize, bytes.len());
                assert_fixture(index, header);
            }
        });
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_unmarshal_rejects_every_truncated_fixture_prefix() {
        for bytes in fixtures() {
            for boundary in 0..bytes.len() {
                let error = sync_error(&bytes[..boundary]);
                assert!(
                    matches!(error, UnmarshalError::Io(ref error) if error.kind() == ErrorKind::UnexpectedEof),
                    "boundary {boundary} of {} bytes produced {error:?}",
                    bytes.len()
                );
            }
        }
    }

    #[cfg(feature = "async_marshal")]
    #[test]
    fn async_unmarshal_rejects_every_truncated_fixture_prefix() {
        futures_executor::block_on(async {
            for bytes in fixtures() {
                for boundary in 0..bytes.len() {
                    let error = async_error(&bytes[..boundary]).await;
                    assert!(
                        matches!(error, UnmarshalError::Io(ref error) if error.kind() == ErrorKind::UnexpectedEof),
                        "boundary {boundary} of {} bytes produced {error:?}",
                        bytes.len()
                    );
                }
            }
        });
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_unmarshal_rejects_invalid_metadata() {
        assert!(matches!(
            sync_error(&[0x04, 0x04]),
            UnmarshalError::InvalidVersion(0x04)
        ));
        assert!(matches!(
            sync_error(&[0x05, 0xfe]),
            UnmarshalError::InvalidCommand(0xfe)
        ));
        assert!(matches!(
            sync_error(&[0x05, 0x01, 0xfe]),
            UnmarshalError::InvalidAddressType(0xfe)
        ));
        assert!(matches!(
            sync_error(&[0x05, 0x01, 0x00, 0x01, 0xff, 0x01, 0xbb]),
            UnmarshalError::AddressParse(_)
        ));
    }

    #[cfg(feature = "async_marshal")]
    #[test]
    fn async_unmarshal_rejects_invalid_metadata() {
        futures_executor::block_on(async {
            assert!(matches!(
                async_error(&[0x04, 0x04]).await,
                UnmarshalError::InvalidVersion(0x04)
            ));
            assert!(matches!(
                async_error(&[0x05, 0xfe]).await,
                UnmarshalError::InvalidCommand(0xfe)
            ));
            assert!(matches!(
                async_error(&[0x05, 0x01, 0xfe]).await,
                UnmarshalError::InvalidAddressType(0xfe)
            ));
            assert!(matches!(
                async_error(&[0x05, 0x01, 0x00, 0x01, 0xff, 0x01, 0xbb]).await,
                UnmarshalError::AddressParse(_)
            ));
        });
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_unmarshal_leaves_packet_payload_unread() {
        use std::io::Read;

        let mut bytes = PACKET_FIRST_BYTES.to_vec();
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let mut input = std::io::Cursor::new(bytes);
        let header = Header::unmarshal(&mut input).unwrap();
        assert_fixture(4, header);

        let mut payload = Vec::new();
        input.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, [0xaa, 0xbb, 0xcc]);
    }

    #[cfg(feature = "async_marshal")]
    #[test]
    fn async_unmarshal_leaves_packet_payload_unread() {
        use futures_util::AsyncReadExt;

        futures_executor::block_on(async {
            let mut bytes = PACKET_FIRST_BYTES.to_vec();
            bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
            let mut input = futures_util::io::Cursor::new(bytes);
            let header = Header::async_unmarshal(&mut input).await.unwrap();
            assert_fixture(4, header);

            let mut payload = Vec::new();
            input.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, [0xaa, 0xbb, 0xcc]);
        });
    }

    #[cfg(feature = "marshal")]
    #[test]
    fn sync_unmarshal_propagates_reader_errors() {
        use std::io::{Error, Read};

        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Error> {
                Err(Error::new(ErrorKind::ConnectionReset, "read failed"))
            }
        }

        let error = Header::unmarshal(&mut FailingReader).unwrap_err();
        assert!(matches!(
            error,
            UnmarshalError::Io(error) if error.kind() == ErrorKind::ConnectionReset
        ));
    }
}
