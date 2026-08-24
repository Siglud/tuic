use super::side::{self, Side};
use crate::{Authenticate as AuthenticateHeader, Header};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use uuid::Uuid;

/// The model of the `Authenticate` command
pub struct Authenticate<M> {
    inner: Side<Tx, Rx>,
    _marker: M,
}

struct Tx {
    header: Header,
}

impl Authenticate<side::Tx> {
    pub(super) fn new(
        uuid: Uuid,
        password: impl AsRef<[u8]>,
        exporter: &impl KeyingMaterialExporter,
    ) -> Self {
        Self {
            inner: Side::Tx(Tx {
                header: Header::Authenticate(AuthenticateHeader::new(
                    uuid,
                    exporter.export_keying_material(uuid.as_ref(), password.as_ref()),
                )),
            }),
            _marker: side::Tx,
        }
    }

    /// Returns the header of the `Authenticate` command
    pub fn header(&self) -> &Header {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        &tx.header
    }
}

impl Debug for Authenticate<side::Tx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("Authenticate")
            .field("header", &tx.header)
            .finish()
    }
}

struct Rx {
    uuid: Uuid,
    token: [u8; 32],
}

impl Authenticate<side::Rx> {
    pub(super) fn new(uuid: Uuid, token: [u8; 32]) -> Self {
        Self {
            inner: Side::Rx(Rx { uuid, token }),
            _marker: side::Rx,
        }
    }

    /// Returns the UUID of the peer
    pub fn uuid(&self) -> Uuid {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.uuid
    }

    /// Returns the token of the peer
    pub fn token(&self) -> [u8; 32] {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.token
    }

    /// Returns whether the token is valid
    pub fn is_valid(
        &self,
        password: impl AsRef<[u8]>,
        exporter: &impl KeyingMaterialExporter,
    ) -> bool {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.token == exporter.export_keying_material(rx.uuid.as_ref(), password.as_ref())
    }
}

impl Debug for Authenticate<side::Rx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("Authenticate")
            .field("uuid", &rx.uuid)
            .field("token", &rx.token)
            .finish()
    }
}

/// The trait for exporting keying material
pub trait KeyingMaterialExporter {
    /// Exports keying material
    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Connection;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingExporter {
        calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl RecordingExporter {
        fn token(label: &[u8], context: &[u8]) -> [u8; 32] {
            let mut token = [0; 32];
            token[..label.len()].copy_from_slice(label);
            for (index, byte) in context.iter().enumerate() {
                token[index % token.len()] ^= byte;
            }
            token
        }
    }

    impl KeyingMaterialExporter for RecordingExporter {
        fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32] {
            self.calls
                .lock()
                .unwrap()
                .push((label.to_vec(), context.to_vec()));
            Self::token(label, context)
        }
    }

    #[test]
    fn send_uses_uuid_as_label_and_password_as_context() {
        let connection = Connection::<Vec<u8>>::new();
        let exporter = RecordingExporter::default();
        let uuid = Uuid::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let authenticate = connection.send_authenticate(uuid, b"secret", &exporter);

        let Header::Authenticate(header) = authenticate.header() else {
            panic!("unexpected authentication header")
        };
        assert_eq!(header.uuid(), uuid);
        assert_eq!(
            header.token(),
            RecordingExporter::token(uuid.as_ref(), b"secret")
        );
        assert_eq!(
            *exporter.calls.lock().unwrap(),
            vec![(uuid.as_bytes().to_vec(), b"secret".to_vec())]
        );
        let debug = format!("{authenticate:?}");
        assert!(debug.contains("Authenticate"));
        assert!(debug.contains("header"));
    }

    #[test]
    fn receive_exposes_credentials_and_validates_password() {
        let connection = Connection::<Vec<u8>>::new();
        let exporter = RecordingExporter::default();
        let uuid = Uuid::from_bytes([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        let token = RecordingExporter::token(uuid.as_ref(), b"secret");
        let authenticate = connection.recv_authenticate(AuthenticateHeader::new(uuid, token));

        assert_eq!(authenticate.uuid(), uuid);
        assert_eq!(authenticate.token(), token);
        assert!(authenticate.is_valid(b"secret", &exporter));
        assert!(!authenticate.is_valid(b"wrong", &exporter));
        assert_eq!(
            *exporter.calls.lock().unwrap(),
            vec![
                (uuid.as_bytes().to_vec(), b"secret".to_vec()),
                (uuid.as_bytes().to_vec(), b"wrong".to_vec()),
            ]
        );
        let debug = format!("{authenticate:?}");
        assert!(debug.contains("uuid"));
        assert!(debug.contains("token"));
    }
}
