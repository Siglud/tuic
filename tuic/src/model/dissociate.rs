use super::side::{self, Side};
use crate::{Dissociate as DissociateHeader, Header};
use std::fmt::{Debug, Formatter, Result as FmtResult};

/// The model of the `Dissociate` command
pub struct Dissociate<M> {
    inner: Side<Tx, Rx>,
    _marker: M,
}

struct Tx {
    header: Header,
}

impl Dissociate<side::Tx> {
    pub(super) fn new(assoc_id: u16) -> Self {
        Self {
            inner: Side::Tx(Tx {
                header: Header::Dissociate(DissociateHeader::new(assoc_id)),
            }),
            _marker: side::Tx,
        }
    }

    /// Returns the header of the `Dissociate` command
    pub fn header(&self) -> &Header {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        &tx.header
    }
}

impl Debug for Dissociate<side::Tx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("Dissociate")
            .field("header", &tx.header)
            .finish()
    }
}

struct Rx {
    assoc_id: u16,
}

impl Dissociate<side::Rx> {
    pub(super) fn new(assoc_id: u16) -> Self {
        Self {
            inner: Side::Rx(Rx { assoc_id }),
            _marker: side::Rx,
        }
    }

    /// Returns the UDP session ID
    pub fn assoc_id(&self) -> u16 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.assoc_id
    }
}

impl Debug for Dissociate<side::Rx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("Dissociate")
            .field("assoc_id", &rx.assoc_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::Connection, Address, Packet as PacketHeader};

    #[test]
    fn send_removes_session_and_exposes_header() {
        let connection = Connection::<Vec<u8>>::new();
        drop(connection.send_packet(7, Address::None, 64));
        assert_eq!(connection.task_associate_count(), 1);

        let dissociate = connection.send_dissociate(7);
        assert_eq!(connection.task_associate_count(), 0);
        let Header::Dissociate(header) = dissociate.header() else {
            panic!("unexpected dissociate header")
        };
        assert_eq!(header.assoc_id(), 7);
        assert!(format!("{dissociate:?}").contains("assoc_id: 7"));
        assert!(connection
            .recv_packet(PacketHeader::new(7, 0, 1, 0, 1, Address::None))
            .is_none());
    }

    #[test]
    fn receive_removes_session_and_exposes_association() {
        let connection = Connection::<Vec<u8>>::new();
        drop(connection.send_packet(9, Address::None, 64));
        assert_eq!(connection.task_associate_count(), 1);

        let dissociate = connection.recv_dissociate(DissociateHeader::new(9));
        assert_eq!(connection.task_associate_count(), 0);
        assert_eq!(dissociate.assoc_id(), 9);
        assert!(format!("{dissociate:?}").contains("assoc_id: 9"));
    }
}
