use super::{
    side::{self, Side},
    Assemblable, AssembleError, UdpSessions,
};
use crate::{Address, Header, Packet as PacketHeader};
use parking_lot::Mutex;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    ops::Range,
    sync::Arc,
};

pub struct Packet<M, B> {
    inner: Side<Tx, Rx<B>>,
    _marker: M,
}

struct Tx {
    assoc_id: u16,
    pkt_id: u16,
    addr: Address,
    max_pkt_size: usize,
}

impl<B> Packet<side::Tx, B> {
    pub(super) fn new(assoc_id: u16, pkt_id: u16, addr: Address, max_pkt_size: usize) -> Self {
        Self {
            inner: Side::Tx(Tx {
                assoc_id,
                pkt_id,
                addr,
                max_pkt_size,
            }),
            _marker: side::Tx,
        }
    }

    /// Fragment the payload into multiple packets
    pub fn into_fragments<P>(self, payload: P) -> Fragments<P>
    where
        P: AsRef<[u8]>,
    {
        let Side::Tx(tx) = self.inner else {
            unreachable!()
        };
        Fragments::new(tx.assoc_id, tx.pkt_id, tx.addr, tx.max_pkt_size, payload)
    }

    /// Returns the UDP session ID
    pub fn assoc_id(&self) -> u16 {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        tx.assoc_id
    }

    /// Returns the packet ID
    pub fn pkt_id(&self) -> u16 {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        tx.pkt_id
    }

    /// Returns the address
    pub fn addr(&self) -> &Address {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        &tx.addr
    }
}

impl<B> Debug for Packet<side::Tx, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("Packet")
            .field("assoc_id", &tx.assoc_id)
            .field("pkt_id", &tx.pkt_id)
            .field("addr", &tx.addr)
            .field("max_pkt_size", &tx.max_pkt_size)
            .finish()
    }
}

struct Rx<B> {
    sessions: Arc<Mutex<UdpSessions<B>>>,
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    size: u16,
    addr: Address,
}

impl<B> Packet<side::Rx, B>
where
    B: AsRef<[u8]>,
{
    pub(super) fn new(
        sessions: Arc<Mutex<UdpSessions<B>>>,
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        size: u16,
        addr: Address,
    ) -> Self {
        Self {
            inner: Side::Rx(Rx {
                sessions,
                assoc_id,
                pkt_id,
                frag_total,
                frag_id,
                size,
                addr,
            }),
            _marker: side::Rx,
        }
    }

    /// Reassembles the packet. If the packet is not complete yet, `None` is returned.
    pub fn assemble(self, data: B) -> Result<Option<Assemblable<B>>, AssembleError> {
        let Side::Rx(rx) = self.inner else {
            unreachable!()
        };
        let mut sessions = rx.sessions.lock();

        sessions.insert(
            rx.assoc_id,
            rx.pkt_id,
            rx.frag_total,
            rx.frag_id,
            rx.size,
            rx.addr,
            data,
        )
    }

    /// Returns the UDP session ID
    pub fn assoc_id(&self) -> u16 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.assoc_id
    }

    /// Returns the packet ID
    pub fn pkt_id(&self) -> u16 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.pkt_id
    }

    /// Returns the fragment ID
    pub fn frag_id(&self) -> u8 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.frag_id
    }

    /// Returns the total number of fragments
    pub fn frag_total(&self) -> u8 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.frag_total
    }

    /// Returns the address
    pub fn addr(&self) -> &Address {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        &rx.addr
    }

    /// Returns the size of the (fragmented) packet
    pub fn size(&self) -> u16 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.size
    }
}

impl<B> Debug for Packet<side::Rx, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("Packet")
            .field("assoc_id", &rx.assoc_id)
            .field("pkt_id", &rx.pkt_id)
            .field("frag_total", &rx.frag_total)
            .field("frag_id", &rx.frag_id)
            .field("size", &rx.size)
            .field("addr", &rx.addr)
            .finish()
    }
}

/// Iterator over fragments of a packet
#[derive(Debug)]
pub struct Fragments<P> {
    assoc_id: u16,
    pkt_id: u16,
    addr: Address,
    max_pkt_size: usize,
    frag_total: usize,
    next_frag_id: usize,
    next_frag_start: usize,
    payload: Arc<P>,
}

impl<P> Fragments<P>
where
    P: AsRef<[u8]>,
{
    fn new(assoc_id: u16, pkt_id: u16, addr: Address, max_pkt_size: usize, payload: P) -> Self {
        let header_addr_ref = Header::Packet(PacketHeader::new(0, 0, 0, 0, 0, addr));
        let header_addr_none_ref = Header::Packet(PacketHeader::new(0, 0, 0, 0, 0, Address::None));

        let first_frag_size = max_pkt_size
            .checked_sub(header_addr_ref.len())
            .expect("maximum packet size is smaller than the first fragment header")
            .min(u16::MAX as usize);
        let frag_size_addr_none = max_pkt_size
            .checked_sub(header_addr_none_ref.len())
            .expect("maximum packet size is smaller than a continuation header")
            .min(u16::MAX as usize);

        let Header::Packet(pkt) = header_addr_ref else {
            unreachable!()
        };
        let (_, _, _, _, _, addr) = pkt.into();

        let frag_total = if payload.as_ref().len() > first_frag_size {
            assert!(
                frag_size_addr_none > 0,
                "maximum packet size leaves no room for continuation payload"
            );
            1 + (payload.as_ref().len() - first_frag_size).div_ceil(frag_size_addr_none)
        } else {
            1
        };
        assert!(
            frag_total <= u8::MAX as usize,
            "payload requires more than 255 fragments"
        );

        Self {
            assoc_id,
            pkt_id,
            addr,
            max_pkt_size,
            frag_total,
            next_frag_id: 0,
            next_frag_start: 0,
            payload: Arc::new(payload),
        }
    }
}

/// A memory-safe view over one packet fragment.
#[derive(Debug)]
pub struct Fragment<P> {
    payload: Arc<P>,
    range: Range<usize>,
}

impl<P> AsRef<[u8]> for Fragment<P>
where
    P: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        &self.payload.as_ref().as_ref()[self.range.clone()]
    }
}

impl<P> Iterator for Fragments<P>
where
    P: AsRef<[u8]>,
{
    type Item = (Header, Fragment<P>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_frag_id < self.frag_total {
            let header_ref = Header::Packet(PacketHeader::new(0, 0, 0, 0, 0, self.addr.take()));

            let payload_size = self.max_pkt_size - header_ref.len();
            let next_frag_end =
                (self.next_frag_start + payload_size).min(self.payload.as_ref().as_ref().len());

            let Header::Packet(pkt) = header_ref else {
                unreachable!()
            };
            let (_, _, _, _, _, addr) = pkt.into();

            let header = Header::Packet(PacketHeader::new(
                self.assoc_id,
                self.pkt_id,
                self.frag_total as u8,
                self.next_frag_id as u8,
                (next_frag_end - self.next_frag_start) as u16,
                addr,
            ));

            let payload = Fragment {
                payload: self.payload.clone(),
                range: self.next_frag_start..next_frag_end,
            };

            self.next_frag_id += 1;
            self.next_frag_start = next_frag_end;

            Some((header, payload))
        } else {
            None
        }
    }
}

impl<P> ExactSizeIterator for Fragments<P>
where
    P: AsRef<[u8]>,
{
    fn len(&self) -> usize {
        self.frag_total - self.next_frag_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Connection;
    use std::net::{Ipv4Addr, SocketAddr};

    fn tx(max_pkt_size: usize) -> Packet<side::Tx, Vec<u8>> {
        Packet::<side::Tx, Vec<u8>>::new(
            7,
            11,
            Address::SocketAddress(SocketAddr::from((Ipv4Addr::LOCALHOST, 53))),
            max_pkt_size,
        )
    }

    #[test]
    fn fragments_empty_payload_once() {
        let mut fragments = tx(64).into_fragments(Vec::<u8>::new());
        assert_eq!(fragments.len(), 1);

        let (header, fragment) = fragments.next().unwrap();
        let Header::Packet(header) = header else {
            unreachable!()
        };
        assert_eq!(header.frag_total(), 1);
        assert_eq!(header.frag_id(), 0);
        assert_eq!(header.size(), 0);
        assert!(fragment.as_ref().is_empty());
        assert_eq!(fragments.len(), 0);
        assert!(fragments.next().is_none());
    }

    #[test]
    fn send_accessors_and_debug_expose_packet_metadata() {
        let packet = tx(64);

        assert_eq!(packet.assoc_id(), 7);
        assert_eq!(packet.pkt_id(), 11);
        assert!(packet.addr().is_ipv4());
        let debug = format!("{packet:?}");
        assert!(debug.contains("assoc_id: 7"));
        assert!(debug.contains("pkt_id: 11"));
        assert!(debug.contains("max_pkt_size: 64"));
    }

    #[test]
    fn receive_accessors_and_debug_expose_fragment_metadata() {
        let connection = Connection::<Vec<u8>>::new();
        let address = Address::DomainAddress("example.com".into(), 443);
        let packet =
            connection.recv_packet_unrestricted(PacketHeader::new(7, 11, 3, 2, 4, address.clone()));

        assert_eq!(packet.assoc_id(), 7);
        assert_eq!(packet.pkt_id(), 11);
        assert_eq!(packet.frag_total(), 3);
        assert_eq!(packet.frag_id(), 2);
        assert_eq!(packet.size(), 4);
        assert_eq!(packet.addr(), &address);
        let debug = format!("{packet:?}");
        assert!(debug.contains("frag_total: 3"));
        assert!(debug.contains("frag_id: 2"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn fragments_non_empty_payload_as_single_packet() {
        let payload = vec![1, 2, 3];
        let mut fragments = tx(64).into_fragments(payload.clone());
        let (header, fragment) = fragments.next().unwrap();
        let Header::Packet(header) = header else {
            unreachable!()
        };

        assert_eq!(header.frag_total(), 1);
        assert_eq!(header.frag_id(), 0);
        assert_eq!(header.size(), 3);
        assert!(header.addr().is_ipv4());
        assert_eq!(fragment.as_ref(), payload);
        assert!(fragments.next().is_none());
    }

    #[test]
    fn fragments_exact_continuation_boundary_without_empty_fragment() {
        let max_pkt_size = 20;
        let payload: Vec<_> = (0..12).collect();
        let fragments: Vec<_> = tx(max_pkt_size).into_fragments(payload.clone()).collect();

        assert_eq!(fragments.len(), 2);
        let mut reassembled = Vec::new();
        for (index, (header, fragment)) in fragments.into_iter().enumerate() {
            let Header::Packet(header) = header else {
                unreachable!()
            };
            assert_eq!(header.assoc_id(), 7);
            assert_eq!(header.pkt_id(), 11);
            assert_eq!(header.frag_total(), 2);
            assert_eq!(header.frag_id(), index as u8);
            assert_eq!(header.size() as usize, fragment.as_ref().len());
            if index == 0 {
                assert!(header.addr().is_ipv4());
            } else {
                assert!(header.addr().is_none());
            }
            assert!(header.len() + fragment.as_ref().len() <= max_pkt_size);
            reassembled.extend_from_slice(fragment.as_ref());
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn fragment_keeps_payload_alive_after_iterator_is_dropped() {
        let mut fragments = tx(20).into_fragments(vec![1, 2, 3, 4]);
        let (_, fragment) = fragments.next().unwrap();
        drop(fragments);
        assert_eq!(fragment.as_ref(), &[1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "smaller than the first fragment header")]
    fn rejects_packet_size_smaller_than_header() {
        let _ = tx(1).into_fragments(vec![1]);
    }

    #[test]
    #[should_panic(expected = "more than 255 fragments")]
    fn rejects_payload_requiring_too_many_fragments() {
        let _ = tx(18).into_fragments(vec![0; 2041]);
    }
}
