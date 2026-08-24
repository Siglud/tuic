#![doc = include_str!("../README.md")]

use self::side::Side;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use quinn::{
    ClosedStream, Connection as QuinnConnection, ConnectionError, RecvStream, SendDatagramError,
    SendStream, VarInt,
};
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    io::{Cursor, Error as IoError},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thiserror::Error;
use tuic::{
    model::{
        side::{Rx, Tx},
        AssembleError, Authenticate as AuthenticateModel, Connect as ConnectModel,
        Connection as ConnectionModel, KeyingMaterialExporter as KeyingMaterialExporterImpl,
        Packet as PacketModel,
    },
    Address, Header, UnmarshalError,
};
use uuid::Uuid;

pub mod side {
    //! Side marker types for a connection.

    #[derive(Clone, Debug)]
    pub struct Client;
    #[derive(Clone, Debug)]
    pub struct Server;

    pub(super) enum Side<C, S> {
        Client(C),
        Server(S),
    }
}

/// The TUIC Connection.
///
/// This struct takes a clone of `quinn::Connection` for performing TUIC operations.
///
/// See more details about the TUIC protocol at [SPEC.md](https://github.com/EAimTY/tuic/blob/dev/tuic/SPEC.md)
#[derive(Clone)]
pub struct Connection<Side> {
    conn: QuinnConnection,
    model: ConnectionModel<Bytes>,
    _marker: Side,
}

impl<Side> Connection<Side> {
    /// Sends a `Packet` using UDP relay mode `native`.
    pub fn packet_native(
        &self,
        pkt: impl AsRef<[u8]>,
        addr: Address,
        assoc_id: u16,
    ) -> Result<(), Error> {
        let Some(max_pkt_size) = self.conn.max_datagram_size() else {
            return Err(Error::SendDatagram(SendDatagramError::Disabled));
        };

        let model = self.model.send_packet(assoc_id, addr, max_pkt_size);

        for (header, frag) in model.into_fragments(pkt) {
            let mut buf = BytesMut::with_capacity(header.len() + frag.as_ref().len());
            header.write(&mut buf);
            buf.put_slice(frag.as_ref());
            self.conn.send_datagram(Bytes::from(buf))?;
        }

        Ok(())
    }

    /// Sends a `Packet` using UDP relay mode `quic`.
    pub async fn packet_quic(
        &self,
        pkt: impl AsRef<[u8]>,
        addr: Address,
        assoc_id: u16,
    ) -> Result<(), Error> {
        let model = self.model.send_packet(assoc_id, addr, u16::MAX as usize);

        for (header, frag) in model.into_fragments(pkt) {
            let mut send = self.conn.open_uni().await?;
            header.async_marshal(&mut send).await?;
            AsyncWriteExt::write_all(&mut send, frag.as_ref()).await?;
            send.close().await?;
        }

        Ok(())
    }

    /// Returns the number of `Connect` tasks
    pub fn task_connect_count(&self) -> usize {
        self.model.task_connect_count()
    }

    /// Returns the number of active UDP sessions
    pub fn task_associate_count(&self) -> usize {
        self.model.task_associate_count()
    }

    /// Removes packet fragments that can not be reassembled within the specified timeout
    pub fn collect_garbage(&self, timeout: Duration) {
        self.model.collect_garbage(timeout);
    }

    fn keying_material_exporter(&self) -> KeyingMaterialExporter {
        KeyingMaterialExporter(self.conn.clone())
    }
}

impl Connection<side::Client> {
    /// Creates a new client side `Connection`.
    pub fn new(conn: QuinnConnection) -> Self {
        Self {
            conn,
            model: ConnectionModel::new(),
            _marker: side::Client,
        }
    }

    /// Sends an `Authenticate` command.
    pub async fn authenticate(&self, uuid: Uuid, password: impl AsRef<[u8]>) -> Result<(), Error> {
        let model = self
            .model
            .send_authenticate(uuid, password, &self.keying_material_exporter());

        let mut send = self.conn.open_uni().await?;
        model.header().async_marshal(&mut send).await?;
        send.close().await?;
        Ok(())
    }

    /// Sends a `Connect` command.
    pub async fn connect(&self, addr: Address) -> Result<Connect, Error> {
        let model = self.model.send_connect(addr);
        let (mut send, recv) = self.conn.open_bi().await?;
        model.header().async_marshal(&mut send).await?;
        Ok(Connect::new(Side::Client(model), send, recv))
    }

    /// Sends a `Dissociate` command.
    pub async fn dissociate(&self, assoc_id: u16) -> Result<(), Error> {
        let model = self.model.send_dissociate(assoc_id);
        let mut send = self.conn.open_uni().await?;
        model.header().async_marshal(&mut send).await?;
        send.close().await?;
        Ok(())
    }

    /// Sends a `Heartbeat` command.
    pub async fn heartbeat(&self) -> Result<(), Error> {
        let model = self.model.send_heartbeat();
        let mut buf = Vec::with_capacity(model.header().len());
        model.header().async_marshal(&mut buf).await.unwrap();
        self.conn.send_datagram(Bytes::from(buf))?;
        Ok(())
    }

    /// Try to parse a `quinn::RecvStream` as a TUIC command.
    ///
    /// The `quinn::RecvStream` should be accepted by `quinn::Connection::accept_uni()` from the same `quinn::Connection`.
    pub async fn accept_uni_stream(&self, mut recv: RecvStream) -> Result<Task, Error> {
        let header = match Header::async_unmarshal(&mut recv).await {
            Ok(header) => header,
            Err(err) => return Err(Error::UnmarshalUniStream(err, recv)),
        };

        match header {
            Header::Authenticate(_) => Err(Error::BadCommandUniStream("authenticate", recv)),
            Header::Connect(_) => Err(Error::BadCommandUniStream("connect", recv)),
            Header::Packet(pkt) => {
                let assoc_id = pkt.assoc_id();
                let pkt_id = pkt.pkt_id();
                self.model
                    .recv_packet(pkt)
                    .map_or(Err(Error::InvalidUdpSession(assoc_id, pkt_id)), |pkt| {
                        Ok(Task::Packet(Packet::new(pkt, PacketSource::Quic(recv))))
                    })
            }
            Header::Dissociate(_) => Err(Error::BadCommandUniStream("dissociate", recv)),
            Header::Heartbeat(_) => Err(Error::BadCommandUniStream("heartbeat", recv)),
            _ => unreachable!(),
        }
    }

    /// Try to parse a pair of `quinn::SendStream` and `quinn::RecvStream` as a TUIC command.
    ///
    /// The pair of stream should be accepted by `quinn::Connection::accept_bi()` from the same `quinn::Connection`.
    pub async fn accept_bi_stream(
        &self,
        send: SendStream,
        mut recv: RecvStream,
    ) -> Result<Task, Error> {
        let header = match Header::async_unmarshal(&mut recv).await {
            Ok(header) => header,
            Err(err) => return Err(Error::UnmarshalBiStream(err, send, recv)),
        };

        match header {
            Header::Authenticate(_) => Err(Error::BadCommandBiStream("authenticate", send, recv)),
            Header::Connect(_) => Err(Error::BadCommandBiStream("connect", send, recv)),
            Header::Packet(_) => Err(Error::BadCommandBiStream("packet", send, recv)),
            Header::Dissociate(_) => Err(Error::BadCommandBiStream("dissociate", send, recv)),
            Header::Heartbeat(_) => Err(Error::BadCommandBiStream("heartbeat", send, recv)),
            _ => unreachable!(),
        }
    }

    /// Try to parse a QUIC Datagram as a TUIC command.
    ///
    /// The Datagram should be accepted by `quinn::Connection::read_datagram()` from the same `quinn::Connection`.
    pub fn accept_datagram(&self, dg: Bytes) -> Result<Task, Error> {
        let mut dg = Cursor::new(dg);

        let header = match Header::unmarshal(&mut dg) {
            Ok(header) => header,
            Err(err) => return Err(Error::UnmarshalDatagram(err, dg.into_inner())),
        };

        match header {
            Header::Authenticate(_) => {
                Err(Error::BadCommandDatagram("authenticate", dg.into_inner()))
            }
            Header::Connect(_) => Err(Error::BadCommandDatagram("connect", dg.into_inner())),
            Header::Packet(pkt) => {
                let assoc_id = pkt.assoc_id();
                let pkt_id = pkt.pkt_id();
                if let Some(pkt) = self.model.recv_packet(pkt) {
                    let pos = dg.position() as usize;
                    let mut buf = dg.into_inner();
                    if (pos + pkt.size() as usize) <= buf.len() {
                        buf = buf.slice(pos..pos + pkt.size() as usize);
                        Ok(Task::Packet(Packet::new(pkt, PacketSource::Native(buf))))
                    } else {
                        Err(Error::PayloadLength(pkt.size() as usize, buf.len() - pos))
                    }
                } else {
                    Err(Error::InvalidUdpSession(assoc_id, pkt_id))
                }
            }
            Header::Dissociate(_) => Err(Error::BadCommandDatagram("dissociate", dg.into_inner())),
            Header::Heartbeat(_) => Err(Error::BadCommandDatagram("heartbeat", dg.into_inner())),
            _ => unreachable!(),
        }
    }
}

impl Connection<side::Server> {
    /// Creates a new server side `Connection`.
    pub fn new(conn: QuinnConnection) -> Self {
        Self {
            conn,
            model: ConnectionModel::new(),
            _marker: side::Server,
        }
    }

    /// Try to parse a `quinn::RecvStream` as a TUIC command.
    ///
    /// The `quinn::RecvStream` should be accepted by `quinn::Connection::accept_uni()` from the same `quinn::Connection`.
    pub async fn accept_uni_stream(&self, mut recv: RecvStream) -> Result<Task, Error> {
        let header = match Header::async_unmarshal(&mut recv).await {
            Ok(header) => header,
            Err(err) => return Err(Error::UnmarshalUniStream(err, recv)),
        };

        match header {
            Header::Authenticate(auth) => {
                let model = self.model.recv_authenticate(auth);
                Ok(Task::Authenticate(Authenticate::new(
                    model,
                    self.keying_material_exporter(),
                )))
            }
            Header::Connect(_) => Err(Error::BadCommandUniStream("connect", recv)),
            Header::Packet(pkt) => {
                let model = self.model.recv_packet_unrestricted(pkt);
                Ok(Task::Packet(Packet::new(model, PacketSource::Quic(recv))))
            }
            Header::Dissociate(dissoc) => {
                let model = self.model.recv_dissociate(dissoc);
                Ok(Task::Dissociate(model.assoc_id()))
            }
            Header::Heartbeat(_) => Err(Error::BadCommandUniStream("heartbeat", recv)),
            _ => unreachable!(),
        }
    }

    /// Try to parse a pair of `quinn::SendStream` and `quinn::RecvStream` as a TUIC command.
    ///
    /// The pair of stream should be accepted by `quinn::Connection::accept_bi()` from the same `quinn::Connection`.
    pub async fn accept_bi_stream(
        &self,
        send: SendStream,
        mut recv: RecvStream,
    ) -> Result<Task, Error> {
        let header = match Header::async_unmarshal(&mut recv).await {
            Ok(header) => header,
            Err(err) => return Err(Error::UnmarshalBiStream(err, send, recv)),
        };

        match header {
            Header::Authenticate(_) => Err(Error::BadCommandBiStream("authenticate", send, recv)),
            Header::Connect(conn) => {
                let model = self.model.recv_connect(conn);
                Ok(Task::Connect(Connect::new(Side::Server(model), send, recv)))
            }
            Header::Packet(_) => Err(Error::BadCommandBiStream("packet", send, recv)),
            Header::Dissociate(_) => Err(Error::BadCommandBiStream("dissociate", send, recv)),
            Header::Heartbeat(_) => Err(Error::BadCommandBiStream("heartbeat", send, recv)),
            _ => unreachable!(),
        }
    }

    /// Try to parse a QUIC Datagram as a TUIC command.
    ///
    /// The Datagram should be accepted by `quinn::Connection::read_datagram()` from the same `quinn::Connection`.
    pub fn accept_datagram(&self, dg: Bytes) -> Result<Task, Error> {
        let mut dg = Cursor::new(dg);

        let header = match Header::unmarshal(&mut dg) {
            Ok(header) => header,
            Err(err) => return Err(Error::UnmarshalDatagram(err, dg.into_inner())),
        };

        match header {
            Header::Authenticate(_) => {
                Err(Error::BadCommandDatagram("authenticate", dg.into_inner()))
            }
            Header::Connect(_) => Err(Error::BadCommandDatagram("connect", dg.into_inner())),
            Header::Packet(pkt) => {
                let model = self.model.recv_packet_unrestricted(pkt);
                let pos = dg.position() as usize;
                let mut buf = dg.into_inner();
                if (pos + model.size() as usize) <= buf.len() {
                    buf = buf.slice(pos..pos + model.size() as usize);
                    Ok(Task::Packet(Packet::new(model, PacketSource::Native(buf))))
                } else {
                    Err(Error::PayloadLength(model.size() as usize, buf.len() - pos))
                }
            }
            Header::Dissociate(_) => Err(Error::BadCommandDatagram("dissociate", dg.into_inner())),
            Header::Heartbeat(hb) => {
                let _ = self.model.recv_heartbeat(hb);
                Ok(Task::Heartbeat)
            }
            _ => unreachable!(),
        }
    }
}

impl<Side> Debug for Connection<Side> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Connection")
            .field("conn", &self.conn)
            .field("model", &self.model)
            .finish()
    }
}

/// A received `Authenticate` command.
#[derive(Debug)]
pub struct Authenticate {
    model: AuthenticateModel<Rx>,
    exporter: KeyingMaterialExporter,
}

impl Authenticate {
    fn new(model: AuthenticateModel<Rx>, exporter: KeyingMaterialExporter) -> Self {
        Self { model, exporter }
    }

    /// The UUID of the client.
    pub fn uuid(&self) -> Uuid {
        self.model.uuid()
    }

    /// The hashed token.
    pub fn token(&self) -> [u8; 32] {
        self.model.token()
    }

    /// Validates if the given password is matching the hashed token.
    pub fn validate(&self, password: impl AsRef<[u8]>) -> bool {
        self.model.is_valid(password, &self.exporter)
    }
}

/// A received `Connect` command.
pub struct Connect {
    model: Side<ConnectModel<Tx>, ConnectModel<Rx>>,
    send: SendStream,
    recv: RecvStream,
}

impl Connect {
    fn new(
        model: Side<ConnectModel<Tx>, ConnectModel<Rx>>,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        Self { model, send, recv }
    }

    /// Returns the `Connect` address
    pub fn addr(&self) -> &Address {
        match &self.model {
            Side::Client(model) => {
                let Header::Connect(conn) = model.header() else {
                    unreachable!()
                };
                conn.addr()
            }
            Side::Server(model) => model.addr(),
        }
    }

    /// Immediately closes the `Connect` streams with the given error code. Returns the result of closing the send and receive streams, respectively.
    pub fn reset(
        &mut self,
        error_code: VarInt,
    ) -> (Result<(), ClosedStream>, Result<(), ClosedStream>) {
        let send_res = self.send.reset(error_code);
        let recv_res = self.recv.stop(error_code);
        (send_res, recv_res)
    }
}

impl AsyncRead for Connect {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for Connect {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        AsyncWrite::poll_close(Pin::new(&mut self.get_mut().send), cx)
    }
}

impl Debug for Connect {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let model = match &self.model {
            Side::Client(model) => model as &dyn Debug,
            Side::Server(model) => model as &dyn Debug,
        };

        f.debug_struct("Connect")
            .field("model", model)
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish()
    }
}

/// A received `Packet` command.
#[derive(Debug)]
pub struct Packet {
    model: PacketModel<Rx, Bytes>,
    src: PacketSource,
}

#[derive(Debug)]
enum PacketSource {
    Quic(RecvStream),
    Native(Bytes),
}

impl Packet {
    fn new(model: PacketModel<Rx, Bytes>, src: PacketSource) -> Self {
        Self { src, model }
    }

    /// Returns the UDP session ID
    pub fn assoc_id(&self) -> u16 {
        self.model.assoc_id()
    }

    /// Returns the packet ID
    pub fn pkt_id(&self) -> u16 {
        self.model.pkt_id()
    }

    /// Returns the fragment ID
    pub fn frag_id(&self) -> u8 {
        self.model.frag_id()
    }

    /// Returns the total number of fragments
    pub fn frag_total(&self) -> u8 {
        self.model.frag_total()
    }

    /// Whether the packet is from UDP relay mode `quic`
    pub fn is_from_quic(&self) -> bool {
        matches!(self.src, PacketSource::Quic(_))
    }

    /// Whether the packet is from UDP relay mode `native`
    pub fn is_from_native(&self) -> bool {
        matches!(self.src, PacketSource::Native(_))
    }

    /// Accepts the packet payload. If the packet is fragmented and not yet fully assembled, `Ok(None)` is returned.
    pub async fn accept(self) -> Result<Option<(Bytes, Address, u16)>, Error> {
        let pkt = match self.src {
            PacketSource::Quic(mut recv) => {
                let mut buf = vec![0; self.model.size() as usize];
                AsyncReadExt::read_exact(&mut recv, &mut buf).await?;
                Bytes::from(buf)
            }
            PacketSource::Native(pkt) => pkt,
        };

        let mut asm = Vec::new();

        Ok(self
            .model
            .assemble(pkt)?
            .map(|pkt| pkt.assemble(&mut asm))
            .map(|(addr, assoc_id)| (Bytes::from(asm), addr, assoc_id)))
    }
}

/// Type of tasks that can be received.
#[non_exhaustive]
#[derive(Debug)]
pub enum Task {
    Authenticate(Authenticate),
    Connect(Connect),
    Packet(Packet),
    Dissociate(u16),
    Heartbeat,
}

#[derive(Debug)]
struct KeyingMaterialExporter(QuinnConnection);

impl KeyingMaterialExporterImpl for KeyingMaterialExporter {
    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32] {
        let mut buf = [0; 32];
        self.0
            .export_keying_material(&mut buf, label, context)
            .unwrap();
        buf
    }
}

/// Errors that can occur when processing a task.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    SendDatagram(#[from] SendDatagramError),
    #[error("expecting payload length {0} but got {1}")]
    PayloadLength(usize, usize),
    #[error("packet {1:#06x} on invalid udp session {0:#06x}")]
    InvalidUdpSession(u16, u16),
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error("error unmarshalling uni_stream: {0}")]
    UnmarshalUniStream(UnmarshalError, RecvStream),
    #[error("error unmarshalling bi_stream: {0}")]
    UnmarshalBiStream(UnmarshalError, SendStream, RecvStream),
    #[error("error unmarshalling datagram: {0}")]
    UnmarshalDatagram(UnmarshalError, Bytes),
    #[error("bad command `{0}` from uni_stream")]
    BadCommandUniStream(&'static str, RecvStream),
    #[error("bad command `{0}` from bi_stream")]
    BadCommandBiStream(&'static str, SendStream, RecvStream),
    #[error("bad command `{0}` from datagram")]
    BadCommandDatagram(&'static str, Bytes),
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
    use rustls::{
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        RootCertStore,
    };
    use std::{
        collections::HashSet,
        future::Future,
        io::ErrorKind,
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };
    use tokio::time::timeout;
    use tuic::{
        Authenticate as AuthenticateHeader, Connect as ConnectHeader,
        Dissociate as DissociateHeader, Heartbeat as HeartbeatHeader, Packet as PacketHeader,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const ASSOC_ID: u16 = 0x1234;

    struct Fixture {
        client_endpoint: Endpoint,
        server_endpoint: Endpoint,
        client_raw: QuinnConnection,
        server_raw: QuinnConnection,
        client: Connection<side::Client>,
        server: Connection<side::Server>,
    }

    impl Fixture {
        async fn new() -> Self {
            Self::with_datagrams(true).await
        }

        async fn with_datagrams(datagrams_enabled: bool) -> Self {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate: CertificateDer<'static> = certified.cert.der().clone();
            let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

            let mut server_config =
                ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())
                    .unwrap();
            let mut server_transport = TransportConfig::default();
            if !datagrams_enabled {
                server_transport.datagram_receive_buffer_size(None);
            }
            server_config.transport_config(Arc::new(server_transport));

            let server_endpoint = Endpoint::server(server_config, loopback()).unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();

            let mut roots = RootCertStore::empty();
            roots.add(certificate).unwrap();
            let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
            let mut client_transport = TransportConfig::default();
            if !datagrams_enabled {
                client_transport.datagram_receive_buffer_size(None);
            }
            client_config.transport_config(Arc::new(client_transport));

            let mut client_endpoint = Endpoint::client(loopback()).unwrap();
            client_endpoint.set_default_client_config(client_config);

            let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
            let incoming = bounded(server_endpoint.accept())
                .await
                .expect("server endpoint closed before accepting a connection");
            let (client_raw, server_raw) =
                bounded(async { tokio::try_join!(connecting, incoming) })
                    .await
                    .unwrap();

            Self {
                client: Connection::<side::Client>::new(client_raw.clone()),
                server: Connection::<side::Server>::new(server_raw.clone()),
                client_endpoint,
                server_endpoint,
                client_raw,
                server_raw,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.client_endpoint.close(0_u32.into(), b"test complete");
            self.server_endpoint.close(0_u32.into(), b"test complete");
        }
    }

    async fn bounded<F>(future: F) -> F::Output
    where
        F: Future,
    {
        timeout(TEST_TIMEOUT, future)
            .await
            .expect("loopback QUIC operation timed out")
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    fn target() -> Address {
        Address::DomainAddress("example.com".into(), 443)
    }

    fn encode(header: &Header, payload: &[u8]) -> Bytes {
        let mut bytes = BytesMut::with_capacity(header.len() + payload.len());
        header.write(&mut bytes);
        bytes.extend_from_slice(payload);
        bytes.freeze()
    }

    fn packet_datagram(
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        advertised_size: u16,
        addr: Address,
        payload: &[u8],
    ) -> Bytes {
        encode(
            &Header::Packet(PacketHeader::new(
                assoc_id,
                pkt_id,
                frag_total,
                frag_id,
                advertised_size,
                addr,
            )),
            payload,
        )
    }

    async fn send_uni_bytes(connection: &QuinnConnection, bytes: &[u8]) {
        bounded(async {
            let mut send = connection.open_uni().await.unwrap();
            send.write_all(bytes).await.unwrap();
            send.close().await.unwrap();
        })
        .await;
    }

    async fn send_uni_header(connection: &QuinnConnection, header: &Header) {
        let bytes = encode(header, &[]);
        send_uni_bytes(connection, &bytes).await;
    }

    async fn send_bi_bytes(connection: &QuinnConnection, bytes: &[u8]) {
        bounded(async {
            let (mut send, _recv) = connection.open_bi().await.unwrap();
            send.write_all(bytes).await.unwrap();
            send.close().await.unwrap();
        })
        .await;
    }

    async fn send_bi_header(connection: &QuinnConnection, header: &Header) {
        let bytes = encode(header, &[]);
        send_bi_bytes(connection, &bytes).await;
    }

    async fn accept_server_uni(fixture: &Fixture) -> Result<Task, Error> {
        let recv = bounded(fixture.server_raw.accept_uni()).await.unwrap();
        bounded(fixture.server.accept_uni_stream(recv)).await
    }

    async fn accept_client_uni(fixture: &Fixture) -> Result<Task, Error> {
        let recv = bounded(fixture.client_raw.accept_uni()).await.unwrap();
        bounded(fixture.client.accept_uni_stream(recv)).await
    }

    async fn accept_server_bi(fixture: &Fixture) -> Result<Task, Error> {
        let (send, recv) = bounded(fixture.server_raw.accept_bi()).await.unwrap();
        bounded(fixture.server.accept_bi_stream(send, recv)).await
    }

    async fn accept_client_bi(fixture: &Fixture) -> Result<Task, Error> {
        let (send, recv) = bounded(fixture.client_raw.accept_bi()).await.unwrap();
        bounded(fixture.client.accept_bi_stream(send, recv)).await
    }

    async fn accept_server_datagram(fixture: &Fixture) -> Result<Task, Error> {
        let datagram = bounded(fixture.server_raw.read_datagram()).await.unwrap();
        fixture.server.accept_datagram(datagram)
    }

    async fn accept_client_datagram(fixture: &Fixture) -> Result<Task, Error> {
        let datagram = bounded(fixture.client_raw.read_datagram()).await.unwrap();
        fixture.client.accept_datagram(datagram)
    }

    fn expect_authenticate(task: Task) -> Authenticate {
        match task {
            Task::Authenticate(authenticate) => authenticate,
            other => panic!("expected authenticate task, got {other:?}"),
        }
    }

    fn expect_connect(task: Task) -> Connect {
        match task {
            Task::Connect(connect) => connect,
            other => panic!("expected connect task, got {other:?}"),
        }
    }

    fn expect_packet(task: Task) -> Packet {
        match task {
            Task::Packet(packet) => packet,
            other => panic!("expected packet task, got {other:?}"),
        }
    }

    fn assert_bad_uni(error: Error, expected: &'static str) {
        match error {
            Error::BadCommandUniStream(command, _) => assert_eq!(command, expected),
            other => panic!("expected bad {expected} uni-stream command, got {other:?}"),
        }
    }

    fn assert_bad_bi(error: Error, expected: &'static str) {
        match error {
            Error::BadCommandBiStream(command, _, _) => assert_eq!(command, expected),
            other => panic!("expected bad {expected} bi-stream command, got {other:?}"),
        }
    }

    fn assert_bad_datagram(error: Error, expected: &'static str) {
        match error {
            Error::BadCommandDatagram(command, _) => assert_eq!(command, expected),
            other => panic!("expected bad {expected} datagram command, got {other:?}"),
        }
    }

    fn command_headers() -> Vec<(&'static str, Header)> {
        vec![
            (
                "authenticate",
                Header::Authenticate(AuthenticateHeader::new(Uuid::nil(), [0; 32])),
            ),
            ("connect", Header::Connect(ConnectHeader::new(target()))),
            (
                "packet",
                Header::Packet(PacketHeader::new(ASSOC_ID, 0, 1, 0, 0, target())),
            ),
            (
                "dissociate",
                Header::Dissociate(DissociateHeader::new(ASSOC_ID)),
            ),
            ("heartbeat", Header::Heartbeat(HeartbeatHeader::new())),
        ]
    }

    #[tokio::test]
    async fn loopback_connection_setup_and_cleanup() {
        let fixture = Fixture::new().await;

        assert_eq!(
            fixture.client_raw.remote_address(),
            fixture.server_endpoint.local_addr().unwrap()
        );
        assert_eq!(
            fixture.server_raw.remote_address(),
            fixture.client_endpoint.local_addr().unwrap()
        );

        fixture
            .client_raw
            .close(VarInt::from_u32(7), b"fixture cleanup");
        let (client_error, server_error) = bounded(async {
            tokio::join!(fixture.client_raw.closed(), fixture.server_raw.closed())
        })
        .await;
        assert!(matches!(client_error, ConnectionError::LocallyClosed));
        assert!(matches!(
            server_error,
            ConnectionError::ApplicationClosed(_)
        ));

        fixture.client_endpoint.close(0_u32.into(), &[]);
        fixture.server_endpoint.close(0_u32.into(), &[]);
        bounded(async {
            tokio::join!(
                fixture.client_endpoint.wait_idle(),
                fixture.server_endpoint.wait_idle()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn authenticate_round_trip_validates_credentials_and_token() {
        let fixture = Fixture::new().await;
        let uuid = Uuid::from_u128(0x00112233_4455_6677_8899_aabbccddeeff);
        let password = b"correct horse battery staple";

        bounded(fixture.client.authenticate(uuid, password))
            .await
            .unwrap();
        let authenticate = expect_authenticate(accept_server_uni(&fixture).await.unwrap());
        let token = authenticate.token();
        assert_eq!(authenticate.uuid(), uuid);
        assert!(authenticate.validate(password));
        assert!(!authenticate.validate(b"incorrect password"));

        bounded(fixture.client.authenticate(uuid, password))
            .await
            .unwrap();
        let repeated = expect_authenticate(accept_server_uni(&fixture).await.unwrap());
        assert_eq!(repeated.token(), token);
    }

    #[tokio::test]
    async fn connect_round_trip_transfers_data_and_tracks_tasks() {
        let fixture = Fixture::new().await;
        let addr = target();
        assert_eq!(fixture.client.task_connect_count(), 0);
        assert_eq!(fixture.server.task_connect_count(), 0);

        let mut client = bounded(fixture.client.connect(addr.clone())).await.unwrap();
        assert_eq!(fixture.client.task_connect_count(), 1);
        let mut server = expect_connect(accept_server_bi(&fixture).await.unwrap());
        assert_eq!(fixture.server.task_connect_count(), 1);
        assert_eq!(client.addr(), &addr);
        assert_eq!(server.addr(), &addr);

        bounded(async {
            client.write_all(b"client to server").await.unwrap();
            client.flush().await.unwrap();
            let mut from_client = [0; 16];
            server.read_exact(&mut from_client).await.unwrap();
            assert_eq!(&from_client, b"client to server");

            server.write_all(b"server to client").await.unwrap();
            server.flush().await.unwrap();
            let mut from_server = [0; 16];
            client.read_exact(&mut from_server).await.unwrap();
            assert_eq!(&from_server, b"server to client");
        })
        .await;

        drop(server);
        assert_eq!(fixture.server.task_connect_count(), 0);
        assert_eq!(fixture.client.task_connect_count(), 1);
        drop(client);
        assert_eq!(fixture.client.task_connect_count(), 0);
    }

    #[tokio::test]
    async fn connect_reset_stops_both_peer_directions() {
        let fixture = Fixture::new().await;
        let mut client = bounded(fixture.client.connect(target())).await.unwrap();
        let mut server = expect_connect(accept_server_bi(&fixture).await.unwrap());

        let (send_result, recv_result) = server.reset(VarInt::from_u32(42));
        assert!(send_result.is_ok());
        assert!(recv_result.is_ok());

        let mut byte = [0];
        assert!(bounded(client.read(&mut byte)).await.is_err());
        assert!(bounded(client.write_all(b"after reset")).await.is_err());

        drop(server);
        drop(client);
        assert_eq!(fixture.server.task_connect_count(), 0);
        assert_eq!(fixture.client.task_connect_count(), 0);
    }

    #[tokio::test]
    async fn heartbeat_datagram_round_trip() {
        let fixture = Fixture::new().await;

        bounded(fixture.client.heartbeat()).await.unwrap();
        assert!(matches!(
            accept_server_datagram(&fixture).await.unwrap(),
            Task::Heartbeat
        ));
    }

    #[tokio::test]
    async fn dissociate_round_trip_removes_association() {
        let fixture = Fixture::new().await;
        fixture
            .client
            .packet_native(b"association seed", target(), ASSOC_ID)
            .unwrap();
        let packet = expect_packet(accept_server_datagram(&fixture).await.unwrap());
        assert!(bounded(packet.accept()).await.unwrap().is_some());
        assert_eq!(fixture.client.task_associate_count(), 1);
        assert_eq!(fixture.server.task_associate_count(), 1);

        bounded(fixture.client.dissociate(ASSOC_ID)).await.unwrap();
        assert_eq!(fixture.client.task_associate_count(), 0);
        match accept_server_uni(&fixture).await.unwrap() {
            Task::Dissociate(assoc_id) => assert_eq!(assoc_id, ASSOC_ID),
            other => panic!("expected dissociate task, got {other:?}"),
        }
        assert_eq!(fixture.server.task_associate_count(), 0);
    }

    #[tokio::test]
    async fn native_packet_round_trip_exposes_metadata() {
        let fixture = Fixture::new().await;
        let addr = target();
        let payload = b"native packet";

        fixture
            .client
            .packet_native(payload, addr.clone(), ASSOC_ID)
            .unwrap();
        let packet = expect_packet(accept_server_datagram(&fixture).await.unwrap());
        assert_eq!(packet.assoc_id(), ASSOC_ID);
        assert_eq!(packet.pkt_id(), 0);
        assert_eq!(packet.frag_total(), 1);
        assert_eq!(packet.frag_id(), 0);
        assert!(packet.is_from_native());
        assert!(!packet.is_from_quic());

        let (received, received_addr, received_assoc_id) =
            bounded(packet.accept()).await.unwrap().unwrap();
        assert_eq!(received.as_ref(), payload);
        assert_eq!(received_addr, addr);
        assert_eq!(received_assoc_id, ASSOC_ID);
    }

    #[tokio::test]
    async fn empty_native_packet_round_trip() {
        let fixture = Fixture::new().await;
        let addr = target();

        fixture
            .client
            .packet_native([], addr.clone(), ASSOC_ID)
            .unwrap();
        let packet = expect_packet(accept_server_datagram(&fixture).await.unwrap());
        assert_eq!(packet.frag_total(), 1);
        assert_eq!(packet.frag_id(), 0);
        let (received, received_addr, received_assoc_id) =
            bounded(packet.accept()).await.unwrap().unwrap();
        assert!(received.is_empty());
        assert_eq!(received_addr, addr);
        assert_eq!(received_assoc_id, ASSOC_ID);
    }

    #[tokio::test]
    async fn native_fragmented_packet_reassembles() {
        let fixture = Fixture::new().await;
        let addr = target();
        let max_datagram_size = fixture.client_raw.max_datagram_size().unwrap();
        let payload: Vec<u8> = (0..max_datagram_size * 3)
            .map(|index| (index % 251) as u8)
            .collect();

        fixture
            .client
            .packet_native(&payload, addr.clone(), ASSOC_ID)
            .unwrap();

        let first = expect_packet(accept_server_datagram(&fixture).await.unwrap());
        let fragment_total = first.frag_total();
        assert!(fragment_total > 1);
        let mut packets = vec![first];
        for _ in 1..fragment_total {
            packets.push(expect_packet(
                accept_server_datagram(&fixture).await.unwrap(),
            ));
        }

        let mut fragment_ids = HashSet::new();
        let mut assembled = None;
        for packet in packets {
            assert_eq!(packet.assoc_id(), ASSOC_ID);
            assert_eq!(packet.pkt_id(), 0);
            assert_eq!(packet.frag_total(), fragment_total);
            assert!(packet.is_from_native());
            assert!(fragment_ids.insert(packet.frag_id()));
            if let Some(result) = bounded(packet.accept()).await.unwrap() {
                assert!(assembled.replace(result).is_none());
            }
        }

        assert_eq!(fragment_ids.len(), fragment_total as usize);
        let (received, received_addr, received_assoc_id) = assembled.unwrap();
        assert_eq!(received.as_ref(), payload.as_slice());
        assert_eq!(received_addr, addr);
        assert_eq!(received_assoc_id, ASSOC_ID);
    }

    #[tokio::test]
    async fn native_fragments_reassemble_out_of_order() {
        let fixture = Fixture::new().await;
        let addr = target();
        let fragments: [(u8, Address, &[u8]); 3] = [
            (2, Address::None, b"third"),
            (0, addr.clone(), b"first-"),
            (1, Address::None, b"second-"),
        ];

        for (index, (frag_id, frag_addr, payload)) in fragments.into_iter().enumerate() {
            fixture
                .client_raw
                .send_datagram(packet_datagram(
                    ASSOC_ID,
                    0x3344,
                    3,
                    frag_id,
                    payload.len() as u16,
                    frag_addr,
                    payload,
                ))
                .unwrap();
            let packet = expect_packet(accept_server_datagram(&fixture).await.unwrap());
            assert_eq!(packet.frag_id(), frag_id);
            let accepted = bounded(packet.accept()).await.unwrap();
            if index < 2 {
                assert!(accepted.is_none());
            } else {
                let (received, received_addr, received_assoc_id) = accepted.unwrap();
                assert_eq!(received.as_ref(), b"first-second-third");
                assert_eq!(received_addr, addr);
                assert_eq!(received_assoc_id, ASSOC_ID);
            }
        }
    }

    #[tokio::test]
    async fn quic_packets_deliver_single_and_fragmented_payloads() {
        let fixture = Fixture::new().await;
        let addr = target();

        fixture
            .client
            .packet_native(b"association seed", addr.clone(), ASSOC_ID)
            .unwrap();
        let seed = expect_packet(accept_server_datagram(&fixture).await.unwrap());
        assert!(bounded(seed.accept()).await.unwrap().is_some());

        bounded(
            fixture
                .server
                .packet_quic(b"single quic packet", addr.clone(), ASSOC_ID),
        )
        .await
        .unwrap();
        let single = expect_packet(accept_client_uni(&fixture).await.unwrap());
        assert_eq!(single.assoc_id(), ASSOC_ID);
        assert_eq!(single.pkt_id(), 0);
        assert_eq!(single.frag_total(), 1);
        assert_eq!(single.frag_id(), 0);
        assert!(single.is_from_quic());
        assert!(!single.is_from_native());
        let (received, received_addr, received_assoc_id) =
            bounded(single.accept()).await.unwrap().unwrap();
        assert_eq!(received.as_ref(), b"single quic packet");
        assert_eq!(received_addr, addr);
        assert_eq!(received_assoc_id, ASSOC_ID);

        let payload: Vec<u8> = (0..70_000).map(|index| (index % 251) as u8).collect();
        bounded(fixture.server.packet_quic(&payload, addr.clone(), ASSOC_ID))
            .await
            .unwrap();

        let first = expect_packet(accept_client_uni(&fixture).await.unwrap());
        let fragment_total = first.frag_total();
        assert!(fragment_total > 1);
        let mut packets = vec![first];
        for _ in 1..fragment_total {
            packets.push(expect_packet(accept_client_uni(&fixture).await.unwrap()));
        }

        let mut assembled = None;
        for packet in packets {
            assert_eq!(packet.assoc_id(), ASSOC_ID);
            assert_eq!(packet.pkt_id(), 1);
            assert_eq!(packet.frag_total(), fragment_total);
            assert!(packet.is_from_quic());
            if let Some(result) = bounded(packet.accept()).await.unwrap() {
                assert!(assembled.replace(result).is_none());
            }
        }
        let (received, received_addr, received_assoc_id) = assembled.unwrap();
        assert_eq!(received.as_ref(), payload.as_slice());
        assert_eq!(received_addr, addr);
        assert_eq!(received_assoc_id, ASSOC_ID);
    }

    #[tokio::test]
    async fn client_rejects_packets_for_unknown_association() {
        let fixture = Fixture::new().await;

        fixture
            .server
            .packet_native(b"native", target(), 0xaaaa)
            .unwrap();
        match accept_client_datagram(&fixture).await.unwrap_err() {
            Error::InvalidUdpSession(assoc_id, pkt_id) => {
                assert_eq!((assoc_id, pkt_id), (0xaaaa, 0));
            }
            other => panic!("expected invalid native UDP session, got {other:?}"),
        }

        bounded(fixture.server.packet_quic(b"quic", target(), 0xbbbb))
            .await
            .unwrap();
        match accept_client_uni(&fixture).await.unwrap_err() {
            Error::InvalidUdpSession(assoc_id, pkt_id) => {
                assert_eq!((assoc_id, pkt_id), (0xbbbb, 0));
            }
            other => panic!("expected invalid QUIC UDP session, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_rejects_commands_on_wrong_transports() {
        let fixture = Fixture::new().await;

        for (name, header) in command_headers()
            .into_iter()
            .filter(|(name, _)| matches!(*name, "connect" | "heartbeat"))
        {
            send_uni_header(&fixture.client_raw, &header).await;
            assert_bad_uni(accept_server_uni(&fixture).await.unwrap_err(), name);
        }

        for (name, header) in command_headers()
            .into_iter()
            .filter(|(name, _)| *name != "connect")
        {
            send_bi_header(&fixture.client_raw, &header).await;
            assert_bad_bi(accept_server_bi(&fixture).await.unwrap_err(), name);
        }

        for (name, header) in command_headers()
            .into_iter()
            .filter(|(name, _)| matches!(*name, "authenticate" | "connect" | "dissociate"))
        {
            fixture
                .client_raw
                .send_datagram(encode(&header, &[]))
                .unwrap();
            assert_bad_datagram(accept_server_datagram(&fixture).await.unwrap_err(), name);
        }
    }

    #[tokio::test]
    async fn client_rejects_commands_on_wrong_transports() {
        let fixture = Fixture::new().await;

        for (name, header) in command_headers()
            .into_iter()
            .filter(|(name, _)| *name != "packet")
        {
            send_uni_header(&fixture.server_raw, &header).await;
            assert_bad_uni(accept_client_uni(&fixture).await.unwrap_err(), name);
        }

        for (name, header) in command_headers() {
            send_bi_header(&fixture.server_raw, &header).await;
            assert_bad_bi(accept_client_bi(&fixture).await.unwrap_err(), name);
        }

        for (name, header) in command_headers()
            .into_iter()
            .filter(|(name, _)| *name != "packet")
        {
            fixture
                .server_raw
                .send_datagram(encode(&header, &[]))
                .unwrap();
            assert_bad_datagram(accept_client_datagram(&fixture).await.unwrap_err(), name);
        }
    }

    #[tokio::test]
    async fn malformed_headers_preserve_transport_and_unmarshal_errors() {
        let fixture = Fixture::new().await;

        send_uni_bytes(&fixture.client_raw, &[0x04, Header::TYPE_CODE_HEARTBEAT]).await;
        match accept_server_uni(&fixture).await.unwrap_err() {
            Error::UnmarshalUniStream(UnmarshalError::InvalidVersion(0x04), _) => {}
            other => panic!("expected invalid-version uni-stream error, got {other:?}"),
        }

        send_bi_bytes(&fixture.client_raw, &[tuic::VERSION, 0xfe]).await;
        match accept_server_bi(&fixture).await.unwrap_err() {
            Error::UnmarshalBiStream(UnmarshalError::InvalidCommand(0xfe), _, _) => {}
            other => panic!("expected invalid-command bi-stream error, got {other:?}"),
        }

        let malformed_datagram =
            Bytes::from_static(&[tuic::VERSION, Header::TYPE_CODE_CONNECT, 0xfe]);
        fixture
            .client_raw
            .send_datagram(malformed_datagram.clone())
            .unwrap();
        match accept_server_datagram(&fixture).await.unwrap_err() {
            Error::UnmarshalDatagram(UnmarshalError::InvalidAddressType(0xfe), bytes) => {
                assert_eq!(bytes, malformed_datagram);
            }
            other => panic!("expected invalid-address datagram error, got {other:?}"),
        }

        fixture
            .client_raw
            .send_datagram(Bytes::from_static(&[tuic::VERSION]))
            .unwrap();
        match accept_server_datagram(&fixture).await.unwrap_err() {
            Error::UnmarshalDatagram(UnmarshalError::Io(error), _) => {
                assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
            }
            other => panic!("expected truncated datagram error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disabled_datagrams_return_send_errors() {
        let fixture = Fixture::with_datagrams(false).await;
        assert!(fixture.client_raw.max_datagram_size().is_none());
        assert!(matches!(
            fixture.client.packet_native(b"packet", target(), ASSOC_ID),
            Err(Error::SendDatagram(SendDatagramError::Disabled))
        ));
        assert!(matches!(
            bounded(fixture.client.heartbeat()).await,
            Err(Error::SendDatagram(SendDatagramError::Disabled))
        ));
    }

    #[tokio::test]
    async fn truncated_native_payload_returns_length_error_on_both_sides() {
        let fixture = Fixture::new().await;
        let addr = target();

        fixture
            .client_raw
            .send_datagram(packet_datagram(ASSOC_ID, 7, 1, 0, 5, addr.clone(), b"xy"))
            .unwrap();
        match accept_server_datagram(&fixture).await.unwrap_err() {
            Error::PayloadLength(expected, actual) => assert_eq!((expected, actual), (5, 2)),
            other => panic!("expected server payload-length error, got {other:?}"),
        }

        fixture
            .client
            .packet_native(b"association seed", addr.clone(), ASSOC_ID)
            .unwrap();
        let seed = expect_packet(accept_server_datagram(&fixture).await.unwrap());
        assert!(bounded(seed.accept()).await.unwrap().is_some());

        fixture
            .server_raw
            .send_datagram(packet_datagram(ASSOC_ID, 8, 1, 0, 6, addr, b"abc"))
            .unwrap();
        match accept_client_datagram(&fixture).await.unwrap_err() {
            Error::PayloadLength(expected, actual) => assert_eq!((expected, actual), (6, 3)),
            other => panic!("expected client payload-length error, got {other:?}"),
        }
    }
}
