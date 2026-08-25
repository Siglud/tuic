use self::{authenticated::Authenticated, udp_session::UdpSession};
use crate::{error::Error, utils::UdpRelayMode};
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use quinn::{Connecting, Connection as QuinnConnection, ConnectionError, ConnectionStats, VarInt};
use register_count::Counter;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};
use tokio::time;
use tuic_quinn::{side, Authenticate, Connection as Model};
use uuid::Uuid;

mod authenticated;
mod handle_stream;
mod handle_task;
mod udp_session;

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
pub const DEFAULT_CONCURRENT_STREAMS: u32 = 32;

#[derive(Debug)]
struct ConnectionDiagnostics {
    age: Duration,
    close_reason: Option<ConnectionError>,
    stats: ConnectionStats,
    active_remote_uni_streams: usize,
    active_remote_bi_streams: usize,
    max_remote_uni_streams: u32,
    max_remote_bi_streams: u32,
    active_connect_tasks: usize,
    active_udp_associations: usize,
    udp_relay_mode: Option<&'static str>,
    udp_sessions: usize,
}

impl Display for ConnectionDiagnostics {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "age={:?} close_reason={:?} udp_tx={:?} udp_rx={:?} frame_tx={:?} frame_rx={:?} path={:?} active_remote_streams=uni:{}/bi:{} max_remote_streams=uni:{}/bi:{} active_tasks=connect:{}/udp:{} udp_mode={:?} udp_sessions={}",
            self.age,
            self.close_reason,
            self.stats.udp_tx,
            self.stats.udp_rx,
            self.stats.frame_tx,
            self.stats.frame_rx,
            self.stats.path,
            self.active_remote_uni_streams,
            self.active_remote_bi_streams,
            self.max_remote_uni_streams,
            self.max_remote_bi_streams,
            self.active_connect_tasks,
            self.active_udp_associations,
            self.udp_relay_mode,
            self.udp_sessions,
        )
    }
}

#[derive(Clone)]
pub struct Connection {
    inner: QuinnConnection,
    model: Model<side::Server>,
    users: Arc<HashMap<Uuid, Box<[u8]>>>,
    udp_relay_ipv6: bool,
    auth: Authenticated,
    task_negotiation_timeout: Duration,
    udp_sessions: Arc<Mutex<HashMap<u16, UdpSession>>>,
    udp_relay_mode: Arc<AtomicCell<Option<UdpRelayMode>>>,
    max_external_pkt_size: usize,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
    established_at: Instant,
}

#[allow(clippy::too_many_arguments)]
impl Connection {
    pub async fn handle(
        conn: Connecting,
        users: Arc<HashMap<Uuid, Box<[u8]>>>,
        udp_relay_ipv6: bool,
        zero_rtt_handshake: bool,
        auth_timeout: Duration,
        task_negotiation_timeout: Duration,
        max_external_pkt_size: usize,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        let addr = conn.remote_address();

        let init = async {
            let conn = if zero_rtt_handshake {
                match conn.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(conn) => conn.await?,
                }
            } else {
                conn.await?
            };

            Ok::<_, Error>(Self::new(
                conn,
                users,
                udp_relay_ipv6,
                task_negotiation_timeout,
                max_external_pkt_size,
            ))
        };

        match init.await {
            Ok(conn) => {
                log::info!(
                    "[{id:#010x}] [{addr}] [{user}] connection established",
                    id = conn.id(),
                    user = conn.auth,
                );

                tokio::spawn(conn.clone().timeout_authenticate(auth_timeout));
                tokio::spawn(conn.clone().collect_garbage(gc_interval, gc_lifetime));

                loop {
                    if conn.is_closed() {
                        break;
                    }

                    let handle_incoming = async {
                        tokio::select! {
                            res = conn.inner.accept_uni() =>
                                tokio::spawn(conn.clone().handle_uni_stream(res?, conn.remote_uni_stream_cnt.reg())),
                            res = conn.inner.accept_bi() =>
                                tokio::spawn(conn.clone().handle_bi_stream(res?, conn.remote_bi_stream_cnt.reg())),
                            res = conn.inner.read_datagram() =>
                                tokio::spawn(conn.clone().handle_datagram(res?)),
                        };

                        Ok::<_, Error>(())
                    };

                    match handle_incoming.await {
                        Ok(()) => {}
                        Err(err) if err.is_trivial() => {
                            log::debug!(
                                "[{id:#010x}] [{addr}] [{user}] {err}",
                                id = conn.id(),
                                user = conn.auth,
                            );
                        }
                        Err(err) => conn.log_connection_error(&err),
                    }
                }

                conn.close_udp_sessions();
            }
            Err(err) if err.is_trivial() => {
                log::debug!(
                    "[{id:#010x}] [{addr}] [unauthenticated] {err}",
                    id = u32::MAX,
                );
            }
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [unauthenticated] {err}",
                    id = u32::MAX,
                )
            }
        }
    }

    fn new(
        conn: QuinnConnection,
        users: Arc<HashMap<Uuid, Box<[u8]>>>,
        udp_relay_ipv6: bool,
        task_negotiation_timeout: Duration,
        max_external_pkt_size: usize,
    ) -> Self {
        Self {
            inner: conn.clone(),
            model: Model::<side::Server>::new(conn),
            users,
            udp_relay_ipv6,
            auth: Authenticated::new(),
            task_negotiation_timeout,
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            udp_relay_mode: Arc::new(AtomicCell::new(None)),
            max_external_pkt_size,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
            established_at: Instant::now(),
        }
    }

    fn authenticate(&self, auth: &Authenticate) -> Result<(), Error> {
        if self.auth.get().is_some() {
            Err(Error::DuplicatedAuth)
        } else if self
            .users
            .get(&auth.uuid())
            .is_some_and(|password| auth.validate(password))
        {
            self.auth.set(auth.uuid());
            Ok(())
        } else {
            Err(Error::AuthFailed(auth.uuid()))
        }
    }

    async fn timeout_authenticate(self, timeout: Duration) {
        time::sleep(timeout).await;

        if self.auth.get().is_none() {
            log::warn!(
                "[{id:#010x}] [{addr}] [unauthenticated] [authenticate] timeout",
                id = self.id(),
                addr = self.inner.remote_address(),
            );
            self.close();
        }
    }

    async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
        loop {
            time::sleep(gc_interval).await;

            if self.is_closed() {
                break;
            }

            log::debug!(
                "[{id:#010x}] [{addr}] [{user}] connection diagnostics: {diagnostics}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                diagnostics = self.diagnostics(),
            );
            self.model.collect_garbage(gc_lifetime);
        }
    }

    fn id(&self) -> u32 {
        self.inner.stable_id() as u32
    }

    fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    fn close(&self) {
        self.inner.close(ERROR_CODE, &[]);
    }

    fn close_udp_sessions(&self) {
        let sessions = std::mem::take(&mut *self.udp_sessions.lock());
        for session in sessions.into_values() {
            session.close();
        }
    }

    fn diagnostics(&self) -> ConnectionDiagnostics {
        ConnectionDiagnostics {
            age: self.established_at.elapsed(),
            close_reason: self.inner.close_reason(),
            stats: self.inner.stats(),
            active_remote_uni_streams: self.remote_uni_stream_cnt.count(),
            active_remote_bi_streams: self.remote_bi_stream_cnt.count(),
            max_remote_uni_streams: self
                .max_concurrent_uni_streams
                .load(std::sync::atomic::Ordering::Relaxed),
            max_remote_bi_streams: self
                .max_concurrent_bi_streams
                .load(std::sync::atomic::Ordering::Relaxed),
            active_connect_tasks: self.model.task_connect_count(),
            active_udp_associations: self.model.task_associate_count(),
            udp_relay_mode: match self.udp_relay_mode.load() {
                Some(UdpRelayMode::Native) => Some("native"),
                Some(UdpRelayMode::Quic) => Some("quic"),
                None => None,
            },
            udp_sessions: self.udp_sessions.lock().len(),
        }
    }

    fn log_connection_error(&self, err: &Error) {
        log::warn!(
            "[{id:#010x}] [{addr}] [{user}] connection error: {err}; error={err:?}; diagnostics={diagnostics}",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
            diagnostics = self.diagnostics(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use rustls::{
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        RootCertStore,
    };
    use std::{future::Future, net::Ipv4Addr};
    use tokio::time::{self, timeout};
    use tuic_quinn::{side, Connection as ModelConnection, Task};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const UUID: Uuid = Uuid::from_u128(0x00112233_4455_6677_8899_aabbccddeeff);
    const PASSWORD: &[u8] = b"correct horse battery staple";

    struct Fixture {
        client_endpoint: Endpoint,
        server_endpoint: Endpoint,
        client: ModelConnection<side::Client>,
        server: Connection,
    }

    impl Fixture {
        async fn new() -> Self {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate: CertificateDer<'static> = certified.cert.der().clone();
            let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
            let server_config =
                ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())
                    .unwrap();
            let server_endpoint = Endpoint::server(server_config, loopback()).unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();

            let mut roots = RootCertStore::empty();
            roots.add(certificate).unwrap();
            let client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
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

            let mut users = HashMap::new();
            users.insert(UUID, Box::from(PASSWORD));
            let server = Connection::new(
                server_raw,
                Arc::new(users),
                false,
                Duration::from_secs(3),
                1500,
            );

            Self {
                client_endpoint,
                server_endpoint,
                client: ModelConnection::<side::Client>::new(client_raw),
                server,
            }
        }

        async fn authenticate(&self, uuid: Uuid, password: &[u8]) -> Authenticate {
            bounded(self.client.authenticate(uuid, password))
                .await
                .unwrap();
            let recv = bounded(self.server.inner.accept_uni()).await.unwrap();
            let task = bounded(self.server.model.accept_uni_stream(recv))
                .await
                .unwrap();

            match task {
                Task::Authenticate(authenticate) => authenticate,
                other => panic!("expected authenticate task, got {other:?}"),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.client_endpoint.close(ERROR_CODE, b"test complete");
            self.server_endpoint.close(ERROR_CODE, b"test complete");
        }
    }

    async fn bounded<F: Future>(future: F) -> F::Output {
        timeout(TEST_TIMEOUT, future)
            .await
            .expect("loopback QUIC operation timed out")
    }

    fn loopback() -> std::net::SocketAddr {
        std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    #[tokio::test]
    async fn authenticate_accepts_valid_credentials_and_rejects_duplicate() {
        let fixture = Fixture::new().await;
        let authenticate = fixture.authenticate(UUID, PASSWORD).await;

        assert!(fixture.server.authenticate(&authenticate).is_ok());
        assert_eq!(fixture.server.auth.get(), Some(UUID));
        assert!(matches!(
            fixture.server.authenticate(&authenticate),
            Err(Error::DuplicatedAuth)
        ));
    }

    #[tokio::test]
    async fn authenticate_rejects_wrong_password_and_unknown_user() {
        let fixture = Fixture::new().await;
        let wrong_password = fixture.authenticate(UUID, b"wrong password").await;
        assert!(matches!(
            fixture.server.authenticate(&wrong_password),
            Err(Error::AuthFailed(uuid)) if uuid == UUID
        ));

        let unknown_uuid = Uuid::from_u128(0xffeeddcc_bbaa_9988_7766_554433221100);
        let unknown = fixture.authenticate(unknown_uuid, PASSWORD).await;
        assert!(matches!(
            fixture.server.authenticate(&unknown),
            Err(Error::AuthFailed(uuid)) if uuid == unknown_uuid
        ));
        assert_eq!(fixture.server.auth.get(), None);
    }

    #[tokio::test]
    async fn authentication_timeout_closes_unauthenticated_connection() {
        let fixture = Fixture::new().await;
        time::pause();
        let server = fixture.server.clone();
        let task = tokio::spawn(server.clone().timeout_authenticate(Duration::from_secs(1)));
        tokio::task::yield_now().await;

        time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();

        assert!(server.is_closed());
        assert!(matches!(
            server.inner.close_reason(),
            Some(quinn::ConnectionError::LocallyClosed)
        ));
    }

    #[tokio::test]
    async fn authentication_timeout_preserves_authenticated_connection() {
        let fixture = Fixture::new().await;
        fixture.server.auth.set(UUID);
        time::pause();
        let server = fixture.server.clone();
        let task = tokio::spawn(server.clone().timeout_authenticate(Duration::from_secs(1)));
        tokio::task::yield_now().await;

        time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();

        assert!(!server.is_closed());
    }

    #[tokio::test]
    async fn connection_cleanup_drains_udp_sessions() {
        let fixture = Fixture::new().await;
        let session = UdpSession::new(fixture.server.clone(), 7, false, 1500).unwrap();
        fixture
            .server
            .udp_sessions
            .lock()
            .insert(7, session.clone());

        fixture.server.close_udp_sessions();

        assert!(fixture.server.udp_sessions.lock().is_empty());
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn diagnostics_preserve_close_reason_and_runtime_state() {
        let fixture = Fixture::new().await;
        fixture
            .server
            .udp_relay_mode
            .store(Some(UdpRelayMode::Quic));
        fixture.server.close();
        bounded(fixture.server.inner.closed()).await;

        let diagnostics = fixture.server.diagnostics();

        assert!(matches!(
            diagnostics.close_reason,
            Some(ConnectionError::LocallyClosed)
        ));
        assert_eq!(diagnostics.udp_relay_mode, Some("quic"));
        assert_eq!(
            diagnostics.max_remote_uni_streams,
            DEFAULT_CONCURRENT_STREAMS
        );
        assert_eq!(
            diagnostics.max_remote_bi_streams,
            DEFAULT_CONCURRENT_STREAMS
        );
        assert_eq!(diagnostics.active_remote_uni_streams, 0);
        assert_eq!(diagnostics.active_remote_bi_streams, 0);
        assert_eq!(diagnostics.active_connect_tasks, 0);
        assert_eq!(diagnostics.active_udp_associations, 0);
        assert_eq!(diagnostics.udp_sessions, 0);
        assert!(diagnostics.stats.udp_rx.datagrams > 0);
    }
}
