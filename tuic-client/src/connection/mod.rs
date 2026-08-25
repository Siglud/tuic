use crate::{
    config::Relay,
    error::Error,
    utils::{self, CongestionControl, ServerAddr, UdpRelayMode},
};
use crossbeam_utils::atomic::AtomicCell;
use once_cell::sync::OnceCell;
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
    ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig,
    TokioRuntime, TransportConfig, VarInt, ZeroRttAccepted,
};
use register_count::Counter;
use rustls::{version, ClientConfig as RustlsClientConfig};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, OnceCell as AsyncOnceCell},
    time,
};
use tuic_quinn::{side, Connection as Model};
use uuid::Uuid;

mod handle_stream;
mod handle_task;

static ENDPOINT: OnceCell<AsyncMutex<Endpoint>> = OnceCell::new();
static CONNECTION: AsyncOnceCell<AsyncMutex<Connection>> = AsyncOnceCell::const_new();
static TIMEOUT: AtomicCell<Duration> = AtomicCell::new(Duration::from_secs(0));

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
const DEFAULT_CONCURRENT_STREAMS: u32 = 32;
const PACKET_REORDERING_THRESHOLD: u32 = u32::MAX;

fn reordering_tolerant_transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.packet_threshold(PACKET_REORDERING_THRESHOLD);
    config
}

#[derive(Clone)]
pub struct Connection {
    conn: QuinnConnection,
    model: Model<side::Client>,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl Connection {
    pub fn set_config(cfg: Relay) -> Result<(), Error> {
        let certs = utils::load_certs(cfg.certificates, cfg.disable_native_certs)?;

        let mut crypto = RustlsClientConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_root_certificates(certs)
            .with_no_client_auth();

        crypto.alpn_protocols = cfg.alpn;
        crypto.enable_early_data = true;
        crypto.enable_sni = !cfg.disable_sni;

        let mut config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).map_err(|e| std::io::Error::other(e.to_string()))?,
        ));
        let mut tp_cfg = reordering_tolerant_transport_config();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .send_window(cfg.send_window)
            .stream_receive_window(VarInt::from_u32(cfg.receive_window))
            .max_idle_timeout(None);

        match cfg.congestion_control {
            CongestionControl::Cubic => {
                tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionControl::NewReno => {
                tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionControl::Bbr => {
                tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        // Try to create an IPv4 socket as the placeholder first, if it fails, try IPv6.
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .or_else(|err| {
                UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).map_err(|_| err)
            })
            .map_err(|err| Error::Socket("failed to create endpoint UDP socket", err))?;

        let mut ep = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;

        ep.set_default_client_config(config);

        let ep = Endpoint {
            ep,
            server: ServerAddr::new(cfg.server.0, cfg.server.1, cfg.ip),
            uuid: cfg.uuid,
            password: cfg.password,
            udp_relay_mode: cfg.udp_relay_mode,
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            heartbeat: cfg.heartbeat,
            gc_interval: cfg.gc_interval,
            gc_lifetime: cfg.gc_lifetime,
        };

        ENDPOINT
            .set(AsyncMutex::new(ep))
            .map_err(|_| "endpoint already initialized")
            .unwrap();

        TIMEOUT.store(cfg.timeout);

        Ok(())
    }

    pub async fn get() -> Result<Connection, Error> {
        let try_init_conn = async {
            let mut endpoint = ENDPOINT.get().unwrap().lock().await;
            endpoint.connect().await.map(AsyncMutex::new)
        };

        let try_get_conn = async {
            let mut conn = CONNECTION
                .get_or_try_init(|| try_init_conn)
                .await?
                .lock()
                .await;

            if conn.is_closed() {
                let mut endpoint = ENDPOINT.get().unwrap().lock().await;
                let new_conn = endpoint.connect().await?;
                *conn = new_conn;
            }

            Ok::<_, Error>(conn.clone())
        };

        let conn = time::timeout(TIMEOUT.load(), try_get_conn)
            .await
            .map_err(|_| Error::Timeout)??;

        Ok(conn)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: QuinnConnection,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        udp_relay_mode: UdpRelayMode,
        uuid: Uuid,
        password: Arc<[u8]>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) -> Self {
        let conn = Self {
            conn: conn.clone(),
            model: Model::<side::Client>::new(conn),
            uuid,
            password,
            udp_relay_mode,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
        };

        tokio::spawn(
            conn.clone()
                .init(zero_rtt_accepted, heartbeat, gc_interval, gc_lifetime),
        );

        conn
    }

    async fn init(
        self,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        log::info!("[relay] connection established");

        tokio::spawn(self.clone().authenticate(zero_rtt_accepted));
        tokio::spawn(self.clone().heartbeat(heartbeat));
        tokio::spawn(self.clone().collect_garbage(gc_interval, gc_lifetime));

        let err = loop {
            tokio::select! {
                res = self.accept_uni_stream() => match res {
                    Ok((recv, reg)) => tokio::spawn(self.clone().handle_uni_stream(recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_bi_stream() => match res {
                    Ok((send, recv, reg)) => tokio::spawn(self.clone().handle_bi_stream(send, recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_datagram() => match res {
                    Ok(dg) => tokio::spawn(self.clone().handle_datagram(dg)),
                    Err(err) => break err,
                },
            };
        };

        log::warn!("[relay] connection error: {err}");
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
        loop {
            time::sleep(gc_interval).await;

            if self.is_closed() {
                break;
            }

            log::debug!("[relay] packet fragment garbage collecting event");
            self.model.collect_garbage(gc_lifetime);
        }
    }
}

struct Endpoint {
    ep: QuinnEndpoint,
    server: ServerAddr,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    zero_rtt_handshake: bool,
    heartbeat: Duration,
    gc_interval: Duration,
    gc_lifetime: Duration,
}

impl Endpoint {
    async fn connect(&mut self) -> Result<Connection, Error> {
        let mut last_err = None;

        for addr in self.server.resolve().await? {
            let connect_to = async {
                if !self
                    .ep
                    .local_addr()
                    .is_ok_and(|local_addr| same_address_family(addr, local_addr))
                {
                    self.ep
                        .rebind(UdpSocket::bind(wildcard_addr_for(addr)).map_err(|err| {
                            Error::Socket("failed to create endpoint UDP socket", err)
                        })?)
                        .map_err(|err| {
                            Error::Socket("failed to rebind endpoint UDP socket", err)
                        })?;
                }

                let conn = self.ep.connect(addr, self.server.server_name())?;
                let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                    match conn.into_0rtt() {
                        Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                        Err(conn) => (conn.await?, None),
                    }
                } else {
                    (conn.await?, None)
                };

                Ok((conn, zero_rtt_accepted))
            };

            match connect_to.await {
                Ok((conn, zero_rtt_accepted)) => {
                    return Ok(Connection::new(
                        conn,
                        zero_rtt_accepted,
                        self.udp_relay_mode,
                        self.uuid,
                        self.password.clone(),
                        self.heartbeat,
                        self.gc_interval,
                        self.gc_lifetime,
                    ));
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(Error::DnsResolve))
    }
}

fn same_address_family(left: SocketAddr, right: SocketAddr) -> bool {
    left.is_ipv4() == right.is_ipv4()
}

fn wildcard_addr_for(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_family_helpers_select_matching_wildcard_bindings() {
        let ipv4 = SocketAddr::from(([192, 0, 2, 1], 443));
        let ipv4_local = SocketAddr::from(([0, 0, 0, 0], 12345));
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();
        let ipv6_local = "[::]:12345".parse().unwrap();

        assert!(same_address_family(ipv4, ipv4_local));
        assert!(same_address_family(ipv6, ipv6_local));
        assert!(!same_address_family(ipv4, ipv6_local));
        assert_eq!(
            wildcard_addr_for(ipv4),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        );
        assert_eq!(
            wildcard_addr_for(ipv6),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        );
    }

    #[test]
    fn default_remote_stream_capacity_is_nonzero() {
        assert_eq!(DEFAULT_CONCURRENT_STREAMS, 32);
    }

    #[test]
    fn transport_tolerates_large_packet_reordering() {
        let config = reordering_tolerant_transport_config();
        let debug = format!("{config:?}");

        assert!(
            debug.contains(&format!("packet_threshold: {PACKET_REORDERING_THRESHOLD}")),
            "unexpected transport configuration: {debug}"
        );
    }
}
