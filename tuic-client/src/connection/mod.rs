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
    task::JoinSet,
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
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

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
        let server = ServerAddr::new(cfg.server.0, cfg.server.1, cfg.ip, cfg.forwarder_server)?;
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
        let mut tp_cfg = TransportConfig::default();

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

        ep.set_default_client_config(config.clone());

        let ep = Endpoint {
            ep,
            config,
            server,
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
    config: ClientConfig,
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
        let addresses = self.server.resolve().await?.collect();
        let (ep, conn, zero_rtt_accepted) = connect_addresses(
            self.ep.clone(),
            self.config.clone(),
            self.server.server_name().to_string(),
            addresses,
            self.zero_rtt_handshake,
        )
        .await?;
        self.ep = ep;

        Ok(Connection::new(
            conn,
            zero_rtt_accepted,
            self.udp_relay_mode,
            self.uuid,
            self.password.clone(),
            self.heartbeat,
            self.gc_interval,
            self.gc_lifetime,
        ))
    }
}

async fn connect_addresses(
    endpoint: QuinnEndpoint,
    config: ClientConfig,
    server_name: String,
    mut addresses: Vec<SocketAddr>,
    zero_rtt: bool,
) -> Result<(QuinnEndpoint, QuinnConnection, Option<ZeroRttAccepted>), Error> {
    // Early data does not prove reachability, so racing candidates need a full handshake.
    let zero_rtt = zero_rtt && addresses.len() == 1;
    if let Some(first) = addresses.first().copied() {
        if let Some(index) = addresses
            .iter()
            .position(|addr| !same_address_family(*addr, first))
        {
            let alternate = addresses.remove(index);
            addresses.insert(1, alternate);
        }
    }
    let mut addresses = addresses.into_iter().peekable();
    let mut attempts = JoinSet::new();
    let mut next_attempt = time::Instant::now();
    let mut last_err = Error::DnsResolve;

    while addresses.peek().is_some() || !attempts.is_empty() {
        tokio::select! {
            _ = time::sleep_until(next_attempt), if addresses.peek().is_some() => {
                let addr = addresses.next().unwrap();
                let endpoint = endpoint.clone();
                let config = config.clone();
                let server_name = server_name.clone();
                attempts.spawn(async move {
                    let result = async {
                        // Rebinding a shared endpoint would also move in-flight attempts.
                        let endpoint = if same_address_family(addr, endpoint.local_addr()?) {
                            endpoint
                        } else {
                            QuinnEndpoint::new(
                                EndpointConfig::default(),
                                None,
                                UdpSocket::bind(wildcard_addr_for(addr)).map_err(|err| {
                                    Error::Socket("failed to create endpoint UDP socket", err)
                                })?,
                                Arc::new(TokioRuntime),
                            )?
                        };
                        let conn = endpoint.connect_with(config, addr, &server_name)?;
                        let (conn, accepted) = if zero_rtt {
                            match conn.into_0rtt() {
                                Ok((conn, accepted)) => (conn, Some(accepted)),
                                Err(conn) => (conn.await?, None),
                            }
                        } else {
                            (conn.await?, None)
                        };
                        Ok((endpoint, conn, accepted))
                    }.await;
                    if let Err(err) = &result {
                        log::debug!("[relay] connection attempt to {addr} failed: {err}");
                    }
                    result
                });
                next_attempt = time::Instant::now() + CONNECTION_ATTEMPT_DELAY;
            }
            Some(result) = attempts.join_next(), if !attempts.is_empty() => {
                match result {
                    Ok(Ok(connection)) => return Ok(connection),
                    Ok(Err(err)) => last_err = err,
                    Err(err) => return Err(std::io::Error::other(
                        format!("connection attempt task failed: {err}")
                    ).into()),
                }
                if attempts.is_empty() {
                    next_attempt = time::Instant::now();
                }
            }
        }
    }

    Err(last_err)
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
    use rcgen::generate_simple_self_signed;
    use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};

    fn quic_configs() -> (quinn::ServerConfig, ClientConfig) {
        let certified = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let server = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut crypto = RustlsClientConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.enable_early_data = true;
        let client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        (server, client)
    }

    #[tokio::test]
    async fn unreachable_addresses_do_not_block_working_candidates() {
        for (blackhole_bind, server_bind) in [
            ("[::1]:0", "127.0.0.1:0"),
            ("127.0.0.1:0", "[::1]:0"),
            ("127.0.0.1:0", "127.0.0.1:0"),
        ] {
            let blackhole = tokio::net::UdpSocket::bind(blackhole_bind).await.unwrap();
            let blackhole_addr = blackhole.local_addr().unwrap();
            let (server_config, client_config) = quic_configs();
            let server =
                QuinnEndpoint::server(server_config, server_bind.parse().unwrap()).unwrap();
            let server_addr = server.local_addr().unwrap();
            let endpoint = QuinnEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let attempts = connect_addresses(
                endpoint,
                client_config,
                "localhost".to_string(),
                vec![blackhole_addr, blackhole_addr, blackhole_addr, server_addr],
                false,
            );
            let accept = async { server.accept().await.unwrap().await.unwrap() };
            let (connection, incoming) = time::timeout(Duration::from_secs(2), async {
                tokio::join!(attempts, accept)
            })
            .await
            .expect("a blackholed address blocked the reachable address");
            let (endpoint, connection, accepted) = connection.unwrap();
            assert_eq!(connection.remote_address(), server_addr);
            assert!(same_address_family(
                endpoint.local_addr().unwrap(),
                server_addr
            ));
            assert!(accepted.is_none());
            assert_eq!(
                incoming.remote_address().port(),
                endpoint.local_addr().unwrap().port()
            );
            assert!(incoming.remote_address().ip().is_loopback());
        }
    }

    #[tokio::test]
    async fn connection_attempts_preserve_tls_verification_and_report_errors() {
        let (server_config, client_config) = quic_configs();
        let server = QuinnEndpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let endpoint = QuinnEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let attempts = connect_addresses(
            endpoint,
            client_config,
            "wrong.example".to_string(),
            vec![server.local_addr().unwrap()],
            false,
        );
        let accept = async { server.accept().await.unwrap().await };
        let (result, _) = time::timeout(Duration::from_secs(2), async {
            tokio::join!(attempts, accept)
        })
        .await
        .unwrap();
        let error = result.err().expect("an untrusted TLS name was accepted");
        assert!(
            error.to_string().contains("certificate not valid for name"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn cached_zero_rtt_does_not_select_an_unreachable_candidate() {
        let (server_config, client_config) = quic_configs();
        let server = QuinnEndpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let endpoint = QuinnEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        let connect = async {
            let (_, first, _) = connect_addresses(
                endpoint.clone(),
                client_config.clone(),
                "localhost".to_string(),
                vec![server_addr],
                false,
            )
            .await
            .unwrap();
            time::timeout(Duration::from_secs(2), async {
                loop {
                    let probe = endpoint
                        .connect_with(client_config.clone(), blackhole_addr, "localhost")
                        .unwrap();
                    if probe.into_0rtt().is_ok() {
                        break;
                    }
                    time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the initial connection did not cache a resumption ticket");
            let (_, second, accepted) = time::timeout(
                Duration::from_secs(2),
                connect_addresses(
                    endpoint,
                    client_config,
                    "localhost".to_string(),
                    vec![blackhole_addr, server_addr],
                    true,
                ),
            )
            .await
            .expect("cached early data bypassed address fallback")
            .unwrap();
            assert_eq!(second.remote_address(), server_addr);
            assert!(accepted.is_none());
            (first, second)
        };
        let accept = async {
            let first = server.accept().await.unwrap().await.unwrap();
            let second = server.accept().await.unwrap().await.unwrap();
            (first, second)
        };
        time::timeout(Duration::from_secs(5), async {
            tokio::join!(connect, accept)
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn empty_address_list_reports_resolution_failure() {
        let (_, config) = quic_configs();
        let endpoint = QuinnEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let result =
            connect_addresses(endpoint, config, "localhost".to_string(), vec![], false).await;
        assert!(matches!(result, Err(Error::DnsResolve)));
    }

    #[test]
    fn rejects_forwarder_and_ip_before_initializing_endpoint() {
        let cfg: Relay = serde_json::from_value(serde_json::json!({
            "server": "relay.example:443",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "password": "secret",
            "ip": "192.0.2.10",
            "forwarder_server": "192.0.2.20:8443"
        }))
        .unwrap();
        let error = Connection::set_config(cfg).unwrap_err();
        assert!(matches!(error, Error::ConflictingRelayAddresses));
        assert!(error
            .to_string()
            .contains("relay.forwarder_server and relay.ip cannot both be set"));
    }

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
}
