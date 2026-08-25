use crate::{
    config::Config,
    connection::{Connection, DEFAULT_CONCURRENT_STREAMS},
    error::Error,
    utils::{self, CongestionControl},
};
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicServerConfig,
    Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt,
};
use rustls::{version, ServerConfig as RustlsServerConfig};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

const MAX_STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;

fn effective_receive_window(configured: u32) -> u32 {
    configured.min(MAX_STREAM_RECEIVE_WINDOW)
}

fn server_transport_config(cfg: &Config) -> Result<TransportConfig, Error> {
    let mut config = TransportConfig::default();
    let receive_window = effective_receive_window(cfg.receive_window);

    if receive_window != cfg.receive_window {
        log::warn!(
            "configured receive_window {} exceeds the server safety limit; using {}",
            cfg.receive_window,
            receive_window,
        );
    }

    config
        .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
        .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
        .send_window(cfg.send_window)
        .stream_receive_window(VarInt::from_u32(receive_window))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(cfg.max_idle_time).map_err(|_| Error::InvalidMaxIdleTime)?,
        ));

    match cfg.congestion_control {
        CongestionControl::Cubic => {
            config.congestion_controller_factory(Arc::new(CubicConfig::default()))
        }
        CongestionControl::NewReno => {
            config.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
        }
        CongestionControl::Bbr => {
            config.congestion_controller_factory(Arc::new(BbrConfig::default()))
        }
    };

    Ok(config)
}

pub struct Server {
    ep: Endpoint,
    users: Arc<HashMap<Uuid, Box<[u8]>>>,
    udp_relay_ipv6: bool,
    zero_rtt_handshake: bool,
    auth_timeout: Duration,
    task_negotiation_timeout: Duration,
    max_external_pkt_size: usize,
    gc_interval: Duration,
    gc_lifetime: Duration,
}

impl Server {
    pub fn init(cfg: Config) -> Result<Self, Error> {
        let tp_cfg = server_transport_config(&cfg)?;
        let certs = utils::load_certs(cfg.certificate)?;
        let priv_key = utils::load_priv_key(cfg.private_key)?;

        let mut crypto = RustlsServerConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)?;

        crypto.alpn_protocols = cfg.alpn;
        crypto.max_early_data_size = u32::MAX;
        crypto.send_half_rtt_data = cfg.zero_rtt_handshake;

        let mut config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).map_err(|e| std::io::Error::other(e.to_string()))?,
        ));

        config.transport_config(Arc::new(tp_cfg));

        let socket = {
            let domain = match cfg.server {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|err| Error::Socket("failed to create endpoint UDP socket", err))?;

            if cfg.server.is_ipv6() {
                if let Some(dual_stack) = cfg.dual_stack {
                    socket.set_only_v6(!dual_stack).map_err(|err| {
                        Error::Socket("endpoint dual-stack socket setting error", err)
                    })?;
                }
            }

            socket
                .bind(&SockAddr::from(cfg.server))
                .map_err(|err| Error::Socket("failed to bind endpoint UDP socket", err))?;

            StdUdpSocket::from(socket)
        };

        let ep = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self {
            ep,
            users: Arc::new(cfg.users),
            udp_relay_ipv6: cfg.udp_relay_ipv6,
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            auth_timeout: cfg.auth_timeout,
            task_negotiation_timeout: cfg.task_negotiation_timeout,
            max_external_pkt_size: cfg.max_external_packet_size,
            gc_interval: cfg.gc_interval,
            gc_lifetime: cfg.gc_lifetime,
        })
    }

    pub async fn start(&self) {
        log::warn!(
            "server started, listening on {}",
            self.ep.local_addr().unwrap()
        );

        loop {
            let Some(incoming) = self.ep.accept().await else {
                return;
            };

            let conn = match incoming.accept() {
                Ok(conn) => conn,
                Err(err) => {
                    log::warn!("failed to accept incoming connection: {err}");
                    continue;
                }
            };

            tokio::spawn(Connection::handle(
                conn,
                self.users.clone(),
                self.udp_relay_ipv6,
                self.zero_rtt_handshake,
                self.auth_timeout,
                self.task_negotiation_timeout,
                self.max_external_pkt_size,
                self.gc_interval,
                self.gc_lifetime,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::LevelFilter;
    use rcgen::generate_simple_self_signed;
    use std::{fs, io::ErrorKind, net::Ipv4Addr, path::PathBuf};
    use tempfile::{tempdir, TempDir};

    const UUID: Uuid = Uuid::from_u128(0x00112233_4455_6677_8899_aabbccddeeff);

    struct TlsFiles {
        _dir: TempDir,
        certificate: PathBuf,
        private_key: PathBuf,
    }

    impl TlsFiles {
        fn new() -> Self {
            let dir = tempdir().unwrap();
            let certificate = dir.path().join("certificate.pem");
            let private_key = dir.path().join("private-key.pem");
            let certified = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            fs::write(&certificate, certified.cert.pem()).unwrap();
            fs::write(&private_key, certified.signing_key.serialize_pem()).unwrap();

            Self {
                _dir: dir,
                certificate,
                private_key,
            }
        }

        fn config(&self, congestion_control: CongestionControl) -> Config {
            let mut users = HashMap::new();
            users.insert(UUID, Box::from(b"test-password".as_slice()));

            Config {
                server: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                users,
                certificate: self.certificate.clone(),
                private_key: self.private_key.clone(),
                congestion_control,
                alpn: vec![b"tuic-test".to_vec()],
                udp_relay_ipv6: false,
                zero_rtt_handshake: true,
                dual_stack: None,
                auth_timeout: Duration::from_secs(7),
                task_negotiation_timeout: Duration::from_secs(11),
                max_idle_time: Duration::from_secs(13),
                max_external_packet_size: 2048,
                send_window: 2 * 1024 * 1024,
                receive_window: 1024 * 1024,
                gc_interval: Duration::from_secs(17),
                gc_lifetime: Duration::from_secs(19),
                log_level: LevelFilter::Trace,
            }
        }
    }

    fn init_error(config: Config) -> Error {
        match Server::init(config) {
            Ok(_) => panic!("server initialization unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn init_binds_ephemeral_loopback_and_retains_runtime_settings() {
        let tls = TlsFiles::new();
        let server = Server::init(tls.config(CongestionControl::Cubic)).unwrap();
        let local_addr = server.ep.local_addr().unwrap();

        assert!(local_addr.ip().is_loopback());
        assert_ne!(local_addr.port(), 0);
        assert_eq!(server.users.len(), 1);
        assert_eq!(server.users[&UUID].as_ref(), b"test-password");
        assert!(!server.udp_relay_ipv6);
        assert!(server.zero_rtt_handshake);
        assert_eq!(server.auth_timeout, Duration::from_secs(7));
        assert_eq!(server.task_negotiation_timeout, Duration::from_secs(11));
        assert_eq!(server.max_external_pkt_size, 2048);
        assert_eq!(server.gc_interval, Duration::from_secs(17));
        assert_eq!(server.gc_lifetime, Duration::from_secs(19));
    }

    #[tokio::test]
    async fn init_supports_every_congestion_controller() {
        let tls = TlsFiles::new();

        for congestion_control in [
            CongestionControl::Cubic,
            CongestionControl::NewReno,
            CongestionControl::Bbr,
        ] {
            let server = Server::init(tls.config(congestion_control)).unwrap();
            assert!(server.ep.local_addr().unwrap().ip().is_loopback());
        }
    }

    #[test]
    fn receive_window_caps_legacy_client_bursts() {
        let tls = TlsFiles::new();
        let mut config = tls.config(CongestionControl::Cubic);
        config.receive_window = 8 * 1024 * 1024;
        let transport = server_transport_config(&config).unwrap();
        let debug = format!("{transport:?}");

        assert_eq!(
            effective_receive_window(config.receive_window),
            MAX_STREAM_RECEIVE_WINDOW,
        );
        assert!(
            debug.contains(&format!(
                "stream_receive_window: {MAX_STREAM_RECEIVE_WINDOW}"
            )),
            "unexpected transport configuration: {debug}",
        );
        assert_eq!(
            effective_receive_window(MAX_STREAM_RECEIVE_WINDOW),
            MAX_STREAM_RECEIVE_WINDOW
        );
        assert_eq!(effective_receive_window(512 * 1024), 512 * 1024);
    }

    #[tokio::test]
    async fn ipv4_bind_ignores_ipv6_only_dual_stack_setting() {
        let tls = TlsFiles::new();

        for dual_stack in [false, true] {
            let mut config = tls.config(CongestionControl::Cubic);
            config.dual_stack = Some(dual_stack);
            let server = Server::init(config).unwrap();
            assert!(server.ep.local_addr().unwrap().is_ipv4());
        }
    }

    #[tokio::test]
    async fn init_rejects_invalid_and_mismatched_tls_material() {
        let tls = TlsFiles::new();
        let invalid_certificate = tls._dir.path().join("invalid-certificate.pem");
        fs::write(
            &invalid_certificate,
            b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let mut invalid = tls.config(CongestionControl::Cubic);
        invalid.certificate = invalid_certificate;
        assert!(matches!(
            init_error(invalid),
            Error::Io(error) if error.kind() == ErrorKind::InvalidData
        ));

        let other = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mismatched_key = tls._dir.path().join("mismatched-key.pem");
        fs::write(&mismatched_key, other.signing_key.serialize_pem()).unwrap();
        let mut mismatched = tls.config(CongestionControl::Cubic);
        mismatched.private_key = mismatched_key;
        assert!(matches!(init_error(mismatched), Error::Rustls(_)));
    }

    #[tokio::test]
    async fn init_rejects_unrepresentable_idle_timeout() {
        let tls = TlsFiles::new();
        let mut config = tls.config(CongestionControl::Cubic);
        config.max_idle_time = Duration::MAX;

        assert!(matches!(init_error(config), Error::InvalidMaxIdleTime));
    }
}
