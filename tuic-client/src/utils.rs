use crate::error::Error;
use rustls::{pki_types::CertificateDer, RootCertStore};
use rustls_pemfile::Item;
use std::{
    fs::{self, File},
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};
use tokio::net;

pub fn load_certs(paths: Vec<PathBuf>, disable_native: bool) -> Result<RootCertStore, Error> {
    let mut certs = RootCertStore::empty();

    for path in &paths {
        let mut file = BufReader::new(File::open(path)?);

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::X509Certificate(cert) = item {
                certs.add(cert)?;
            }
        }
    }

    if certs.is_empty() {
        for path in &paths {
            certs.add(CertificateDer::from(fs::read(path)?))?;
        }
    }

    if !disable_native {
        let result = rustls_native_certs::load_native_certs();
        for cert in result.certs {
            let _ = certs.add(cert);
        }
    }

    Ok(certs)
}

pub struct ServerAddr {
    domain: String,
    port: u16,
    ip: Option<IpAddr>,
}

impl ServerAddr {
    pub fn new(domain: String, port: u16, ip: Option<IpAddr>) -> Self {
        Self { domain, port, ip }
    }

    pub fn server_name(&self) -> &str {
        &self.domain
    }

    pub async fn resolve(&self) -> Result<impl Iterator<Item = SocketAddr>, Error> {
        if let Some(ip) = self.ip {
            Ok(vec![SocketAddr::from((ip, self.port))].into_iter())
        } else {
            Ok(net::lookup_host((self.domain.as_str(), self.port))
                .await?
                .collect::<Vec<_>>()
                .into_iter())
        }
    }
}

#[derive(Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl FromStr for UdpRelayMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("native") {
            Ok(Self::Native)
        } else if s.eq_ignore_ascii_case("quic") {
            Ok(Self::Quic)
        } else {
            Err("invalid UDP relay mode")
        }
    }
}

pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl FromStr for CongestionControl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("cubic") {
            Ok(Self::Cubic)
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Ok(Self::NewReno)
        } else if s.eq_ignore_ascii_case("bbr") {
            Ok(Self::Bbr)
        } else {
            Err("invalid congestion control")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use std::{fs, net::Ipv4Addr};
    use tempfile::tempdir;
    use tokio::time::{timeout, Duration};

    #[test]
    fn load_certs_reads_pem_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.pem");
        let first = generate_simple_self_signed(vec!["first.example".into()]).unwrap();
        let second = generate_simple_self_signed(vec!["second.example".into()]).unwrap();
        fs::write(
            path.as_path(),
            format!("{}{}", first.cert.pem(), second.cert.pem()),
        )
        .unwrap();

        let store = load_certs(vec![path], true).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn load_certs_falls_back_to_der() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("certificate.der");
        let certified = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(path.as_path(), certified.cert.der()).unwrap();

        let store = load_certs(vec![path], true).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn load_certs_reports_invalid_and_missing_files() {
        let dir = tempdir().unwrap();
        let invalid = dir.path().join("invalid.pem");
        fs::write(invalid.as_path(), b"not a certificate").unwrap();

        assert!(matches!(
            load_certs(vec![invalid], true),
            Err(Error::Rustls(_))
        ));
        assert!(matches!(
            load_certs(vec![dir.path().join("missing.pem")], true),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn load_certs_can_disable_native_roots() {
        let store = load_certs(Vec::new(), true).unwrap();
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn server_addr_prefers_override_and_preserves_server_name() {
        let address = ServerAddr::new(
            "relay.example".to_string(),
            443,
            Some(Ipv4Addr::new(192, 0, 2, 7).into()),
        );

        assert_eq!(address.server_name(), "relay.example");
        assert_eq!(
            address.resolve().await.unwrap().collect::<Vec<_>>(),
            [SocketAddr::from(([192, 0, 2, 7], 443))]
        );
    }

    #[tokio::test]
    async fn server_addr_resolves_localhost() {
        let address = ServerAddr::new("localhost".to_string(), 43123, None);
        let resolved = timeout(Duration::from_secs(5), address.resolve())
            .await
            .unwrap()
            .unwrap()
            .collect::<Vec<_>>();

        assert!(!resolved.is_empty());
        assert!(resolved.iter().all(|addr| addr.ip().is_loopback()));
        assert!(resolved.iter().all(|addr| addr.port() == 43123));
    }

    #[test]
    fn udp_relay_mode_parses_case_insensitively() {
        for value in ["native", "NATIVE", "NaTiVe"] {
            assert!(matches!(value.parse(), Ok(UdpRelayMode::Native)));
        }
        for value in ["quic", "QUIC", "QuIc"] {
            assert!(matches!(value.parse(), Ok(UdpRelayMode::Quic)));
        }
        for value in ["", "udp", "native "] {
            assert_eq!(
                value.parse::<UdpRelayMode>().err(),
                Some("invalid UDP relay mode")
            );
        }
    }

    #[test]
    fn congestion_control_parses_aliases_and_case() {
        for value in ["cubic", "CUBIC", "CuBiC"] {
            assert!(matches!(value.parse(), Ok(CongestionControl::Cubic)));
        }
        for value in ["new_reno", "NEW_RENO", "newreno", "NewReno"] {
            assert!(matches!(value.parse(), Ok(CongestionControl::NewReno)));
        }
        for value in ["bbr", "BBR", "Bbr"] {
            assert!(matches!(value.parse(), Ok(CongestionControl::Bbr)));
        }
        for value in ["", "reno", "bbr "] {
            assert_eq!(
                value.parse::<CongestionControl>().err(),
                Some("invalid congestion control")
            );
        }
    }
}
