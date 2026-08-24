use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::Item;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    fs,
    io::{Cursor, Error as IoError, ErrorKind},
    path::PathBuf,
    str::FromStr,
};

pub fn load_certs(path: PathBuf) -> Result<Vec<CertificateDer<'static>>, IoError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "empty certificate file",
        ));
    }

    let mut file = Cursor::new(bytes.as_slice());
    let mut certs = Vec::new();

    while let Some(item) = rustls_pemfile::read_one(&mut file)? {
        if let Item::X509Certificate(cert) = item {
            certs.push(cert);
        }
    }

    if certs.is_empty() {
        if looks_like_pem(&bytes) {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "no certificate found in PEM file",
            ));
        }
        certs.push(CertificateDer::from(bytes));
    }

    Ok(certs)
}

pub fn load_priv_key(path: PathBuf) -> Result<PrivateKeyDer<'static>, IoError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "empty private key file",
        ));
    }

    let mut file = Cursor::new(bytes.as_slice());
    let mut priv_key = None;

    while let Some(item) = rustls_pemfile::read_one(&mut file)? {
        match item {
            Item::Pkcs1Key(key) => priv_key = Some(PrivateKeyDer::from(key)),
            Item::Pkcs8Key(key) => priv_key = Some(PrivateKeyDer::from(key)),
            Item::Sec1Key(key) => priv_key = Some(PrivateKeyDer::from(key)),
            _ => {}
        }
    }

    if let Some(priv_key) = priv_key {
        Ok(priv_key)
    } else if looks_like_pem(&bytes) {
        Err(IoError::new(
            ErrorKind::InvalidData,
            "no supported private key found in PEM file",
        ))
    } else {
        Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(bytes)))
    }
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN".len())
        .any(|window| window == b"-----BEGIN")
}

#[derive(Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl Display for UdpRelayMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Native => write!(f, "native"),
            Self::Quic => write!(f, "quic"),
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
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn load_certs_reads_pem_chain_and_der() {
        let dir = tempdir().unwrap();
        let chain_path = dir.path().join("chain.pem");
        let der_path = dir.path().join("certificate.der");
        let first = generate_simple_self_signed(vec!["first.example".into()]).unwrap();
        let second = generate_simple_self_signed(vec!["second.example".into()]).unwrap();
        fs::write(
            &chain_path,
            format!("{}{}", first.cert.pem(), second.cert.pem()),
        )
        .unwrap();
        fs::write(&der_path, first.cert.der()).unwrap();

        let chain = load_certs(chain_path).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].as_ref(), first.cert.der().as_ref());
        assert_eq!(chain[1].as_ref(), second.cert.der().as_ref());

        let der = load_certs(der_path).unwrap();
        assert_eq!(der.len(), 1);
        assert_eq!(der[0].as_ref(), first.cert.der().as_ref());
    }

    #[test]
    fn load_private_key_reads_pkcs8_pem_and_der() {
        let dir = tempdir().unwrap();
        let pem_path = dir.path().join("private-key.pem");
        let der_path = dir.path().join("private-key.der");
        let certified = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let expected = certified.signing_key.serialize_der();
        fs::write(&pem_path, certified.signing_key.serialize_pem()).unwrap();
        fs::write(&der_path, &expected).unwrap();

        assert_eq!(load_priv_key(pem_path).unwrap().secret_der(), expected);
        assert_eq!(load_priv_key(der_path).unwrap().secret_der(), expected);
    }

    #[test]
    fn loaders_reject_invalid_missing_and_empty_files() {
        let dir = tempdir().unwrap();
        let invalid_cert = dir.path().join("invalid-cert.pem");
        let invalid_key = dir.path().join("invalid-key.pem");
        let empty = dir.path().join("empty");
        fs::write(
            &invalid_cert,
            b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            &invalid_key,
            b"-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(&empty, []).unwrap();

        assert_eq!(
            load_certs(invalid_cert).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            load_priv_key(invalid_key).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            load_certs(empty.clone()).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            load_priv_key(empty).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            load_certs(dir.path().join("missing-cert"))
                .err()
                .unwrap()
                .kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            load_priv_key(dir.path().join("missing-key"))
                .err()
                .unwrap()
                .kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn udp_relay_mode_displays_protocol_names() {
        assert_eq!(UdpRelayMode::Native.to_string(), "native");
        assert_eq!(UdpRelayMode::Quic.to_string(), "quic");
    }

    #[test]
    fn congestion_control_parses_aliases_case_insensitively() {
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
