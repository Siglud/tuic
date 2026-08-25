use crate::utils::{CongestionControl, UdpRelayMode};
use humantime::Duration as HumanDuration;
use lexopt::{Arg, Error as ArgumentError, Parser};
use log::LevelFilter;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use serde_json::Error as SerdeError;
use std::{
    env::ArgsOs,
    ffi::OsString,
    fmt::Display,
    fs::File,
    io::Error as IoError,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use uuid::Uuid;

const HELP_MSG: &str = r#"
Usage tuic-client [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub relay: Relay,

    pub local: Local,

    #[serde(default = "default::log_level")]
    pub log_level: LevelFilter,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    #[serde(deserialize_with = "deserialize_server")]
    pub server: (String, u16),

    pub uuid: Uuid,

    #[serde(deserialize_with = "deserialize_password")]
    pub password: Arc<[u8]>,

    pub ip: Option<IpAddr>,

    #[serde(default = "default::relay::certificates")]
    pub certificates: Vec<PathBuf>,

    #[serde(
        default = "default::relay::udp_relay_mode",
        deserialize_with = "deserialize_from_str"
    )]
    pub udp_relay_mode: UdpRelayMode,

    #[serde(
        default = "default::relay::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    #[serde(
        default = "default::relay::alpn",
        deserialize_with = "deserialize_alpn"
    )]
    pub alpn: Vec<Vec<u8>>,

    #[serde(default = "default::relay::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    #[serde(default = "default::relay::disable_sni")]
    pub disable_sni: bool,

    #[serde(
        default = "default::relay::timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub timeout: Duration,

    #[serde(
        default = "default::relay::heartbeat",
        deserialize_with = "deserialize_duration"
    )]
    pub heartbeat: Duration,

    #[serde(default = "default::relay::disable_native_certs")]
    pub disable_native_certs: bool,

    #[serde(default = "default::relay::send_window")]
    pub send_window: u64,

    #[serde(default = "default::relay::receive_window")]
    pub receive_window: u32,

    #[serde(
        default = "default::relay::gc_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_interval: Duration,

    #[serde(
        default = "default::relay::gc_lifetime",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_lifetime: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    pub server: SocketAddr,

    #[serde(deserialize_with = "deserialize_optional_bytes", default)]
    pub username: Option<Vec<u8>>,

    #[serde(deserialize_with = "deserialize_optional_bytes", default)]
    pub password: Option<Vec<u8>>,

    pub dual_stack: Option<bool>,

    #[serde(default = "default::local::max_packet_size")]
    pub max_packet_size: usize,

    #[serde(default)]
    pub enable_http: bool,
}

impl Config {
    pub fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
        Self::parse_from(args)
    }

    fn parse_from<I>(args: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator,
        I::Item: Into<OsString>,
    {
        let mut parser = Parser::from_iter(args);
        let mut path = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('c') | Arg::Long("config") => {
                    if path.is_none() {
                        path = Some(parser.value()?);
                    } else {
                        return Err(ConfigError::Argument(arg.unexpected()));
                    }
                }
                Arg::Short('v') | Arg::Long("version") => {
                    return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")))
                }
                Arg::Short('h') | Arg::Long("help") => return Err(ConfigError::Help(HELP_MSG)),
                _ => return Err(ConfigError::Argument(arg.unexpected())),
            }
        }

        if path.is_none() {
            return Err(ConfigError::NoConfig);
        }

        let file = File::open(path.unwrap())?;
        Ok(serde_json::from_reader(file)?)
    }
}

mod default {
    use log::LevelFilter;

    pub mod relay {
        use crate::utils::{CongestionControl, UdpRelayMode};
        use std::{path::PathBuf, time::Duration};

        pub fn certificates() -> Vec<PathBuf> {
            Vec::new()
        }

        pub fn udp_relay_mode() -> UdpRelayMode {
            UdpRelayMode::Native
        }

        pub fn congestion_control() -> CongestionControl {
            CongestionControl::Cubic
        }

        pub fn alpn() -> Vec<Vec<u8>> {
            Vec::new()
        }

        pub fn zero_rtt_handshake() -> bool {
            false
        }

        pub fn disable_sni() -> bool {
            false
        }

        pub fn timeout() -> Duration {
            Duration::from_secs(8)
        }

        pub fn heartbeat() -> Duration {
            Duration::from_secs(3)
        }

        pub fn disable_native_certs() -> bool {
            false
        }

        pub fn send_window() -> u64 {
            8 * 1024 * 1024 * 2
        }

        pub fn receive_window() -> u32 {
            1024 * 1024
        }

        pub fn gc_interval() -> Duration {
            Duration::from_secs(3)
        }

        pub fn gc_lifetime() -> Duration {
            Duration::from_secs(15)
        }
    }

    pub mod local {
        pub fn max_packet_size() -> usize {
            1500
        }
    }

    pub fn log_level() -> LevelFilter {
        LevelFilter::Warn
    }
}

pub fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(DeError::custom)
}

pub fn deserialize_server<'de, D>(deserializer: D) -> Result<(String, u16), D::Error>
where
    D: Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;

    let (domain, port) = s
        .rsplit_once(':')
        .ok_or(DeError::custom("invalid server address"))?;

    if domain.is_empty() {
        return Err(DeError::custom("invalid server address"));
    }

    let port = port.parse().map_err(DeError::custom)?;
    if port == 0 {
        return Err(DeError::custom("invalid server port"));
    }
    s.truncate(domain.len());

    Ok((s, port))
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<Arc<[u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Arc::from(s.into_bytes().into_boxed_slice()))
}

pub fn deserialize_alpn<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    Ok(s.into_iter().map(|alpn| alpn.into_bytes()).collect())
}

pub fn deserialize_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Some(s.into_bytes()))
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    s.parse::<HumanDuration>()
        .map(|d| *d)
        .map_err(DeError::custom)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Argument(#[from] ArgumentError),
    #[error("no config file specified")]
    NoConfig,
    #[error("{0}")]
    Version(&'static str),
    #[error("{0}")]
    Help(&'static str),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Serde(#[from] SerdeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::fs;
    use tempfile::NamedTempFile;

    const UUID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn minimal_config() -> Value {
        json!({
            "relay": {
                "server": "example.com:443",
                "uuid": UUID,
                "password": "secret",
                "ip": null
            },
            "local": {
                "server": "127.0.0.1:1080",
                "dual_stack": null
            }
        })
    }

    fn parse_file(value: &Value) -> Result<Config, ConfigError> {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(value).unwrap()).unwrap();

        Config::parse_from(vec![
            OsString::from("tuic-client"),
            OsString::from("--config"),
            file.path().as_os_str().to_owned(),
        ])
    }

    #[test]
    fn cli_requires_config() {
        assert!(matches!(
            Config::parse_from(args(&["tuic-client"])),
            Err(ConfigError::NoConfig)
        ));
    }

    #[test]
    fn cli_reports_help_and_version() {
        for flag in ["-h", "--help"] {
            assert!(matches!(
                Config::parse_from(args(&["tuic-client", flag])),
                Err(ConfigError::Help(HELP_MSG))
            ));
        }

        for flag in ["-v", "--version"] {
            assert!(matches!(
                Config::parse_from(args(&["tuic-client", flag])),
                Err(ConfigError::Version(env!("CARGO_PKG_VERSION")))
            ));
        }
    }

    #[test]
    fn cli_rejects_unknown_duplicate_and_missing_arguments() {
        let cases = [
            args(&["tuic-client", "--unknown"]),
            args(&["tuic-client", "--config", "first.json", "-c", "second.json"]),
            args(&["tuic-client", "--config"]),
        ];

        for case in cases {
            assert!(matches!(
                Config::parse_from(case),
                Err(ConfigError::Argument(_))
            ));
        }
    }

    #[test]
    fn minimal_json_applies_all_defaults() {
        let config = parse_file(&minimal_config()).unwrap();

        assert_eq!(config.relay.server, ("example.com".to_string(), 443));
        assert_eq!(config.relay.uuid, Uuid::parse_str(UUID).unwrap());
        assert_eq!(config.relay.password.as_ref(), b"secret");
        assert_eq!(config.relay.ip, None);
        assert!(config.relay.certificates.is_empty());
        assert!(matches!(config.relay.udp_relay_mode, UdpRelayMode::Native));
        assert!(matches!(
            config.relay.congestion_control,
            CongestionControl::Cubic
        ));
        assert!(config.relay.alpn.is_empty());
        assert!(!config.relay.zero_rtt_handshake);
        assert!(!config.relay.disable_sni);
        assert_eq!(config.relay.timeout, Duration::from_secs(8));
        assert_eq!(config.relay.heartbeat, Duration::from_secs(3));
        assert!(!config.relay.disable_native_certs);
        assert_eq!(config.relay.send_window, 16 * 1024 * 1024);
        assert_eq!(config.relay.receive_window, 1024 * 1024);
        assert_eq!(config.relay.gc_interval, Duration::from_secs(3));
        assert_eq!(config.relay.gc_lifetime, Duration::from_secs(15));

        assert_eq!(config.local.server, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(config.local.username, None);
        assert_eq!(config.local.password, None);
        assert_eq!(config.local.dual_stack, None);
        assert_eq!(config.local.max_packet_size, 1500);
        assert!(!config.local.enable_http);
        assert_eq!(config.log_level, LevelFilter::Warn);
    }

    #[test]
    fn complete_json_deserializes_every_setting() {
        let value = json!({
            "relay": {
                "server": "relay.example:8443",
                "uuid": UUID,
                "password": "p:a:ss",
                "ip": "192.0.2.10",
                "certificates": ["first.pem", "second.der"],
                "udp_relay_mode": "QUIC",
                "congestion_control": "new_reno",
                "alpn": ["h3", "tuic"],
                "zero_rtt_handshake": true,
                "disable_sni": true,
                "timeout": "1250ms",
                "heartbeat": "4s",
                "disable_native_certs": true,
                "send_window": 123456,
                "receive_window": 654321,
                "gc_interval": "250ms",
                "gc_lifetime": "30s"
            },
            "local": {
                "server": "[::1]:2080",
                "username": "client",
                "password": "s:cret",
                "dual_stack": true,
                "max_packet_size": 4096,
                "enable_http": true
            },
            "log_level": "info"
        });
        let config = parse_file(&value).unwrap();

        assert_eq!(config.relay.server, ("relay.example".to_string(), 8443));
        assert_eq!(config.relay.password.as_ref(), b"p:a:ss");
        assert_eq!(config.relay.ip, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(
            config.relay.certificates,
            vec![PathBuf::from("first.pem"), PathBuf::from("second.der")]
        );
        assert!(matches!(config.relay.udp_relay_mode, UdpRelayMode::Quic));
        assert!(matches!(
            config.relay.congestion_control,
            CongestionControl::NewReno
        ));
        assert_eq!(config.relay.alpn, [b"h3".to_vec(), b"tuic".to_vec()]);
        assert!(config.relay.zero_rtt_handshake);
        assert!(config.relay.disable_sni);
        assert_eq!(config.relay.timeout, Duration::from_millis(1250));
        assert_eq!(config.relay.heartbeat, Duration::from_secs(4));
        assert!(config.relay.disable_native_certs);
        assert_eq!(config.relay.send_window, 123456);
        assert_eq!(config.relay.receive_window, 654321);
        assert_eq!(config.relay.gc_interval, Duration::from_millis(250));
        assert_eq!(config.relay.gc_lifetime, Duration::from_secs(30));

        assert_eq!(config.local.server, "[::1]:2080".parse().unwrap());
        assert_eq!(config.local.username.as_deref(), Some(b"client".as_slice()));
        assert_eq!(config.local.password.as_deref(), Some(b"s:cret".as_slice()));
        assert_eq!(config.local.dual_stack, Some(true));
        assert_eq!(config.local.max_packet_size, 4096);
        assert!(config.local.enable_http);
        assert_eq!(config.log_level, LevelFilter::Info);
    }

    #[test]
    fn optional_credentials_preserve_utf8_bytes() {
        let mut value = minimal_config();
        value["local"]["username"] = json!("us\u{e9}r");
        value["local"]["password"] = json!("");

        let config = parse_file(&value).unwrap();
        assert_eq!(
            config.local.username.as_deref(),
            Some("us\u{e9}r".as_bytes())
        );
        assert_eq!(config.local.password.as_deref(), Some(b"".as_slice()));
    }

    #[test]
    fn json_rejects_unknown_fields_at_every_level() {
        let mut root = minimal_config();
        root["unexpected"] = json!(true);
        assert!(matches!(parse_file(&root), Err(ConfigError::Serde(_))));

        let mut relay = minimal_config();
        relay["relay"]["unexpected"] = json!(true);
        assert!(matches!(parse_file(&relay), Err(ConfigError::Serde(_))));

        let mut local = minimal_config();
        local["local"]["unexpected"] = json!(true);
        assert!(matches!(parse_file(&local), Err(ConfigError::Serde(_))));
    }

    #[test]
    fn json_rejects_invalid_relay_values() {
        let cases = [
            ("server", json!("example.com")),
            ("server", json!(":443")),
            ("server", json!("example.com:0")),
            ("server", json!("example.com:65536")),
            ("server", json!("example.com:not-a-port")),
            ("udp_relay_mode", json!("datagram")),
            ("congestion_control", json!("reno")),
            ("timeout", json!("eventually")),
            ("uuid", json!("not-a-uuid")),
        ];

        for (field, invalid) in cases {
            let mut value = minimal_config();
            value["relay"][field] = invalid;
            assert!(
                matches!(parse_file(&value), Err(ConfigError::Serde(_))),
                "accepted invalid relay field {field}"
            );
        }
    }
}
