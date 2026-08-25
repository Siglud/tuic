use crate::utils::CongestionControl;
use humantime::Duration as HumanDuration;
use lexopt::{Arg, Error as ArgumentError, Parser};
use log::LevelFilter;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use serde_json::Error as SerdeError;
use std::{
    collections::HashMap, env::ArgsOs, ffi::OsString, fmt::Display, fs::File, io::Error as IoError,
    net::SocketAddr, path::PathBuf, str::FromStr, time::Duration,
};
use thiserror::Error;
use uuid::Uuid;

const HELP_MSG: &str = r#"
Usage tuic-server [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: SocketAddr,

    #[serde(deserialize_with = "deserialize_users")]
    pub users: HashMap<Uuid, Box<[u8]>>,

    pub certificate: PathBuf,

    pub private_key: PathBuf,

    #[serde(
        default = "default::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    #[serde(default = "default::alpn", deserialize_with = "deserialize_alpn")]
    pub alpn: Vec<Vec<u8>>,

    #[serde(default = "default::udp_relay_ipv6")]
    pub udp_relay_ipv6: bool,

    #[serde(default = "default::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    pub dual_stack: Option<bool>,

    #[serde(
        default = "default::auth_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub auth_timeout: Duration,

    #[serde(
        default = "default::task_negotiation_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub task_negotiation_timeout: Duration,

    #[serde(
        default = "default::max_idle_time",
        deserialize_with = "deserialize_duration"
    )]
    pub max_idle_time: Duration,

    #[serde(default = "default::max_external_packet_size")]
    pub max_external_packet_size: usize,

    #[serde(default = "default::send_window")]
    pub send_window: u64,

    #[serde(default = "default::receive_window")]
    pub receive_window: u32,

    #[serde(
        default = "default::gc_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_interval: Duration,

    #[serde(
        default = "default::gc_lifetime",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_lifetime: Duration,

    #[serde(default = "default::log_level")]
    pub log_level: LevelFilter,
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
    use crate::utils::CongestionControl;
    use log::LevelFilter;
    use std::time::Duration;

    pub fn congestion_control() -> CongestionControl {
        CongestionControl::Cubic
    }

    pub fn alpn() -> Vec<Vec<u8>> {
        Vec::new()
    }

    pub fn udp_relay_ipv6() -> bool {
        true
    }

    pub fn zero_rtt_handshake() -> bool {
        false
    }

    pub fn auth_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn task_negotiation_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn max_idle_time() -> Duration {
        Duration::from_secs(10)
    }

    pub fn max_external_packet_size() -> usize {
        1500
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

pub fn deserialize_users<'de, D>(deserializer: D) -> Result<HashMap<Uuid, Box<[u8]>>, D::Error>
where
    D: Deserializer<'de>,
{
    let users = HashMap::<Uuid, String>::deserialize(deserializer)?;

    if users.is_empty() {
        return Err(DeError::custom("users cannot be empty"));
    }

    Ok(users
        .into_iter()
        .map(|(k, v)| (k, v.into_bytes().into_boxed_slice()))
        .collect())
}

pub fn deserialize_alpn<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    Ok(s.into_iter().map(|alpn| alpn.into_bytes()).collect())
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
    use std::{ffi::OsString, fs};
    use tempfile::NamedTempFile;

    const UUID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn minimal_config() -> Value {
        json!({
            "server": "127.0.0.1:443",
            "users": { UUID: "secret" },
            "certificate": "certificate.pem",
            "private_key": "private-key.pem"
        })
    }

    fn parse_file(value: &Value) -> Result<Config, ConfigError> {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(value).unwrap()).unwrap();

        Config::parse_from(vec![
            OsString::from("tuic-server"),
            OsString::from("--config"),
            file.path().as_os_str().to_owned(),
        ])
    }

    #[test]
    fn cli_requires_config() {
        assert!(matches!(
            Config::parse_from(args(&["tuic-server"])),
            Err(ConfigError::NoConfig)
        ));
    }

    #[test]
    fn cli_reports_help_and_version() {
        for flag in ["-h", "--help"] {
            assert!(matches!(
                Config::parse_from(args(&["tuic-server", flag])),
                Err(ConfigError::Help(HELP_MSG))
            ));
        }

        for flag in ["-v", "--version"] {
            assert!(matches!(
                Config::parse_from(args(&["tuic-server", flag])),
                Err(ConfigError::Version(env!("CARGO_PKG_VERSION")))
            ));
        }
    }

    #[test]
    fn cli_rejects_unknown_duplicate_and_missing_arguments() {
        let cases = [
            args(&["tuic-server", "--unknown"]),
            args(&["tuic-server", "--config", "first.json", "-c", "second.json"]),
            args(&["tuic-server", "--config"]),
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
        let uuid = Uuid::parse_str(UUID).unwrap();

        assert_eq!(config.server, "127.0.0.1:443".parse().unwrap());
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[&uuid].as_ref(), b"secret");
        assert_eq!(config.certificate, PathBuf::from("certificate.pem"));
        assert_eq!(config.private_key, PathBuf::from("private-key.pem"));
        assert!(matches!(
            config.congestion_control,
            CongestionControl::Cubic
        ));
        assert!(config.alpn.is_empty());
        assert!(config.udp_relay_ipv6);
        assert!(!config.zero_rtt_handshake);
        assert_eq!(config.dual_stack, None);
        assert_eq!(config.auth_timeout, Duration::from_secs(3));
        assert_eq!(config.task_negotiation_timeout, Duration::from_secs(3));
        assert_eq!(config.max_idle_time, Duration::from_secs(10));
        assert_eq!(config.max_external_packet_size, 1500);
        assert_eq!(config.send_window, 16 * 1024 * 1024);
        assert_eq!(config.receive_window, 1024 * 1024);
        assert_eq!(config.gc_interval, Duration::from_secs(3));
        assert_eq!(config.gc_lifetime, Duration::from_secs(15));
        assert_eq!(config.log_level, LevelFilter::Warn);
    }

    #[test]
    fn complete_json_deserializes_every_setting() {
        let value = json!({
            "server": "[::1]:8443",
            "users": { UUID: "p\u{e4}ssword" },
            "certificate": "server.der",
            "private_key": "server-key.der",
            "congestion_control": "NEWRENO",
            "alpn": ["h3", "tuic"],
            "udp_relay_ipv6": false,
            "zero_rtt_handshake": true,
            "dual_stack": true,
            "auth_timeout": "1250ms",
            "task_negotiation_timeout": "2s",
            "max_idle_time": "45s",
            "max_external_packet_size": 4096,
            "send_window": 123456,
            "receive_window": 654321,
            "gc_interval": "250ms",
            "gc_lifetime": "30s",
            "log_level": "info"
        });
        let config = parse_file(&value).unwrap();
        let uuid = Uuid::parse_str(UUID).unwrap();

        assert_eq!(config.server, "[::1]:8443".parse().unwrap());
        assert_eq!(config.users[&uuid].as_ref(), "p\u{e4}ssword".as_bytes());
        assert_eq!(config.certificate, PathBuf::from("server.der"));
        assert_eq!(config.private_key, PathBuf::from("server-key.der"));
        assert!(matches!(
            config.congestion_control,
            CongestionControl::NewReno
        ));
        assert_eq!(config.alpn, [b"h3".to_vec(), b"tuic".to_vec()]);
        assert!(!config.udp_relay_ipv6);
        assert!(config.zero_rtt_handshake);
        assert_eq!(config.dual_stack, Some(true));
        assert_eq!(config.auth_timeout, Duration::from_millis(1250));
        assert_eq!(config.task_negotiation_timeout, Duration::from_secs(2));
        assert_eq!(config.max_idle_time, Duration::from_secs(45));
        assert_eq!(config.max_external_packet_size, 4096);
        assert_eq!(config.send_window, 123456);
        assert_eq!(config.receive_window, 654321);
        assert_eq!(config.gc_interval, Duration::from_millis(250));
        assert_eq!(config.gc_lifetime, Duration::from_secs(30));
        assert_eq!(config.log_level, LevelFilter::Info);
    }

    #[test]
    fn json_rejects_unknown_fields_and_empty_users() {
        let mut unknown = minimal_config();
        unknown["unexpected"] = json!(true);
        assert!(matches!(parse_file(&unknown), Err(ConfigError::Serde(_))));

        let mut empty_users = minimal_config();
        empty_users["users"] = json!({});
        let error = match parse_file(&empty_users) {
            Ok(_) => panic!("accepted empty users"),
            Err(error) => error,
        };
        assert!(matches!(error, ConfigError::Serde(_)));
        assert!(error.to_string().contains("users cannot be empty"));
    }

    #[test]
    fn json_rejects_invalid_uuid_mode_duration_and_address() {
        let cases = [
            ("users", json!({ "not-a-uuid": "secret" })),
            ("congestion_control", json!("reno")),
            ("auth_timeout", json!("eventually")),
            ("server", json!("localhost:443")),
        ];

        for (field, invalid) in cases {
            let mut value = minimal_config();
            value[field] = invalid;
            assert!(
                matches!(parse_file(&value), Err(ConfigError::Serde(_))),
                "accepted invalid config field {field}"
            );
        }
    }
}
