use humantime::Duration as HumanDuration;
use lexopt::{Arg, Error as ArgumentError, Parser};
use log::LevelFilter;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use std::{ffi::OsString, fs::File, io, net::SocketAddr, num::NonZeroUsize, time::Duration};
use thiserror::Error;

const HELP_MSG: &str = r#"
Usage tuic-udp-forwarder [arguments]

Arguments:
    -c, --config <path>     Path to the JSONC config file (any extension, required)
    -v, --version           Print the version
    -h, --help              Print this help message
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: SocketAddr,
    pub upstream: String,
    pub dual_stack: Option<bool>,
    #[serde(
        default = "default_idle_timeout",
        deserialize_with = "deserialize_timeout"
    )]
    pub idle_timeout: Duration,
    #[serde(default = "default_max_clients")]
    pub max_clients: NonZeroUsize,
    #[serde(default = "default_log_level")]
    pub log_level: LevelFilter,
}

impl Config {
    pub fn parse<I>(args: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator,
        I::Item: Into<OsString>,
    {
        let mut parser = Parser::from_iter(args);
        let mut path = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('c') | Arg::Long("config") if path.is_none() => {
                    path = Some(parser.value()?);
                }
                Arg::Short('v') | Arg::Long("version") => {
                    return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")));
                }
                Arg::Short('h') | Arg::Long("help") => return Err(ConfigError::Help(HELP_MSG)),
                _ => return Err(ConfigError::Argument(arg.unexpected())),
            }
        }

        let file = File::open(path.ok_or(ConfigError::NoConfig)?)?;
        Ok(serde_json_lenient::from_reader(file)?)
    }
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_max_clients() -> NonZeroUsize {
    NonZeroUsize::new(1024).unwrap()
}

fn default_log_level() -> LevelFilter {
    LevelFilter::Warn
}

fn deserialize_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    let duration = text.parse::<HumanDuration>().map_err(DeError::custom)?;
    let duration = Duration::from(duration);
    if duration.is_zero() || std::time::Instant::now().checked_add(duration).is_none() {
        return Err(DeError::custom(
            "idle_timeout must be positive and fit in a timer",
        ));
    }
    Ok(duration)
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
    Io(#[from] io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json_lenient::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::{Builder, NamedTempFile};

    fn minimal_config() -> serde_json::Value {
        json!({"server": "127.0.0.1:0", "upstream": "localhost:443"})
    }

    fn parse_text_file(text: &str, suffix: &str) -> Result<Config, ConfigError> {
        let file = Builder::new().suffix(suffix).tempfile().unwrap();
        fs::write(file.path(), text).unwrap();
        Config::parse(vec![
            OsString::from("forwarder"),
            OsString::from("--config"),
            file.path().as_os_str().to_owned(),
        ])
    }

    #[test]
    fn cli_loads_jsonc_regardless_of_extension() {
        let text = r#"
        /* Forwarder configuration */
        {
            "server": "127.0.0.1:0", // UDP listener
            "upstream": "localhost:443",
            "idle_timeout": /* Inline comment */ "1250ms",
        } // No final newline"#;

        for suffix in [".json", ".jsonc", ".conf", ""] {
            let config = parse_text_file(text, suffix).unwrap();
            assert_eq!(config.server, "127.0.0.1:0".parse().unwrap());
            assert_eq!(config.upstream, "localhost:443");
            assert_eq!(config.idle_timeout, Duration::from_millis(1250));
            assert_eq!(config.max_clients.get(), 1024);
            assert_eq!(config.log_level, LevelFilter::Warn);
        }
    }

    #[test]
    fn cli_rejects_malformed_jsonc() {
        let valid = minimal_config().to_string();
        for text in [
            "{ invalid".to_string(),
            format!("{valid} /* unterminated"),
            format!("{valid}\n{{}}"),
            valid.replace("\"upstream\":", "\"upstream\" /* missing colon */"),
            valid.replace("\"server\":", "server:"),
            valid.replacen("\"server\"", "'server'", 1),
        ] {
            match parse_text_file(&text, ".json") {
                Err(ConfigError::Serde(error)) => {
                    assert!(error.line() > 0);
                    assert!(error.column() > 0);
                }
                _ => panic!("expected a JSONC parsing error"),
            }
        }
    }

    #[test]
    fn readme_configurations_are_valid_jsonc() {
        let mut examples = 0;
        for readme in [
            include_str!("../README.md"),
            include_str!("../../README.md"),
        ] {
            for block in readme.split("```jsonc").skip(1) {
                let text = block.split_once("```").unwrap().0;
                let value: serde_json_lenient::Value = serde_json_lenient::from_str(text).unwrap();
                if value.get("upstream").is_some() {
                    parse_text_file(text, ".json").unwrap();
                    examples += 1;
                }
            }
        }
        assert_eq!(examples, 2);
    }

    #[test]
    fn defaults_and_complete_config() {
        let cfg: Config = serde_json::from_value(minimal_config()).unwrap();
        assert_eq!(cfg.server, "127.0.0.1:0".parse().unwrap());
        assert_eq!(cfg.upstream, "localhost:443");
        assert_eq!(cfg.dual_stack, None);
        assert_eq!(cfg.idle_timeout, Duration::from_secs(60));
        assert_eq!(cfg.max_clients.get(), 1024);
        assert_eq!(cfg.log_level, LevelFilter::Warn);

        let cfg: Config = serde_json::from_value(json!({
            "server": "[::]:8443",
            "upstream": "[::1]:443",
            "dual_stack": true,
            "idle_timeout": "1250ms",
            "max_clients": 5,
            "log_level": "debug"
        }))
        .unwrap();
        assert_eq!(cfg.server, "[::]:8443".parse().unwrap());
        assert_eq!(cfg.upstream, "[::1]:443");
        assert_eq!(cfg.dual_stack, Some(true));
        assert_eq!(cfg.idle_timeout, Duration::from_millis(1250));
        assert_eq!(cfg.max_clients.get(), 5);
        assert_eq!(cfg.log_level, LevelFilter::Debug);
    }

    #[test]
    fn rejects_invalid_settings() {
        for (field, value) in [
            ("server", json!("not-an-address")),
            ("idle_timeout", json!("0s")),
            ("idle_timeout", json!("eventually")),
            ("max_clients", json!(0)),
            ("max_clients", json!(-1)),
            ("log_level", json!("invalid")),
            ("unexpected", json!(true)),
        ] {
            let mut config = minimal_config();
            config[field] = value;
            assert!(serde_json::from_value::<Config>(config).is_err(), "{field}");
        }
        for field in ["server", "upstream"] {
            let mut config = minimal_config();
            config.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Config>(config).is_err());
        }
    }

    #[test]
    fn cli_handles_help_version_and_invalid_arguments() {
        assert!(matches!(
            Config::parse(["forwarder"]),
            Err(ConfigError::NoConfig)
        ));
        for flag in ["-h", "--help"] {
            assert!(matches!(
                Config::parse(["forwarder", flag]),
                Err(ConfigError::Help(_))
            ));
        }
        for flag in ["-v", "--version"] {
            assert!(matches!(
                Config::parse(["forwarder", flag]),
                Err(ConfigError::Version(_))
            ));
        }
        for args in [
            vec!["forwarder", "--unknown"],
            vec!["forwarder", "-c"],
            vec!["forwarder", "-c", "a", "--config", "b"],
        ] {
            assert!(matches!(Config::parse(args), Err(ConfigError::Argument(_))));
        }
    }

    #[test]
    fn cli_loads_json_and_reports_file_and_json_errors() {
        let file = NamedTempFile::new().unwrap();
        let args = vec![
            OsString::from("forwarder"),
            OsString::from("--config"),
            file.path().as_os_str().to_owned(),
        ];
        fs::write(file.path(), minimal_config().to_string()).unwrap();
        assert_eq!(
            Config::parse(args.clone()).unwrap().upstream,
            "localhost:443"
        );
        fs::write(file.path(), "{ invalid").unwrap();
        assert!(matches!(
            Config::parse(args.clone()),
            Err(ConfigError::Serde(_))
        ));
        drop(file);
        assert!(matches!(Config::parse(args), Err(ConfigError::Io(_))));
    }
}
