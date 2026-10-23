use log::Level;
use quinn::{ConnectError, ConnectionError, ReadError, WriteError};
use rustls::Error as RustlsError;
use std::io::Error as IoError;
use thiserror::Error;
use tuic_quinn::Error as ModelError;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("load native certificates error: {0}")]
    #[allow(dead_code)]
    LoadNativeCerts(IoError),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    #[error("{0}: {1}")]
    Socket(&'static str, IoError),
    #[error("timeout establishing connection")]
    Timeout,
    #[error("cannot resolve the server name")]
    DnsResolve,
    #[error("received packet from an unexpected source")]
    WrongPacketSource,
    #[error("invalid socks5 authentication")]
    InvalidSocks5Auth,
    #[error("relay.forwarder_server and relay.ip cannot both be set")]
    ConflictingRelayAddresses,
}

impl Error {
    pub fn connection_log_level(&self, active_tasks: usize) -> Level {
        let Self::Io(err) = self else {
            return Level::Warn;
        };
        match err
            .get_ref()
            .and_then(|source| source.downcast_ref::<ConnectionError>())
        {
            Some(ConnectionError::TimedOut) if active_tasks == 0 => Level::Info,
            Some(ConnectionError::LocallyClosed) => Level::Debug,
            _ => Level::Warn,
        }
    }
}

pub fn stream_error_log_level(err: &IoError) -> Level {
    if let Some(source) = err.get_ref() {
        if matches!(source.downcast_ref::<ReadError>(), Some(ReadError::Reset(code)) if *code == quinn::VarInt::from_u32(0))
            || matches!(source.downcast_ref::<WriteError>(), Some(WriteError::Stopped(code)) if *code == quinn::VarInt::from_u32(0))
        {
            return Level::Info;
        }
    }
    Level::Warn
}

impl From<ConnectionError> for Error {
    fn from(err: ConnectionError) -> Self {
        Self::Io(IoError::from(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn idle_expiration_is_info_but_active_timeouts_remain_warnings() {
        let err = Error::from(ConnectionError::TimedOut);
        assert_eq!(err.connection_log_level(0), Level::Info);
        assert_eq!(err.connection_log_level(1), Level::Warn);
        assert_eq!(
            Error::from(ConnectionError::LocallyClosed).connection_log_level(0),
            Level::Debug
        );
        assert_eq!(Error::Timeout.connection_log_level(0), Level::Warn);
        assert_eq!(
            Error::WrongPacketSource.connection_log_level(0),
            Level::Warn
        );
        assert_eq!(
            Error::from(IoError::new(ErrorKind::TimedOut, "socket timed out"))
                .connection_log_level(0),
            Level::Warn
        );
    }

    #[test]
    fn only_zero_code_quic_stream_cleanup_is_informational() {
        for (code, expected) in [(0, Level::Info), (42, Level::Warn)] {
            let code = quinn::VarInt::from_u32(code);
            for err in [
                IoError::from(ReadError::Reset(code)),
                IoError::from(WriteError::Stopped(code)),
            ] {
                assert_eq!(stream_error_log_level(&err), expected, "{err}");
            }
        }
        for err in [
            IoError::new(ErrorKind::ConnectionReset, "TCP connection reset"),
            IoError::new(ErrorKind::BrokenPipe, "TCP connection closed"),
            IoError::from(ReadError::ConnectionLost(ConnectionError::TimedOut)),
            IoError::from(WriteError::ConnectionLost(ConnectionError::TimedOut)),
        ] {
            assert_eq!(stream_error_log_level(&err), Level::Warn, "{err}");
        }
    }
}
