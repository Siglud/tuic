use quinn::ConnectionError;
use rustls::Error as RustlsError;
use std::{io::Error as IoError, net::SocketAddr};
use thiserror::Error;
use tuic_quinn::Error as ModelError;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    #[error("invalid max idle time")]
    InvalidMaxIdleTime,
    #[error("connection timed out")]
    TimedOut,
    #[error("connection locally closed")]
    LocallyClosed,
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("duplicated authentication")]
    DuplicatedAuth,
    #[error("authentication failed: {0}")]
    AuthFailed(Uuid),
    #[error("received packet from unexpected source")]
    UnexpectedPacketSource,
    #[error("{0}: {1}")]
    Socket(&'static str, #[source] IoError),
    #[error("task negotiation timed out")]
    TaskNegotiationTimeout,
    #[error("failed sending packet to {0}: relaying IPv6 UDP packet is disabled")]
    UdpRelayIpv6Disabled(SocketAddr),
}

impl Error {
    pub fn is_trivial(&self) -> bool {
        matches!(self, Self::TimedOut | Self::LocallyClosed)
    }
}

impl From<ConnectionError> for Error {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::TimedOut => Self::TimedOut,
            ConnectionError::LocallyClosed => Self::LocallyClosed,
            _ => Self::Io(IoError::from(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error::Error as StdError, io::ErrorKind};

    #[test]
    fn only_timeout_and_local_close_are_trivial() {
        assert!(Error::TimedOut.is_trivial());
        assert!(Error::LocallyClosed.is_trivial());
        assert!(!Error::DuplicatedAuth.is_trivial());
        assert!(!Error::TaskNegotiationTimeout.is_trivial());
    }

    #[test]
    fn connection_close_errors_map_to_server_variants() {
        assert!(matches!(
            Error::from(ConnectionError::TimedOut),
            Error::TimedOut
        ));
        assert!(matches!(
            Error::from(ConnectionError::LocallyClosed),
            Error::LocallyClosed
        ));
    }

    #[test]
    fn errors_display_context_and_expose_sources() {
        let io = Error::Io(IoError::new(ErrorKind::NotFound, "missing fixture"));
        assert_eq!(io.to_string(), "missing fixture");
        assert!(io.source().is_none());

        let socket = Error::Socket(
            "failed to bind test socket",
            IoError::new(ErrorKind::AddrInUse, "already bound"),
        );
        assert_eq!(
            socket.to_string(),
            "failed to bind test socket: already bound"
        );
        assert_eq!(socket.source().unwrap().to_string(), "already bound");

        let uuid = Uuid::nil();
        assert_eq!(
            Error::AuthFailed(uuid).to_string(),
            format!("authentication failed: {uuid}")
        );
        assert!(Error::DuplicatedAuth.source().is_none());
    }
}
