use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};
use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use std::sync::atomic::Ordering;
use tokio::time;
use tuic_quinn::Task;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketSource {
    Datagram,
    UniStream,
}

impl Connection {
    pub async fn handle_uni_stream(self, recv: RecvStream, _reg: Register) {
        log::debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming unidirectional stream",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if let Some(next) = increased_stream_limit(self.remote_uni_stream_cnt.count(), max) {
            self.max_concurrent_uni_streams
                .store(next, Ordering::Relaxed);

            self.inner
                .set_max_concurrent_uni_streams(VarInt::from(next));
        }

        let pre_process = async {
            let task = time::timeout(
                self.task_negotiation_timeout,
                self.model.accept_uni_stream(recv),
            )
            .await
            .map_err(|_| Error::TaskNegotiationTimeout)??;

            if let Task::Authenticate(auth) = &task {
                self.authenticate(auth)?;
            }

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            let wrong_pkt_src = matches!(task, Task::Packet(_))
                && !accepts_packet_source(self.udp_relay_mode.load(), PacketSource::UniStream);
            if wrong_pkt_src {
                return Err(Error::UnexpectedPacketSource);
            }

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Authenticate(auth)) => self.handle_authenticate(auth).await,
            Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Quic).await,
            Ok(Task::Dissociate(assoc_id)) => self.handle_dissociate(assoc_id).await,
            Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming unidirectional stream error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }

    pub async fn handle_bi_stream(self, (send, recv): (SendStream, RecvStream), _reg: Register) {
        log::debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming bidirectional stream",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if let Some(next) = increased_stream_limit(self.remote_bi_stream_cnt.count(), max) {
            self.max_concurrent_bi_streams
                .store(next, Ordering::Relaxed);

            self.inner.set_max_concurrent_bi_streams(VarInt::from(next));
        }

        let pre_process = async {
            let task = time::timeout(
                self.task_negotiation_timeout,
                self.model.accept_bi_stream(send, recv),
            )
            .await
            .map_err(|_| Error::TaskNegotiationTimeout)??;

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Connect(conn)) => self.handle_connect(conn).await,
            Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming bidirectional stream error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }

    pub async fn handle_datagram(self, dg: Bytes) {
        log::debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming datagram",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let pre_process = async {
            let task = self.model.accept_datagram(dg)?;

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            let wrong_pkt_src = matches!(task, Task::Packet(_))
                && !accepts_packet_source(self.udp_relay_mode.load(), PacketSource::Datagram);
            if wrong_pkt_src {
                return Err(Error::UnexpectedPacketSource);
            }

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Native).await,
            Ok(Task::Heartbeat) => self.handle_heartbeat().await,
            Ok(_) => unreachable!(),
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming datagram error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }
}

fn increased_stream_limit(count: usize, current_limit: u32) -> Option<u32> {
    if count >= current_limit as usize {
        Some(current_limit.saturating_mul(2))
    } else {
        None
    }
}

fn accepts_packet_source(mode: Option<UdpRelayMode>, source: PacketSource) -> bool {
    matches!(
        (mode, source),
        (None, _)
            | (Some(UdpRelayMode::Native), PacketSource::Datagram)
            | (Some(UdpRelayMode::Quic), PacketSource::UniStream)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_limit_doubles_at_or_above_capacity_and_saturates() {
        assert_eq!(increased_stream_limit(31, 32), None);
        assert_eq!(increased_stream_limit(32, 32), Some(64));
        assert_eq!(increased_stream_limit(33, 32), Some(64));
        assert_eq!(increased_stream_limit(usize::MAX, u32::MAX), Some(u32::MAX));
    }

    #[test]
    fn first_packet_source_is_accepted() {
        assert!(accepts_packet_source(None, PacketSource::Datagram));
        assert!(accepts_packet_source(None, PacketSource::UniStream));
    }

    #[test]
    fn established_udp_mode_accepts_only_matching_packet_source() {
        assert!(accepts_packet_source(
            Some(UdpRelayMode::Native),
            PacketSource::Datagram
        ));
        assert!(!accepts_packet_source(
            Some(UdpRelayMode::Native),
            PacketSource::UniStream
        ));
        assert!(accepts_packet_source(
            Some(UdpRelayMode::Quic),
            PacketSource::UniStream
        ));
        assert!(!accepts_packet_source(
            Some(UdpRelayMode::Quic),
            PacketSource::Datagram
        ));
    }
}
