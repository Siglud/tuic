use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};
use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use std::sync::atomic::Ordering;
use tuic_quinn::Task;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketSource {
    Datagram,
    UniStream,
}

impl Connection {
    pub async fn accept_uni_stream(&self) -> Result<(RecvStream, Register), Error> {
        let max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if let Some(next) = increased_stream_limit(self.remote_uni_stream_cnt.count(), max) {
            self.max_concurrent_uni_streams
                .store(next, Ordering::Relaxed);

            self.conn.set_max_concurrent_uni_streams(VarInt::from(next));
        }

        let recv = self.conn.accept_uni().await?;
        let reg = self.remote_uni_stream_cnt.reg();
        Ok((recv, reg))
    }

    pub async fn accept_bi_stream(&self) -> Result<(SendStream, RecvStream, Register), Error> {
        let max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if let Some(next) = increased_stream_limit(self.remote_bi_stream_cnt.count(), max) {
            self.max_concurrent_bi_streams
                .store(next, Ordering::Relaxed);

            self.conn.set_max_concurrent_bi_streams(VarInt::from(next));
        }

        let (send, recv) = self.conn.accept_bi().await?;
        let reg = self.remote_bi_stream_cnt.reg();
        Ok((send, recv, reg))
    }

    pub async fn accept_datagram(&self) -> Result<Bytes, Error> {
        Ok(self.conn.read_datagram().await?)
    }

    pub async fn handle_uni_stream(self, recv: RecvStream, _reg: Register) {
        log::debug!("[relay] incoming unidirectional stream");

        let res = match self.model.accept_uni_stream(recv).await {
            Err(err) => Err(Error::Model(err)),
            Ok(Task::Packet(pkt)) => {
                if accepts_packet_source(self.udp_relay_mode, PacketSource::UniStream) {
                    Self::handle_packet(pkt).await;
                    Ok(())
                } else {
                    Err(Error::WrongPacketSource)
                }
            }
            _ => unreachable!(), // already filtered in `tuic_quinn`
        };

        if let Err(err) = res {
            log::warn!("[relay] incoming unidirectional stream error: {err}");
        }
    }

    pub async fn handle_bi_stream(self, send: SendStream, recv: RecvStream, _reg: Register) {
        log::debug!("[relay] incoming bidirectional stream");

        let res = match self.model.accept_bi_stream(send, recv).await {
            Err(err) => Err::<(), _>(Error::Model(err)),
            _ => unreachable!(), // already filtered in `tuic_quinn`
        };

        if let Err(err) = res {
            log::warn!("[relay] incoming bidirectional stream error: {err}");
        }
    }

    pub async fn handle_datagram(self, dg: Bytes) {
        log::debug!("[relay] incoming datagram");

        let res = match self.model.accept_datagram(dg) {
            Err(err) => Err(Error::Model(err)),
            Ok(Task::Packet(pkt)) => {
                if accepts_packet_source(self.udp_relay_mode, PacketSource::Datagram) {
                    Self::handle_packet(pkt).await;
                    Ok(())
                } else {
                    Err(Error::WrongPacketSource)
                }
            }
            _ => unreachable!(), // already filtered in `tuic_quinn`
        };

        if let Err(err) = res {
            log::warn!("[relay] incoming datagram error: {err}");
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

fn accepts_packet_source(mode: UdpRelayMode, source: PacketSource) -> bool {
    matches!(
        (mode, source),
        (UdpRelayMode::Native, PacketSource::Datagram)
            | (UdpRelayMode::Quic, PacketSource::UniStream)
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
    fn udp_mode_accepts_only_its_expected_packet_source() {
        assert!(accepts_packet_source(
            UdpRelayMode::Native,
            PacketSource::Datagram
        ));
        assert!(!accepts_packet_source(
            UdpRelayMode::Native,
            PacketSource::UniStream
        ));
        assert!(accepts_packet_source(
            UdpRelayMode::Quic,
            PacketSource::UniStream
        ));
        assert!(!accepts_packet_source(
            UdpRelayMode::Quic,
            PacketSource::Datagram
        ));
    }
}
