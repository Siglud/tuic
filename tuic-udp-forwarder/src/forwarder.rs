use crate::config::Config;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::watch,
    task::{AbortHandle, Id, JoinError, JoinSet},
    time::{self, Instant},
};

const MAX_DATAGRAM_SIZE: usize = u16::MAX as usize;
struct Session {
    upstream: Arc<UdpSocket>,
    activity: watch::Sender<Instant>,
    task: AbortHandle,
}

pub struct Forwarder {
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    idle_timeout: Duration,
    max_clients: usize,
    sessions: HashMap<SocketAddr, Session>,
    tasks: JoinSet<(SocketAddr, io::Result<()>)>,
}

impl Forwarder {
    pub async fn bind(cfg: &Config) -> io::Result<Self> {
        let upstream = lookup_host(&cfg.upstream)
            .await?
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no upstream address resolved"))?;
        if upstream.port() == 0 || upstream.ip().is_unspecified() || upstream.ip().is_multicast() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "upstream must be a unicast address with a nonzero port",
            ));
        }

        let socket = Socket::new(
            Domain::for_address(cfg.server),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if cfg.server.is_ipv6() {
            if let Some(dual_stack) = cfg.dual_stack {
                socket.set_only_v6(!dual_stack)?;
            }
        }
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(cfg.server))?;
        let socket = UdpSocket::from_std(StdUdpSocket::from(socket))?;
        if socket.local_addr()? == upstream {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "upstream cannot be the listening address",
            ));
        }

        Ok(Self {
            socket: Arc::new(socket),
            upstream,
            idle_timeout: cfg.idle_timeout,
            max_clients: cfg.max_clients.get(),
            sessions: HashMap::new(),
            tasks: JoinSet::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    pub async fn run(mut self) -> io::Result<()> {
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        loop {
            tokio::select! {
                biased;
                Some(result) = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    self.reap_session(result);
                }
                result = self.socket.recv_from(&mut buffer) => {
                    let (len, client) = match result {
                        Ok(result) => result,
                        Err(err) if matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused) => {
                            log::warn!("listener received a UDP connection error: {err}");
                            continue;
                        }
                        Err(err) => return Err(err),
                    };
                    if let Err(err) = self.forward_packet(client, &buffer[..len]).await {
                        log::warn!("[{client}] failed forwarding datagram: {err}");
                    }
                }
            }
        }
    }

    async fn forward_packet(&mut self, client: SocketAddr, packet: &[u8]) -> io::Result<()> {
        if self
            .sessions
            .get(&client)
            .is_some_and(|session| session.activity.is_closed())
        {
            self.sessions.remove(&client).unwrap().task.abort();
        }

        if !self.sessions.contains_key(&client) {
            if self.sessions.len() >= self.max_clients {
                return Err(io::Error::new(
                    ErrorKind::ConnectionRefused,
                    "maximum client mappings reached",
                ));
            }

            let bind_address = match self.upstream {
                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            };
            let upstream = UdpSocket::bind(bind_address).await?;
            upstream.connect(self.upstream).await?;
            let upstream = Arc::new(upstream);
            let (activity, receiver) = watch::channel(Instant::now());
            let listener = self.socket.clone();
            let idle_timeout = self.idle_timeout;
            let session_upstream = upstream.clone();
            let task = self.tasks.spawn(async move {
                (
                    client,
                    run_session(listener, session_upstream, client, receiver, idle_timeout).await,
                )
            });
            self.sessions.insert(
                client,
                Session {
                    upstream,
                    activity,
                    task,
                },
            );
            log::debug!("[{client}] created upstream mapping");
        }

        let session = &self.sessions[&client];
        let result = time::timeout(self.idle_timeout, session.upstream.send(packet))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "upstream send timed out"))
            .and_then(|result| result);
        match result {
            Ok(_) => {
                session.activity.send_replace(Instant::now());
                Ok(())
            }
            Err(err) => {
                self.sessions.remove(&client).unwrap().task.abort();
                Err(err)
            }
        }
    }

    fn reap_session(&mut self, result: Result<(Id, (SocketAddr, io::Result<()>)), JoinError>) {
        match result {
            Ok((id, (client, result))) => {
                // A new mapping may already have replaced this completed task.
                if self
                    .sessions
                    .get(&client)
                    .is_some_and(|session| session.task.id() == id)
                {
                    self.sessions.remove(&client);
                }
                match result {
                    Ok(()) => log::debug!("[{client}] upstream mapping expired"),
                    Err(err) => log::warn!("[{client}] upstream mapping failed: {err}"),
                }
            }
            Err(err) => {
                self.sessions
                    .retain(|_, session| session.task.id() != err.id());
                if !err.is_cancelled() {
                    log::warn!("upstream mapping task failed: {err}");
                }
            }
        }
    }
}

async fn run_session(
    listener: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    client: SocketAddr,
    mut activity: watch::Receiver<Instant>,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
    let mut deadline = Instant::now() + idle_timeout;
    loop {
        tokio::select! {
            _ = time::sleep_until(deadline) => {
                deadline = deadline.max(*activity.borrow_and_update() + idle_timeout);
                if deadline <= Instant::now() {
                    return Ok(());
                }
            }
            changed = activity.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                deadline = deadline.max(*activity.borrow_and_update() + idle_timeout);
            }
            result = upstream.recv(&mut buffer) => {
                let len = result?;
                time::timeout(idle_timeout, listener.send_to(&buffer[..len], client))
                    .await.map_err(|_| io::Error::new(ErrorKind::TimedOut, "client send timed out"))??;
                deadline = Instant::now() + idle_timeout;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    async fn udp_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    fn config(upstream: SocketAddr) -> Config {
        serde_json::from_value(json!({
            "server": "127.0.0.1:0",
            "upstream": upstream.to_string()
        }))
        .unwrap()
    }

    async fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        let (len, peer) = time::timeout(TEST_TIMEOUT, socket.recv_from(&mut buffer))
            .await
            .expect("datagram receive timed out")
            .unwrap();
        buffer.truncate(len);
        (buffer, peer)
    }

    fn start(forwarder: Forwarder) -> (SocketAddr, JoinSet<io::Result<()>>) {
        let address = forwarder.local_addr().unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(forwarder.run());
        (address, tasks)
    }

    #[tokio::test]
    async fn preserves_binary_empty_and_maximum_ipv4_datagrams() {
        let upstream = udp_socket().await;
        let forwarder = Forwarder::bind(&config(upstream.local_addr().unwrap()))
            .await
            .unwrap();
        let (address, _tasks) = start(forwarder);
        let client = udp_socket().await;

        for payload in [vec![0, 255, 1, 128, 0], vec![], vec![0xa5; 65507]] {
            client.send_to(&payload, address).await.unwrap();
            let (observed, peer) = receive(&upstream).await;
            assert_eq!(observed, payload);
            upstream.send_to(&observed, peer).await.unwrap();
            let (reply, source) = receive(&client).await;
            assert_eq!(reply, payload);
            assert_eq!(source, address);
        }
    }

    #[tokio::test]
    async fn isolates_clients_and_filters_non_upstream_replies() {
        let upstream = udp_socket().await;
        let rogue = udp_socket().await;
        let forwarder = Forwarder::bind(&config(upstream.local_addr().unwrap()))
            .await
            .unwrap();
        let (address, _tasks) = start(forwarder);
        let first = udp_socket().await;
        let second = udp_socket().await;

        first.send_to(b"first", address).await.unwrap();
        let (payload, first_peer) = receive(&upstream).await;
        assert_eq!(payload, b"first");
        second.send_to(b"second", address).await.unwrap();
        let (payload, second_peer) = receive(&upstream).await;
        assert_eq!(payload, b"second");
        assert_ne!(first_peer, second_peer);

        rogue.send_to(b"spoofed", first_peer).await.unwrap();
        upstream
            .send_to(b"second-reply", second_peer)
            .await
            .unwrap();
        upstream.send_to(b"first-reply", first_peer).await.unwrap();
        assert_eq!(receive(&second).await.0, b"second-reply");
        assert_eq!(receive(&first).await.0, b"first-reply");

        first.send_to(b"still-first", address).await.unwrap();
        assert_eq!(
            receive(&upstream).await,
            (b"still-first".to_vec(), first_peer)
        );
    }

    #[tokio::test]
    async fn forwards_between_ipv4_and_ipv6_in_both_directions() {
        for (listen, upstream_bind, client_bind) in [
            ("[::1]:0", "127.0.0.1:0", "[::1]:0"),
            ("127.0.0.1:0", "[::1]:0", "127.0.0.1:0"),
        ] {
            let upstream = UdpSocket::bind(upstream_bind).await.unwrap();
            let mut cfg = config(upstream.local_addr().unwrap());
            cfg.server = listen.parse().unwrap();
            cfg.dual_stack = Some(false);
            let forwarder = Forwarder::bind(&cfg).await.unwrap();
            let (address, _tasks) = start(forwarder);
            let client = UdpSocket::bind(client_bind).await.unwrap();
            client.send_to(b"cross-family", address).await.unwrap();
            let (payload, peer) = receive(&upstream).await;
            assert_eq!(payload, b"cross-family");
            upstream.send_to(&payload, peer).await.unwrap();
            assert_eq!(receive(&client).await, (payload, address));
        }
    }

    #[tokio::test]
    async fn dual_stack_listener_accepts_ipv4_clients() {
        let upstream = udp_socket().await;
        let mut cfg = config(upstream.local_addr().unwrap());
        cfg.server = "[::]:0".parse().unwrap();
        cfg.dual_stack = Some(true);
        let forwarder = Forwarder::bind(&cfg).await.unwrap();
        let port = forwarder.local_addr().unwrap().port();
        let (_, _tasks) = start(forwarder);
        let client = udp_socket().await;
        client
            .send_to(b"dual-stack", ("127.0.0.1", port))
            .await
            .unwrap();
        let (payload, peer) = receive(&upstream).await;
        upstream.send_to(&payload, peer).await.unwrap();
        assert_eq!(receive(&client).await.0, b"dual-stack");
    }

    #[tokio::test]
    async fn forwards_bursts_larger_than_the_old_queue_and_bounds_client_mappings() {
        let upstream = udp_socket().await;
        let mut cfg = config(upstream.local_addr().unwrap());
        cfg.max_clients = 1.try_into().unwrap();
        let mut forwarder = Forwarder::bind(&cfg).await.unwrap();
        let first_socket = udp_socket().await;
        let second_socket = udp_socket().await;
        let first = first_socket.local_addr().unwrap();
        let second = second_socket.local_addr().unwrap();

        const BURST_SIZE: u8 = 64;
        for index in 0..BURST_SIZE {
            forwarder.forward_packet(first, &[index]).await.unwrap();
        }
        assert_eq!(
            forwarder
                .forward_packet(second, b"new client")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::ConnectionRefused
        );
        assert_eq!(forwarder.sessions.len(), 1);
        assert_eq!(forwarder.tasks.len(), 1);
        for index in 0..BURST_SIZE {
            let (payload, peer) = receive(&upstream).await;
            assert_eq!(payload, [index]);
            upstream.send_to(&payload, peer).await.unwrap();
            assert_eq!(receive(&first_socket).await.0, payload);
        }
    }

    #[tokio::test]
    async fn activity_in_either_direction_resets_expiry_and_releases_capacity() {
        let upstream = udp_socket().await;
        let client = udp_socket().await;
        let client_addr = client.local_addr().unwrap();
        let mut cfg = config(upstream.local_addr().unwrap());
        cfg.max_clients = 1.try_into().unwrap();
        let mut forwarder = Forwarder::bind(&cfg).await.unwrap();
        forwarder
            .forward_packet(client_addr, b"initial")
            .await
            .unwrap();
        let (_, peer) = receive(&upstream).await;

        time::pause();
        time::advance(Duration::from_secs(40)).await;
        time::resume();
        forwarder
            .forward_packet(client_addr, b"refresh")
            .await
            .unwrap();
        assert_eq!(receive(&upstream).await.0, b"refresh");
        time::pause();
        time::advance(Duration::from_secs(40)).await;
        assert!(!forwarder.sessions[&client_addr].activity.is_closed());
        time::resume();
        upstream.send_to(b"reply-refresh", peer).await.unwrap();
        assert_eq!(receive(&client).await.0, b"reply-refresh");
        time::pause();
        time::advance(Duration::from_secs(40)).await;
        assert!(!forwarder.sessions[&client_addr].activity.is_closed());
        time::advance(Duration::from_secs(21)).await;
        let result = forwarder.tasks.join_next_with_id().await.unwrap();
        forwarder.reap_session(result);
        assert!(forwarder.sessions.is_empty());

        time::resume();
        let new_client = udp_socket().await;
        forwarder
            .forward_packet(new_client.local_addr().unwrap(), b"new client")
            .await
            .unwrap();
        assert_eq!(receive(&upstream).await.0, b"new client");
    }

    #[tokio::test]
    async fn mapping_expiry_uses_the_forwarder_timeout_not_the_protocol_timeout() {
        for configured in [None, Some(Duration::from_secs(5))] {
            let upstream = udp_socket().await;
            let client = udp_socket().await;
            let client_addr = client.local_addr().unwrap();
            let mut cfg = config(upstream.local_addr().unwrap());
            if let Some(timeout) = configured {
                cfg.idle_timeout = timeout;
            }
            let mut forwarder = Forwarder::bind(&cfg).await.unwrap();
            forwarder
                .forward_packet(client_addr, b"initial")
                .await
                .unwrap();
            receive(&upstream).await;

            time::pause();
            let timeout = configured.unwrap_or(Duration::from_secs(60));
            time::advance(timeout - Duration::from_secs(1)).await;
            assert!(!forwarder.sessions[&client_addr].activity.is_closed());
            time::advance(Duration::from_secs(2)).await;
            let result = forwarder.tasks.join_next_with_id().await.unwrap();
            forwarder.reap_session(result);
            assert!(forwarder.sessions.is_empty());
            time::resume();
        }
    }

    #[tokio::test]
    async fn recreates_expired_mapping_before_old_task_is_reaped() {
        let upstream = udp_socket().await;
        let client = udp_socket().await.local_addr().unwrap();
        let mut forwarder = Forwarder::bind(&config(upstream.local_addr().unwrap()))
            .await
            .unwrap();
        forwarder.forward_packet(client, b"initial").await.unwrap();
        receive(&upstream).await;

        time::pause();
        time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(forwarder.sessions[&client].activity.is_closed());
        time::resume();
        forwarder
            .forward_packet(client, b"replacement")
            .await
            .unwrap();
        let new_task = forwarder.sessions[&client].task.id();
        let result = forwarder.tasks.join_next_with_id().await.unwrap();
        forwarder.reap_session(result);
        assert_eq!(forwarder.sessions[&client].task.id(), new_task);
        assert_eq!(receive(&upstream).await.0, b"replacement");
    }

    #[tokio::test]
    async fn dropping_forwarder_closes_session_tasks() {
        let upstream = udp_socket().await;
        let client = udp_socket().await.local_addr().unwrap();
        let mut forwarder = Forwarder::bind(&config(upstream.local_addr().unwrap()))
            .await
            .unwrap();
        forwarder.forward_packet(client, b"initial").await.unwrap();
        receive(&upstream).await;
        let sender = forwarder.sessions[&client].activity.clone();
        drop(forwarder);
        time::timeout(TEST_TIMEOUT, sender.closed()).await.unwrap();
    }

    #[tokio::test]
    async fn session_io_failure_releases_client_mapping() {
        let upstream = udp_socket().await;
        let mut cfg = config(upstream.local_addr().unwrap());
        cfg.max_clients = 1.try_into().unwrap();
        let mut forwarder = Forwarder::bind(&cfg).await.unwrap();
        let client = udp_socket().await;
        let err = forwarder
            .forward_packet(
                client.local_addr().unwrap(),
                &vec![0; MAX_DATAGRAM_SIZE + 1],
            )
            .await
            .unwrap_err();
        assert_ne!(err.kind(), ErrorKind::WouldBlock);
        assert!(forwarder.sessions.is_empty());

        forwarder
            .forward_packet(client.local_addr().unwrap(), b"replacement")
            .await
            .unwrap();
        assert_eq!(receive(&upstream).await.0, b"replacement");
    }

    #[tokio::test]
    async fn reports_resolution_bind_and_invalid_upstream_errors() {
        for upstream in [
            "127.0.0.1:0",
            "0.0.0.0:443",
            "224.0.0.1:443",
            "invalid\0host:443",
            "missing-port",
        ] {
            let mut cfg = config("127.0.0.1:443".parse().unwrap());
            cfg.upstream = upstream.to_string();
            assert!(Forwarder::bind(&cfg).await.is_err(), "{upstream:?}");
        }

        let listener = udp_socket().await;
        let mut cfg = config("127.0.0.1:443".parse().unwrap());
        cfg.server = listener.local_addr().unwrap();
        assert_eq!(
            Forwarder::bind(&cfg).await.err().unwrap().kind(),
            ErrorKind::AddrInUse
        );
    }

    #[tokio::test]
    async fn resolves_hostnames_at_startup() {
        let mut cfg = config("127.0.0.1:443".parse().unwrap());
        cfg.upstream = "localhost:443".to_string();
        let forwarder = Forwarder::bind(&cfg).await.unwrap();
        assert!(forwarder.upstream().ip().is_loopback());
        assert_eq!(forwarder.upstream().port(), 443);
    }
}
