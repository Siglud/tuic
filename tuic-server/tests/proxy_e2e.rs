use rcgen::generate_simple_self_signed;
use serde_json::json;
use std::{
    any::Any,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_tuic-server");
const UUID: &str = "3b9e80ea-78d7-4fd9-9d85-06b77cb5d0ce";
const RELAY_PASSWORD: &str = "e2e-relay-password";
const PROXY_USERNAME: &[u8] = b"user";
const PROXY_PASSWORD: &[u8] = b"pass";
const PROXY_BASIC_AUTH: &str = "dXNlcjpwYXNz";
const ALPN: &str = "tuic-e2e";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_TIMEOUT: Duration = Duration::from_secs(12);

static PAYLOAD_ID: AtomicU64 = AtomicU64::new(0);

#[test]
#[ignore = "requires prebuilt workspace binaries"]
fn cli_smoke_for_client_and_server() {
    let temp_dir = TempDir::new().expect("failed to create CLI smoke temp dir");
    let malformed_config = temp_dir.path().join("malformed.json");
    fs::write(&malformed_config, b"{ this is not JSON").expect("failed to write malformed config");

    for (name, binary) in [
        ("tuic-server", PathBuf::from(SERVER_BIN)),
        ("tuic-client", client_bin()),
    ] {
        let help = run(&binary, &["--help"]);
        assert_success(name, "--help", &help);
        assert!(
            String::from_utf8_lossy(&help.stdout).contains(&format!("Usage {name}")),
            "{name} --help did not contain its usage line:\n{}",
            output_text(&help)
        );

        let version = run(&binary, &["--version"]);
        assert_success(name, "--version", &version);
        assert!(
            String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")),
            "{name} --version did not contain {}:\n{}",
            env!("CARGO_PKG_VERSION"),
            output_text(&version)
        );

        for args in [&[][..], &["--not-a-real-option"] as &[&str]] {
            let output = run(&binary, args);
            assert!(
                !output.status.success(),
                "{name} unexpectedly accepted {args:?}:\n{}",
                output_text(&output)
            );
        }

        let malformed = Command::new(&binary)
            .arg("--config")
            .arg(&malformed_config)
            .output()
            .unwrap_or_else(|err| panic!("failed to run {}: {err}", binary.display()));
        assert!(
            !malformed.status.success(),
            "{name} unexpectedly accepted malformed JSON:\n{}",
            output_text(&malformed)
        );
    }
}

#[test]
#[ignore = "requires prebuilt workspace binaries"]
fn authenticated_socks5_and_http_connect_relay_tcp() {
    let mut harness = ServerHarness::start();
    let (mut client, proxy_addr) = harness.start_client("tcp", "native");
    let diagnostics = Diagnostics::new([harness.log_capture(), client.log_capture()]);

    with_diagnostics(&diagnostics, || {
        socks_connect_round_trip(proxy_addr, &unique_payload("socks-connect"));
        http_connect_round_trip(proxy_addr, &unique_payload("http-connect"));
    });

    client.assert_running();
    harness.assert_running();
}

#[test]
#[ignore = "requires prebuilt workspace binaries"]
fn udp_associate_relays_in_native_and_quic_modes() {
    let mut harness = ServerHarness::start();

    for mode in ["native", "quic"] {
        let (mut client, proxy_addr) = harness.start_client(mode, mode);
        let diagnostics = Diagnostics::new([harness.log_capture(), client.log_capture()]);

        with_diagnostics(&diagnostics, || {
            udp_associate_round_trip(proxy_addr, &unique_payload(&format!("udp-{mode}")));
        });

        client.assert_running();
        harness.assert_running();
        drop(client);
    }
}

struct ServerHarness {
    server: Option<ProcessGuard>,
    temp_dir: TempDir,
    relay_addr: SocketAddr,
    certificate: PathBuf,
}

impl ServerHarness {
    fn start() -> Self {
        let temp_dir = TempDir::new().expect("failed to create E2E temp dir");
        let certificate = temp_dir.path().join("localhost-cert.pem");
        let private_key = temp_dir.path().join("localhost-key.pem");
        let certified = generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("failed to generate localhost certificate");
        fs::write(&certificate, certified.cert.pem()).expect("failed to write certificate");
        fs::write(&private_key, certified.signing_key.serialize_pem())
            .expect("failed to write private key");

        let config_path = temp_dir.path().join("server.json");
        write_json(
            &config_path,
            &json!({
                "server": "127.0.0.1:0",
                "users": { UUID: RELAY_PASSWORD },
                "certificate": certificate,
                "private_key": private_key,
                "alpn": [ALPN],
                "udp_relay_ipv6": false,
                "log_level": "warn"
            }),
        );

        let mut server = ProcessGuard::spawn("tuic-server", Path::new(SERVER_BIN), &config_path);
        let relay_addr = server.wait_for_address("server started, listening on ");

        Self {
            server: Some(server),
            temp_dir,
            relay_addr,
            certificate,
        }
    }

    fn start_client(&self, name: &'static str, udp_relay_mode: &str) -> (ProcessGuard, SocketAddr) {
        let config_path = self.temp_dir.path().join(format!("client-{name}.json"));
        write_json(
            &config_path,
            &json!({
                "relay": {
                    "server": format!("localhost:{}", self.relay_addr.port()),
                    "uuid": UUID,
                    "password": RELAY_PASSWORD,
                    "ip": "127.0.0.1",
                    "certificates": [&self.certificate],
                    "udp_relay_mode": udp_relay_mode,
                    "alpn": [ALPN],
                    "disable_native_certs": true
                },
                "local": {
                    "server": "127.0.0.1:0",
                    "username": String::from_utf8_lossy(PROXY_USERNAME),
                    "password": String::from_utf8_lossy(PROXY_PASSWORD),
                    "enable_http": true
                },
                "log_level": "warn"
            }),
        );

        let mut client = ProcessGuard::spawn(name, &client_bin(), &config_path);
        let proxy_addr = client.wait_for_address("listening on ");
        (client, proxy_addr)
    }

    fn log_capture(&self) -> ProcessLog {
        self.server.as_ref().unwrap().log_capture()
    }

    fn assert_running(&mut self) {
        self.server.as_mut().unwrap().assert_running();
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        drop(self.server.take());
    }
}

struct ProcessGuard {
    name: &'static str,
    child: Child,
    log: ProcessLog,
    lines: Receiver<String>,
    stderr_reader: Option<JoinHandle<()>>,
}

impl ProcessGuard {
    fn spawn(name: &'static str, binary: &Path, config: &Path) -> Self {
        assert!(
            binary.is_file(),
            "{name} binary does not exist at {}",
            binary.display()
        );

        let mut child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {name} at {}: {err}", binary.display()));
        let stderr = child
            .stderr
            .take()
            .expect("spawned child has no stderr pipe");
        let (line_tx, lines) = mpsc::channel();
        let log = ProcessLog {
            name,
            lines: Arc::new(Mutex::new(Vec::new())),
        };
        let reader_log = log.clone();
        let stderr_reader = thread::Builder::new()
            .name(format!("{name}-stderr"))
            .spawn(move || {
                for line in BufReader::new(stderr).lines() {
                    let line = match line {
                        Ok(line) => line,
                        Err(err) => format!("<stderr read error: {err}>"),
                    };
                    lock(&reader_log.lines).push(line.clone());
                    if line_tx.send(line).is_err() {
                        break;
                    }
                }
            })
            .unwrap_or_else(|err| {
                let _ = child.kill();
                let _ = child.wait();
                panic!("failed to spawn {name} stderr reader: {err}");
            });

        Self {
            name,
            child,
            log,
            lines,
            stderr_reader: Some(stderr_reader),
        }
    }

    fn wait_for_address(&mut self, marker: &str) -> SocketAddr {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("{}\n{}", self.startup_failure(marker), self.log.render());
            }

            match self.lines.recv_timeout(remaining) {
                Ok(line) => {
                    if let Some((_, suffix)) = line.split_once(marker) {
                        let value = suffix.split_whitespace().next().unwrap_or_default();
                        return value.parse().unwrap_or_else(|err| {
                            panic!(
                                "{} emitted an invalid listener address {value:?}: {err}\n{}",
                                self.name,
                                self.log.render()
                            )
                        });
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("{}\n{}", self.startup_failure(marker), self.log.render());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!(
                        "{} stderr closed before log marker {marker:?}; status: {:?}\n{}",
                        self.name,
                        self.child.try_wait(),
                        self.log.render()
                    );
                }
            }
        }
    }

    fn startup_failure(&mut self, marker: &str) -> String {
        format!(
            "{} did not emit log marker {marker:?} within {STARTUP_TIMEOUT:?}; status: {:?}",
            self.name,
            self.child.try_wait()
        )
    }

    fn log_capture(&self) -> ProcessLog {
        self.log.clone()
    }

    fn assert_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            status => panic!(
                "{} exited unexpectedly; status: {status:?}\n{}",
                self.name,
                self.log.render()
            ),
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

#[derive(Clone)]
struct ProcessLog {
    name: &'static str,
    lines: Arc<Mutex<Vec<String>>>,
}

impl ProcessLog {
    fn render(&self) -> String {
        let lines = lock(&self.lines);
        let body = if lines.is_empty() {
            "<no stderr captured>".to_string()
        } else {
            lines.join("\n")
        };
        format!("--- {} stderr ---\n{body}", self.name)
    }
}

struct Diagnostics {
    logs: Vec<ProcessLog>,
}

impl Diagnostics {
    fn new<const N: usize>(logs: [ProcessLog; N]) -> Self {
        Self { logs: logs.into() }
    }

    fn render(&self) -> String {
        self.logs
            .iter()
            .map(ProcessLog::render)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn with_diagnostics<T>(diagnostics: &Diagnostics, test: impl FnOnce() -> T) -> T {
    match panic::catch_unwind(AssertUnwindSafe(test)) {
        Ok(value) => value,
        Err(payload) => panic!(
            "{}\n{}",
            panic_message(payload.as_ref()),
            diagnostics.render()
        ),
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else {
        "E2E operation panicked with a non-string payload".to_string()
    }
}

fn socks_connect_round_trip(proxy_addr: SocketAddr, payload: &[u8]) {
    let target = TcpEchoTarget::start(payload.len());
    let mut proxy = authenticated_socks_stream(proxy_addr);
    let (reply, _) = socks_command(&mut proxy, 0x01, target.addr());
    assert_eq!(reply, 0x00, "SOCKS5 CONNECT was rejected");

    write_all(&mut proxy, payload, "write SOCKS5 CONNECT payload");
    let mut echoed = vec![0; payload.len()];
    read_exact(&mut proxy, &mut echoed, "read SOCKS5 CONNECT echo");
    assert_eq!(echoed, payload, "SOCKS5 CONNECT echoed the wrong payload");

    let (observed, source) = target.wait().expect("TCP echo target failed");
    assert_eq!(
        observed, payload,
        "TCP target observed the wrong SOCKS payload"
    );
    assert!(
        source.ip().is_loopback(),
        "TCP relay source was not loopback"
    );
}

fn http_connect_round_trip(proxy_addr: SocketAddr, payload: &[u8]) {
    let target = TcpEchoTarget::start(payload.len());
    let authority = target.addr().to_string();

    let mut rejected = connect_tcp(proxy_addr, "connect for rejected HTTP credentials");
    write_all(
        &mut rejected,
        format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\
             Proxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n"
        )
        .as_bytes(),
        "write rejected HTTP CONNECT request",
    );
    let rejected_head = read_http_head(&mut rejected);
    assert!(
        rejected_head.starts_with("HTTP/1.1 407 "),
        "bad HTTP proxy credentials returned: {rejected_head:?}"
    );
    drop(rejected);

    let mut proxy = connect_tcp(proxy_addr, "connect for authenticated HTTP CONNECT");
    write_all(
        &mut proxy,
        format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\
             Proxy-Authorization: Basic {PROXY_BASIC_AUTH}\r\n\r\n"
        )
        .as_bytes(),
        "write authenticated HTTP CONNECT request",
    );
    let response_head = read_http_head(&mut proxy);
    assert!(
        response_head.starts_with("HTTP/1.1 200 "),
        "HTTP CONNECT failed: {response_head:?}"
    );

    write_all(&mut proxy, payload, "write HTTP CONNECT payload");
    let mut echoed = vec![0; payload.len()];
    read_exact(&mut proxy, &mut echoed, "read HTTP CONNECT echo");
    assert_eq!(echoed, payload, "HTTP CONNECT echoed the wrong payload");

    let (observed, source) = target.wait().expect("HTTP TCP echo target failed");
    assert_eq!(
        observed, payload,
        "TCP target observed the wrong HTTP payload"
    );
    assert!(
        source.ip().is_loopback(),
        "HTTP relay source was not loopback"
    );
}

fn udp_associate_round_trip(proxy_addr: SocketAddr, payload: &[u8]) {
    let target = UdpEchoTarget::start();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("failed to bind SOCKS5 UDP socket");
    udp.set_read_timeout(Some(IO_TIMEOUT))
        .expect("failed to set UDP read timeout");
    udp.set_write_timeout(Some(IO_TIMEOUT))
        .expect("failed to set UDP write timeout");

    let mut control = authenticated_socks_stream(proxy_addr);
    let (reply, relay) = socks_command(
        &mut control,
        0x03,
        udp.local_addr().expect("SOCKS5 UDP socket has no address"),
    );
    assert_eq!(reply, 0x00, "SOCKS5 UDP ASSOCIATE was rejected");
    let relay_addr = relay
        .into_socket_addr()
        .expect("UDP relay address was a domain");
    assert_ne!(relay_addr.port(), 0, "UDP relay returned port zero");

    let request = socks_udp_frame(target.addr(), payload);
    let sent = udp
        .send_to(&request, relay_addr)
        .expect("failed to send SOCKS5 UDP frame");
    assert_eq!(sent, request.len(), "SOCKS5 UDP frame was partially sent");

    let mut response = vec![0; 65_535];
    let (response_len, response_source) = udp
        .recv_from(&mut response)
        .expect("failed to receive SOCKS5 UDP response");
    assert_eq!(
        response_source, relay_addr,
        "SOCKS5 UDP response came from the wrong relay address"
    );
    let (source, echoed) = parse_socks_udp_frame(&response[..response_len]);
    assert_eq!(
        source,
        SocksAddress::Socket(target.addr()),
        "SOCKS5 UDP response reported the wrong source"
    );
    assert_eq!(echoed, payload, "SOCKS5 UDP response payload differed");

    let (observed, target_source) = target.wait().expect("UDP echo target failed");
    assert_eq!(observed, payload, "UDP target observed the wrong payload");
    assert!(
        target_source.ip().is_loopback(),
        "UDP relay source was not loopback: {target_source}"
    );

    control
        .shutdown(Shutdown::Both)
        .expect("failed to close UDP ASSOCIATE control connection");
    drop(control);

    let follow_up = authenticated_socks_stream(proxy_addr);
    drop(follow_up);
}

fn authenticated_socks_stream(proxy_addr: SocketAddr) -> TcpStream {
    let mut stream = connect_tcp(proxy_addr, "connect to SOCKS5 proxy");
    write_all(
        &mut stream,
        &[0x05, 0x01, 0x02],
        "write SOCKS5 method negotiation",
    );
    let mut method = [0; 2];
    read_exact(&mut stream, &mut method, "read SOCKS5 method selection");
    assert_eq!(
        method,
        [0x05, 0x02],
        "SOCKS5 selected the wrong auth method"
    );

    let mut request = Vec::with_capacity(3 + PROXY_USERNAME.len() + PROXY_PASSWORD.len());
    request.extend_from_slice(&[0x01, PROXY_USERNAME.len() as u8]);
    request.extend_from_slice(PROXY_USERNAME);
    request.push(PROXY_PASSWORD.len() as u8);
    request.extend_from_slice(PROXY_PASSWORD);
    write_all(&mut stream, &request, "write SOCKS5 username/password auth");
    let mut auth = [0; 2];
    read_exact(&mut stream, &mut auth, "read SOCKS5 auth response");
    assert_eq!(auth, [0x01, 0x00], "SOCKS5 authentication failed");
    stream
}

fn socks_command(stream: &mut TcpStream, command: u8, address: SocketAddr) -> (u8, SocksAddress) {
    let mut request = vec![0x05, command, 0x00];
    encode_socks_address(&mut request, address);
    write_all(stream, &request, "write SOCKS5 command");

    let mut head = [0; 4];
    read_exact(stream, &mut head, "read SOCKS5 command response");
    assert_eq!(head[0], 0x05, "invalid SOCKS5 response version");
    assert_eq!(head[2], 0x00, "invalid SOCKS5 reserved byte");
    let address = read_socks_address(stream, head[3]);
    (head[1], address)
}

#[derive(Debug, PartialEq, Eq)]
enum SocksAddress {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl SocksAddress {
    fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Self::Socket(address) => Some(address),
            Self::Domain(_, _) => None,
        }
    }
}

fn encode_socks_address(buffer: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buffer.push(0x04);
            buffer.extend_from_slice(&ip.octets());
        }
    }
    buffer.extend_from_slice(&address.port().to_be_bytes());
}

fn read_socks_address(stream: &mut TcpStream, address_type: u8) -> SocksAddress {
    match address_type {
        0x01 => {
            let mut bytes = [0; 6];
            read_exact(stream, &mut bytes, "read SOCKS5 IPv4 address");
            SocksAddress::Socket(SocketAddr::from((
                [bytes[0], bytes[1], bytes[2], bytes[3]],
                u16::from_be_bytes([bytes[4], bytes[5]]),
            )))
        }
        0x04 => {
            let mut bytes = [0; 18];
            read_exact(stream, &mut bytes, "read SOCKS5 IPv6 address");
            let mut ip = [0; 16];
            ip.copy_from_slice(&bytes[..16]);
            SocksAddress::Socket(SocketAddr::from((
                Ipv6Addr::from(ip),
                u16::from_be_bytes([bytes[16], bytes[17]]),
            )))
        }
        0x03 => {
            let mut length = [0];
            read_exact(stream, &mut length, "read SOCKS5 domain length");
            let mut bytes = vec![0; usize::from(length[0]) + 2];
            read_exact(stream, &mut bytes, "read SOCKS5 domain address");
            let port_at = bytes.len() - 2;
            SocksAddress::Domain(
                String::from_utf8(bytes[..port_at].to_vec())
                    .expect("SOCKS5 response domain was not UTF-8"),
                u16::from_be_bytes([bytes[port_at], bytes[port_at + 1]]),
            )
        }
        value => panic!("unsupported SOCKS5 address type {value:#04x}"),
    }
}

fn socks_udp_frame(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x00, 0x00, 0x00];
    encode_socks_address(&mut frame, target);
    frame.extend_from_slice(payload);
    frame
}

fn parse_socks_udp_frame(frame: &[u8]) -> (SocksAddress, &[u8]) {
    assert!(frame.len() >= 4, "truncated SOCKS5 UDP frame: {frame:?}");
    assert_eq!(&frame[..2], &[0, 0], "invalid SOCKS5 UDP reserved bytes");
    assert_eq!(frame[2], 0, "fragmented SOCKS5 UDP response");

    let (address, payload_at) = match frame[3] {
        0x01 => {
            assert!(frame.len() >= 10, "truncated SOCKS5 UDP IPv4 frame");
            (
                SocksAddress::Socket(SocketAddr::from((
                    [frame[4], frame[5], frame[6], frame[7]],
                    u16::from_be_bytes([frame[8], frame[9]]),
                ))),
                10,
            )
        }
        0x04 => {
            assert!(frame.len() >= 22, "truncated SOCKS5 UDP IPv6 frame");
            let mut ip = [0; 16];
            ip.copy_from_slice(&frame[4..20]);
            (
                SocksAddress::Socket(SocketAddr::from((
                    Ipv6Addr::from(ip),
                    u16::from_be_bytes([frame[20], frame[21]]),
                ))),
                22,
            )
        }
        0x03 => {
            assert!(frame.len() >= 5, "truncated SOCKS5 UDP domain frame");
            let length = usize::from(frame[4]);
            let payload_at = 5 + length + 2;
            assert!(
                frame.len() >= payload_at,
                "truncated SOCKS5 UDP domain address"
            );
            (
                SocksAddress::Domain(
                    String::from_utf8(frame[5..5 + length].to_vec())
                        .expect("SOCKS5 UDP domain was not UTF-8"),
                    u16::from_be_bytes([frame[5 + length], frame[6 + length]]),
                ),
                payload_at,
            )
        }
        value => panic!("unsupported SOCKS5 UDP address type {value:#04x}"),
    };
    (address, &frame[payload_at..])
}

struct TcpEchoTarget {
    addr: SocketAddr,
    result: Receiver<Result<(Vec<u8>, SocketAddr), String>>,
    thread: Option<JoinHandle<()>>,
}

impl TcpEchoTarget {
    fn start(payload_len: usize) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("failed to bind TCP echo target");
        let addr = listener
            .local_addr()
            .expect("TCP echo target has no address");
        let (result_tx, result) = mpsc::channel();
        let thread = thread::spawn(move || {
            let outcome = (|| -> Result<_, String> {
                let (mut stream, source) = listener.accept().map_err(|err| err.to_string())?;
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|err| err.to_string())?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|err| err.to_string())?;
                let mut payload = vec![0; payload_len];
                stream
                    .read_exact(&mut payload)
                    .map_err(|err| format!("TCP target read failed: {err}"))?;
                stream
                    .write_all(&payload)
                    .map_err(|err| format!("TCP target echo failed: {err}"))?;
                Ok((payload, source))
            })();
            let _ = result_tx.send(outcome);
        });
        Self {
            addr,
            result,
            thread: Some(thread),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn wait(mut self) -> Result<(Vec<u8>, SocketAddr), String> {
        let result = self
            .result
            .recv_timeout(TARGET_TIMEOUT)
            .map_err(|err| format!("TCP target deadline expired: {err}"));
        if result.is_err() {
            self.wake();
        }
        self.join();
        result?
    }

    fn wake(&self) {
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for TcpEchoTarget {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.wake();
            self.join();
        }
    }
}

struct UdpEchoTarget {
    addr: SocketAddr,
    result: Receiver<Result<(Vec<u8>, SocketAddr), String>>,
    thread: Option<JoinHandle<()>>,
}

impl UdpEchoTarget {
    fn start() -> Self {
        let socket =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("failed to bind UDP echo target");
        socket
            .set_read_timeout(Some(TARGET_TIMEOUT))
            .expect("failed to set UDP target read timeout");
        let addr = socket.local_addr().expect("UDP echo target has no address");
        let (result_tx, result) = mpsc::channel();
        let thread = thread::spawn(move || {
            let outcome = (|| -> Result<_, String> {
                let mut payload = vec![0; 65_535];
                let (length, source) = socket
                    .recv_from(&mut payload)
                    .map_err(|err| format!("UDP target receive failed: {err}"))?;
                payload.truncate(length);
                socket
                    .send_to(&payload, source)
                    .map_err(|err| format!("UDP target echo failed: {err}"))?;
                Ok((payload, source))
            })();
            let _ = result_tx.send(outcome);
        });
        Self {
            addr,
            result,
            thread: Some(thread),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn wait(mut self) -> Result<(Vec<u8>, SocketAddr), String> {
        let result = self
            .result
            .recv_timeout(TARGET_TIMEOUT)
            .map_err(|err| format!("UDP target deadline expired: {err}"));
        if result.is_err() {
            self.wake();
        }
        self.join();
        result?
    }

    fn wake(&self) {
        if let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            let _ = socket.send_to(&[], self.addr);
        }
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for UdpEchoTarget {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.wake();
            self.join();
        }
    }
}

fn read_http_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::with_capacity(256);
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16 * 1024, "HTTP response head exceeded 16 KiB");
        let mut byte = [0];
        read_exact(stream, &mut byte, "read HTTP CONNECT response head");
        head.push(byte[0]);
    }
    String::from_utf8(head).expect("HTTP CONNECT response was not UTF-8")
}

fn connect_tcp(address: SocketAddr, context: &str) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .unwrap_or_else(|err| panic!("{context}: {err}"));
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("failed to set TCP read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("failed to set TCP write timeout");
    stream
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8], context: &str) {
    stream
        .read_exact(buffer)
        .unwrap_or_else(|err| panic!("{context}: {err}"));
}

fn write_all(stream: &mut TcpStream, buffer: &[u8], context: &str) {
    stream
        .write_all(buffer)
        .unwrap_or_else(|err| panic!("{context}: {err}"));
}

fn unique_payload(label: &str) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    let id = PAYLOAD_ID.fetch_add(1, Ordering::Relaxed);
    format!("tuic-e2e:{label}:{}:{timestamp}:{id}", std::process::id()).into_bytes()
}

fn write_json(path: &Path, value: &serde_json::Value) {
    let file = fs::File::create(path)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", path.display()));
    serde_json::to_writer_pretty(file, value)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

fn client_bin() -> PathBuf {
    if let Some(path) = env::var_os("TUIC_CLIENT_BIN") {
        return path.into();
    }

    Path::new(SERVER_BIN)
        .parent()
        .expect("server binary path has no parent")
        .join(format!("tuic-client{}", env::consts::EXE_SUFFIX))
}

fn run(binary: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", binary.display()))
}

fn assert_success(name: &str, args: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{name} {args} failed:\n{}",
        output_text(output)
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
