# tuic-udp-forwarder

A standalone, protocol-independent UDP forwarder. It passes datagrams unchanged
to one fixed upstream server and routes replies back to the originating client.
It does not terminate QUIC/TLS, parse TUIC, or need certificates or TUIC credentials.
No TUIC server or client process is needed on the forwarding machine.

```text
TUIC client -> UDP forwarder -> TUIC server -> destination
              encrypted QUIC remains end-to-end
```

## Usage

Download binaries from [releases](../../../releases).
For a complete server/client/forwarder setup, see the
[main usage guide](../README.md#usage).

Build with Rust 1.89.0 or newer:

```sh
cargo build --release -p tuic-udp-forwarder --locked
```

Run with a JSONC configuration file (a `.json` filename is fine):

```sh
tuic-udp-forwarder -c forwarder.json
```

## Configuration

All config files are parsed as **JSONC**, regardless of extension (including no
extension). Plain JSON, `//` line comments, `/* ... */` block comments, and
trailing commas in objects and arrays are supported. Use double-quoted property
names and strings; other JSON5 syntax is not supported. Unknown properties and
invalid values are rejected.

Complete configuration (only `server` and `upstream` are required):

```jsonc
{
    // Required. UDP listening IP:PORT; use "[ADDRESS]:PORT" for IPv6.
    // Port range: 0-65535 (0 requests an OS-assigned port); not a hostname.
    "server": "0.0.0.0:8443",
    // Required. Fixed upstream HOST:PORT; use "[ADDRESS]:PORT" for IPv6.
    // HOST may be an IP address or domain; use a reachable UDP service port.
    "upstream": "203.0.113.10:443",
    // Optional boolean. For an IPv6 listener, true also accepts IPv4 where supported;
    // false restricts it to IPv6. Omit or use null for the OS default; ignored for IPv4.
    "dual_stack": null,
    // Optional. Positive duration string fitting in a timer, e.g. "1250ms" or "1m".
    // Activity in either direction keeps the mapping alive. Default: "60s".
    "idle_timeout": "60s",
    // Optional. Positive integer fitting in usize: maximum simultaneous client mappings.
    // Default: 1024.
    "max_clients": 1024,
    // Optional. Log level: "off", "error", "warn", "info", "debug", or "trace".
    // Default: "warn".
    "log_level": "warn"
}
```

| Setting | Meaning | Default |
| --- | --- | --- |
| `server` | UDP listening IP and port; port `0` requests an ephemeral port | Required |
| `upstream` | Fixed upstream `HOST:PORT`; IPv6 addresses use `[ADDRESS]:PORT` | Required |
| `dual_stack` | Whether an IPv6 listener also accepts IPv4 | OS default |
| `idle_timeout` | Positive duration, e.g. `"60s"`; activity in either direction keeps a mapping alive | `"60s"` |
| `max_clients` | Maximum simultaneous client IP/port mappings; must be positive | `1024` |
| `log_level` | `off`, `error`, `warn`, `info`, `debug`, or `trace` | `"warn"` |

Hostnames resolve once at startup and use the first returned address. There is no
upstream failover or periodic DNS refresh. The listener and upstream can use
different IP families.

Each client source IP/port gets a separate, connected upstream UDP socket.
Replies from other source addresses are rejected by the socket. Idle mappings
are closed automatically. A new datagram after expiry creates a new mapping and
may use a different upstream source port. Set the idle timeout above the expected
heartbeat/idle interval of the forwarded protocol.

Client datagrams are sent directly through each mapping's upstream socket,
without a small application queue that can drop normal QUIC bursts. Socket
backpressure is awaited up to `idle_timeout`; send failures close the affected
mapping and emit warnings. New clients are dropped with a warning when the
client limit is reached. UDP delivery is not guaranteed, and the forwarder does
not add retransmission; OS socket buffers can still overflow under sustained
overload. It accepts full-size UDP datagrams without application truncation;
network MTU and fragmentation limits still apply.

## TUIC client configuration

Keep the real TUIC server's TLS hostname, trust settings, ALPN, UUID, and password.
Keep `relay.server` set to the real server's hostname and original port.
Set `relay.forwarder_server` to the forwarder's hostname/IP and listening port:

```jsonc
{
    // Required. Outbound TUIC connection settings on the client, not the forwarder.
    "relay": {
        // Required. Real TUIC server HOST:PORT (port 1-65535), used for TLS verification/SNI.
        "server": "exit.example.com:443",
        // Optional. Forwarder HOST:PORT (port 1-65535); cannot be combined with relay.ip.
        "forwarder_server": "198.51.100.20:8443",
        // Required. User UUID configured on the real TUIC server.
        "uuid": "00000000-0000-0000-0000-000000000000",
        // Required. Password associated with that UUID on the real server.
        "password": "PASSWORD"
    },
    // Required. Local proxy settings.
    "local": {
        // Required. Listening IP:PORT; loopback restricts proxy access to this machine.
        "server": "127.0.0.1:1080"
    }
}
```

Here the forwarder listens on `198.51.100.20:8443` and forwards to the real
server, for example `203.0.113.10:443`. The hostname `exit.example.com` is still
used for TLS verification/SNI. The forwarder's hostname/IP and port are
independent of the real server's address. Hostnames and bracketed IPv6 addresses
are also supported, e.g. `"forwarder_server": "forwarder.example.com:8443"` or
`"forwarder_server": "[2001:db8::20]:8443"`.
Local computer names work too, for example
`"forwarder_server": "MS-DESKTOP-SIGLUD:8443"` (the port is required).
The client staggers attempts to resolved addresses so an unreachable address
does not consume the whole connection timeout before another address is tried.
If the forwarder uses `"server": "0.0.0.0:8443"`, it listens only on IPv4,
even with `dual_stack: true`. To accept both IPv6 and IPv4, use
`"server": "[::]:8443"` with `dual_stack: true` where supported.

Do not also set `relay.ip`; configuring both it and `relay.forwarder_server` is
an error. Legacy client configurations using only `relay.ip` still work as
before. Older client binaries do not understand `forwarder_server`; upgrade the
client before using this setting. A failed forwarder connection does not fall
back to contacting the real server directly.

The upstream sees the forwarder's IP, not the original client's IP. This tool
has no local authentication or rate limiting: restrict access with a firewall
or private network as needed. `max_clients` bounds mappings, not bandwidth.
Do not configure the upstream to point back to this forwarder or create forwarding
loops. OS-level UDP forwarding can be preferable for maximum packet throughput;
this user-space tool prioritizes portability and simple deployment.

## License

GNU General Public License v3.0 or later.
