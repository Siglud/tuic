# tuic-client

Minimalistic TUIC client implementation as a reference

[![Release](https://img.shields.io/github/v/release/Siglud/tuic?style=flat)](../../../releases)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg?style=flat)](../LICENSE)

# Overview

The main goal of this TUIC client implementation is not to provide a full-featured, production-ready TUIC client, but to provide a minimal reference for the TUIC protocol client implementation.

This implementation provides a local SOCKS5 proxy, optional HTTP proxy support,
and an outbound TUIC connection, optionally through a UDP forwarder. It is not
intended to provide advanced features such as load balancing.

## Usage

Download the latest binary from [releases](../../../releases).

Or install this repository's version from a local checkout:

```bash
cargo install --path tuic-client --locked
```

Run the TUIC client with configuration file:

```bash
tuic-client -c PATH/TO/CONFIG
```

For a complete server/client/forwarder setup, see the
[main usage guide](../README.md#usage).

## Configuration

All configuration files are parsed as **JSONC**, even when named `client.json`
or given another extension (or none). Plain JSON, `//` line comments,
`/* ... */` block comments, and trailing commas in objects and arrays are
supported. Use double-quoted property names and strings, not JSON5 single quotes
or unquoted names. Unknown properties and invalid values are rejected.

Required settings are marked below; omit optional properties to use their
defaults. Relative file paths are resolved from the process's working directory,
not the configuration file's directory. Durations are human-readable strings
such as `"250ms"`, `"3s"`, or `"1m"`; use positive intervals for heartbeat and
garbage collection.

```jsonc
{
    // Required. Settings for the outbound TUIC connection.
    "relay": {
        // Required. Real TUIC server HOST:PORT, with a port from 1 to 65535.
        // Use "[ADDRESS]:PORT" for IPv6; HOST must match the TLS certificate.
        // Without "ip" or "forwarder_server", HOST is also resolved for the connection.
        "server": "example.com:443",

        // Required. User UUID registered in the TUIC server's "users" map.
        "uuid": "00000000-0000-0000-0000-000000000000",

        // Required. Password string associated with that UUID on the server.
        "password": "PASSWORD",

        // Optional. IPv4 or IPv6 address string without a port, overriding DNS.
        // The port still comes from "server"; omit or use null for normal DNS.
        // Cannot be combined with a non-null "forwarder_server".
        "ip": null,

        // Optional. Connect through a UDP forwarder, e.g. "forwarder.example.com:8443"
        // Format: "HOST:PORT", port 1-65535; use "[ADDRESS]:PORT" for IPv6.
        // The "server" field still identifies the real TUIC server for TLS/SNI
        // Both the forwarder's hostname/IP and port are independent of "server"
        // Omit or use null for a direct connection; cannot be combined with a non-null "ip".
        "forwarder_server": null,

        // Optional. List of trusted TLS certificate file paths (PEM or DER). Default: [].
        // System native certificates are also loaded unless "disable_native_certs" is true.
        // For a private CA/self-signed certificate, provide the required certificate chain.
        "certificates": ["PATH/TO/CERTIFICATE_1", "PATH/TO/CERTIFICATE_2"],

        // Optional. UDP relay mode string (case-insensitive).
        // Can be:
        // - "native": native UDP characteristics
        // - "quic": lossless UDP relay using QUIC streams, additional overhead is introduced
        // Default: "native"
        "udp_relay_mode": "native",

        // Optional. Congestion control algorithm string (case-insensitive):
        // "cubic", "new_reno" (alias "newreno"), or "bbr".
        // Default: "cubic"
        "congestion_control": "cubic",

        // Optional. List of ALPN strings; match the server's supported protocols.
        // Default: [] (no ALPN).
        "alpn": ["h3", "spdy/3.1"],

        // Optional boolean. Enable 0-RTT QUIC connection handshake on the client side.
        // This is not impacting much on the performance, as the protocol is fully multiplexed
        // WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
        // Default: false
        "zero_rtt_handshake": false,

        // Optional boolean. Disable SNI (Server Name Indication) in TLS handshake.
        // The server name used in SNI is the same as the HOST in the "server" field
        // Default: false
        "disable_sni": false,

        // Optional. Connection timeout duration string, e.g. "8s" or "1250ms".
        // Default: "8s"
        "timeout": "8s",

        // Optional. Heartbeat interval duration string; use a positive interval.
        // Sent only while TCP relay tasks or UDP associations are active.
        // Default: "3s"
        "heartbeat": "3s",

        // Optional boolean. Disable loading system native certificates.
        // If true, supply trust anchors through "certificates".
        // Default: false
        "disable_native_certs": false,

        // Optional. Maximum number of bytes to transmit to a peer without acknowledgment
        // Nonnegative integer fitting in u64.
        // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
        // Default: 8MiB * 2
        "send_window": 16777216,

        // Optional. Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
        // Integer from 0 to 4294967295 (u32), in bytes.
        // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
        // Larger values improve high-bandwidth, high-latency throughput but increase out-of-order reassembly pressure
        // Default: 1MiB
        "receive_window": 1048576,

        // Optional. Positive duration string between UDP fragment garbage collections.
        // Default: "3s".
        "gc_interval": "3s",

        // Optional. Duration string for retaining incomplete UDP fragments on the client.
        // Older fragments are dropped. Default: "15s".
        "gc_lifetime": "15s"
    },

    // Required. Settings for the local proxy server.
    "local": {
        // Required. Listening IP:PORT, or "[ADDRESS]:PORT" for IPv6; not a hostname.
        // Port range: 0-65535 (0 requests an OS-assigned port).
        // Both SOCKS5 and HTTP proxy listen on this single port when "enable_http" is true
        "server": "[::]:1080",

        // Optional. Proxy authentication username string; set together with "password".
        // Omit both credentials to disable local proxy authentication.
        // Applies to both SOCKS5 (password auth) and HTTP (Proxy-Authorization: Basic)
        "username": "USERNAME",

        // Optional. Proxy authentication password string; set together with "username".
        // Applies to both SOCKS5 (password auth) and HTTP (Proxy-Authorization: Basic)
        "password": "PASSWORD",

        // Optional boolean. Enable HTTP proxy on the same port as SOCKS5.
        // When enabled, the server automatically detects whether each incoming connection
        // is a SOCKS5 connection (first byte 0x05) or an HTTP proxy request, and handles
        // it accordingly. Both protocols share the same username/password credentials.
        // Default: false
        "enable_http": false,

        // Optional boolean. For an IPv6 listener, true also accepts IPv4 where supported;
        // false restricts it to IPv6. Only set this with an IPv6 listening address.
        // Omit or use null for the OS default.
        "dual_stack": true,

        // Optional. Nonnegative integer fitting in usize: receive buffer size in bytes.
        // UDP packets larger than the buffer may be truncated; choose a positive size.
        // Note: ignored for HTTP proxy connections
        // Default: 1500
        "max_packet_size": 1500
    },

    // Optional. Log level: "off", "error", "warn", "info", "debug", or "trace".
    // Default: "warn"
    "log_level": "warn"
}
```

## Using a UDP forwarder

The client can connect through [tuic-udp-forwarder](../tuic-udp-forwarder/README.md).
Set `relay.forwarder_server` to the forwarder's hostname/IP and listening port.
Keep `relay.server` set to the real TUIC server, including its original port,
and keep its UUID, password, certificate trust, and ALPN settings unchanged.

For example, set `"server": "exit.example.com:443"` and
`"forwarder_server": "198.51.100.20:8443"` to connect through a forwarder at
`198.51.100.20:8443`. TLS verification/SNI still uses `exit.example.com`.
Forwarder hostnames are resolved when connecting, and bracketed IPv6 addresses
are supported, e.g. `"forwarder_server": "[2001:db8::20]:8443"`.
Local computer names are also supported, e.g.
`"forwarder_server": "MS-DESKTOP-SIGLUD:8443"`; the port is always required.
When a hostname resolves to multiple addresses, connection attempts are staggered
by 250 ms, trying the alternate IP family second if available. An unreachable
IPv6 or stale address therefore does not block a reachable IPv4 address for the
entire connection timeout. TLS still uses `relay.server`, not the computer name.
With multiple candidates, a completed handshake selects the winner even when
`zero_rtt_handshake` is enabled; single-address connections still support 0-RTT.
The forwarder must listen on the selected address family: `0.0.0.0:8443` accepts
only IPv4; use `[::]:8443` with `dual_stack: true` to also accept IPv4 on an
IPv6 listener where supported.

Do not set `relay.ip` when using `relay.forwarder_server`; the client rejects
configurations that set both. Existing configurations without `forwarder_server`
keep their previous behavior, including `relay.ip` DNS overrides. Forwarder
failures do not cause a fallback to a direct connection to the real server.

## Connection cleanup and logging

An idle relay connection may expire using the server's `max_idle_time`
(default `"10s"`). Heartbeats stop when no TCP relay tasks or UDP associations
remain; the next proxy request establishes a new connection. Idle expiration
with no active tasks is logged at `info`, and local connection closure at
`debug`. A timeout while tasks are still active remains a warning.

Each new relay connection uses a fresh UDP socket and source port, including
retries after a connection-establishment timeout. This avoids repeatedly reusing
a stale NAT or UDP-forwarder mapping. Established connections continue to share
their existing socket; TLS settings and the configured relay destination are
unchanged. Debug logging includes each attempted destination and local socket.

QUIC stream resets or stop requests with application code `0`, used for stream
cleanup by older TUIC servers, are logged at `info` for SOCKS5, HTTP CONNECT,
and plain HTTP relaying. Nonzero stream codes, TCP socket resets (including
Windows error 10054), and other relay failures remain warnings because they
are not confirmed normal cleanup. Updated servers finish successful TCP relays
gracefully instead of resetting them.

The forwarder's `idle_timeout` only expires UDP mappings; it does not override
the server's QUIC timeout. See the
[forwarder timeout explanation](../tuic-udp-forwarder/README.md#idle-timeout-versus-quic-connection-lifetime).

## License

GNU General Public License v3.0
