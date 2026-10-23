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

```json5
{
    // Settings for the outbound TUIC proxy
    "relay": {
        // Set the TUIC proxy server address
        // Format: "HOST:PORT"
        // The HOST must be a common name in the certificate
        // With neither "ip" nor "forwarder_server" set, HOST is also used for DNS resolving
        "server": "example.com:443",

        // Set the user UUID
        "uuid": "00000000-0000-0000-0000-000000000000",

        // Set the user password
        "password": "PASSWORD",

        // Optional. The IP address of the TUIC proxy server, for overriding DNS resolving
        // For forwarding, use "forwarder_server" instead
        // Cannot be combined with a non-null "forwarder_server"
        "ip": null,

        // Optional. Connect through a UDP forwarder, e.g. "forwarder.example.com:8443"
        // Format: "HOST:PORT"; use "[ADDRESS]:PORT" for an IPv6 address
        // The "server" field still identifies the real TUIC server for TLS/SNI
        // Both the forwarder's hostname/IP and port are independent of "server"
        // Cannot be combined with a non-null "ip"
        "forwarder_server": null,

        // Optional. A list of certificates for TLS handshake
        // System native certificates are also loaded by default
        // When using self-signed certificates, the full certificate chain must be provided
        "certificates": ["PATH/TO/CERTIFICATE_1", "PATH/TO/CERTIFICATE_2"],

        // Optional. Set the UDP packet relay mode
        // Can be:
        // - "native": native UDP characteristics
        // - "quic": lossless UDP relay using QUIC streams, additional overhead is introduced
        // Default: "native"
        "udp_relay_mode": "native",

        // Optional. Congestion control algorithm, available options:
        // "cubic", "new_reno", "bbr"
        // Default: "cubic"
        "congestion_control": "cubic",

        // Optional. Application layer protocol negotiation
        // Default being empty (no ALPN)
        "alpn": ["h3", "spdy/3.1"],

        // Optional. Enable 0-RTT QUIC connection handshake on the client side
        // This is not impacting much on the performance, as the protocol is fully multiplexed
        // WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
        // Default: false
        "zero_rtt_handshake": false,

        // Optional. Disable SNI (Server Name Indication) in TLS handshake
        // The server name used in SNI is the same as the HOST in the "server" field
        // Default: false
        "disable_sni": false,

        // Optional. Set the timeout for establishing a connection to the TUIC proxy server
        // Default: "8s"
        "timeout": "8s",

        // Optional. Set the interval for sending heartbeat packets for keeping the connection alive
        // Default: "3s"
        "heartbeat": "3s",

        // Optional. Disable loading system native certificates
        // Default: false
        "disable_native_certs": false,

        // Optional. Maximum number of bytes to transmit to a peer without acknowledgment
        // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
        // Default: 8MiB * 2
        "send_window": 16777216,

        // Optional. Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
        // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
        // Larger values improve high-bandwidth, high-latency throughput but increase out-of-order reassembly pressure
        // Default: 1MiB
        "receive_window": 1048576,

        // Optional. Interval between UDP packet fragment garbage collection
        // Default: 3s
        "gc_interval": "3s",

        // Optional. How long the server should keep a UDP packet fragment. Outdated fragments will be dropped
        // Default: 15s
        "gc_lifetime": "15s"
    },

    // Settings for the local proxy server
    "local": {
        // Local proxy server address
        // Both SOCKS5 and HTTP proxy listen on this single port when "enable_http" is true
        "server": "[::]:1080",

        // Optional. Set the username for proxy authentication
        // Applies to both SOCKS5 (password auth) and HTTP (Proxy-Authorization: Basic)
        "username": "USERNAME",

        // Optional. Set the password for proxy authentication
        // Applies to both SOCKS5 (password auth) and HTTP (Proxy-Authorization: Basic)
        "password": "PASSWORD",

        // Optional. Enable HTTP proxy on the same port as SOCKS5
        // When enabled, the server automatically detects whether each incoming connection
        // is a SOCKS5 connection (first byte 0x05) or an HTTP proxy request, and handles
        // it accordingly. Both protocols share the same username/password credentials.
        // Default: false
        "enable_http": false,

        // Optional. Set if the listening socket should be dual-stack (e.g. an IPv6
        // listening address also accepts IPv4 connections when supported by the OS)
        // If this option is not set, the socket behavior is platform dependent
        "dual_stack": true,
        // Optional. Maximum packet size the SOCKS5 server can receive from external, in bytes
        // Note: ignored for HTTP proxy connections
        // Default: 1500
        "max_packet_size": 1500
    },

    // Optional. Set the log level
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

Do not set `relay.ip` when using `relay.forwarder_server`; the client rejects
configurations that set both. Existing configurations without `forwarder_server`
keep their previous behavior, including `relay.ip` DNS overrides. Forwarder
failures do not cause a fallback to a direct connection to the real server.

## License

GNU General Public License v3.0
