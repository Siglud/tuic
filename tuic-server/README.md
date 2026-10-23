# tuic-server

Minimalistic TUIC server implementation as a reference

[![Release](https://img.shields.io/github/v/release/Siglud/tuic?style=flat)](../../../releases)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg?style=flat)](../LICENSE)

# Overview

The main goal of this TUIC server implementation is not to provide a full-featured, production-ready TUIC server, but to provide a minimal reference for the TUIC protocol server implementation.

This implementation only contains the most basic requirements of a functional TUIC protocol server. If you are looking for features like outbound-control, DNS-caching, etc., try other implementations, or implement them yourself.

## Usage

Download the latest binary from [releases](../../../releases).

Or install this repository's version from a local checkout:

```bash
cargo install --path tuic-server --locked
```

Run the TUIC server with configuration file:

```bash
tuic-server -c PATH/TO/CONFIG
```

For a complete server/client/forwarder setup, see the
[main usage guide](../README.md#usage).

## Configuration

All configuration files are parsed as **JSONC**, regardless of their extension,
including `.json`, `.jsonc`, or no extension. Plain JSON, `//` line comments,
`/* ... */` block comments, and trailing commas in objects and arrays are
supported. Property names and strings must use double quotes; other JSON5
syntax is not supported. Unknown properties and invalid values are rejected.

Required settings are marked below; omit optional properties to use their
defaults. Relative file paths are resolved from the process's working directory,
not the configuration file's directory. Durations use human-readable strings
such as `"250ms"`, `"3s"`, or `"1m"`.

```jsonc
{
    // Required. UDP listening IP:PORT, or "[ADDRESS]:PORT" for IPv6; not a hostname.
    // Port range: 0-65535 (0 requests an OS-assigned port).
    "server": "[::]:443",

    // Required. Nonempty object mapping valid user UUIDs to password strings.
    "users": {
        // First user's UUID and password; the client must use the same pair.
        "00000000-0000-0000-0000-000000000000": "PASSWORD_0",
        // Additional user; replace the UUID key and password with your own values.
        "00000000-0000-0000-0000-000000000001": "PASSWORD_1"
    },

    // Required. TLS certificate chain file path (PEM, or a single DER certificate).
    "certificate": "PATH/TO/CERTIFICATE",

    // Required. Matching private key file path (PKCS#1/PKCS#8/SEC1 PEM or PKCS#8 DER).
    "private_key": "PATH/TO/PRIVATE_KEY",

    // Optional. Congestion control algorithm string (case-insensitive):
    // "cubic", "new_reno" (alias "newreno"), or "bbr".
    // Default: "cubic"
    "congestion_control": "cubic",

    // Optional. List of ALPN strings; match the client's supported protocols.
    // Default: [] (no ALPN).
    "alpn": ["h3", "spdy/3.1"],

    // Optional boolean. Create separate UDP sockets for relaying IPv6 packets.
    // Default: true
    "udp_relay_ipv6": true,

    // Optional boolean. Enable 0-RTT QUIC connection handshake on the server side.
    // This is not impacting much on the performance, as the protocol is fully multiplexed
    // WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
    // Default: false
    "zero_rtt_handshake": false,

    // Optional boolean. For an IPv6 listener, true also accepts IPv4 where supported;
    // false restricts it to IPv6. Ignored for an IPv4 listener.
    // Omit or use null for the OS default.
    "dual_stack": true,

    // Optional. Duration string to wait for the client's authentication command.
    // Default: "3s".
    "auth_timeout": "3s",

    // Optional. Maximum task negotiation duration string.
    // Default: "3s".
    "task_negotiation_timeout": "3s",

    // Optional. QUIC idle timeout duration string; must fit in a QUIC idle timeout.
    // "0s" disables the idle timeout. Default: "10s".
    // Independent of a UDP forwarder's idle_timeout, which only expires UDP mappings.
    "max_idle_time": "10s",

    // Optional. Maximum packet size the server can receive from outbound UDP sockets, in bytes
    // Nonnegative integer fitting in usize; choose a positive buffer size.
    // Larger UDP packets may be truncated.
    // Default: 1500
    "max_external_packet_size": 1500,

    // Optional. Maximum number of bytes to transmit to a peer without acknowledgment
    // Nonnegative integer fitting in u64.
    // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
    // Default: 8MiB * 2
    "send_window": 16777216,

    // Optional. Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
    // Integer from 0 to 4294967295 (u32), in bytes.
    // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
    // Larger values improve high-bandwidth, high-latency throughput but increase out-of-order reassembly pressure
    // Values above 1MiB are capped by the server so legacy clients cannot overflow stream reassembly
    // Default: 1MiB
    "receive_window": 1048576,

    // Optional. Positive duration string between UDP fragment garbage collections.
    // Default: "3s".
    "gc_interval": "3s",

    // Optional. Duration string for retaining incomplete UDP fragments.
    // Older fragments are dropped. Default: "15s".
    "gc_lifetime": "15s",

    // Optional. Log level: "off", "error", "warn", "info", "debug", or "trace".
    // Default: "warn"
    "log_level": "warn"
}
```

## Idle connection lifetime

`max_idle_time` controls the QUIC connection's idle timeout, not a forwarder's
UDP mapping lifetime. TUIC clients send heartbeats only while relay tasks are
active, so a connection with no remaining tasks can expire after the default
`"10s"` even when the forwarder's `idle_timeout` is `"60s"`. Set a larger
`max_idle_time` to permit longer idle QUIC connections, and ensure any
forwarder's mapping timeout also covers the expected gaps between datagrams.
The forwarder cannot keep QUIC alive or override this setting.

Successful TCP relays finish gracefully; stream resets are reserved for errors
or interrupted relays.

## License

GNU General Public License v3.0
