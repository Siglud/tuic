# TUIC

Delicately-TUICed 0-RTT proxy protocol

This repository is maintained as **Siglud/tuic**.
Download binaries from [releases](../../releases), or build
the [current source tree](.) for the latest changes.

## Introduction

TUIC is a proxy protocol focusing on minimize the additional handshake latency caused by relaying as much as possible, as well as keeping the protocol itself being simple and easy to implement

TUIC is originally designed to be used on top of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol, but you can use it with any other protocol, e.g. TCP, in theory

When paired with QUIC, TUIC can achieve:

- 0-RTT TCP proxying
- 0-RTT UDP proxying with NAT type [Full Cone](https://www.rfc-editor.org/rfc/rfc3489#section-5)
- 0-RTT authentication
- Two UDP proxying modes:
    - `native`: Having characteristics of native UDP mechanism
    - `quic`: Transferring UDP packets losslessly using QUIC streams
- Fully multiplexed
- All the advantages of QUIC, including but not limited to:
    - Bidirectional user-space congestion control
    - Optional 0-RTT connection handshake
    - Connection migration

Fully-detailed TUIC protocol specification can be found in [SPEC.md](SPEC.md)

## Overview

There are 5 crates provided in this repository:

- **[tuic](tuic/README.md)** - Library. The protocol itself, protocol & model abstraction, synchronous / asynchronous marshalling
- **[tuic-quinn](tuic-quinn/README.md)** - Library. A thin layer on top of [quinn](https://github.com/quinn-rs/quinn) to provide functions of TUIC
- **[tuic-server](tuic-server/README.md)** - Binary. TUIC server that connects to the requested TCP and UDP destinations
- **[tuic-client](tuic-client/README.md)** - Binary. Local SOCKS5 proxy with optional HTTP proxy support and an outbound TUIC connection

## Usage

### Get the binaries

Download the binaries for your platform from [releases](../../releases).
To build the client and server, install Rust 1.89.0 or newer and run:

```sh
git clone https://github.com/Siglud/tuic.git
cd tuic
cargo build --workspace --bins --release --locked
```

The executables are in `target\release` and have the `.exe` extension on Windows.
The commands below assume the executables are on your `PATH`; otherwise, use their
full paths.

### Choose a topology

Use the client and server alone for a direct connection, or use an external UDP forwarder
on a separate machine:

```text
Direct:
Application -> tuic-client -> tuic-server -> destination

Through a forwarder:
Application -> tuic-client -> UDP port forwarder -> tuic-server -> destination
                            QUIC/TLS stays end-to-end with the TUIC server
```

The examples below use `exit.example.com` for the real TUIC server and
`forwarder.example.com` for the optional forwarding machine. Replace these names,
the example IP addresses, UUID, and password with your own values. Configuration
files are always parsed as **JSONC**, regardless of their extension (including
`.json`, `.jsonc`, or no extension). Plain JSON remains valid. You can use `//`
line comments, `/* ... */` block comments, and trailing commas in objects and
arrays. Property names and string values still require double quotes; JSON5
features such as single quotes and unquoted property names are not supported.
Unknown properties and invalid values are rejected.

### Start the server

On the exit machine, create `server.json`:

```jsonc
{
    // Required. UDP listening IP and port; use "[::]:443" for IPv6.
    "server": "0.0.0.0:443",
    // Required. Nonempty map of user UUIDs to passwords.
    "users": {
        // Replace the UUID key and password; the client must use the same pair.
        "00000000-0000-0000-0000-000000000000": "REPLACE_WITH_A_STRONG_PASSWORD"
    },
    // Required. TLS certificate chain path (PEM, or a single DER certificate).
    "certificate": "server-cert.pem",
    // Required. Matching private key path (PEM or PKCS#8 DER); keep it secret.
    "private_key": "server-key.pem",
    // Optional. ALPN strings; match the client. Default: [] (no ALPN).
    "alpn": ["tuic"]
}
```

Provide a TLS certificate valid for `exit.example.com` and its matching private
key at the configured paths. The hostname must resolve to the exit machine.
Allow inbound **UDP port 443**, then start the server:

```sh
tuic-server -c server.json
```

The server authenticates clients and connects directly to the TCP and UDP
destinations they request. See the
[server configuration reference](tuic-server/README.md)
for all settings.

### Start the client

On your local machine, create `client.json`:

```jsonc
{
    // Required. Outbound TUIC connection settings.
    "relay": {
        // Required. Real TUIC server HOST:PORT; hostname must match its TLS certificate.
        "server": "exit.example.com:443",
        // Required. User UUID configured on the server.
        "uuid": "00000000-0000-0000-0000-000000000000",
        // Required. Password associated with that UUID on the server.
        "password": "REPLACE_WITH_A_STRONG_PASSWORD",
        // Optional. ALPN strings; match the server. Default: [] (no ALPN).
        "alpn": ["tuic"]
    },
    // Required. Local SOCKS5 and optional HTTP proxy settings.
    "local": {
        // Required. Listening IP and port; loopback restricts access to this machine.
        "server": "127.0.0.1:1080",
        // Optional. Enable HTTP proxy on the SOCKS5 port. Default: false.
        "enable_http": true
    }
}
```

Use the same UUID, password, and ALPN as the server. Publicly trusted certificates
use the client's system trust store by default. For a private CA or self-signed
certificate, add its certificate file to `relay.certificates`, for example
`"certificates": ["server-cert.pem"]`; provide the full chain when required.
Never copy the server's private key to clients.

```sh
tuic-client -c client.json
```

Configure applications to use SOCKS5 at `127.0.0.1:1080`. With `enable_http: true`,
HTTP proxy requests and HTTP CONNECT also use that same port. UDP proxying is
available through SOCKS5 UDP ASSOCIATE. Starting the client does not automatically
change system-wide proxy settings.

For example, with the curl command-line tool:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
curl --proxy http://127.0.0.1:1080 https://example.com
```

On Windows PowerShell, use `curl.exe` if `curl` resolves to a PowerShell alias.
See the [client configuration reference](tuic-client/README.md)
for authentication, TLS, UDP modes, and other options.

### Use an optional external UDP forwarder

This repository no longer ships a standalone forwarder. Use a third-party UDP
port forwarder, such as [Xray's tunnel inbound](https://xtls.github.io/en/config/inbounds/tunnel.html),
to forward UDP port `8443` to `exit.example.com:443` and return replies to the
client. Restrict access to the listener using a firewall or private network.

Update `client.json` to use the forwarder, then restart the client:

```jsonc
{
    // Required. Outbound TUIC connection settings.
    "relay": {
        // Required. Real TUIC server HOST:PORT, still used for TLS verification/SNI.
        "server": "exit.example.com:443",
        // Optional. Forwarder HOST:PORT (port 1-65535); cannot be combined with relay.ip.
        "forwarder_server": "forwarder.example.com:8443",
        // Required. User UUID configured on the real TUIC server.
        "uuid": "00000000-0000-0000-0000-000000000000",
        // Required. Password associated with that UUID on the real server.
        "password": "REPLACE_WITH_A_STRONG_PASSWORD",
        // Optional. ALPN strings; match the real server. Default: [] (no ALPN).
        "alpn": ["tuic"]
    },
    // Required. Local SOCKS5 and optional HTTP proxy settings.
    "local": {
        // Required. Listening IP and port; loopback restricts access to this machine.
        "server": "127.0.0.1:1080",
        // Optional. Enable HTTP proxy on the SOCKS5 port. Default: false.
        "enable_http": true
    }
}
```

Keep any existing `relay.certificates` setting. `relay.server` remains the real
server's address, including its original port; its hostname is used for TLS
verification and SNI. Only `relay.forwarder_server` selects the forwarding
machine's address and listening port. It accepts an IP and port or a domain and
port, for example `198.51.100.20:8443`, `forwarder.example.com:8443`, or
`[2001:db8::20]:8443`.

Do not also set `relay.ip`: the client rejects configurations that set both
`relay.ip` and `relay.forwarder_server`. Existing direct configurations using
`relay.ip` as a DNS override remain supported. Forwarder failures do not fall
back to a direct connection to the real server.

To switch back to a direct connection, remove `relay.forwarder_server` or set
it to `null`, then restart the client.

## Testing

Building and testing the workspace requires Rust 1.89.0 or newer.

Run the workspace unit tests with all features enabled:

```bash
cargo test --workspace --all-features --locked
```

The end-to-end suite generates temporary TLS material, starts the client and
server, and exercises TCP and UDP relaying over localhost:

```bash
cargo build --workspace --bins --locked
cargo test -p tuic-server --test proxy_e2e --locked -- --ignored --nocapture --test-threads=1
```

## License

Code in this repository is licensed under [GNU General Public License v3.0](LICENSE)

However, the concept of the TUIC protocol is license-free. You can implement, modify, and redistribute the protocol without any restrictions, even for commercial use
