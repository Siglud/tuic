# tuic

Delicately-TUICed 0-RTT proxy protocol

[![Release](https://img.shields.io/github/v/release/Siglud/tuic?style=flat)](../../../releases)
[![Source](https://img.shields.io/badge/docs-source-brightgreen.svg?style=flat)](src)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg?style=flat)](../LICENSE)

## Overview

The TUIC protocol specification can be found in [SPEC.md](../SPEC.md). This crate provides the low-level abstract of the TUIC protocol in Rust.

Some optional features that can be enabled:

- `model` - Provides a connection model abstraction of the TUIC protocol, with packet fragmentation and task counter built-in. No I/O operation is involved.
- `marshal` - Provides methods for (un)marsalling the protocol in sync flavor.
- `async_marshal` - Provides methods for (un)marsalling the protocol in async flavor.

The root of the protocol abstraction is the [`Header`](src/protocol/mod.rs).

## Versioning Syntax

```text
5.0.0-rc0
^ ^ ^  ^
| | |  |- Pre-release version, considered to be unstable
| | |---- Patch version, no breaking changes
| |------ Major version of a specific TUIC protocol version, may have breaking changes
|-------- TUIC protocol version
```

To avoid breaking changes, import `tuic` into `Cargo.toml` using:

```toml
# Use this repository's main branch, with TUIC protocol version 5.
tuic = { git = "https://github.com/Siglud/tuic", branch = "main", version = "5.0.*" }
```

## Configuration

This protocol library is configured through its Rust API and does not read
configuration files. For runnable tools, see the
[main usage guide](../README.md#usage) and the commented configuration references
for the [client](../tuic-client/README.md#configuration),
[server](../tuic-server/README.md#configuration), and
[UDP forwarder](../tuic-udp-forwarder/README.md#configuration). All three tools
parse config files as JSONC regardless of extension, including `.json`, with
line/block comments and trailing commas supported. Plain JSON remains valid.

## License

This library is licensed under [GNU General Public License v3.0](../LICENSE)

However, the concept of the TUIC protocol is license-free. You can implement, modify, and redistribute the protocol without any restrictions, even for commercial use
