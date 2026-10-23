# tuic-quinn

A thin layer on top of [quinn](https://github.com/quinn-rs/quinn) to provide functions for TUIC

[![Release](https://img.shields.io/github/v/release/Siglud/tuic?style=flat)](../../../releases)
[![Source](https://img.shields.io/badge/docs-source-brightgreen.svg?style=flat)](src)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg?style=flat)](../LICENSE)

## Overview

This crate provides a wrapper [`Connection`](src/lib.rs) around [`quinn::Connection`](https://docs.rs/quinn/latest/quinn/struct.Connection.html). It can be used to perform TUIC operations.

Note that there is no state machine abstraction for the TUIC protocol flow in this crate. You need to implement it yourself.

## Configuration

This library is configured through its Rust API and does not read configuration
files. The repository's [client](../tuic-client/README.md#configuration),
[server](../tuic-server/README.md#configuration), and
[UDP forwarder](../tuic-udp-forwarder/README.md#configuration) always parse their
config files as JSONC, even with a `.json` extension. Their references include
commented examples describing every property, default, and applicable value
scope. JSONC supports line/block comments and trailing commas; plain JSON
remains valid.

## License

GNU General Public License v3.0
