# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

<!-- next-header -->
## [Unreleased] - ReleaseDate

## [0.1.0] - 2026-07-08

### Added
- Synchronous `SctpSocket` (one-to-one / one-to-many) over Linux kernel SCTP
  with no libsctp dependency: bindx/connectx, sendmsg/recvmsg with
  `SCTP_SNDINFO`/`SCTP_RCVINFO`, notification parsing (with reassembly of
  notifications larger than the receive buffer), `SCTP_STATUS` /
  `SCTP_GET_PEER_ADDR_INFO` introspection, per-path tuning via
  `SCTP_PEER_ADDR_PARAMS`, peeloff, and `AsRawFd`/`IntoRawFd`/`FromRawFd`.
- tokio-integrated async types `SctpStream`, `SctpListener`, `SctpEndpoint`
  (default `tokio` feature) built on `AsyncFd` readiness loops. Async
  connect resolves only when the association is fully established, observed
  via the `SCTP_COMM_UP` notification (SCTP sockets report writability
  during the handshake, so TCP-style connect polling does not apply).
- Compiles on non-Linux targets (constructors return
  `io::ErrorKind::Unsupported`).
- Blocking receive/send timeouts (`set_recv_timeout` / `set_send_timeout`,
  `SO_RCVTIMEO`/`SO_SNDTIMEO`) for thread-based use of `SctpSocket`.
- Loopback integration test suites (tokio-based and blocking/thread-based)
  with wire-accurate Diameter and M3UA traffic; devcontainer for running
  them on macOS hosts.

### Requirements
- Linux kernel 4.11+ at runtime (`SCTP_EVENT` socket option); compiles on
  any platform. MSRV: Rust 1.85 (edition 2024).
