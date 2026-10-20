# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

<!-- next-header -->
## [Unreleased] - ReleaseDate

## [0.2.0] - 2026-10-20

### Added
- Association retransmission and delayed SACK options (`SCTP_ASSOCINFO`,
  `SCTP_DELAYED_SACK`), including future-association defaults.
- Per-association chunk, SACK, packet, and observed maximum-RTO statistics
  (`SCTP_GET_ASSOC_STATS`).
- `SO_REUSEADDR` / `SCTP_REUSE_PORT` options and tuning methods on the stream
  and listener builders.
- Conversion of a configured `SctpSocket` into the Tokio listener, stream, and
  endpoint types (`from_socket`, `connectx_from_socket`).
- `SctpStream::abort` and `set_abort_on_drop` (immediate ABORT through zero
  `SO_LINGER`); the latter also works for a stream shared through `Arc`.
- `subscribe_event_for` to change the subscriptions of existing associations
  (`AssocId::ALL` covers current and future ones).
- The README is embedded as the crate documentation and its examples are
  compiled as doctests.

### Changed
- **Breaking:** `SctpListener` exposes only listener-level settings and
  future-association defaults; association status, paths, and statistics are
  queried on the accepted `SctpStream`.
- **Breaking:** `SctpEndpoint::shutdown` was removed and one-to-many
  `SctpSocket::shutdown` returns `Unsupported`, because Linux `shutdown(2)`
  never sends an SCTP SHUTDOWN on one-to-many sockets. Use `SendFlags::EOF`
  or drop the socket instead.
- **Breaking:** `SctpEndpoint` no longer exposes `SCTP_REUSE_PORT`, which
  Linux supports only on one-to-one sockets.
- **Breaking:** `SctpStream::set_reuse_port` was removed because streams are
  already bound. Use `StreamBuilder::reuse_port` or
  `ListenerBuilder::reuse_port` before binding; the stream getter remains.
- The runtime requirement is Linux 5.1+ (`SCTP_EVENT` needs 5.0 and the
  `SCTP_*_ASSOC` selectors 5.1); 0.1.0 wrongly documented 4.11+.
- Accepted and peeled-off Tokio streams are created with `SOCK_NONBLOCK`
  instead of a separate `fcntl` call.
- A multi-address `bindx_add` with port zero is a single kernel call.
- Cancellation behavior of the async operations is documented.

### Fixed
- A blocking `connectx` whose send timeout expired reported success; it now
  fails with `TimedOut`.
- Oversized socket buffer requests are rejected instead of wrapping through
  the kernel's `i32` option value, and sub-microsecond timeouts remain enabled.
- `local_addrs` / `peer_addrs` failed with `ENOMEM` on endpoints with more
  than 64 addresses; the query now grows its buffer.
- Linux CI fails instead of silently skipping the integration tests when the
  kernel lacks SCTP; macOS build, MSRV, and rustdoc checks were added.

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
