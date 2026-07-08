# lksctp

[![crates.io](https://img.shields.io/crates/v/lksctp.svg)](https://crates.io/crates/lksctp)
[![docs.rs](https://docs.rs/lksctp/badge.svg)](https://docs.rs/lksctp)
[![CI](https://github.com/shozoo/lksctp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/shozoo/lksctp-rs/actions)

Rust bindings for **Linux kernel SCTP** with tokio integration and no
dependency on lksctp-tools (libsctp) — everything goes straight to the
kernel via syscalls.

Built for telecom signaling protocols (NGAP, M3UA, Diameter, ...) that need:

- message-oriented send/receive with per-message **sid / ppid / assoc_id**
- **multi-streaming** and **multi-homing** (`bindx` / `connectx`)
- inline **notifications** (association up/down, path state changes,
  shutdown, stream reset, ...)
- deep **introspection**: association status (`SCTP_STATUS`) and per-path
  state — cwnd, srtt, RTO, MTU, reachability (`SCTP_GET_PEER_ADDR_INFO`)
- a fast async data path: `AsyncFd` readiness loops straight onto
  `sendmsg(2)`/`recvmsg(2)`, no intermediate buffering or task hops

## Requirements

- **Runtime**: Linux kernel 4.11+ with the `sctp` module (`modprobe sctp`).
  No user-space SCTP library needed.
- **Build**: Rust 1.85+ (edition 2024), any platform. On non-Linux targets
  the crate compiles but all constructors return
  `io::ErrorKind::Unsupported` (handy for cross-platform development and
  CI).
- Optional: without the default `tokio` feature the crate is a pure
  synchronous binding with zero async dependencies.

## Socket types

| Type | Kernel socket | Model |
|---|---|---|
| `SctpListener` / `SctpStream` | `SOCK_STREAM` (one-to-one) | TCP-like accept/connect; one association per socket |
| `SctpEndpoint` | `SOCK_SEQPACKET` (one-to-many) | UDP-like; many associations keyed by `AssocId`, `peeloff` to detach |
| `SctpSocket` | either | synchronous low-level building block |

## Example

```rust,no_run
use lksctp::{EventType, Family, InitParams, RecvMsg, SctpListener, SendInfo};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = SctpListener::builder(Family::Ipv4)?
        .init_params(&InitParams { num_ostreams: 8, max_instreams: 8, ..Default::default() })?
        .subscribe_events(&[EventType::AssocChange, EventType::PeerAddrChange])?
        .bindx(&["10.0.0.1:38412".parse().unwrap(), "10.0.1.1:38412".parse().unwrap()])?
        .listen(128)?;

    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match stream.recv_msg(&mut buf).await.unwrap() {
                    // A zero-length read means the peer closed the association.
                    RecvMsg::Data { len: 0, .. } => break,
                    RecvMsg::Data { len, info, .. } => {
                        let info = info.unwrap();
                        println!("{peer}: {len}B sid={} ppid={:?}", info.sid, info.ppid);
                        let reply = SendInfo { sid: info.sid, ppid: info.ppid, ..Default::default() };
                        stream.send_msg(&buf[..len], &reply).await.unwrap();
                    }
                    RecvMsg::Notification(n) => println!("{peer}: event {n:?}"),
                }
            }
        });
    }
}
```

## Blocking (thread-based) usage

The synchronous `SctpSocket` is a first-class API, not a test helper. With
`default-features = false` the crate has zero async dependencies and works
with plain OS threads:

```rust,ignore
let sock = SctpSocket::new(Family::Ipv4, Style::OneToOne)?;
sock.set_recv_timeout(Some(Duration::from_secs(5)))?; // recv fails with WouldBlock on expiry
sock.connectx(&[addr])?;                              // blocks until established
let mut buf = vec![0u8; 64 * 1024];
match sock.recv_msg(&mut buf)? {
    RecvMsg::Data { len: 0, .. } => { /* peer closed */ }
    RecvMsg::Data { len, info, .. } => { /* message */ }
    RecvMsg::Notification(n) => { /* subscribed event */ }
}
```

## Development

Unit tests (layout checks, notification/cmsg/sockaddr parsers) run on any
OS with `cargo test`. The loopback integration tests need a Linux kernel
with SCTP; the repo ships a devcontainer for that:

```console
$ devcontainer up --workspace-folder .
$ devcontainer exec --workspace-folder . cargo test
```

(or open the folder in VS Code and "Reopen in Container"). On macOS,
`cargo check --target x86_64-unknown-linux-gnu` type-checks the Linux
implementation without a container.

## Status

Early development. Implemented: sync + async one-to-one and one-to-many
sockets, bindx/connectx, notification parsing, `SCTP_STATUS` /
`SCTP_GET_PEER_ADDR_INFO` introspection, per-path tuning
(`SCTP_PEER_ADDR_PARAMS`), peeloff, blocking timeouts. Planned: `poll_*` /
`try_*` APIs, PR-SCTP send options, stream reset/add (RFC 6525),
`sendmmsg`/`recvmmsg` batching, benchmarks.

## License

MIT
