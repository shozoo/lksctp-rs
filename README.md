# lksctp

[![crates.io](https://img.shields.io/crates/v/lksctp.svg)](https://crates.io/crates/lksctp)
[![docs.rs](https://docs.rs/lksctp/badge.svg)](https://docs.rs/lksctp)
[![CI](https://github.com/shozoo/lksctp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/shozoo/lksctp-rs/actions)

`lksctp` is a Rust wrapper around **Linux kernel SCTP**. Its design is to
stay thin: keep overhead low, use the kernel's SCTP implementation directly,
and make as much of its socket API available as practical. It does not
implement SCTP in user space or depend on lksctp-tools (`libsctp`).

The crate provides a synchronous socket and, by default, Tokio-integrated
types. Both preserve SCTP's message boundaries, streams, associations,
multi-homing, notifications, and per-path controls. The async data path uses
`AsyncFd` readiness with `sendmsg(2)` and `recvmsg(2)`, without an intermediate
message queue or task hop. Notification fragments are reassembled when the
caller-provided buffer is too small.

## Requirements and installation

- **Runtime:** Linux kernel 5.0 or newer with SCTP support. The crate uses
  `SCTP_EVENT`, which is needed for async connection establishment.
- **Toolchain:** Rust 1.85 or newer (edition 2024).
- **Other platforms:** The crate compiles, but socket constructors return
  `io::ErrorKind::Unsupported`.

The `tokio` feature is enabled by default. Add Tokio separately if you use
the async API:

```toml
[dependencies]
lksctp = "0.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

For a synchronous-only application, use
`lksctp = { version = "0.2", default-features = false }`.

## Choose a socket type

| Type | Kernel style | Use it for |
| --- | --- | --- |
| `SctpListener` and `SctpStream` | `SOCK_STREAM`, one-to-one | Accepting or connecting one association per stream with Tokio. |
| `SctpEndpoint` | `SOCK_SEQPACKET`, one-to-many | Carrying several associations on one Tokio socket, identified by `AssocId`. |
| `SctpSocket` | Either style | Blocking or explicitly nonblocking use, and configuring a socket before handing it to Tokio. |

`SctpListener` exposes local socket settings and defaults for **future**
associations. Query an accepted association's status, paths, and statistics
through its `SctpStream`. On a one-to-many endpoint, pass the association ID
to those operations.

## Supported features

| Area | Available API | Kernel interface |
| --- | --- | --- |
| Association setup | `bind`, `listen`, `accept`, `connect`, `connectx`; `bindx_add`/`bindx_remove` for local multi-homing | SCTP one-to-one and one-to-many sockets, bindx/connectx options |
| Message I/O | `send_msg`, `send_msg_to`, `recv_msg`, `recv_msg_from`; stream ID, PPID, flags, and association ID in `SendInfo`/`RcvInfo` | `sendmsg(2)`/`recvmsg(2)`, `SCTP_SNDINFO`/`SCTP_RCVINFO` |
| Notifications | Per-event subscriptions and parsed association, path, shutdown, send-failure, sender-dry, and other notifications | `SCTP_EVENT` |
| Socket tuning | INIT parameters, `SCTP_NODELAY`, send/receive buffers, `SO_REUSEADDR`, and one-to-one `SCTP_REUSE_PORT` | `SCTP_INITMSG`, socket options |
| Association tuning | Retransmission limit and cookie life, RTO bounds, delayed SACK delay and frequency | `SCTP_ASSOCINFO`, `SCTP_RTOINFO`, `SCTP_DELAYED_SACK` |
| Path tuning | Heartbeat, retransmission, PMTU, primary-path settings, IPv6 flow label, and DSCP | `SCTP_PEER_ADDR_PARAMS`, `SCTP_PRIMARY_ADDR` |
| Introspection | Association status, local/peer addresses, path state and metrics, association counters | `SCTP_STATUS`, `SCTP_GET_PEER_ADDR_INFO`, `SCTP_GET_ASSOC_STATS` |
| Association lifecycle | Graceful shutdown, one-to-many `SCTP_EOF`, immediate ABORT, and `peeloff` | `shutdown(2)`, `SCTP_EOF`, `SCTP_ABORT`, peeloff option |

`SctpSocket` is the broadest interface. The builders cover common setup
options; for another option that must be set before `listen` or `connectx`,
configure an `SctpSocket` and use `SctpListener::from_socket`,
`SctpStream::connectx_from_socket`, or `SctpEndpoint::from_socket`. These
conversions set nonblocking mode and register the socket with Tokio.

## One-to-one example

This server replies to messages that fit its 64 KiB receive buffer. A
`RecvMsg::Data` result with `eor: false` is a fragment; applications that
accept larger messages should collect fragments until `eor` is true.

```rust,no_run
use lksctp::{EventType, Family, RecvMsg, SctpListener, SendInfo};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = SctpListener::builder(Family::Ipv4)?
        .reuse_address(true)?
        .subscribe_events(&[EventType::AssocChange, EventType::PeerAddrChange])?
        .bindx(&["0.0.0.0:38412".parse().unwrap()])?
        .listen(128)?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let _ = tokio::spawn(async move {
            let mut buf = [0u8; 64 * 1024];
            loop {
                match stream.recv_msg(&mut buf).await? {
                    RecvMsg::Data { len: 0, info: None, .. } => break,
                    RecvMsg::Data { eor: false, .. } => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "message exceeds receive buffer",
                        ));
                    }
                    RecvMsg::Data { len, info, eor: true } => {
                        let info = info.ok_or_else(|| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "missing SCTP receive metadata",
                        ))?;
                        println!("{peer}: {len} bytes on stream {}", info.sid);
                        let reply = SendInfo {
                            sid: info.sid,
                            ppid: info.ppid,
                            ..Default::default()
                        };
                        stream.send_msg(&buf[..len], &reply).await?;
                    }
                    RecvMsg::Notification(event) => println!("{peer}: {event:?}"),
                }
            }
            Ok::<(), std::io::Error>(())
        });
    }
}
```

## One-to-many example

An `SctpEndpoint` carries several associations on one socket. Subscribe to
`AssocChange` to learn when one comes up; each DATA message's
`RcvInfo::assoc_id` identifies the association to reply to. This example
accepts messages that fit its receive buffer:

```rust,no_run
use lksctp::{EventType, Family, Notification, RecvMsg, SctpEndpoint, SendInfo};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let endpoint = SctpEndpoint::builder(Family::Ipv4)?
        .subscribe_events(&[EventType::AssocChange])?
        .bindx(&["0.0.0.0:38412".parse().unwrap()])?
        .listen(128)?;
    let mut buf = [0u8; 64 * 1024];

    loop {
        match endpoint.recv_msg(&mut buf).await? {
            RecvMsg::Notification(Notification::AssocChange(change)) => {
                println!("association {}: {:?}", change.assoc_id.0, change.state);
            }
            RecvMsg::Data { len, info: Some(info), eor: true } => {
                let reply = SendInfo {
                    assoc_id: info.assoc_id,
                    sid: info.sid,
                    ppid: info.ppid,
                    ..Default::default()
                };
                endpoint.send_msg(&buf[..len], &reply).await?;
            }
            RecvMsg::Data { eor: false, .. } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "message exceeds receive buffer",
                ));
            }
            _ => {}
        }
    }
}
```

`peeloff` moves one association to a `SctpStream` while the endpoint keeps
serving the others.

## Configuration and observation

For association defaults, `AssocId::FUTURE` applies to connections created
later. `AssocId::ALL` covers current and future associations when changing
one-to-many notification subscriptions with `subscribe_event_for`. A
one-to-one `SctpStream` also accepts `AssocId::FUTURE` for its current
association. Listener methods such as `set_assoc_info` select future
associations implicitly and do not take an ID.

```rust,no_run
use lksctp::{AssocId, AssocInfo, Family, SackInfo, SctpListener, SctpSocket, Style};

# fn prepare() -> std::io::Result<SctpListener> {
let socket = SctpSocket::new(Family::Ipv4, Style::OneToOne)?;
socket.set_assoc_info(AssocId::FUTURE, &AssocInfo {
    asocmaxrxt: 7,
    ..Default::default()
})?;
socket.set_delayed_sack(AssocId::FUTURE, &SackInfo {
    delay_ms: 100,
    freq: 2,
})?;
socket.bind(&"127.0.0.1:0".parse().unwrap())?;
socket.listen(128)?;
SctpListener::from_socket(socket)
# }
```

Some kernel semantics matter when configuring a socket:

- Zero fields in `AssocInfo` leave their current values unchanged;
  `number_peer_destinations` and receive-window fields are read-only.
  `SackInfo::freq = 1` disables delayed SACK on Linux. A zero `delay_ms`
  leaves the stored timer unchanged, although a get reports zero while
  delayed SACK is disabled.
- `InitParams::max_init_timeo` is a `u16` in milliseconds. Check that a
  converted duration is at most **65,535 ms** before storing it.
- Set `SO_REUSEADDR` and one-to-one `SCTP_REUSE_PORT` before binding. With
  multiple port-zero addresses, `bindx_add` uses one ephemeral port for all
  of them; query `local_addr` or `local_addrs` for the chosen port. After a
  failed `bindx_add`, discard the socket because the kernel may retain a
  partial bind.
- `assoc_stats` returns cumulative chunk, SACK, and packet counters. Reading
  it restarts the maximum-RTO observation period. `max_rto_kernel_ticks`
  is in kernel ticks, not milliseconds.

## Closing an association

On a `SctpStream`, `shutdown(Shutdown::Write)` starts graceful SCTP shutdown;
`abort(self)` closes it immediately without waiting for queued DATA. If a
stream is shared through `Arc`, call `set_abort_on_drop` and release the final
reference to send ABORT. `Shutdown::Read` only changes local reads.

For one-to-many sockets, use `SendFlags::EOF` to gracefully close one
association or `SendFlags::ABORT` to abort one. Dropping the endpoint closes
all its associations. `SctpEndpoint::shutdown` and one-to-many
`SctpSocket::shutdown` return `io::ErrorKind::Unsupported` because Linux
`shutdown(2)` does not send SCTP SHUTDOWN for that socket style.

## Synchronous use

Disable the default feature to use `SctpSocket` without a Tokio dependency.
The socket is blocking unless `set_nonblocking(true)` is called; send and
receive timeouts use `SO_SNDTIMEO` and `SO_RCVTIMEO`.

```rust,no_run
use std::time::Duration;
use lksctp::{Family, RecvMsg, SctpSocket, Style};

# fn receive_one() -> std::io::Result<()> {
let socket = SctpSocket::new(Family::Ipv4, Style::OneToOne)?;
socket.set_recv_timeout(Some(Duration::from_secs(5)))?;
socket.connectx(&["127.0.0.1:38412".parse().unwrap()])?;
let mut buf = [0u8; 4096];
match socket.recv_msg(&mut buf)? {
    RecvMsg::Data { len: 0, info: None, .. } => println!("peer closed"),
    RecvMsg::Data { len, .. } => println!("received {len} bytes"),
    RecvMsg::Notification(event) => println!("{event:?}"),
}
# Ok(())
# }
```

## Scope

The crate exposes parsed notifications for stream-reset events but does not
yet provide stream-reset operations. It also does not provide `sendmmsg` /
`recvmmsg` batching, PR-SCTP, or UDP encapsulation. Raw Linux constants and
structures remain available through `lksctp::sys`.

## Development

Unit tests check layouts and protocol parsing. Loopback integration tests
exercise the kernel SCTP stack for both blocking and Tokio sockets. They
self-skip where SCTP is unavailable; Linux CI first checks for a working SCTP
socket so that a skipped integration suite cannot produce a passing run.
The included devcontainer provides a Linux environment for development from
macOS:

```console
$ devcontainer up --workspace-folder .
$ devcontainer exec --workspace-folder . cargo test --all-targets
$ devcontainer exec --workspace-folder . cargo test --no-default-features
```

## License

MIT
