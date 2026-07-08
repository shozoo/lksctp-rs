//! # lksctp
//!
//! Rust bindings for **Linux kernel SCTP** with no dependency on
//! lksctp-tools (libsctp): everything goes straight to the kernel through
//! syscalls. Designed for telecom signaling protocols (NGAP, M3UA,
//! Diameter, ...) that need message-oriented, multi-streamed, multi-homed
//! transport plus deep visibility into association and path state.
//!
//! The crate compiles on every platform, but sockets can only be created on
//! Linux (kernel 4.11+); elsewhere constructors return
//! [`std::io::ErrorKind::Unsupported`].
//!
//! ## Layers
//!
//! - [`sys`]: raw constants and structs mirroring `<uapi/linux/sctp.h>`.
//! - [`SctpSocket`]: synchronous safe wrapper, usable without tokio
//!   (`default-features = false`).
//! - [`SctpStream`] / [`SctpListener`] (one-to-one) and [`SctpEndpoint`]
//!   (one-to-many): tokio-integrated async types (`tokio` feature, default
//!   on), styled after `tokio::net`'s TCP/UDP types but message-oriented.
//!
//! ## Example (async one-to-one server and client)
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # mod example {
//! use lksctp::{Ppid, RecvMsg, SctpListener, SctpStream, SendInfo};
//!
//! # async fn run() -> std::io::Result<()> {
//! // Server
//! let listener = SctpListener::bind("0.0.0.0:38412".parse().unwrap())?;
//! let (stream, peer) = listener.accept().await?;
//!
//! let mut buf = vec![0u8; 64 * 1024];
//! match stream.recv_msg(&mut buf).await? {
//!     RecvMsg::Data { len, info, .. } => {
//!         let info = info.unwrap();
//!         println!("{} bytes from {peer} on sid={} ppid={:?}", len, info.sid, info.ppid);
//!     }
//!     RecvMsg::Notification(n) => println!("event: {n:?}"),
//! }
//!
//! // Client
//! let client = SctpStream::connect("203.0.113.1:38412".parse().unwrap()).await?;
//! client
//!     .send_msg(b"NGSetupRequest", &SendInfo { ppid: Ppid::NGAP, ..Default::default() })
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```

// Off-Linux, the kernel-facing halves of the internal modules are unused by
// the stub; the Linux build (CI) still catches genuinely dead code.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod addr;
mod cmsg;
mod imp;
#[cfg(feature = "tokio")]
mod net;
mod notification;
mod socket;
mod types;

pub mod sys;

#[cfg(feature = "tokio")]
pub use net::{
    EndpointBuilder, ListenerBuilder, SctpEndpoint, SctpListener, SctpStream, StreamBuilder,
};
pub use notification::{
    AdaptationIndication, AssocChange, AssocChangeState, AssocResetEvent, AuthenticationEvent,
    Notification, PartialDeliveryEvent, PeerAddrChange, PeerAddrChangeState, RawNotification,
    RemoteError, SendFailed, SenderDryEvent, ShutdownEvent, StreamChangeEvent, StreamResetEvent,
};
pub use socket::SctpSocket;
pub use types::{
    AssocId, AssocState, AssocStatus, EventType, Family, InitParams, PeerAddrInfo, PeerAddrParams,
    PeerAddrState, Ppid, RcvFlags, RcvInfo, RecvMsg, RtoInfo, SendFlags, SendInfo, SppFlags, Style,
};
