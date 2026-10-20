// The README doubles as the crate documentation, so its examples are
// compiled as doctests. They use the async types, hence the feature gate.
#![cfg_attr(feature = "tokio", doc = include_str!("../README.md"))]
#![cfg_attr(
    not(feature = "tokio"),
    doc = "Rust bindings for Linux kernel SCTP with no libsctp dependency. This \
           build has the `tokio` feature disabled, so only the synchronous \
           [`SctpSocket`] is available; see the README for an overview."
)]
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
    AssocId, AssocInfo, AssocState, AssocStats, AssocStatus, EventType, Family, InitParams,
    PeerAddrInfo, PeerAddrParams, PeerAddrState, Ppid, RcvFlags, RcvInfo, RecvMsg, RtoInfo,
    SackInfo, SendFlags, SendInfo, SppFlags, Style,
};
