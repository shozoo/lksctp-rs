//! Shared plumbing for the tokio-based socket types.
//!
//! On Linux the raw socket is registered with the tokio reactor through
//! [`tokio::io::unix::AsyncFd`] and all async operations are
//! readiness-driven `try_io` loops — the same model `tokio::net::UdpSocket`
//! uses internally, with no extra buffering or task hops in the data path.
//! Off Linux, `Io` is the uninhabited stub socket, so these functions are
//! trivially unreachable while keeping every signature compiling.

use std::io;

use crate::imp;

#[cfg(target_os = "linux")]
pub(crate) type Io = tokio::io::unix::AsyncFd<imp::Socket>;
#[cfg(not(target_os = "linux"))]
pub(crate) type Io = imp::Socket;

/// Borrows the raw socket for synchronous operations (sockopts etc.).
pub(crate) fn sock(io: &Io) -> &imp::Socket {
    #[cfg(target_os = "linux")]
    {
        io.get_ref()
    }
    #[cfg(not(target_os = "linux"))]
    {
        match *io {}
    }
}

/// Switches the socket to non-blocking mode and registers it with the
/// current tokio reactor. Must be called from within a tokio runtime.
pub(crate) fn register(sock: imp::Socket) -> io::Result<Io> {
    #[cfg(target_os = "linux")]
    {
        sock.set_nonblocking(true)?;
        tokio::io::unix::AsyncFd::new(sock)
    }
    #[cfg(not(target_os = "linux"))]
    {
        match sock {}
    }
}

/// Runs `f` when the socket is readable, retrying on `WouldBlock` with the
/// readiness cleared (edge-triggered semantics handled by `AsyncFd`).
pub(crate) async fn read_op<T, F>(io: &Io, mut f: F) -> io::Result<T>
where
    F: FnMut(&imp::Socket) -> io::Result<T>,
{
    #[cfg(target_os = "linux")]
    {
        loop {
            let mut guard = io.readable().await?;
            match guard.try_io(|inner| f(inner.get_ref())) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &mut f;
        match *io {}
    }
}

/// Runs `f` when the socket is writable, retrying on `WouldBlock`.
pub(crate) async fn write_op<T, F>(io: &Io, mut f: F) -> io::Result<T>
where
    F: FnMut(&imp::Socket) -> io::Result<T>,
{
    #[cfg(target_os = "linux")]
    {
        loop {
            let mut guard = io.writable().await?;
            match guard.try_io(|inner| f(inner.get_ref())) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &mut f;
        match *io {}
    }
}

/// Waits for a non-blocking connect to complete by observing the
/// association-change notification stream.
///
/// The TCP idiom "writable means connected" does not carry over to SCTP:
/// `sctp_poll()` reports the socket writable whenever send-buffer space is
/// available, which is already true while the 4-way handshake is still in
/// flight. The reliable completion signals are the `SCTP_ASSOC_CHANGE`
/// notifications (`CommUp` on success, `CantStartAssoc`/`CommLost` on
/// failure), which the caller must have subscribed to *before* initiating
/// the connect. Nothing else can be delivered before `CommUp`, so consuming
/// notifications here cannot swallow user data; pre-establishment
/// notifications other than the outcome are discarded.
pub(crate) async fn established(io: &Io) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use crate::notification::{AssocChangeState, Notification};
        use crate::types::RecvMsg;

        let mut buf = [0u8; 512];
        loop {
            let mut guard = io.readable().await?;
            let result = match guard.try_io(|inner| inner.get_ref().recv_msg(&mut buf, false)) {
                Err(_would_block) => continue,
                Ok(result) => result?,
            };
            match result.0 {
                RecvMsg::Notification(Notification::AssocChange(ac)) => match ac.state {
                    AssocChangeState::CommUp => return Ok(()),
                    AssocChangeState::CommLost | AssocChangeState::CantStartAssoc => {
                        return Err(match sock(io).take_error()? {
                            Some(e) => e,
                            None => io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "SCTP association could not be established",
                            ),
                        });
                    }
                    _ => continue,
                },
                RecvMsg::Notification(_) => continue,
                RecvMsg::Data { len: 0, .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "socket closed during association setup",
                    ));
                }
                RecvMsg::Data { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "user data received before SCTP_COMM_UP",
                    ));
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        match *io {}
    }
}

/// Implements the introspection / socket-option methods shared by all three
/// async socket types by delegating to the underlying raw socket. These are
/// plain syscalls (no waiting), hence synchronous.
macro_rules! impl_common_sockopts {
    ($ty:ty) => {
        impl $ty {
            /// Returns an association status snapshot (`SCTP_STATUS`),
            /// including negotiated stream counts and primary path info.
            /// One-to-one style sockets ignore `assoc_id`.
            pub fn status(&self, assoc_id: crate::AssocId) -> std::io::Result<crate::AssocStatus> {
                crate::net::common::sock(&self.io).status(assoc_id)
            }

            /// Returns per-path state (reachability, cwnd, srtt, rto, MTU)
            /// for one peer address (`SCTP_GET_PEER_ADDR_INFO`).
            pub fn peer_addr_info(
                &self,
                assoc_id: crate::AssocId,
                addr: &std::net::SocketAddr,
            ) -> std::io::Result<crate::PeerAddrInfo> {
                crate::net::common::sock(&self.io).peer_addr_info(assoc_id, addr)
            }

            /// Returns the per-path parameters — heartbeat interval, path
            /// failure threshold, PMTU handling (`SCTP_PEER_ADDR_PARAMS`).
            /// `addr: None` queries the association/endpoint defaults.
            pub fn peer_addr_params(
                &self,
                assoc_id: crate::AssocId,
                addr: Option<&std::net::SocketAddr>,
            ) -> std::io::Result<crate::PeerAddrParams> {
                crate::net::common::sock(&self.io).peer_addr_params(assoc_id, addr)
            }

            /// Sets per-path parameters (`SCTP_PEER_ADDR_PARAMS`), e.g. the
            /// heartbeat interval and `path_max_rxt` that drive failover
            /// timing on multi-homed associations.
            pub fn set_peer_addr_params(
                &self,
                assoc_id: crate::AssocId,
                addr: Option<&std::net::SocketAddr>,
                params: &crate::PeerAddrParams,
            ) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).set_peer_addr_params(assoc_id, addr, params)
            }

            /// Returns the RTO bounds in milliseconds (`SCTP_RTOINFO`).
            pub fn rto_info(&self, assoc_id: crate::AssocId) -> std::io::Result<crate::RtoInfo> {
                crate::net::common::sock(&self.io).rto_info(assoc_id)
            }

            /// Sets the RTO bounds in milliseconds; zero fields keep current
            /// values.
            pub fn set_rto_info(
                &self,
                assoc_id: crate::AssocId,
                rto: &crate::RtoInfo,
            ) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).set_rto_info(assoc_id, rto)
            }

            /// Subscribes to (or unsubscribes from) a notification class
            /// (`SCTP_EVENT`); events arrive through the receive path.
            pub fn subscribe_event(
                &self,
                event: crate::EventType,
                on: bool,
            ) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).subscribe_event(event, on)
            }

            /// Subscribes to several notification classes at once.
            pub fn subscribe_events(&self, events: &[crate::EventType]) -> std::io::Result<()> {
                for ev in events {
                    self.subscribe_event(*ev, true)?;
                }
                Ok(())
            }

            /// Returns whether Nagle-style bundling delay is disabled.
            pub fn nodelay(&self) -> std::io::Result<bool> {
                crate::net::common::sock(&self.io).nodelay()
            }

            /// Disables (or re-enables) Nagle-style bundling delay.
            pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).set_nodelay(nodelay)
            }

            /// Requests that the given peer address become the primary path.
            pub fn set_primary(
                &self,
                assoc_id: crate::AssocId,
                addr: &std::net::SocketAddr,
            ) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).set_primary(assoc_id, addr)
            }

            /// Returns one bound local address (`getsockname(2)`).
            pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
                crate::net::common::sock(&self.io).local_addr()
            }

            /// Returns all bound local addresses (`sctp_getladdrs(3)`).
            pub fn local_addrs(
                &self,
                assoc_id: crate::AssocId,
            ) -> std::io::Result<Vec<std::net::SocketAddr>> {
                crate::net::common::sock(&self.io).local_addrs(assoc_id)
            }

            /// Returns all peer addresses of an association
            /// (`sctp_getpaddrs(3)`).
            pub fn peer_addrs(
                &self,
                assoc_id: crate::AssocId,
            ) -> std::io::Result<Vec<std::net::SocketAddr>> {
                crate::net::common::sock(&self.io).peer_addrs(assoc_id)
            }

            /// Returns the send buffer size (`SO_SNDBUF`).
            pub fn send_buffer_size(&self) -> std::io::Result<usize> {
                crate::net::common::sock(&self.io).send_buffer_size()
            }

            /// Sets the send buffer size (`SO_SNDBUF`).
            pub fn set_send_buffer_size(&self, size: usize) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).set_send_buffer_size(size)
            }

            /// Returns the receive buffer size (`SO_RCVBUF`).
            pub fn recv_buffer_size(&self) -> std::io::Result<usize> {
                crate::net::common::sock(&self.io).recv_buffer_size()
            }

            /// Sets the receive buffer size (`SO_RCVBUF`); this feeds the
            /// advertised receiver window (rwnd).
            pub fn set_recv_buffer_size(&self, size: usize) -> std::io::Result<()> {
                crate::net::common::sock(&self.io).set_recv_buffer_size(size)
            }

            /// Returns and clears the pending socket error (`SO_ERROR`).
            pub fn take_error(&self) -> std::io::Result<Option<std::io::Error>> {
                crate::net::common::sock(&self.io).take_error()
            }
        }
    };
}

pub(crate) use impl_common_sockopts;
