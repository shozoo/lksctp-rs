//! The synchronous [`SctpSocket`], a thin safe wrapper over the kernel API.

use std::io;
use std::net::{Shutdown, SocketAddr};

use crate::imp;
use crate::types::{
    AssocId, AssocStatus, EventType, Family, InitParams, PeerAddrInfo, PeerAddrParams, RecvMsg,
    RtoInfo, SendInfo, Style,
};

/// A synchronous SCTP socket (one-to-one or one-to-many style).
///
/// This is the low-level building block of the crate: a direct, blocking (or
/// explicitly non-blocking) interface to Linux kernel SCTP with no libsctp
/// dependency. The async tokio types are built on top of it.
///
/// Sockets created by this crate always enable `SCTP_RECVRCVINFO`, so
/// [`recv_msg`](Self::recv_msg) returns per-message metadata (sid, ppid,
/// ...) without further setup.
///
/// On non-Linux platforms every constructor returns
/// [`io::ErrorKind::Unsupported`].
#[derive(Debug)]
pub struct SctpSocket {
    pub(crate) inner: imp::Socket,
}

impl SctpSocket {
    /// Creates a new unbound SCTP socket.
    pub fn new(family: Family, style: Style) -> io::Result<SctpSocket> {
        Ok(SctpSocket {
            inner: imp::Socket::new(family, style)?,
        })
    }

    // -- addresses / connection setup --------------------------------------

    /// Binds to a single local address (`bind(2)`).
    pub fn bind(&self, addr: &SocketAddr) -> io::Result<()> {
        self.inner.bind(addr)
    }

    /// Adds local addresses to the endpoint (`sctp_bindx(SCTP_BINDX_ADD_ADDR)`).
    ///
    /// All addresses must share one port. To multi-home, either call this
    /// with the full list on an unbound socket, or [`bind`](Self::bind) first
    /// and add more addresses (with the same port) here.
    pub fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.inner.bindx_add(addrs)
    }

    /// Removes local addresses from the endpoint
    /// (`sctp_bindx(SCTP_BINDX_REM_ADDR)`).
    pub fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.inner.bindx_remove(addrs)
    }

    /// Marks the socket as accepting new associations.
    ///
    /// One-to-one: TCP-like listen backlog. One-to-many: enables the
    /// endpoint to accept inbound associations (they are established by the
    /// kernel without an `accept` call and surface as `CommUp` notifications
    /// or via [`RcvInfo::assoc_id`](crate::RcvInfo::assoc_id)).
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        self.inner.listen(backlog)
    }

    /// Accepts one established association as a new one-to-one socket.
    /// One-to-one style only.
    ///
    /// Transient errors (`ECONNABORTED`, `EINTR`) are returned to the
    /// caller; robust accept loops should retry on them.
    pub fn accept(&self) -> io::Result<(SctpSocket, SocketAddr)> {
        let (sock, addr) = self.inner.accept()?;
        Ok((SctpSocket { inner: sock }, addr))
    }

    /// Connects to a single peer address (`connect(2)`).
    pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
        self.inner.connect(addr)
    }

    /// Connects to a multi-homed peer (`sctp_connectx(3)`), returning the new
    /// association's id.
    ///
    /// On a blocking socket this waits for establishment. On a non-blocking
    /// socket it returns immediately (kernel `EINPROGRESS` is treated as
    /// success) and establishment must be observed via the `CommUp`
    /// notification; note that SCTP sockets report writability *during* the
    /// handshake, so TCP-style connect-completion polling does not apply.
    /// The returned id is meaningful on one-to-many sockets; one-to-one
    /// sockets may report 0 until the association is established.
    pub fn connectx(&self, addrs: &[SocketAddr]) -> io::Result<AssocId> {
        self.inner.connectx(addrs)
    }

    // -- data path ----------------------------------------------------------

    /// Sends one message with the given per-message parameters.
    ///
    /// SCTP is message-oriented: the whole buffer is delivered as one
    /// message (never partially written). Messages larger than the send
    /// buffer fail with `EMSGSIZE`.
    pub fn send_msg(&self, buf: &[u8], info: &SendInfo) -> io::Result<usize> {
        self.inner.send_msg(buf, None, info)
    }

    /// Sends one message to an explicit peer address.
    ///
    /// On a one-to-many socket, sending to an address with no existing
    /// association implicitly establishes one. Combine with
    /// [`SendFlags::ADDR_OVER`](crate::SendFlags::ADDR_OVER) to override the
    /// primary path of an existing association.
    pub fn send_msg_to(&self, buf: &[u8], addr: &SocketAddr, info: &SendInfo) -> io::Result<usize> {
        self.inner.send_msg(buf, Some(addr), info)
    }

    /// Receives one message or notification into `buf`.
    ///
    /// Data payloads are written into `buf`; see [`RecvMsg`] for the
    /// returned metadata. Notifications (for subscribed event types) are
    /// parsed and returned as [`RecvMsg::Notification`].
    ///
    /// A return of `RecvMsg::Data { len: 0, info: None, .. }` means the
    /// association was closed by the peer (EOF), like a zero-length
    /// `TcpStream` read. `EINTR` is returned to the caller (retry if
    /// desired), and an elapsed
    /// [`recv_timeout`](Self::set_recv_timeout) surfaces as
    /// [`io::ErrorKind::WouldBlock`]. Concurrent calls from multiple
    /// threads are memory-safe but lose per-stream ordering and can split
    /// partially delivered messages — keep a single reader thread.
    pub fn recv_msg(&self, buf: &mut [u8]) -> io::Result<RecvMsg> {
        let (msg, _) = self.inner.recv_msg(buf, false)?;
        Ok(msg)
    }

    /// Like [`recv_msg`](Self::recv_msg), additionally reporting the peer
    /// address the message arrived from (useful on one-to-many sockets).
    pub fn recv_msg_from(&self, buf: &mut [u8]) -> io::Result<(RecvMsg, Option<SocketAddr>)> {
        self.inner.recv_msg(buf, true)
    }

    // -- socket options ------------------------------------------------------

    /// Moves the socket into or out of non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Subscribes to (or unsubscribes from) a notification class
    /// (`SCTP_EVENT`, kernel 4.11+). Applies to future associations.
    pub fn subscribe_event(&self, event: EventType, on: bool) -> io::Result<()> {
        self.inner.subscribe_event(event, on)
    }

    /// Subscribes to several notification classes at once.
    pub fn subscribe_events(&self, events: &[EventType]) -> io::Result<()> {
        for ev in events {
            self.subscribe_event(*ev, true)?;
        }
        Ok(())
    }

    /// Returns the INIT parameters used for new associations (`SCTP_INITMSG`).
    pub fn init_params(&self) -> io::Result<InitParams> {
        self.inner.init_params()
    }

    /// Sets the INIT parameters (stream counts etc.) for associations
    /// established after this call. Must be called before
    /// `connect`/`connectx` (or on the listening socket) to take effect.
    pub fn set_init_params(&self, params: &InitParams) -> io::Result<()> {
        self.inner.set_init_params(params)
    }

    /// Returns whether Nagle-style bundling delay is disabled (`SCTP_NODELAY`).
    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    /// Disables (or re-enables) Nagle-style bundling delay. Telecom
    /// signaling usually wants `set_nodelay(true)`.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    /// One-to-many only: automatically closes idle associations after
    /// `seconds` (0 disables; `SCTP_AUTOCLOSE`).
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.inner.set_autoclose(seconds)
    }

    /// Returns an association status snapshot (`SCTP_STATUS`), including the
    /// negotiated stream counts and primary path info.
    ///
    /// One-to-one sockets ignore `assoc_id` (pass [`AssocId::FUTURE`]).
    pub fn status(&self, assoc_id: AssocId) -> io::Result<AssocStatus> {
        self.inner.status(assoc_id)
    }

    /// Returns per-path state (reachability, cwnd, srtt, rto, MTU) for one
    /// peer address (`SCTP_GET_PEER_ADDR_INFO`).
    pub fn peer_addr_info(&self, assoc_id: AssocId, addr: &SocketAddr) -> io::Result<PeerAddrInfo> {
        self.inner.peer_addr_info(assoc_id, addr)
    }

    /// Returns the per-path parameters — heartbeat interval, path failure
    /// threshold, PMTU handling (`SCTP_PEER_ADDR_PARAMS`).
    ///
    /// `addr: None` queries the association (or, with [`AssocId::FUTURE`],
    /// endpoint) defaults; `Some(addr)` queries one specific peer address.
    pub fn peer_addr_params(
        &self,
        assoc_id: AssocId,
        addr: Option<&SocketAddr>,
    ) -> io::Result<PeerAddrParams> {
        self.inner.peer_addr_params(assoc_id, addr)
    }

    /// Sets per-path parameters (`SCTP_PEER_ADDR_PARAMS`), e.g. the
    /// heartbeat interval and `path_max_rxt` that drive failover timing on
    /// multi-homed associations. `addr: None` applies to the whole
    /// association / endpoint; see [`PeerAddrParams`] for the semantics of
    /// zero fields and [`SppFlags`](crate::SppFlags).
    pub fn set_peer_addr_params(
        &self,
        assoc_id: AssocId,
        addr: Option<&SocketAddr>,
        params: &PeerAddrParams,
    ) -> io::Result<()> {
        self.inner.set_peer_addr_params(assoc_id, addr, params)
    }

    /// Returns the RTO bounds in milliseconds (`SCTP_RTOINFO`).
    pub fn rto_info(&self, assoc_id: AssocId) -> io::Result<RtoInfo> {
        self.inner.rto_info(assoc_id)
    }

    /// Sets the RTO bounds in milliseconds. Zero fields keep current values.
    pub fn set_rto_info(&self, assoc_id: AssocId, rto: &RtoInfo) -> io::Result<()> {
        self.inner.set_rto_info(assoc_id, rto)
    }

    /// Requests that the given peer address become the primary path
    /// (`SCTP_PRIMARY_ADDR`).
    pub fn set_primary(&self, assoc_id: AssocId, addr: &SocketAddr) -> io::Result<()> {
        self.inner.set_primary(assoc_id, addr)
    }

    /// Returns the send buffer size (`SO_SNDBUF`; kernel reports twice the
    /// set value).
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        self.inner.send_buffer_size()
    }

    /// Sets the send buffer size (`SO_SNDBUF`), capped by `net.core.wmem_max`.
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.set_send_buffer_size(size)
    }

    /// Returns the receive buffer size (`SO_RCVBUF`).
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        self.inner.recv_buffer_size()
    }

    /// Sets the receive buffer size (`SO_RCVBUF`), capped by
    /// `net.core.rmem_max`. Feeds the advertised receiver window (rwnd).
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.set_recv_buffer_size(size)
    }

    /// Sets a timeout for blocking receives (`SO_RCVTIMEO`), for use in
    /// thread-based blocking designs. `None` (the default) blocks forever.
    ///
    /// When the timeout elapses, [`recv_msg`](Self::recv_msg) fails with
    /// [`io::ErrorKind::WouldBlock`]. A zero duration is rejected with
    /// `InvalidInput` (matching `std::net`). Has no effect on a
    /// non-blocking socket, and therefore none on the async tokio types.
    pub fn set_recv_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_recv_timeout(dur)
    }

    /// Returns the blocking receive timeout (`SO_RCVTIMEO`).
    pub fn recv_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.inner.recv_timeout()
    }

    /// Sets a timeout for blocking sends (`SO_SNDTIMEO`); see
    /// [`set_recv_timeout`](Self::set_recv_timeout) for the semantics.
    pub fn set_send_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_send_timeout(dur)
    }

    /// Returns the blocking send timeout (`SO_SNDTIMEO`).
    pub fn send_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.inner.send_timeout()
    }

    /// Returns and clears the pending socket error (`SO_ERROR`); used to
    /// resolve the outcome of a non-blocking connect.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    // -- address queries -----------------------------------------------------

    /// Returns one bound local address (`getsockname(2)`); handy for
    /// discovering the port after binding to port 0. For the full
    /// multi-homing list use [`local_addrs`](Self::local_addrs).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the primary peer address (`getpeername(2)`); one-to-one only.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Returns all bound local addresses (`sctp_getladdrs(3)`).
    pub fn local_addrs(&self, assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
        self.inner.local_addrs(assoc_id)
    }

    /// Returns all peer addresses of an association (`sctp_getpaddrs(3)`).
    pub fn peer_addrs(&self, assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
        self.inner.peer_addrs(assoc_id)
    }

    // -- association management ----------------------------------------------

    /// Detaches one association from a one-to-many socket into its own
    /// one-to-one socket (`sctp_peeloff(3)`).
    pub fn peeloff(&self, assoc_id: AssocId) -> io::Result<SctpSocket> {
        Ok(SctpSocket {
            inner: self.inner.peeloff(assoc_id)?,
        })
    }

    /// Shuts down the association(s) on this socket (`shutdown(2)`).
    ///
    /// `Shutdown::Write` triggers the SCTP graceful shutdown handshake. For
    /// a graceful shutdown of a *single* association on a one-to-many
    /// socket, send with [`SendFlags::EOF`](crate::SendFlags::EOF) instead.
    ///
    /// Note: the *initiator* does not observe handshake completion as a
    /// zero-length read (the kernel grants EOF semantics only to the peer
    /// receiving the SHUTDOWN chunk); subscribe to
    /// [`EventType::AssocChange`] and wait for `ShutdownComplete` instead.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
}

#[cfg(target_os = "linux")]
mod fd_impls {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

    use super::SctpSocket;
    use crate::imp;

    impl AsRawFd for SctpSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }

    impl IntoRawFd for SctpSocket {
        fn into_raw_fd(self) -> RawFd {
            self.inner.into_raw_fd()
        }
    }

    impl FromRawFd for SctpSocket {
        /// # Safety
        ///
        /// `fd` must be an open SCTP socket owned by the caller. Note that
        /// `SCTP_RECVRCVINFO` is *not* enabled here — call
        /// [`SctpSocket::subscribe_event`]-style setup yourself, or expect
        /// [`RecvMsg::Data`](crate::RecvMsg) with `info: None`.
        unsafe fn from_raw_fd(fd: RawFd) -> SctpSocket {
            SctpSocket {
                inner: unsafe { imp::Socket::from_raw_fd(fd) },
            }
        }
    }
}
