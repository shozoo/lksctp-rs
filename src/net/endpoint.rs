//! One-to-many style async socket: [`SctpEndpoint`].

use std::io;
use std::net::{Shutdown, SocketAddr};

use crate::EventType;
use crate::net::common::{self, Io};
use crate::net::stream::SctpStream;
use crate::socket::SctpSocket;
use crate::types::{AssocId, Family, InitParams, RecvMsg, SendInfo, Style};

/// A one-to-many (`SOCK_SEQPACKET`) SCTP socket carrying multiple
/// associations, integrated with the tokio reactor.
///
/// Usage resembles [`tokio::net::UdpSocket`], with [`AssocId`] taking the
/// role addresses play for UDP. A single endpoint can simultaneously act as
/// a server (after [`EndpointBuilder::listen`], inbound associations are
/// established by the kernel and announced via `CommUp` notifications) and as
/// a client ([`connectx`](Self::connectx) or implicit setup by sending to a
/// new address) — the M3UA-style symmetric deployment maps directly onto this.
///
/// There is no `accept`: learn about new associations from
/// [`Notification::AssocChange`](crate::Notification::AssocChange) or from
/// [`RcvInfo::assoc_id`](crate::RcvInfo::assoc_id), and detach one into an
/// [`SctpStream`] with [`peeloff`](Self::peeloff) if desired.
#[derive(Debug)]
pub struct SctpEndpoint {
    io: Io,
}

impl SctpEndpoint {
    /// Registers an existing one-to-many socket with Tokio.
    pub fn from_socket(sock: SctpSocket) -> io::Result<SctpEndpoint> {
        if sock.inner.style()? != Style::OneToMany {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket is not one-to-many",
            ));
        }
        Ok(SctpEndpoint {
            io: common::register(sock.inner)?,
        })
    }
    /// Binds a listening endpoint on one address with default parameters
    /// and a backlog of 128. See [`EndpointBuilder`] for more control.
    pub fn bind(addr: SocketAddr) -> io::Result<SctpEndpoint> {
        let family = if addr.is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        };
        SctpEndpoint::builder(family)?.bindx(&[addr])?.listen(128)
    }

    /// Starts building an endpoint.
    pub fn builder(family: Family) -> io::Result<EndpointBuilder> {
        Ok(EndpointBuilder {
            sock: SctpSocket::new(family, Style::OneToMany)?,
        })
    }

    /// Initiates an association to a (possibly multi-homed) peer, returning
    /// its id immediately.
    ///
    /// Establishment completes in the background: success is announced by a
    /// `CommUp` [`AssocChange`](crate::AssocChange) notification carrying
    /// the same id (subscribe to [`EventType::AssocChange`] first), failure
    /// by `CantStartAssoc`.
    pub fn connectx(&self, addrs: &[SocketAddr]) -> io::Result<AssocId> {
        common::sock(&self.io).connectx(addrs)
    }

    /// Sends one message on an existing association selected by
    /// [`SendInfo::assoc_id`].
    /// Cancellation is safe: a send syscall completes without suspending
    /// the future.
    pub async fn send_msg(&self, buf: &[u8], info: &SendInfo) -> io::Result<usize> {
        common::write_op(&self.io, |s| s.send_msg(buf, None, info)).await
    }

    /// Sends one message to an explicit peer address.
    ///
    /// Sending to an address with no existing association implicitly
    /// establishes one (`CommUp` follows if subscribed). With
    /// [`SendFlags::ADDR_OVER`](crate::SendFlags::ADDR_OVER) the address
    /// overrides the primary path of the existing association.
    /// Cancellation is safe: a send syscall completes without suspending
    /// the future.
    pub async fn send_msg_to(
        &self,
        buf: &[u8],
        addr: &SocketAddr,
        info: &SendInfo,
    ) -> io::Result<usize> {
        common::write_op(&self.io, |s| s.send_msg(buf, Some(addr), info)).await
    }

    /// Receives the next message or notification into `buf`.
    ///
    /// As with [`SctpStream::recv_msg`], concurrent calls from multiple
    /// tasks are memory-safe but make per-stream ordering nondeterministic
    /// and can split partially delivered messages across readers — keep a
    /// single reader task per endpoint.
    /// Cancellation is safe: each receive attempt completes without
    /// suspending the future.
    pub async fn recv_msg(&self, buf: &mut [u8]) -> io::Result<RecvMsg> {
        common::read_op(&self.io, |s| s.recv_msg(buf, false).map(|(m, _)| m)).await
    }

    /// Like [`recv_msg`](Self::recv_msg), additionally reporting the peer
    /// address the message arrived from.
    /// Cancellation is safe: each receive attempt completes without
    /// suspending the future.
    pub async fn recv_msg_from(&self, buf: &mut [u8]) -> io::Result<(RecvMsg, Option<SocketAddr>)> {
        common::read_op(&self.io, |s| s.recv_msg(buf, true)).await
    }

    /// Detaches one association into its own one-to-one [`SctpStream`]
    /// (`sctp_peeloff(3)`). The endpoint keeps serving its remaining
    /// associations.
    pub fn peeloff(&self, assoc_id: AssocId) -> io::Result<SctpStream> {
        SctpStream::from_nonblocking_imp(common::sock(&self.io).peeloff_nonblocking(assoc_id)?)
    }

    /// One-to-many only: automatically closes idle associations after
    /// `seconds` (0 disables; `SCTP_AUTOCLOSE`).
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        common::sock(&self.io).set_autoclose(seconds)
    }

    /// Returns [`io::ErrorKind::Unsupported`]: `shutdown(2)` has no SCTP
    /// effect on one-to-many sockets. Send with
    /// [`SendFlags::EOF`](crate::SendFlags::EOF) to gracefully shut down one
    /// association, or drop the endpoint to close all associations.
    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shutdown(2) does not close one-to-many SCTP associations; use SCTP_EOF or drop the endpoint",
        ))
    }
}

common::impl_common_sockopts!(SctpEndpoint);

/// Builder for [`SctpEndpoint`].
#[derive(Debug)]
pub struct EndpointBuilder {
    sock: SctpSocket,
}

impl EndpointBuilder {
    /// Binds local addresses (all sharing one port) for a multi-homed
    /// endpoint.
    pub fn bindx(self, addrs: &[SocketAddr]) -> io::Result<EndpointBuilder> {
        self.sock.bindx_add(addrs)?;
        Ok(self)
    }

    /// Sets the default INIT parameters for associations on this endpoint.
    pub fn init_params(self, params: &InitParams) -> io::Result<EndpointBuilder> {
        self.sock.set_init_params(params)?;
        Ok(self)
    }

    /// Subscribes to notification classes before any association exists.
    /// One-to-many workflows almost always want at least
    /// [`EventType::AssocChange`].
    pub fn subscribe_events(self, events: &[EventType]) -> io::Result<EndpointBuilder> {
        self.sock.subscribe_events(events)?;
        Ok(self)
    }

    /// Disables Nagle-style bundling delay.
    pub fn nodelay(self, nodelay: bool) -> io::Result<EndpointBuilder> {
        self.sock.set_nodelay(nodelay)?;
        Ok(self)
    }

    /// Sets the send buffer size (`SO_SNDBUF`).
    pub fn send_buffer_size(self, size: usize) -> io::Result<EndpointBuilder> {
        self.sock.set_send_buffer_size(size)?;
        Ok(self)
    }

    /// Sets the receive buffer size (`SO_RCVBUF`).
    pub fn recv_buffer_size(self, size: usize) -> io::Result<EndpointBuilder> {
        self.sock.set_recv_buffer_size(size)?;
        Ok(self)
    }

    /// Sets `SO_REUSEADDR` before binding.
    pub fn reuse_address(self, enabled: bool) -> io::Result<EndpointBuilder> {
        self.sock.set_reuse_address(enabled)?;
        Ok(self)
    }

    /// Finishes as a listening endpoint: inbound associations are accepted
    /// (and outbound ones can still be initiated).
    pub fn listen(self, backlog: i32) -> io::Result<SctpEndpoint> {
        self.sock.listen(backlog)?;
        self.build()
    }

    /// Finishes as a client-only endpoint (no inbound associations).
    pub fn build(self) -> io::Result<SctpEndpoint> {
        SctpEndpoint::from_socket(self.sock)
    }
}
