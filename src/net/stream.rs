//! One-to-one style async socket: [`SctpStream`].

use std::io;
use std::net::{Shutdown, SocketAddr};

use crate::net::common::{self, Io};
use crate::socket::SctpSocket;
use crate::types::{Family, InitParams, RecvMsg, SendInfo, Style};
use crate::{EventType, imp};

/// An established one-to-one (`SOCK_STREAM`) SCTP association, integrated
/// with the tokio reactor.
///
/// The message-oriented sibling of [`tokio::net::TcpStream`]: obtained
/// either from [`SctpListener::accept`](crate::SctpListener::accept), from
/// [`SctpStream::connect`]/[`connectx`](StreamBuilder::connectx), or by
/// peeling an association off a one-to-many
/// [`SctpEndpoint`](crate::SctpEndpoint). Once established, both sides are
/// symmetric peers with identical capabilities regardless of who initiated.
///
/// All methods take `&self`; wrap the stream in an `Arc` to read and write
/// concurrently from different tasks. Sharing one *reader* and one *writer*
/// task is the intended pattern; see [`recv_msg`](Self::recv_msg) for why
/// multiple concurrent readers are discouraged.
#[derive(Debug)]
pub struct SctpStream {
    pub(crate) io: Io,
}

impl SctpStream {
    /// Connects to a peer with default parameters. See [`StreamBuilder`]
    /// for local binding, INIT parameters, and multi-homed connects.
    pub async fn connect(addr: SocketAddr) -> io::Result<SctpStream> {
        let family = if addr.is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        };
        SctpStream::builder(family)?.connectx(&[addr]).await
    }

    /// Starts building a client socket (set options, bind, then connect).
    pub fn builder(family: Family) -> io::Result<StreamBuilder> {
        Ok(StreamBuilder {
            sock: SctpSocket::new(family, Style::OneToOne)?,
            assoc_change_subscribed: false,
        })
    }

    pub(crate) fn from_imp(sock: imp::Socket) -> io::Result<SctpStream> {
        Ok(SctpStream {
            io: common::register(sock)?,
        })
    }

    /// Sends one message with the given per-message parameters, waiting for
    /// send buffer space if necessary.
    ///
    /// SCTP is message-oriented: the buffer is delivered as a single message
    /// (no partial writes). Messages larger than the send buffer fail with
    /// `EMSGSIZE`.
    pub async fn send_msg(&self, buf: &[u8], info: &SendInfo) -> io::Result<usize> {
        common::write_op(&self.io, |s| s.send_msg(buf, None, info)).await
    }

    /// Receives the next message or notification into `buf`.
    ///
    /// Notifications arrive only for subscribed event types (see
    /// [`subscribe_events`](Self::subscribe_events)).
    ///
    /// Calling this concurrently from multiple tasks is memory-safe and each
    /// call receives a whole message, but which task gets which message is
    /// nondeterministic: per-stream ordering is lost from the application's
    /// point of view, and partially delivered messages (`eor: false`) can
    /// have their fragments split across readers. Keep a single reader task
    /// and distribute parsed messages through channels instead.
    pub async fn recv_msg(&self, buf: &mut [u8]) -> io::Result<RecvMsg> {
        common::read_op(&self.io, |s| s.recv_msg(buf, false).map(|(m, _)| m)).await
    }

    /// Returns the primary peer address (`getpeername(2)`).
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        common::sock(&self.io).peer_addr()
    }

    /// Shuts down the association. `Shutdown::Write` starts the SCTP
    /// graceful shutdown handshake.
    ///
    /// Note: the *initiator* does not observe handshake completion as a
    /// zero-length read — the kernel grants EOF semantics only to the peer
    /// that *receives* the SHUTDOWN chunk. To learn when the shutdown
    /// completes, subscribe to [`EventType::AssocChange`](crate::EventType)
    /// before connecting and wait for
    /// [`AssocChangeState::ShutdownComplete`](crate::AssocChangeState), or
    /// simply drop the stream.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        common::sock(&self.io).shutdown(how)
    }
}

common::impl_common_sockopts!(SctpStream);

/// Builder for outbound [`SctpStream`] connections.
///
/// Options that must precede association setup (INIT parameters, local
/// multi-homing, event subscriptions) are set here, then consumed by
/// [`connectx`](Self::connectx).
#[derive(Debug)]
pub struct StreamBuilder {
    sock: SctpSocket,
    /// Whether the caller subscribed to AssocChange themselves; connectx
    /// needs the subscription either way and must know whether to keep it.
    assoc_change_subscribed: bool,
}

impl StreamBuilder {
    /// Binds local addresses (multi-homing and/or a fixed source port).
    pub fn bindx(self, addrs: &[SocketAddr]) -> io::Result<StreamBuilder> {
        self.sock.bindx_add(addrs)?;
        Ok(self)
    }

    /// Sets the INIT parameters (stream counts etc.) for the association.
    pub fn init_params(self, params: &InitParams) -> io::Result<StreamBuilder> {
        self.sock.set_init_params(params)?;
        Ok(self)
    }

    /// Subscribes to notification classes before the association exists, so
    /// no early event is missed.
    pub fn subscribe_events(mut self, events: &[EventType]) -> io::Result<StreamBuilder> {
        self.sock.subscribe_events(events)?;
        if events.contains(&EventType::AssocChange) {
            self.assoc_change_subscribed = true;
        }
        Ok(self)
    }

    /// Disables Nagle-style bundling delay from the start.
    pub fn nodelay(self, nodelay: bool) -> io::Result<StreamBuilder> {
        self.sock.set_nodelay(nodelay)?;
        Ok(self)
    }

    /// Sets the send buffer size (`SO_SNDBUF`).
    pub fn send_buffer_size(self, size: usize) -> io::Result<StreamBuilder> {
        self.sock.set_send_buffer_size(size)?;
        Ok(self)
    }

    /// Sets the receive buffer size (`SO_RCVBUF`).
    pub fn recv_buffer_size(self, size: usize) -> io::Result<StreamBuilder> {
        self.sock.set_recv_buffer_size(size)?;
        Ok(self)
    }

    /// Connects to a (possibly multi-homed) peer and waits for the
    /// association to be fully established.
    ///
    /// Establishment is observed via the `SCTP_COMM_UP` notification (SCTP
    /// sockets report writability during the handshake, so the TCP
    /// "writable = connected" idiom does not apply). Consequences:
    /// - the initial `AssocChange(CommUp)` is consumed here and not
    ///   redelivered, even with [`EventType::AssocChange`] subscribed;
    /// - other notifications arriving before establishment are discarded.
    pub async fn connectx(self, addrs: &[SocketAddr]) -> io::Result<SctpStream> {
        // Establishment/failure is observed through AssocChange; subscribe
        // temporarily if the caller has not.
        if !self.assoc_change_subscribed {
            self.sock.subscribe_event(EventType::AssocChange, true)?;
        }
        let io = common::register(self.sock.inner)?;
        // Non-blocking connectx reports EINPROGRESS, mapped to Ok here.
        common::sock(&io).connectx(addrs)?;
        common::established(&io).await?;
        if !self.assoc_change_subscribed {
            common::sock(&io).subscribe_event(EventType::AssocChange, false)?;
        }
        Ok(SctpStream { io })
    }
}
