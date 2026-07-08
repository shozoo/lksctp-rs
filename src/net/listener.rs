//! One-to-one style async listener: [`SctpListener`].

use std::io;
use std::net::SocketAddr;

use crate::EventType;
use crate::net::common::{self, Io};
use crate::net::stream::SctpStream;
use crate::socket::SctpSocket;
use crate::types::{Family, InitParams, Style};

/// A one-to-one (`SOCK_STREAM`) SCTP listener, integrated with the tokio
/// reactor — the SCTP counterpart of [`tokio::net::TcpListener`].
///
/// Options set on the listener via [`ListenerBuilder`] (INIT parameters,
/// event subscriptions, ...) apply to accepted associations.
#[derive(Debug)]
pub struct SctpListener {
    io: Io,
}

impl SctpListener {
    /// Listens on a single address with default parameters and a backlog of
    /// 128. See [`ListenerBuilder`] for multi-homing and tuning.
    pub fn bind(addr: SocketAddr) -> io::Result<SctpListener> {
        let family = if addr.is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        };
        SctpListener::builder(family)?.bindx(&[addr])?.listen(128)
    }

    /// Starts building a listener.
    pub fn builder(family: Family) -> io::Result<ListenerBuilder> {
        Ok(ListenerBuilder {
            sock: SctpSocket::new(family, Style::OneToOne)?,
        })
    }

    /// Accepts the next established association.
    pub async fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        let (sock, peer) = common::read_op(&self.io, |s| s.accept()).await?;
        Ok((SctpStream::from_imp(sock)?, peer))
    }
}

common::impl_common_sockopts!(SctpListener);

/// Builder for [`SctpListener`].
#[derive(Debug)]
pub struct ListenerBuilder {
    sock: SctpSocket,
}

impl ListenerBuilder {
    /// Binds local addresses (all sharing one port) for a multi-homed
    /// endpoint.
    pub fn bindx(self, addrs: &[SocketAddr]) -> io::Result<ListenerBuilder> {
        self.sock.bindx_add(addrs)?;
        Ok(self)
    }

    /// Sets the INIT parameters applied to accepted associations.
    pub fn init_params(self, params: &InitParams) -> io::Result<ListenerBuilder> {
        self.sock.set_init_params(params)?;
        Ok(self)
    }

    /// Subscribes accepted associations to notification classes.
    pub fn subscribe_events(self, events: &[EventType]) -> io::Result<ListenerBuilder> {
        self.sock.subscribe_events(events)?;
        Ok(self)
    }

    /// Sets the receive buffer size (`SO_RCVBUF`) for the listening socket.
    pub fn recv_buffer_size(self, size: usize) -> io::Result<ListenerBuilder> {
        self.sock.set_recv_buffer_size(size)?;
        Ok(self)
    }

    /// Starts listening and registers with the tokio reactor.
    pub fn listen(self, backlog: i32) -> io::Result<SctpListener> {
        self.sock.listen(backlog)?;
        Ok(SctpListener {
            io: common::register(self.sock.inner)?,
        })
    }
}
