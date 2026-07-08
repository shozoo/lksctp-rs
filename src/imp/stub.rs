//! Stub implementation for non-Linux platforms (mio `sys/shell` style).
//!
//! Every constructor returns `ErrorKind::Unsupported`, so a `Socket` value
//! can never exist off-Linux; the uninhabited enum makes the remaining
//! method bodies trivially unreachable while keeping signatures identical
//! to the Linux implementation.

use std::io;
use std::net::{Shutdown, SocketAddr};

use crate::types::{
    AssocId, AssocStatus, EventType, Family, InitParams, PeerAddrInfo, PeerAddrParams, RecvMsg,
    RtoInfo, SendInfo, Style,
};

pub(crate) enum Socket {}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "SCTP sockets are only supported on Linux",
    )
}

impl Socket {
    pub(crate) fn new(_family: Family, _style: Style) -> io::Result<Socket> {
        Err(unsupported())
    }

    pub(crate) fn bind(&self, _addr: &SocketAddr) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn bindx_add(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn bindx_remove(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn listen(&self, _backlog: i32) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        match *self {}
    }

    pub(crate) fn connect(&self, _addr: &SocketAddr) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn connectx(&self, _addrs: &[SocketAddr]) -> io::Result<AssocId> {
        match *self {}
    }

    pub(crate) fn send_msg(
        &self,
        _buf: &[u8],
        _dest: Option<&SocketAddr>,
        _info: &SendInfo,
    ) -> io::Result<usize> {
        match *self {}
    }

    pub(crate) fn recv_msg(
        &self,
        _buf: &mut [u8],
        _want_from: bool,
    ) -> io::Result<(RecvMsg, Option<SocketAddr>)> {
        match *self {}
    }

    pub(crate) fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn subscribe_event(&self, _event: EventType, _on: bool) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn init_params(&self) -> io::Result<InitParams> {
        match *self {}
    }

    pub(crate) fn set_init_params(&self, _params: &InitParams) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn nodelay(&self) -> io::Result<bool> {
        match *self {}
    }

    pub(crate) fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn set_autoclose(&self, _seconds: u32) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn status(&self, _assoc_id: AssocId) -> io::Result<AssocStatus> {
        match *self {}
    }

    pub(crate) fn peer_addr_info(
        &self,
        _assoc_id: AssocId,
        _addr: &SocketAddr,
    ) -> io::Result<PeerAddrInfo> {
        match *self {}
    }

    pub(crate) fn peer_addr_params(
        &self,
        _assoc_id: AssocId,
        _addr: Option<&SocketAddr>,
    ) -> io::Result<PeerAddrParams> {
        match *self {}
    }

    pub(crate) fn set_peer_addr_params(
        &self,
        _assoc_id: AssocId,
        _addr: Option<&SocketAddr>,
        _params: &PeerAddrParams,
    ) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn rto_info(&self, _assoc_id: AssocId) -> io::Result<RtoInfo> {
        match *self {}
    }

    pub(crate) fn set_rto_info(&self, _assoc_id: AssocId, _rto: &RtoInfo) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn set_primary(&self, _assoc_id: AssocId, _addr: &SocketAddr) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn send_buffer_size(&self) -> io::Result<usize> {
        match *self {}
    }

    pub(crate) fn set_send_buffer_size(&self, _size: usize) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn recv_buffer_size(&self) -> io::Result<usize> {
        match *self {}
    }

    pub(crate) fn set_recv_buffer_size(&self, _size: usize) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn set_recv_timeout(&self, _dur: Option<std::time::Duration>) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn recv_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        match *self {}
    }

    pub(crate) fn set_send_timeout(&self, _dur: Option<std::time::Duration>) -> io::Result<()> {
        match *self {}
    }

    pub(crate) fn send_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        match *self {}
    }

    pub(crate) fn take_error(&self) -> io::Result<Option<io::Error>> {
        match *self {}
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {}
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match *self {}
    }

    pub(crate) fn local_addrs(&self, _assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
        match *self {}
    }

    pub(crate) fn peer_addrs(&self, _assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
        match *self {}
    }

    pub(crate) fn peeloff(&self, _assoc_id: AssocId) -> io::Result<Socket> {
        match *self {}
    }

    pub(crate) fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        match *self {}
    }
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}
