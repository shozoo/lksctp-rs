//! Linux implementation of the socket operations, calling into the kernel
//! directly via libc syscall wrappers. No lksctp-tools (libsctp) involved.

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use crate::addr;
use crate::cmsg;
use crate::notification;
use crate::sys;
use crate::types::{
    AssocId, AssocStatus, EventType, Family, InitParams, PeerAddrInfo, PeerAddrParams, RcvInfo,
    RecvMsg, RtoInfo, SendInfo, Style,
};

pub(crate) struct Socket {
    fd: OwnedFd,
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn cvt_size(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Control buffer for sending one SCTP_SNDINFO cmsg.
const SND_CMSG_SPACE: usize = cmsg::space(size_of::<sys::sctp_sndinfo>());

/// Received control messages: room for SCTP_RCVINFO plus slack for
/// SCTP_NXTINFO or anything else the kernel decides to attach.
const RCV_CMSG_SPACE: usize = 192;

/// Keeps stack cmsg buffers safely aligned for the kernel's cmsghdr writes.
#[repr(C, align(8))]
struct CmsgBuf<const N: usize>([u8; N]);

/// Packs `addr` into a kernel sockaddr_storage; zeroed when `None`
/// (meaning "association/endpoint default" for per-address sockopts).
fn pack_optional_addr(addr: Option<&SocketAddr>) -> sys::sockaddr_storage {
    let mut storage = sys::sockaddr_storage::zeroed();
    if let Some(a) = addr {
        addr::write_sockaddr(a, &mut storage.bytes);
    }
    storage
}

impl Socket {
    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(crate) fn new(family: Family, style: Style) -> io::Result<Socket> {
        let domain = match family {
            Family::Ipv4 => libc::AF_INET,
            Family::Ipv6 => libc::AF_INET6,
        };
        let ty = match style {
            Style::OneToOne => libc::SOCK_STREAM,
            Style::OneToMany => libc::SOCK_SEQPACKET,
        };
        let fd = cvt(unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, sys::IPPROTO_SCTP) })?;
        let sock = Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        sock.enable_rcvinfo()?;
        Ok(sock)
    }

    /// recv_msg() relies on the SCTP_RCVINFO cmsg; enabled on every socket
    /// this crate creates or obtains (accept/peeloff).
    fn enable_rcvinfo(&self) -> io::Result<()> {
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_RECVRCVINFO, &1i32)
    }

    // -- generic sockopt plumbing ------------------------------------------

    fn setsockopt<T>(&self, level: i32, opt: i32, val: &T) -> io::Result<()> {
        cvt(unsafe {
            libc::setsockopt(
                self.raw(),
                level,
                opt,
                val as *const T as *const libc::c_void,
                size_of::<T>() as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    fn getsockopt<T: Copy>(&self, level: i32, opt: i32) -> io::Result<T> {
        let mut val = MaybeUninit::<T>::zeroed();
        let mut len = size_of::<T>() as libc::socklen_t;
        cvt(unsafe {
            libc::getsockopt(
                self.raw(),
                level,
                opt,
                val.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        })?;
        // SAFETY: zero-initialized and (partially) overwritten by the kernel;
        // all T used here are plain-old-data for which any bytes are valid.
        Ok(unsafe { val.assume_init() })
    }

    /// getsockopt variant where fields of `val` are kernel inputs
    /// (e.g. `sstat_assoc_id` for SCTP_STATUS).
    fn getsockopt_inout<T>(&self, level: i32, opt: i32, val: &mut T) -> io::Result<()> {
        let mut len = size_of::<T>() as libc::socklen_t;
        cvt(unsafe {
            libc::getsockopt(
                self.raw(),
                level,
                opt,
                val as *mut T as *mut libc::c_void,
                &mut len,
            )
        })?;
        Ok(())
    }

    // -- addresses / connection setup --------------------------------------

    pub(crate) fn bind(&self, addr: &SocketAddr) -> io::Result<()> {
        let mut storage = [0u8; 128];
        let len = addr::write_sockaddr(addr, &mut storage);
        cvt(unsafe {
            libc::bind(
                self.raw(),
                storage.as_ptr() as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    fn bindx(&self, addrs: &[SocketAddr], opt: i32) -> io::Result<()> {
        let packed = addr::pack_addr_list(addrs);
        cvt(unsafe {
            libc::setsockopt(
                self.raw(),
                sys::SOL_SCTP,
                opt,
                packed.as_ptr() as *const libc::c_void,
                packed.len() as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    pub(crate) fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.bindx(addrs, sys::SCTP_SOCKOPT_BINDX_ADD)
    }

    pub(crate) fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.bindx(addrs, sys::SCTP_SOCKOPT_BINDX_REM)
    }

    pub(crate) fn listen(&self, backlog: i32) -> io::Result<()> {
        cvt(unsafe { libc::listen(self.raw(), backlog) })?;
        Ok(())
    }

    pub(crate) fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        let mut storage = [0u8; 128];
        let mut len = storage.len() as libc::socklen_t;
        let fd = cvt(unsafe {
            libc::accept4(
                self.raw(),
                storage.as_mut_ptr() as *mut libc::sockaddr,
                &mut len,
                libc::SOCK_CLOEXEC,
            )
        })?;
        let sock = Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        // Not all options are inherited across accept; re-enable explicitly.
        sock.enable_rcvinfo()?;
        let peer = addr::read_sockaddr(&storage[..len as usize])
            .map(|(a, _)| a)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad peer sockaddr"))?;
        Ok((sock, peer))
    }

    pub(crate) fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
        let mut storage = [0u8; 128];
        let len = addr::write_sockaddr(addr, &mut storage);
        cvt(unsafe {
            libc::connect(
                self.raw(),
                storage.as_ptr() as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    /// `sctp_connectx()` via SCTP_SOCKOPT_CONNECTX3.
    ///
    /// Returns the new association id. On a non-blocking socket the kernel
    /// reports `EINPROGRESS`; the id is still valid, so that case is also
    /// returned as success (establishment completes asynchronously and is
    /// observed via writability / `SCTP_COMM_UP`).
    pub(crate) fn connectx(&self, addrs: &[SocketAddr]) -> io::Result<AssocId> {
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no addresses"));
        }
        let mut packed = addr::pack_addr_list(addrs);
        let mut param = sys::sctp_getaddrs_old {
            assoc_id: 0,
            addr_num: packed.len() as i32,
            addrs: packed.as_mut_ptr(),
        };
        let mut len = size_of::<sys::sctp_getaddrs_old>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                self.raw(),
                sys::SOL_SCTP,
                sys::SCTP_SOCKOPT_CONNECTX3,
                &mut param as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret == 0 {
            return Ok(AssocId(param.assoc_id));
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINPROGRESS) {
            Ok(AssocId(param.assoc_id))
        } else {
            Err(e)
        }
    }

    // -- data path ----------------------------------------------------------

    pub(crate) fn send_msg(
        &self,
        buf: &[u8],
        dest: Option<&SocketAddr>,
        info: &SendInfo,
    ) -> io::Result<usize> {
        let sndinfo = info.to_sys();
        let sndinfo_bytes: [u8; size_of::<sys::sctp_sndinfo>()] =
            unsafe { mem::transmute(sndinfo) };
        let mut control = CmsgBuf([0u8; SND_CMSG_SPACE]);
        let clen = cmsg::write(
            &mut control.0,
            sys::IPPROTO_SCTP,
            sys::SCTP_CMSG_SNDINFO,
            &sndinfo_bytes,
        );

        let mut name = [0u8; 128];
        let (name_ptr, name_len) = match dest {
            Some(a) => {
                let n = addr::write_sockaddr(a, &mut name);
                (name.as_mut_ptr() as *mut libc::c_void, n as libc::socklen_t)
            }
            None => (std::ptr::null_mut(), 0),
        };

        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = name_ptr;
        msg.msg_namelen = name_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = clen as _;

        // MSG_NOSIGNAL: report EPIPE instead of raising SIGPIPE.
        cvt_size(unsafe { libc::sendmsg(self.raw(), &msg, libc::MSG_NOSIGNAL) })
    }

    pub(crate) fn recv_msg(
        &self,
        buf: &mut [u8],
        want_from: bool,
    ) -> io::Result<(RecvMsg, Option<SocketAddr>)> {
        let mut name = [0u8; 128];
        let mut control = CmsgBuf([0u8; RCV_CMSG_SPACE]);

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        if want_from {
            msg.msg_name = name.as_mut_ptr() as *mut libc::c_void;
            msg.msg_namelen = name.len() as libc::socklen_t;
        }
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = RCV_CMSG_SPACE as _;

        let n = cvt_size(unsafe { libc::recvmsg(self.raw(), &mut msg, 0) })?;
        let flags = msg.msg_flags;
        let eor = flags & sys::MSG_EOR != 0;

        let from = if want_from && msg.msg_namelen > 0 {
            addr::read_sockaddr(&name[..msg.msg_namelen as usize]).map(|(a, _)| a)
        } else {
            None
        };

        if flags & sys::MSG_NOTIFICATION != 0 {
            if !eor {
                // The notification did not fit the caller's buffer.
                // Reassemble the rest here: simply erroring out would leave
                // the remainder queued in the kernel, and the next receive
                // would misparse notification *tail bytes* (which a peer can
                // influence, e.g. via a large ERROR chunk) as a fresh
                // notification, permanently desynchronizing the stream.
                let assembled = self.reassemble_notification(&buf[..n])?;
                let parsed = notification::parse(&assembled)?;
                return Ok((RecvMsg::Notification(parsed), from));
            }
            let parsed = notification::parse(&buf[..n])?;
            return Ok((RecvMsg::Notification(parsed), from));
        }

        let mut info = None;
        let controllen = msg.msg_controllen as usize;
        for (level, ty, data) in cmsg::iter(&control.0[..controllen]) {
            if level == sys::IPPROTO_SCTP
                && ty == sys::SCTP_CMSG_RCVINFO
                && data.len() >= size_of::<sys::sctp_rcvinfo>()
            {
                let raw: sys::sctp_rcvinfo =
                    unsafe { std::ptr::read_unaligned(data.as_ptr() as *const sys::sctp_rcvinfo) };
                info = Some(RcvInfo::from_sys(&raw));
            }
        }

        Ok((RecvMsg::Data { len: n, info, eor }, from))
    }

    /// Reads the remaining fragments of a partially delivered notification.
    ///
    /// The kernel keeps the rest of a partially consumed message at the head
    /// of the receive queue, readable immediately — so this loop cannot
    /// block (or return `WouldBlock` on a non-blocking socket) before
    /// reaching `MSG_EOR`. Growth is capped; an absurdly large notification
    /// is drained and reported as an error instead of buffered.
    fn reassemble_notification(&self, first: &[u8]) -> io::Result<Vec<u8>> {
        const MAX_NOTIFICATION: usize = 1 << 20;
        let mut out = first.to_vec();
        let mut oversized = false;
        let mut scratch = [0u8; 4096];
        loop {
            let mut iov = libc::iovec {
                iov_base: scratch.as_mut_ptr() as *mut libc::c_void,
                iov_len: scratch.len(),
            };
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let n = cvt_size(unsafe { libc::recvmsg(self.raw(), &mut msg, 0) })?;
            if msg.msg_flags & sys::MSG_NOTIFICATION == 0 {
                // Should be impossible; refuse to mix user data into a
                // notification rather than corrupt both streams.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sctp notification reassembly desynchronized",
                ));
            }
            if out.len() + n > MAX_NOTIFICATION {
                oversized = true;
            } else {
                out.extend_from_slice(&scratch[..n]);
            }
            if msg.msg_flags & sys::MSG_EOR != 0 {
                return if oversized {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sctp notification larger than 1 MiB discarded",
                    ))
                } else {
                    Ok(out)
                };
            }
        }
    }

    // -- socket options ------------------------------------------------------

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = cvt(unsafe { libc::fcntl(self.raw(), libc::F_GETFL) })?;
        let new = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if new != flags {
            cvt(unsafe { libc::fcntl(self.raw(), libc::F_SETFL, new) })?;
        }
        Ok(())
    }

    pub(crate) fn subscribe_event(&self, event: EventType, on: bool) -> io::Result<()> {
        let ev = sys::sctp_event {
            se_assoc_id: sys::SCTP_FUTURE_ASSOC,
            se_type: event.to_raw(),
            se_on: on as u8,
        };
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_EVENT, &ev)
    }

    pub(crate) fn init_params(&self) -> io::Result<InitParams> {
        let raw: sys::sctp_initmsg = self.getsockopt(sys::SOL_SCTP, sys::SCTP_INITMSG)?;
        Ok(InitParams::from_sys(&raw))
    }

    pub(crate) fn set_init_params(&self, params: &InitParams) -> io::Result<()> {
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_INITMSG, &params.to_sys())
    }

    pub(crate) fn nodelay(&self) -> io::Result<bool> {
        let v: i32 = self.getsockopt(sys::SOL_SCTP, sys::SCTP_NODELAY)?;
        Ok(v != 0)
    }

    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_NODELAY, &(nodelay as i32))
    }

    pub(crate) fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_AUTOCLOSE, &seconds)
    }

    pub(crate) fn status(&self, assoc_id: AssocId) -> io::Result<AssocStatus> {
        let mut raw = sys::sctp_status {
            sstat_assoc_id: assoc_id.0,
            ..Default::default()
        };
        self.getsockopt_inout(sys::SOL_SCTP, sys::SCTP_STATUS, &mut raw)?;
        Ok(AssocStatus::from_sys(&raw))
    }

    pub(crate) fn peer_addr_info(
        &self,
        assoc_id: AssocId,
        addr: &SocketAddr,
    ) -> io::Result<PeerAddrInfo> {
        let mut storage = sys::sockaddr_storage::zeroed();
        addr::write_sockaddr(addr, &mut storage.bytes);
        let mut raw = sys::sctp_paddrinfo {
            spinfo_assoc_id: assoc_id.0,
            spinfo_address: storage,
            ..Default::default()
        };
        self.getsockopt_inout(sys::SOL_SCTP, sys::SCTP_GET_PEER_ADDR_INFO, &mut raw)?;
        Ok(PeerAddrInfo::from_sys(&raw))
    }

    pub(crate) fn peer_addr_params(
        &self,
        assoc_id: AssocId,
        addr: Option<&SocketAddr>,
    ) -> io::Result<PeerAddrParams> {
        let mut raw = sys::sctp_paddrparams {
            spp_assoc_id: assoc_id.0,
            spp_address: pack_optional_addr(addr),
            ..Default::default()
        };
        self.getsockopt_inout(sys::SOL_SCTP, sys::SCTP_PEER_ADDR_PARAMS, &mut raw)?;
        Ok(PeerAddrParams::from_sys(&raw))
    }

    pub(crate) fn set_peer_addr_params(
        &self,
        assoc_id: AssocId,
        addr: Option<&SocketAddr>,
        params: &PeerAddrParams,
    ) -> io::Result<()> {
        let raw = sys::sctp_paddrparams {
            spp_assoc_id: assoc_id.0,
            spp_address: pack_optional_addr(addr),
            spp_hbinterval: params.hb_interval,
            spp_pathmaxrxt: params.path_max_rxt,
            spp_pathmtu: params.path_mtu,
            spp_sackdelay: params.sack_delay,
            spp_flags: params.flags.bits(),
            spp_ipv6_flowlabel: params.ipv6_flowlabel,
            spp_dscp: params.dscp,
            ..Default::default()
        };
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_PEER_ADDR_PARAMS, &raw)
    }

    pub(crate) fn rto_info(&self, assoc_id: AssocId) -> io::Result<RtoInfo> {
        let mut raw = sys::sctp_rtoinfo {
            srto_assoc_id: assoc_id.0,
            ..Default::default()
        };
        self.getsockopt_inout(sys::SOL_SCTP, sys::SCTP_RTOINFO, &mut raw)?;
        Ok(RtoInfo {
            initial: raw.srto_initial,
            max: raw.srto_max,
            min: raw.srto_min,
        })
    }

    pub(crate) fn set_rto_info(&self, assoc_id: AssocId, rto: &RtoInfo) -> io::Result<()> {
        let raw = sys::sctp_rtoinfo {
            srto_assoc_id: assoc_id.0,
            srto_initial: rto.initial,
            srto_max: rto.max,
            srto_min: rto.min,
        };
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_RTOINFO, &raw)
    }

    pub(crate) fn set_primary(&self, assoc_id: AssocId, addr: &SocketAddr) -> io::Result<()> {
        let mut storage = sys::sockaddr_storage::zeroed();
        addr::write_sockaddr(addr, &mut storage.bytes);
        let raw = sys::sctp_prim {
            ssp_assoc_id: assoc_id.0,
            ssp_addr: storage,
        };
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_PRIMARY_ADDR, &raw)
    }

    pub(crate) fn send_buffer_size(&self) -> io::Result<usize> {
        let v: i32 = self.getsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF)?;
        Ok(v as usize)
    }

    pub(crate) fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.setsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF, &(size as i32))
    }

    pub(crate) fn recv_buffer_size(&self) -> io::Result<usize> {
        let v: i32 = self.getsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF)?;
        Ok(v as usize)
    }

    pub(crate) fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.setsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF, &(size as i32))
    }

    fn set_timeout(&self, opt: i32, dur: Option<std::time::Duration>) -> io::Result<()> {
        let tv = match dur {
            Some(d) => {
                if d.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "cannot set a zero duration timeout",
                    ));
                }
                libc::timeval {
                    tv_sec: d.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
                    tv_usec: d.subsec_micros() as libc::suseconds_t,
                }
            }
            None => libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        self.setsockopt(libc::SOL_SOCKET, opt, &tv)
    }

    fn timeout(&self, opt: i32) -> io::Result<Option<std::time::Duration>> {
        let tv: libc::timeval = self.getsockopt(libc::SOL_SOCKET, opt)?;
        Ok(if tv.tv_sec == 0 && tv.tv_usec == 0 {
            None
        } else {
            // Composed from parts so an unnormalized tv_usec (foreign fd)
            // cannot overflow a nanosecond field.
            Some(
                std::time::Duration::from_secs(tv.tv_sec.max(0) as u64)
                    + std::time::Duration::from_micros(tv.tv_usec.max(0) as u64),
            )
        })
    }

    pub(crate) fn set_recv_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.set_timeout(libc::SO_RCVTIMEO, dur)
    }

    pub(crate) fn recv_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.timeout(libc::SO_RCVTIMEO)
    }

    pub(crate) fn set_send_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.set_timeout(libc::SO_SNDTIMEO, dur)
    }

    pub(crate) fn send_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.timeout(libc::SO_SNDTIMEO)
    }

    pub(crate) fn take_error(&self) -> io::Result<Option<io::Error>> {
        let v: i32 = self.getsockopt(libc::SOL_SOCKET, libc::SO_ERROR)?;
        Ok(if v == 0 {
            None
        } else {
            Some(io::Error::from_raw_os_error(v))
        })
    }

    // -- address queries -----------------------------------------------------

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut storage = [0u8; 128];
        let mut len = storage.len() as libc::socklen_t;
        cvt(unsafe {
            libc::getsockname(
                self.raw(),
                storage.as_mut_ptr() as *mut libc::sockaddr,
                &mut len,
            )
        })?;
        addr::read_sockaddr(&storage[..len as usize])
            .map(|(a, _)| a)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad local sockaddr"))
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        let mut storage = [0u8; 128];
        let mut len = storage.len() as libc::socklen_t;
        cvt(unsafe {
            libc::getpeername(
                self.raw(),
                storage.as_mut_ptr() as *mut libc::sockaddr,
                &mut len,
            )
        })?;
        addr::read_sockaddr(&storage[..len as usize])
            .map(|(a, _)| a)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad peer sockaddr"))
    }

    fn getaddrs(&self, assoc_id: AssocId, opt: i32) -> io::Result<Vec<SocketAddr>> {
        // Header (8 bytes) followed by packed sockaddrs. Sized for a very
        // multi-homed endpoint: 64 IPv6 addresses.
        const BUF_LEN: usize = 8 + 64 * addr::SOCKADDR_IN6_LEN;
        let mut buf = [0u8; BUF_LEN];
        buf[0..4].copy_from_slice(&assoc_id.0.to_ne_bytes());
        let mut len = BUF_LEN as libc::socklen_t;
        cvt(unsafe {
            libc::getsockopt(
                self.raw(),
                sys::SOL_SCTP,
                opt,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        })?;
        let count = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as usize;
        // Don't slice by the returned optlen: SCTP_GET_PEER_ADDRS includes
        // the 8-byte header in it but SCTP_GET_LOCAL_ADDRS does not (the
        // kernel keeps this asymmetry for ABI compatibility — see the XXX
        // comment in sctp_getsockopt_local_addrs). addr_num is authoritative.
        Ok(addr::read_addr_list(&buf[8..], count))
    }

    pub(crate) fn local_addrs(&self, assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
        self.getaddrs(assoc_id, sys::SCTP_GET_LOCAL_ADDRS)
    }

    pub(crate) fn peer_addrs(&self, assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
        self.getaddrs(assoc_id, sys::SCTP_GET_PEER_ADDRS)
    }

    // -- association management ----------------------------------------------

    pub(crate) fn peeloff(&self, assoc_id: AssocId) -> io::Result<Socket> {
        // Prefer the flags variant (kernel 4.15+) for an atomic CLOEXEC.
        let mut flags_arg = sys::sctp_peeloff_flags_arg_t {
            p_arg: sys::sctp_peeloff_arg_t {
                associd: assoc_id.0,
                sd: -1,
            },
            flags: libc::SOCK_CLOEXEC as u32,
        };
        let fd = match self.getsockopt_inout(
            sys::SOL_SCTP,
            sys::SCTP_SOCKOPT_PEELOFF_FLAGS,
            &mut flags_arg,
        ) {
            Ok(()) => unsafe { OwnedFd::from_raw_fd(flags_arg.p_arg.sd) },
            // Pre-4.15 kernels: fall back to the plain variant and set
            // CLOEXEC after the fact (non-atomic, best effort).
            Err(e)
                if e.raw_os_error() == Some(libc::ENOPROTOOPT)
                    || e.raw_os_error() == Some(libc::EOPNOTSUPP) =>
            {
                let mut arg = sys::sctp_peeloff_arg_t {
                    associd: assoc_id.0,
                    sd: -1,
                };
                self.getsockopt_inout(sys::SOL_SCTP, sys::SCTP_SOCKOPT_PEELOFF, &mut arg)?;
                // Take ownership before anything can fail, so the fd cannot
                // leak on the error path.
                let owned = unsafe { OwnedFd::from_raw_fd(arg.sd) };
                cvt(unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
                owned
            }
            Err(e) => return Err(e),
        };
        let sock = Socket { fd };
        sock.enable_rcvinfo()?;
        Ok(sock)
    }

    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        cvt(unsafe { libc::shutdown(self.raw(), how) })?;
        Ok(())
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl FromRawFd for Socket {
    unsafe fn from_raw_fd(fd: RawFd) -> Socket {
        Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SctpSocket")
            .field("fd", &self.raw())
            .finish()
    }
}
