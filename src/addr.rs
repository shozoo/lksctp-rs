//! Conversion between [`std::net::SocketAddr`] and the **Linux** wire layout
//! of `sockaddr_in` / `sockaddr_in6`.
//!
//! The layout is hardcoded (rather than borrowed from the host libc) because
//! the bytes always describe what the Linux kernel produces or consumes, and
//! keeping the code host-independent lets the parsers be unit-tested on any
//! platform.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::sys;

/// Byte length of a packed Linux `sockaddr_in`.
pub(crate) const SOCKADDR_IN_LEN: usize = 16;
/// Byte length of a packed Linux `sockaddr_in6`.
pub(crate) const SOCKADDR_IN6_LEN: usize = 28;

/// Writes `addr` into `out` in Linux sockaddr layout and returns the number
/// of bytes written. `out` must be at least [`SOCKADDR_IN6_LEN`] bytes.
///
/// As with `std`, `sin6_flowinfo` and `sin6_scope_id` are stored without
/// byte-order conversion.
pub(crate) fn write_sockaddr(addr: &SocketAddr, out: &mut [u8]) -> usize {
    match addr {
        SocketAddr::V4(v4) => {
            out[..SOCKADDR_IN_LEN].fill(0);
            out[0..2].copy_from_slice(&sys::AF_INET.to_ne_bytes());
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&v4.ip().octets());
            SOCKADDR_IN_LEN
        }
        SocketAddr::V6(v6) => {
            out[..SOCKADDR_IN6_LEN].fill(0);
            out[0..2].copy_from_slice(&sys::AF_INET6.to_ne_bytes());
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            out[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
            out[8..24].copy_from_slice(&v6.ip().octets());
            out[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            SOCKADDR_IN6_LEN
        }
    }
}

/// Reads one Linux-layout sockaddr from the head of `buf`. Returns the
/// address and the number of bytes consumed.
pub(crate) fn read_sockaddr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family {
        sys::AF_INET if buf.len() >= SOCKADDR_IN_LEN => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), SOCKADDR_IN_LEN))
        }
        sys::AF_INET6 if buf.len() >= SOCKADDR_IN6_LEN => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let flowinfo = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            let scope_id = u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]);
            let v6 = std::net::SocketAddrV6::new(Ipv6Addr::from(octets), port, flowinfo, scope_id);
            Some((SocketAddr::V6(v6), SOCKADDR_IN6_LEN))
        }
        _ => None,
    }
}

/// Packs `addrs` back-to-back (no padding), the format expected by
/// `SCTP_SOCKOPT_BINDX_*` and `SCTP_SOCKOPT_CONNECTX3`.
pub(crate) fn pack_addr_list(addrs: &[SocketAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addrs.len() * SOCKADDR_IN6_LEN);
    let mut tmp = [0u8; SOCKADDR_IN6_LEN];
    for addr in addrs {
        let n = write_sockaddr(addr, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

/// Reads `count` sockaddrs packed back-to-back, the format returned by
/// `SCTP_GET_PEER_ADDRS` / `SCTP_GET_LOCAL_ADDRS`.
pub(crate) fn read_addr_list(mut buf: &[u8], count: usize) -> Vec<SocketAddr> {
    // The parse loop is bounded by the buffer, but the capacity request
    // must not trust `count` (it is read from a kernel-filled buffer).
    let mut out = Vec::with_capacity(count.min(buf.len() / SOCKADDR_IN_LEN));
    for _ in 0..count {
        match read_sockaddr(buf) {
            Some((addr, consumed)) => {
                out.push(addr);
                buf = &buf[consumed..];
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip() {
        let addr: SocketAddr = "192.0.2.1:38412".parse().unwrap();
        let mut buf = [0u8; SOCKADDR_IN6_LEN];
        let n = write_sockaddr(&addr, &mut buf);
        assert_eq!(n, SOCKADDR_IN_LEN);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), sys::AF_INET);
        // Port is big-endian on the wire.
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 38412);
        let (parsed, consumed) = read_sockaddr(&buf).unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(consumed, SOCKADDR_IN_LEN);
    }

    #[test]
    fn v6_roundtrip() {
        let addr: SocketAddr = "[2001:db8::2]:3868".parse().unwrap();
        let mut buf = [0u8; SOCKADDR_IN6_LEN];
        let n = write_sockaddr(&addr, &mut buf);
        assert_eq!(n, SOCKADDR_IN6_LEN);
        let (parsed, consumed) = read_sockaddr(&buf).unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(consumed, SOCKADDR_IN6_LEN);
    }

    #[test]
    fn mixed_list_roundtrip() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:2905".parse().unwrap(),
            "[2001:db8::1]:2905".parse().unwrap(),
            "10.0.0.2:2905".parse().unwrap(),
        ];
        let packed = pack_addr_list(&addrs);
        assert_eq!(packed.len(), SOCKADDR_IN_LEN * 2 + SOCKADDR_IN6_LEN);
        assert_eq!(read_addr_list(&packed, 3), addrs);
    }

    #[test]
    fn rejects_unknown_family_and_short_input() {
        assert!(read_sockaddr(&[0xff, 0xff, 0, 0]).is_none());
        assert!(read_sockaddr(&[]).is_none());
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut buf = [0u8; SOCKADDR_IN6_LEN];
        write_sockaddr(&addr, &mut buf);
        assert!(read_sockaddr(&buf[..8]).is_none());
    }
}
