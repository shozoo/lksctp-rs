//! Helpers and wire-accurate protocol encoders shared by the loopback
//! integration test binaries (`loopback_tokio.rs` and
//! `loopback_blocking.rs`).

// Each test binary compiles this module separately and uses only a subset.
#![allow(dead_code)]

use std::net::SocketAddr;

#[cfg(feature = "tokio")]
use lksctp::SctpStream;
use lksctp::{Family, RcvInfo, RecvMsg, SctpSocket, Style};

/// Returns false (and logs) when the kernel lacks SCTP support, so tests
/// skip instead of failing on machines without the sctp module.
pub fn sctp_available() -> bool {
    match SctpSocket::new(Family::Ipv4, Style::OneToOne) {
        Ok(_) => true,
        // EPROTONOSUPPORT / ESOCKTNOSUPPORT / EAFNOSUPPORT
        Err(e) if matches!(e.raw_os_error(), Some(93) | Some(94) | Some(97)) => {
            eprintln!("skipping: kernel SCTP unavailable ({e})");
            false
        }
        Err(e) => panic!("socket creation failed unexpectedly: {e}"),
    }
}

/// Like [`sctp_available`], for IPv6 sockets (kernels can have SCTP but no
/// IPv6, e.g. `ipv6.disable=1`).
pub fn sctp_ipv6_available() -> bool {
    match SctpSocket::new(Family::Ipv6, Style::OneToOne) {
        Ok(_) => true,
        Err(e) if matches!(e.raw_os_error(), Some(93) | Some(94) | Some(97)) => {
            eprintln!("skipping: kernel SCTP/IPv6 unavailable ({e})");
            false
        }
        Err(e) => panic!("socket creation failed unexpectedly: {e}"),
    }
}

pub fn localhost(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Bounds a test step so a protocol-level stall fails with a location
/// instead of hanging the whole suite.
#[cfg(feature = "tokio")]
pub async fn t<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("test step timed out")
}

/// Receives the next complete data message, skipping interleaved
/// notifications.
#[cfg(feature = "tokio")]
pub async fn recv_data(stream: &SctpStream, buf: &mut [u8]) -> (usize, RcvInfo) {
    loop {
        match t(stream.recv_msg(buf)).await.unwrap() {
            RecvMsg::Data { len, info, eor } => {
                assert!(eor, "message truncated; enlarge the buffer");
                return (len, info.expect("rcvinfo enabled by default"));
            }
            RecvMsg::Notification(_) => {}
        }
    }
}

/// Blocking counterpart of [`recv_data`] for the synchronous [`SctpSocket`].
/// Callers should have set a receive timeout on the socket so a stall fails
/// instead of hanging the suite.
pub fn recv_data_blocking(sock: &SctpSocket, buf: &mut [u8]) -> (usize, RcvInfo) {
    loop {
        match sock.recv_msg(buf).unwrap() {
            RecvMsg::Data { len, info, eor } => {
                assert!(eor, "message truncated; enlarge the buffer");
                return (len, info.expect("rcvinfo enabled by default"));
            }
            RecvMsg::Notification(_) => {}
        }
    }
}

/// Minimal but wire-accurate Diameter (RFC 6733) encoder/decoder used as
/// realistic test traffic. Diameter runs over SCTP with PPID 46 and RFC
/// 6733 §2.1 allows sending on any stream of the association.
pub mod diameter {
    pub const CAPABILITIES_EXCHANGE: u32 = 257;
    pub const DEVICE_WATCHDOG: u32 = 280;
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const ORIGIN_HOST: u32 = 264;

    const RESULT_CODE: u32 = 268;
    const ORIGIN_REALM: u32 = 296;
    const HOST_IP_ADDRESS: u32 = 257;
    const VENDOR_ID: u32 = 266;
    const PRODUCT_NAME: u32 = 269;

    const REQUEST_FLAG: u8 = 0x80;
    const AVP_MANDATORY: u8 = 0x40;
    const AVP_VENDOR: u8 = 0x80;

    /// One AVP: code(4), flags(1), length(3, header included, padding
    /// excluded), data padded to a 4-byte boundary.
    fn avp(code: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + data.len() + 3);
        v.extend_from_slice(&code.to_be_bytes());
        v.push(flags);
        v.extend_from_slice(&((8 + data.len()) as u32).to_be_bytes()[1..4]);
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    /// Diameter header: version(1)=1, length(3), flags(1), code(3),
    /// application-id(4), hop-by-hop(4), end-to-end(4), then AVPs.
    fn message(code: u32, flags: u8, hbh: u32, e2e: u32, avps: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![1, 0, 0, 0]; // version + length (fixed up below)
        v.push(flags);
        v.extend_from_slice(&code.to_be_bytes()[1..4]);
        v.extend_from_slice(&0u32.to_be_bytes()); // Application-ID: common messages
        v.extend_from_slice(&hbh.to_be_bytes());
        v.extend_from_slice(&e2e.to_be_bytes());
        for a in avps {
            v.extend_from_slice(a);
        }
        let len = (v.len() as u32).to_be_bytes();
        v[1..4].copy_from_slice(&len[1..4]);
        v
    }

    /// The identity AVPs every CER/CEA must carry (RFC 6733 §5.3).
    fn identity_avps(origin_host: &str) -> Vec<Vec<u8>> {
        let mut host_ip = vec![0u8, 1]; // AddressType 1 = IPv4
        host_ip.extend_from_slice(&[127, 0, 0, 1]);
        vec![
            avp(ORIGIN_HOST, AVP_MANDATORY, origin_host.as_bytes()),
            avp(ORIGIN_REALM, AVP_MANDATORY, b"example.com"),
            avp(HOST_IP_ADDRESS, AVP_MANDATORY, &host_ip),
            avp(VENDOR_ID, AVP_MANDATORY, &0u32.to_be_bytes()),
            avp(PRODUCT_NAME, 0, b"lksctp-rs test"),
        ]
    }

    /// Capabilities-Exchange-Request.
    pub fn cer(origin_host: &str, hbh: u32, e2e: u32) -> Vec<u8> {
        message(
            CAPABILITIES_EXCHANGE,
            REQUEST_FLAG,
            hbh,
            e2e,
            &identity_avps(origin_host),
        )
    }

    /// Capabilities-Exchange-Answer (DIAMETER_SUCCESS). Answers echo the
    /// request's hop-by-hop / end-to-end identifiers (RFC 6733 §6.2).
    pub fn cea(hbh: u32, e2e: u32) -> Vec<u8> {
        let mut avps = vec![avp(
            RESULT_CODE,
            AVP_MANDATORY,
            &DIAMETER_SUCCESS.to_be_bytes(),
        )];
        avps.extend(identity_avps("server.example.com"));
        message(CAPABILITIES_EXCHANGE, 0, hbh, e2e, &avps)
    }

    /// Device-Watchdog-Request.
    pub fn dwr(origin_host: &str, hbh: u32, e2e: u32) -> Vec<u8> {
        message(
            DEVICE_WATCHDOG,
            REQUEST_FLAG,
            hbh,
            e2e,
            &[
                avp(ORIGIN_HOST, AVP_MANDATORY, origin_host.as_bytes()),
                avp(ORIGIN_REALM, AVP_MANDATORY, b"example.com"),
            ],
        )
    }

    /// Device-Watchdog-Answer (DIAMETER_SUCCESS).
    pub fn dwa(hbh: u32, e2e: u32) -> Vec<u8> {
        message(
            DEVICE_WATCHDOG,
            0,
            hbh,
            e2e,
            &[
                avp(RESULT_CODE, AVP_MANDATORY, &DIAMETER_SUCCESS.to_be_bytes()),
                avp(ORIGIN_HOST, AVP_MANDATORY, b"server.example.com"),
                avp(ORIGIN_REALM, AVP_MANDATORY, b"example.com"),
            ],
        )
    }

    pub struct Header {
        pub code: u32,
        pub request: bool,
        pub hbh: u32,
        pub e2e: u32,
    }

    pub fn parse_header(buf: &[u8]) -> Header {
        assert_eq!(buf[0], 1, "Diameter version");
        let length = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(
            length,
            buf.len(),
            "Diameter Message-Length must match the SCTP message boundary"
        );
        Header {
            request: buf[4] & REQUEST_FLAG != 0,
            code: u32::from_be_bytes([0, buf[5], buf[6], buf[7]]),
            hbh: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
            e2e: u32::from_be_bytes(buf[16..20].try_into().unwrap()),
        }
    }

    /// Returns the data of the first AVP with the given code.
    pub fn find_avp(buf: &[u8], code: u32) -> Option<Vec<u8>> {
        let mut off = 20;
        while off + 8 <= buf.len() {
            let c = u32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
            let flags = buf[off + 4];
            let len = u32::from_be_bytes([0, buf[off + 5], buf[off + 6], buf[off + 7]]) as usize;
            if len < 8 || off + len > buf.len() {
                return None;
            }
            let hdr = if flags & AVP_VENDOR != 0 { 12 } else { 8 };
            if c == code {
                return Some(buf[off + hdr..off + len].to_vec());
            }
            off += (len + 3) & !3;
        }
        None
    }

    pub fn result_code(buf: &[u8]) -> Option<u32> {
        find_avp(buf, RESULT_CODE).map(|d| u32::from_be_bytes(d.try_into().unwrap()))
    }
}

/// Wire-accurate M3UA (RFC 4666) test messages: common header is
/// version(1)=1, reserved(1), class(1), type(1), length(4, header and
/// padding included). M3UA is the classic user of one-to-many sockets.
pub mod m3ua {
    /// ASP Up (class 3 "ASPSM", type 1), no parameters.
    pub const ASPUP: [u8; 8] = [1, 0, 3, 1, 0, 0, 0, 8];
    /// ASP Up Ack (class 3, type 4).
    pub const ASPUP_ACK: [u8; 8] = [1, 0, 3, 4, 0, 0, 0, 8];

    /// Heartbeat (class 3, type 3) with a Heartbeat Data parameter
    /// (tag 0x0009; parameter length includes its 4-byte header but not
    /// the padding).
    pub fn beat(data: &[u8]) -> Vec<u8> {
        let param_len = 4 + data.len();
        let padded = (param_len + 3) & !3;
        let mut v = vec![1, 0, 3, 3];
        v.extend_from_slice(&((8 + padded) as u32).to_be_bytes());
        v.extend_from_slice(&9u16.to_be_bytes());
        v.extend_from_slice(&(param_len as u16).to_be_bytes());
        v.extend_from_slice(data);
        v.resize(8 + padded, 0);
        v
    }
}
