//! Parsing of SCTP notifications (`union sctp_notification`).
//!
//! The kernel delivers notifications through the normal receive path with
//! `MSG_NOTIFICATION` set in `msg_flags`; the payload is one of the
//! notification structs from `<uapi/linux/sctp.h>`. Parsing reads fields at
//! explicit byte offsets in native endianness, so it is pure and testable on
//! any platform.

use std::io;
use std::net::SocketAddr;

use crate::addr;
use crate::sys;
use crate::types::{AssocId, Ppid};

/// A parsed SCTP notification.
///
/// Notifications only arrive for event classes subscribed via
/// [`SctpSocket::subscribe_event`](crate::SctpSocket::subscribe_event).
#[derive(Debug, Clone)]
pub enum Notification {
    AssocChange(AssocChange),
    PeerAddrChange(PeerAddrChange),
    RemoteError(RemoteError),
    /// Unified representation of both the legacy `SCTP_SEND_FAILED` and the
    /// new `SCTP_SEND_FAILED_EVENT` notification.
    SendFailed(SendFailed),
    /// Peer initiated a graceful shutdown; stop sending data.
    Shutdown(ShutdownEvent),
    PartialDelivery(PartialDeliveryEvent),
    AdaptationIndication(AdaptationIndication),
    Authentication(AuthenticationEvent),
    SenderDry(SenderDryEvent),
    StreamReset(StreamResetEvent),
    AssocReset(AssocResetEvent),
    StreamChange(StreamChangeEvent),
    /// A notification type this crate does not know; raw bytes preserved.
    Unknown(RawNotification),
}

/// State reported by [`AssocChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssocChangeState {
    /// A new association is ready for data transfer.
    CommUp,
    /// The association failed (unreachable peer, excessive retransmissions...).
    CommLost,
    /// The peer restarted the association.
    Restart,
    /// A graceful shutdown completed.
    ShutdownComplete,
    /// The association could not be established.
    CantStartAssoc,
    Unknown(u16),
}

impl AssocChangeState {
    fn from_raw(v: u16) -> Self {
        match v {
            sys::SCTP_COMM_UP => AssocChangeState::CommUp,
            sys::SCTP_COMM_LOST => AssocChangeState::CommLost,
            sys::SCTP_RESTART => AssocChangeState::Restart,
            sys::SCTP_SHUTDOWN_COMP => AssocChangeState::ShutdownComplete,
            sys::SCTP_CANT_STR_ASSOC => AssocChangeState::CantStartAssoc,
            other => AssocChangeState::Unknown(other),
        }
    }
}

/// `SCTP_ASSOC_CHANGE`: association lifecycle event.
#[derive(Debug, Clone)]
pub struct AssocChange {
    pub state: AssocChangeState,
    /// Protocol error code, if the event was caused by one.
    pub error: u16,
    /// Negotiated outbound stream count (valid for `CommUp` / `Restart`).
    pub outbound_streams: u16,
    /// Negotiated inbound stream count (valid for `CommUp` / `Restart`).
    pub inbound_streams: u16,
    pub assoc_id: AssocId,
    /// Optional trailing info (e.g. the ABORT chunk for `CommLost`).
    pub info: Vec<u8>,
}

/// State reported by [`PeerAddrChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddrChangeState {
    /// The address is now reachable.
    Available,
    /// The address can no longer be reached.
    Unreachable,
    /// The address was removed from the association.
    Removed,
    /// The address was added to the association.
    Added,
    /// The address was made the primary path.
    MadePrimary,
    /// The address has been confirmed as valid.
    Confirmed,
    /// The address is potentially failed (path probing in progress).
    PotentiallyFailed,
    Unknown(i32),
}

impl PeerAddrChangeState {
    fn from_raw(v: i32) -> Self {
        match v {
            sys::SCTP_ADDR_AVAILABLE => PeerAddrChangeState::Available,
            sys::SCTP_ADDR_UNREACHABLE => PeerAddrChangeState::Unreachable,
            sys::SCTP_ADDR_REMOVED => PeerAddrChangeState::Removed,
            sys::SCTP_ADDR_ADDED => PeerAddrChangeState::Added,
            sys::SCTP_ADDR_MADE_PRIM => PeerAddrChangeState::MadePrimary,
            sys::SCTP_ADDR_CONFIRMED => PeerAddrChangeState::Confirmed,
            sys::SCTP_ADDR_POTENTIALLY_FAILED => PeerAddrChangeState::PotentiallyFailed,
            other => PeerAddrChangeState::Unknown(other),
        }
    }
}

/// `SCTP_PEER_ADDR_CHANGE`: a multi-homing path changed state.
#[derive(Debug, Clone)]
pub struct PeerAddrChange {
    /// The affected peer address (`None` for unrecognized address families).
    pub address: Option<SocketAddr>,
    pub state: PeerAddrChangeState,
    pub error: i32,
    pub assoc_id: AssocId,
}

/// `SCTP_REMOTE_ERROR`: the peer sent an operational ERROR chunk.
#[derive(Debug, Clone)]
pub struct RemoteError {
    /// Error cause code (converted from network byte order).
    pub error: u16,
    pub assoc_id: AssocId,
    /// The complete error TLV as it appeared on the wire.
    pub data: Vec<u8>,
}

/// `SCTP_SEND_FAILED` / `SCTP_SEND_FAILED_EVENT`: a message could not be
/// delivered.
#[derive(Debug, Clone)]
pub struct SendFailed {
    /// `SCTP_DATA_UNSENT` (never on the wire) or `SCTP_DATA_SENT`.
    pub unsent: bool,
    /// Error cause.
    pub error: u32,
    /// Stream id of the failed message.
    pub sid: u16,
    /// Payload protocol identifier of the failed message.
    pub ppid: Ppid,
    /// The `context` value supplied in [`SendInfo`](crate::SendInfo).
    pub context: u32,
    pub assoc_id: AssocId,
    /// The undelivered payload.
    pub payload: Vec<u8>,
}

/// `SCTP_SHUTDOWN_EVENT`.
#[derive(Debug, Clone, Copy)]
pub struct ShutdownEvent {
    pub assoc_id: AssocId,
}

/// `SCTP_PARTIAL_DELIVERY_EVENT`.
#[derive(Debug, Clone, Copy)]
pub struct PartialDeliveryEvent {
    /// `SCTP_PARTIAL_DELIVERY_ABORTED` (0) is the only defined indication.
    pub indication: u32,
    pub assoc_id: AssocId,
    pub stream: u32,
    pub seq: u32,
}

/// `SCTP_ADAPTATION_INDICATION`.
#[derive(Debug, Clone, Copy)]
pub struct AdaptationIndication {
    pub indication: u32,
    pub assoc_id: AssocId,
}

/// `SCTP_AUTHENTICATION_EVENT`.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticationEvent {
    pub key_number: u16,
    pub alt_key_number: u16,
    pub indication: u32,
    pub assoc_id: AssocId,
}

/// `SCTP_SENDER_DRY_EVENT`: nothing left to send or retransmit.
#[derive(Debug, Clone, Copy)]
pub struct SenderDryEvent {
    pub assoc_id: AssocId,
}

/// `SCTP_STREAM_RESET_EVENT` (RFC 6525).
#[derive(Debug, Clone)]
pub struct StreamResetEvent {
    /// Combination of `SCTP_STREAM_RESET_{INCOMING_SSN,OUTGOING_SSN,DENIED,FAILED}`.
    pub flags: u16,
    pub assoc_id: AssocId,
    /// Affected stream ids (empty means all streams).
    pub streams: Vec<u16>,
}

/// `SCTP_ASSOC_RESET_EVENT` (RFC 6525).
#[derive(Debug, Clone, Copy)]
pub struct AssocResetEvent {
    pub flags: u16,
    pub assoc_id: AssocId,
    pub local_tsn: u32,
    pub remote_tsn: u32,
}

/// `SCTP_STREAM_CHANGE_EVENT` (RFC 6525).
#[derive(Debug, Clone, Copy)]
pub struct StreamChangeEvent {
    pub flags: u16,
    pub assoc_id: AssocId,
    pub instrms: u16,
    pub outstrms: u16,
}

/// An unrecognized notification, kept as raw bytes.
#[derive(Debug, Clone)]
pub struct RawNotification {
    pub sn_type: u16,
    pub sn_flags: u16,
    /// The full notification including the 8-byte header.
    pub data: Vec<u8>,
}

// -------------------------------------------------------------------------
// Parser
// -------------------------------------------------------------------------

fn err(msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("sctp notification: {msg}"),
    )
}

fn u16_at(buf: &[u8], off: usize) -> io::Result<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_ne_bytes([b[0], b[1]]))
        .ok_or_else(|| err("truncated"))
}

fn u32_at(buf: &[u8], off: usize) -> io::Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| err("truncated"))
}

fn i32_at(buf: &[u8], off: usize) -> io::Result<i32> {
    Ok(u32_at(buf, off)? as i32)
}

fn assoc_at(buf: &[u8], off: usize) -> io::Result<AssocId> {
    Ok(AssocId(i32_at(buf, off)?))
}

fn tail(buf: &[u8], off: usize) -> Vec<u8> {
    buf.get(off..).unwrap_or(&[]).to_vec()
}

/// Parses one notification from `buf` (the payload of a receive that had
/// `MSG_NOTIFICATION` set).
///
/// `buf` must contain the complete notification; the receive path guarantees
/// this by rejecting notification reads without `MSG_EOR`.
pub(crate) fn parse(buf: &[u8]) -> io::Result<Notification> {
    let sn_type = u16_at(buf, 0)?;
    let sn_flags = u16_at(buf, 2)?;
    // sn_length (offset 4) describes the same extent as buf; buf is
    // authoritative since recvmsg reported it.

    let n = match sn_type {
        sys::SCTP_ASSOC_CHANGE => Notification::AssocChange(AssocChange {
            state: AssocChangeState::from_raw(u16_at(buf, 8)?),
            error: u16_at(buf, 10)?,
            outbound_streams: u16_at(buf, 12)?,
            inbound_streams: u16_at(buf, 14)?,
            assoc_id: assoc_at(buf, 16)?,
            info: tail(buf, 20),
        }),
        sys::SCTP_PEER_ADDR_CHANGE => {
            // struct sctp_paddr_change is packed: aaddr at 8, state at 136.
            let addr_bytes = buf
                .get(8..136)
                .ok_or_else(|| err("truncated paddr_change"))?;
            Notification::PeerAddrChange(PeerAddrChange {
                address: addr::read_sockaddr(addr_bytes).map(|(a, _)| a),
                state: PeerAddrChangeState::from_raw(i32_at(buf, 136)?),
                error: i32_at(buf, 140)?,
                assoc_id: assoc_at(buf, 144)?,
            })
        }
        sys::SCTP_REMOTE_ERROR => Notification::RemoteError(RemoteError {
            // sre_error is __be16.
            error: u16::from_be(u16_at(buf, 8)?),
            assoc_id: assoc_at(buf, 12)?,
            data: tail(buf, 16),
        }),
        sys::SCTP_SEND_FAILED => {
            // Legacy layout: ssf_info is a 32-byte sctp_sndrcvinfo at 12.
            Notification::SendFailed(SendFailed {
                unsent: sn_flags == sys::SCTP_DATA_UNSENT,
                error: u32_at(buf, 8)?,
                sid: u16_at(buf, 12)?,
                ppid: Ppid::from_wire(u32_at(buf, 20)?),
                context: u32_at(buf, 24)?,
                assoc_id: assoc_at(buf, 44)?,
                payload: tail(buf, 48),
            })
        }
        sys::SCTP_SEND_FAILED_EVENT => {
            // New layout: ssfe_info is a 16-byte sctp_sndinfo at 12.
            Notification::SendFailed(SendFailed {
                unsent: sn_flags == sys::SCTP_DATA_UNSENT,
                error: u32_at(buf, 8)?,
                sid: u16_at(buf, 12)?,
                ppid: Ppid::from_wire(u32_at(buf, 16)?),
                context: u32_at(buf, 20)?,
                assoc_id: assoc_at(buf, 28)?,
                payload: tail(buf, 32),
            })
        }
        sys::SCTP_SHUTDOWN_EVENT => Notification::Shutdown(ShutdownEvent {
            assoc_id: assoc_at(buf, 8)?,
        }),
        sys::SCTP_PARTIAL_DELIVERY_EVENT => Notification::PartialDelivery(PartialDeliveryEvent {
            indication: u32_at(buf, 8)?,
            assoc_id: assoc_at(buf, 12)?,
            stream: u32_at(buf, 16)?,
            seq: u32_at(buf, 20)?,
        }),
        sys::SCTP_ADAPTATION_INDICATION => {
            Notification::AdaptationIndication(AdaptationIndication {
                indication: u32_at(buf, 8)?,
                assoc_id: assoc_at(buf, 12)?,
            })
        }
        sys::SCTP_AUTHENTICATION_EVENT => Notification::Authentication(AuthenticationEvent {
            key_number: u16_at(buf, 8)?,
            alt_key_number: u16_at(buf, 10)?,
            indication: u32_at(buf, 12)?,
            assoc_id: assoc_at(buf, 16)?,
        }),
        sys::SCTP_SENDER_DRY_EVENT => Notification::SenderDry(SenderDryEvent {
            assoc_id: assoc_at(buf, 8)?,
        }),
        sys::SCTP_STREAM_RESET_EVENT => {
            let mut streams = Vec::new();
            let mut off = 12;
            while off + 2 <= buf.len() {
                streams.push(u16_at(buf, off)?);
                off += 2;
            }
            Notification::StreamReset(StreamResetEvent {
                flags: sn_flags,
                assoc_id: assoc_at(buf, 8)?,
                streams,
            })
        }
        sys::SCTP_ASSOC_RESET_EVENT => Notification::AssocReset(AssocResetEvent {
            flags: sn_flags,
            assoc_id: assoc_at(buf, 8)?,
            local_tsn: u32_at(buf, 12)?,
            remote_tsn: u32_at(buf, 16)?,
        }),
        sys::SCTP_STREAM_CHANGE_EVENT => Notification::StreamChange(StreamChangeEvent {
            flags: sn_flags,
            assoc_id: assoc_at(buf, 8)?,
            instrms: u16_at(buf, 12)?,
            outstrms: u16_at(buf, 14)?,
        }),
        _ => Notification::Unknown(RawNotification {
            sn_type,
            sn_flags,
            data: buf.to_vec(),
        }),
    };
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-vector builder writing fields in native endianness, mirroring
    /// what the kernel would place in the receive buffer.
    struct Builder(Vec<u8>);

    impl Builder {
        fn new(sn_type: u16, sn_flags: u16) -> Self {
            let mut v = Vec::new();
            v.extend_from_slice(&sn_type.to_ne_bytes());
            v.extend_from_slice(&sn_flags.to_ne_bytes());
            v.extend_from_slice(&0u32.to_ne_bytes()); // sn_length, fixed up in finish()
            Builder(v)
        }

        fn u16(mut self, v: u16) -> Self {
            self.0.extend_from_slice(&v.to_ne_bytes());
            self
        }

        fn u32(mut self, v: u32) -> Self {
            self.0.extend_from_slice(&v.to_ne_bytes());
            self
        }

        fn i32(mut self, v: i32) -> Self {
            self.0.extend_from_slice(&v.to_ne_bytes());
            self
        }

        fn bytes(mut self, v: &[u8]) -> Self {
            self.0.extend_from_slice(v);
            self
        }

        fn finish(mut self) -> Vec<u8> {
            let len = self.0.len() as u32;
            self.0[4..8].copy_from_slice(&len.to_ne_bytes());
            self.0
        }
    }

    #[test]
    fn parses_assoc_change_comm_up() {
        let buf = Builder::new(sys::SCTP_ASSOC_CHANGE, 0)
            .u16(sys::SCTP_COMM_UP) // sac_state
            .u16(0) // sac_error
            .u16(10) // outbound
            .u16(5) // inbound
            .i32(42) // assoc_id
            .finish();
        match parse(&buf).unwrap() {
            Notification::AssocChange(ac) => {
                assert_eq!(ac.state, AssocChangeState::CommUp);
                assert_eq!(ac.outbound_streams, 10);
                assert_eq!(ac.inbound_streams, 5);
                assert_eq!(ac.assoc_id, AssocId(42));
                assert!(ac.info.is_empty());
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_peer_addr_change() {
        let addr: SocketAddr = "10.1.2.3:2905".parse().unwrap();
        let mut storage = [0u8; 128];
        crate::addr::write_sockaddr(&addr, &mut storage);
        let buf = Builder::new(sys::SCTP_PEER_ADDR_CHANGE, 0)
            .bytes(&storage) // spc_aaddr at offset 8, 128 bytes
            .i32(sys::SCTP_ADDR_UNREACHABLE) // spc_state at 136
            .i32(7) // spc_error
            .i32(3) // assoc_id
            .finish();
        assert_eq!(buf.len(), 148); // sizeof(struct sctp_paddr_change)
        match parse(&buf).unwrap() {
            Notification::PeerAddrChange(pc) => {
                assert_eq!(pc.address, Some(addr));
                assert_eq!(pc.state, PeerAddrChangeState::Unreachable);
                assert_eq!(pc.error, 7);
                assert_eq!(pc.assoc_id, AssocId(3));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_shutdown_and_sender_dry() {
        let buf = Builder::new(sys::SCTP_SHUTDOWN_EVENT, 0).i32(9).finish();
        match parse(&buf).unwrap() {
            Notification::Shutdown(e) => assert_eq!(e.assoc_id, AssocId(9)),
            other => panic!("wrong variant: {other:?}"),
        }
        let buf = Builder::new(sys::SCTP_SENDER_DRY_EVENT, 0).i32(11).finish();
        match parse(&buf).unwrap() {
            Notification::SenderDry(e) => assert_eq!(e.assoc_id, AssocId(11)),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_new_style_send_failed() {
        // sctp_send_failed_event: error@8, sndinfo@12 (sid,flags,ppid,context,assoc),
        // ssf_assoc_id@28, data@32.
        let payload = b"lost-message";
        let buf = Builder::new(sys::SCTP_SEND_FAILED_EVENT, sys::SCTP_DATA_UNSENT)
            .u32(5) // ssf_error
            .u16(2) // snd_sid
            .u16(0) // snd_flags
            .u32(crate::types::Ppid::NGAP.to_wire()) // snd_ppid (wire order)
            .u32(0xdead_beef) // snd_context
            .i32(6) // snd_assoc_id
            .i32(6) // ssf_assoc_id
            .bytes(payload)
            .finish();
        match parse(&buf).unwrap() {
            Notification::SendFailed(sf) => {
                assert!(sf.unsent);
                assert_eq!(sf.error, 5);
                assert_eq!(sf.sid, 2);
                assert_eq!(sf.ppid, crate::types::Ppid::NGAP);
                assert_eq!(sf.context, 0xdead_beef);
                assert_eq!(sf.assoc_id, AssocId(6));
                assert_eq!(sf.payload, payload);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_stream_reset_with_stream_list() {
        let buf = Builder::new(
            sys::SCTP_STREAM_RESET_EVENT,
            sys::SCTP_STREAM_RESET_INCOMING_SSN,
        )
        .i32(4) // assoc_id
        .u16(1)
        .u16(3)
        .u16(5)
        .finish();
        match parse(&buf).unwrap() {
            Notification::StreamReset(sr) => {
                assert_eq!(sr.assoc_id, AssocId(4));
                assert_eq!(sr.streams, vec![1, 3, 5]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_type_preserved_raw() {
        let buf = Builder::new(0x9999, 1).u32(123).finish();
        match parse(&buf).unwrap() {
            Notification::Unknown(raw) => {
                assert_eq!(raw.sn_type, 0x9999);
                assert_eq!(raw.sn_flags, 1);
                assert_eq!(raw.data.len(), 12);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn truncated_input_is_an_error() {
        assert!(parse(&[0x01]).is_err());
        let buf = Builder::new(sys::SCTP_ASSOC_CHANGE, 0).u16(0).finish();
        assert!(parse(&buf).is_err());
    }
}
