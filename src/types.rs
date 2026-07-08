//! Public, idiomatic types wrapping the raw kernel structures in [`crate::sys`].

use std::net::SocketAddr;
use std::ops::{BitOr, BitOrAssign};

use crate::notification::Notification;
use crate::sys;

// -------------------------------------------------------------------------
// Identifiers
// -------------------------------------------------------------------------

/// SCTP association identifier (`sctp_assoc_t`).
///
/// Meaningful on one-to-many sockets, where a single socket carries multiple
/// associations. One-to-one sockets ignore it in most APIs; use
/// [`AssocId::FUTURE`] (zero) there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AssocId(pub i32);

impl AssocId {
    /// Applies an option to future associations (also the "unspecified" id).
    pub const FUTURE: AssocId = AssocId(sys::SCTP_FUTURE_ASSOC);
    /// Applies an option to all current associations.
    pub const CURRENT: AssocId = AssocId(sys::SCTP_CURRENT_ASSOC);
    /// Applies an option to all current and future associations.
    pub const ALL: AssocId = AssocId(sys::SCTP_ALL_ASSOC);
}

/// SCTP Payload Protocol Identifier.
///
/// Held in **host byte order** in this API; conversion to the big-endian
/// on-wire representation (which the kernel passes through verbatim) happens
/// at the sendmsg/recvmsg boundary. This spares callers the `htonl` dance
/// that trips up users of the raw C API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ppid(pub u32);

impl Ppid {
    pub const UNSPECIFIED: Ppid = Ppid(0);
    /// IUA (RFC 4233 / IANA SCTP payload protocol identifiers).
    pub const IUA: Ppid = Ppid(1);
    /// M2UA (RFC 3331).
    pub const M2UA: Ppid = Ppid(2);
    /// M3UA (RFC 4666).
    pub const M3UA: Ppid = Ppid(3);
    /// SUA (RFC 3868).
    pub const SUA: Ppid = Ppid(4);
    /// M2PA (RFC 4165).
    pub const M2PA: Ppid = Ppid(5);
    /// S1 Application Protocol (S1AP, 3GPP TS 36.412).
    pub const S1AP: Ppid = Ppid(18);
    /// X2 Application Protocol (X2AP, 3GPP TS 36.422).
    pub const X2AP: Ppid = Ppid(27);
    /// Diameter over SCTP (RFC 6733).
    pub const DIAMETER: Ppid = Ppid(46);
    /// Diameter over DTLS/SCTP (RFC 6733).
    pub const DIAMETER_DTLS: Ppid = Ppid(47);
    /// NG Application Protocol (NGAP, 3GPP TS 38.412).
    pub const NGAP: Ppid = Ppid(60);
    /// XnAP (3GPP TS 38.422).
    pub const XNAP: Ppid = Ppid(61);
    /// F1AP (3GPP TS 38.472).
    pub const F1AP: Ppid = Ppid(62);
    /// E1AP (3GPP TS 38.462).
    pub const E1AP: Ppid = Ppid(64);

    /// Converts to the value stored in `snd_ppid` (big-endian on the wire).
    pub(crate) fn to_wire(self) -> u32 {
        self.0.to_be()
    }

    /// Converts from the value found in `rcv_ppid`.
    pub(crate) fn from_wire(v: u32) -> Ppid {
        Ppid(u32::from_be(v))
    }
}

// -------------------------------------------------------------------------
// Socket construction parameters
// -------------------------------------------------------------------------

/// Address family for a new SCTP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

/// RFC 6458 socket style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `SOCK_STREAM`: one association per socket, TCP-like
    /// `listen`/`accept`/`connect` workflow.
    OneToOne,
    /// `SOCK_SEQPACKET`: many associations multiplexed over one socket,
    /// UDP-like workflow keyed by [`AssocId`].
    OneToMany,
}

// -------------------------------------------------------------------------
// Send / receive metadata
// -------------------------------------------------------------------------

/// Flags for [`SendInfo`] (subset of `sinfo_flags` valid on send).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendFlags(u16);

impl SendFlags {
    pub const NONE: SendFlags = SendFlags(0);
    /// Deliver the message unordered (no SSN ordering within the stream).
    pub const UNORDERED: SendFlags = SendFlags(sys::SCTP_UNORDERED);
    /// Send via the given destination address, overriding the primary path
    /// (only meaningful together with an explicit destination address).
    pub const ADDR_OVER: SendFlags = SendFlags(sys::SCTP_ADDR_OVER);
    /// Abort the association; the payload (if any) becomes the abort cause.
    pub const ABORT: SendFlags = SendFlags(sys::SCTP_ABORT);
    /// Ask the peer to SACK immediately.
    pub const SACK_IMMEDIATELY: SendFlags = SendFlags(sys::SCTP_SACK_IMMEDIATELY);
    /// Initiate a graceful shutdown after this message (`SCTP_EOF`).
    pub const EOF: SendFlags = SendFlags(sys::SCTP_EOF);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits(bits: u16) -> SendFlags {
        SendFlags(bits)
    }

    pub const fn contains(self, other: SendFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for SendFlags {
    type Output = SendFlags;
    fn bitor(self, rhs: SendFlags) -> SendFlags {
        SendFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for SendFlags {
    fn bitor_assign(&mut self, rhs: SendFlags) {
        self.0 |= rhs.0;
    }
}

/// Per-message send parameters, carried to the kernel as an `SCTP_SNDINFO`
/// control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendInfo {
    /// Outgoing stream id. Must be below the negotiated `outstrms`
    /// (see [`AssocStatus::outstrms`]), or the send fails with `EINVAL`.
    pub sid: u16,
    /// Payload protocol identifier (host byte order; see [`Ppid`]).
    pub ppid: Ppid,
    pub flags: SendFlags,
    /// Opaque value echoed back in send-failure notifications.
    pub context: u32,
    /// Target association (one-to-many sockets only).
    pub assoc_id: AssocId,
}

impl SendInfo {
    pub(crate) fn to_sys(self) -> sys::sctp_sndinfo {
        sys::sctp_sndinfo {
            snd_sid: self.sid,
            snd_flags: self.flags.bits(),
            snd_ppid: self.ppid.to_wire(),
            snd_context: self.context,
            snd_assoc_id: self.assoc_id.0,
        }
    }
}

/// Flags reported in [`RcvInfo`] (`rcv_flags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RcvFlags(u16);

impl RcvFlags {
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// The message was delivered unordered.
    pub const fn unordered(self) -> bool {
        self.0 & sys::SCTP_UNORDERED != 0
    }
}

/// Per-message receive metadata (`SCTP_RCVINFO` control message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RcvInfo {
    /// Stream id the message arrived on.
    pub sid: u16,
    /// Stream sequence number (0 for unordered messages).
    pub ssn: u16,
    pub flags: RcvFlags,
    /// Payload protocol identifier (host byte order; see [`Ppid`]).
    pub ppid: Ppid,
    /// Transmission sequence number of the (first chunk of the) message.
    pub tsn: u32,
    /// Cumulative TSN at delivery time.
    pub cumtsn: u32,
    pub context: u32,
    /// Association the message belongs to.
    pub assoc_id: AssocId,
}

impl RcvInfo {
    pub(crate) fn from_sys(raw: &sys::sctp_rcvinfo) -> RcvInfo {
        RcvInfo {
            sid: raw.rcv_sid,
            ssn: raw.rcv_ssn,
            flags: RcvFlags(raw.rcv_flags),
            ppid: Ppid::from_wire(raw.rcv_ppid),
            tsn: raw.rcv_tsn,
            cumtsn: raw.rcv_cumtsn,
            context: raw.rcv_context,
            assoc_id: AssocId(raw.rcv_assoc_id),
        }
    }
}

/// One received item: either user data or (if subscribed) an event.
///
/// The kernel interleaves notifications with data on the same socket buffer,
/// so a single receive path returning both preserves ordering. Data payloads
/// are written into the caller-supplied buffer (`len` bytes); notifications
/// are parsed into an owned [`Notification`].
#[derive(Debug)]
pub enum RecvMsg {
    Data {
        /// Number of payload bytes written into the caller's buffer.
        ///
        /// **`len == 0` (with `info: None`) signals end-of-association**:
        /// the peer closed and no more data will arrive — the SCTP
        /// counterpart of a zero-length `TcpStream` read. Receive loops
        /// must break on it (further reads keep returning it).
        len: usize,
        /// Receive metadata. Always present for data in practice: sockets
        /// created by this crate enable `SCTP_RECVRCVINFO`. `None` on the
        /// zero-length EOF read, or on a foreign fd without that option.
        info: Option<RcvInfo>,
        /// `MSG_EOR`: the buffer holds a complete message. `false` means the
        /// message was larger than the buffer (partial delivery); the
        /// remainder arrives in subsequent reads on the same stream.
        eor: bool,
    },
    Notification(Notification),
}

// -------------------------------------------------------------------------
// Socket / association parameters
// -------------------------------------------------------------------------

/// `SCTP_INITMSG`: parameters carried in the INIT / INIT-ACK chunk.
///
/// Must be configured before association setup. A zero field keeps the
/// kernel default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InitParams {
    /// Number of outgoing streams requested.
    pub num_ostreams: u16,
    /// Maximum number of incoming streams accepted.
    pub max_instreams: u16,
    /// Maximum INIT retransmissions.
    pub max_attempts: u16,
    /// Maximum INIT retransmission timeout in milliseconds.
    pub max_init_timeo: u16,
}

impl InitParams {
    pub(crate) fn to_sys(self) -> sys::sctp_initmsg {
        sys::sctp_initmsg {
            sinit_num_ostreams: self.num_ostreams,
            sinit_max_instreams: self.max_instreams,
            sinit_max_attempts: self.max_attempts,
            sinit_max_init_timeo: self.max_init_timeo,
        }
    }

    pub(crate) fn from_sys(raw: &sys::sctp_initmsg) -> InitParams {
        InitParams {
            num_ostreams: raw.sinit_num_ostreams,
            max_instreams: raw.sinit_max_instreams,
            max_attempts: raw.sinit_max_attempts,
            max_init_timeo: raw.sinit_max_init_timeo,
        }
    }
}

/// `SCTP_RTOINFO`: retransmission timeout bounds, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtoInfo {
    pub initial: u32,
    pub max: u32,
    pub min: u32,
}

/// Association state (`sstat_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssocState {
    Empty,
    Closed,
    CookieWait,
    CookieEchoed,
    Established,
    ShutdownPending,
    ShutdownSent,
    ShutdownReceived,
    ShutdownAckSent,
    Unknown(i32),
}

impl AssocState {
    pub(crate) fn from_raw(v: i32) -> AssocState {
        match v {
            sys::SCTP_STATE_EMPTY => AssocState::Empty,
            sys::SCTP_STATE_CLOSED => AssocState::Closed,
            sys::SCTP_STATE_COOKIE_WAIT => AssocState::CookieWait,
            sys::SCTP_STATE_COOKIE_ECHOED => AssocState::CookieEchoed,
            sys::SCTP_STATE_ESTABLISHED => AssocState::Established,
            sys::SCTP_STATE_SHUTDOWN_PENDING => AssocState::ShutdownPending,
            sys::SCTP_STATE_SHUTDOWN_SENT => AssocState::ShutdownSent,
            sys::SCTP_STATE_SHUTDOWN_RECEIVED => AssocState::ShutdownReceived,
            sys::SCTP_STATE_SHUTDOWN_ACK_SENT => AssocState::ShutdownAckSent,
            other => AssocState::Unknown(other),
        }
    }
}

/// Reachability state of one peer address (`spinfo_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddrState {
    /// Confirmed unreachable; not used for data transfer.
    Inactive,
    /// Potentially failed (intermediate state, exposed on newer kernels).
    PotentiallyFailed,
    /// Confirmed and available for data transfer.
    Active,
    /// Learned from INIT/INIT-ACK but not yet confirmed by heartbeat.
    Unconfirmed,
    Unknown(i32),
}

impl PeerAddrState {
    pub(crate) fn from_raw(v: i32) -> PeerAddrState {
        match v {
            sys::SCTP_INACTIVE => PeerAddrState::Inactive,
            sys::SCTP_PF => PeerAddrState::PotentiallyFailed,
            sys::SCTP_ACTIVE => PeerAddrState::Active,
            sys::SCTP_UNCONFIRMED => PeerAddrState::Unconfirmed,
            other => PeerAddrState::Unknown(other),
        }
    }
}

/// Per-path information (`SCTP_GET_PEER_ADDR_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddrInfo {
    pub assoc_id: AssocId,
    /// The peer address this entry describes; `None` if the kernel returned
    /// an address family this crate does not understand.
    pub address: Option<SocketAddr>,
    pub state: PeerAddrState,
    /// Congestion window for this path, in bytes.
    pub cwnd: u32,
    /// Smoothed round-trip time, in milliseconds.
    pub srtt: u32,
    /// Current retransmission timeout, in milliseconds.
    pub rto: u32,
    /// Path MTU.
    pub mtu: u32,
}

impl PeerAddrInfo {
    pub(crate) fn from_sys(raw: &sys::sctp_paddrinfo) -> PeerAddrInfo {
        // Fields are copied out by value; taking references into a packed
        // struct is not allowed.
        let addr_bytes = raw.spinfo_address.bytes;
        PeerAddrInfo {
            assoc_id: AssocId(raw.spinfo_assoc_id),
            address: crate::addr::read_sockaddr(&addr_bytes).map(|(a, _)| a),
            state: PeerAddrState::from_raw(raw.spinfo_state),
            cwnd: raw.spinfo_cwnd,
            srtt: raw.spinfo_srtt,
            rto: raw.spinfo_rto,
            mtu: raw.spinfo_mtu,
        }
    }
}

/// Flags for [`PeerAddrParams`] (`spp_flags`).
///
/// The enable/disable pairs are tri-state selectors: setting neither bit
/// leaves the corresponding feature unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SppFlags(u32);

impl SppFlags {
    pub const NONE: SppFlags = SppFlags(0);
    /// Enable heartbeats on the address(es).
    pub const HB_ENABLE: SppFlags = SppFlags(sys::SPP_HB_ENABLE);
    /// Disable heartbeats on the address(es).
    pub const HB_DISABLE: SppFlags = SppFlags(sys::SPP_HB_DISABLE);
    /// Send a heartbeat immediately (one-shot).
    pub const HB_DEMAND: SppFlags = SppFlags(sys::SPP_HB_DEMAND);
    /// Enable path MTU discovery.
    pub const PMTUD_ENABLE: SppFlags = SppFlags(sys::SPP_PMTUD_ENABLE);
    /// Disable path MTU discovery ([`PeerAddrParams::path_mtu`] then fixes
    /// the MTU).
    pub const PMTUD_DISABLE: SppFlags = SppFlags(sys::SPP_PMTUD_DISABLE);
    /// Enable delayed SACK.
    pub const SACKDELAY_ENABLE: SppFlags = SppFlags(sys::SPP_SACKDELAY_ENABLE);
    /// Disable delayed SACK.
    pub const SACKDELAY_DISABLE: SppFlags = SppFlags(sys::SPP_SACKDELAY_DISABLE);
    /// Set the heartbeat delay to zero (jitter-only spacing).
    pub const HB_TIME_IS_ZERO: SppFlags = SppFlags(sys::SPP_HB_TIME_IS_ZERO);
    /// Apply [`PeerAddrParams::ipv6_flowlabel`].
    pub const IPV6_FLOWLABEL: SppFlags = SppFlags(sys::SPP_IPV6_FLOWLABEL);
    /// Apply [`PeerAddrParams::dscp`].
    pub const DSCP: SppFlags = SppFlags(sys::SPP_DSCP);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits(bits: u32) -> SppFlags {
        SppFlags(bits)
    }

    pub const fn contains(self, other: SppFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for SppFlags {
    type Output = SppFlags;
    fn bitor(self, rhs: SppFlags) -> SppFlags {
        SppFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for SppFlags {
    fn bitor_assign(&mut self, rhs: SppFlags) {
        self.0 |= rhs.0;
    }
}

/// Per-path tunables (`SCTP_PEER_ADDR_PARAMS`): heartbeat interval, path
/// failure threshold, PMTU control.
///
/// When setting, zero-valued numeric fields keep their current values; the
/// [`SppFlags`] enable/disable bits select what changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerAddrParams {
    /// Heartbeat interval in milliseconds.
    pub hb_interval: u32,
    /// Retransmissions to an address before it is considered unreachable.
    pub path_max_rxt: u16,
    /// Fixed path MTU, used when PMTU discovery is disabled.
    pub path_mtu: u32,
    /// Delayed SACK time in milliseconds.
    pub sack_delay: u32,
    pub flags: SppFlags,
    /// IPv6 flow label (applied with [`SppFlags::IPV6_FLOWLABEL`]).
    pub ipv6_flowlabel: u32,
    /// DSCP value (applied with [`SppFlags::DSCP`]).
    pub dscp: u8,
}

impl PeerAddrParams {
    pub(crate) fn from_sys(raw: &sys::sctp_paddrparams) -> PeerAddrParams {
        PeerAddrParams {
            hb_interval: raw.spp_hbinterval,
            path_max_rxt: raw.spp_pathmaxrxt,
            path_mtu: raw.spp_pathmtu,
            sack_delay: raw.spp_sackdelay,
            flags: SppFlags(raw.spp_flags),
            ipv6_flowlabel: raw.spp_ipv6_flowlabel,
            dscp: raw.spp_dscp,
        }
    }
}

/// Association status snapshot (`SCTP_STATUS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssocStatus {
    pub assoc_id: AssocId,
    pub state: AssocState,
    /// Peer's current advertised receiver window, in bytes.
    pub rwnd: u32,
    /// Number of unacked DATA chunks.
    pub unackdata: u16,
    /// Number of DATA chunks pending receipt.
    pub penddata: u16,
    /// Negotiated number of inbound streams.
    pub instrms: u16,
    /// Negotiated number of outbound streams
    /// (`min(local ostreams, peer max_instreams)`).
    pub outstrms: u16,
    /// Message size above which the kernel fragments user messages.
    pub fragmentation_point: u32,
    /// Info about the current primary path.
    pub primary: PeerAddrInfo,
}

impl AssocStatus {
    pub(crate) fn from_sys(raw: &sys::sctp_status) -> AssocStatus {
        AssocStatus {
            assoc_id: AssocId(raw.sstat_assoc_id),
            state: AssocState::from_raw(raw.sstat_state),
            rwnd: raw.sstat_rwnd,
            unackdata: raw.sstat_unackdata,
            penddata: raw.sstat_penddata,
            instrms: raw.sstat_instrms,
            outstrms: raw.sstat_outstrms,
            fragmentation_point: raw.sstat_fragmentation_point,
            primary: PeerAddrInfo::from_sys(&raw.sstat_primary),
        }
    }
}

// -------------------------------------------------------------------------
// Event subscription
// -------------------------------------------------------------------------

/// Notification classes subscribable via `SCTP_EVENT` (kernel 4.11+).
///
/// Subscribed events are delivered inline through the receive path as
/// [`RecvMsg::Notification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Association established / lost / restarted ([`Notification::AssocChange`]).
    AssocChange,
    /// Per-path reachability changes ([`Notification::PeerAddrChange`]).
    PeerAddrChange,
    /// Legacy send-failure event carrying `sctp_sndrcvinfo`.
    SendFailed,
    /// Peer sent an operational ERROR chunk.
    RemoteError,
    /// Peer initiated a graceful shutdown.
    Shutdown,
    /// Partial delivery API events (e.g. aborted partial delivery).
    PartialDelivery,
    /// Peer's adaptation layer indication.
    AdaptationIndication,
    /// SCTP-AUTH key events.
    Authentication,
    /// Send queue drained (nothing left to transmit or retransmit).
    SenderDry,
    /// Incoming/outgoing stream reset (RFC 6525).
    StreamReset,
    /// Association reset (RFC 6525).
    AssocReset,
    /// Stream count change (RFC 6525 ADD_STREAMS).
    StreamChange,
    /// New-style send-failure event (kernel 5.10+).
    SendFailedEvent,
}

impl EventType {
    pub(crate) fn to_raw(self) -> u16 {
        match self {
            EventType::AssocChange => sys::SCTP_ASSOC_CHANGE,
            EventType::PeerAddrChange => sys::SCTP_PEER_ADDR_CHANGE,
            EventType::SendFailed => sys::SCTP_SEND_FAILED,
            EventType::RemoteError => sys::SCTP_REMOTE_ERROR,
            EventType::Shutdown => sys::SCTP_SHUTDOWN_EVENT,
            EventType::PartialDelivery => sys::SCTP_PARTIAL_DELIVERY_EVENT,
            EventType::AdaptationIndication => sys::SCTP_ADAPTATION_INDICATION,
            EventType::Authentication => sys::SCTP_AUTHENTICATION_EVENT,
            EventType::SenderDry => sys::SCTP_SENDER_DRY_EVENT,
            EventType::StreamReset => sys::SCTP_STREAM_RESET_EVENT,
            EventType::AssocReset => sys::SCTP_ASSOC_RESET_EVENT,
            EventType::StreamChange => sys::SCTP_STREAM_CHANGE_EVENT,
            EventType::SendFailedEvent => sys::SCTP_SEND_FAILED_EVENT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_wire_conversion_is_big_endian() {
        // NGAP = 60 must appear as 00 00 00 3c on the wire.
        assert_eq!(Ppid::NGAP.to_wire().to_ne_bytes(), [0, 0, 0, 60]);
        assert_eq!(
            Ppid::from_wire(u32::from_ne_bytes([0, 0, 0, 60])),
            Ppid::NGAP
        );
        assert_eq!(Ppid::from_wire(Ppid::M3UA.to_wire()), Ppid::M3UA);
    }

    #[test]
    fn send_flags_compose() {
        let f = SendFlags::UNORDERED | SendFlags::SACK_IMMEDIATELY;
        assert!(f.contains(SendFlags::UNORDERED));
        assert!(!f.contains(SendFlags::ABORT));
        assert_eq!(f.bits(), 0x9);
    }

    #[test]
    fn state_mappings() {
        assert_eq!(AssocState::from_raw(4), AssocState::Established);
        assert_eq!(AssocState::from_raw(99), AssocState::Unknown(99));
        assert_eq!(PeerAddrState::from_raw(2), PeerAddrState::Active);
        assert_eq!(
            PeerAddrState::from_raw(0xffff),
            PeerAddrState::Unknown(0xffff)
        );
    }
}
