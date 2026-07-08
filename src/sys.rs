//! Raw constants and `#[repr(C)]` structures mirroring `<uapi/linux/sctp.h>`.
//!
//! Everything in this module compiles on every platform (the definitions are
//! plain integers and byte layouts), but the values describe the **Linux
//! kernel ABI** and are only meaningful when talking to a Linux kernel.
//!
//! Layout notes:
//! - Several kernel structs carry `__attribute__((packed, aligned(4)))`.
//!   GCC's `packed` lays out every member with alignment 1, so the Rust
//!   equivalents use `#[repr(C, packed)]`. Where the kernel's `aligned(4)`
//!   introduces tail padding (e.g. `sctp_paddrparams`: 155 → 156 bytes) an
//!   explicit padding field is added, because `repr(packed)` cannot be
//!   combined with `repr(align)` (E0587).
//! - [`sockaddr_storage`] is defined as a plain 128-byte blob with alignment
//!   1 instead of the kernel's pointer-aligned union. A `repr(packed)` struct
//!   may not transitively contain a `repr(align)` type (E0588), and all
//!   structs in this module that embed it are packed, so the field offsets
//!   still match the kernel exactly.

#![allow(non_camel_case_types)]

pub type sctp_assoc_t = i32;

// -------------------------------------------------------------------------
// Protocol / level
// -------------------------------------------------------------------------

pub const IPPROTO_SCTP: i32 = 132;
pub const SOL_SCTP: i32 = 132;

/// Linux address family values (used inside kernel-provided sockaddr blobs).
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

// -------------------------------------------------------------------------
// Association id wildcards
// -------------------------------------------------------------------------

pub const SCTP_FUTURE_ASSOC: sctp_assoc_t = 0;
pub const SCTP_CURRENT_ASSOC: sctp_assoc_t = 1;
pub const SCTP_ALL_ASSOC: sctp_assoc_t = 2;

// -------------------------------------------------------------------------
// Socket options (RFC 6458 section numbers in <uapi/linux/sctp.h>)
// -------------------------------------------------------------------------

pub const SCTP_RTOINFO: i32 = 0;
pub const SCTP_ASSOCINFO: i32 = 1;
pub const SCTP_INITMSG: i32 = 2;
pub const SCTP_NODELAY: i32 = 3;
pub const SCTP_AUTOCLOSE: i32 = 4;
pub const SCTP_SET_PEER_PRIMARY_ADDR: i32 = 5;
pub const SCTP_PRIMARY_ADDR: i32 = 6;
pub const SCTP_ADAPTATION_LAYER: i32 = 7;
pub const SCTP_DISABLE_FRAGMENTS: i32 = 8;
pub const SCTP_PEER_ADDR_PARAMS: i32 = 9;
pub const SCTP_DEFAULT_SEND_PARAM: i32 = 10;
pub const SCTP_EVENTS: i32 = 11;
pub const SCTP_I_WANT_MAPPED_V4_ADDR: i32 = 12;
pub const SCTP_MAXSEG: i32 = 13;
pub const SCTP_STATUS: i32 = 14;
pub const SCTP_GET_PEER_ADDR_INFO: i32 = 15;
pub const SCTP_DELAYED_ACK_TIME: i32 = 16;
pub const SCTP_CONTEXT: i32 = 17;
pub const SCTP_FRAGMENT_INTERLEAVE: i32 = 18;
pub const SCTP_PARTIAL_DELIVERY_POINT: i32 = 19;
pub const SCTP_MAX_BURST: i32 = 20;
pub const SCTP_AUTH_CHUNK: i32 = 21;
pub const SCTP_HMAC_IDENT: i32 = 22;
pub const SCTP_AUTH_KEY: i32 = 23;
pub const SCTP_AUTH_ACTIVE_KEY: i32 = 24;
pub const SCTP_AUTH_DELETE_KEY: i32 = 25;
pub const SCTP_PEER_AUTH_CHUNKS: i32 = 26;
pub const SCTP_LOCAL_AUTH_CHUNKS: i32 = 27;
pub const SCTP_GET_ASSOC_NUMBER: i32 = 28;
pub const SCTP_GET_ASSOC_ID_LIST: i32 = 29;
pub const SCTP_AUTO_ASCONF: i32 = 30;
pub const SCTP_PEER_ADDR_THLDS: i32 = 31;
pub const SCTP_RECVRCVINFO: i32 = 32;
pub const SCTP_RECVNXTINFO: i32 = 33;
pub const SCTP_DEFAULT_SNDINFO: i32 = 34;
pub const SCTP_AUTH_DEACTIVATE_KEY: i32 = 35;
pub const SCTP_REUSE_PORT: i32 = 36;
pub const SCTP_PEER_ADDR_THLDS_V2: i32 = 37;

// "Internal" socket options implementing the library functions of RFC 6458.
pub const SCTP_SOCKOPT_BINDX_ADD: i32 = 100;
pub const SCTP_SOCKOPT_BINDX_REM: i32 = 101;
pub const SCTP_SOCKOPT_PEELOFF: i32 = 102;
pub const SCTP_SOCKOPT_CONNECTX_OLD: i32 = 107;
pub const SCTP_GET_PEER_ADDRS: i32 = 108;
pub const SCTP_GET_LOCAL_ADDRS: i32 = 109;
pub const SCTP_SOCKOPT_CONNECTX: i32 = 110;
pub const SCTP_SOCKOPT_CONNECTX3: i32 = 111;
pub const SCTP_GET_ASSOC_STATS: i32 = 112;
pub const SCTP_PR_SUPPORTED: i32 = 113;
pub const SCTP_DEFAULT_PRINFO: i32 = 114;
pub const SCTP_PR_ASSOC_STATUS: i32 = 115;
pub const SCTP_PR_STREAM_STATUS: i32 = 116;
pub const SCTP_RECONFIG_SUPPORTED: i32 = 117;
pub const SCTP_ENABLE_STREAM_RESET: i32 = 118;
pub const SCTP_RESET_STREAMS: i32 = 119;
pub const SCTP_RESET_ASSOC: i32 = 120;
pub const SCTP_ADD_STREAMS: i32 = 121;
pub const SCTP_SOCKOPT_PEELOFF_FLAGS: i32 = 122;
pub const SCTP_STREAM_SCHEDULER: i32 = 123;
pub const SCTP_STREAM_SCHEDULER_VALUE: i32 = 124;
pub const SCTP_INTERLEAVING_SUPPORTED: i32 = 125;
pub const SCTP_SENDMSG_CONNECT: i32 = 126;
pub const SCTP_EVENT: i32 = 127;
pub const SCTP_ASCONF_SUPPORTED: i32 = 128;
pub const SCTP_AUTH_SUPPORTED: i32 = 129;
pub const SCTP_ECN_SUPPORTED: i32 = 130;
pub const SCTP_EXPOSE_POTENTIALLY_FAILED_STATE: i32 = 131;
pub const SCTP_REMOTE_UDP_ENCAPS_PORT: i32 = 132;
pub const SCTP_PLPMTUD_PROBE_INTERVAL: i32 = 133;

// -------------------------------------------------------------------------
// cmsg types (enum sctp_cmsg_type)
// -------------------------------------------------------------------------

pub const SCTP_CMSG_INIT: i32 = 0;
pub const SCTP_CMSG_SNDRCV: i32 = 1;
pub const SCTP_CMSG_SNDINFO: i32 = 2;
pub const SCTP_CMSG_RCVINFO: i32 = 3;
pub const SCTP_CMSG_NXTINFO: i32 = 4;
pub const SCTP_CMSG_PRINFO: i32 = 5;
pub const SCTP_CMSG_AUTHINFO: i32 = 6;

// -------------------------------------------------------------------------
// sinfo_flags / msg_flags
// -------------------------------------------------------------------------

pub const SCTP_UNORDERED: u16 = 1 << 0;
pub const SCTP_ADDR_OVER: u16 = 1 << 1;
pub const SCTP_ABORT: u16 = 1 << 2;
pub const SCTP_SACK_IMMEDIATELY: u16 = 1 << 3;
pub const SCTP_SENDALL: u16 = 1 << 6;
pub const SCTP_PR_SCTP_ALL_FLAG: u16 = 1 << 7;
/// `MSG_FIN`: initiate graceful shutdown of the association with this send.
pub const SCTP_EOF: u16 = 0x200;

/// `msg_flags` bit marking a notification (Linux value).
pub const MSG_NOTIFICATION: i32 = 0x8000;
/// `MSG_EOR` (Linux value); set when a complete message was delivered.
pub const MSG_EOR: i32 = 0x80;

// -------------------------------------------------------------------------
// PR-SCTP policies
// -------------------------------------------------------------------------

pub const SCTP_PR_SCTP_NONE: u16 = 0x0000;
pub const SCTP_PR_SCTP_TTL: u16 = 0x0010;
pub const SCTP_PR_SCTP_RTX: u16 = 0x0020;
pub const SCTP_PR_SCTP_PRIO: u16 = 0x0030;

// -------------------------------------------------------------------------
// Notification types (enum sctp_sn_type)
// -------------------------------------------------------------------------

pub const SCTP_SN_TYPE_BASE: u16 = 1 << 15;
pub const SCTP_ASSOC_CHANGE: u16 = 0x8001;
pub const SCTP_PEER_ADDR_CHANGE: u16 = 0x8002;
pub const SCTP_SEND_FAILED: u16 = 0x8003;
pub const SCTP_REMOTE_ERROR: u16 = 0x8004;
pub const SCTP_SHUTDOWN_EVENT: u16 = 0x8005;
pub const SCTP_PARTIAL_DELIVERY_EVENT: u16 = 0x8006;
pub const SCTP_ADAPTATION_INDICATION: u16 = 0x8007;
pub const SCTP_AUTHENTICATION_EVENT: u16 = 0x8008;
pub const SCTP_SENDER_DRY_EVENT: u16 = 0x8009;
pub const SCTP_STREAM_RESET_EVENT: u16 = 0x800a;
pub const SCTP_ASSOC_RESET_EVENT: u16 = 0x800b;
pub const SCTP_STREAM_CHANGE_EVENT: u16 = 0x800c;
pub const SCTP_SEND_FAILED_EVENT: u16 = 0x800d;

// enum sctp_sac_state
pub const SCTP_COMM_UP: u16 = 0;
pub const SCTP_COMM_LOST: u16 = 1;
pub const SCTP_RESTART: u16 = 2;
pub const SCTP_SHUTDOWN_COMP: u16 = 3;
pub const SCTP_CANT_STR_ASSOC: u16 = 4;

// enum sctp_spc_state
pub const SCTP_ADDR_AVAILABLE: i32 = 0;
pub const SCTP_ADDR_UNREACHABLE: i32 = 1;
pub const SCTP_ADDR_REMOVED: i32 = 2;
pub const SCTP_ADDR_ADDED: i32 = 3;
pub const SCTP_ADDR_MADE_PRIM: i32 = 4;
pub const SCTP_ADDR_CONFIRMED: i32 = 5;
pub const SCTP_ADDR_POTENTIALLY_FAILED: i32 = 6;

// enum sctp_ssf_flags
pub const SCTP_DATA_UNSENT: u16 = 0;
pub const SCTP_DATA_SENT: u16 = 1;

// enum sctp_spinfo_state (peer address / transport state)
pub const SCTP_INACTIVE: i32 = 0;
pub const SCTP_PF: i32 = 1;
pub const SCTP_ACTIVE: i32 = 2;
pub const SCTP_UNCONFIRMED: i32 = 3;
pub const SCTP_UNKNOWN: i32 = 0xffff;

// enum sctp_sstat_state (association state)
pub const SCTP_STATE_EMPTY: i32 = 0;
pub const SCTP_STATE_CLOSED: i32 = 1;
pub const SCTP_STATE_COOKIE_WAIT: i32 = 2;
pub const SCTP_STATE_COOKIE_ECHOED: i32 = 3;
pub const SCTP_STATE_ESTABLISHED: i32 = 4;
pub const SCTP_STATE_SHUTDOWN_PENDING: i32 = 5;
pub const SCTP_STATE_SHUTDOWN_SENT: i32 = 6;
pub const SCTP_STATE_SHUTDOWN_RECEIVED: i32 = 7;
pub const SCTP_STATE_SHUTDOWN_ACK_SENT: i32 = 8;

// Flags in sctp_stream_reset_event / sctp_assoc_reset_event /
// sctp_stream_change_event headers.
pub const SCTP_STREAM_RESET_INCOMING_SSN: u16 = 0x0001;
pub const SCTP_STREAM_RESET_OUTGOING_SSN: u16 = 0x0002;
pub const SCTP_STREAM_RESET_DENIED: u16 = 0x0004;
pub const SCTP_STREAM_RESET_FAILED: u16 = 0x0008;
pub const SCTP_ASSOC_RESET_DENIED: u16 = 0x0004;
pub const SCTP_ASSOC_RESET_FAILED: u16 = 0x0008;
pub const SCTP_STREAM_CHANGE_DENIED: u16 = 0x0004;
pub const SCTP_STREAM_CHANGE_FAILED: u16 = 0x0008;

// sctp_bindx() flags
pub const SCTP_BINDX_ADD_ADDR: i32 = 0x01;
pub const SCTP_BINDX_REM_ADDR: i32 = 0x02;

// -------------------------------------------------------------------------
// Structures
// -------------------------------------------------------------------------

/// Linux `struct __kernel_sockaddr_storage` as an opaque 128-byte blob.
///
/// Alignment is 1 (see module docs); always read/write through it with
/// unaligned accesses or byte copies.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_storage {
    pub bytes: [u8; 128],
}

impl sockaddr_storage {
    pub const fn zeroed() -> Self {
        sockaddr_storage { bytes: [0; 128] }
    }
}

impl Default for sockaddr_storage {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_initmsg {
    pub sinit_num_ostreams: u16,
    pub sinit_max_instreams: u16,
    pub sinit_max_attempts: u16,
    pub sinit_max_init_timeo: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_sndrcvinfo {
    pub sinfo_stream: u16,
    pub sinfo_ssn: u16,
    pub sinfo_flags: u16,
    pub sinfo_ppid: u32,
    pub sinfo_context: u32,
    pub sinfo_timetolive: u32,
    pub sinfo_tsn: u32,
    pub sinfo_cumtsn: u32,
    pub sinfo_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_sndinfo {
    pub snd_sid: u16,
    pub snd_flags: u16,
    pub snd_ppid: u32,
    pub snd_context: u32,
    pub snd_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_rcvinfo {
    pub rcv_sid: u16,
    pub rcv_ssn: u16,
    pub rcv_flags: u16,
    pub rcv_ppid: u32,
    pub rcv_tsn: u32,
    pub rcv_cumtsn: u32,
    pub rcv_context: u32,
    pub rcv_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_nxtinfo {
    pub nxt_sid: u16,
    pub nxt_flags: u16,
    pub nxt_ppid: u32,
    pub nxt_length: u32,
    pub nxt_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_prinfo {
    pub pr_policy: u16,
    pub pr_value: u32,
}

/// `SCTP_EVENT` socket option payload (kernel 4.11+).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_event {
    pub se_assoc_id: sctp_assoc_t,
    pub se_type: u16,
    pub se_on: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_rtoinfo {
    pub srto_assoc_id: sctp_assoc_t,
    pub srto_initial: u32,
    pub srto_max: u32,
    pub srto_min: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_assocparams {
    pub sasoc_assoc_id: sctp_assoc_t,
    pub sasoc_asocmaxrxt: u16,
    pub sasoc_number_peer_destinations: u16,
    pub sasoc_peer_rwnd: u32,
    pub sasoc_local_rwnd: u32,
    pub sasoc_cookie_life: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_assoc_value {
    pub assoc_id: sctp_assoc_t,
    pub assoc_value: u32,
}

/// Kernel: `__attribute__((packed, aligned(4)))`, size 152.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct sctp_paddrinfo {
    pub spinfo_assoc_id: sctp_assoc_t,
    pub spinfo_address: sockaddr_storage,
    pub spinfo_state: i32,
    pub spinfo_cwnd: u32,
    pub spinfo_srtt: u32,
    pub spinfo_rto: u32,
    pub spinfo_mtu: u32,
}

impl Default for sctp_paddrinfo {
    fn default() -> Self {
        // SAFETY: all-zero bytes are a valid value for every field.
        unsafe { core::mem::zeroed() }
    }
}

/// Size 176; embeds the packed `sctp_paddrinfo` at offset 24.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct sctp_status {
    pub sstat_assoc_id: sctp_assoc_t,
    pub sstat_state: i32,
    pub sstat_rwnd: u32,
    pub sstat_unackdata: u16,
    pub sstat_penddata: u16,
    pub sstat_instrms: u16,
    pub sstat_outstrms: u16,
    pub sstat_fragmentation_point: u32,
    pub sstat_primary: sctp_paddrinfo,
}

/// Kernel: `__attribute__((packed, aligned(4)))`, size 132.
/// Used for both `SCTP_PRIMARY_ADDR` and `SCTP_SET_PEER_PRIMARY_ADDR`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct sctp_prim {
    pub ssp_assoc_id: sctp_assoc_t,
    pub ssp_addr: sockaddr_storage,
}

impl Default for sctp_prim {
    fn default() -> Self {
        // SAFETY: all-zero bytes are a valid value for every field.
        unsafe { core::mem::zeroed() }
    }
}

// enum sctp_spp_flags (for sctp_paddrparams.spp_flags)
pub const SPP_HB_ENABLE: u32 = 1 << 0;
pub const SPP_HB_DISABLE: u32 = 1 << 1;
pub const SPP_HB_DEMAND: u32 = 1 << 2;
pub const SPP_PMTUD_ENABLE: u32 = 1 << 3;
pub const SPP_PMTUD_DISABLE: u32 = 1 << 4;
pub const SPP_SACKDELAY_ENABLE: u32 = 1 << 5;
pub const SPP_SACKDELAY_DISABLE: u32 = 1 << 6;
pub const SPP_HB_TIME_IS_ZERO: u32 = 1 << 7;
pub const SPP_IPV6_FLOWLABEL: u32 = 1 << 8;
pub const SPP_DSCP: u32 = 1 << 9;

/// Kernel: `__attribute__((packed, aligned(4)))`.
///
/// GCC lays the members out with no padding at all (155 bytes) and then pads
/// the struct to 156 for `aligned(4)`; `_pad` reproduces that final byte.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct sctp_paddrparams {
    pub spp_assoc_id: sctp_assoc_t,
    pub spp_address: sockaddr_storage,
    pub spp_hbinterval: u32,
    pub spp_pathmaxrxt: u16,
    pub spp_pathmtu: u32,
    pub spp_sackdelay: u32,
    pub spp_flags: u32,
    pub spp_ipv6_flowlabel: u32,
    pub spp_dscp: u8,
    pub _pad: u8,
}

impl Default for sctp_paddrparams {
    fn default() -> Self {
        // SAFETY: all-zero bytes are a valid value for every field.
        unsafe { core::mem::zeroed() }
    }
}

/// `getsockopt(SCTP_SOCKOPT_PEELOFF)` argument.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_peeloff_arg_t {
    pub associd: sctp_assoc_t,
    pub sd: i32,
}

/// `getsockopt(SCTP_SOCKOPT_PEELOFF_FLAGS)` argument (kernel 4.15+);
/// `flags` accepts `SOCK_CLOEXEC` / `SOCK_NONBLOCK`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_peeloff_flags_arg_t {
    pub p_arg: sctp_peeloff_arg_t,
    pub flags: u32,
}

/// `getsockopt(SCTP_SOCKOPT_CONNECTX3)` argument. `addr_num` is the byte
/// length of the packed sockaddr array on input; `assoc_id` is set on output.
#[repr(C)]
pub struct sctp_getaddrs_old {
    pub assoc_id: sctp_assoc_t,
    pub addr_num: i32,
    pub addrs: *mut u8,
}

/// Header of the `SCTP_GET_PEER_ADDRS` / `SCTP_GET_LOCAL_ADDRS` result
/// buffer; `addr_num` packed sockaddrs follow immediately after.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sctp_getaddrs {
    pub assoc_id: sctp_assoc_t,
    pub addr_num: u32,
    // __u8 addrs[] follows
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    /// Sizes and offsets must match the kernel ABI on every architecture
    /// (none of these structs contain pointers or arch-dependent types).
    #[test]
    fn struct_layouts_match_kernel_abi() {
        assert_eq!(size_of::<sockaddr_storage>(), 128);
        assert_eq!(size_of::<sctp_initmsg>(), 8);
        assert_eq!(size_of::<sctp_sndrcvinfo>(), 32);
        assert_eq!(size_of::<sctp_sndinfo>(), 16);
        assert_eq!(size_of::<sctp_rcvinfo>(), 28);
        assert_eq!(size_of::<sctp_nxtinfo>(), 16);
        assert_eq!(size_of::<sctp_event>(), 8);
        assert_eq!(size_of::<sctp_rtoinfo>(), 16);
        assert_eq!(size_of::<sctp_assocparams>(), 20);
        assert_eq!(size_of::<sctp_assoc_value>(), 8);
        assert_eq!(size_of::<sctp_paddrinfo>(), 152);
        assert_eq!(size_of::<sctp_status>(), 176);
        assert_eq!(size_of::<sctp_prim>(), 132);
        assert_eq!(size_of::<sctp_paddrparams>(), 156);
        assert_eq!(size_of::<sctp_peeloff_arg_t>(), 8);
        assert_eq!(size_of::<sctp_peeloff_flags_arg_t>(), 12);
        assert_eq!(size_of::<sctp_getaddrs>(), 8);

        assert_eq!(offset_of!(sctp_rcvinfo, rcv_ppid), 8);
        assert_eq!(offset_of!(sctp_rcvinfo, rcv_assoc_id), 24);
        assert_eq!(offset_of!(sctp_sndinfo, snd_assoc_id), 12);

        assert_eq!(offset_of!(sctp_paddrinfo, spinfo_address), 4);
        assert_eq!(offset_of!(sctp_paddrinfo, spinfo_state), 132);
        assert_eq!(offset_of!(sctp_paddrinfo, spinfo_mtu), 148);

        assert_eq!(offset_of!(sctp_status, sstat_fragmentation_point), 20);
        assert_eq!(offset_of!(sctp_status, sstat_primary), 24);

        assert_eq!(offset_of!(sctp_paddrparams, spp_hbinterval), 132);
        assert_eq!(offset_of!(sctp_paddrparams, spp_pathmaxrxt), 136);
        assert_eq!(offset_of!(sctp_paddrparams, spp_pathmtu), 138);
        assert_eq!(offset_of!(sctp_paddrparams, spp_dscp), 154);

        assert_eq!(offset_of!(sctp_event, se_type), 4);
        assert_eq!(offset_of!(sctp_event, se_on), 6);
    }

    /// `sctp_getaddrs_old` contains a user pointer, so its layout is
    /// pointer-width dependent.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn getaddrs_old_layout_64bit() {
        assert_eq!(size_of::<sctp_getaddrs_old>(), 16);
        assert_eq!(offset_of!(sctp_getaddrs_old, addrs), 8);
    }
}
