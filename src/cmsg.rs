//! Manual construction and parsing of Linux control messages (`cmsghdr`).
//!
//! The Linux `struct cmsghdr` is `{ size_t cmsg_len; int cmsg_level; int
//! cmsg_type; }` followed by the payload, with everything aligned to
//! `size_of::<usize>()`. Implementing it by hand (instead of via the libc
//! `CMSG_*` macros) keeps this module pure so it can be unit-tested on any
//! platform, and lets buffers live on the stack with no libc types involved.
//!
//! Note: the layout matches the kernel only when the build target's pointer
//! width equals the kernel's (i.e. no 32-bit userland on a 64-bit kernel);
//! that is the standard assumption for pure-Rust cmsg handling.

/// Aligns `n` up to the cmsg alignment boundary (`size_of::<usize>()`).
pub(crate) const fn align(n: usize) -> usize {
    (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// Byte length of an aligned `cmsghdr` (16 on 64-bit, 12 on 32-bit).
pub(crate) const HDR_LEN: usize = align(size_of::<usize>() + 4 + 4);

/// Total buffer space one control message with a `data_len`-byte payload
/// occupies (`CMSG_SPACE`).
pub(crate) const fn space(data_len: usize) -> usize {
    HDR_LEN + align(data_len)
}

/// Value stored in `cmsg_len` for a `data_len`-byte payload (`CMSG_LEN`).
pub(crate) const fn cmsg_len(data_len: usize) -> usize {
    HDR_LEN + data_len
}

/// Writes one control message into the head of `buf` and returns the number
/// of bytes used (`space(data.len())`). Padding bytes are zeroed.
pub(crate) fn write(buf: &mut [u8], level: i32, ty: i32, data: &[u8]) -> usize {
    let total = space(data.len());
    assert!(buf.len() >= total, "cmsg buffer too small");
    let p = size_of::<usize>();
    buf[..total].fill(0);
    buf[..p].copy_from_slice(&cmsg_len(data.len()).to_ne_bytes());
    buf[p..p + 4].copy_from_slice(&level.to_ne_bytes());
    buf[p + 4..p + 8].copy_from_slice(&ty.to_ne_bytes());
    buf[HDR_LEN..HDR_LEN + data.len()].copy_from_slice(data);
    total
}

/// Iterates over the control messages in a received control buffer,
/// yielding `(cmsg_level, cmsg_type, payload)`.
pub(crate) struct Iter<'a> {
    buf: &'a [u8],
}

pub(crate) fn iter(buf: &[u8]) -> Iter<'_> {
    Iter { buf }
}

impl<'a> Iterator for Iter<'a> {
    type Item = (i32, i32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < HDR_LEN {
            return None;
        }
        let p = size_of::<usize>();
        let mut len_bytes = [0u8; size_of::<usize>()];
        len_bytes.copy_from_slice(&self.buf[..p]);
        let cmsg_len = usize::from_ne_bytes(len_bytes);
        if cmsg_len < HDR_LEN || cmsg_len > self.buf.len() {
            return None;
        }
        let level = i32::from_ne_bytes(self.buf[p..p + 4].try_into().unwrap());
        let ty = i32::from_ne_bytes(self.buf[p + 4..p + 8].try_into().unwrap());
        let data = &self.buf[HDR_LEN..cmsg_len];
        let advance = align(cmsg_len).min(self.buf.len());
        self.buf = &self.buf[advance..];
        Some((level, ty, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys;

    #[test]
    fn constants_match_kernel_macros() {
        // Mirrors CMSG_ALIGN / CMSG_SPACE / CMSG_LEN for this pointer width.
        let p = size_of::<usize>();
        assert_eq!(HDR_LEN, if p == 8 { 16 } else { 12 });
        assert_eq!(space(16), HDR_LEN + 16);
        assert_eq!(cmsg_len(16), HDR_LEN + 16);
        assert_eq!(align(1), p);
    }

    #[test]
    fn write_then_iterate_roundtrip() {
        let sndinfo = [0xabu8; 16];
        let mut buf = [0u8; 64];
        let used = write(
            &mut buf,
            sys::IPPROTO_SCTP,
            sys::SCTP_CMSG_SNDINFO,
            &sndinfo,
        );
        assert_eq!(used, space(16));

        let items: Vec<_> = iter(&buf[..used]).collect();
        assert_eq!(items.len(), 1);
        let (level, ty, data) = items[0];
        assert_eq!(level, sys::IPPROTO_SCTP);
        assert_eq!(ty, sys::SCTP_CMSG_SNDINFO);
        assert_eq!(data, &sndinfo);
    }

    #[test]
    fn iterates_multiple_messages() {
        let mut buf = [0u8; 128];
        let a = write(&mut buf, 1, 10, &[1, 2, 3]);
        let b = write(&mut buf[a..], 2, 20, &[4; 28]);
        let items: Vec<_> = iter(&buf[..a + b]).collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (1, 10, &[1u8, 2, 3][..]));
        assert_eq!(items[1].0, 2);
        assert_eq!(items[1].2.len(), 28);
    }

    #[test]
    fn stops_on_truncated_or_bogus_header() {
        let mut buf = [0u8; 64];
        let used = write(&mut buf, 1, 1, &[0; 8]);
        // Truncate mid-header.
        assert_eq!(iter(&buf[..HDR_LEN - 1]).count(), 0);
        // Corrupt cmsg_len to exceed the buffer.
        buf[..size_of::<usize>()].copy_from_slice(&usize::MAX.to_ne_bytes());
        assert_eq!(iter(&buf[..used]).count(), 0);
    }
}
