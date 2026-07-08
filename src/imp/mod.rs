//! Implementation selection (mio's `sys/unix` + `sys/shell` pattern).
//!
//! This crate is Linux-only by nature, so the split is not "per OS" but
//! "real vs stub": `kernel` talks to the Linux kernel, while `stub`
//! provides the same interface returning `ErrorKind::Unsupported` so the
//! crate compiles (but does not operate) on every other platform.

#[cfg(target_os = "linux")]
mod kernel;
#[cfg(target_os = "linux")]
pub(crate) use kernel::Socket;

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub(crate) use stub::Socket;
