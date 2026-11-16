//! Network monitoring (FR-5). Today: which programs look up which domains,
//! from Windows' own DNS client events. Bytes and connections per process
//! (Kernel-Network ETW) come next.
//!
//! Limitation: programs that resolve names themselves (a browser with
//! DNS-over-HTTPS turned on, some VPN clients) bypass the Windows DNS client
//! and do not appear here. The local DNS resolver planned for blocking (FR-7)
//! closes most of that gap.

mod aggregator;

pub use aggregator::{Aggregator, MAX_ENTRIES, ProcessResolver};

#[cfg(windows)]
mod dns;

#[cfg(windows)]
pub use dns::{DnsMonitor, NetmonError};
