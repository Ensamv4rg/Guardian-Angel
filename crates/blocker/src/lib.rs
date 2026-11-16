//! Blocking (FR-7). Today: a local DNS resolver that blocks tracker domains
//! by profile, with user allow/block lists, a pause switch and domains that
//! are never blocked.
//!
//! This crate never changes Windows' DNS settings. Pointing Windows at the
//! resolver, with a snapshot and automatic rollback (FR-8, NFR-9, NFR-11),
//! belongs to the background service.

pub mod policy;
pub mod resolver;

#[cfg(windows)]
pub mod upstream;

pub use policy::{AllowReason, Decision, Policy, Profile};
pub use resolver::{BlockStats, DnsBlocker, ResolverConfig};

#[cfg(test)]
mod tests;
