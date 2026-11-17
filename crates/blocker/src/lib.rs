//! Blocking and fixing (FR-7, FR-8):
//! - `settings`: privacy setting changes with a journal and undo.
//! - `resolver` and `policy`: a local DNS resolver that blocks tracker
//!   domains by profile, with user allow/block lists, a pause switch and
//!   domains that are never blocked.
//!
//! - `switch`: pointing Windows' network adapters at the resolver, with a
//!   snapshot so every adapter can be put back exactly as it was.

pub mod policy;
pub mod resolver;
pub mod settings;
pub mod switch;
#[cfg(windows)]
pub mod system_dns;

#[cfg(windows)]
pub mod upstream;

pub use policy::{AllowReason, Decision, Policy, Profile};
pub use resolver::{BlockStats, DnsBlocker, ResolverConfig, ResolverControl, probe};

#[cfg(test)]
mod tests;
