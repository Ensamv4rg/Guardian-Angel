//! The Guardian Angel engine: everything the service does, behind the IPC
//! protocol. It keeps scan results per user, raises alerts when something
//! gets worse, runs the network monitor and hosts the inspection proxy.
//!
//! Each request is answered for one user only (identified by the service
//! from the pipe connection), so one user never sees another's data. The
//! network monitor is machine-wide and shows program names only.

pub mod alerts;
pub mod context;
pub mod score;

#[cfg(windows)]
pub mod blocking;
#[cfg(windows)]
mod engine;

pub use context::UserContext;

#[cfg(windows)]
pub use engine::{Engine, EngineConfig, UserSlot, unix_now};

#[cfg(all(test, windows))]
mod tests;
