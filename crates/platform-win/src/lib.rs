//! Thin wrappers over Windows APIs that the `windows` crate only exposes as
//! `unsafe`. This is the only crate in the workspace allowed to use `unsafe`;
//! every block states why it is sound. Keep wrappers small and boring.

#[cfg(windows)]
mod identity;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod tcp;

#[cfg(windows)]
pub use identity::{SERVICE_PIPE_SDDL, create_secure_pipe, pipe_client_sid, process_user_sid};
#[cfg(windows)]
pub use process::process_image_path;
#[cfg(windows)]
pub use tcp::tcp_connection_owner;
