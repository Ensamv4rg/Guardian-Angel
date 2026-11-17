//! Thin wrappers over Windows APIs that the `windows` crate only exposes as
//! `unsafe`. This is the only crate in the workspace allowed to use `unsafe`;
//! every block states why it is sound. Keep wrappers small and boring.

#[cfg(windows)]
mod identity;
#[cfg(windows)]
pub mod inet_proxy;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod processes;
#[cfg(windows)]
mod tcp;
#[cfg(windows)]
mod windows_list;

#[cfg(windows)]
pub use windows_list::processes_with_windows;

#[cfg(windows)]
pub use identity::{SERVICE_PIPE_SDDL, create_secure_pipe, pipe_client_sid, process_user_sid};
#[cfg(windows)]
pub use process::process_image_path;
#[cfg(windows)]
pub use processes::{ProcessEntry, running_processes};
#[cfg(windows)]
pub use tcp::tcp_connection_owner;

#[cfg(all(test, windows))]
mod inet_proxy_tests {
    /// Reads the real setting (read-only; never changes it).
    #[test]
    fn reads_the_current_proxy_setting() {
        let setting = super::inet_proxy::current_proxy().expect("WinInet answers");
        assert!(setting.flags & super::inet_proxy::PROXY_TYPE_DIRECT != 0 || setting.flags != 0);
    }
}