//! `guardian-service`: the Guardian Angel background service.
//!
//! - no arguments: started by Windows' Service Control Manager, runs as SYSTEM
//! - `console`: runs in this terminal as the current user (development)
//! - `install` / `uninstall`: registers or removes the service (administrator)
//!
//! Clients (the desktop UI, the CLI) talk to it over the named pipe in
//! `ga_ipc::PIPE_NAME`. Each connection is answered for the Windows user on
//! the other end only.

#[cfg(windows)]
mod windows_main;

#[cfg(windows)]
fn main() {
    if let Err(e) = windows_main::main() {
        eprintln!("guardian-service: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("guardian-service runs on Windows only.");
    std::process::exit(1);
}
