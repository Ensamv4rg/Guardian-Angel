//! Thin wrappers over Windows APIs that the `windows` crate only exposes as
//! `unsafe`. This is the only crate in the workspace allowed to use `unsafe`;
//! every block states why it is sound. Keep wrappers small and boring.

#[cfg(windows)]
mod process;

#[cfg(windows)]
pub use process::process_image_path;
