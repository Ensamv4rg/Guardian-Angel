//! Windows privacy settings and per-app permission history (FR-3).
//!
//! Read-only: this module never changes a setting. Changing settings belongs
//! to the blocker crate, which snapshots values first (FR-8).

mod app_access;
pub mod registry;
mod settings;

use ga_core::PrivacyScan;
pub use registry::{Hive, Registry};

#[cfg(windows)]
pub use registry::WindowsRegistry;

/// Scans the current user's Windows privacy settings.
#[cfg(windows)]
pub fn scan_privacy() -> PrivacyScan {
    scan_privacy_with(&WindowsRegistry::default())
}

/// Scans privacy settings from any registry source.
pub fn scan_privacy_with(reg: &dyn Registry) -> PrivacyScan {
    PrivacyScan {
        settings: settings::read_settings(reg),
        app_access: app_access::read_app_access(reg),
    }
}

#[cfg(test)]
mod tests;
