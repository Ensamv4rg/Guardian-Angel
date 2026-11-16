//! Installed browser extensions and what they can access (FR-2).
//!
//! Reads browser preference files only; never changes or disables anything.

mod chromium;
mod firefox;
mod permissions;

use crate::browsers::{self, BrowserRoots};
use ga_core::{Browser, ExtensionScan, ScanWarning};

/// Scans every supported browser for the current Windows user.
pub fn scan_extensions() -> ExtensionScan {
    scan_extensions_in(&BrowserRoots::from_env())
}

/// Scans every supported browser under the given roots.
pub fn scan_extensions_in(roots: &BrowserRoots) -> ExtensionScan {
    let mut scan = ExtensionScan::default();

    for profile in browsers::chromium::profiles(roots) {
        scan.profiles_scanned += 1;
        match chromium::read_profile(&profile) {
            Ok(mut found) => scan.extensions.append(&mut found),
            Err(message) => warn(&mut scan, profile.browser, &profile.name, message),
        }
    }

    for (name, dir) in browsers::firefox::profiles(roots) {
        match firefox::read_profile(&dir, &name) {
            Ok(Some(mut found)) => {
                scan.profiles_scanned += 1;
                scan.extensions.append(&mut found);
            }
            Ok(None) => {}
            Err(message) => {
                scan.profiles_scanned += 1;
                warn(&mut scan, Browser::Firefox, &name, message);
            }
        }
    }

    // Riskiest first, then by name.
    scan.extensions.sort_by(|a, b| {
        a.risk
            .cmp(&b.risk)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.browser.cmp(&b.browser))
            .then_with(|| a.profile.cmp(&b.profile))
    });
    scan
}

fn warn(scan: &mut ExtensionScan, browser: Browser, profile: &str, message: String) {
    scan.warnings.push(ScanWarning {
        browser,
        profile: profile.to_owned(),
        message,
    });
}

#[cfg(test)]
mod tests;
