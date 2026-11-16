//! Shared types for Guardian Angel.
//!
//! Every other crate depends on this one; it holds no logic beyond small
//! helpers, so scanners, the knowledge base and the report stay decoupled.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A browser whose profile data we can scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Vivaldi,
    Opera,
    OperaGx,
    Firefox,
}

impl fmt::Display for Browser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Brave => "Brave",
            Browser::Vivaldi => "Vivaldi",
            Browser::Opera => "Opera",
            Browser::OperaGx => "Opera GX",
            Browser::Firefox => "Firefox",
        })
    }
}

/// What kind of data collection a tracker domain is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Advertising,
    Analytics,
    Social,
    SessionRecording,
    AudienceData,
    AdVerification,
    TagManagement,
    CustomerData,
    /// A large platform's own domain (google.com, yandex.ru) that also tracks.
    Platform,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Category::Advertising => "Advertising",
            Category::Analytics => "Analytics",
            Category::Social => "Social",
            Category::SessionRecording => "Session recording",
            Category::AudienceData => "Audience data",
            Category::AdVerification => "Ad verification",
            Category::TagManagement => "Tag management",
            Category::CustomerData => "Customer data",
            Category::Platform => "Platform",
        })
    }
}

/// One cookie found in a browser profile.
///
/// Holds metadata only. Cookie values are never read (requirement NFR-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CookieRecord {
    pub browser: Browser,
    pub profile: String,
    /// Normalised host: lowercase, without a leading dot.
    pub host: String,
    pub name: String,
    /// Last time the browser sent this cookie, as Unix seconds.
    pub last_access_unix: Option<i64>,
}

/// Something that stopped part of a scan, reported to the user instead of failing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanWarning {
    pub browser: Browser,
    pub profile: String,
    pub message: String,
}

/// Result of scanning every browser profile for cookies.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CookieScan {
    pub cookies: Vec<CookieRecord>,
    pub warnings: Vec<ScanWarning>,
    pub profiles_scanned: usize,
}

/// Lowercases a host and strips the leading dot browsers use for domain cookies.
pub fn normalize_host(host: &str) -> String {
    host.trim().trim_start_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_dot_and_case() {
        assert_eq!(normalize_host(".DoubleClick.net"), "doubleclick.net");
        assert_eq!(normalize_host("  stats.g.doubleclick.net "), "stats.g.doubleclick.net");
    }

    #[test]
    fn category_serializes_as_snake_case() {
        let json = serde_json::to_string(&Category::SessionRecording).unwrap();
        assert_eq!(json, "\"session_recording\"");
        let back: Category = serde_json::from_str("\"ad_verification\"").unwrap();
        assert_eq!(back, Category::AdVerification);
    }
}
