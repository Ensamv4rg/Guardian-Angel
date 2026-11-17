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
    /// Crash and error reports (Sentry, Bugsnag). Usually include device
    /// details and sometimes what you were doing when the app failed.
    ErrorReporting,
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
            Category::ErrorReporting => "Error reporting",
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

/// Which part of Windows a privacy setting belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum PrivacyArea {
    Diagnostics,
    Advertising,
    InputAndSpeech,
    ActivityTracking,
    Suggestions,
    Location,
}

impl fmt::Display for PrivacyArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PrivacyArea::Diagnostics => "Diagnostics",
            PrivacyArea::Advertising => "Advertising",
            PrivacyArea::InputAndSpeech => "Input and speech",
            PrivacyArea::ActivityTracking => "Activity tracking",
            PrivacyArea::Suggestions => "Suggestions and ads",
            PrivacyArea::Location => "Location",
        })
    }
}

/// Whether a setting's current value shares data or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Exposure {
    /// The current value sends or collects data.
    Exposed,
    /// The current value is the privacy-friendly one.
    Protected,
    /// The value is missing and Windows' default is not certain.
    Unknown,
}

/// One Windows privacy setting and what its current value means (FR-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivacySetting {
    /// Stable identifier, e.g. `advertising_id`.
    pub id: &'static str,
    pub area: PrivacyArea,
    pub title: &'static str,
    /// Current value in plain words, e.g. "Optional (full)".
    pub state: String,
    pub exposure: Exposure,
    /// What the setting does, written for non-technical users.
    pub explanation: &'static str,
    /// True when a Group Policy value decides the setting.
    pub set_by_policy: bool,
    /// Registry location the value was read from, for the details view.
    pub source: String,
}

/// A device capability that apps ask permission for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Capability {
    Location,
    Camera,
    Microphone,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Capability::Location => "Location",
            Capability::Camera => "Camera",
            Capability::Microphone => "Microphone",
        })
    }
}

/// An app's permission for, and recorded use of, a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppAccess {
    pub capability: Capability,
    /// Short display name, e.g. `chrome.exe` or `Microsoft.WindowsCamera`.
    pub app: String,
    /// Full executable path or package family name.
    pub identifier: String,
    /// Store (packaged) app, as opposed to a classic desktop program.
    pub packaged: bool,
    /// Store apps have an explicit Allow/Deny; desktop apps have none.
    pub allowed: Option<bool>,
    pub last_used_start_unix: Option<i64>,
    pub last_used_stop_unix: Option<i64>,
    /// Windows marks an app as using the capability right now.
    pub in_use_now: bool,
}

/// Result of scanning Windows privacy settings and app permissions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PrivacyScan {
    pub settings: Vec<PrivacySetting>,
    pub app_access: Vec<AppAccess>,
}

/// Where an extension was installed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum ExtensionSource {
    /// The browser's official store (Chrome Web Store, Edge Add-ons, addons.mozilla.org).
    Store,
    /// Installed by another program or the registry, not by the user from a store.
    Sideloaded,
    /// Forced by an organisation's policy.
    Policy,
    /// Loaded from a folder in developer mode.
    Developer,
    Unknown,
}

impl fmt::Display for ExtensionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ExtensionSource::Store => "Store",
            ExtensionSource::Sideloaded => "Installed by another program",
            ExtensionSource::Policy => "Installed by policy",
            ExtensionSource::Developer => "Developer mode",
            ExtensionSource::Unknown => "Unknown",
        })
    }
}

/// Which websites an extension can read and change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SiteAccess {
    AllSites,
    /// Host patterns such as `*.google.com`.
    SomeSites(Vec<String>),
    NoSites,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Risk {
    High,
    Medium,
    Low,
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Risk::High => "High",
            Risk::Medium => "Medium",
            Risk::Low => "Low",
        })
    }
}

/// A browser permission that gives access to personal data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SensitivePermission {
    pub permission: String,
    /// What it allows, in plain words.
    pub meaning: &'static str,
}

/// An installed browser extension and what it can access (FR-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserExtension {
    pub browser: Browser,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub source: ExtensionSource,
    pub site_access: SiteAccess,
    pub sensitive_permissions: Vec<SensitivePermission>,
    pub risk: Risk,
    /// Plain-language reasons for the risk level, most serious first.
    pub risk_reasons: Vec<String>,
}

/// Result of scanning every browser profile for extensions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ExtensionScan {
    pub extensions: Vec<BrowserExtension>,
    pub warnings: Vec<ScanWarning>,
    pub profiles_scanned: usize,
}

/// How often one program looked up one domain during a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessDomainStat {
    /// Executable name, e.g. `chrome.exe`, or `PID 1234` when it could not be read.
    pub process: String,
    /// Full executable path, when known.
    pub process_path: Option<String>,
    pub domain: String,
    pub lookups: u32,
    /// Lookups that returned an error (e.g. the domain does not exist).
    pub failed: u32,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}

/// DNS lookups per program, collected over a period of time (FR-5).
#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkCapture {
    pub started_unix: i64,
    pub ended_unix: i64,
    pub total_lookups: u64,
    pub stats: Vec<ProcessDomainStat>,
}

/// What kind of personal data a decoded tracker field carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataKind {
    /// Plain email address.
    Email,
    /// Hashed email address: still identifies you across sites.
    HashedEmail,
    /// Hashed phone, name, city or other personal detail.
    HashedPersonalDetail,
    /// Name, phone or other personal detail in plain text.
    PersonalDetail,
    /// The site's own account ID for you.
    UserId,
    /// Long-lived ID stored in your browser (cookie or local storage).
    PersistentId,
    /// ID from an ad you clicked.
    ClickId,
    PageUrl,
    PageTitle,
    Referrer,
    /// What you did: page view, add to cart, purchase, sign up.
    Event,
    /// Money: order value, currency, products.
    Purchase,
    /// Screen size, language, browser and device details.
    Device,
    /// Which website account receives the data.
    TrackerAccount,
    Other,
}

impl DataKind {
    /// Plain-language name used in summaries.
    pub fn describe(self) -> &'static str {
        match self {
            DataKind::Email => "your email address",
            DataKind::HashedEmail => "your email address (hashed, still identifies you)",
            DataKind::HashedPersonalDetail => "personal details (hashed)",
            DataKind::PersonalDetail => "personal details",
            DataKind::UserId => "your account ID on the site",
            DataKind::PersistentId => "a long-lived ID that recognises your browser",
            DataKind::ClickId => "the ad you clicked",
            DataKind::PageUrl => "the page you were on",
            DataKind::PageTitle => "the page title",
            DataKind::Referrer => "the page you came from",
            DataKind::Event => "what you did on the page",
            DataKind::Purchase => "purchase details",
            DataKind::Device => "device and browser details",
            DataKind::TrackerAccount => "the site's tracker account",
            DataKind::Other => "other details",
        }
    }
}

/// One decoded value from a tracker request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedField {
    /// Parameter name as sent, e.g. `cid` or `ud[em]`.
    pub key: String,
    /// Plain-language label, e.g. "Client ID".
    pub label: String,
    pub kind: DataKind,
    pub value: String,
}

/// A privacy choice found inside a tracker request (a cookie banner's
/// consent string, Google Consent Mode, Global Privacy Control...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentSignal {
    /// Where the choice came from, e.g. "Google Consent Mode".
    pub source: String,
    /// The choice in plain words.
    pub summary: String,
    /// The choice says no to tracking or personalised ads.
    pub refused: bool,
}

/// One tracker hit, decoded (FR-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodedPayload {
    pub company: &'static str,
    /// e.g. "Google Analytics 4", "Meta Pixel".
    pub product: &'static str,
    pub request_url: String,
    pub fields: Vec<DecodedField>,
}

impl DecodedPayload {
    /// Distinct kinds of data sent, most sensitive first.
    pub fn kinds(&self) -> Vec<DataKind> {
        let mut kinds: Vec<DataKind> = self.fields.iter().map(|f| f.kind).collect();
        kinds.sort();
        kinds.dedup();
        kinds
    }
}

/// How sure a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// The SDK's own files or package are bundled with the app.
    High,
    /// The app's code mentions the tracker's address. It may or may not
    /// send data there (the code could be an unused library).
    Medium,
}

/// A tracking or telemetry SDK found inside an installed app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppFinding {
    /// SDK or service name, e.g. "Sentry", or the company for address-only hits.
    pub sdk: String,
    pub company: String,
    pub category: Category,
    /// What it is used for, in plain words.
    pub purpose: String,
    pub confidence: Confidence,
    /// Why we think so, e.g. "Bundled file: sentry.dll".
    pub evidence: Vec<String>,
}

/// An installed desktop app and the SDKs found in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_dir: String,
    /// Built with Electron (a bundled Chromium browser running web code).
    pub electron: bool,
    pub findings: Vec<AppFinding>,
    pub bytes_scanned: u64,
    /// Some code was not read: see `skipped`.
    pub truncated: bool,
    /// Files whose code was not read, or only partly (at most
    /// `MAX_SKIPPED_LISTED`; `skipped_count` has the full number).
    #[serde(default)]
    pub skipped: Vec<SkippedFile>,
    #[serde(default)]
    pub skipped_count: usize,
    #[serde(default)]
    pub skipped_bytes: u64,
    /// The folder has more files than the scan lists, so some were not even looked at.
    #[serde(default)]
    pub too_many_files: bool,
    /// Scanned without any size limits, at the user's request.
    #[serde(default)]
    pub full_scan: bool,
}

/// Files listed per app in `InstalledApp::skipped`.
pub const MAX_SKIPPED_LISTED: usize = 50;

/// A file the app scan did not read completely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedFile {
    /// Path inside the app's folder.
    pub path: String,
    pub size: u64,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Larger than the per-file limit.
    TooLarge,
    /// The app's reading budget ran out before this file.
    AppLimit,
    /// The budget ran out partway through this file.
    PartlyRead,
}

/// Result of scanning installed desktop apps for SDKs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AppScan {
    pub apps: Vec<InstalledApp>,
    pub warnings: Vec<String>,
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
