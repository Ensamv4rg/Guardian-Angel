//! Alerts: what changed since the last scan (FR-14). Each scan is reduced
//! to a small baseline that is saved, so changes are caught across restarts.

use ga_core::{AppScan, Confidence, Exposure, ExtensionScan, PrivacyScan, Risk};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Kept alerts; older ones are dropped first.
pub const MAX_ALERTS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub unix: i64,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub read: bool,
}

/// The parts of a scan that alerts compare.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// "browser/profile/id" -> (name, risk as text).
    pub extensions: BTreeMap<String, (String, String)>,
    /// Setting id -> (title, exposed).
    pub privacy: BTreeMap<String, (String, bool)>,
    /// App name -> SDKs found with high confidence.
    pub apps: BTreeMap<String, BTreeSet<String>>,
    /// Whether `apps` has been filled (the app scan runs after the rest).
    pub apps_scanned: bool,
}

impl Baseline {
    pub fn record_quick(&mut self, extensions: &ExtensionScan, privacy: &PrivacyScan) {
        self.extensions = extensions
            .extensions
            .iter()
            .map(|e| (format!("{}/{}/{}", e.browser, e.profile, e.id), (e.name.clone(), format!("{:?}", e.risk))))
            .collect();
        self.privacy = privacy
            .settings
            .iter()
            .map(|s| (s.id.to_owned(), (s.title.to_owned(), s.exposure == Exposure::Exposed)))
            .collect();
    }

    pub fn record_apps(&mut self, apps: &AppScan) {
        self.apps = apps
            .apps
            .iter()
            .map(|a| {
                let sure = a.findings.iter().filter(|f| f.confidence == Confidence::High).map(|f| f.sdk.clone()).collect();
                (a.name.clone(), sure)
            })
            .collect();
        self.apps_scanned = true;
    }
}

/// A new alert without an ID or time yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

/// What became worse between two baselines. Improvements are not alerts.
pub fn compare_quick(old: &Baseline, extensions: &ExtensionScan, privacy: &PrivacyScan) -> Vec<Change> {
    let mut out = Vec::new();
    for e in &extensions.extensions {
        let key = format!("{}/{}/{}", e.browser, e.profile, e.id);
        let was = old.extensions.get(&key);
        let severity = match e.risk {
            Risk::High => Severity::High,
            Risk::Medium => Severity::Medium,
            Risk::Low => continue,
        };
        let reason = e.risk_reasons.first().cloned().unwrap_or_default();
        match was {
            None => out.push(Change {
                severity,
                title: format!("New {} extension: {}", e.browser, e.name),
                detail: reason,
            }),
            Some((_, old_risk)) if *old_risk != format!("{:?}", e.risk) && e.risk == Risk::High => out.push(Change {
                severity,
                title: format!("{} extension now has more access: {}", e.browser, e.name),
                detail: reason,
            }),
            _ => {}
        }
    }
    for s in &privacy.settings {
        let exposed_now = s.exposure == Exposure::Exposed;
        if exposed_now && old.privacy.get(s.id).is_some_and(|(_, was_exposed)| !was_exposed) {
            out.push(Change {
                severity: Severity::Medium,
                title: format!("Windows setting switched back on: {}", s.title),
                detail: format!("Now: {}. Updates sometimes reset privacy settings.", s.state),
            });
        }
    }
    out
}

pub fn compare_apps(old: &Baseline, apps: &AppScan) -> Vec<Change> {
    if !old.apps_scanned {
        return Vec::new();
    }
    let mut out = Vec::new();
    for a in &apps.apps {
        let before = old.apps.get(&a.name);
        for f in a.findings.iter().filter(|f| f.confidence == Confidence::High) {
            if before.is_none_or(|sdks| !sdks.contains(&f.sdk)) {
                out.push(Change {
                    severity: Severity::Info,
                    title: format!("{} now includes {}", a.name, f.sdk),
                    detail: f.purpose.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ga_core::{Browser, BrowserExtension, ExtensionSource, PrivacyArea, PrivacySetting, SiteAccess};

    fn ext(id: &str, risk: Risk) -> BrowserExtension {
        BrowserExtension {
            browser: Browser::Chrome,
            profile: "Default".into(),
            id: id.into(),
            name: format!("Ext {id}"),
            version: "1".into(),
            enabled: true,
            source: ExtensionSource::Store,
            site_access: SiteAccess::AllSites,
            sensitive_permissions: vec![],
            risk,
            risk_reasons: vec!["Can read and change all your data on every website".into()],
        }
    }

    fn setting(exposure: Exposure) -> PrivacySetting {
        PrivacySetting {
            id: "advertising_id",
            area: PrivacyArea::Advertising,
            title: "Advertising ID",
            state: "On".into(),
            exposure,
            explanation: "",
            set_by_policy: false,
            source: String::new(),
        }
    }

    #[test]
    fn flags_new_risky_extensions_and_reset_settings_only() {
        let mut base = Baseline::default();
        let exts = ExtensionScan {
            extensions: vec![ext("a", Risk::Low)],
            ..Default::default()
        };
        let privacy = PrivacyScan {
            settings: vec![setting(Exposure::Protected)],
            ..Default::default()
        };
        base.record_quick(&exts, &privacy);

        let exts2 = ExtensionScan {
            extensions: vec![ext("a", Risk::High), ext("b", Risk::High), ext("c", Risk::Low)],
            ..Default::default()
        };
        let privacy2 = PrivacyScan {
            settings: vec![setting(Exposure::Exposed)],
            ..Default::default()
        };
        let changes = compare_quick(&base, &exts2, &privacy2);
        let titles: Vec<&str> = changes.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Chrome extension now has more access: Ext a",
                "New Chrome extension: Ext b",
                "Windows setting switched back on: Advertising ID"
            ]
        );
        // Improvements do not alert.
        assert!(compare_quick(&{
            let mut b = Baseline::default();
            b.record_quick(&exts2, &privacy2);
            b
        }, &exts, &privacy)
        .is_empty());
    }

    #[test]
    fn app_alerts_wait_for_a_first_app_scan() {
        use ga_core::{AppFinding, Category, InstalledApp};
        let app = |sdks: &[&str]| AppScan {
            apps: vec![InstalledApp {
                name: "Chatty".into(),
                publisher: None,
                version: None,
                install_dir: String::new(),
                electron: true,
                findings: sdks
                    .iter()
                    .map(|s| AppFinding {
                        sdk: (*s).into(),
                        company: String::new(),
                        category: Category::Analytics,
                        purpose: "Product analytics".into(),
                        confidence: Confidence::High,
                        evidence: vec![],
                    })
                    .collect(),
                bytes_scanned: 0,
                truncated: false,
            }],
            warnings: vec![],
        };
        let mut base = Baseline::default();
        assert!(compare_apps(&base, &app(&["Sentry"])).is_empty(), "no alerts before a first scan");
        base.record_apps(&app(&["Sentry"]));
        let changes = compare_apps(&base, &app(&["Sentry", "Mixpanel"]));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].title, "Chatty now includes Mixpanel");
    }
}
