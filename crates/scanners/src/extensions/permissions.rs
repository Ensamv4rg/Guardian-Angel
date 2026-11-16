//! Turns raw extension permissions into site access, sensitive permissions
//! and a risk level. Shared by the Chromium and Firefox readers.

use ga_core::{ExtensionSource, Risk, SensitivePermission, SiteAccess};
use std::collections::BTreeSet;

/// Permissions that expose personal data, with plain-language meanings.
const SENSITIVE: &[(&str, &str)] = &[
    ("debugger", "Take full control of pages through the debugger"),
    ("nativeMessaging", "Talk to programs installed on your computer"),
    ("history", "See and delete your browsing history"),
    ("tabs", "See the address and title of every tab"),
    ("webNavigation", "See every page you go to"),
    ("webRequest", "Watch your network traffic"),
    ("webRequestBlocking", "Block or change your network traffic"),
    ("cookies", "Read and change cookies on sites it can access"),
    ("clipboardRead", "Read what you copy"),
    ("proxy", "Route your traffic through another server"),
    ("privacy", "Change your browser's privacy settings"),
    ("management", "See, enable and disable your other extensions"),
    ("contentSettings", "Change site permissions such as camera and microphone"),
    ("desktopCapture", "Capture your screen"),
    ("tabCapture", "Record video and audio of your tabs"),
    ("pageCapture", "Save complete copies of pages"),
    ("downloads", "See and manage your downloads"),
    ("geolocation", "Use your location"),
    ("topSites", "See your most visited sites"),
    ("bookmarks", "Read and change your bookmarks"),
    ("browsingData", "Delete your browsing data"),
    ("sessions", "See recently closed tabs and your other devices"),
    ("identity.email", "See your email address"),
    ("scripting", "Run its own code on pages it can access"),
];

/// Permissions that alone make an extension high risk.
const HIGH_RISK: &[&str] = &["debugger"];

/// Raw permissions as read from the browser.
#[derive(Debug, Default)]
pub struct RawPermissions {
    /// API permissions, e.g. `tabs`, `history`.
    pub api: Vec<String>,
    /// Host and match patterns, e.g. `<all_urls>`, `https://*.google.com/*`.
    pub hosts: Vec<String>,
}

pub struct Assessment {
    pub site_access: SiteAccess,
    pub sensitive_permissions: Vec<SensitivePermission>,
    pub risk: Risk,
    pub risk_reasons: Vec<String>,
}

/// Splits a mixed permission list (Manifest V2 puts hosts in `permissions`).
pub fn split_mixed(list: impl IntoIterator<Item = String>, into: &mut RawPermissions) {
    for p in list {
        if is_host_pattern(&p) {
            into.hosts.push(p);
        } else {
            into.api.push(p);
        }
    }
}

fn is_host_pattern(p: &str) -> bool {
    p == "<all_urls>" || p.contains("://")
}

/// The host part of a match pattern: `https://*.google.com/*` -> `*.google.com`.
/// Returns `None` for patterns that grant no web access (e.g. `chrome://`).
fn pattern_host(pattern: &str) -> Option<&str> {
    if pattern == "<all_urls>" {
        return Some("*");
    }
    let (scheme, rest) = pattern.split_once("://")?;
    if !matches!(scheme, "*" | "http" | "https" | "ws" | "wss") {
        return None;
    }
    let host = rest.split('/').next().unwrap_or("");
    // Drop a port, if any.
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
    (!host.is_empty()).then_some(host)
}

pub fn site_access(hosts: &[String]) -> SiteAccess {
    let mut some = BTreeSet::new();
    for pattern in hosts {
        match pattern_host(pattern) {
            Some("*") => return SiteAccess::AllSites,
            Some(host) => {
                some.insert(host.to_owned());
            }
            None => {}
        }
    }
    if some.is_empty() {
        SiteAccess::NoSites
    } else {
        SiteAccess::SomeSites(some.into_iter().collect())
    }
}

pub fn assess(raw: &RawPermissions, source: ExtensionSource) -> Assessment {
    let site_access = site_access(&raw.hosts);
    let api: BTreeSet<&str> = raw.api.iter().map(String::as_str).collect();

    // Keep the order of SENSITIVE (most serious first), no duplicates.
    let sensitive_permissions: Vec<SensitivePermission> = SENSITIVE
        .iter()
        .filter(|(name, _)| api.contains(name))
        .map(|(name, meaning)| SensitivePermission {
            permission: (*name).to_owned(),
            meaning,
        })
        .collect();

    let mut reasons = Vec::new();
    match &site_access {
        SiteAccess::AllSites => reasons.push("Can read and change all your data on every website".to_owned()),
        SiteAccess::SomeSites(hosts) if hosts.len() == 1 => {
            reasons.push(format!("Can read and change your data on {}", hosts[0]))
        }
        SiteAccess::SomeSites(hosts) => {
            reasons.push(format!("Can read and change your data on {} sites", hosts.len()))
        }
        SiteAccess::NoSites => {}
    }
    reasons.extend(sensitive_permissions.iter().map(|p| p.meaning.to_owned()));
    if source == ExtensionSource::Sideloaded {
        reasons.push("Installed by another program, not from the store".to_owned());
    }
    if source == ExtensionSource::Developer {
        reasons.push("Loaded in developer mode, so the store never reviewed it".to_owned());
    }

    let high = site_access == SiteAccess::AllSites
        || sensitive_permissions.iter().any(|p| HIGH_RISK.contains(&p.permission.as_str()));
    let medium = matches!(site_access, SiteAccess::SomeSites(_))
        || !sensitive_permissions.is_empty()
        || matches!(source, ExtensionSource::Sideloaded | ExtensionSource::Developer);
    let risk = if high {
        Risk::High
    } else if medium {
        Risk::Medium
    } else {
        Risk::Low
    };

    Assessment {
        site_access,
        sensitive_permissions,
        risk,
        risk_reasons: reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(api: &[&str], hosts: &[&str]) -> RawPermissions {
        RawPermissions {
            api: api.iter().map(|s| s.to_string()).collect(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn recognises_all_sites_patterns() {
        for p in ["<all_urls>", "*://*/*", "https://*/*", "http://*/", "*://*:8080/*"] {
            assert_eq!(site_access(&[p.to_owned()]), SiteAccess::AllSites, "{p}");
        }
    }

    #[test]
    fn collects_specific_sites_and_ignores_internal_schemes() {
        let hosts = ["https://*.google.com/*", "https://mail.google.com/*", "*://*.google.com/*", "chrome://favicon/*", "file:///*"]
            .map(String::from);
        assert_eq!(
            site_access(&hosts),
            SiteAccess::SomeSites(vec!["*.google.com".into(), "mail.google.com".into()])
        );
        assert_eq!(site_access(&["chrome://favicon/*".to_owned()]), SiteAccess::NoSites);
    }

    #[test]
    fn splits_manifest_v2_permissions() {
        let mut r = RawPermissions::default();
        split_mixed(["tabs", "<all_urls>", "https://x.com/*", "storage"].map(String::from), &mut r);
        assert_eq!(r.api, ["tabs", "storage"]);
        assert_eq!(r.hosts, ["<all_urls>", "https://x.com/*"]);
    }

    #[test]
    fn all_sites_is_high_risk() {
        let a = assess(&raw(&["storage"], &["<all_urls>"]), ExtensionSource::Store);
        assert_eq!(a.risk, Risk::High);
        assert_eq!(a.risk_reasons[0], "Can read and change all your data on every website");
    }

    #[test]
    fn debugger_alone_is_high_risk() {
        assert_eq!(assess(&raw(&["debugger"], &[]), ExtensionSource::Store).risk, Risk::High);
    }

    #[test]
    fn sensitive_permission_or_some_sites_is_medium() {
        assert_eq!(assess(&raw(&["history"], &[]), ExtensionSource::Store).risk, Risk::Medium);
        let a = assess(&raw(&[], &["https://*.google.com/*"]), ExtensionSource::Store);
        assert_eq!(a.risk, Risk::Medium);
        assert_eq!(a.risk_reasons[0], "Can read and change your data on *.google.com");
    }

    #[test]
    fn sideloading_raises_low_to_medium() {
        assert_eq!(assess(&raw(&["storage"], &[]), ExtensionSource::Store).risk, Risk::Low);
        let a = assess(&raw(&["storage"], &[]), ExtensionSource::Sideloaded);
        assert_eq!(a.risk, Risk::Medium);
        assert!(a.risk_reasons[0].contains("another program"));
    }
}
