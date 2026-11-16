//! End-to-end tests against fake browser profiles in a temp folder.

use super::*;
use ga_core::{ExtensionSource, Risk, SiteAccess};
use serde_json::json;
use std::fs;
use std::path::Path;

fn write_json(path: &Path, value: &serde_json::Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

/// A Chrome profile with: a store extension whose name is localised and that
/// can read every site, a sideloaded low-permission extension, a disabled
/// one, a component extension (must be skipped) and a leftover entry with no
/// install location (must be skipped).
fn make_chrome_profile(profile: &Path) {
    let ext_dir = profile.join(r"Extensions\aaaa\1.2.3");
    write_json(
        &ext_dir.join("manifest.json"),
        &json!({"name": "__MSG_extName__", "default_locale": "en", "version": "1.2.3", "manifest_version": 3}),
    );
    write_json(
        &ext_dir.join(r"_locales\en\messages.json"),
        &json!({"EXTNAME": {"message": "Super Shopper"}}),
    );

    write_json(
        &profile.join("Secure Preferences"),
        &json!({"extensions": {"settings": {
            "aaaa": {
                "location": 1, "from_webstore": true, "path": "aaaa\\1.2.3", "disable_reasons": [],
                "active_permissions": {"api": ["tabs", "storage"], "explicit_host": ["<all_urls>"], "scriptable_host": []}
            },
            "bbbb": {
                "location": 3, "from_webstore": true,
                "manifest": {"name": "Toolbar Helper", "version": "9.0", "permissions": ["storage"]}
            },
            "cccc": {
                "location": 1, "from_webstore": true, "disable_reasons": [1],
                "manifest": {"name": "Old Thing", "version": "0.1", "permissions": ["history", "https://*.example.com/*"]}
            },
            "comp": {"location": 5, "manifest": {"name": "Chrome PDF Viewer"}},
            "left": {"active_permissions": {"api": []}}
        }}}),
    );
}

#[test]
fn reads_chrome_extensions() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    make_chrome_profile(&local.join(r"Google\Chrome\User Data\Default"));

    let scan = scan_extensions_in(&BrowserRoots {
        local_app_data: Some(local),
        app_data: None,
    });
    assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
    assert_eq!(scan.profiles_scanned, 1);

    let names: Vec<&str> = scan.extensions.iter().map(|e| e.name.as_str()).collect();
    // Sorted riskiest first; component and leftover entries skipped.
    assert_eq!(names, ["Super Shopper", "Old Thing", "Toolbar Helper"]);

    let shopper = &scan.extensions[0];
    assert_eq!(shopper.version, "1.2.3");
    assert_eq!(shopper.site_access, SiteAccess::AllSites);
    assert_eq!(shopper.risk, Risk::High);
    assert_eq!(shopper.source, ExtensionSource::Store);
    assert!(shopper.enabled);
    assert_eq!(shopper.sensitive_permissions[0].permission, "tabs");

    let old = &scan.extensions[1];
    assert!(!old.enabled);
    // No active_permissions recorded: falls back to the manifest (MV2 mixed list).
    assert_eq!(old.site_access, SiteAccess::SomeSites(vec!["*.example.com".into()]));
    assert_eq!(old.risk, Risk::Medium);

    let toolbar = &scan.extensions[2];
    assert_eq!(toolbar.source, ExtensionSource::Sideloaded);
    assert_eq!(toolbar.risk, Risk::Medium);
}

#[test]
fn reads_firefox_extensions_and_skips_built_ins() {
    let tmp = tempfile::tempdir().unwrap();
    let roaming = tmp.path().join("Roaming");
    write_json(
        &roaming.join(r"Mozilla\Firefox\Profiles\ab12.default-release\extensions.json"),
        &json!({"addons": [
            {"id": "blocker@example.org", "type": "extension", "location": "app-profile", "active": true,
             "version": "1.0", "defaultLocale": {"name": "Ad Blocker"},
             "userPermissions": {"permissions": ["webRequest", "webRequestBlocking"], "origins": ["<all_urls>"]}},
            {"id": "pushed@vendor.com", "type": "extension", "location": "winreg-app-global", "active": true,
             "version": "2.0", "defaultLocale": {"name": "Vendor Helper"},
             "userPermissions": {"permissions": [], "origins": []}},
            {"id": "screenshots@mozilla.org", "type": "extension", "location": "app-builtin", "active": true},
            {"id": "default-theme@mozilla.org", "type": "theme", "location": "app-profile", "active": true}
        ]}),
    );

    let scan = scan_extensions_in(&BrowserRoots {
        local_app_data: None,
        app_data: Some(roaming),
    });
    assert_eq!(scan.profiles_scanned, 1);
    assert_eq!(scan.extensions.len(), 2);

    let blocker = &scan.extensions[0];
    assert_eq!(blocker.name, "Ad Blocker");
    assert_eq!(blocker.profile, "default-release");
    assert_eq!(blocker.risk, Risk::High);

    let vendor = &scan.extensions[1];
    assert_eq!(vendor.source, ExtensionSource::Sideloaded);
    assert_eq!(vendor.risk, Risk::Medium);
}

#[test]
fn broken_preferences_become_a_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    let profile = local.join(r"Microsoft\Edge\User Data\Default");
    fs::create_dir_all(&profile).unwrap();
    fs::write(profile.join("Secure Preferences"), b"{ not json").unwrap();

    let scan = scan_extensions_in(&BrowserRoots {
        local_app_data: Some(local),
        app_data: None,
    });
    assert_eq!(scan.warnings.len(), 1);
    assert_eq!(scan.warnings[0].browser, Browser::Edge);
    assert!(scan.extensions.is_empty());
}
