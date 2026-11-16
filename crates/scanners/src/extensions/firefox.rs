//! Extensions in Firefox, read from each profile's `extensions.json`.

use super::permissions::{self, RawPermissions};
use ga_core::{Browser, BrowserExtension, ExtensionSource};
use serde_json::Value;
use std::path::Path;

/// Locations holding Mozilla's own built-in and system add-ons.
const BUILT_IN: &[&str] = &["app-builtin", "app-system-defaults", "app-system-addons"];

/// Locations where other programs place add-ons (sideloading).
const SIDELOAD: &[&str] = &[
    "app-system-share",
    "app-system-local",
    "app-system-user",
    "winreg-app-user",
    "winreg-app-global",
];

/// Reads one profile. `Ok(None)` means the profile has no `extensions.json` yet.
pub fn read_profile(dir: &Path, profile: &str) -> Result<Option<Vec<BrowserExtension>>, String> {
    let path = dir.join("extensions.json");
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(None) };
    let json: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("Could not read extensions.json: {e}"))?;

    let addons = json.get("addons").and_then(Value::as_array).cloned().unwrap_or_default();
    Ok(Some(addons.iter().filter_map(|a| read_addon(a, profile)).collect()))
}

fn read_addon(addon: &Value, profile: &str) -> Option<BrowserExtension> {
    let str_field = |k: &str| addon.get(k).and_then(Value::as_str);
    if str_field("type") != Some("extension") {
        return None;
    }
    let location = str_field("location").unwrap_or("");
    if BUILT_IN.contains(&location) {
        return None;
    }

    let source = if SIDELOAD.contains(&location) {
        ExtensionSource::Sideloaded
    } else if location == "app-temporary" {
        ExtensionSource::Developer
    } else if location == "app-profile" {
        ExtensionSource::Store
    } else {
        ExtensionSource::Unknown
    };

    let granted = addon.get("userPermissions");
    let list = |k: &str| -> Vec<String> {
        granted
            .and_then(|g| g.get(k))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default()
    };
    let raw = RawPermissions {
        api: list("permissions"),
        hosts: list("origins"),
    };
    let a = permissions::assess(&raw, source);

    let id = str_field("id")?.to_owned();
    Some(BrowserExtension {
        browser: Browser::Firefox,
        profile: profile.to_owned(),
        name: addon
            .pointer("/defaultLocale/name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| id.clone()),
        id,
        version: str_field("version").unwrap_or("").to_owned(),
        enabled: addon.get("active").and_then(Value::as_bool).unwrap_or(false),
        source,
        site_access: a.site_access,
        sensitive_permissions: a.sensitive_permissions,
        risk: a.risk,
        risk_reasons: a.risk_reasons,
    })
}
