//! Extensions in Chromium browsers.
//!
//! Each profile's `Secure Preferences` (and on some versions `Preferences`)
//! holds `extensions.settings`: one entry per extension with its install
//! location, enabled state and the permissions actually granted
//! (`active_permissions`). The manifest supplies the name and version.

use super::permissions::{self, RawPermissions};
use crate::browsers::chromium::Profile;
use ga_core::{BrowserExtension, ExtensionSource};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Update URLs of the official stores.
const STORE_UPDATE_HOSTS: &[&str] = &["clients2.google.com", "edge.microsoft.com"];

/// Reads one profile. `Err` is a user-facing message.
pub fn read_profile(profile: &Profile) -> Result<Vec<BrowserExtension>, String> {
    let settings = load_settings(&profile.dir)?;
    let mut out = Vec::new();
    for (id, entry) in &settings {
        if let Some(ext) = read_extension(profile, id, entry) {
            out.push(ext);
        }
    }
    Ok(out)
}

/// Merges `extensions.settings` from both preference files. An entry that has
/// an install location wins over one that does not.
fn load_settings(profile_dir: &Path) -> Result<BTreeMap<String, Value>, String> {
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    for file in ["Secure Preferences", "Preferences"] {
        let path = profile_dir.join(file);
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let json: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|e| format!("Could not read browser preferences ({file}): {e}"))?;
        let Some(settings) = json.pointer("/extensions/settings").and_then(Value::as_object) else {
            continue;
        };
        for (id, entry) in settings {
            let has_location = entry.get("location").is_some();
            let keep_existing = merged
                .get(id)
                .is_some_and(|e| e.get("location").is_some() || !has_location);
            if !keep_existing {
                merged.insert(id.clone(), entry.clone());
            }
        }
    }
    Ok(merged)
}

fn read_extension(profile: &Profile, id: &str, entry: &Value) -> Option<BrowserExtension> {
    let location = entry.get("location")?.as_i64()?;
    // Component extensions are part of the browser itself.
    if matches!(location, 5 | 10) {
        return None;
    }

    let ext_dir = extension_dir(&profile.dir, entry);
    let manifest = entry
        .get("manifest")
        .filter(|m| m.is_object())
        .cloned()
        .or_else(|| ext_dir.as_deref().and_then(read_manifest))
        .unwrap_or(Value::Null);

    let source = install_source(location, entry, &manifest);
    let raw = granted_permissions(entry).unwrap_or_else(|| manifest_permissions(&manifest));
    let a = permissions::assess(&raw, source);

    Some(BrowserExtension {
        browser: profile.browser,
        profile: profile.name.clone(),
        id: id.to_owned(),
        name: display_name(&manifest, ext_dir.as_deref()).unwrap_or_else(|| id.to_owned()),
        version: manifest.get("version").and_then(Value::as_str).unwrap_or("").to_owned(),
        enabled: is_enabled(entry),
        source,
        site_access: a.site_access,
        sensitive_permissions: a.sensitive_permissions,
        risk: a.risk,
        risk_reasons: a.risk_reasons,
    })
}

/// `path` is relative to the profile's `Extensions` folder for store installs
/// and absolute for unpacked ones.
fn extension_dir(profile_dir: &Path, entry: &Value) -> Option<PathBuf> {
    let path = PathBuf::from(entry.get("path")?.as_str()?);
    Some(if path.is_absolute() {
        path
    } else {
        profile_dir.join("Extensions").join(path)
    })
}

fn read_manifest(dir: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

/// Chromium's `ManifestLocation` values.
fn install_source(location: i64, entry: &Value, manifest: &Value) -> ExtensionSource {
    let flag = |k: &str| entry.get(k).and_then(Value::as_bool).unwrap_or(false);
    let from_store = flag("from_webstore")
        || manifest
            .get("update_url")
            .and_then(Value::as_str)
            .is_some_and(|u| STORE_UPDATE_HOSTS.iter().any(|h| u.contains(h)));

    match location {
        // INTERNAL: installed by the user.
        1 if from_store => ExtensionSource::Store,
        1 => ExtensionSource::Sideloaded,
        // EXTERNAL_PREF, EXTERNAL_REGISTRY, EXTERNAL_PREF_DOWNLOAD: another
        // program asked the browser to install it, unless the browser or PC
        // maker shipped it.
        2 | 3 | 6 if (flag("was_installed_by_default") || flag("was_installed_by_oem")) && from_store => {
            ExtensionSource::Store
        }
        2 | 3 | 6 => ExtensionSource::Sideloaded,
        // UNPACKED, COMMAND_LINE
        4 | 8 => ExtensionSource::Developer,
        // EXTERNAL_POLICY_DOWNLOAD, EXTERNAL_POLICY
        7 | 9 => ExtensionSource::Policy,
        _ => ExtensionSource::Unknown,
    }
}

/// Newer versions use a `disable_reasons` list, older ones a bitmask or `state`.
fn is_enabled(entry: &Value) -> bool {
    if entry.get("state").and_then(Value::as_i64) == Some(0) {
        return false;
    }
    match entry.get("disable_reasons") {
        None | Some(Value::Null) => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Number(n)) => n.as_i64() == Some(0),
        Some(_) => true,
    }
}

/// The permissions the user actually granted.
fn granted_permissions(entry: &Value) -> Option<RawPermissions> {
    let active = entry.get("active_permissions")?.as_object()?;
    let mut raw = RawPermissions {
        api: permission_names(active.get("api")),
        hosts: Vec::new(),
    };
    for key in ["explicit_host", "scriptable_host"] {
        raw.hosts.extend(strings(active.get(key)));
    }
    Some(raw)
}

/// Falls back to what the manifest asks for.
fn manifest_permissions(manifest: &Value) -> RawPermissions {
    let mut raw = RawPermissions::default();
    permissions::split_mixed(permission_names(manifest.get("permissions")), &mut raw);
    raw.hosts.extend(strings(manifest.get("host_permissions")));
    if let Some(scripts) = manifest.get("content_scripts").and_then(Value::as_array) {
        for script in scripts {
            raw.hosts.extend(strings(script.get("matches")));
        }
    }
    raw
}

/// Permission entries are strings, or objects like `{"socket": [...]}`.
fn permission_names(list: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = list else { return Vec::new() };
    items
        .iter()
        .flat_map(|item| match item {
            Value::String(s) => vec![s.clone()],
            Value::Object(o) => o.keys().cloned().collect(),
            _ => Vec::new(),
        })
        .collect()
}

fn strings(list: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = list else { return Vec::new() };
    items.iter().filter_map(Value::as_str).map(str::to_owned).collect()
}

/// Resolves `__MSG_appName__` names through the extension's `_locales` folder.
fn display_name(manifest: &Value, ext_dir: Option<&Path>) -> Option<String> {
    let name = manifest.get("name")?.as_str()?;
    let Some(key) = name.strip_prefix("__MSG_").and_then(|k| k.strip_suffix("__")) else {
        return Some(name.to_owned());
    };
    let dir = ext_dir?;
    let locale = manifest.get("default_locale").and_then(Value::as_str).unwrap_or("en");
    let text = std::fs::read_to_string(dir.join("_locales").join(locale).join("messages.json")).ok()?;
    let messages: Map<String, Value> = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    // Message keys are case-insensitive.
    messages
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, v)| v.get("message")?.as_str())
        .map(str::to_owned)
}

#[cfg(test)]
mod unit {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_install_sources() {
        let m = json!({});
        assert_eq!(install_source(1, &json!({"from_webstore": true}), &m), ExtensionSource::Store);
        assert_eq!(install_source(1, &json!({}), &m), ExtensionSource::Sideloaded);
        let edge = json!({"update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx"});
        assert_eq!(install_source(1, &json!({}), &edge), ExtensionSource::Store);
        assert_eq!(install_source(3, &json!({"from_webstore": true}), &m), ExtensionSource::Sideloaded);
        assert_eq!(
            install_source(6, &json!({"from_webstore": true, "was_installed_by_default": true}), &m),
            ExtensionSource::Store
        );
        assert_eq!(install_source(4, &json!({}), &m), ExtensionSource::Developer);
        assert_eq!(install_source(9, &json!({}), &m), ExtensionSource::Policy);
    }

    #[test]
    fn reads_enabled_state_in_all_formats() {
        assert!(is_enabled(&json!({})));
        assert!(is_enabled(&json!({"disable_reasons": []})));
        assert!(!is_enabled(&json!({"disable_reasons": [1]})));
        assert!(!is_enabled(&json!({"disable_reasons": 8})));
        assert!(!is_enabled(&json!({"state": 0})));
    }

    #[test]
    fn reads_object_permissions() {
        let names = permission_names(Some(&json!(["tabs", {"socket": ["tcp-connect"]}])));
        assert_eq!(names, ["tabs", "socket"]);
    }
}
