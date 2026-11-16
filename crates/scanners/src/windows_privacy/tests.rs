//! Interpretation tests against a fake registry.

use super::registry::fake::FakeRegistry;
use super::settings::CONSENT_STORE;
use super::*;
use ga_core::{Capability, Exposure, PrivacySetting};

const HKLM: Hive = Hive::LocalMachine;
const HKCU: Hive = Hive::CurrentUser;

fn setting<'a>(scan: &'a PrivacyScan, id: &str) -> &'a PrivacySetting {
    scan.settings
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("no setting {id}"))
}

/// Mirrors the values found on the development machine.
fn typical_machine() -> FakeRegistry {
    let mut reg = FakeRegistry::default();
    reg.set_dword(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 3)
        .set_dword(HKCU, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0)
        .set_dword(HKCU, r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0)
        .set_dword(HKCU, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 0)
        .set_dword(HKCU, r"Software\Microsoft\Input\TIPC", "Enabled", 1)
        .set_dword(HKCU, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 1)
        .set_dword(HKCU, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 1)
        .set_string(HKLM, &format!(r"{CONSENT_STORE}\location"), "Value", "Allow")
        .set_string(HKCU, &format!(r"{CONSENT_STORE}\location"), "Value", "Allow");
    reg
}

#[test]
fn reads_typical_machine() {
    let scan = scan_privacy_with(&typical_machine());

    let diag = setting(&scan, "diagnostic_data");
    assert_eq!(diag.state, "Optional (full)");
    assert_eq!(diag.exposure, Exposure::Exposed);
    assert!(!diag.set_by_policy);

    assert_eq!(setting(&scan, "advertising_id").exposure, Exposure::Protected);
    assert_eq!(setting(&scan, "tailored_experiences").exposure, Exposure::Protected);
    assert_eq!(setting(&scan, "typing_personalization").exposure, Exposure::Exposed);
    assert_eq!(setting(&scan, "improve_inking_typing").exposure, Exposure::Exposed);
    assert_eq!(setting(&scan, "silent_app_installs").exposure, Exposure::Exposed);
    assert_eq!(setting(&scan, "location").state, "On");
}

#[test]
fn missing_values_use_only_known_defaults() {
    let scan = scan_privacy_with(&FakeRegistry::default());

    // Well-established defaults.
    let lang = setting(&scan, "language_list");
    assert_eq!(lang.state, "On (Windows default)");
    assert_eq!(lang.exposure, Exposure::Exposed);
    assert_eq!(setting(&scan, "app_launch_tracking").exposure, Exposure::Exposed);
    assert_eq!(setting(&scan, "online_speech").exposure, Exposure::Protected);

    // Defaults that vary: never guessed.
    for id in ["diagnostic_data", "advertising_id", "tailored_experiences", "location"] {
        assert_eq!(setting(&scan, id).exposure, Exposure::Unknown, "{id}");
    }
}

#[test]
fn opt_out_flags_are_inverted() {
    let mut reg = FakeRegistry::default();
    reg.set_dword(HKCU, r"Control Panel\International\User Profile", "HttpAcceptLanguageOptOut", 1)
        .set_dword(HKCU, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1);
    let scan = scan_privacy_with(&reg);
    assert_eq!(setting(&scan, "language_list").state, "Off");
    assert_eq!(setting(&scan, "typing_personalization").state, "Off");
}

#[test]
fn group_policy_overrides_user_choice() {
    let mut reg = typical_machine();
    reg.set_dword(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 1)
        .set_dword(HKCU, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 1)
        .set_dword(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1);
    let scan = scan_privacy_with(&reg);

    let diag = setting(&scan, "diagnostic_data");
    assert_eq!(diag.state, "Required (minimum)");
    assert!(diag.set_by_policy);

    let ad = setting(&scan, "advertising_id");
    assert_eq!(ad.state, "Off");
    assert!(ad.set_by_policy);
}

#[test]
fn location_off_at_either_level() {
    let mut reg = typical_machine();
    reg.set_string(HKCU, &format!(r"{CONSENT_STORE}\location"), "Value", "Deny");
    assert_eq!(setting(&scan_privacy_with(&reg), "location").state, "Off for your account");

    reg.set_string(HKLM, &format!(r"{CONSENT_STORE}\location"), "Value", "Deny");
    assert_eq!(setting(&scan_privacy_with(&reg), "location").state, "Off for this device");
}

#[test]
fn reads_app_access_history() {
    let mic = format!(r"{CONSENT_STORE}\microphone");
    let cam = format!(r"{CONSENT_STORE}\webcam");
    let jan_2024 = 133_485_408_000_000_000; // 2024-01-01T00:00:00Z as FILETIME
    let hour = 36_000_000_000; // one hour in FILETIME units

    let mut reg = FakeRegistry::default();
    // Desktop app, used and finished.
    reg.set_qword(HKCU, &format!(r"{mic}\NonPackaged\C:#Program Files#Zoom#bin#Zoom.exe"), "LastUsedTimeStart", jan_2024)
        .set_qword(HKCU, &format!(r"{mic}\NonPackaged\C:#Program Files#Zoom#bin#Zoom.exe"), "LastUsedTimeStop", jan_2024 + hour)
        // Desktop app using the camera right now (stop = 0).
        .set_qword(HKCU, &format!(r"{cam}\NonPackaged\C:#Apps#spy.exe"), "LastUsedTimeStart", jan_2024)
        .set_qword(HKCU, &format!(r"{cam}\NonPackaged\C:#Apps#spy.exe"), "LastUsedTimeStop", 0)
        // Store app, allowed but never used.
        .set_string(HKCU, &format!(r"{cam}\Microsoft.WindowsCamera_8wekyb3d8bbwe"), "Value", "Allow");

    let apps = scan_privacy_with(&reg).app_access;
    assert_eq!(apps.len(), 3);

    let first = &apps[0];
    assert_eq!(first.app, "spy.exe");
    assert_eq!(first.capability, Capability::Camera);
    assert!(first.in_use_now);
    assert_eq!(first.identifier, r"C:\Apps\spy.exe");

    let zoom = apps.iter().find(|a| a.app == "Zoom.exe").unwrap();
    assert_eq!(zoom.capability, Capability::Microphone);
    assert!(!zoom.in_use_now);
    assert!(!zoom.packaged);
    assert_eq!(zoom.allowed, None);
    assert_eq!(zoom.last_used_start_unix, Some(1_704_067_200));
    assert_eq!(zoom.last_used_stop_unix, Some(1_704_070_800));

    let camera_app = apps.iter().find(|a| a.packaged).unwrap();
    assert_eq!(camera_app.app, "Microsoft.WindowsCamera");
    assert_eq!(camera_app.allowed, Some(true));
    assert_eq!(camera_app.last_used_start_unix, None);
}

/// Read-only: the per-user view (HKEY_USERS\<SID>, used by the service)
/// must see exactly what the current-user view sees.
#[cfg(windows)]
#[test]
fn per_user_registry_matches_current_user() {
    let sid = ga_platform_win::process_user_sid(std::process::id()).unwrap();
    let mine = scan_privacy_with(&WindowsRegistry::default());
    let via_sid = scan_privacy_with(&WindowsRegistry::for_user(&sid));
    assert_eq!(mine.settings, via_sid.settings);
    assert_eq!(mine.app_access.len(), via_sid.app_access.len());
}
