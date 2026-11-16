//! End-to-end tests against fake installed apps in a temp folder.

use super::*;
use crate::windows_privacy::Hive;
use crate::windows_privacy::registry::fake::FakeRegistry;
use ga_core::{Category, Confidence};
use std::fs;
use std::path::Path;

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// Three fake apps:
/// - "Chatty": Electron, registered with an icon path only, bundles
///   @sentry/electron and calls Mixpanel from its code.
/// - "NativeTool": swept from Program Files, ships sentry.dll and has a
///   Criteo address (UTF-16) in its exe.
/// - "Clean": registered with an install location, no trackers.
fn setup(tmp: &Path) -> (FakeRegistry, AppRoots) {
    let local = tmp.join("Local");
    let pf = tmp.join("Program Files");

    let chatty = local.join("Chatty");
    let asar = asar::build(&[
        ("package.json", br#"{"dependencies":{"@sentry/electron":"5"}}"#),
        ("dist/main.js", br#"fetch("https://api.mixpanel.com/track",{})"#),
    ]);
    write(&chatty.join(r"app-2.0.1\resources\app.asar"), &asar);
    write(&chatty.join(r"app-2.0.1\Chatty.exe"), b"MZ chromium runtime google-analytics.com");
    write(&chatty.join("app.ico"), b"icon");

    let native = pf.join("NativeTool");
    let utf16: Vec<u8> = "https://static.criteo.net/x".encode_utf16().flat_map(u16::to_le_bytes).collect();
    write(&native.join("tool.exe"), &[b"MZ".as_slice(), &utf16].concat());
    write(&native.join("Sentry.dll"), b"MZ");

    let clean = pf.join("Clean");
    write(&clean.join("clean.exe"), b"MZ nothing to see");

    let uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    let hklm_uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let mut reg = FakeRegistry::default();
    reg.set_string(Hive::CurrentUser, &format!(r"{uninstall}\Chatty"), "DisplayName", "Chatty")
        .set_string(
            Hive::CurrentUser,
            &format!(r"{uninstall}\Chatty"),
            "DisplayIcon",
            &format!("{}", chatty.join("app.ico").display()),
        )
        .set_string(Hive::LocalMachine, &format!(r"{hklm_uninstall}\Clean"), "DisplayName", "Clean App")
        .set_string(Hive::LocalMachine, &format!(r"{hklm_uninstall}\Clean"), "Publisher", "Clean Co")
        .set_string(
            Hive::LocalMachine,
            &format!(r"{hklm_uninstall}\Clean"),
            "InstallLocation",
            &clean.display().to_string(),
        )
        // A Windows update entry must be ignored.
        .set_string(Hive::LocalMachine, &format!(r"{hklm_uninstall}\KB123"), "DisplayName", "Security Update")
        .set_string(Hive::LocalMachine, &format!(r"{hklm_uninstall}\KB123"), "ParentKeyName", "OperatingSystem");

    let roots = AppRoots {
        program_files: vec![pf],
        local_app_data: Some(local),
        windows_dir: None,
    };
    (reg, roots)
}

#[test]
fn finds_sdks_in_electron_and_native_apps() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, roots) = setup(tmp.path());
    let matcher = Matcher::bundled(&TrackerDb::bundled().unwrap());
    let scan = scan_apps_with(&reg, &roots, &matcher, Limits::default());

    let names: Vec<&str> = scan.apps.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["Chatty", "NativeTool", "Clean App"], "apps sorted by findings");

    let chatty = &scan.apps[0];
    assert!(chatty.electron);
    assert!(chatty.install_dir.ends_with("Chatty"), "icon in app-x folder resolves to the app root");
    let sentry = chatty.findings.iter().find(|f| f.sdk == "Sentry").unwrap();
    assert_eq!(sentry.confidence, Confidence::High);
    assert_eq!(sentry.category, Category::ErrorReporting);
    assert!(sentry.evidence[0].contains("@sentry/electron"));
    let mixpanel = chatty.findings.iter().find(|f| f.sdk == "Mixpanel").unwrap();
    assert_eq!(mixpanel.confidence, Confidence::Medium);
    assert!(mixpanel.evidence[0].contains("api.mixpanel.com"));
    // The Electron runtime exe is not searched, so its strings do not count.
    assert!(chatty.findings.iter().all(|f| f.company != "Google"));

    let native = &scan.apps[1];
    assert!(!native.electron);
    assert_eq!(native.findings[0].sdk, "Sentry");
    assert_eq!(native.findings[0].confidence, Confidence::High);
    let criteo = native.findings.iter().find(|f| f.company == "Criteo").unwrap();
    assert_eq!(criteo.category, Category::Advertising);

    let clean = &scan.apps[2];
    assert_eq!(clean.publisher.as_deref(), Some("Clean Co"));
    assert!(clean.findings.is_empty());
}

#[test]
fn size_limit_marks_scan_as_truncated() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, roots) = setup(tmp.path());
    let matcher = Matcher::bundled(&TrackerDb::bundled().unwrap());
    let limits = Limits {
        max_app_bytes: 10,
        ..Limits::default()
    };
    let scan = scan_apps_with(&reg, &roots, &matcher, limits);
    assert!(scan.apps.iter().any(|a| a.truncated));
    assert!(scan.apps.iter().all(|a| a.bytes_scanned <= 10));
}

#[test]
fn lists_skipped_files_and_scans_everything_on_request() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, roots) = setup(tmp.path());
    let matcher = Matcher::bundled(&TrackerDb::bundled().unwrap());
    // tool.exe (the Criteo address) is over the per-file limit; Sentry.dll is not.
    let limits = Limits {
        max_file_bytes: 10,
        ..Limits::default()
    };
    let scan = scan_apps_with(&reg, &roots, &matcher, limits);
    let native = scan.apps.iter().find(|a| a.name == "NativeTool").unwrap();
    assert!(native.truncated && !native.full_scan);
    assert_eq!(native.skipped_count, 1);
    assert_eq!(native.skipped[0].path, "tool.exe");
    assert_eq!(native.skipped[0].reason, ga_core::SkipReason::TooLarge);
    assert!(native.findings.iter().all(|f| f.company != "Criteo"), "the skipped file was not read");

    let files = std::sync::Mutex::new(Vec::new());
    let full = scan_one_app(&reg, &roots, &matcher, "nativetool", Limits::everything(), &|_, _, file| {
        files.lock().unwrap().push(file.to_owned());
    })
    .unwrap();
    assert!(full.full_scan && !full.truncated && full.skipped.is_empty());
    assert!(full.findings.iter().any(|f| f.company == "Criteo"));
    assert!(files.into_inner().unwrap().contains(&"tool.exe".to_owned()), "progress names each file");
    assert!(scan_one_app(&reg, &roots, &matcher, "Nope", Limits::everything(), &|_, _, _| {}).is_none());
}

#[test]
fn reports_progress_for_every_app() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, roots) = setup(tmp.path());
    let matcher = Matcher::bundled(&TrackerDb::bundled().unwrap());
    let calls = std::sync::Mutex::new(Vec::new());
    scan_apps_with_progress(&reg, &roots, &matcher, Limits::default(), &|done, total, name| {
        calls.lock().unwrap().push((done, total, name.to_owned()));
    });
    let calls = calls.into_inner().unwrap();
    assert_eq!(calls.first(), Some(&(0, 3, String::new())), "first call announces the total");
    assert!(calls.iter().any(|(d, t, _)| d == t), "a final call reports all done");
    assert!(calls.iter().any(|(_, _, n)| n == "Chatty"), "names the app being scanned");
}
