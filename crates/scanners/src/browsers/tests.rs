//! End-to-end tests against fake browser profiles in a temp folder.

use super::*;
use rusqlite::Connection;
use std::fs;

fn make_chromium_db(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE cookies (
             creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT,
             encrypted_value BLOB, path TEXT, expires_utc INTEGER, last_access_utc INTEGER);
         INSERT INTO cookies VALUES
             (0, '.doubleclick.net', 'IDE', 'secret-value', x'00', '/', 0, 13348540800000000),
             (0, 'www.example.com', 'session', 'secret-value', x'00', '/', 0, 0);",
    )
    .unwrap();
}

fn make_firefox_db(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_cookies (
             id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT,
             expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER);
         INSERT INTO moz_cookies (name, value, host, path, expiry, lastAccessed, creationTime)
         VALUES ('_ga', 'secret-value', '.google-analytics.com', '/', 0, 1704067200000000, 0);",
    )
    .unwrap();
}

#[test]
fn scans_chromium_and_firefox_profiles() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    let roaming = tmp.path().join("Roaming");

    make_chromium_db(&local.join(r"Google\Chrome\User Data\Default\Network\Cookies"));
    make_chromium_db(&local.join(r"Microsoft\Edge\User Data\Profile 1\Cookies"));
    make_firefox_db(&roaming.join(r"Mozilla\Firefox\Profiles\ab12.default-release\cookies.sqlite"));

    let scan = scan_cookies_in(&BrowserRoots {
        local_app_data: Some(local),
        app_data: Some(roaming),
    });

    assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
    assert_eq!(scan.profiles_scanned, 3);
    assert_eq!(scan.cookies.len(), 5);

    let chrome_ide = scan
        .cookies
        .iter()
        .find(|c| c.browser == Browser::Chrome && c.name == "IDE")
        .unwrap();
    assert_eq!(chrome_ide.host, "doubleclick.net");
    assert_eq!(chrome_ide.profile, "Default");
    assert_eq!(chrome_ide.last_access_unix, Some(1_704_067_200));

    let edge = scan.cookies.iter().find(|c| c.browser == Browser::Edge).unwrap();
    assert_eq!(edge.profile, "Profile 1");

    let ff = scan.cookies.iter().find(|c| c.browser == Browser::Firefox).unwrap();
    assert_eq!(ff.host, "google-analytics.com");
    assert_eq!(ff.profile, "default-release");
    assert_eq!(ff.last_access_unix, Some(1_704_067_200));
}

#[test]
fn never_exposes_cookie_values() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    make_chromium_db(&local.join(r"Google\Chrome\User Data\Default\Network\Cookies"));

    let scan = scan_cookies_in(&BrowserRoots {
        local_app_data: Some(local),
        app_data: None,
    });
    let debug = format!("{scan:?}");
    assert!(!debug.contains("secret-value"));
}

#[test]
fn missing_browsers_are_not_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = scan_cookies_in(&BrowserRoots {
        local_app_data: Some(tmp.path().to_path_buf()),
        app_data: Some(tmp.path().to_path_buf()),
    });
    assert_eq!(scan.profiles_scanned, 0);
    assert!(scan.cookies.is_empty());
    assert!(scan.warnings.is_empty());
}

#[test]
fn unreadable_database_becomes_a_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    let db = local.join(r"Google\Chrome\User Data\Default\Network\Cookies");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    fs::write(&db, b"not a sqlite file").unwrap();

    let scan = scan_cookies_in(&BrowserRoots {
        local_app_data: Some(local),
        app_data: None,
    });
    assert_eq!(scan.profiles_scanned, 1);
    assert_eq!(scan.warnings.len(), 1);
    assert_eq!(scan.warnings[0].browser, Browser::Chrome);
}

#[test]
fn deletes_only_chosen_cookies_and_skips_open_browsers() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    let roaming = tmp.path().join("Roaming");
    make_chromium_db(&local.join(r"Google\Chrome\User Data\Default\Network\Cookies"));
    make_chromium_db(&local.join(r"Microsoft\Edge\User Data\Default\Network\Cookies"));
    make_firefox_db(&roaming.join(r"Mozilla\Firefox\Profiles\ab12.default-release\cookies.sqlite"));
    let roots = BrowserRoots {
        local_app_data: Some(local),
        app_data: Some(roaming),
    };

    // Edge is "open": left alone. Delete tracker hosts and any `_ga`.
    let rule = |host: &str, name: &str| host.ends_with("doubleclick.net") || name == "_ga";
    let report = delete_cookies_in(&roots, &[Browser::Edge], &rule);
    assert_eq!(report.deleted, 2, "Chrome's IDE and Firefox's _ga");
    assert_eq!(report.profiles.len(), 2);
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].browser, Browser::Edge);

    let scan = scan_cookies_in(&roots);
    let left: Vec<(Browser, &str)> = scan.cookies.iter().map(|c| (c.browser, c.name.as_str())).collect();
    assert!(left.contains(&(Browser::Chrome, "session")), "other cookies stay");
    assert!(!left.contains(&(Browser::Chrome, "IDE")));
    assert!(left.contains(&(Browser::Edge, "IDE")), "the open browser was not touched");
    assert!(!left.iter().any(|(b, _)| *b == Browser::Firefox));
}