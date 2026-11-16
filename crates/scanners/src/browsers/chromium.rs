//! Chromium-based browsers: Chrome, Edge, Brave, Vivaldi, Opera.

use super::{BrowserRoots, copy_db, describe_error, dir_name, subdirs, warn};
use ga_core::{Browser, CookieRecord, CookieScan, normalize_host};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Seconds between 1601-01-01 (Windows/Chromium epoch) and 1970-01-01.
const CHROMIUM_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

enum Root {
    Local,
    Roaming,
}

/// (browser, which AppData folder, path to the "User Data" folder)
const INSTALLS: &[(Browser, Root, &str)] = &[
    (Browser::Chrome, Root::Local, r"Google\Chrome\User Data"),
    (Browser::Edge, Root::Local, r"Microsoft\Edge\User Data"),
    (Browser::Brave, Root::Local, r"BraveSoftware\Brave-Browser\User Data"),
    (Browser::Vivaldi, Root::Local, r"Vivaldi\User Data"),
    (Browser::Opera, Root::Roaming, r"Opera Software\Opera Stable"),
    (Browser::OperaGx, Root::Roaming, r"Opera Software\Opera GX Stable"),
];

/// A Chromium browser profile folder.
pub(crate) struct Profile {
    pub browser: Browser,
    pub name: String,
    pub dir: PathBuf,
}

/// Finds every Chromium profile under the given roots. A folder counts as a
/// profile if it holds preferences or a cookie database.
pub(crate) fn profiles(roots: &BrowserRoots) -> Vec<Profile> {
    let mut found = Vec::new();
    for (browser, root, rel) in INSTALLS {
        let base = match root {
            Root::Local => roots.local_app_data.as_ref(),
            Root::Roaming => roots.app_data.as_ref(),
        };
        let Some(base) = base else { continue };
        let user_data = base.join(rel);
        if !user_data.is_dir() {
            continue;
        }

        // Opera keeps a single profile directly in its folder; the others keep
        // "Default", "Profile 1", ... inside "User Data".
        let mut candidates = vec![user_data.clone()];
        candidates.extend(subdirs(&user_data));

        for dir in candidates {
            let is_profile = dir.join("Preferences").is_file()
                || dir.join("Secure Preferences").is_file()
                || cookie_db(&dir).is_some();
            if !is_profile {
                continue;
            }
            let name = if dir == user_data {
                "Default".to_owned()
            } else {
                dir_name(&dir)
            };
            found.push(Profile {
                browser: *browser,
                name,
                dir,
            });
        }
    }
    found
}

pub(super) fn scan(roots: &BrowserRoots, scan: &mut CookieScan) {
    for profile in profiles(roots) {
        let Some(db) = cookie_db(&profile.dir) else { continue };
        scan.profiles_scanned += 1;
        match read_profile(&db, profile.browser, &profile.name) {
            Ok(mut cookies) => scan.cookies.append(&mut cookies),
            Err(message) => warn(scan, profile.browser, &profile.name, message),
        }
    }
}

/// Newer Chromium keeps cookies in `Network\Cookies`; older versions in `Cookies`.
fn cookie_db(profile_dir: &Path) -> Option<PathBuf> {
    [profile_dir.join("Network").join("Cookies"), profile_dir.join("Cookies")]
        .into_iter()
        .find(|p| p.is_file())
}

fn read_profile(db: &Path, browser: Browser, profile: &str) -> Result<Vec<CookieRecord>, String> {
    let copy = copy_db(db).map_err(|e| describe_error(browser, &e))?;
    read_cookies(&copy.path, browser, profile).map_err(|e| format!("Could not read cookies: {e}"))
}

/// Reads host, name and last access from a Chromium `cookies` table.
/// `encrypted_value` and `value` are deliberately never selected.
pub(super) fn read_cookies(
    db: &Path,
    browser: Browser,
    profile: &str,
) -> rusqlite::Result<Vec<CookieRecord>> {
    let conn = Connection::open(db)?;
    let mut stmt = conn.prepare("SELECT host_key, name, last_access_utc FROM cookies")?;
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let last_access: Option<i64> = row.get(2)?;
        Ok(CookieRecord {
            browser,
            profile: profile.to_owned(),
            host: normalize_host(&host),
            name,
            last_access_unix: last_access.and_then(chromium_time_to_unix),
        })
    })?;
    rows.collect()
}

/// Chromium stores times as microseconds since 1601-01-01; 0 means unset.
fn chromium_time_to_unix(micros: i64) -> Option<i64> {
    (micros > 0).then(|| micros / 1_000_000 - CHROMIUM_EPOCH_OFFSET_SECS)
}

#[cfg(test)]
mod tests {
    use super::chromium_time_to_unix;

    #[test]
    fn converts_chromium_timestamps() {
        // 2024-01-01T00:00:00Z
        assert_eq!(chromium_time_to_unix(13_348_540_800_000_000), Some(1_704_067_200));
        assert_eq!(chromium_time_to_unix(0), None);
    }
}
