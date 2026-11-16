//! Firefox profiles under `%APPDATA%\Mozilla\Firefox\Profiles`.

use super::{BrowserRoots, copy_db, describe_error, dir_name, subdirs, warn};
use ga_core::{Browser, CookieRecord, CookieScan, normalize_host};
use rusqlite::Connection;
use std::path::Path;

pub(super) fn scan(roots: &BrowserRoots, scan: &mut CookieScan) {
    let Some(app_data) = &roots.app_data else { return };
    let profiles = app_data.join(r"Mozilla\Firefox\Profiles");

    for profile_dir in subdirs(&profiles) {
        let db = profile_dir.join("cookies.sqlite");
        if !db.is_file() {
            continue;
        }
        let profile = profile_name(&dir_name(&profile_dir));
        scan.profiles_scanned += 1;

        let result = copy_db(&db)
            .map_err(|e| describe_error(Browser::Firefox, &e))
            .and_then(|copy| {
                read_cookies(&copy.path, &profile)
                    .map_err(|e| format!("Could not read cookies: {e}"))
            });
        match result {
            Ok(mut cookies) => scan.cookies.append(&mut cookies),
            Err(message) => warn(scan, Browser::Firefox, &profile, message),
        }
    }
}

/// Every Firefox profile folder, with its display name.
pub(crate) fn profiles(roots: &BrowserRoots) -> Vec<(String, std::path::PathBuf)> {
    let Some(app_data) = &roots.app_data else { return Vec::new() };
    subdirs(&app_data.join(r"Mozilla\Firefox\Profiles"))
        .into_iter()
        .map(|dir| (profile_name(&dir_name(&dir)), dir))
        .collect()
}

/// Firefox folders look like `x1y2z3.default-release`; show `default-release`.
fn profile_name(folder: &str) -> String {
    folder
        .split_once('.')
        .map(|(_, name)| name)
        .unwrap_or(folder)
        .to_owned()
}

/// Reads host, name and last access from `moz_cookies`. `value` is never selected.
pub(super) fn read_cookies(db: &Path, profile: &str) -> rusqlite::Result<Vec<CookieRecord>> {
    let conn = Connection::open(db)?;
    let mut stmt = conn.prepare("SELECT host, name, lastAccessed FROM moz_cookies")?;
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        // Microseconds since the Unix epoch.
        let last_access: Option<i64> = row.get(2)?;
        Ok(CookieRecord {
            browser: Browser::Firefox,
            profile: profile.to_owned(),
            host: normalize_host(&host),
            name,
            last_access_unix: last_access.filter(|t| *t > 0).map(|t| t / 1_000_000),
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::profile_name;

    #[test]
    fn strips_random_prefix_from_profile_folder() {
        assert_eq!(profile_name("x1y2z3.default-release"), "default-release");
        assert_eq!(profile_name("plain"), "plain");
    }
}
