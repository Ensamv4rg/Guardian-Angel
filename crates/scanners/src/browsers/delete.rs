//! Deleting cookies from browser profiles.
//!
//! The browser must be closed: a running browser keeps its cookies in memory
//! and writes them back, and Chromium locks the file. The caller checks which
//! browsers are running and passes them in `skip`; a locked file is reported
//! the same way. Only whole rows chosen by the caller's rule are deleted, in
//! one transaction per profile, so a profile is never left half-done.

use super::{BrowserRoots, chromium, dir_name, firefox};
use ga_core::{Browser, normalize_host};
use rusqlite::Connection;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DeleteReport {
    pub deleted: usize,
    pub profiles: Vec<ProfileDeleted>,
    /// Browsers left alone, with the reason (usually "close it first").
    pub skipped: Vec<SkippedBrowser>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProfileDeleted {
    pub browser: Browser,
    pub profile: String,
    pub deleted: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SkippedBrowser {
    pub browser: Browser,
    pub reason: String,
}

/// Deletes every cookie for which `delete(host, name)` is true, in every
/// profile of every browser not listed in `skip`.
pub fn delete_cookies_in(roots: &BrowserRoots, skip: &[Browser], delete: &dyn Fn(&str, &str) -> bool) -> DeleteReport {
    let mut report = DeleteReport::default();
    for browser in skip {
        report.skipped.push(SkippedBrowser {
            browser: *browser,
            reason: format!("{browser} is open. Close it and try again."),
        });
    }

    let mut targets: Vec<(Browser, String, std::path::PathBuf, &str, &str)> = Vec::new();
    for p in chromium::profiles(roots) {
        if let Some(db) = chromium::cookie_db(&p.dir) {
            targets.push((p.browser, p.name, db, "cookies", "host_key"));
        }
    }
    for (name, dir) in firefox::profiles(roots) {
        let db = dir.join("cookies.sqlite");
        if db.is_file() {
            targets.push((Browser::Firefox, name, db, "moz_cookies", "host"));
        }
    }

    for (browser, profile, db, table, host_col) in targets {
        if skip.contains(&browser) || report.skipped.iter().any(|s| s.browser == browser) {
            continue;
        }
        match delete_in(&db, table, host_col, delete) {
            Ok(0) => {}
            Ok(n) => {
                report.deleted += n;
                report.profiles.push(ProfileDeleted {
                    browser,
                    profile: if profile.is_empty() { dir_name(&db) } else { profile },
                    deleted: n,
                });
            }
            Err(e) => report.skipped.push(SkippedBrowser {
                browser,
                reason: if e.contains("locked") || e.contains("busy") || e.contains("being used") {
                    format!("{browser} is open. Close it and try again.")
                } else {
                    format!("Could not change {browser}'s cookies: {e}")
                },
            }),
        }
    }
    report
}

fn delete_in(db: &Path, table: &str, host_col: &str, delete: &dyn Fn(&str, &str) -> bool) -> Result<usize, String> {
    let mut conn = Connection::open(db).map_err(|e| e.to_string())?;
    // Fail at once instead of waiting if the browser holds the database.
    conn.busy_timeout(std::time::Duration::ZERO).map_err(|e| e.to_string())?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let ids: Vec<i64> = {
        // Values are never selected (NFR-5).
        let mut stmt = tx
            .prepare(&format!("SELECT rowid, {host_col}, name FROM {table}"))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(|e| e.to_string())?;
        rows.filter_map(Result::ok)
            .filter(|(_, host, name)| delete(&normalize_host(host), name))
            .map(|(id, _, _)| id)
            .collect()
    };
    {
        let mut stmt = tx
            .prepare(&format!("DELETE FROM {table} WHERE rowid = ?1"))
            .map_err(|e| e.to_string())?;
        for id in &ids {
            stmt.execute([id]).map_err(|e| e.to_string())?;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(ids.len())
}
