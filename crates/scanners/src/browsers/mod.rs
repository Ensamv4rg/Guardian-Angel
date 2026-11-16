//! Browser profile scanning.
//!
//! Browsers keep their cookie stores open while running, so each database is
//! copied to a private temp folder first and read from the copy. Only the
//! cookie's host, name and last-access time are read; values are never
//! selected (requirement NFR-5).

pub(crate) mod chromium;
pub(crate) mod firefox;

use ga_core::{Browser, CookieScan, ScanWarning};
use std::io;
use std::path::{Path, PathBuf};

/// Where browsers keep their profiles. Normally read from the environment;
/// tests point it at a temporary folder.
#[derive(Debug, Clone)]
pub struct BrowserRoots {
    /// `%LOCALAPPDATA%`
    pub local_app_data: Option<PathBuf>,
    /// `%APPDATA%`
    pub app_data: Option<PathBuf>,
}

impl BrowserRoots {
    pub fn from_env() -> Self {
        Self {
            local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            app_data: std::env::var_os("APPDATA").map(PathBuf::from),
        }
    }
}

/// Scans every supported browser for the current Windows user.
pub fn scan_cookies() -> CookieScan {
    scan_cookies_in(&BrowserRoots::from_env())
}

/// Scans every supported browser under the given roots.
pub fn scan_cookies_in(roots: &BrowserRoots) -> CookieScan {
    let mut scan = CookieScan::default();
    chromium::scan(roots, &mut scan);
    firefox::scan(roots, &mut scan);
    scan
}

/// A database copied into a temp folder. The folder is deleted on drop.
struct DbCopy {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

/// Copies a SQLite database and its WAL/journal side files into a new temp folder.
fn copy_db(src: &Path) -> io::Result<DbCopy> {
    let dir = tempfile::Builder::new().prefix("ga-scan-").tempdir()?;
    let path = dir.path().join("db.sqlite");
    std::fs::copy(src, &path)?;

    // Recent writes may still sit in the write-ahead log. Missing side files
    // are normal; failing to copy one only means slightly older data.
    for suffix in ["-wal", "-journal"] {
        let mut side = src.as_os_str().to_owned();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.exists() {
            let mut dest = path.as_os_str().to_owned();
            dest.push(suffix);
            let _ = std::fs::copy(&side, PathBuf::from(dest));
        }
    }

    Ok(DbCopy { _dir: dir, path })
}

/// Turns a copy or read failure into a message a non-technical user can act on.
fn describe_error(browser: Browser, err: &io::Error) -> String {
    // ERROR_SHARING_VIOLATION (32) / ERROR_LOCK_VIOLATION (33)
    match err.raw_os_error() {
        Some(32) | Some(33) => format!(
            "{browser} is running and has locked its cookie database. Close {browser} and scan again."
        ),
        _ => format!("Could not read the cookie database: {err}"),
    }
}

fn warn(scan: &mut CookieScan, browser: Browser, profile: &str, message: String) {
    scan.warnings.push(ScanWarning {
        browser,
        profile: profile.to_owned(),
        message,
    });
}

/// Subfolders of `dir`, sorted for stable output. Unreadable entries are skipped.
pub(crate) fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs
}

pub(crate) fn dir_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
