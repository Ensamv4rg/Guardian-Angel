//! Whose data a request is about: the user's profile folders, registry hive
//! and Guardian Angel's own data folder for that user.

use ga_scanners::apps::AppRoots;
use ga_scanners::browsers::BrowserRoots;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct UserContext {
    /// Stable key for this user's state: their SID, or "local".
    pub key: String,
    pub sid: Option<String>,
    /// Read and write `HKEY_USERS\<SID>` instead of `HKEY_CURRENT_USER`
    /// (the service runs as SYSTEM, so its own HKCU is not the user's).
    pub use_user_hive: bool,
    pub browser_roots: BrowserRoots,
    pub app_roots: AppRoots,
    /// Journal, baseline and alerts for this user.
    pub data_dir: PathBuf,
}

impl UserContext {
    /// The user this process runs as (console mode, CLI).
    pub fn current(data_root: &Path) -> Self {
        #[cfg(windows)]
        let sid = ga_platform_win::process_user_sid(std::process::id());
        #[cfg(not(windows))]
        let sid: Option<String> = None;
        let key = sid.clone().unwrap_or_else(|| "local".to_owned());
        Self {
            data_dir: data_root.join("users").join(&key),
            key,
            sid,
            use_user_hive: false,
            browser_roots: BrowserRoots::from_env(),
            app_roots: AppRoots::from_env(),
        }
    }

    /// Another signed-in user, found through the registry's profile list
    /// (service mode). `None` if the SID has no local profile.
    #[cfg(windows)]
    pub fn for_sid(sid: &str, data_root: &Path) -> Option<Self> {
        use ga_scanners::windows_privacy::{Hive, Registry, WindowsRegistry};
        let key = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        let profile = WindowsRegistry::default().string(Hive::LocalMachine, &key, "ProfileImagePath")?;
        let profile = PathBuf::from(expand_system_drive(&profile));
        if !profile.is_dir() {
            return None;
        }
        let local = profile.join("AppData").join("Local");
        let mut app_roots = AppRoots::from_env();
        app_roots.local_app_data = Some(local.clone());
        Some(Self {
            key: sid.to_owned(),
            sid: Some(sid.to_owned()),
            use_user_hive: true,
            browser_roots: BrowserRoots {
                local_app_data: Some(local),
                app_data: Some(profile.join("AppData").join("Roaming")),
            },
            app_roots,
            data_dir: data_root.join("users").join(sid),
        })
    }

    #[cfg(windows)]
    pub fn registry(&self) -> ga_scanners::windows_privacy::WindowsRegistry {
        match (&self.sid, self.use_user_hive) {
            (Some(sid), true) => ga_scanners::windows_privacy::WindowsRegistry::for_user(sid),
            _ => Default::default(),
        }
    }

    #[cfg(windows)]
    pub fn store(&self) -> ga_blocker::settings::store::WindowsStore {
        match (&self.sid, self.use_user_hive) {
            (Some(sid), true) => ga_blocker::settings::store::WindowsStore::for_user(sid),
            _ => Default::default(),
        }
    }
}

/// Profile paths are sometimes stored as `%SystemDrive%\Users\name`.
#[cfg(windows)]
fn expand_system_drive(path: &str) -> String {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    path.replace("%SystemDrive%", &drive).replace("%SYSTEMDRIVE%", &drive)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn service_view_of_current_user_matches_console_view() {
        let tmp = tempfile::tempdir().unwrap();
        let me = UserContext::current(tmp.path());
        let sid = me.sid.clone().expect("own SID");
        let via_service = UserContext::for_sid(&sid, tmp.path()).expect("own profile is listed");
        assert_eq!(via_service.browser_roots.local_app_data, me.browser_roots.local_app_data);
        assert_eq!(via_service.browser_roots.app_data, me.browser_roots.app_data);
        assert_eq!(via_service.data_dir, me.data_dir);
        assert!(UserContext::for_sid("S-1-5-21-0-0-0-424242", tmp.path()).is_none());
    }
}
