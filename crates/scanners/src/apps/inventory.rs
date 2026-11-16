//! Finds installed desktop apps: uninstall entries in the registry, plus a
//! sweep of the usual program folders for apps that do not register (or
//! register without an install path, which is most of them).

use crate::windows_privacy::registry::{Hive, Registry};
use std::path::{Path, PathBuf};

const UNINSTALL_KEYS: [(Hive, &str); 3] = [
    (Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (Hive::LocalMachine, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
];

/// Program Files subfolders that are part of Windows or shared runtimes.
const SKIP_PROGRAM_FILES: &[&str] = &[
    "common files",
    "windowsapps",
    "modifiablewindowsapps",
    "internet explorer",
    "microsoft update health tools",
    "reference assemblies",
    "msbuild",
    "dotnet",
    "uninstall information",
];

/// %LOCALAPPDATA% subfolders that hold caches or browser data, not apps.
const SKIP_LOCAL_APP_DATA: &[&str] = &[
    "programs",
    "temp",
    "packages",
    "microsoft",
    "google",
    "mozilla",
    "bravesoftware",
    "vivaldi",
    "crashdumps",
    "d3dscache",
    "connecteddevicesplatform",
    "virtualstore",
    "pip",
    "npm-cache",
    "yarn",
];

/// Where to look for apps. Normally from the environment; tests use temp dirs.
#[derive(Debug, Clone, Default)]
pub struct AppRoots {
    pub program_files: Vec<PathBuf>,
    pub local_app_data: Option<PathBuf>,
    /// `C:\Windows`; anything below it is skipped.
    pub windows_dir: Option<PathBuf>,
}

impl AppRoots {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var_os(k).map(PathBuf::from);
        let mut program_files: Vec<PathBuf> = ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"]
            .iter()
            .filter_map(|k| var(k))
            .collect();
        program_files.sort();
        program_files.dedup();
        Self {
            program_files,
            local_app_data: var("LOCALAPPDATA"),
            windows_dir: var("SystemRoot"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub dir: PathBuf,
}

pub fn discover(reg: &dyn Registry, roots: &AppRoots) -> Vec<Candidate> {
    let mut apps: Vec<Candidate> = Vec::new();
    for c in from_registry(reg, roots) {
        if !apps.iter().any(|a| same_or_nested(&a.dir, &c.dir)) {
            apps.push(c);
        }
    }
    for c in sweep(roots) {
        if !apps.iter().any(|a| same_or_nested(&a.dir, &c.dir)) {
            apps.push(c);
        }
    }
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

fn from_registry(reg: &dyn Registry, roots: &AppRoots) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (hive, root) in UNINSTALL_KEYS {
        for sub in reg.subkeys(hive, root) {
            let key = format!(r"{root}\{sub}");
            let get = |name: &str| reg.string(hive, &key, name).map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
            let Some(name) = get("DisplayName") else { continue };
            // Windows components, updates and patches are not apps.
            if reg.dword(hive, &key, "SystemComponent") == Some(1)
                || get("ParentKeyName").is_some()
                || get("ReleaseType").is_some_and(|t| t.contains("Update") || t == "Hotfix")
            {
                continue;
            }
            let dir = get("InstallLocation")
                .map(|p| PathBuf::from(expand(p.trim_matches('"'))))
                .filter(|p| p.is_dir())
                .or_else(|| get("DisplayIcon").and_then(|icon| icon_dir(&icon)));
            let Some(dir) = dir else { continue };
            if too_broad(&dir, roots) {
                continue;
            }
            out.push(Candidate {
                name,
                publisher: get("Publisher"),
                version: get("DisplayVersion"),
                dir,
            });
        }
    }
    out
}

/// `"C:\Apps\Foo\foo.exe",0` -> `C:\Apps\Foo`. Squirrel installers put the
/// exe in a versioned `app-1.2.3` folder; use its parent so updates are covered.
fn icon_dir(icon: &str) -> Option<PathBuf> {
    let mut path = icon.trim().trim_matches('"').to_owned();
    if let Some((before, index)) = path.rsplit_once(',')
        && index.trim().trim_start_matches('-').chars().all(|c| c.is_ascii_digit())
    {
        path = before.trim().trim_matches('"').to_owned();
    }
    let file = PathBuf::from(expand(&path));
    let mut dir = file.parent()?.to_path_buf();
    if dir.file_name().is_some_and(|n| n.to_string_lossy().to_lowercase().starts_with("app-")) {
        dir = dir.parent()?.to_path_buf();
    }
    dir.is_dir().then_some(dir)
}

/// Expands `%VAR%` references.
fn expand(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else { break };
        let var = &rest[start + 1..start + 1 + len];
        out.push_str(&rest[..start]);
        match std::env::var(var) {
            Ok(v) => out.push_str(&v),
            Err(_) => out.push_str(&rest[start..start + len + 2]),
        }
        rest = &rest[start + len + 2..];
    }
    out.push_str(rest);
    out
}

/// A drive root, a whole Program Files folder or anything inside Windows
/// would sweep up far more than one app.
fn too_broad(dir: &Path, roots: &AppRoots) -> bool {
    let is = |other: &Path| lower(dir) == lower(other);
    dir.parent().is_none()
        || dir.components().count() <= 2
        || roots.program_files.iter().any(|p| is(p))
        || roots.local_app_data.as_deref().is_some_and(is)
        || roots.windows_dir.as_deref().is_some_and(|w| is_within(dir, w))
}

fn sweep(roots: &AppRoots) -> Vec<Candidate> {
    let mut out = Vec::new();
    for pf in &roots.program_files {
        for dir in crate::browsers::subdirs(pf) {
            let name = crate::browsers::dir_name(&dir);
            let l = name.to_lowercase();
            if l.starts_with("windows") || SKIP_PROGRAM_FILES.contains(&l.as_str()) {
                continue;
            }
            if has_app_payload(&dir) {
                out.push(folder_app(name, dir));
            }
        }
    }
    if let Some(local) = &roots.local_app_data {
        for dir in crate::browsers::subdirs(&local.join("Programs")) {
            if has_app_payload(&dir) {
                out.push(folder_app(crate::browsers::dir_name(&dir), dir));
            }
        }
        for dir in crate::browsers::subdirs(local) {
            let name = crate::browsers::dir_name(&dir);
            if SKIP_LOCAL_APP_DATA.contains(&name.to_lowercase().as_str()) {
                continue;
            }
            if has_app_payload(&dir) {
                out.push(folder_app(name, dir));
            }
        }
    }
    out
}

fn folder_app(name: String, dir: PathBuf) -> Candidate {
    Candidate {
        name,
        publisher: None,
        version: None,
        dir,
    }
}

/// An `.exe` within two levels, or an Electron `app.asar` within three.
fn has_app_payload(dir: &Path) -> bool {
    fn walk(dir: &Path, depth: usize) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else { return false };
        for e in entries.flatten().take(500) {
            let path = e.path();
            let Ok(t) = e.file_type() else { continue };
            if t.is_file() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if (depth <= 2 && n.ends_with(".exe")) || n == "app.asar" {
                    return true;
                }
            } else if t.is_dir() && depth < 3 && walk(&path, depth + 1) {
                return true;
            }
        }
        false
    }
    walk(dir, 1)
}

fn lower(p: &Path) -> String {
    p.to_string_lossy().trim_end_matches(['\\', '/']).to_lowercase()
}

fn is_within(path: &Path, root: &Path) -> bool {
    let (p, r) = (lower(path), lower(root));
    p == r || p.starts_with(&format!("{r}\\")) || p.starts_with(&format!("{r}/"))
}

/// One folder equals or contains the other.
fn same_or_nested(a: &Path, b: &Path) -> bool {
    is_within(a, b) || is_within(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_paths_resolve_to_app_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("Slack").join("app-4.41.0");
        std::fs::create_dir_all(&app).unwrap();
        let icon = format!("\"{}\",0", app.join("slack.exe").display());
        assert_eq!(icon_dir(&icon), Some(tmp.path().join("Slack")));
        assert_eq!(icon_dir(r"C:\does\not\exist\x.exe"), None);
    }

    #[test]
    fn nested_folders_count_as_one_app() {
        assert!(same_or_nested(Path::new(r"C:\Program Files\Docker"), Path::new(r"C:\Program Files\Docker\Docker")));
        assert!(!same_or_nested(Path::new(r"C:\Apps\Foo"), Path::new(r"C:\Apps\FooBar")));
    }

    #[test]
    fn broad_folders_are_rejected() {
        let roots = AppRoots {
            program_files: vec![PathBuf::from(r"C:\Program Files")],
            local_app_data: None,
            windows_dir: Some(PathBuf::from(r"C:\Windows")),
        };
        assert!(too_broad(Path::new(r"C:\Program Files"), &roots));
        assert!(too_broad(Path::new(r"C:\Windows\Installer\{ABC}"), &roots));
        assert!(too_broad(Path::new(r"C:\"), &roots));
        assert!(!too_broad(Path::new(r"C:\Program Files\Obsidian"), &roots));
    }
}
