//! Looks inside one app folder for SDKs: bundled files, npm packages and
//! tracker addresses in code. Reads only, within fixed limits.

use super::asar::Asar;
use super::inventory::Candidate;
use super::matcher::{Found, Matcher, Owner};
use ga_core::{AppFinding, Category, Confidence, InstalledApp};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_depth: usize,
    pub max_entries: usize,
    /// Larger files are skipped for content search.
    pub max_file_bytes: u64,
    /// Content search stops after reading this much of one app.
    pub max_app_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_entries: 20_000,
            // Tracker code sits in an app's own smaller files; huge binaries
            // are engines and runtimes. Antivirus scanning of every opened
            // file makes reading more than this per app very slow.
            max_file_bytes: 32 * 1024 * 1024,
            max_app_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Runtime files that embed Chromium, Qt WebEngine or the C runtime. They
/// contain web addresses of their own and say nothing about the app.
const RUNTIME_PREFIXES: &[&str] = &[
    "libcef",
    "chrome_elf",
    "libegl",
    "libglesv2",
    "vk_swiftshader",
    "vulkan-1",
    "ffmpeg",
    "d3dcompiler",
    "icu",
    "qt5webengine",
    "qt6webengine",
    "qtwebengine",
    "api-ms-win",
    "vcruntime",
    "msvcp",
    "ucrtbase",
    "concrt",
];

const SEARCHED_EXTENSIONS: &[&str] = &["dll", "exe", "js", "cjs", "mjs", "node"];

/// Evidence collected for one SDK or company.
#[derive(Default)]
struct Hit {
    high: bool,
    evidence: Vec<String>,
}

const MAX_EVIDENCE: usize = 4;

impl Hit {
    fn add(&mut self, high: bool, text: String) {
        self.high |= high;
        if self.evidence.len() < MAX_EVIDENCE && !self.evidence.contains(&text) {
            self.evidence.push(text);
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Sdk(usize),
    Company(String),
}

pub fn inspect(app: &Candidate, matcher: &Matcher, limits: Limits) -> InstalledApp {
    let files = walk(&app.dir, limits);
    let electron = files.iter().any(|f| f.name == "app.asar");
    let mut hits: BTreeMap<Key, (Hit, Option<Category>)> = BTreeMap::new();
    let rel = |p: &Path| p.strip_prefix(&app.dir).unwrap_or(p).display().to_string();

    // 1. Bundled SDK files and on-disk node_modules packages.
    for f in &files {
        if let Some(sdk) = matcher.sdk_for_file(&f.name) {
            entry(&mut hits, Key::Sdk(sdk)).add(true, format!("Bundled file: {}", rel(&f.path)));
        }
        if let Some(pkg) = &f.package
            && let Some(sdk) = matcher.sdk_for_package(pkg)
        {
            entry(&mut hits, Key::Sdk(sdk)).add(true, format!("Package: {pkg}"));
        }
    }

    // 2. Packages inside Electron archives.
    for f in files.iter().filter(|f| f.name == "app.asar") {
        let Ok(asar) = Asar::open(&f.path) else { continue };
        let mut pkgs = asar.packages();
        pkgs.extend(asar.dependencies());
        for pkg in pkgs {
            if let Some(sdk) = matcher.sdk_for_package(&pkg) {
                entry(&mut hits, Key::Sdk(sdk)).add(true, format!("Package: {pkg} (in app.asar)"));
            }
        }
    }

    // 3. Tracker addresses in code. For Electron apps the exe and DLLs are
    // the Chromium runtime, so only the app's own code is searched.
    let mut targets: Vec<&FileInfo> = files
        .iter()
        .filter(|f| f.size <= limits.max_file_bytes && searchable(f, electron))
        .collect();
    // App code first: archives and scripts, then native files by size.
    targets.sort_by_key(|f| (!matches!(f.ext.as_str(), "asar" | "js" | "cjs" | "mjs"), f.size));

    let mut scanned = 0u64;
    let mut truncated = false;
    for f in targets {
        if scanned >= limits.max_app_bytes {
            truncated = true;
            break;
        }
        let mut found = Found::new();
        let budget = limits.max_app_bytes - scanned;
        if let Ok(n) = matcher.scan_file(&f.path, budget, &mut found) {
            scanned += n;
            if n < f.size {
                truncated = true;
            }
        }
        for (pattern, example) in found {
            let text = format!("Address in code: {example} ({})", rel(&f.path));
            match matcher.owner(pattern) {
                Owner::Sdk(i) => entry(&mut hits, Key::Sdk(*i)).add(false, text),
                Owner::Tracker { company, category } => {
                    let (hit, cat) = hits.entry(Key::Company(company.clone())).or_default();
                    hit.add(false, text);
                    cat.get_or_insert(*category);
                }
            }
        }
    }

    let mut findings: Vec<AppFinding> = hits
        .into_iter()
        .map(|(key, (hit, category))| {
            let confidence = if hit.high { Confidence::High } else { Confidence::Medium };
            match key {
                Key::Sdk(i) => {
                    let sdk = &matcher.sdks[i];
                    AppFinding {
                        sdk: sdk.name.clone(),
                        company: sdk.company.clone(),
                        category: sdk.category,
                        purpose: sdk.purpose.clone(),
                        confidence,
                        evidence: hit.evidence,
                    }
                }
                Key::Company(company) => {
                    let category = category.unwrap_or(Category::Analytics);
                    AppFinding {
                        sdk: company.clone(),
                        company,
                        category,
                        purpose: format!("{category} (address found in the app's code)"),
                        confidence,
                        evidence: hit.evidence,
                    }
                }
            }
        })
        .collect();
    findings.sort_by(|a, b| a.confidence.cmp(&b.confidence).then_with(|| a.sdk.cmp(&b.sdk)));

    InstalledApp {
        name: app.name.clone(),
        publisher: app.publisher.clone(),
        version: app.version.clone(),
        install_dir: app.dir.display().to_string(),
        electron,
        findings,
        bytes_scanned: scanned,
        truncated,
    }
}

fn entry(hits: &mut BTreeMap<Key, (Hit, Option<Category>)>, key: Key) -> &mut Hit {
    &mut hits.entry(key).or_default().0
}

fn searchable(f: &FileInfo, electron: bool) -> bool {
    if f.ext == "asar" {
        return true;
    }
    if !SEARCHED_EXTENSIONS.contains(&f.ext.as_str()) || RUNTIME_PREFIXES.iter().any(|p| f.name.starts_with(p)) {
        return false;
    }
    // In Electron apps, skip the Chromium runtime binaries but keep native
    // add-ons (`.node`) and unpacked scripts.
    !(electron && matches!(f.ext.as_str(), "exe" | "dll"))
}

struct FileInfo {
    path: PathBuf,
    /// Lowercase file name.
    name: String,
    ext: String,
    size: u64,
    /// Set for a folder directly inside `node_modules` (or a scope folder).
    package: Option<String>,
}

/// Lists files under `root` breadth-first, within the depth and entry limits.
/// Folders directly inside `node_modules` are reported as packages.
fn walk(root: &Path, limits: Limits) -> Vec<FileInfo> {
    let mut out = Vec::new();
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = queue.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let parent = dir.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let grandparent = dir
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        for e in entries.flatten() {
            seen += 1;
            if seen > limits.max_entries {
                return out;
            }
            let Ok(t) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            if t.is_dir() {
                let package = if parent == "node_modules" && !name.starts_with('@') {
                    Some(name.clone())
                } else if grandparent == "node_modules" && parent.starts_with('@') {
                    Some(format!("{parent}/{name}"))
                } else {
                    None
                };
                if let Some(pkg) = package {
                    out.push(FileInfo {
                        path: e.path(),
                        name: String::new(),
                        ext: String::new(),
                        size: 0,
                        package: Some(pkg),
                    });
                }
                if depth < limits.max_depth {
                    queue.push((e.path(), depth + 1));
                }
            } else if t.is_file() {
                let lname = name.to_lowercase();
                let ext = lname.rsplit_once('.').map(|(_, x)| x.to_owned()).unwrap_or_default();
                out.push(FileInfo {
                    path: e.path(),
                    size: e.metadata().map(|m| m.len()).unwrap_or(0),
                    name: lname,
                    ext,
                    package: None,
                });
            }
        }
    }
    out
}
