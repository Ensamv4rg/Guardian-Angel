//! Tracking and telemetry SDKs inside installed desktop apps.
//!
//! Finds apps through the registry and the usual program folders, then looks
//! for SDK files, npm packages (including inside Electron `app.asar`
//! archives) and tracker addresses in the apps' code. Read-only, with size
//! limits per file and per app. Store (MSIX) apps under `WindowsApps` are
//! not readable without elevation and are skipped for now.

mod asar;
mod inspect;
pub mod inventory;
pub mod matcher;

pub use inspect::Limits;
pub use inventory::{AppRoots, Candidate};

use crate::windows_privacy::registry::Registry;
use ga_core::AppScan;
use ga_knowledge::TrackerDb;
use matcher::Matcher;

/// Scans every installed app for the current user.
#[cfg(windows)]
pub fn scan_apps(db: &TrackerDb) -> AppScan {
    scan_apps_with(
        &crate::windows_privacy::WindowsRegistry::default(),
        &AppRoots::from_env(),
        &Matcher::bundled(db),
        Limits::default(),
    )
}

pub fn scan_apps_with(reg: &dyn Registry, roots: &AppRoots, matcher: &Matcher, limits: Limits) -> AppScan {
    let candidates = inventory::discover(reg, roots);
    let mut apps = merge_same_name(inspect_parallel(&candidates, matcher, limits));
    // Apps with the most certain findings first.
    apps.sort_by(|a, b| {
        let score = |x: &ga_core::InstalledApp| {
            let high = x.findings.iter().filter(|f| f.confidence == ga_core::Confidence::High).count();
            (high, x.findings.len())
        };
        score(b).cmp(&score(a)).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    AppScan {
        apps,
        warnings: Vec::new(),
    }
}

/// The same product installed twice (32- and 64-bit, or per-user and
/// per-machine) is shown once, with the findings of both.
fn merge_same_name(apps: Vec<ga_core::InstalledApp>) -> Vec<ga_core::InstalledApp> {
    let mut out: Vec<ga_core::InstalledApp> = Vec::new();
    for app in apps {
        match out.iter_mut().find(|a| a.name.eq_ignore_ascii_case(&app.name)) {
            Some(existing) => {
                for f in app.findings {
                    match existing.findings.iter_mut().find(|e| e.sdk == f.sdk) {
                        Some(e) => {
                            e.confidence = e.confidence.min(f.confidence);
                            for ev in f.evidence {
                                if e.evidence.len() < 4 && !e.evidence.contains(&ev) {
                                    e.evidence.push(ev);
                                }
                            }
                        }
                        None => existing.findings.push(f),
                    }
                }
                existing.bytes_scanned += app.bytes_scanned;
                existing.truncated |= app.truncated;
                existing.electron |= app.electron;
            }
            None => out.push(app),
        }
    }
    out
}

/// Apps scanned at once. Most time is spent waiting on disk and antivirus,
/// so a few threads help without loading the machine.
const PARALLEL_APPS: usize = 4;

fn inspect_parallel(candidates: &[Candidate], matcher: &Matcher, limits: Limits) -> Vec<ga_core::InstalledApp> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new(Vec::with_capacity(candidates.len()));
    std::thread::scope(|s| {
        for _ in 0..PARALLEL_APPS.min(candidates.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(c) = candidates.get(i) else { break };
                    let app = inspect::inspect(c, matcher, limits);
                    results.lock().unwrap_or_else(|p| p.into_inner()).push(app);
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests;
