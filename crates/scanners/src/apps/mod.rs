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

pub use inspect::{FileProgress, Limits};
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
    scan_apps_with_progress(reg, roots, matcher, limits, &|_, _, _| {})
}

/// Reports progress as (apps finished, apps in total, app being scanned).
pub type Progress<'a> = &'a (dyn Fn(usize, usize, &str) + Sync);

pub fn scan_apps_with_progress(
    reg: &dyn Registry,
    roots: &AppRoots,
    matcher: &Matcher,
    limits: Limits,
    progress: Progress<'_>,
) -> AppScan {
    let candidates = inventory::discover(reg, roots);
    progress(0, candidates.len(), "");
    let mut apps = merge_same_name(inspect_parallel(&candidates, matcher, limits, progress));
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

/// Scans one app (every install of it, by name) with the given limits; used
/// for "scan everything" on an app the normal scan only skimmed. `None` if
/// no installed app has that name.
pub fn scan_one_app(
    reg: &dyn Registry,
    roots: &AppRoots,
    matcher: &Matcher,
    name: &str,
    limits: Limits,
    progress: FileProgress<'_>,
) -> Option<ga_core::InstalledApp> {
    let apps: Vec<_> = inventory::discover(reg, roots)
        .iter()
        .filter(|c| c.name.eq_ignore_ascii_case(name))
        .map(|c| inspect::inspect_with_progress(c, matcher, limits, progress))
        .collect();
    merge_same_name(apps).into_iter().next()
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
                existing.skipped_count += app.skipped_count;
                existing.skipped_bytes += app.skipped_bytes;
                existing.too_many_files |= app.too_many_files;
                existing.full_scan &= app.full_scan;
                let room = ga_core::MAX_SKIPPED_LISTED.saturating_sub(existing.skipped.len());
                existing.skipped.extend(app.skipped.into_iter().take(room));
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

fn inspect_parallel(
    candidates: &[Candidate],
    matcher: &Matcher,
    limits: Limits,
    progress: Progress<'_>,
) -> Vec<ga_core::InstalledApp> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let finished = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new(Vec::with_capacity(candidates.len()));
    std::thread::scope(|s| {
        for _ in 0..PARALLEL_APPS.min(candidates.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(c) = candidates.get(i) else { break };
                    progress(finished.load(std::sync::atomic::Ordering::Relaxed), candidates.len(), &c.name);
                    let app = inspect::inspect(c, matcher, limits);
                    results.lock().unwrap_or_else(|p| p.into_inner()).push(app);
                    let done = finished.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    progress(done, candidates.len(), &c.name);
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests;
