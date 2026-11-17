use crate::alerts::{self, Alert, Baseline, MAX_ALERTS};
use crate::context::UserContext;
use crate::score;
use ga_blocker::settings::journal::Journal;
use ga_blocker::settings::store::{RegValue, RegistryStore};
use ga_blocker::settings::{self, FixValue, SettingsError};
use ga_core::{AppScan, Exposure, ExtensionScan, InstalledApp, PrivacyScan};
use ga_ipc::Request;
use ga_knowledge::TrackerDb;
use ga_proxy::{CertAuthority, InspectedRequest, Proxy, ProxyConfig, ProxyEvent, Rules};
use ga_report::CookieReport;
use ga_scanners::apps::{Limits, matcher::Matcher};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// Decrypted requests kept for the UI.
const MAX_PROXY_EVENTS: usize = 200;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Machine-wide data (inspection CA) and per-user folders below `users/`.
    pub data_root: PathBuf,
    /// 0 picks a free port (tests).
    pub proxy_port: u16,
    pub network_monitor: bool,
    /// The app scan reads installed apps and takes a minute or more.
    pub app_scan: bool,
    /// Machine-wide DNS blocking may change Windows' network settings
    /// (needs administrator rights: the installed service).
    pub dns_blocking: bool,
}

pub struct Engine {
    config: EngineConfig,
    db: Arc<TrackerDb>,
    matcher: Arc<Matcher>,
    users: Mutex<HashMap<String, Arc<UserSlot>>>,
    started: Instant,
    network: Mutex<NetworkState>,
    proxy: ProxyState,
    blocking: Arc<crate::blocking::Blocking>,
    watch: Arc<crate::watch::Watch>,
}

enum NetworkState {
    Off,
    Running(Box<ga_netmon::DnsMonitor>),
    Failed(String),
}

struct ProxyState {
    /// Decrypt any app's connections to trackers (persisted; on by default).
    watch_trackers: Mutex<bool>,
    tracker_hosts: ga_proxy::TrackerHosts,
    listening: Option<SocketAddr>,
    error: Option<String>,
    ca: Option<Arc<CertAuthority>>,
    rules: Arc<RwLock<Rules>>,
    events: Arc<Mutex<VecDeque<InspectedRequest>>>,
}

pub struct UserSlot {
    ctx: UserContext,
    state: Mutex<UserState>,
}

/// What a running scan is doing, for the progress bar.
#[derive(Debug, Clone, serde::Serialize)]
struct ScanProgress {
    percent: u32,
    step: String,
    detail: String,
}

#[derive(Default)]
struct UserState {
    scanning: bool,
    progress: Option<ScanProgress>,
    generated_unix: Option<i64>,
    cookies: Option<CookieReport>,
    extensions: Option<ExtensionScan>,
    privacy: Option<PrivacyScan>,
    apps: Option<AppScan>,
    /// Apps the user asked to scan completely. They replace the normal,
    /// limited result until the app is updated.
    full_scans: Vec<InstalledApp>,
    baseline: Option<Baseline>,
    alerts: Vec<Alert>,
}

impl Engine {
    /// Starts the engine: loads the tracker data, the network monitor and
    /// the proxy. A part that fails to start is reported in `status`; the
    /// rest keeps working.
    pub async fn start(config: EngineConfig) -> Arc<Self> {
        let db = Arc::new(TrackerDb::bundled().expect("bundled tracker list is valid"));
        let matcher = Arc::new(Matcher::bundled(&db));

        let network = if config.network_monitor {
            match ga_netmon::DnsMonitor::start() {
                Ok(m) => NetworkState::Running(Box::new(m)),
                Err(e) => NetworkState::Failed(e.to_string()),
            }
        } else {
            NetworkState::Off
        };

        let watch = crate::watch::Watch::new(&config.data_root, db.clone());
        let proxy = start_proxy(&config, db.clone(), watch.clone()).await;
        let blocking = crate::blocking::Blocking::load(&config.data_root, db.clone());
        if config.dns_blocking {
            blocking.resume_after_start().await;
            let b = blocking.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(crate::blocking::CHECK_EVERY);
                every.tick().await;
                loop {
                    every.tick().await;
                    b.check().await;
                }
            });
        }
        Arc::new(Self {
            config,
            db,
            matcher,
            users: Mutex::new(HashMap::new()),
            started: Instant::now(),
            network: Mutex::new(network),
            proxy,
            blocking,
            watch,
        })
    }

    fn set_watch_trackers(&self, on: bool) {
        *lock(&self.proxy.watch_trackers) = on;
        write(&self.proxy.rules).watch_trackers(on.then(|| self.proxy.tracker_hosts.clone()));
        save_json(&self.config.data_root.join("watch_trackers.json"), &json!({ "on": on }));
    }

    /// The service is stopping: put Windows' network settings back (blocking
    /// resumes when it starts again).
    pub async fn shutdown(&self) {
        if self.config.dns_blocking {
            self.blocking.shutdown().await;
        }
    }

    fn blocking_allowed(&self) -> Result<(), String> {
        if self.config.dns_blocking {
            Ok(())
        } else {
            Err("Blocking works when Guardian Angel runs as an installed service.".into())
        }
    }

    /// Deletes tracking cookies from browsers that are closed, then rereads
    /// the cookies so the Trackers page updates.
    fn delete_tracker_cookies(&self, slot: &UserSlot, include_social: bool, site_trackers: bool) -> Value {
        use ga_core::{Browser, Category};
        // Browsers of this user that are running keep their cookies in memory.
        const EXES: &[(&str, Browser)] = &[
            ("chrome.exe", Browser::Chrome),
            ("msedge.exe", Browser::Edge),
            ("brave.exe", Browser::Brave),
            ("vivaldi.exe", Browser::Vivaldi),
            ("opera.exe", Browser::Opera),
            ("firefox.exe", Browser::Firefox),
        ];
        let mut open: Vec<Browser> = Vec::new();
        for p in ga_platform_win::running_processes() {
            let Some((_, browser)) = EXES.iter().find(|(exe, _)| p.exe.eq_ignore_ascii_case(exe)) else { continue };
            let mine = match &slot.ctx.sid {
                Some(sid) => ga_platform_win::process_user_sid(p.pid).as_deref() == Some(sid.as_str()),
                None => true,
            };
            if mine && !open.contains(browser) {
                open.push(*browser);
                // Opera GX runs as opera.exe too.
                if *browser == Browser::Opera {
                    open.push(Browser::OperaGx);
                }
            }
        }
        let db = self.db.clone();
        let rule = move |host: &str, name: &str| {
            if let Some(m) = db.classify(host) {
                return match m.category {
                    // Signing-in sites: deleting signs the user out.
                    Category::Social | Category::Platform => include_social,
                    _ => true,
                };
            }
            site_trackers && ga_report::purpose::identify(name).0 == ga_report::purpose::CookiePurpose::Tracking
        };
        let report = ga_scanners::browsers::delete_cookies_in(&slot.ctx.browser_roots, &open, &rule);
        // Show the result straight away.
        let cookies = ga_scanners::browsers::scan_cookies_in(&slot.ctx.browser_roots);
        lock(&slot.state).cookies = Some(ga_report::build_cookie_report(&cookies, &self.db));
        json!(report)
    }

    /// The state slot for a user, created (and loaded from disk) on first use.
    pub fn slot(&self, ctx: &UserContext) -> Arc<UserSlot> {
        let mut users = lock(&self.users);
        users
            .entry(ctx.key.clone())
            .or_insert_with(|| {
                let state = UserState {
                    baseline: read_json(&ctx.data_dir.join("baseline.json")),
                    alerts: read_json(&ctx.data_dir.join("alerts.json")).unwrap_or_default(),
                    full_scans: read_json(&ctx.data_dir.join("full_scans.json")).unwrap_or_default(),
                    ..UserState::default()
                };
                Arc::new(UserSlot {
                    ctx: ctx.clone(),
                    state: Mutex::new(state),
                })
            })
            .clone()
    }

    /// Rescans every user who has connected (periodic refresh).
    pub fn rescan_known_users(self: &Arc<Self>) {
        let slots: Vec<Arc<UserSlot>> = lock(&self.users).values().cloned().collect();
        for slot in slots {
            self.start_scan(slot);
        }
    }

    /// Answers one request for one user.
    pub async fn handle(self: &Arc<Self>, slot: Arc<UserSlot>, request: Request) -> Result<Value, String> {
        match request {
            Request::Status => Ok(self.status()),
            Request::Overview => {
                let never_scanned = lock(&slot.state).generated_unix.is_none();
                if never_scanned {
                    self.start_scan(slot.clone());
                }
                Ok(self.overview(&slot))
            }
            Request::ScanNow => Ok(json!({ "started": self.start_scan(slot) })),
            Request::Alerts => {
                let state = lock(&slot.state);
                let mut list = state.alerts.clone();
                list.reverse();
                Ok(json!(list))
            }
            Request::MarkAlertsRead => {
                let mut state = lock(&slot.state);
                state.alerts.iter_mut().for_each(|a| a.read = true);
                save_json(&slot.ctx.data_dir.join("alerts.json"), &state.alerts);
                Ok(Value::Null)
            }
            Request::Fixes => Ok(self.fixes(&slot)),
            Request::ApplyFix { setting_id } => {
                let fix = settings::fix_for(&setting_id).ok_or_else(|| format!("unknown setting '{setting_id}'"))?;
                let journal = journal(&slot.ctx)?;
                let mut store = slot.ctx.store();
                let record = settings::apply(&mut store, &journal, fix, unix_now()).map_err(|e| match e {
                    SettingsError::NeedsAdmin => "This change needs administrator rights.".to_owned(),
                    other => other.to_string(),
                })?;
                self.refresh_privacy(&slot);
                Ok(json!(record))
            }
            Request::Changes => Ok(json!(journal(&slot.ctx)?.active().map_err(|e| e.to_string())?)),
            Request::Undo { id } => {
                let journal = journal(&slot.ctx)?;
                let report = settings::undo(&mut slot.ctx.store(), &journal, &id).map_err(|e| e.to_string())?;
                self.refresh_privacy(&slot);
                Ok(json!({ "restored": report.restored, "left_alone": report.skipped_changed_since }))
            }
            Request::UndoAll => {
                let journal = journal(&slot.ctx)?;
                let done = settings::undo_all(&mut slot.ctx.store(), &journal).map_err(|e| e.to_string())?;
                self.refresh_privacy(&slot);
                Ok(json!({ "undone": done.len() }))
            }
            Request::ProxyStatus => Ok(self.proxy_status()),
            Request::ProxySetApps { apps } => {
                let watching = *lock(&self.proxy.watch_trackers);
                let mut rules = write(&self.proxy.rules);
                let bypassed: Vec<String> = rules.bypassed_hosts().map(str::to_owned).collect();
                *rules = Rules::for_apps(apps.iter().map(String::as_str));
                bypassed.iter().for_each(|h| rules.learn_bypass(h));
                rules.watch_trackers(watching.then(|| self.proxy.tracker_hosts.clone()));
                drop(rules);
                Ok(self.proxy_status())
            }
            Request::ProxyEvents => {
                // Only this user's programs.
                let events: Vec<InspectedRequest> = lock(&self.proxy.events)
                    .iter()
                    .rev()
                    .filter(|e| e.user.is_some() && e.user == slot.ctx.sid)
                    .cloned()
                    .collect();
                Ok(json!(events))
            }
            Request::TrackerActivity => {
                let mut report = self.watch.report(&slot.ctx.key, unix_now());
                report["watching"] = json!(*lock(&self.proxy.watch_trackers));
                report["proxy_running"] = json!(self.proxy.listening.is_some());
                // Apps whose tracker contacts were seen on the network but not
                // read (they do not use the proxy): names only.
                if let NetworkState::Running(m) = &*lock(&self.network) {
                    let net = ga_report::build_network_report(&m.snapshot(), &self.db);
                    report["network_only"] = json!(net.processes.iter().filter(|p| p.tracker_lookups > 0).collect::<Vec<_>>());
                }
                Ok(report)
            }
            Request::SetWatchTrackers { on } => {
                self.set_watch_trackers(on);
                Ok(self.proxy_status())
            }
            Request::SetSiteChoice { site, refused } => {
                if crate::watch::site_name(&site).is_empty() {
                    return Err("Enter a site, for example news.example".into());
                }
                self.watch.set_choice(&slot.ctx.key, &site, refused, unix_now());
                Ok(Value::Null)
            }
            Request::SetDataRequest { company, kind, sent } => {
                if !matches!(kind.as_str(), "access" | "delete" | "object") {
                    return Err(format!("unknown request kind '{kind}'"));
                }
                if sent {
                    self.watch.request_sent(&slot.ctx.key, &company, &kind, unix_now());
                } else {
                    self.watch.request_removed(&slot.ctx.key, &company, &kind);
                }
                Ok(Value::Null)
            }
            Request::SetRequester { name, email, region } => {
                if !matches!(region.as_str(), "gdpr" | "ccpa" | "other") {
                    return Err(format!("unknown region '{region}'"));
                }
                self.watch.set_requester(&slot.ctx.key, crate::watch::Requester { name, email, region });
                Ok(Value::Null)
            }
            Request::RunningApps => Ok(self.running_apps(&slot.ctx)),
            Request::DeleteTrackerCookies { include_social, site_trackers } => {
                Ok(self.delete_tracker_cookies(&slot, include_social, site_trackers))
            }
            Request::BlockingStatus => Ok(self.blocking.status().await),
            Request::BlockingPreview => Ok(self.blocking.preview().await),
            Request::BlockingEnable { profile } => {
                self.blocking_allowed()?;
                self.blocking.enable(crate::blocking::profile_from(&profile)?).await
            }
            Request::BlockingDisable => Ok(self.blocking.disable().await),
            Request::BlockingSetProfile { profile } => {
                Ok(self.blocking.set_profile(crate::blocking::profile_from(&profile)?).await)
            }
            Request::BlockingPause { minutes } => Ok(self.blocking.pause(minutes.clamp(1, 24 * 60)).await),
            Request::BlockingResume => Ok(self.blocking.resume().await),
            Request::BlockingAllow { domain, allow } => {
                if ga_core::normalize_host(&domain).is_empty() {
                    return Err("Enter a domain, for example example.com".into());
                }
                Ok(self.blocking.allow(&domain, allow).await)
            }
            Request::ScanAppFully { name } => {
                let known = lock(&slot.state)
                    .apps
                    .as_ref()
                    .is_some_and(|scan| scan.apps.iter().any(|a| a.name.eq_ignore_ascii_case(&name)));
                if !known {
                    return Err(format!("'{name}' is not in the list of installed apps."));
                }
                Ok(json!({ "started": self.start_full_app_scan(slot, name) }))
            }
            Request::ProxyExportCa => {
                let ca = self.proxy.ca.as_ref().ok_or("The inspection certificate is not available.")?;
                let path = slot.ctx.data_dir.join("guardian-angel-inspection.pem");
                std::fs::create_dir_all(&slot.ctx.data_dir).map_err(|e| e.to_string())?;
                std::fs::write(&path, ca.cert_pem()).map_err(|e| e.to_string())?;
                Ok(json!({ "path": path, "pem": ca.cert_pem() }))
            }
        }
    }

    fn status(&self) -> Value {
        let network = match &*lock(&self.network) {
            NetworkState::Off => json!({ "state": "off" }),
            NetworkState::Running(_) => json!({ "state": "running" }),
            NetworkState::Failed(e) => json!({ "state": "failed", "error": e }),
        };
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.started.elapsed().as_secs(),
            "users": lock(&self.users).len(),
            "network": network,
            "proxy": self.proxy_status(),
        })
    }

    fn proxy_status(&self) -> Value {
        let rules = read(&self.proxy.rules);
        json!({
            "listening": self.proxy.listening,
            "watching_trackers": *lock(&self.proxy.watch_trackers),
            "error": self.proxy.error,
            "inspected_apps": rules.apps().collect::<Vec<_>>(),
            "refused_inspection": rules.bypassed_hosts().collect::<Vec<_>>(),
            "recent_requests": lock(&self.proxy.events).len(),
        })
    }

    /// Programs running for this user (not other users, not Windows itself),
    /// one entry per executable, for the "inspect an app" picker.
    fn running_apps(&self, ctx: &UserContext) -> Value {
        let windows_dir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned()).to_lowercase();
        /// Never offered: Guardian Angel itself and the web view hosting apps' UIs.
        const HIDDEN: &[&str] = &["guardian-angel.exe", "guardian-service.exe", "guardian.exe", "msedgewebview2.exe"];
        let mut apps: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
        for p in ga_platform_win::running_processes() {
            let key = p.exe.to_lowercase();
            if HIDDEN.contains(&key.as_str()) {
                continue;
            }
            if let Some(existing) = apps.get_mut(&key) {
                // Same program, another process: remember its ID too.
                if let Some(pids) = existing["pids"].as_array_mut() {
                    pids.push(json!(p.pid));
                }
                continue;
            }
            // Only processes we can open (the user's own); others return None.
            let Some(path) = ga_platform_win::process_image_path(p.pid) else { continue };
            if path.to_lowercase().starts_with(&windows_dir) {
                continue;
            }
            if let Some(sid) = &ctx.sid
                && ga_platform_win::process_user_sid(p.pid).as_deref() != Some(sid.as_str())
            {
                continue;
            }
            // Electron and Chromium apps accept a proxy on their command line.
            let dir = Path::new(&path).parent();
            let electron = dir.is_some_and(|d| d.join("resources").join("app.asar").is_file() || d.join("resources").join("app").is_dir());
            let name = Path::new(&p.exe).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.exe.clone());
            apps.insert(key, json!({ "exe": p.exe, "name": name, "path": path, "electron": electron, "pids": [p.pid] }));
        }
        let mut list: Vec<Value> = apps.into_values().collect();
        list.sort_by_key(|v| v["name"].as_str().unwrap_or("").to_lowercase());
        json!(list)
    }

    fn overview(&self, slot: &UserSlot) -> Value {
        let state = lock(&slot.state);
        let network = match &*lock(&self.network) {
            NetworkState::Running(m) => Some(ga_report::build_network_report(&m.snapshot(), &self.db)),
            _ => None,
        };
        let score = score::score(state.privacy.as_ref(), state.extensions.as_ref(), state.cookies.as_ref(), state.apps.as_ref());
        json!({
            "scanning": state.scanning,
            "progress": state.progress,
            "generated_unix": state.generated_unix,
            "score": score,
            "unread_alerts": state.alerts.iter().filter(|a| !a.read).count(),
            "cookies": state.cookies,
            "extensions": state.extensions,
            "privacy": state.privacy,
            "apps": state.apps,
            "network": network,
        })
    }

    fn fixes(&self, slot: &UserSlot) -> Value {
        let privacy = ga_scanners::windows_privacy::scan_privacy_with(&slot.ctx.registry());
        let store = slot.ctx.store();
        let list: Vec<Value> = privacy
            .settings
            .iter()
            .filter(|s| s.exposure == Exposure::Exposed)
            .filter_map(|s| {
                let fix = settings::fix_for(s.id)?;
                let writes: Vec<Value> = fix
                    .writes
                    .iter()
                    .map(|w| {
                        let current = store.get(w.hive, w.path, w.name).ok().flatten().map(|v| match v {
                            RegValue::Dword(n) => n.to_string(),
                            RegValue::String(t) => t,
                        });
                        let new = match &w.value {
                            FixValue::Dword(n) => n.to_string(),
                            FixValue::Str(t) => (*t).to_owned(),
                        };
                        json!({ "location": format!(r"{}\{}\{}", w.hive.prefix(), w.path, w.name), "current": current, "new": new })
                    })
                    .collect();
                Some(json!({
                    "setting_id": s.id,
                    "setting": s.title,
                    "state": s.state,
                    "explanation": s.explanation,
                    "fix": fix.title,
                    "needs_admin": fix.needs_admin,
                    "needs_restart": fix.needs_restart,
                    "writes": writes,
                }))
            })
            .collect();
        json!(list)
    }

    /// Re-reads privacy settings after a fix or undo, and records them in
    /// the baseline so our own change is not reported as an alert.
    fn refresh_privacy(&self, slot: &UserSlot) {
        let privacy = ga_scanners::windows_privacy::scan_privacy_with(&slot.ctx.registry());
        let mut state = lock(&slot.state);
        let extensions = state.extensions.clone().unwrap_or_default();
        let baseline = state.baseline.get_or_insert_with(Baseline::default);
        baseline.record_quick(&extensions, &privacy);
        save_json(&slot.ctx.data_dir.join("baseline.json"), &*baseline);
        state.privacy = Some(privacy);
    }

    /// Starts a background scan unless one is running. Quick parts first,
    /// then the slower app scan.
    pub fn start_scan(self: &Arc<Self>, slot: Arc<UserSlot>) -> bool {
        {
            let mut state = lock(&slot.state);
            if state.scanning {
                return false;
            }
            state.scanning = true;
        }
        let engine = self.clone();
        tokio::spawn(async move {
            let (ctx, db, s) = (slot.ctx.clone(), engine.db.clone(), slot.clone());
            let quick = tokio::task::spawn_blocking(move || {
                s.set_progress(1, "Reading browser cookies", "Chrome, Edge, Brave, Vivaldi, Opera and Firefox profiles");
                let cookies = ga_scanners::browsers::scan_cookies_in(&ctx.browser_roots);
                let cookies = ga_report::build_cookie_report(&cookies, &db);
                s.set_progress(4, "Checking browser extensions", "Every browser profile on this account");
                let extensions = ga_scanners::extensions::scan_extensions_in(&ctx.browser_roots);
                s.set_progress(6, "Checking Windows privacy settings", "Diagnostics, advertising, location, typing and speech");
                let privacy = ga_scanners::windows_privacy::scan_privacy_with(&ctx.registry());
                (cookies, extensions, privacy)
            })
            .await;
            if let Ok((cookies, extensions, privacy)) = quick {
                let mut state = lock(&slot.state);
                let changes = state
                    .baseline
                    .as_ref()
                    .map(|b| alerts::compare_quick(b, &extensions, &privacy))
                    .unwrap_or_default();
                add_alerts(&mut state, changes);
                let baseline = state.baseline.get_or_insert_with(Baseline::default);
                baseline.record_quick(&extensions, &privacy);
                save_json(&slot.ctx.data_dir.join("baseline.json"), &*baseline);
                save_json(&slot.ctx.data_dir.join("alerts.json"), &state.alerts);
                state.cookies = Some(cookies);
                state.extensions = Some(extensions);
                state.privacy = Some(privacy);
                state.generated_unix = Some(unix_now());
            }

            if engine.config.app_scan {
                let (ctx, matcher, s) = (slot.ctx.clone(), engine.matcher.clone(), slot.clone());
                let apps = tokio::task::spawn_blocking(move || {
                    const STEP: &str = "Looking inside installed apps";
                    s.set_progress(8, STEP, "Finding installed apps");
                    ga_scanners::apps::scan_apps_with_progress(
                        &ctx.registry(),
                        &ctx.app_roots,
                        &matcher,
                        Limits::default(),
                        &|done, total, name| {
                            // Apps take most of the time: 8% to 99%.
                            let percent = 8 + (done * 91).checked_div(total).unwrap_or(0) as u32;
                            let detail = if name.is_empty() {
                                format!("{total} apps found")
                            } else {
                                format!("{name} ({done} of {total} done)")
                            };
                            s.set_progress(percent, STEP, &detail);
                        },
                    )
                })
                .await;
                if let Ok(mut apps) = apps {
                    let mut state = lock(&slot.state);
                    use_full_scans(&mut apps, &mut state.full_scans);
                    save_json(&slot.ctx.data_dir.join("full_scans.json"), &state.full_scans);
                    let changes = state.baseline.as_ref().map(|b| alerts::compare_apps(b, &apps)).unwrap_or_default();
                    add_alerts(&mut state, changes);
                    let baseline = state.baseline.get_or_insert_with(Baseline::default);
                    baseline.record_apps(&apps);
                    save_json(&slot.ctx.data_dir.join("baseline.json"), &*baseline);
                    save_json(&slot.ctx.data_dir.join("alerts.json"), &state.alerts);
                    state.apps = Some(apps);
                }
            }
            let mut state = lock(&slot.state);
            state.scanning = false;
            state.progress = None;
        });
        true
    }

    /// Reads every file of one app in the background, then puts the result
    /// in place of the limited one. Shares the "scanning" flag with the
    /// normal scan so the two never run at once.
    fn start_full_app_scan(self: &Arc<Self>, slot: Arc<UserSlot>, name: String) -> bool {
        {
            let mut state = lock(&slot.state);
            if state.scanning {
                return false;
            }
            state.scanning = true;
        }
        let engine = self.clone();
        tokio::spawn(async move {
            let (ctx, matcher, s, app_name) = (slot.ctx.clone(), engine.matcher.clone(), slot.clone(), name.clone());
            let step = format!("Reading all of {name}");
            s.set_progress(0, &step, "Listing its files");
            let result = tokio::task::spawn_blocking(move || {
                ga_scanners::apps::scan_one_app(
                    &ctx.registry(),
                    &ctx.app_roots,
                    &matcher,
                    &app_name,
                    Limits::everything(),
                    &|done, total, file| {
                        let percent = (done.saturating_mul(100)).checked_div(total).unwrap_or(0).min(99) as u32;
                        let mb = |b: u64| b / (1024 * 1024);
                        s.set_progress(percent, &step, &format!("{file} ({} of {} MB)", mb(done), mb(total)));
                    },
                )
            })
            .await;
            let mut state = lock(&slot.state);
            if let Ok(Some(app)) = result {
                if let Some(scan) = state.apps.as_mut()
                    && let Some(slot_app) = scan.apps.iter_mut().find(|a| a.name.eq_ignore_ascii_case(&app.name))
                {
                    *slot_app = app.clone();
                }
                state.full_scans.retain(|a| !a.name.eq_ignore_ascii_case(&app.name));
                state.full_scans.push(app);
                save_json(&slot.ctx.data_dir.join("full_scans.json"), &state.full_scans);
            }
            state.scanning = false;
            state.progress = None;
        });
        true
    }
}

/// Puts remembered full scans in place of the limited results for the same
/// app, and forgets those whose app was updated (other version or folder)
/// or uninstalled.
fn use_full_scans(scan: &mut AppScan, full_scans: &mut Vec<InstalledApp>) {
    full_scans.retain(|full| {
        let Some(app) = scan.apps.iter_mut().find(|a| a.name.eq_ignore_ascii_case(&full.name)) else {
            return false;
        };
        if app.version != full.version || app.install_dir != full.install_dir {
            return false;
        }
        *app = full.clone();
        true
    });
}

impl UserSlot {
    fn set_progress(&self, percent: u32, step: &str, detail: &str) {
        lock(&self.state).progress = Some(ScanProgress {
            percent,
            step: step.to_owned(),
            detail: detail.to_owned(),
        });
    }
}

fn add_alerts(state: &mut UserState, changes: Vec<alerts::Change>) {
    let now = unix_now();
    let mut next = state.alerts.last().map_or(1, |a| a.id + 1);
    for c in changes {
        state.alerts.push(Alert {
            id: next,
            unix: now,
            severity: c.severity,
            title: c.title,
            detail: c.detail,
            read: false,
        });
        next += 1;
    }
    let excess = state.alerts.len().saturating_sub(MAX_ALERTS);
    state.alerts.drain(..excess);
}

async fn start_proxy(config: &EngineConfig, db: Arc<TrackerDb>, watch: Arc<crate::watch::Watch>) -> ProxyState {
    // Only tracking companies: never platforms people sign in to (Google
    // search, Facebook) or anything else.
    let tracker_hosts = ga_proxy::TrackerHosts(Arc::new(move |host: &str| {
        db.classify(host)
            .is_some_and(|m| !matches!(m.category, ga_core::Category::Platform | ga_core::Category::Social))
    }));
    let watching = read_json::<Value>(&config.data_root.join("watch_trackers.json"))
        .and_then(|v| v["on"].as_bool())
        .unwrap_or(true);
    let mut initial = Rules::default();
    initial.watch_trackers(watching.then(|| tracker_hosts.clone()));
    let rules = Arc::new(RwLock::new(initial));
    let events: Arc<Mutex<VecDeque<InspectedRequest>>> = Arc::default();
    let mut state = ProxyState {
        watch_trackers: Mutex::new(watching),
        tracker_hosts,
        listening: None,
        error: None,
        ca: None,
        rules: rules.clone(),
        events: events.clone(),
    };
    let ca = match CertAuthority::load_or_create(&config.data_root.join("ca")) {
        Ok(ca) => Arc::new(ca),
        Err(e) => {
            state.error = Some(e.to_string());
            return state;
        }
    };
    state.ca = Some(ca.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let listen = SocketAddr::from(([127, 0, 0, 1], config.proxy_port));
    match Proxy::bind(ProxyConfig::new(listen), ca, rules, tx, ga_proxy::windows_app_resolver()).await {
        Ok(proxy) => {
            state.listening = proxy.local_addr().ok();
            tokio::spawn(proxy.run());
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    if let ProxyEvent::Inspected(r) = event {
                        watch.record(&r);
                        let mut q = lock(&events);
                        q.push_back(*r);
                        while q.len() > MAX_PROXY_EVENTS {
                            q.pop_front();
                        }
                    }
                }
            });
        }
        Err(e) => state.error = Some(e.to_string()),
    }
    state
}

fn journal(ctx: &UserContext) -> Result<Journal, String> {
    Journal::open(&ctx.data_dir.join("changes")).map_err(|e| e.to_string())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Best effort: state is rebuilt by the next scan if a write fails.
fn save_json<T: serde::Serialize>(path: &Path, value: &T) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(value) {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(tmp, path);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|p| p.into_inner())
}

fn write<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|p| p.into_inner())
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod full_scan_tests {
    use super::*;

    fn app(name: &str, version: &str, full: bool) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            publisher: None,
            version: Some(version.into()),
            install_dir: format!(r"C:\Apps\{name}"),
            electron: false,
            findings: Vec::new(),
            bytes_scanned: 0,
            truncated: !full,
            skipped: Vec::new(),
            skipped_count: usize::from(!full),
            skipped_bytes: 0,
            too_many_files: false,
            full_scan: full,
        }
    }

    #[test]
    fn full_scans_replace_limited_results_until_the_app_changes() {
        let mut scan = AppScan {
            apps: vec![app("Big", "1.0", false), app("Updated", "2.0", false)],
            warnings: Vec::new(),
        };
        let mut full = vec![app("Big", "1.0", true), app("Updated", "1.0", true), app("Gone", "1.0", true)];
        use_full_scans(&mut scan, &mut full);
        assert!(scan.apps[0].full_scan, "same version: the full result is used");
        assert!(!scan.apps[1].full_scan, "updated app: back to the normal scan");
        assert_eq!(full.len(), 1, "results for updated and removed apps are forgotten");
    }
}