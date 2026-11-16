use crate::alerts::{self, Alert, Baseline, MAX_ALERTS};
use crate::context::UserContext;
use crate::score;
use ga_blocker::settings::journal::Journal;
use ga_blocker::settings::store::{RegValue, RegistryStore};
use ga_blocker::settings::{self, FixValue, SettingsError};
use ga_core::{AppScan, Exposure, ExtensionScan, PrivacyScan};
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
}

pub struct Engine {
    config: EngineConfig,
    db: Arc<TrackerDb>,
    matcher: Arc<Matcher>,
    users: Mutex<HashMap<String, Arc<UserSlot>>>,
    started: Instant,
    network: Mutex<NetworkState>,
    proxy: ProxyState,
}

enum NetworkState {
    Off,
    Running(Box<ga_netmon::DnsMonitor>),
    Failed(String),
}

struct ProxyState {
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

#[derive(Default)]
struct UserState {
    scanning: bool,
    generated_unix: Option<i64>,
    cookies: Option<CookieReport>,
    extensions: Option<ExtensionScan>,
    privacy: Option<PrivacyScan>,
    apps: Option<AppScan>,
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

        let proxy = start_proxy(&config).await;
        Arc::new(Self {
            config,
            db,
            matcher,
            users: Mutex::new(HashMap::new()),
            started: Instant::now(),
            network: Mutex::new(network),
            proxy,
        })
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
                let mut rules = write(&self.proxy.rules);
                let bypassed: Vec<String> = rules.bypassed_hosts().map(str::to_owned).collect();
                *rules = Rules::for_apps(apps.iter().map(String::as_str));
                bypassed.iter().for_each(|h| rules.learn_bypass(h));
                drop(rules);
                Ok(self.proxy_status())
            }
            Request::ProxyEvents => {
                let events: Vec<InspectedRequest> = lock(&self.proxy.events).iter().rev().cloned().collect();
                Ok(json!(events))
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
            "error": self.proxy.error,
            "inspected_apps": rules.apps().collect::<Vec<_>>(),
            "refused_inspection": rules.bypassed_hosts().collect::<Vec<_>>(),
            "recent_requests": lock(&self.proxy.events).len(),
        })
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
            let (ctx, db) = (slot.ctx.clone(), engine.db.clone());
            let quick = tokio::task::spawn_blocking(move || {
                let cookies = ga_scanners::browsers::scan_cookies_in(&ctx.browser_roots);
                (
                    ga_report::build_cookie_report(&cookies, &db),
                    ga_scanners::extensions::scan_extensions_in(&ctx.browser_roots),
                    ga_scanners::windows_privacy::scan_privacy_with(&ctx.registry()),
                )
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
                let (ctx, matcher) = (slot.ctx.clone(), engine.matcher.clone());
                let apps = tokio::task::spawn_blocking(move || {
                    ga_scanners::apps::scan_apps_with(&ctx.registry(), &ctx.app_roots, &matcher, Limits::default())
                })
                .await;
                if let Ok(apps) = apps {
                    let mut state = lock(&slot.state);
                    let changes = state.baseline.as_ref().map(|b| alerts::compare_apps(b, &apps)).unwrap_or_default();
                    add_alerts(&mut state, changes);
                    let baseline = state.baseline.get_or_insert_with(Baseline::default);
                    baseline.record_apps(&apps);
                    save_json(&slot.ctx.data_dir.join("baseline.json"), &*baseline);
                    save_json(&slot.ctx.data_dir.join("alerts.json"), &state.alerts);
                    state.apps = Some(apps);
                }
            }
            lock(&slot.state).scanning = false;
        });
        true
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

async fn start_proxy(config: &EngineConfig) -> ProxyState {
    let rules = Arc::new(RwLock::new(Rules::default()));
    let events: Arc<Mutex<VecDeque<InspectedRequest>>> = Arc::default();
    let mut state = ProxyState {
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
                        let mut q = lock(&events);
                        q.push_back(r);
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
