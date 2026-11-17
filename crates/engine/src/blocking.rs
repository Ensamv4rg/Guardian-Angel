//! Machine-wide tracker blocking: the DNS resolver plus pointing Windows at
//! it, with every safety net in one place.
//!
//! - Turning it on records each adapter's DNS setting first; turning it off,
//!   stopping the service and uninstalling put them back.
//! - The original DNS server stays second on each adapter, so the internet
//!   keeps working if the resolver ever stops answering.
//! - A health check every 30 seconds compares lookups through the resolver
//!   with lookups sent straight to the network's DNS server. If only ours
//!   fail, three times in a row, blocking switches itself off and says why.
//! - Moving to another network updates where lookups are forwarded.

use ga_blocker::switch::{self, AdapterSnapshot, DnsSystem};
use ga_blocker::{DnsBlocker, Policy, Profile, ResolverConfig, ResolverControl, probe};
use ga_knowledge::TrackerDb;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A name that always exists and is not a tracker (Windows' own
/// "am I online?" check).
const PROBE_NAME: &str = "www.msftconnecttest.com";
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Failed health checks in a row before blocking switches itself off.
const MAX_STRIKES: u32 = 3;
pub const CHECK_EVERY: Duration = Duration::from_secs(30);

/// What survives a restart: the user's choices and the adapters to put back.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    enabled: bool,
    profile: Option<Profile>,
    allowed: Vec<String>,
    paused_until: Option<i64>,
    /// Adapters currently pointed at the resolver, as they were before.
    pointed: Vec<AdapterSnapshot>,
}

struct Running {
    /// Where the resolver answers (port 53 normally; any port in tests).
    addr: SocketAddr,
    control: ResolverControl,
    task: tokio::task::JoinHandle<()>,
    ipv6: bool,
}

struct Inner {
    saved: Saved,
    running: Option<Running>,
    error: Option<String>,
    /// Shown once in the UI: why blocking turned itself off.
    notice: Option<String>,
    strikes: u32,
}

pub struct Blocking {
    path: PathBuf,
    db: Arc<TrackerDb>,
    policy: Arc<RwLock<Policy>>,
    system: Arc<dyn DnsSystem + Send + Sync>,
    listen_v4: SocketAddr,
    listen_v6: SocketAddr,
    inner: tokio::sync::Mutex<Inner>,
}

pub fn profile_from(text: &str) -> Result<Profile, String> {
    serde_json::from_value(json!(text)).map_err(|_| format!("unknown blocking level '{text}'"))
}

impl Blocking {
    pub fn load(data_root: &std::path::Path, db: Arc<TrackerDb>) -> Arc<Self> {
        Self::with_system(data_root, db, Arc::new(ga_blocker::system_dns::WindowsDns), 53)
    }

    pub(crate) fn with_system(
        data_root: &std::path::Path,
        db: Arc<TrackerDb>,
        system: Arc<dyn DnsSystem + Send + Sync>,
        port: u16,
    ) -> Arc<Self> {
        let path = data_root.join("blocking.json");
        let saved: Saved = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut policy = Policy::new(saved.profile.unwrap_or_default());
        saved.allowed.iter().for_each(|d| policy.allow(d));
        if let Some(until) = saved.paused_until {
            policy.pause_until(until);
        }
        Arc::new(Self {
            path,
            db,
            policy: Arc::new(RwLock::new(policy)),
            system,
            listen_v4: (Ipv4Addr::LOCALHOST, port).into(),
            listen_v6: (Ipv6Addr::LOCALHOST, port).into(),
            inner: tokio::sync::Mutex::new(Inner {
                saved,
                running: None,
                error: None,
                notice: None,
                strikes: 0,
            }),
        })
    }

    fn save(&self, saved: &Saved) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_vec_pretty(saved) {
            let _ = std::fs::write(&self.path, json);
        }
    }

    /// At service start: resumes blocking if it was on, and puts back any
    /// adapter left pointed at the resolver while blocking is off.
    pub async fn resume_after_start(&self) {
        let mut inner = self.inner.lock().await;
        if inner.saved.enabled {
            if let Err(e) = self.turn_on(&mut inner).await {
                inner.error = Some(e);
            }
        } else if !inner.saved.pointed.is_empty() {
            self.turn_off(&mut inner).await;
        }
    }

    /// What turning blocking on would change, for the consent screen.
    pub async fn preview(&self) -> Value {
        let system = self.system.clone();
        let adapters = tokio::task::spawn_blocking(move || system.adapters()).await.unwrap_or_default();
        let list: Vec<Value> = adapters
            .iter()
            .map(|a| {
                let current = if a.v4_static.is_empty() {
                    let servers: Vec<String> = a.v4_auto.iter().map(ToString::to_string).collect();
                    format!("Automatic ({})", if servers.is_empty() { "from the network".into() } else { servers.join(", ") })
                } else {
                    a.v4_static.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                };
                json!({ "name": a.name, "current": current })
            })
            .collect();
        json!({ "adapters": list })
    }

    pub async fn enable(&self, profile: Profile) -> Result<Value, String> {
        let mut inner = self.inner.lock().await;
        self.policy_mut().profile = profile;
        inner.saved.profile = Some(profile);
        inner.notice = None;
        if inner.running.is_none() {
            self.turn_on(&mut inner).await?;
        }
        inner.saved.enabled = true;
        self.save(&inner.saved);
        drop(inner);
        Ok(self.status().await)
    }

    pub async fn disable(&self) -> Value {
        let mut inner = self.inner.lock().await;
        inner.saved.enabled = false;
        self.turn_off(&mut inner).await;
        drop(inner);
        self.status().await
    }

    /// Service stopping: put Windows back but remember blocking was on, so
    /// it resumes when the service starts again.
    pub async fn shutdown(&self) {
        let mut inner = self.inner.lock().await;
        self.turn_off(&mut inner).await;
    }

    async fn turn_on(&self, inner: &mut Inner) -> Result<(), String> {
        inner.error = None;
        let config = ResolverConfig {
            listen: self.listen_v4,
            upstreams: Vec::new(),
            upstream_timeout: Duration::from_secs(2),
        };
        let mut resolver = DnsBlocker::bind(config, self.db.clone(), self.policy.clone()).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse || e.raw_os_error() == Some(10048) {
                "Another program already answers DNS on this PC (often Windows' Internet Connection Sharing), so Guardian Angel cannot block here.".to_owned()
            } else {
                format!("Could not start the blocking resolver: {e}")
            }
        })?;
        let addr = resolver.local_addr().map_err(|e| e.to_string())?;
        let ipv6 = resolver.also_listen(self.listen_v6).await.is_ok();
        let control = resolver.control();
        let task = tokio::spawn(async move {
            let _ = resolver.run().await;
        });

        let (system, mut pointed) = (self.system.clone(), std::mem::take(&mut inner.saved.pointed));
        let result = tokio::task::spawn_blocking(move || {
            let r = switch::point_at_resolver(system.as_ref(), ipv6, &mut pointed);
            let ups = switch::upstreams(system.as_ref(), &pointed);
            (r, pointed, ups)
        })
        .await
        .map_err(|e| e.to_string())?;
        let (pointed_result, pointed, upstreams) = result;
        inner.saved.pointed = pointed;
        self.save(&inner.saved);
        control.set_upstreams(upstreams.clone());
        inner.running = Some(Running { addr, control, task, ipv6 });
        if let Err(e) = pointed_result {
            self.turn_off(inner).await;
            return Err(e);
        }

        // Check lookups still work. Offline (the network's own server does
        // not answer either) is not our fault and is not a reason to stop.
        if !probe(addr, PROBE_NAME, PROBE_TIMEOUT).await && any_answers(&upstreams).await {
            self.turn_off(inner).await;
            return Err("Lookups stopped working through Guardian Angel, so nothing was changed. Your network settings are as before.".into());
        }
        inner.strikes = 0;
        Ok(())
    }

    async fn turn_off(&self, inner: &mut Inner) {
        let (system, pointed) = (self.system.clone(), std::mem::take(&mut inner.saved.pointed));
        let left = tokio::task::spawn_blocking(move || switch::restore(system.as_ref(), &pointed))
            .await
            .unwrap_or_default();
        if !left.is_empty() {
            let names: Vec<&str> = left.iter().map(|a| a.name.as_str()).collect();
            inner.error = Some(format!("Could not put back the DNS setting of {}; will retry.", names.join(", ")));
        }
        inner.saved.pointed = left;
        if let Some(running) = inner.running.take() {
            running.task.abort();
        }
        self.save(&inner.saved);
    }

    /// The periodic check (see the module docs).
    pub async fn check(&self) {
        let mut inner = self.inner.lock().await;
        if inner.running.is_none() {
            // A restore that failed earlier is retried.
            if !inner.saved.pointed.is_empty() && !inner.saved.enabled {
                self.turn_off(&mut inner).await;
            }
            return;
        }
        let Some((ipv6, addr)) = inner.running.as_ref().map(|r| (r.ipv6, r.addr)) else { return };
        let (system, mut pointed) = (self.system.clone(), std::mem::take(&mut inner.saved.pointed));
        let (pointed, upstreams) = tokio::task::spawn_blocking(move || {
            // Another network hands out other servers: refresh the fallback.
            let stale = switch::stale_fallbacks(system.as_ref(), &pointed);
            if !stale.is_empty() {
                let (redo, keep): (Vec<_>, Vec<_>) = pointed.into_iter().partition(|p| stale.contains(&p.id));
                switch::restore(system.as_ref(), &redo);
                pointed = keep;
            }
            // New adapters (a USB tether, a dock) are pointed too.
            let _ = switch::point_at_resolver(system.as_ref(), ipv6, &mut pointed);
            let ups = switch::upstreams(system.as_ref(), &pointed);
            (pointed, ups)
        })
        .await
        .unwrap_or_default();
        inner.saved.pointed = pointed;
        self.save(&inner.saved);
        if let Some(running) = &inner.running {
            running.control.set_upstreams(upstreams.clone());
        }

        if probe(addr, PROBE_NAME, PROBE_TIMEOUT).await {
            inner.strikes = 0;
        } else if any_answers(&upstreams).await {
            inner.strikes += 1;
            if inner.strikes >= MAX_STRIKES {
                inner.saved.enabled = false;
                self.turn_off(&mut inner).await;
                inner.notice = Some(
                    "Blocking turned itself off because lookups stopped working through Guardian Angel. Your network settings are back as they were."
                        .into(),
                );
            }
        }
    }

    fn policy_mut(&self) -> std::sync::RwLockWriteGuard<'_, Policy> {
        self.policy.write().unwrap_or_else(|p| p.into_inner())
    }

    async fn update_saved(&self, change: impl FnOnce(&mut Saved, &mut Policy)) -> Value {
        let mut inner = self.inner.lock().await;
        change(&mut inner.saved, &mut self.policy_mut());
        self.save(&inner.saved);
        drop(inner);
        self.status().await
    }

    pub async fn set_profile(&self, profile: Profile) -> Value {
        self.update_saved(|s, p| {
            s.profile = Some(profile);
            p.profile = profile;
        })
        .await
    }

    pub async fn pause(&self, minutes: u32) -> Value {
        let until = crate::engine::unix_now() + i64::from(minutes) * 60;
        self.update_saved(|s, p| {
            s.paused_until = Some(until);
            p.pause_until(until);
        })
        .await
    }

    pub async fn resume(&self) -> Value {
        self.update_saved(|s, p| {
            s.paused_until = None;
            p.resume();
        })
        .await
    }

    pub async fn allow(&self, domain: &str, allowed: bool) -> Value {
        self.update_saved(|s, p| {
            if allowed {
                p.allow(domain);
            } else {
                p.unallow(domain);
            }
            s.allowed = p.allowed().map(str::to_owned).collect();
        })
        .await
    }

    pub async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let policy = self.policy.read().unwrap_or_else(|p| p.into_inner());
        let paused_until = policy.paused_until().filter(|u| *u > crate::engine::unix_now());
        let stats = inner.running.as_ref().map(|r| r.control.stats()).unwrap_or_default();
        let mut companies: Vec<(&String, &u64)> = stats.blocked_by_company.iter().collect();
        companies.sort_by(|a, b| b.1.cmp(a.1));
        json!({
            "enabled": inner.saved.enabled,
            "running": inner.running.is_some(),
            "profile": policy.profile,
            "paused_until": paused_until,
            "adapters": inner.saved.pointed.iter().map(|a| a.name.clone()).collect::<Vec<_>>(),
            "upstreams": inner.running.as_ref().map(|r| r.control.upstreams()).unwrap_or_default(),
            "queries": stats.queries,
            "blocked": stats.blocked,
            "top_companies": companies.iter().take(10).map(|(c, n)| json!({ "company": c, "blocked": n })).collect::<Vec<_>>(),
            "allowed": policy.allowed().collect::<Vec<_>>(),
            "error": inner.error,
            "notice": inner.notice,
        })
    }
}

/// Whether any of the network's own DNS servers answers right now.
async fn any_answers(upstreams: &[SocketAddr]) -> bool {
    for upstream in upstreams.iter().take(3) {
        if probe(*upstream, PROBE_NAME, PROBE_TIMEOUT).await {
            return true;
        }
    }
    false
}

/// Puts back adapters recorded in `blocking.json` without starting the
/// engine. Used by the uninstaller in case the service could not do it.
pub fn restore_from_disk(data_root: &std::path::Path) -> Vec<String> {
    let path = data_root.join("blocking.json");
    let Some(mut saved) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Saved>(&b).ok()) else {
        return Vec::new();
    };
    let restored: Vec<String> = saved.pointed.iter().map(|a| a.name.clone()).collect();
    saved.pointed = switch::restore(&ga_blocker::system_dns::WindowsDns, &saved.pointed);
    saved.enabled = false;
    if let Ok(json) = serde_json::to_vec_pretty(&saved) {
        let _ = std::fs::write(&path, json);
    }
    restored
}

#[cfg(test)]
mod tests {
    use super::*;
    use ga_blocker::switch::AdapterDns;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        set: Mutex<HashMap<(u32, bool), Vec<IpAddr>>>,
    }
    impl DnsSystem for Fake {
        fn adapters(&self) -> Vec<AdapterDns> {
            vec![AdapterDns {
                id: "{wifi}".into(),
                index: 7,
                name: "Wi-Fi".into(),
                v4_static: vec![],
                v6_static: vec![],
                // TEST-NET: never answers, so the health check treats the PC as offline.
                v4_auto: vec!["192.0.2.1".parse().unwrap()],
                v6_auto: vec![],
            }]
        }
        fn set(&self, index: u32, ipv6: bool, servers: &[IpAddr]) -> Result<(), String> {
            self.set.lock().unwrap().insert((index, ipv6), servers.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn turning_on_and_off_points_and_restores_adapters_and_survives_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(TrackerDb::bundled().unwrap());
        let fake = Arc::new(Fake::default());
        let blocking = Blocking::with_system(tmp.path(), db.clone(), fake.clone(), 0);

        let status = blocking.enable(Profile::Strict).await.unwrap();
        assert_eq!(status["enabled"], true);
        assert_eq!(status["adapters"], json!(["Wi-Fi"]));
        assert_eq!(fake.set.lock().unwrap()[&(7, false)][0].to_string(), "127.0.0.1");

        // Stopping the service puts Windows back but remembers the choice.
        blocking.shutdown().await;
        assert!(fake.set.lock().unwrap()[&(7, false)].is_empty(), "automatic again");
        let again = Blocking::with_system(tmp.path(), db.clone(), fake.clone(), 0);
        again.resume_after_start().await;
        let status = again.status().await;
        assert_eq!((status["enabled"].clone(), status["running"].clone()), (json!(true), json!(true)));
        assert_eq!(status["profile"], "strict");

        let status = again.disable().await;
        assert_eq!(status["enabled"], false);
        assert!(fake.set.lock().unwrap()[&(7, false)].is_empty());
        assert!(restore_from_disk(tmp.path()).is_empty(), "nothing left to restore");
    }

    #[tokio::test]
    async fn allow_list_and_pause_are_remembered() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(TrackerDb::bundled().unwrap());
        let blocking = Blocking::with_system(tmp.path(), db.clone(), Arc::new(Fake::default()), 0);
        blocking.allow("Example.com", true).await;
        let status = blocking.pause(10).await;
        assert_eq!(status["allowed"], json!(["example.com"]));
        assert!(status["paused_until"].as_i64().is_some());

        let again = Blocking::with_system(tmp.path(), db, Arc::new(Fake::default()), 0);
        let status = again.status().await;
        assert_eq!(status["allowed"], json!(["example.com"]));
        assert!(status["paused_until"].as_i64().is_some());
    }

    #[test]
    fn reads_profile_names() {
        assert_eq!(profile_from("balanced").unwrap(), Profile::Balanced);
        assert!(profile_from("extreme").is_err());
    }
}