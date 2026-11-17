//! Which connections are decrypted: every connection of an app the user
//! picked, and (when watching is on) connections from any app to a known
//! tracking company only. Hosts that must never be touched, and hosts an app
//! refused to let us inspect, are always tunnelled untouched.

use std::collections::BTreeSet;
use std::sync::Arc;

/// Says whether a host belongs to a tracking company.
#[derive(Clone)]
pub struct TrackerHosts(pub Arc<dyn Fn(&str) -> bool + Send + Sync>);

impl std::fmt::Debug for TrackerHosts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrackerHosts")
    }
}

/// Never decrypted, whatever the user chose: system updates, security
/// services and Microsoft sign-in.
const NEVER_INSPECT: &[&str] = &[
    "windowsupdate.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "definitionupdates.microsoft.com",
    "wdcp.microsoft.com",
    "smartscreen.microsoft.com",
    "activation.sls.microsoft.com",
    "login.microsoftonline.com",
    "login.live.com",
];

#[derive(Debug, Clone, Default)]
pub struct Rules {
    inspect_all: bool,
    /// Lowercase executable names, e.g. `discord.exe`.
    apps: BTreeSet<String>,
    /// Hosts whose app rejected our certificate (pinning or its own trust
    /// list). Tunnelled from then on so the app keeps working.
    learned_bypass: BTreeSet<String>,
    /// When set, connections from any app to these hosts are decrypted.
    trackers: Option<TrackerHosts>,
}

impl Rules {
    /// Inspect only these apps (executable names).
    pub fn for_apps<'a>(apps: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            apps: apps.into_iter().map(str::to_lowercase).collect(),
            ..Self::default()
        }
    }

    /// Inspect every app (developer and test use).
    pub fn everything() -> Self {
        Self {
            inspect_all: true,
            ..Self::default()
        }
    }

    pub fn add_app(&mut self, exe: &str) {
        self.apps.insert(exe.to_lowercase());
    }

    pub fn remove_app(&mut self, exe: &str) {
        self.apps.remove(&exe.to_lowercase());
    }

    pub fn should_inspect(&self, app: Option<&str>, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        if NEVER_INSPECT.iter().any(|d| covers(&host, d)) || self.learned_bypass.contains(&host) {
            return false;
        }
        self.inspect_all
            || app.is_some_and(|a| self.apps.contains(&a.to_lowercase()))
            || self.trackers.as_ref().is_some_and(|t| (t.0)(&host))
    }

    /// Watch what every app sends to tracking companies (`None` stops it).
    pub fn watch_trackers(&mut self, trackers: Option<TrackerHosts>) {
        self.trackers = trackers;
    }

    pub fn watching_trackers(&self) -> bool {
        self.trackers.is_some()
    }

    pub fn learn_bypass(&mut self, host: &str) {
        self.learned_bypass.insert(host.to_ascii_lowercase());
    }

    /// Apps opted in to inspection (lowercase executable names).
    pub fn apps(&self) -> impl Iterator<Item = &str> {
        self.apps.iter().map(String::as_str)
    }

    pub fn bypassed_hosts(&self) -> impl Iterator<Item = &str> {
        self.learned_bypass.iter().map(String::as_str)
    }
}

fn covers(host: &str, rule: &str) -> bool {
    host == rule || host.strip_suffix(rule).is_some_and(|rest| rest.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_only_opted_in_apps() {
        let r = Rules::for_apps(["Discord.exe"]);
        assert!(r.should_inspect(Some("discord.exe"), "discord.com"));
        assert!(!r.should_inspect(Some("slack.exe"), "slack.com"));
        assert!(!r.should_inspect(None, "discord.com"));
    }

    #[test]
    fn watching_trackers_decrypts_only_tracker_hosts_from_any_app() {
        let mut r = Rules::default();
        r.watch_trackers(Some(TrackerHosts(Arc::new(|h: &str| h.ends_with("doubleclick.net")))));
        assert!(r.should_inspect(Some("chrome.exe"), "stats.g.doubleclick.net"));
        assert!(r.should_inspect(None, "stats.g.doubleclick.net"));
        assert!(!r.should_inspect(Some("chrome.exe"), "mybank.example"), "everything else is untouched");
        r.watch_trackers(None);
        assert!(!r.should_inspect(Some("chrome.exe"), "stats.g.doubleclick.net"));
    }

    #[test]
    fn never_inspects_protected_or_learned_hosts() {
        let mut r = Rules::everything();
        assert!(!r.should_inspect(Some("x.exe"), "ctldl.windowsupdate.com"));
        assert!(!r.should_inspect(Some("x.exe"), "login.microsoftonline.com"));
        assert!(r.should_inspect(Some("x.exe"), "pinned.example"));
        r.learn_bypass("Pinned.Example");
        assert!(!r.should_inspect(Some("x.exe"), "pinned.example"));
        assert_eq!(r.bypassed_hosts().collect::<Vec<_>>(), ["pinned.example"]);
    }
}
