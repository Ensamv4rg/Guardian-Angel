//! Counts DNS lookups per (program, domain). Pure logic: the ETW layer feeds
//! it events, tests feed it directly.

use ga_core::{NetworkCapture, ProcessDomainStat};
use std::collections::HashMap;
use std::net::IpAddr;

/// Distinct (program, domain) pairs kept in memory. Lookups beyond this are
/// still counted in the total but not itemised, so memory stays bounded
/// (requirement NFR-1).
pub const MAX_ENTRIES: usize = 50_000;

/// How long a PID-to-executable lookup is trusted before asking again, since
/// Windows reuses PIDs after a process exits.
const PID_CACHE_SECS: i64 = 300;

/// Looks up the executable path for a PID.
pub type ProcessResolver = Box<dyn Fn(u32) -> Option<String> + Send>;

pub struct Aggregator {
    own_pid: u32,
    started_unix: i64,
    last_event_unix: i64,
    total: u64,
    resolver: ProcessResolver,
    pid_cache: HashMap<u32, (Option<String>, i64)>,
    stats: HashMap<(String, String), ProcessDomainStat>,
}

impl Aggregator {
    pub fn new(own_pid: u32, started_unix: i64, resolver: ProcessResolver) -> Self {
        Self {
            own_pid,
            started_unix,
            last_event_unix: started_unix,
            total: 0,
            resolver,
            pid_cache: HashMap::new(),
            stats: HashMap::new(),
        }
    }

    /// Records one completed lookup.
    pub fn record(&mut self, pid: u32, domain: &str, succeeded: bool, unix: i64) {
        if pid == self.own_pid {
            return;
        }
        let Some(domain) = normalize(domain) else { return };
        self.total += 1;
        self.last_event_unix = self.last_event_unix.max(unix);

        let path = self.process_path(pid, unix);
        let process = match &path {
            Some(p) => p.rsplit('\\').next().unwrap_or(p).to_owned(),
            None => format!("PID {pid}"),
        };
        let key = (path.clone().unwrap_or_else(|| process.clone()), domain.clone());

        if !self.stats.contains_key(&key) && self.stats.len() >= MAX_ENTRIES {
            return;
        }
        let stat = self.stats.entry(key).or_insert_with(|| ProcessDomainStat {
            process,
            process_path: path,
            domain,
            lookups: 0,
            failed: 0,
            first_seen_unix: unix,
            last_seen_unix: unix,
        });
        stat.lookups += 1;
        if !succeeded {
            stat.failed += 1;
        }
        stat.first_seen_unix = stat.first_seen_unix.min(unix);
        stat.last_seen_unix = stat.last_seen_unix.max(unix);
    }

    fn process_path(&mut self, pid: u32, now: i64) -> Option<String> {
        if let Some((path, at)) = self.pid_cache.get(&pid)
            && now - at < PID_CACHE_SECS
        {
            return path.clone();
        }
        let path = (self.resolver)(pid);
        self.pid_cache.insert(pid, (path.clone(), now));
        path
    }

    /// Current totals, busiest pairs first.
    pub fn snapshot(&self, now_unix: i64) -> NetworkCapture {
        let mut stats: Vec<ProcessDomainStat> = self.stats.values().cloned().collect();
        stats.sort_by(|a, b| {
            b.lookups
                .cmp(&a.lookups)
                .then_with(|| a.process.cmp(&b.process))
                .then_with(|| a.domain.cmp(&b.domain))
        });
        NetworkCapture {
            started_unix: self.started_unix,
            ended_unix: now_unix.max(self.last_event_unix),
            total_lookups: self.total,
            stats,
        }
    }
}

/// Lowercases and strips the trailing dot. Drops names that never reach an
/// internet tracker: reverse lookups, IP literals, single-label and `.local`
/// names.
fn normalize(domain: &str) -> Option<String> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let local_only = d.is_empty()
        || !d.contains('.')
        || d.ends_with(".in-addr.arpa")
        || d.ends_with(".ip6.arpa")
        || d.ends_with(".local")
        || d.parse::<IpAddr>().is_ok();
    (!local_only).then_some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg() -> Aggregator {
        Aggregator::new(
            1,
            1_000,
            Box::new(|pid| match pid {
                100 => Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_owned()),
                200 => Some(r"C:\Windows\System32\svchost.exe".to_owned()),
                _ => None,
            }),
        )
    }

    #[test]
    fn counts_per_process_and_domain() {
        let mut a = agg();
        a.record(100, "www.google-analytics.com.", true, 1_010);
        a.record(100, "WWW.Google-Analytics.com", true, 1_020);
        a.record(100, "doubleclick.net", false, 1_030);
        a.record(200, "www.google-analytics.com", true, 1_040);
        a.record(999, "example.com", true, 1_050);

        let c = a.snapshot(1_060);
        assert_eq!(c.total_lookups, 5);
        assert_eq!(c.started_unix, 1_000);
        assert_eq!(c.ended_unix, 1_060);
        assert_eq!(c.stats.len(), 4);

        let top = &c.stats[0];
        assert_eq!(top.process, "chrome.exe");
        assert_eq!(top.domain, "www.google-analytics.com");
        assert_eq!(top.lookups, 2);
        assert_eq!((top.first_seen_unix, top.last_seen_unix), (1_010, 1_020));

        let dc = c.stats.iter().find(|s| s.domain == "doubleclick.net").unwrap();
        assert_eq!(dc.failed, 1);

        let unknown = c.stats.iter().find(|s| s.domain == "example.com").unwrap();
        assert_eq!(unknown.process, "PID 999");
        assert_eq!(unknown.process_path, None);
    }

    #[test]
    fn ignores_own_process_and_local_names() {
        let mut a = agg();
        a.record(1, "tracker.com", true, 1_001);
        for name in ["wpad", "localhost", "printer.local", "1.0.0.127.in-addr.arpa", "192.168.1.1", "::1", ""] {
            a.record(100, name, true, 1_002);
        }
        let c = a.snapshot(1_003);
        assert_eq!(c.total_lookups, 0);
        assert!(c.stats.is_empty());
    }

    #[test]
    fn caches_process_lookups_but_expires_them() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let c2 = calls.clone();
        let mut a = Aggregator::new(
            1,
            0,
            Box::new(move |_| {
                c2.fetch_add(1, Ordering::SeqCst);
                Some(r"C:\x\app.exe".into())
            }),
        );
        a.record(50, "a.com", true, 10);
        a.record(50, "b.com", true, 20);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        a.record(50, "c.com", true, 10 + PID_CACHE_SECS);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn memory_is_bounded() {
        let mut a = Aggregator::new(1, 0, Box::new(|_| None));
        for i in 0..(MAX_ENTRIES + 10) {
            a.record(7, &format!("d{i}.com"), true, 1);
        }
        // Existing pairs keep counting after the cap.
        a.record(7, "d0.com", true, 2);
        let c = a.snapshot(3);
        assert_eq!(c.stats.len(), MAX_ENTRIES);
        assert_eq!(c.total_lookups, (MAX_ENTRIES + 11) as u64);
        assert_eq!(c.stats[0].domain, "d0.com");
    }
}
