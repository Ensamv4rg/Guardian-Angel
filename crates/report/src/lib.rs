//! Turns raw scan results into a report grouped by company (requirement FR-6).

mod purpose;

pub use purpose::{CookiePurpose, identify as cookie_purpose};

use ga_core::{Browser, Category, CookieScan, NetworkCapture, ScanWarning};
use ga_knowledge::TrackerDb;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// How many unknown domains to list by name.
const TOP_UNCLASSIFIED: usize = 10;

/// Everything one company can see through cookies on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompanyExposure {
    pub company: String,
    pub categories: BTreeSet<Category>,
    pub cookie_count: usize,
    /// Listed tracker domains that matched, e.g. `doubleclick.net`.
    pub domains: BTreeSet<String>,
    pub browsers: BTreeSet<Browser>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieReport {
    pub profiles_scanned: usize,
    pub total_cookies: usize,
    pub tracker_cookies: usize,
    /// Sorted by cookie count, largest first.
    pub companies: Vec<CompanyExposure>,
    pub unclassified_cookies: usize,
    pub unclassified_domains: usize,
    pub top_unclassified: Vec<DomainCount>,
    /// What the cookies outside the tracker list are for.
    pub other: OtherCookies,
    pub warnings: Vec<ScanWarning>,
}

/// Cookies on sites that are not on the tracker list, explained by name.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OtherCookies {
    /// Largest first.
    pub by_purpose: Vec<PurposeCount>,
    /// Tracking tools found under sites' own domains, most sites first.
    pub hidden_trackers: Vec<HiddenTracker>,
    /// Sites with the most of these cookies.
    pub top_sites: Vec<SiteCookies>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PurposeCount {
    pub purpose: CookiePurpose,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HiddenTracker {
    pub tool: String,
    pub cookies: usize,
    /// Number of different sites it was found on.
    pub sites: usize,
    /// A few example sites.
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteCookies {
    pub site: String,
    pub count: usize,
    pub purposes: BTreeSet<CookiePurpose>,
}

const TOP_SITES: usize = 15;
const EXAMPLE_SITES: usize = 4;

fn explain_other(scan: &CookieScan, db: &TrackerDb) -> OtherCookies {
    let mut by_purpose: HashMap<CookiePurpose, usize> = HashMap::new();
    let mut hidden: HashMap<&'static str, (usize, BTreeSet<String>)> = HashMap::new();
    let mut sites: HashMap<String, (usize, BTreeSet<CookiePurpose>)> = HashMap::new();
    for cookie in scan.cookies.iter().filter(|c| db.classify(&c.host).is_none()) {
        let (purpose, tool) = purpose::identify(&cookie.name);
        *by_purpose.entry(purpose).or_default() += 1;
        let site = cookie.host.strip_prefix("www.").unwrap_or(&cookie.host).to_owned();
        if let Some(tool) = tool {
            let entry = hidden.entry(tool).or_default();
            entry.0 += 1;
            entry.1.insert(site.clone());
        }
        let entry = sites.entry(site).or_default();
        entry.0 += 1;
        entry.1.insert(purpose);
    }

    let mut by_purpose: Vec<PurposeCount> = by_purpose.into_iter().map(|(purpose, count)| PurposeCount { purpose, count }).collect();
    by_purpose.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.purpose.cmp(&b.purpose)));

    let mut hidden_trackers: Vec<HiddenTracker> = hidden
        .into_iter()
        .map(|(tool, (cookies, site_set))| HiddenTracker {
            tool: tool.to_owned(),
            cookies,
            sites: site_set.len(),
            examples: site_set.into_iter().take(EXAMPLE_SITES).collect(),
        })
        .collect();
    hidden_trackers.sort_by(|a, b| b.sites.cmp(&a.sites).then_with(|| a.tool.cmp(&b.tool)));

    let mut top_sites: Vec<SiteCookies> = sites
        .into_iter()
        .map(|(site, (count, purposes))| SiteCookies { site, count, purposes })
        .collect();
    top_sites.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.site.cmp(&b.site)));
    top_sites.truncate(TOP_SITES);

    OtherCookies {
        by_purpose,
        hidden_trackers,
        top_sites,
    }
}

pub fn build_cookie_report(scan: &CookieScan, db: &TrackerDb) -> CookieReport {
    let mut companies: HashMap<&str, CompanyExposure> = HashMap::new();
    let mut unclassified: HashMap<&str, usize> = HashMap::new();
    let mut tracker_cookies = 0;

    for cookie in &scan.cookies {
        match db.classify(&cookie.host) {
            Some(m) => {
                tracker_cookies += 1;
                let entry = companies.entry(m.company).or_insert_with(|| CompanyExposure {
                    company: m.company.to_owned(),
                    categories: BTreeSet::new(),
                    cookie_count: 0,
                    domains: BTreeSet::new(),
                    browsers: BTreeSet::new(),
                });
                entry.cookie_count += 1;
                entry.categories.insert(m.category);
                entry.domains.insert(m.domain.to_owned());
                entry.browsers.insert(cookie.browser);
            }
            None => *unclassified.entry(cookie.host.as_str()).or_default() += 1,
        }
    }

    let mut companies: Vec<CompanyExposure> = companies.into_values().collect();
    companies.sort_by(|a, b| {
        b.cookie_count
            .cmp(&a.cookie_count)
            .then_with(|| a.company.cmp(&b.company))
    });

    let unclassified_domains = unclassified.len();
    let unclassified_cookies = unclassified.values().sum();
    let top = top_domains(unclassified);

    CookieReport {
        profiles_scanned: scan.profiles_scanned,
        total_cookies: scan.cookies.len(),
        tracker_cookies,
        companies,
        unclassified_cookies,
        unclassified_domains,
        top_unclassified: top,
        other: explain_other(scan, db),
        warnings: scan.warnings.clone(),
    }
}

/// Which programs contacted one company during a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompanyContacts {
    pub company: String,
    pub categories: BTreeSet<Category>,
    pub lookups: u64,
    /// Listed tracker domains that matched.
    pub domains: BTreeSet<String>,
    /// Executable names, e.g. `chrome.exe`.
    pub processes: BTreeSet<String>,
}

/// One program's lookups during a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessSummary {
    pub process: String,
    pub lookups: u64,
    pub tracker_lookups: u64,
    pub companies: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkReport {
    pub duration_secs: i64,
    pub total_lookups: u64,
    pub tracker_lookups: u64,
    /// Busiest first.
    pub companies: Vec<CompanyContacts>,
    /// Most tracker lookups first.
    pub processes: Vec<ProcessSummary>,
    pub top_unclassified: Vec<DomainCount>,
}

/// Groups a DNS capture by company and by program (FR-5, FR-6).
pub fn build_network_report(capture: &NetworkCapture, db: &TrackerDb) -> NetworkReport {
    let mut companies: HashMap<&str, CompanyContacts> = HashMap::new();
    let mut processes: HashMap<&str, ProcessSummary> = HashMap::new();
    let mut unclassified: HashMap<&str, usize> = HashMap::new();
    let mut tracker_lookups = 0;

    for s in &capture.stats {
        let n = u64::from(s.lookups);
        let proc_entry = processes.entry(s.process.as_str()).or_insert_with(|| ProcessSummary {
            process: s.process.clone(),
            lookups: 0,
            tracker_lookups: 0,
            companies: BTreeSet::new(),
        });
        proc_entry.lookups += n;

        match db.classify(&s.domain) {
            Some(m) => {
                tracker_lookups += n;
                proc_entry.tracker_lookups += n;
                proc_entry.companies.insert(m.company.to_owned());
                let c = companies.entry(m.company).or_insert_with(|| CompanyContacts {
                    company: m.company.to_owned(),
                    categories: BTreeSet::new(),
                    lookups: 0,
                    domains: BTreeSet::new(),
                    processes: BTreeSet::new(),
                });
                c.lookups += n;
                c.categories.insert(m.category);
                c.domains.insert(m.domain.to_owned());
                c.processes.insert(s.process.clone());
            }
            None => *unclassified.entry(s.domain.as_str()).or_default() += s.lookups as usize,
        }
    }

    let mut companies: Vec<CompanyContacts> = companies.into_values().collect();
    companies.sort_by(|a, b| b.lookups.cmp(&a.lookups).then_with(|| a.company.cmp(&b.company)));
    let mut processes: Vec<ProcessSummary> = processes.into_values().collect();
    processes.sort_by(|a, b| {
        b.tracker_lookups
            .cmp(&a.tracker_lookups)
            .then_with(|| b.lookups.cmp(&a.lookups))
            .then_with(|| a.process.cmp(&b.process))
    });

    NetworkReport {
        duration_secs: (capture.ended_unix - capture.started_unix).max(0),
        total_lookups: capture.total_lookups,
        tracker_lookups,
        companies,
        processes,
        top_unclassified: top_domains(unclassified),
    }
}

fn top_domains(counts: HashMap<&str, usize>) -> Vec<DomainCount> {
    let mut top: Vec<DomainCount> = counts
        .into_iter()
        .map(|(domain, count)| DomainCount {
            domain: domain.to_owned(),
            count,
        })
        .collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.domain.cmp(&b.domain)));
    top.truncate(TOP_UNCLASSIFIED);
    top
}

#[cfg(test)]
mod tests {
    use super::*;
    use ga_core::{CookieRecord, ProcessDomainStat};

    fn stat(process: &str, domain: &str, lookups: u32) -> ProcessDomainStat {
        ProcessDomainStat {
            process: process.into(),
            process_path: None,
            domain: domain.into(),
            lookups,
            failed: 0,
            first_seen_unix: 0,
            last_seen_unix: 0,
        }
    }

    #[test]
    fn groups_network_lookups_by_company_and_process() {
        let capture = NetworkCapture {
            started_unix: 100,
            ended_unix: 160,
            total_lookups: 16,
            stats: vec![
                stat("chrome.exe", "www.google-analytics.com", 5),
                stat("chrome.exe", "connect.facebook.net", 3),
                stat("Discord.exe", "discord.com", 6),
                stat("svchost.exe", "settings-win.data.microsoft.com", 1),
                stat("Spotify.exe", "pagead2.googlesyndication.com", 1),
            ],
        };
        let r = build_network_report(&capture, &TrackerDb::bundled().unwrap());

        assert_eq!(r.duration_secs, 60);
        assert_eq!(r.tracker_lookups, 9);
        assert_eq!(r.companies[0].company, "Google");
        assert_eq!(r.companies[0].lookups, 6);
        assert_eq!(
            r.companies[0].processes,
            BTreeSet::from(["Spotify.exe".to_owned(), "chrome.exe".to_owned()])
        );
        assert_eq!(r.companies[1].company, "Meta");

        assert_eq!(r.processes[0].process, "chrome.exe");
        assert_eq!(r.processes[0].tracker_lookups, 8);
        assert_eq!(r.processes[0].companies.len(), 2);

        assert_eq!(r.top_unclassified[0].domain, "discord.com");
        assert_eq!(r.top_unclassified[0].count, 6);
    }

    fn cookie(browser: Browser, host: &str) -> CookieRecord {
        CookieRecord {
            browser,
            profile: "Default".into(),
            host: host.into(),
            name: "c".into(),
            last_access_unix: None,
        }
    }

    #[test]
    fn groups_cookies_by_company() {
        let scan = CookieScan {
            cookies: vec![
                cookie(Browser::Chrome, "doubleclick.net"),
                cookie(Browser::Edge, "stats.g.doubleclick.net"),
                cookie(Browser::Chrome, "google-analytics.com"),
                cookie(Browser::Firefox, "facebook.com"),
                cookie(Browser::Chrome, "example.com"),
                cookie(Browser::Chrome, "example.com"),
                cookie(Browser::Chrome, "other.org"),
            ],
            warnings: vec![],
            profiles_scanned: 3,
        };
        let db = TrackerDb::bundled().unwrap();
        let report = build_cookie_report(&scan, &db);

        assert_eq!(report.total_cookies, 7);
        assert_eq!(report.tracker_cookies, 4);
        assert_eq!(report.companies.len(), 2);

        let google = &report.companies[0];
        assert_eq!(google.company, "Google");
        assert_eq!(google.cookie_count, 3);
        assert_eq!(
            google.categories,
            BTreeSet::from([Category::Advertising, Category::Analytics])
        );
        assert_eq!(
            google.domains,
            BTreeSet::from(["doubleclick.net".to_owned(), "google-analytics.com".to_owned()])
        );
        assert_eq!(google.browsers, BTreeSet::from([Browser::Chrome, Browser::Edge]));

        assert_eq!(report.companies[1].company, "Meta");

        assert_eq!(report.unclassified_cookies, 3);
        assert_eq!(report.unclassified_domains, 2);
        assert_eq!(report.top_unclassified[0].domain, "example.com");
        // The other cookies are explained by name.
        assert_eq!(report.other.by_purpose.iter().map(|p| p.count).sum::<usize>(), 3);
        assert_eq!(report.top_unclassified[0].count, 2);
    }
}

#[cfg(test)]
mod other_cookie_tests {
    use super::*;
    use ga_core::CookieRecord;

    fn cookie(host: &str, name: &str) -> CookieRecord {
        CookieRecord {
            browser: Browser::Chrome,
            profile: "Default".into(),
            host: host.into(),
            name: name.into(),
            last_access_unix: None,
        }
    }

    #[test]
    fn finds_trackers_hiding_under_site_domains() {
        let scan = CookieScan {
            cookies: vec![
                cookie("www.shop.example", "_ga"),
                cookie("shop.example", "_ga_XYZ"),
                cookie("news.example", "_ga"),
                cookie("news.example", "_fbp"),
                cookie("news.example", "PHPSESSID"),
                cookie("bank.example", "__cf_bm"),
                // On the tracker list: counted as a company, not here.
                cookie("doubleclick.net", "IDE"),
            ],
            warnings: vec![],
            profiles_scanned: 1,
        };
        let r = build_cookie_report(&scan, &TrackerDb::bundled().unwrap());
        let ga = &r.other.hidden_trackers[0];
        assert_eq!((ga.tool.as_str(), ga.sites, ga.cookies), ("Google Analytics", 2, 3));
        assert_eq!(r.other.by_purpose[0], PurposeCount { purpose: CookiePurpose::Tracking, count: 4 });
        assert_eq!(r.other.top_sites[0].site, "news.example");
        assert!(r.other.top_sites[0].purposes.contains(&CookiePurpose::Login));
        assert_eq!(r.companies.len(), 1);
    }
}
