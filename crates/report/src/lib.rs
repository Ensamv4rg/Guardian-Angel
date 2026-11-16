//! Turns raw scan results into a report grouped by company (requirement FR-6).

use ga_core::{Browser, Category, CookieScan, ScanWarning};
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
    pub cookie_count: usize,
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
    pub warnings: Vec<ScanWarning>,
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
    let mut top: Vec<DomainCount> = unclassified
        .into_iter()
        .map(|(domain, cookie_count)| DomainCount {
            domain: domain.to_owned(),
            cookie_count,
        })
        .collect();
    top.sort_by(|a, b| {
        b.cookie_count
            .cmp(&a.cookie_count)
            .then_with(|| a.domain.cmp(&b.domain))
    });
    top.truncate(TOP_UNCLASSIFIED);

    CookieReport {
        profiles_scanned: scan.profiles_scanned,
        total_cookies: scan.cookies.len(),
        tracker_cookies,
        companies,
        unclassified_cookies,
        unclassified_domains,
        top_unclassified: top,
        warnings: scan.warnings.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ga_core::CookieRecord;

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
        assert_eq!(report.top_unclassified[0].cookie_count, 2);
    }
}
