//! What trackers received: a per-user log of decrypted requests to tracking
//! companies, and the reports built from it.
//!
//! - Each request is stored with the site or app it came from, the cookies
//!   the tracker set, the privacy choices it carried and what it contained.
//! - "Your choices": sites where the user said no to tracking. Anything sent
//!   from them afterwards with an ID for the user is flagged.
//! - Data requests the user sent, with their due dates.
//!
//! The log stays on this PC, in the user's own Guardian Angel folder, and
//! keeps 30 days or 5,000 requests, whichever is less.

use ga_core::{Category, ConsentSignal, DataKind, DecodedField};
use ga_knowledge::TrackerDb;
use ga_proxy::InspectedRequest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_SIGHTINGS: usize = 5_000;
const KEEP_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_FIELDS: usize = 60;

/// Kinds of data that let a company recognise you.
pub const IDENTIFYING: &[DataKind] = &[
    DataKind::Email,
    DataKind::HashedEmail,
    DataKind::HashedPersonalDetail,
    DataKind::PersonalDetail,
    DataKind::UserId,
    DataKind::PersistentId,
    DataKind::ClickId,
];

/// One request to a tracking company.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sighting {
    pub unix: i64,
    pub app: Option<String>,
    /// The site the request was made from (browsers), without `www.`.
    pub source: Option<String>,
    pub host: String,
    pub company: String,
    pub category: Option<Category>,
    /// Decoder product ("Google Analytics 4") or "Unrecognised format".
    pub product: Option<String>,
    pub fields: Vec<DecodedField>,
    pub consent: Vec<ConsentSignal>,
    pub set_cookies: Vec<String>,
}

impl Sighting {
    fn identifies(&self) -> bool {
        self.fields.iter().any(|f| IDENTIFYING.contains(&f.kind))
    }
    fn refused_in_request(&self) -> bool {
        self.consent.iter().any(|c| c.refused)
    }
}

/// A site where the user said no to tracking, and when.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteChoice {
    pub site: String,
    pub refused_unix: i64,
}

/// A data request the user sent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataRequest {
    pub company: String,
    /// "access", "delete" or "object".
    pub kind: String,
    pub sent_unix: i64,
    pub due_unix: i64,
}

/// Who the letters are from (kept only on this PC).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Requester {
    pub name: String,
    pub email: String,
    /// "gdpr" (EU/UK), "ccpa" (California) or "other".
    pub region: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    choices: Vec<SiteChoice>,
    requests: Vec<DataRequest>,
    requester: Requester,
}

struct UserLog {
    dir: PathBuf,
    sightings: VecDeque<Sighting>,
    saved: Saved,
}

pub struct Watch {
    root: PathBuf,
    db: Arc<TrackerDb>,
    users: Mutex<HashMap<String, UserLog>>,
}

/// `www.news.example` -> `news.example`.
pub fn site_name(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    host.strip_prefix("www.").map(str::to_owned).unwrap_or(host)
}

/// `site` is `choice` or one of its subdomains.
fn covers(site: &str, choice: &str) -> bool {
    site == choice || site.ends_with(&format!(".{choice}"))
}

impl Watch {
    pub fn new(data_root: &Path, db: Arc<TrackerDb>) -> Arc<Self> {
        Arc::new(Self {
            root: data_root.join("users"),
            db,
            users: Mutex::new(HashMap::new()),
        })
    }

    fn with_user<T>(&self, key: &str, f: impl FnOnce(&mut UserLog) -> T) -> T {
        let mut users = self.users.lock().unwrap_or_else(|p| p.into_inner());
        let log = users.entry(key.to_owned()).or_insert_with(|| UserLog::load(&self.root.join(key)));
        f(log)
    }

    /// Turns a decrypted request into a sighting, if it went to a tracker.
    pub fn sighting(&self, r: &InspectedRequest) -> Option<Sighting> {
        let tracker = self.db.classify(&r.host);
        let decoded = r.payloads.first();
        if tracker.is_none() && decoded.is_none() {
            return None;
        }
        let company = decoded
            .map(|p| p.company.to_owned())
            .filter(|c| !c.is_empty())
            .or_else(|| tracker.map(|t| t.company.to_owned()))?;
        let mut fields: Vec<DecodedField> = r.payloads.iter().flat_map(|p| p.fields.iter().cloned()).collect();
        if let Some(summary) = &r.summary {
            fields.extend(summary.fields.iter().cloned());
        }
        fields.truncate(MAX_FIELDS);
        Some(Sighting {
            unix: r.unix,
            app: r.app.clone(),
            source: r.source.as_deref().map(site_name),
            host: r.host.clone(),
            company,
            category: tracker.map(|t| t.category),
            product: decoded.map(|p| p.product.to_owned()).or_else(|| r.summary.as_ref().map(|s| s.product.to_owned())),
            fields,
            consent: r.consent.clone(),
            set_cookies: r.set_cookies.clone(),
        })
    }

    /// Records a decrypted request for the user whose program sent it.
    pub fn record(&self, r: &InspectedRequest) {
        let Some(user) = r.user.as_deref() else { return };
        // Only a plain SID may become a folder name.
        if !user.starts_with("S-1-") || !user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return;
        }
        if let Some(s) = self.sighting(r) {
            self.with_user(user, |log| log.add(s));
        }
    }

    pub fn set_choice(&self, key: &str, site: &str, refused: bool, now: i64) {
        let site = site_name(site);
        self.with_user(key, |log| {
            log.saved.choices.retain(|c| c.site != site);
            if refused && !site.is_empty() {
                log.saved.choices.push(SiteChoice { site, refused_unix: now });
            }
            log.save();
        });
    }

    pub fn request_sent(&self, key: &str, company: &str, kind: &str, now: i64) {
        self.with_user(key, |log| {
            // California allows 45 days; EU/UK one month (30 days here).
            let days = if log.saved.requester.region == "ccpa" { 45 } else { 30 };
            log.saved.requests.retain(|r| !(r.company == company && r.kind == kind));
            log.saved.requests.push(DataRequest {
                company: company.to_owned(),
                kind: kind.to_owned(),
                sent_unix: now,
                due_unix: now + days * 24 * 60 * 60,
            });
            log.save();
        });
    }

    pub fn request_removed(&self, key: &str, company: &str, kind: &str) {
        self.with_user(key, |log| {
            log.saved.requests.retain(|r| !(r.company == company && r.kind == kind));
            log.save();
        });
    }

    pub fn set_requester(&self, key: &str, requester: Requester) {
        self.with_user(key, |log| {
            log.saved.requester = requester;
            log.save();
        });
    }

    /// Everything the Reports page shows.
    pub fn report(&self, key: &str, now: i64) -> Value {
        self.with_user(key, |log| {
            log.trim(now);
            build_report(log.sightings.iter(), &log.saved, now)
        })
    }
}

impl UserLog {
    fn load(dir: &Path) -> Self {
        let sightings = std::fs::read_to_string(dir.join("tracker_log.jsonl"))
            .map(|text| text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
            .unwrap_or_default();
        let saved = std::fs::read(dir.join("watch.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self {
            dir: dir.to_path_buf(),
            sightings,
            saved,
        }
    }

    fn add(&mut self, s: Sighting) {
        let _ = std::fs::create_dir_all(&self.dir);
        if let (Ok(mut file), Ok(line)) = (
            std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("tracker_log.jsonl")),
            serde_json::to_string(&s),
        ) {
            let _ = writeln!(file, "{line}");
        }
        self.sightings.push_back(s);
        if self.sightings.len() > MAX_SIGHTINGS + MAX_SIGHTINGS / 5 {
            self.trim(self.sightings.back().map_or(0, |s| s.unix));
        }
    }

    /// Drops old entries and rewrites the file when anything was dropped.
    fn trim(&mut self, now: i64) {
        let before = self.sightings.len();
        while self.sightings.front().is_some_and(|s| s.unix < now - KEEP_SECS) || self.sightings.len() > MAX_SIGHTINGS {
            self.sightings.pop_front();
        }
        if self.sightings.len() != before {
            let text: String = self
                .sightings
                .iter()
                .filter_map(|s| serde_json::to_string(s).ok())
                .map(|l| l + "\n")
                .collect();
            let _ = std::fs::write(self.dir.join("tracker_log.jsonl"), text);
        }
    }

    fn save(&self) {
        let _ = std::fs::create_dir_all(&self.dir);
        if let Ok(json) = serde_json::to_vec_pretty(&self.saved) {
            let _ = std::fs::write(self.dir.join("watch.json"), json);
        }
    }
}

#[derive(Default)]
struct CompanyAcc {
    requests: usize,
    category: Option<Category>,
    sites: BTreeMap<String, usize>,
    apps: BTreeSet<String>,
    kinds: BTreeSet<DataKind>,
    /// (label, value) of IDs and personal data, for data requests.
    identifiers: Vec<(String, String)>,
    cookies_set: BTreeMap<String, BTreeSet<String>>,
    refused_but_identified: usize,
    products: BTreeSet<String>,
    last: i64,
}

fn build_report<'a>(sightings: impl Iterator<Item = &'a Sighting>, saved: &Saved, now: i64) -> Value {
    let mut companies: BTreeMap<String, CompanyAcc> = BTreeMap::new();
    let mut sites: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    let mut after: BTreeMap<String, (usize, usize, BTreeSet<String>)> = BTreeMap::new();
    let mut recent: Vec<&Sighting> = Vec::new();
    let mut total = 0usize;

    for s in sightings {
        total += 1;
        recent.push(s);
        let c = companies.entry(s.company.clone()).or_default();
        c.requests += 1;
        c.category = c.category.or(s.category);
        c.last = c.last.max(s.unix);
        if let Some(p) = &s.product {
            c.products.insert(p.clone());
        }
        let origin = s.source.clone().or_else(|| s.app.clone()).unwrap_or_else(|| "Unknown".into());
        *c.sites.entry(origin.clone()).or_default() += 1;
        if let Some(app) = &s.app {
            c.apps.insert(app.clone());
        }
        for f in &s.fields {
            c.kinds.insert(f.kind);
            if IDENTIFYING.contains(&f.kind) && c.identifiers.len() < 12 && !c.identifiers.iter().any(|(_, v)| *v == f.value) {
                c.identifiers.push((f.label.clone(), f.value.clone()));
            }
        }
        for cookie in &s.set_cookies {
            c.cookies_set.entry(cookie.clone()).or_default().insert(origin.clone());
        }
        if s.refused_in_request() && s.identifies() {
            c.refused_but_identified += 1;
        }
        if let Some(site) = &s.source {
            let e = sites.entry(site.clone()).or_default();
            e.0 += 1;
            e.1.insert(s.company.clone());
            if let Some(choice) = saved.choices.iter().find(|c| covers(site, &c.site))
                && s.unix >= choice.refused_unix
            {
                let a = after.entry(choice.site.clone()).or_default();
                a.0 += 1;
                if s.identifies() {
                    a.1 += 1;
                    a.2.insert(s.company.clone());
                }
            }
        }
    }

    let mut company_list: Vec<(String, CompanyAcc)> = companies.into_iter().collect();
    company_list.sort_by(|a, b| b.1.requests.cmp(&a.1.requests));
    let companies: Vec<Value> = company_list
        .into_iter()
        .map(|(name, c)| {
            let mut sites: Vec<(String, usize)> = c.sites.into_iter().collect();
            sites.sort_by(|a, b| b.1.cmp(&a.1));
            json!({
                "company": name,
                "category": c.category,
                "requests": c.requests,
                "products": c.products,
                "sources": sites.iter().take(15).map(|(s, n)| json!({ "source": s, "requests": n })).collect::<Vec<_>>(),
                "source_count": sites.len(),
                "apps": c.apps,
                "kinds": c.kinds,
                "identifiers": c.identifiers.iter().map(|(l, v)| json!({ "label": l, "value": v })).collect::<Vec<_>>(),
                "cookies_set": c.cookies_set.iter().map(|(n, from)| json!({ "name": n, "from": from })).collect::<Vec<_>>(),
                "refused_but_identified": c.refused_but_identified,
                "last_unix": c.last,
                "contact": ga_knowledge::privacy_contact(&name),
            })
        })
        .collect();

    let mut site_list: Vec<(String, (usize, BTreeSet<String>))> = sites.into_iter().collect();
    site_list.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    let sites: Vec<Value> = site_list
        .iter()
        .take(100)
        .map(|(site, (n, cs))| json!({ "site": site, "requests": n, "companies": cs }))
        .collect();

    let choices: Vec<Value> = saved
        .choices
        .iter()
        .map(|choice| {
            let (requests, identifying, cos) = after.get(&choice.site).cloned().unwrap_or_default();
            let verdict = if identifying > 0 {
                "ignored"
            } else if requests > 0 {
                "anonymous_only"
            } else {
                "nothing_seen"
            };
            json!({
                "site": choice.site,
                "refused_unix": choice.refused_unix,
                "requests_after": requests,
                "identifying_after": identifying,
                "companies_after": cos,
                "verdict": verdict,
            })
        })
        .collect();

    recent.sort_by(|a, b| b.unix.cmp(&a.unix));
    let recent: Vec<&Sighting> = recent.into_iter().take(100).collect();
    json!({
        "now": now,
        "total": total,
        "companies": companies,
        "sites": sites,
        "choices": choices,
        "recent": recent,
        "requests": saved.requests,
        "requester": saved.requester,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(host: &str, source: Option<&str>, url_query: &str, unix: i64) -> InspectedRequest {
        let url = format!("https://{host}/collect?{url_query}");
        let decoder_request = ga_decoders::Request {
            method: "GET",
            url: &url,
            body: None,
        };
        let payloads = ga_decoders::decode(&decoder_request);
        InspectedRequest {
            app: Some("chrome.exe".into()),
            user: Some("S-1-5-21-1-2-3-1001".into()),
            unix,
            host: host.into(),
            method: "GET".into(),
            path: "/collect".into(),
            status: Some(200),
            request_bytes: 0,
            summary: if payloads.is_empty() { ga_decoders::summarize(&decoder_request) } else { None },
            payloads,
            source: source.map(str::to_owned),
            set_cookies: vec!["uid".into()],
            consent: ga_decoders::consent_signals(&decoder_request),
        }
    }

    #[test]
    fn reports_what_each_company_got_and_from_where() {
        let tmp = tempfile::tempdir().unwrap();
        let watch = Watch::new(tmp.path(), Arc::new(TrackerDb::bundled().unwrap()));
        let key = "S-1-5-21-1-2-3-1001";
        watch.record(&request("stats.g.doubleclick.net", Some("www.news.example"), "visitor_id=8f2b4c6d9e1a3b5c7d", 1_000));
        watch.record(&request("not-a-tracker.example", Some("news.example"), "x=1", 1_001));
        let mut someone_else = request("stats.g.doubleclick.net", Some("shop.example"), "a=1", 1_002);
        someone_else.user = Some("S-1-5-21-9-9-9-1002".into());
        watch.record(&someone_else);

        let report = watch.report(key, 2_000);
        assert_eq!(report["total"], 1, "non-trackers and other users are not in this user's report");
        let google = &report["companies"][0];
        assert_eq!(google["company"], "Google");
        assert_eq!(google["sources"][0]["source"], "news.example");
        assert_eq!(google["cookies_set"][0]["name"], "uid");
        assert_eq!(google["cookies_set"][0]["from"][0], "news.example");
        assert_eq!(google["identifiers"][0]["value"], "8f2b4c6d9e1a3b5c7d");
        assert!(google["contact"]["form"].is_string(), "Google's request form is attached");
        assert_eq!(report["sites"][0]["site"], "news.example");

        // The log survives a restart.
        let again = Watch::new(tmp.path(), Arc::new(TrackerDb::bundled().unwrap()));
        assert_eq!(again.report(key, 2_000)["total"], 1);
    }

    #[test]
    fn flags_sites_that_keep_sending_ids_after_you_said_no() {
        let tmp = tempfile::tempdir().unwrap();
        let watch = Watch::new(tmp.path(), Arc::new(TrackerDb::bundled().unwrap()));
        let key = "S-1-5-21-1-2-3-1001";
        watch.set_choice(key, "www.news.example", true, 1_500);
        watch.set_choice(key, "quiet.example", true, 1_500);
        // Before the choice: does not count.
        watch.record(&request("stats.g.doubleclick.net", Some("news.example"), "visitor_id=8f2b4c6d9e1a3b5c7d", 1_000));
        // After: an ID sent anyway, and the banner's own signal said no.
        watch.record(&request(
            "stats.g.doubleclick.net",
            Some("m.news.example"),
            "gcs=G100&visitor_id=8f2b4c6d9e1a3b5c7d",
            1_600,
        ));
        let report = watch.report(key, 2_000);
        let choices = report["choices"].as_array().unwrap();
        let news = choices.iter().find(|c| c["site"] == "news.example").unwrap();
        assert_eq!(news["verdict"], "ignored");
        assert_eq!(news["identifying_after"], 1);
        let quiet = choices.iter().find(|c| c["site"] == "quiet.example").unwrap();
        assert_eq!(quiet["verdict"], "nothing_seen");
        assert_eq!(report["companies"][0]["refused_but_identified"], 1);

        watch.set_choice(key, "quiet.example", false, 1_700);
        assert_eq!(watch.report(key, 2_000)["choices"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn tracks_data_requests_and_their_due_dates() {
        let tmp = tempfile::tempdir().unwrap();
        let watch = Watch::new(tmp.path(), Arc::new(TrackerDb::bundled().unwrap()));
        let key = "S-1-5-21-1-2-3-1001";
        watch.set_requester(
            key,
            Requester {
                name: "A".into(),
                email: "a@example.org".into(),
                region: "ccpa".into(),
            },
        );
        watch.request_sent(key, "Criteo", "access", 0);
        let report = watch.report(key, 10);
        assert_eq!(report["requests"][0]["due_unix"], 45 * 24 * 60 * 60);
        assert_eq!(report["requester"]["region"], "ccpa");
        watch.request_removed(key, "Criteo", "access");
        assert!(watch.report(key, 10)["requests"].as_array().unwrap().is_empty());
    }
}
