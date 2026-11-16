//! Converts DuckDuckGo's tracker blocklist (`extension-tds.json`, built from
//! Tracker Radar) into the knowledge-base format.
//!
//! The data is licensed CC BY-NC-SA 4.0: free for non-commercial use with
//! attribution. A commercial release needs a licence from DuckDuckGo.

use ga_core::Category;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

pub const SOURCE: &str = "DuckDuckGo Tracker Radar (tracker-blocklists, extension-tds v6)";
pub const LICENSE: &str = "CC BY-NC-SA 4.0, https://creativecommons.org/licenses/by-nc-sa/4.0/";

#[derive(Deserialize)]
struct Tds {
    #[serde(rename = "_builtWith", default)]
    built_with: BTreeMap<String, String>,
    trackers: BTreeMap<String, TdsTracker>,
    #[serde(default)]
    entities: HashMap<String, TdsEntity>,
    /// Every domain DuckDuckGo knows the owner of -> entity name.
    #[serde(default)]
    domains: HashMap<String, String>,
}

#[derive(Deserialize)]
struct TdsTracker {
    owner: Option<TdsOwner>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    default: String,
}

#[derive(Deserialize)]
struct TdsOwner {
    name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "ownedBy")]
    owned_by: Option<String>,
}

#[derive(Deserialize)]
struct TdsEntity {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

/// Categories that mean a domain collects data about people. Content
/// delivery, payments, logins and chat widgets alone do not count.
const TRACKING: &[&str] = &[
    "Advertising",
    "Ad Motivated Tracking",
    "Action Pixels",
    "Session Replay",
    "Analytics",
    "Third-Party Analytics Marketing",
    "Audience Measurement",
    "Ad Fraud",
    "Social Network",
    "Social - Share",
    "Social - Comment",
    "Tag Manager",
    "Malware",
    "Unknown High Risk Behavior",
];

/// Picks our single category for DuckDuckGo's list of categories, most
/// specific first. `None` means the domain is not treated as a tracker.
fn category(categories: &[String], blocked: bool) -> Option<Category> {
    let has = |c: &str| categories.iter().any(|x| x == c);
    let tracking = categories.iter().any(|c| TRACKING.contains(&c.as_str()));
    // DuckDuckGo leaves CDNs and embedded content unblocked; without a clear
    // tracking role they would flag every site's ordinary cookies.
    if !blocked && (!tracking || has("Content Delivery")) {
        return None;
    }
    Some(if has("Session Replay") {
        Category::SessionRecording
    } else if has("Advertising") || has("Ad Motivated Tracking") || has("Action Pixels") {
        Category::Advertising
    } else if has("Social Network") || has("Social - Share") || has("Social - Comment") {
        Category::Social
    } else if has("Ad Fraud") {
        Category::AdVerification
    } else if has("Tag Manager") {
        Category::TagManagement
    } else {
        // Analytics, audience measurement, or blocked without a stated reason.
        Category::Analytics
    })
}

/// Builds the knowledge-base JSON from DuckDuckGo's list. Companies already
/// in `seed_json` keep the seed's name (so "Facebook, Inc." becomes "Meta"),
/// and domains the seed lists are left out; the seed wins.
pub fn convert(tds_json: &str, seed_json: &str) -> Result<String, crate::KnowledgeError> {
    let tds: Tds = serde_json::from_str(tds_json)?;
    let seed: crate::SeedFile = serde_json::from_str(seed_json)?;

    let mut seed_domains = HashMap::new();
    let mut entity_alias: HashMap<&str, &str> = HashMap::new();
    for company in &seed.companies {
        for domain in company.domains.keys() {
            seed_domains.insert(domain.as_str(), company.name.as_str());
            if let Some(entity) = tds.domains.get(domain) {
                entity_alias.entry(entity.as_str()).or_insert(company.name.as_str());
            }
        }
    }

    let mut companies: BTreeMap<String, BTreeMap<String, Category>> = BTreeMap::new();
    for (domain, tracker) in &tds.trackers {
        let domain = ga_core::normalize_host(domain);
        if domain.is_empty() || seed_domains.contains_key(domain.as_str()) {
            continue;
        }
        let Some(category) = category(&tracker.categories, tracker.default == "block") else { continue };
        let Some(owner) = &tracker.owner else { continue };
        // Fake trackers from the EFF's "Cover Your Tracks" test page.
        if owner.name.starts_with("EFF Test") {
            continue;
        }
        // The parent company when DuckDuckGo names one ("Google Ads" -> Google LLC).
        let entity = owner.owned_by.as_deref().unwrap_or(&owner.name);
        let name = match entity_alias.get(entity) {
            Some(seed_name) => (*seed_name).to_owned(),
            None => tds
                .entities
                .get(entity)
                .and_then(|e| e.display_name.clone())
                .or_else(|| owner.display_name.clone())
                .unwrap_or_else(|| owner.name.clone()),
        };
        companies.entry(name).or_default().insert(domain, category);
    }

    let companies: Vec<_> = companies
        .into_iter()
        .map(|(name, domains)| json!({ "name": name, "domains": domains }))
        .collect();
    let out = json!({
        "source": SOURCE,
        "license": LICENSE,
        "built_with": tds.built_with,
        "companies": companies,
    });
    Ok(serde_json::to_string_pretty(&out)? + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = r#"{"companies":[{"name":"Meta","domains":{"facebook.com":"social"}}]}"#;
    const TDS: &str = r#"{
      "_builtWith": {"tracker-radar": "abc"},
      "trackers": {
        "facebook.net": {"owner": {"name": "Facebook, Inc."}, "categories": ["Advertising"], "default": "ignore"},
        "facebook.com": {"owner": {"name": "Facebook, Inc."}, "categories": ["Social Network"], "default": "ignore"},
        "doubleclick.net": {"owner": {"name": "Google Ads", "ownedBy": "Google LLC"}, "categories": ["Advertising"], "default": "block"},
        "hotjar.com": {"owner": {"name": "Hotjar"}, "categories": ["Analytics", "Session Replay"], "default": "block"},
        "jsdelivr.net": {"owner": {"name": "Prospect One"}, "categories": ["Content Delivery"], "default": "ignore"},
        "cloudflare.com": {"owner": {"name": "Cloudflare"}, "categories": ["Analytics", "Content Delivery"], "default": "ignore"},
        "sentry.io": {"owner": {"name": "Functional Software"}, "categories": [], "default": "ignore"},
        "clarity.ms": {"owner": {"name": "Microsoft Corporation"}, "categories": [], "default": "block"}
      },
      "entities": {"Google LLC": {"displayName": "Google"}, "Microsoft Corporation": {"displayName": "Microsoft"}},
      "domains": {"facebook.com": "Facebook, Inc.", "facebook.net": "Facebook, Inc."}
    }"#;

    #[test]
    fn converts_with_seed_names_and_skips_non_trackers() {
        let db = crate::TrackerDb::from_json(&convert(TDS, SEED).unwrap()).unwrap();
        let get = |d: &str| db.classify(d).map(|m| (m.company.to_owned(), m.category));
        assert_eq!(get("facebook.net"), Some(("Meta".into(), Category::Advertising)));
        assert_eq!(get("facebook.com"), None, "the seed's own domains are left to the seed");
        assert_eq!(get("doubleclick.net"), Some(("Google".into(), Category::Advertising)));
        assert_eq!(get("hotjar.com"), Some(("Hotjar".into(), Category::SessionRecording)));
        assert_eq!(get("clarity.ms"), Some(("Microsoft".into(), Category::Analytics)));
        assert_eq!(get("jsdelivr.net"), None);
        assert_eq!(get("cloudflare.com"), None);
        assert_eq!(get("sentry.io"), None);
    }
}
