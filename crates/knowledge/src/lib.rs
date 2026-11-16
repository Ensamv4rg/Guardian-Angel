//! Tracker knowledge base: maps a domain to the company behind it and what
//! kind of tracking it does.
//!
//! The bundled data is a small seed list. A later `kb-builder` tool will
//! compile Tracker Radar and other lists into a compact `fst` file; the
//! public API here stays the same.

use ga_core::{Category, normalize_host};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

const BUNDLED_SEED: &str = include_str!("../../../data/sources/seed_trackers.json");

#[derive(Debug, thiserror::Error)]
pub enum KnowledgeError {
    #[error("tracker list is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("domain {domain:?} is listed for both {first} and {second}")]
    DuplicateDomain {
        domain: String,
        first: String,
        second: String,
    },
    #[error("domain {0:?} must be lowercase with no leading dot or spaces")]
    BadDomain(String),
}

/// A domain that matched an entry in the knowledge base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackerMatch<'a> {
    pub company: &'a str,
    pub category: Category,
    /// The listed domain that matched, e.g. `doubleclick.net` for `stats.g.doubleclick.net`.
    pub domain: &'a str,
}

#[derive(Deserialize)]
struct SeedFile {
    companies: Vec<SeedCompany>,
}

#[derive(Deserialize)]
struct SeedCompany {
    name: String,
    domains: BTreeMap<String, Category>,
}

/// In-memory tracker lookup table.
#[derive(Debug)]
pub struct TrackerDb {
    companies: Vec<String>,
    /// Domain -> (index into `companies`, category).
    domains: HashMap<String, (usize, Category)>,
}

impl TrackerDb {
    /// Loads the list compiled into the binary.
    pub fn bundled() -> Result<Self, KnowledgeError> {
        Self::from_json(BUNDLED_SEED)
    }

    /// Loads a list in the seed-file format.
    pub fn from_json(json: &str) -> Result<Self, KnowledgeError> {
        let seed: SeedFile = serde_json::from_str(json)?;
        let mut companies = Vec::with_capacity(seed.companies.len());
        let mut domains = HashMap::new();

        for (idx, company) in seed.companies.into_iter().enumerate() {
            for (domain, category) in company.domains {
                if domain != normalize_host(&domain) || domain.is_empty() {
                    return Err(KnowledgeError::BadDomain(domain));
                }
                if let Some((other, _)) = domains.get(&domain) {
                    let first: &String = &companies[*other];
                    return Err(KnowledgeError::DuplicateDomain {
                        domain,
                        first: first.clone(),
                        second: company.name,
                    });
                }
                domains.insert(domain, (idx, category));
            }
            companies.push(company.name);
        }

        Ok(Self { companies, domains })
    }

    /// Finds the company behind a host, matching the host itself or any parent
    /// domain (`a.b.doubleclick.net` matches `doubleclick.net`).
    pub fn classify(&self, host: &str) -> Option<TrackerMatch<'_>> {
        let host = normalize_host(host);
        let mut rest = host.as_str();
        loop {
            if let Some((domain, &(idx, category))) = self.domains.get_key_value(rest) {
                return Some(TrackerMatch {
                    company: &self.companies[idx],
                    category,
                    domain,
                });
            }
            match rest.find('.') {
                Some(dot) => rest = &rest[dot + 1..],
                None => return None,
            }
        }
    }

    pub fn company_count(&self) -> usize {
        self.companies.len()
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_list_loads() {
        let db = TrackerDb::bundled().expect("bundled list must be valid");
        assert!(db.company_count() > 40);
        assert!(db.domain_count() > db.company_count());
    }

    #[test]
    fn matches_subdomains_and_cookie_hosts() {
        let db = TrackerDb::bundled().unwrap();
        let m = db.classify(".stats.g.doubleclick.net").unwrap();
        assert_eq!(m.company, "Google");
        assert_eq!(m.category, Category::Advertising);
        assert_eq!(m.domain, "doubleclick.net");

        assert_eq!(db.classify("WWW.Facebook.com").unwrap().company, "Meta");
    }

    #[test]
    fn does_not_match_lookalike_domains() {
        let db = TrackerDb::bundled().unwrap();
        assert!(db.classify("notdoubleclick.net").is_none());
        assert!(db.classify("example.com").is_none());
        assert!(db.classify("").is_none());
    }

    #[test]
    fn rejects_duplicate_domains() {
        let json = r#"{"companies":[
            {"name":"A","domains":{"x.com":"advertising"}},
            {"name":"B","domains":{"x.com":"analytics"}}]}"#;
        assert!(matches!(
            TrackerDb::from_json(json),
            Err(KnowledgeError::DuplicateDomain { .. })
        ));
    }

    #[test]
    fn rejects_unnormalised_domains() {
        let json = r#"{"companies":[{"name":"A","domains":{".X.com":"advertising"}}]}"#;
        assert!(matches!(
            TrackerDb::from_json(json),
            Err(KnowledgeError::BadDomain(_))
        ));
    }
}
