//! Matches SDK signatures: file names, package names, and tracker addresses
//! inside app code (ASCII and UTF-16, on domain-label boundaries).

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use ga_core::Category;
use ga_knowledge::TrackerDb;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;

const BUNDLED_CATALOG: &str = include_str!("../../../../data/sources/sdk_signatures.json");

/// Tracker-list domains shorter than this are too likely to match unrelated
/// text (e.g. `t.co`), so they are not searched for in code.
const MIN_DOMAIN_LEN: usize = 6;
const CHUNK: usize = 8 * 1024 * 1024;
const OVERLAP: usize = 512;

#[derive(Debug, Deserialize)]
pub struct Sdk {
    pub name: String,
    pub company: String,
    pub category: Category,
    pub purpose: String,
    files: Vec<String>,
    file_prefixes: Vec<String>,
    npm: Vec<String>,
    endpoints: Vec<String>,
}

#[derive(Deserialize)]
struct CatalogFile {
    sdks: Vec<Sdk>,
    #[serde(default)]
    not_searched_in_code: Vec<String>,
}

/// Who a matched address belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// An SDK from the catalog (index into `Matcher::sdks`).
    Sdk(usize),
    /// A company from the tracker list.
    Tracker { company: String, category: Category },
}

struct Pattern {
    domain: String,
    owner: Owner,
    utf16: bool,
}

pub struct Matcher {
    pub sdks: Vec<Sdk>,
    patterns: Vec<Pattern>,
    search: AhoCorasick,
}

/// Domain addresses found while scanning, keyed by pattern index, with one
/// example full host each (e.g. `o123.ingest.sentry.io` for `sentry.io`).
pub type Found = HashMap<usize, String>;

impl Matcher {
    pub fn bundled(db: &TrackerDb) -> Self {
        Self::new(BUNDLED_CATALOG, db).expect("bundled SDK catalog must be valid")
    }

    pub fn new(catalog_json: &str, db: &TrackerDb) -> Result<Self, serde_json::Error> {
        let catalog: CatalogFile = serde_json::from_str(catalog_json)?;
        let mut domains: Vec<(String, Owner)> = Vec::new();
        for (i, sdk) in catalog.sdks.iter().enumerate() {
            for e in &sdk.endpoints {
                domains.push((e.to_ascii_lowercase(), Owner::Sdk(i)));
            }
        }
        let mut tracker: Vec<(&str, &str, Category)> = db
            .entries()
            .filter(|(d, _, c)| {
                d.len() >= MIN_DOMAIN_LEN
                    && !matches!(c, Category::Platform | Category::Social)
                    && !catalog.not_searched_in_code.iter().any(|x| x == d)
            })
            .collect();
        tracker.sort();
        for (domain, company, category) in tracker {
            if !domains.iter().any(|(d, _)| d == domain) {
                domains.push((
                    domain.to_owned(),
                    Owner::Tracker {
                        company: company.to_owned(),
                        category,
                    },
                ));
            }
        }

        let mut patterns = Vec::new();
        let mut bytes: Vec<Vec<u8>> = Vec::new();
        for (domain, owner) in domains {
            bytes.push(domain.as_bytes().to_vec());
            bytes.push(domain.encode_utf16().flat_map(u16::to_le_bytes).collect());
            patterns.push(Pattern {
                domain: domain.clone(),
                owner: owner.clone(),
                utf16: false,
            });
            patterns.push(Pattern {
                domain,
                owner,
                utf16: true,
            });
        }
        let search = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&bytes)
            .expect("patterns are plain byte strings");

        Ok(Self {
            sdks: catalog.sdks,
            patterns,
            search,
        })
    }

    /// SDK whose bundled file this is (`sentry.dll`).
    pub fn sdk_for_file(&self, lowercase_name: &str) -> Option<usize> {
        self.sdks.iter().position(|s| {
            s.files.iter().any(|f| f == lowercase_name) || s.file_prefixes.iter().any(|p| lowercase_name.starts_with(p.as_str()))
        })
    }

    /// SDK this npm package belongs to (`@sentry/electron`).
    pub fn sdk_for_package(&self, name: &str) -> Option<usize> {
        self.sdks.iter().position(|s| s.npm.iter().any(|n| n == name))
    }

    pub fn owner(&self, pattern: usize) -> &Owner {
        &self.patterns[pattern].owner
    }

    pub fn domain(&self, pattern: usize) -> &str {
        &self.patterns[pattern].domain
    }

    /// Searches a file in chunks; returns bytes read.
    pub fn scan_file(&self, path: &Path, max_bytes: u64, found: &mut Found) -> io::Result<u64> {
        let mut file = std::fs::File::open(path)?.take(max_bytes);
        let mut buf = vec![0u8; CHUNK + OVERLAP];
        let mut carried = 0;
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buf[carried..])?;
            if n == 0 {
                break;
            }
            total += n as u64;
            let filled = carried + n;
            self.scan_bytes(&buf[..filled], found);
            // Keep the tail so a match split across chunks is still found.
            carried = OVERLAP.min(filled);
            buf.copy_within(filled - carried..filled, 0);
        }
        Ok(total)
    }

    pub fn scan_bytes(&self, hay: &[u8], found: &mut Found) {
        for m in self.search.find_iter(hay) {
            let pattern = m.pattern().as_usize();
            if found.contains_key(&pattern) {
                continue;
            }
            let p = &self.patterns[pattern];
            let (start, end) = (m.start(), m.end());
            let ok = if p.utf16 {
                utf16_boundary(hay, start, end)
            } else {
                ascii_boundary(hay, start, end)
            };
            if ok {
                let example = if p.utf16 { p.domain.clone() } else { full_host(hay, start, end) };
                found.insert(pattern, example);
            }
        }
    }
}

fn is_label_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// `x.com` must not match inside `netflix.com`, but `a.x.com` is fine.
fn ascii_boundary(hay: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !is_label_char(hay[start - 1]);
    let after_ok = end >= hay.len() || !is_label_char(hay[end]);
    before_ok && after_ok
}

fn utf16_boundary(hay: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start < 2 || hay[start - 1] != 0 || !is_label_char(hay[start - 2]);
    let after_ok = end + 1 >= hay.len() || hay[end + 1] != 0 || !is_label_char(hay[end]);
    before_ok && after_ok
}

/// Extends a match backwards to the whole host name.
fn full_host(hay: &[u8], start: usize, end: usize) -> String {
    let mut s = start;
    while s > 0 && start - s < 100 && (is_label_char(hay[s - 1]) || hay[s - 1] == b'.') {
        s -= 1;
    }
    String::from_utf8_lossy(&hay[s..end])
        .trim_start_matches(['.', '-'])
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> Matcher {
        Matcher::bundled(&TrackerDb::bundled().unwrap())
    }

    fn found_domains(m: &Matcher, hay: &[u8]) -> Vec<(String, String)> {
        let mut found = Found::new();
        m.scan_bytes(hay, &mut found);
        let mut v: Vec<(String, String)> = found.iter().map(|(p, ex)| (m.domain(*p).to_owned(), ex.clone())).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn finds_sdk_endpoints_with_full_host() {
        let m = matcher();
        let hits = found_domains(&m, br#"const dsn="https://abc@o123.ingest.sentry.io/456";"#);
        assert_eq!(hits, [("sentry.io".to_owned(), "o123.ingest.sentry.io".to_owned())]);
    }

    #[test]
    fn skips_domains_that_are_mostly_ordinary_links() {
        let m = matcher();
        assert!(found_domains(&m, b"\"https://www.bing.com/search?q=x\"").is_empty());
    }

    #[test]
    fn respects_label_boundaries() {
        let m = matcher();
        assert!(found_domains(&m, b"see https://notsentry.io/ and mysentry.io.").is_empty());
        assert!(found_domains(&m, b"api.mixpanel.community").is_empty());
    }

    #[test]
    fn finds_tracker_list_domains_but_not_platforms_or_short_ones() {
        let m = matcher();
        let hits = found_domains(&m, b"\"https://static.criteo.net/js\" \"https://www.google.com\" \"t.co\"");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "criteo.net");
    }

    #[test]
    fn finds_utf16_strings_in_native_binaries() {
        let m = matcher();
        let text: Vec<u8> = "\0https://api.mixpanel.com/track\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let hits = found_domains(&m, &text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "api.mixpanel.com");
    }

    #[test]
    fn matches_files_and_packages() {
        let m = matcher();
        assert_eq!(m.sdks[m.sdk_for_file("sentry.dll").unwrap()].name, "Sentry");
        assert_eq!(m.sdks[m.sdk_for_file("firebasecppapp-11_0_0.dll").unwrap()].name, "Firebase");
        assert!(m.sdk_for_file("notsentry.dll").is_none());
        assert_eq!(m.sdks[m.sdk_for_package("@sentry/electron").unwrap()].name, "Sentry");
        assert!(m.sdk_for_package("left-pad").is_none());
    }

    #[test]
    fn finds_matches_split_across_chunks() {
        let m = matcher();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.js");
        // The first read takes CHUNK + OVERLAP bytes; start the address 5
        // bytes before that so it is split between two reads.
        let mut data = vec![b' '; CHUNK + OVERLAP - 5];
        data.extend_from_slice(b"\"api.segment.io\"");
        std::fs::write(&path, &data).unwrap();
        let mut found = Found::new();
        let read = m.scan_file(&path, u64::MAX, &mut found).unwrap();
        assert_eq!(read, data.len() as u64);
        assert_eq!(found.values().next().map(String::as_str), Some("api.segment.io"));
    }
}
